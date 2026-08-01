// SPDX-License-Identifier: GPL-2.0-or-later

//! Build-time parsers for the pinned Bash, Zsh, and Fish completion sources.
//!
//! This parser is implemented in-tree and does not invoke or reuse a source
//! shell parser. It intentionally produces a semantic, dialect-neutral AST;
//! source-specific behavior lives in the VM's standard builtin layer.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;

use super::script::{
    ScriptAndOrArm, ScriptAssignment, ScriptBooleanOperator, ScriptCaseArm, ScriptCommand,
    ScriptConditionalBranch, ScriptDialect, ScriptEntry, ScriptFunction, ScriptModule,
    ScriptRedirection, ScriptRegistration, ScriptStatement, ScriptWord, ScriptWordPart,
};

pub const MAX_SCRIPT_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_WORD_PARSE_DEPTH: usize = 32;
const MAX_WORD_PARSE_WORK: usize = 262_144;
const MAX_WORD_PARSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOKENS: usize = 8_000_000;
const MAX_PARSE_NESTING: usize = 256;
const MAX_REDIRECTION_DESCRIPTOR: u16 = 9;
const MAX_STATIC_REGISTRATION_WALK_WORK: usize = 16_384;
const MAX_STATIC_REGISTRATIONS: usize = 4096;
const MAX_STATIC_REGISTRATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_FISH_FORWARDER_FUNCTIONS: usize = 65_536;
const MAX_FISH_FORWARDER_EDGES: usize = 262_144;
thread_local! {
    static WORD_PARSE_DEPTH: Cell<usize> = const { Cell::new(0) };
    static WORD_PARSE_WORK: Cell<usize> = const { Cell::new(0) };
    static WORD_PARSE_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct WordParseGuard;

impl Drop for WordParseGuard {
    fn drop(&mut self) {
        WORD_PARSE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

fn enter_word_parse(value_bytes: usize) -> Result<WordParseGuard, String> {
    let depth_ok = WORD_PARSE_DEPTH.with(|depth| {
        let next = depth.get().saturating_add(1);
        depth.set(next);
        next <= MAX_WORD_PARSE_DEPTH
    });
    if !depth_ok {
        WORD_PARSE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        return Err("word parse depth limit exceeded".into());
    }
    let work_ok = WORD_PARSE_WORK.with(|work| {
        let next = work.get().saturating_add(1);
        work.set(next);
        next <= MAX_WORD_PARSE_WORK
    });
    if !work_ok {
        WORD_PARSE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        return Err("word parse work limit exceeded".into());
    }
    let bytes_ok = WORD_PARSE_BYTES.with(|bytes| {
        let next = bytes.get().saturating_add(value_bytes);
        bytes.set(next);
        next <= MAX_WORD_PARSE_BYTES
    });
    if !bytes_ok {
        WORD_PARSE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        return Err("word parse byte limit exceeded".into());
    }
    Ok(WordParseGuard)
}

const REDIRECTION_OPERATORS: &[&str] = &[
    "<<<", "<<-", ">>!", "&>>", ">!", ">>", "<<", ">&", "<&", ">|", "<>", "&>", ">", "<",
];

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Word(String),
    Operator(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

impl Token {
    fn word(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Word(value) => Some(value),
            TokenKind::Operator(_) => None,
        }
    }

    fn operator(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Operator(value) => Some(value),
            TokenKind::Word(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct ScriptParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ScriptParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ScriptParseError {}

fn validate_redirection_descriptors(tokens: &[Token]) -> Result<(), ScriptParseError> {
    for (index, token) in tokens.iter().enumerate() {
        let value = match &token.kind {
            TokenKind::Word(value) | TokenKind::Operator(value) => value,
        };
        let digits = value.bytes().take_while(u8::is_ascii_digit).count();
        let inline_redirection = digits > 0
            && REDIRECTION_OPERATORS
                .iter()
                .any(|operator| value[digits..].starts_with(operator));
        let separate_redirection = digits == value.len()
            && tokens
                .get(index + 1)
                .and_then(Token::operator)
                .is_some_and(is_redirection);
        if (inline_redirection || separate_redirection)
            && value[..digits]
                .parse::<u16>()
                .map_or(true, |descriptor| descriptor > MAX_REDIRECTION_DESCRIPTOR)
        {
            return Err(ScriptParseError {
                line: token.line,
                message: "redirection descriptor exceeds policy bound".into(),
            });
        }
    }
    Ok(())
}

fn validate_token_nesting(tokens: &[Token]) -> Result<(), ScriptParseError> {
    let mut depth = 0_usize;
    let mut command_position = true;
    for token in tokens {
        if let Some(operator) = token.operator() {
            let opens = matches!(operator, "{" | "(");
            let closes = matches!(operator, "}" | ")");
            if opens {
                depth = depth.saturating_add(1);
            } else if closes {
                depth = depth.saturating_sub(1);
            }
            command_position = matches!(
                operator,
                ";" | ";;"
                    | ";&"
                    | ";;&"
                    | ";|"
                    | "&&"
                    | "||"
                    | "|"
                    | "|&"
                    | "&"
                    | "{"
                    | "("
                    | "}"
                    | ")"
            );
        } else if let Some(word) = token.word() {
            let opens = command_position
                && matches!(
                    word,
                    "if" | "case" | "while" | "until" | "for" | "foreach" | "switch" | "function"
                );
            let closes = command_position && matches!(word, "fi" | "esac" | "done" | "end");
            if opens {
                depth = depth.saturating_add(1);
            } else if closes {
                depth = depth.saturating_sub(1);
            }
            command_position =
                command_position && matches!(word, "then" | "do" | "else" | "elif" | "in");
        }
        if depth > MAX_PARSE_NESTING {
            return Err(ScriptParseError {
                line: token.line,
                message: "token nesting limit exceeded".into(),
            });
        }
    }
    Ok(())
}

const HERE_DOCUMENT_MARKER: &str = "__BASHLUME_HERE_DOCUMENT_";

struct PendingHereDocument {
    marker: String,
    delimiter: String,
    quoted: bool,
    strip_tabs: bool,
    body: String,
    line: usize,
}

struct HereDocumentSpec {
    start: usize,
    end: usize,
    delimiter: String,
    quoted: bool,
    strip_tabs: bool,
}

fn preprocess_here_documents(
    dialect: ScriptDialect,
    source: &str,
) -> Result<(String, HashMap<String, ScriptWord>), ScriptParseError> {
    if !source.contains("<<") {
        return Ok((source.to_owned(), HashMap::new()));
    }
    if source.contains(HERE_DOCUMENT_MARKER) {
        return Err(ScriptParseError {
            line: 1,
            message: "reserved here-document marker appears in source".into(),
        });
    }
    let mut output = String::with_capacity(source.len());
    let mut pending = VecDeque::<PendingHereDocument>::new();
    let mut documents = HashMap::new();
    let mut marker_index = 0_usize;
    for (line_index, inclusive_line) in source.split_inclusive('\n').enumerate() {
        let has_newline = inclusive_line.ends_with('\n');
        let line = inclusive_line
            .strip_suffix('\n')
            .unwrap_or(inclusive_line)
            .strip_suffix('\r')
            .unwrap_or_else(|| inclusive_line.strip_suffix('\n').unwrap_or(inclusive_line));
        if let Some(document) = pending.front_mut() {
            let body_line = if document.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if body_line == document.delimiter {
                let mut document = pending.pop_front().expect("front document exists");
                if document.body.ends_with('\n') {
                    document.body.pop();
                }
                let word = if document.quoted {
                    ScriptWord {
                        parts: vec![ScriptWordPart::Literal {
                            value: document.body,
                            quoted: true,
                        }],
                        raw: None,
                    }
                } else {
                    let quoted = format!("\"{}\"", document.body.replace('"', "\\\""));
                    parse_word_parts(dialect, &quoted).map_err(|message| ScriptParseError {
                        line: document.line,
                        message,
                    })?
                };
                documents.insert(document.marker, word);
            } else {
                document.body.push_str(body_line);
                if has_newline {
                    document.body.push('\n');
                }
            }
            if has_newline {
                output.push('\n');
            }
            continue;
        }
        let specifications = scan_here_document_specs(line);
        if specifications.is_empty() {
            output.push_str(inclusive_line);
            continue;
        }
        let mut cursor = 0_usize;
        for specification in specifications {
            if marker_index >= 4096 {
                return Err(ScriptParseError {
                    line: line_index + 1,
                    message: "too many here-documents".into(),
                });
            }
            output.push_str(&line[cursor..specification.start]);
            let marker = format!("{HERE_DOCUMENT_MARKER}{marker_index}__");
            marker_index += 1;
            output.push_str(&marker);
            cursor = specification.end;
            pending.push_back(PendingHereDocument {
                marker,
                delimiter: specification.delimiter,
                quoted: specification.quoted,
                strip_tabs: specification.strip_tabs,
                body: String::new(),
                line: line_index + 1,
            });
        }
        output.push_str(&line[cursor..]);
        if has_newline {
            output.push('\n');
        }
    }
    if let Some(document) = pending.front() {
        return Err(ScriptParseError {
            line: document.line,
            message: format!("unterminated here-document {}", document.delimiter),
        });
    }
    Ok((output, documents))
}

fn scan_here_document_specs(line: &str) -> Vec<HereDocumentSpec> {
    let bytes = line.as_bytes();
    let mut specifications = Vec::new();
    let mut index = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    let mut arithmetic_depth = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == b'\\' && active == b'"' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"((") {
            arithmetic_depth += 1;
            index += 2;
            continue;
        }
        if arithmetic_depth > 0 {
            if bytes.get(index..index + 2) == Some(b"))") {
                arithmetic_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if byte == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            break;
        }
        if byte != b'<'
            || bytes.get(index + 1) != Some(&b'<')
            || bytes.get(index + 2) == Some(&b'<')
            || (index > 0 && bytes[index - 1] == b'<')
        {
            if byte == b'\\' {
                escaped = true;
            }
            index += 1;
            continue;
        }
        let strip_tabs = bytes.get(index + 2) == Some(&b'-');
        let mut target = index + if strip_tabs { 3 } else { 2 };
        while bytes.get(target).is_some_and(u8::is_ascii_whitespace) {
            target += 1;
        }
        let start = target;
        let mut delimiter = String::new();
        let mut target_quote = None;
        let mut quoted = false;
        let mut target_escaped = false;
        while target < bytes.len() {
            let byte = bytes[target];
            if target_escaped {
                delimiter.push(byte as char);
                target_escaped = false;
                target += 1;
                continue;
            }
            if let Some(active) = target_quote {
                if byte == active {
                    target_quote = None;
                } else if byte == b'\\' && active == b'"' {
                    target_escaped = true;
                } else {
                    delimiter.push(byte as char);
                }
                target += 1;
                continue;
            }
            if matches!(byte, b'\'' | b'"') {
                quoted = true;
                target_quote = Some(byte);
                target += 1;
                continue;
            }
            if byte == b'\\' {
                quoted = true;
                target_escaped = true;
                target += 1;
                continue;
            }
            if byte.is_ascii_whitespace()
                || matches!(byte, b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>')
            {
                break;
            }
            delimiter.push(byte as char);
            target += 1;
        }
        if !delimiter.is_empty() && target_quote.is_none() {
            specifications.push(HereDocumentSpec {
                start,
                end: target,
                delimiter,
                quoted,
                strip_tabs,
            });
        }
        index = target.max(index + 2);
    }
    specifications
}

fn apply_here_documents(
    statements: &mut [ScriptStatement],
    documents: &HashMap<String, ScriptWord>,
) {
    fn apply_word(word: &mut ScriptWord, documents: &HashMap<String, ScriptWord>) {
        for part in &mut word.parts {
            match part {
                ScriptWordPart::CommandSubstitution { statements, .. } => {
                    apply_here_documents(statements, documents);
                }
                ScriptWordPart::DeferredScript {
                    statements, words, ..
                } => {
                    apply_here_documents(statements, documents);
                    for value in words {
                        apply_word(value, documents);
                    }
                }
                ScriptWordPart::Array { elements }
                | ScriptWordPart::BraceExpansion {
                    alternatives: elements,
                    ..
                } => {
                    for value in elements {
                        apply_word(value, documents);
                    }
                }
                _ => {}
            }
        }
    }
    fn redirections(
        redirections: &mut [ScriptRedirection],
        documents: &HashMap<String, ScriptWord>,
    ) {
        for redirection in redirections {
            if matches!(redirection.operator.as_str(), "<<" | "<<-") {
                if let Some(marker) = redirection.target.as_plain_literal() {
                    if let Some(document) = documents.get(marker) {
                        redirection.target = document.clone();
                        continue;
                    }
                }
            }
            apply_word(&mut redirection.target, documents);
        }
    }
    fn command(command: &mut ScriptCommand, documents: &HashMap<String, ScriptWord>) {
        for assignment in &mut command.assignments {
            if let Some(index) = &mut assignment.index {
                apply_word(index, documents);
            }
            apply_word(&mut assignment.value, documents);
        }
        for argument in &mut command.words {
            apply_word(argument, documents);
        }
        redirections(&mut command.redirections, documents);
    }
    for statement in statements {
        match statement {
            ScriptStatement::Command { command: value } => command(value, documents),
            ScriptStatement::Pipeline { commands, .. } => apply_here_documents(commands, documents),
            ScriptStatement::AndOr { first, rest } => {
                apply_here_documents(std::slice::from_mut(first), documents);
                for arm in rest {
                    apply_here_documents(std::slice::from_mut(&mut arm.statement), documents);
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    apply_here_documents(&mut branch.condition, documents);
                    apply_here_documents(&mut branch.body, documents);
                }
                apply_here_documents(otherwise, documents);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                apply_here_documents(condition, documents);
                apply_here_documents(body, documents);
            }
            ScriptStatement::For { words, body, .. } => {
                for value in words {
                    apply_word(value, documents);
                }
                apply_here_documents(body, documents);
            }
            ScriptStatement::Case { word: value, arms } => {
                apply_word(value, documents);
                for arm in arms {
                    for pattern in &mut arm.patterns {
                        apply_word(pattern, documents);
                    }
                    apply_here_documents(&mut arm.body, documents);
                }
            }
            ScriptStatement::Function { function } => {
                for argument in &mut function.arguments {
                    apply_word(argument, documents);
                }
                apply_here_documents(&mut function.body, documents);
            }
            ScriptStatement::Group { body, .. } => apply_here_documents(body, documents),
            ScriptStatement::Return { status } => {
                if let Some(status) = status {
                    apply_word(status, documents);
                }
            }
            ScriptStatement::Redirected {
                statement,
                redirections: values,
            } => {
                apply_here_documents(std::slice::from_mut(statement), documents);
                redirections(values, documents);
            }
            ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => {}
        }
    }
}

pub fn parse_script(
    dialect: ScriptDialect,
    source_path: impl Into<String>,
    source: &str,
) -> Result<ScriptModule, ScriptParseError> {
    WORD_PARSE_DEPTH.with(|depth| depth.set(0));
    WORD_PARSE_WORK.with(|work| work.set(0));
    WORD_PARSE_BYTES.with(|bytes| bytes.set(0));
    let source_path = source_path.into();
    if source.len() > MAX_SCRIPT_SOURCE_BYTES {
        return Err(ScriptParseError {
            line: 1,
            message: "source byte limit exceeded".into(),
        });
    }
    let (lexical_source, here_documents) = preprocess_here_documents(dialect, source)?;
    let tokens = Lexer::new(dialect, &lexical_source).lex()?;
    validate_redirection_descriptors(&tokens)?;
    validate_token_nesting(&tokens)?;
    let mut parser = Parser::new(dialect, tokens);
    let mut statements = parser.parse_list(&[])?;
    apply_here_documents(&mut statements, &here_documents);
    if dialect == ScriptDialect::Fish {
        let mut variables = HashMap::new();
        let forwarders = fish_completion_forwarders(&statements)?;
        compile_fish_deferred_scripts(&mut statements, &mut variables, &forwarders)?;
    }
    let mut functions = Vec::new();
    collect_functions(&statements, &mut functions);
    let registrations =
        extract_registrations(dialect, &source_path, source, &statements, &functions)?;
    let module = ScriptModule {
        dialect,
        source_path,
        statements,
        functions,
        registrations,
        probe_capabilities: Vec::new(),
        zsh_function_snapshot: false,
        zsh_function_table_size: 0,
        zsh_function_names: Vec::new(),
    };
    module.validate().map_err(|error| ScriptParseError {
        line: 1,
        message: error.to_string(),
    })?;
    Ok(module)
}

struct Lexer<'a> {
    dialect: ScriptDialect,
    source: &'a str,
    bytes: &'a [u8],
    index: usize,
    line: usize,
    at_boundary: bool,
    at_line_start: bool,
    arithmetic_depth: usize,
    conditional_depth: usize,
}

impl<'a> Lexer<'a> {
    fn new(dialect: ScriptDialect, source: &'a str) -> Self {
        Self {
            dialect,
            source,
            bytes: source.as_bytes(),
            index: 0,
            line: 1,
            at_boundary: true,
            at_line_start: true,
            arithmetic_depth: 0,
            conditional_depth: 0,
        }
    }

    fn lex(mut self) -> Result<Vec<Token>, ScriptParseError> {
        let mut tokens = Vec::new();
        while self.index < self.bytes.len() {
            if tokens.len() >= MAX_TOKENS {
                return self.error("token limit exceeded");
            }
            match self.bytes[self.index] {
                b'\\' if self.bytes.get(self.index + 1) == Some(&b'\n') => {
                    self.index += 2;
                    self.line += 1;
                }
                b' ' | b'\t' | b'\r' => {
                    self.index += 1;
                    self.at_boundary = true;
                }
                b'\n' => {
                    self.index += 1;
                    if self.arithmetic_depth == 0 && self.conditional_depth == 0 {
                        tokens.push(Token {
                            kind: TokenKind::Operator(";".into()),
                            line: self.line,
                        });
                    }
                    self.line += 1;
                    self.at_boundary = true;
                    self.at_line_start = true;
                }
                b'#' if self.at_boundary
                    && self.arithmetic_depth == 0
                    && self.conditional_depth == 0
                    && (self.at_line_start
                        || (self.index == 0 || self.bytes[self.index - 1] != b'(')
                            && self
                                .bytes
                                .get(self.index + 1)
                                .is_none_or(|next| !matches!(next, b'#' | b'(' | b'~'))) =>
                {
                    self.skip_comment();
                }
                _ => {
                    if let Some(operator) = self.operator() {
                        let line = self.line;
                        self.index += operator.len();
                        let expression_operator = (self.conditional_depth > 0 && operator != "]]")
                            || (self.arithmetic_depth > 0 && operator != "))");
                        if expression_operator {
                            tokens.push(Token {
                                kind: TokenKind::Word(operator.into()),
                                line,
                            });
                            self.at_boundary = true;
                            self.at_line_start = false;
                            continue;
                        }
                        match operator {
                            "((" => self.arithmetic_depth = self.arithmetic_depth.saturating_add(1),
                            "))" => self.arithmetic_depth = self.arithmetic_depth.saturating_sub(1),
                            "[[" => {
                                self.conditional_depth = self.conditional_depth.saturating_add(1)
                            }
                            "]]" => {
                                self.conditional_depth = self.conditional_depth.saturating_sub(1)
                            }
                            _ => {}
                        }
                        tokens.push(Token {
                            kind: TokenKind::Operator(operator.into()),
                            line,
                        });
                        self.at_boundary = true;
                        self.at_line_start = false;
                    } else {
                        let line = self.line;
                        let word = self.word()?;
                        if !word.is_empty() {
                            tokens.push(Token {
                                kind: TokenKind::Word(word),
                                line,
                            });
                        }
                        self.at_boundary = false;
                        self.at_line_start = false;
                    }
                }
            }
        }
        // Collapse repeated separators while retaining one structural boundary.
        let mut collapsed = Vec::with_capacity(tokens.len());
        for token in tokens {
            if token.operator() == Some(";")
                && collapsed
                    .last()
                    .is_some_and(|previous: &Token| previous.operator() == Some(";"))
            {
                continue;
            }
            collapsed.push(token);
        }
        Ok(collapsed)
    }

    fn skip_comment(&mut self) {
        let start = self.index;
        while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
            self.index += 1;
        }
        if self.dialect == ScriptDialect::Fish
            && self.index < self.bytes.len()
            && self.bytes[start..self.index].ends_with(b"\\")
        {
            self.index += 1;
            self.line += 1;
            self.at_boundary = true;
            self.at_line_start = true;
        }
    }

    fn operator(&self) -> Option<&'static str> {
        let rest = &self.bytes[self.index..];
        if rest.starts_with(b"(((") {
            return Some("(");
        }
        const COMMON: &[&str] = &[
            "2>&1", "2>|", "1>|", ";;&", ";;", ";&", ";|", "&&", "||", "|&", "&|", "<<-", "<<<",
            ">>!", ">!", ">>", "<<", "<&", ">&", "<>", ">|", "((", "))", "[[", "]]", "&>", "&>>",
            "|", ";", "&", "(", ")", "{", "}", "<", ">",
        ];
        for operator in COMMON {
            if rest.starts_with(operator.as_bytes()) {
                if *operator == "(("
                    && !rest.get(2).is_some_and(|byte| {
                        byte.is_ascii_whitespace()
                            || matches!(byte, b'$' | b'!' | b'+' | b'-')
                            || byte.is_ascii_digit()
                            || *byte == b'\\' && rest.get(3) == Some(&b'\n')
                    })
                    && !rest
                        .split(|byte| *byte == b'\n')
                        .next()
                        .is_some_and(|line| line.windows(2).any(|window| window == b"))"))
                {
                    return Some("(");
                }
                if *operator == "[["
                    && (rest.starts_with(b"[[:")
                        || self.index > 0 && matches!(self.bytes[self.index - 1], b'(' | b'['))
                {
                    return None;
                }
                if matches!(*operator, "<" | ">") && self.bytes.get(self.index + 1) == Some(&b'(') {
                    return None;
                }
                if *operator == "{"
                    && self.bytes.get(self.index + 1).is_some_and(|next| {
                        !next.is_ascii_whitespace() && !matches!(next, b';' | b')')
                    })
                {
                    return None;
                }
                if self.dialect == ScriptDialect::Fish && matches!(*operator, "(" | ")" | "{" | "}")
                {
                    return None;
                }
                return Some(operator);
            }
        }
        None
    }

    fn word(&mut self) -> Result<String, ScriptParseError> {
        let start = self.index;
        let start_line = self.line;
        let mut quote = None;
        let mut single_quote_escapes = false;
        let mut escaped = false;
        let mut stack: Vec<u8> = Vec::new();
        let mut quote_restore: Vec<Option<u8>> = Vec::new();
        let mut implicit_zsh_parameter: Vec<bool> = Vec::new();
        let mut arithmetic_expansion_stack: Vec<bool> = Vec::new();
        let mut arithmetic_expansion_depth = 0_usize;
        let mut literal_parameter_braces = 0_usize;
        let mut parameter_bracket_depth = 0_usize;
        while self.index < self.bytes.len() {
            let byte = self.bytes[self.index];
            if escaped {
                if byte == b'\n' {
                    self.line += 1;
                }
                escaped = false;
                self.index += 1;
                continue;
            }
            if byte == b'\\'
                && (quote != Some(b'\'')
                    || self.dialect == ScriptDialect::Fish
                    || single_quote_escapes)
            {
                escaped = true;
                self.index += 1;
                continue;
            }
            if quote.is_none()
                && stack.last() == Some(&b')')
                && arithmetic_expansion_depth == 0
                && byte == b'#'
                && (self.index == start
                    || self.bytes[self.index - 1].is_ascii_whitespace()
                    || matches!(self.bytes[self.index - 1], b';' | b'&' | b'|'))
                && self
                    .bytes
                    .get(self.index + 1)
                    .is_none_or(|next| !matches!(next, b'#' | b'(' | b'~'))
            {
                while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                    self.index += 1;
                }
                continue;
            }
            if let Some(active) = quote {
                if active == b'"'
                    && byte == b'$'
                    && self
                        .bytes
                        .get(self.index + 1)
                        .is_some_and(|next| matches!(next, b'(' | b'{'))
                {
                    let open = self.bytes[self.index + 1];
                    stack.push(if open == b'(' { b')' } else { b'}' });
                    quote_restore.push(Some(active));
                    implicit_zsh_parameter.push(false);
                    let arithmetic = open == b'(' && self.bytes.get(self.index + 2) == Some(&b'(');
                    arithmetic_expansion_stack.push(arithmetic);
                    arithmetic_expansion_depth += usize::from(arithmetic);
                    quote = None;
                    self.index += 2;
                    continue;
                }
                if byte == active {
                    quote = None;
                    single_quote_escapes = false;
                } else if byte == b'\n' {
                    self.line += 1;
                }
                self.index += 1;
                continue;
            }
            if byte == b'\''
                && stack.last() == Some(&b'}')
                && quote_restore.last() == Some(&Some(b'"'))
            {
                self.index += 1;
                continue;
            }
            if matches!(byte, b'\'' | b'"' | b'`') {
                quote = Some(byte);
                single_quote_escapes = byte == b'\''
                    && (self.dialect == ScriptDialect::Fish
                        || self.index > start && self.bytes[self.index - 1] == b'$');
                self.index += 1;
                continue;
            }
            if byte == b'\n' {
                if stack.is_empty() {
                    break;
                }
                self.line += 1;
                self.index += 1;
                continue;
            }
            if stack.is_empty() {
                if byte.is_ascii_whitespace() {
                    break;
                }
                if let Some(operator) = self.operator() {
                    let embedded_open = self.index > start
                        && (matches!(operator, "(" | "((" | "[[")
                            || operator == "{" && self.bytes[self.index - 1] != b')');
                    if !embedded_open {
                        break;
                    }
                }
            }
            if matches!(byte, b'(' | b'{' | b'[') {
                let inside_parameter = stack.last() == Some(&b'}');
                let inside_bracket = stack.last() == Some(&b']');
                let bracket_has_close = byte != b'['
                    || !inside_parameter
                        && self.bytes[self.index + 1..]
                            .iter()
                            .take_while(|value| !value.is_ascii_whitespace())
                            .any(|value| *value == b']')
                        && (!inside_bracket
                            || self
                                .bytes
                                .get(self.index + 1)
                                .is_some_and(|value| matches!(value, b':' | b'.' | b'=')));
                let explicit_nested_expansion = self.index > start
                    && match byte {
                        b'(' => matches!(self.bytes[self.index - 1], b'$' | b'<' | b'>'),
                        b'{' => self.bytes[self.index - 1] == b'$',
                        b'[' => false,
                        _ => true,
                    };
                let nested_parameter_syntax = if inside_bracket {
                    explicit_nested_expansion
                } else {
                    !inside_parameter || explicit_nested_expansion
                };
                let is_expansion = if byte == b'[' {
                    bracket_has_close
                } else {
                    nested_parameter_syntax
                        && (byte != b'('
                            || self.dialect == ScriptDialect::Fish
                            || self.index > start)
                };
                if is_expansion {
                    let arithmetic = byte == b'('
                        && self.index > 0
                        && self.bytes[self.index - 1] == b'$'
                        && self.bytes.get(self.index + 1) == Some(&b'(');
                    let implicit_parameter = byte == b'{'
                        && self.dialect == ScriptDialect::Zsh
                        && inside_parameter
                        && self.index >= 2
                        && self.bytes[self.index - 2] == b'{';
                    stack.push(match byte {
                        b'(' => b')',
                        b'{' => b'}',
                        _ => b']',
                    });
                    quote_restore.push(None);
                    implicit_zsh_parameter.push(implicit_parameter);
                    arithmetic_expansion_stack.push(arithmetic);
                    arithmetic_expansion_depth += usize::from(arithmetic);
                } else if byte == b'[' && inside_parameter {
                    parameter_bracket_depth = parameter_bracket_depth.saturating_add(1);
                } else if byte == b'{' && inside_parameter && parameter_bracket_depth == 0 {
                    literal_parameter_braces = literal_parameter_braces.saturating_add(1);
                }
            } else if byte == b']' && parameter_bracket_depth > 0 {
                parameter_bracket_depth -= 1;
            } else if byte == b'}' && stack.last() == Some(&byte) && literal_parameter_braces > 0 {
                literal_parameter_braces -= 1;
            } else if stack.last() == Some(&byte) {
                stack.pop();
                quote = quote_restore.pop().flatten();
                let implicit_parameter = implicit_zsh_parameter.pop().unwrap_or(false);
                if arithmetic_expansion_stack.pop().unwrap_or(false) {
                    arithmetic_expansion_depth = arithmetic_expansion_depth.saturating_sub(1);
                }
                if byte == b'}'
                    && implicit_parameter
                    && stack.last() == Some(&b'}')
                    && self.bytes.get(self.index + 1).is_none_or(|next| {
                        next.is_ascii_whitespace() || matches!(next, b'\'' | b'"')
                    })
                {
                    stack.pop();
                    quote = quote_restore.pop().flatten().or(quote);
                    implicit_zsh_parameter.pop();
                    if arithmetic_expansion_stack.pop().unwrap_or(false) {
                        arithmetic_expansion_depth = arithmetic_expansion_depth.saturating_sub(1);
                    }
                }
            }
            self.index += 1;
        }
        if quote.is_some() || !stack.is_empty() {
            let preview = self.source.get(start..self.index).unwrap_or("");
            return self.error(format!(
                "unterminated quote or expansion from line {start_line} in {:?}",
                preview.chars().take(160).collect::<String>()
            ));
        }
        Ok(self.source[start..self.index].to_owned())
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, ScriptParseError> {
        Err(ScriptParseError {
            line: self.line,
            message: message.into(),
        })
    }
}

struct Parser {
    dialect: ScriptDialect,
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    fn new(dialect: ScriptDialect, tokens: Vec<Token>) -> Self {
        Self {
            dialect,
            tokens,
            index: 0,
        }
    }

    fn parse_list(&mut self, stops: &[&str]) -> Result<Vec<ScriptStatement>, ScriptParseError> {
        let mut statements = Vec::new();
        while self.index < self.tokens.len() {
            self.consume_separators();
            if self.index >= self.tokens.len()
                || self.at_stop(stops)
                || matches!(self.peek_operator(), Some("}" | ")"))
            {
                break;
            }
            let before = self.index;
            statements.push(self.parse_statement()?);
            if self.index == before {
                return self.error("parser made no progress");
            }
            while matches!(
                self.peek_operator(),
                Some("|" | "|&" | "&|" | "2>|" | "1>|")
            ) {
                self.index += 1;
                self.consume_separators();
                let right = self.parse_pipeline_component()?;
                let left = statements.pop().expect("statement was just inserted");
                let mut commands = match left {
                    ScriptStatement::Pipeline {
                        commands,
                        negated: false,
                    } => commands,
                    statement => vec![statement],
                };
                commands.push(right);
                statements.push(ScriptStatement::Pipeline {
                    commands,
                    negated: false,
                });
            }
            self.consume_separators();
            while matches!(
                self.peek_operator(),
                Some("|" | "|&" | "&|" | "2>|" | "1>|")
            ) {
                self.index += 1;
                self.consume_separators();
                let right = self.parse_pipeline_component()?;
                let left = statements.pop().expect("statement was just inserted");
                let mut commands = match left {
                    ScriptStatement::Pipeline {
                        commands,
                        negated: false,
                    } => commands,
                    statement => vec![statement],
                };
                commands.push(right);
                statements.push(ScriptStatement::Pipeline {
                    commands,
                    negated: false,
                });
                self.consume_separators();
            }
            while matches!(self.peek_operator(), Some("&&" | "||")) {
                let operator = if self.peek_operator() == Some("&&") {
                    ScriptBooleanOperator::And
                } else {
                    ScriptBooleanOperator::Or
                };
                self.index += 1;
                self.consume_separators();
                let right = self.parse_statement()?;
                let left = statements.pop().expect("statement was just inserted");
                statements.push(ScriptStatement::AndOr {
                    first: Box::new(left),
                    rest: vec![ScriptAndOrArm {
                        operator,
                        statement: Box::new(right),
                    }],
                });
                self.consume_separators();
            }
        }
        Ok(statements)
    }

    fn parse_statement(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        if self.dialect == ScriptDialect::Fish {
            return self.parse_fish_statement();
        }
        self.parse_bourne_statement()
    }

    fn parse_bourne_statement(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        let statement = match self.peek_word() {
            Some("if") => self.parse_bourne_if()?,
            Some("while") => self.parse_bourne_loop(false)?,
            Some("until") => self.parse_bourne_loop(true)?,
            Some("for" | "select") => self.parse_bourne_for()?,
            Some("foreach") if self.dialect == ScriptDialect::Zsh => self.parse_zsh_foreach()?,
            Some("case") => self.parse_bourne_case()?,
            Some("function") => self.parse_bourne_function(true)?,
            Some("return") => {
                self.index += 1;
                let status = self
                    .take_word()
                    .map(|raw| self.parse_word(&raw))
                    .transpose()?;
                ScriptStatement::Return { status }
            }
            Some("break") => {
                self.index += 1;
                ScriptStatement::Break
            }
            Some("continue") => {
                self.index += 1;
                ScriptStatement::Continue
            }
            _ if self.peek_operator() == Some("{") => self.parse_group(false)?,
            _ if self.peek_operator() == Some("(") => self.parse_group(true)?,
            _ if self.looks_like_bourne_function() => self.parse_bourne_function(false)?,
            _ => self.parse_and_or()?,
        };
        self.attach_trailing_redirections(statement)
    }

    fn parse_fish_statement(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        let statement = match self.peek_word() {
            Some("function") => self.parse_fish_function()?,
            Some("if") => self.parse_fish_if()?,
            Some("while") => self.parse_fish_while()?,
            Some("for") => self.parse_fish_for()?,
            Some("switch") => self.parse_fish_switch()?,
            Some("begin") => {
                self.index += 1;
                self.consume_separators();
                let body = self.parse_list(&["end"])?;
                self.expect_word("end")?;
                ScriptStatement::Group {
                    body,
                    subshell: false,
                }
            }
            Some("return") => {
                self.index += 1;
                let status = self
                    .take_word()
                    .map(|raw| self.parse_word(&raw))
                    .transpose()?;
                ScriptStatement::Return { status }
            }
            Some("break") => {
                self.index += 1;
                ScriptStatement::Break
            }
            Some("continue") => {
                self.index += 1;
                ScriptStatement::Continue
            }
            _ => self.parse_and_or()?,
        };
        self.attach_trailing_redirections(statement)
    }

    fn parse_and_or(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        let first = self.parse_pipeline()?;
        let mut rest = Vec::new();
        loop {
            let operator = match self.peek_operator() {
                Some("&&") => ScriptBooleanOperator::And,
                Some("||") => ScriptBooleanOperator::Or,
                _ => break,
            };
            self.index += 1;
            self.consume_separators();
            rest.push(ScriptAndOrArm {
                operator,
                statement: Box::new(self.parse_pipeline()?),
            });
        }
        if rest.is_empty() {
            Ok(first)
        } else {
            Ok(ScriptStatement::AndOr {
                first: Box::new(first),
                rest,
            })
        }
    }

    fn parse_pipeline(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        let mut negated = false;
        if self.peek_word() == Some("!") {
            self.index += 1;
            negated = true;
        }
        let mut commands = vec![self.parse_pipeline_component()?];
        while matches!(
            self.peek_operator(),
            Some("|" | "|&" | "&|" | "2>|" | "1>|")
        ) {
            self.index += 1;
            self.consume_separators();
            commands.push(self.parse_pipeline_component()?);
        }
        if commands.len() == 1 && !negated {
            Ok(commands.remove(0))
        } else {
            Ok(ScriptStatement::Pipeline { commands, negated })
        }
    }

    fn parse_pipeline_component(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        let statement = if self.peek_operator() == Some("{") {
            self.parse_group(false)?
        } else if self.peek_operator() == Some("(") {
            self.parse_group(true)?
        } else if self.dialect != ScriptDialect::Fish && self.looks_like_bourne_function() {
            self.parse_bourne_function(false)?
        } else {
            match (self.dialect, self.peek_word()) {
                (ScriptDialect::Fish, Some("while")) => self.parse_fish_while()?,
                (ScriptDialect::Fish, Some("for")) => self.parse_fish_for()?,
                (ScriptDialect::Fish, Some("begin")) => self.parse_fish_statement()?,
                (_, Some("while")) => self.parse_bourne_loop(false)?,
                (_, Some("until")) => self.parse_bourne_loop(true)?,
                (_, Some("for" | "select")) => self.parse_bourne_for()?,
                (ScriptDialect::Zsh, Some("foreach")) => self.parse_zsh_foreach()?,
                (_, Some("if")) => self.parse_bourne_if()?,
                (_, Some("case")) => self.parse_bourne_case()?,
                (_, Some("function")) => self.parse_bourne_function(true)?,
                _ => ScriptStatement::Command {
                    command: self.parse_simple_command()?,
                },
            }
        };
        self.attach_trailing_redirections(statement)
    }

    fn at_trailing_redirection(&self) -> bool {
        if self.peek_operator().is_some_and(is_redirection)
            || self
                .peek_operator()
                .and_then(split_inline_redirection)
                .is_some()
            || self
                .peek_word()
                .and_then(split_inline_redirection)
                .is_some()
        {
            return true;
        }
        matches!(
            (
                self.tokens.get(self.index).map(|token| &token.kind),
                self.tokens.get(self.index + 1).map(|token| &token.kind),
            ),
            (Some(TokenKind::Word(descriptor)), Some(TokenKind::Operator(operator)))
                if descriptor.bytes().all(|byte| byte.is_ascii_digit())
                    && is_redirection(operator)
        )
    }

    fn attach_trailing_redirections(
        &mut self,
        statement: ScriptStatement,
    ) -> Result<ScriptStatement, ScriptParseError> {
        let mut redirections = Vec::new();
        while self.at_trailing_redirection() {
            let redirected = self.parse_simple_command()?;
            if !redirected.words.is_empty() || !redirected.assignments.is_empty() {
                return self.error("compound redirection contains a command");
            }
            redirections.extend(redirected.redirections);
        }
        if redirections.is_empty() {
            return Ok(statement);
        }
        Ok(match statement {
            ScriptStatement::Redirected {
                statement,
                redirections: mut existing,
            } => {
                existing.extend(redirections);
                ScriptStatement::Redirected {
                    statement,
                    redirections: existing,
                }
            }
            statement => ScriptStatement::Redirected {
                statement: Box::new(statement),
                redirections,
            },
        })
    }

    fn parse_simple_command(&mut self) -> Result<ScriptCommand, ScriptParseError> {
        if matches!(self.peek_operator(), Some("[[" | "((")) {
            let opening = self.peek_operator().expect("operator checked").to_owned();
            let closing = if opening == "[[" { "]]" } else { "))" };
            self.index += 1;
            let mut words = vec![ScriptWord::literal(opening)];
            let mut regex_rhs = false;
            while self.index < self.tokens.len() && self.peek_operator() != Some(closing) {
                if regex_rhs {
                    let mut expression = String::new();
                    while self.index < self.tokens.len()
                        && self.peek_operator() != Some(closing)
                        && !matches!(
                            &self.tokens[self.index].kind,
                            TokenKind::Word(value) | TokenKind::Operator(value)
                                if matches!(value.as_str(), "&&" | "||")
                        )
                    {
                        match &self.tokens[self.index].kind {
                            TokenKind::Word(value) | TokenKind::Operator(value) => {
                                expression.push_str(value);
                            }
                        }
                        self.index += 1;
                    }
                    words.push(ScriptWord::literal(expression));
                    regex_rhs = false;
                    continue;
                }
                let word = match &self.tokens[self.index].kind {
                    TokenKind::Word(value) => self.parse_word(value)?,
                    TokenKind::Operator(value) => ScriptWord::literal(value),
                };
                regex_rhs = word.as_plain_literal() == Some("=~");
                words.push(word);
                self.index += 1;
            }
            if !self.consume_operator(closing) {
                return self.error(format!("test expression missing {closing}"));
            }
            words.push(ScriptWord::literal(closing));
            return Ok(ScriptCommand {
                assignments: Vec::new(),
                words,
                redirections: Vec::new(),
            });
        }
        let mut assignments = Vec::new();
        let mut words = Vec::new();
        let mut redirections = Vec::new();
        while self.index < self.tokens.len() && !self.simple_command_end() {
            if let Some(operator) = self.peek_operator() {
                if is_redirection(operator) {
                    let operator = operator.to_owned();
                    self.index += 1;
                    let target = self
                        .take_word()
                        .ok_or_else(|| self.make_error("redirection missing target"))?;
                    let descriptor = words
                        .last()
                        .and_then(ScriptWord::as_plain_literal)
                        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
                        .and_then(|value| value.parse::<u16>().ok());
                    if descriptor.is_some() {
                        words.pop();
                    }
                    redirections.push(ScriptRedirection {
                        descriptor,
                        operator,
                        target: self.parse_word(&target)?,
                    });
                    continue;
                }
                if let Some((descriptor, operator, target)) = split_inline_redirection(operator) {
                    let redirection = ScriptRedirection {
                        descriptor,
                        operator: operator.to_owned(),
                        target: self.parse_word(target)?,
                    };
                    self.index += 1;
                    redirections.push(redirection);
                    continue;
                }
                // Unknown punctuation is retained as an ordinary word so the
                // VM can apply dialect builtin semantics without parser loss.
                let value = operator.to_owned();
                self.index += 1;
                words.push(ScriptWord::literal(value));
                continue;
            }
            let raw = self.take_word().expect("word checked above");
            if let Some((descriptor, operator, target)) = split_inline_redirection(&raw) {
                redirections.push(ScriptRedirection {
                    descriptor,
                    operator: operator.to_owned(),
                    target: self.parse_word(target)?,
                });
                continue;
            }
            let declaration_command = words
                .first()
                .and_then(ScriptWord::as_plain_literal)
                .is_some_and(|name| {
                    matches!(
                        name,
                        "local" | "typeset" | "declare" | "export" | "readonly"
                    )
                });
            if words.is_empty() || declaration_command {
                if let Some(assignment) = self.parse_assignment(&raw)? {
                    assignments.push(assignment);
                    continue;
                }
            }
            words.push(self.parse_word(&raw)?);
        }
        if words.is_empty() && assignments.is_empty() && redirections.is_empty() {
            let context_start = self.index.saturating_sub(12);
            return self.error(format!(
                "expected command before {:?}; preceding tokens {:?}",
                self.tokens.get(self.index).map(|token| &token.kind),
                &self.tokens[context_start..self.index]
            ));
        }
        let mut command = ScriptCommand {
            assignments,
            words,
            redirections,
        };
        self.compile_deferred_eval_function(&mut command)?;
        self.compile_deferred_completion_api_actions(&mut command);
        Ok(command)
    }

    fn compile_deferred_completion_api_actions(&self, command: &mut ScriptCommand) {
        if self.dialect != ScriptDialect::Zsh
            || !matches!(
                command.words.first().and_then(ScriptWord::as_plain_literal),
                Some("_arguments" | "_alternative" | "_regex_arguments")
            )
        {
            return;
        }
        for word in command.words.iter_mut().skip(1) {
            *word = self.compile_deferred_completion_action_mode(word.clone(), true);
        }
    }

    fn compile_deferred_eval_function(
        &self,
        command: &mut ScriptCommand,
    ) -> Result<(), ScriptParseError> {
        if self.dialect == ScriptDialect::Fish
            || command.words.first().and_then(ScriptWord::as_plain_literal) != Some("eval")
            || command.words.len() != 2
            || command.words[1]
                .parts
                .iter()
                .any(|part| matches!(part, ScriptWordPart::DeferredScript { .. }))
        {
            return Ok(());
        }
        let prefix = format!("__bashlume_eval_{}_", self.index);
        let mut template = String::new();
        let mut captures = Vec::new();
        for part in &command.words[1].parts {
            if let ScriptWordPart::Literal { value, .. } = part {
                template.push_str(value);
            } else {
                let marker = format!("{prefix}{}", captures.len());
                if captures.is_empty() && template.trim().is_empty() {
                    template.push_str(&marker);
                } else {
                    template.push_str("${");
                    template.push_str(&marker);
                    template.push('}');
                }
                captures.push(ScriptWord {
                    parts: vec![part.clone()],
                    raw: None,
                });
            }
        }
        if !template.contains("()") || !template.contains('{') || captures.is_empty() {
            return Ok(());
        }
        let tokens = Lexer::new(self.dialect, &template).lex()?;
        let mut parser = Parser::new(self.dialect, tokens);
        let statements = parser.parse_list(&[])?;
        if !matches!(statements.as_slice(), [ScriptStatement::Function { .. }]) {
            return Ok(());
        }
        command.words[1] = ScriptWord {
            parts: vec![ScriptWordPart::DeferredScript {
                source: format!("eval-function:{prefix}"),
                statements,
                words: captures,
            }],
            raw: None,
        };
        Ok(())
    }

    fn parse_assignment(
        &mut self,
        raw: &str,
    ) -> Result<Option<ScriptAssignment>, ScriptParseError> {
        let Some(equal) = raw.find('=') else {
            return Ok(None);
        };
        let mut left = &raw[..equal];
        let append = left.ends_with('+');
        if append {
            left = &left[..left.len() - 1];
        }
        let (name, index) = if let Some(open) = left.find('[') {
            if !left.ends_with(']') {
                return Ok(None);
            }
            (
                &left[..open],
                Some(self.parse_word(&left[open + 1..left.len() - 1])?),
            )
        } else {
            (left, None)
        };
        if name.is_empty()
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
            })
        {
            return Ok(None);
        }
        let value = self.parse_assignment_value(&raw[equal + 1..])?;
        Ok(Some(ScriptAssignment {
            name: name.to_owned(),
            index,
            value: self.compile_deferred_assignment_script(value),
            append,
        }))
    }

    fn compile_deferred_assignment_script(&self, mut value: ScriptWord) -> ScriptWord {
        if self.dialect != ScriptDialect::Zsh {
            return value;
        }
        if value.parts.iter().any(|part| {
            matches!(
                part,
                ScriptWordPart::Array { .. } | ScriptWordPart::BraceExpansion { .. }
            )
        }) {
            for part in &mut value.parts {
                let words = match part {
                    ScriptWordPart::Array { elements }
                    | ScriptWordPart::BraceExpansion {
                        alternatives: elements,
                        ..
                    } => elements,
                    _ => continue,
                };
                for word in words {
                    *word = self.compile_deferred_completion_action_mode(word.clone(), true);
                }
            }
            return value;
        }
        let mut source = String::new();
        for part in &value.parts {
            let ScriptWordPart::Literal { value, .. } = part else {
                return value;
            };
            source.push_str(value);
        }
        let trimmed = source.trim();
        if source.contains('\0')
            || !(trimmed.starts_with('{')
                || source.contains('\n')
                    && (source.contains("_describe") || source.contains("compadd")))
        {
            return value;
        }
        let Ok(tokens) = Lexer::new(self.dialect, &source).lex() else {
            return value;
        };
        let mut parser = Parser::new(self.dialect, tokens);
        let Ok(statements) = parser.parse_list(&[]) else {
            return value;
        };
        if statements.is_empty() {
            return value;
        }
        ScriptWord {
            parts: vec![ScriptWordPart::DeferredScript {
                source,
                statements,
                words: Vec::new(),
            }],
            raw: value.raw,
        }
    }

    fn parse_assignment_value(&self, raw: &str) -> Result<ScriptWord, ScriptParseError> {
        if raw.starts_with('(') && raw.ends_with(')') {
            let inner = &raw[1..raw.len() - 1];
            let tokens = Lexer::new(self.dialect, inner).lex()?;
            let mut elements = Vec::new();
            for token in tokens {
                match token.kind {
                    TokenKind::Word(value) => elements.push(self.parse_word(&value)?),
                    TokenKind::Operator(value) if value != ";" => {
                        elements.push(ScriptWord::literal(value));
                    }
                    TokenKind::Operator(_) => {}
                }
            }
            return Ok(ScriptWord {
                parts: vec![ScriptWordPart::Array { elements }],
                raw: Some(raw.to_owned()),
            });
        }
        self.parse_word(raw)
    }

    fn parse_bourne_if(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("if")?;
        let mut branches = Vec::new();
        loop {
            let condition =
                if self.dialect == ScriptDialect::Zsh && self.peek_operator() != Some("{") {
                    self.parse_list(&["then", "{"])?
                } else {
                    self.parse_list(&["then"])?
                };
            if self.dialect == ScriptDialect::Zsh && self.peek_operator() == Some("{") {
                let body = match self.parse_group(false)? {
                    ScriptStatement::Group { body, .. } => body,
                    _ => unreachable!("parse_group always returns a group"),
                };
                branches.push(ScriptConditionalBranch { condition, body });
                self.consume_separators();
                if self.consume_word("elif") {
                    continue;
                }
                let otherwise = if self.consume_word("else") {
                    self.consume_separators();
                    match self.parse_group(false)? {
                        ScriptStatement::Group { body, .. } => body,
                        _ => unreachable!("parse_group always returns a group"),
                    }
                } else {
                    Vec::new()
                };
                return Ok(ScriptStatement::If {
                    branches,
                    otherwise,
                });
            }
            self.expect_word("then")?;
            self.consume_separators();
            let body = self.parse_list(&["elif", "else", "fi"])?;
            branches.push(ScriptConditionalBranch { condition, body });
            if self.consume_word("elif") {
                continue;
            }
            let otherwise = if self.consume_word("else") {
                self.consume_separators();
                self.parse_list(&["fi"])?
            } else {
                Vec::new()
            };
            self.expect_word("fi")?;
            return Ok(ScriptStatement::If {
                branches,
                otherwise,
            });
        }
    }

    fn parse_bourne_loop(&mut self, until: bool) -> Result<ScriptStatement, ScriptParseError> {
        self.index += 1;
        let condition = self.parse_list(&["do"])?;
        self.expect_word("do")?;
        self.consume_separators();
        let body = self.parse_list(&["done"])?;
        self.expect_word("done")?;
        Ok(ScriptStatement::While {
            condition,
            body,
            until,
        })
    }

    fn parse_bourne_for(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.index += 1;
        if self.consume_operator("((") {
            let mut expression = String::new();
            while self.index < self.tokens.len() && self.peek_operator() != Some("))") {
                if !expression.is_empty() {
                    expression.push(' ');
                }
                match &self.tokens[self.index].kind {
                    TokenKind::Word(value) | TokenKind::Operator(value) => {
                        expression.push_str(value)
                    }
                }
                self.index += 1;
            }
            if !self.consume_operator("))") {
                return self.error("arithmetic for loop missing ))");
            }
            self.consume_separators();
            let body = if self.dialect == ScriptDialect::Zsh && self.peek_operator() == Some("{") {
                match self.parse_group(false)? {
                    ScriptStatement::Group { body, .. } => body,
                    _ => unreachable!("parse_group always returns a group"),
                }
            } else {
                self.expect_word("do")?;
                self.consume_separators();
                let body = self.parse_list(&["done"])?;
                self.expect_word("done")?;
                body
            };
            return Ok(ScriptStatement::For {
                variables: Vec::new(),
                words: vec![ScriptWord {
                    parts: vec![ScriptWordPart::Arithmetic {
                        expression,
                        quoted: false,
                    }],
                    raw: None,
                }],
                body,
            });
        }
        let variable = self
            .take_word()
            .ok_or_else(|| self.make_error("for loop missing variable"))?;
        let mut variables = vec![variable];
        if self.dialect == ScriptDialect::Zsh {
            while self.peek_word().is_some_and(|word| word != "in")
                && self.peek_operator() != Some(";")
            {
                variables.push(self.take_word().expect("word checked"));
            }
        }
        let mut words = Vec::new();
        if self.dialect == ScriptDialect::Zsh && self.consume_operator("(") {
            let mut nested = 0_usize;
            while self.index < self.tokens.len() {
                match self.peek_operator() {
                    Some(")") if nested == 0 => {
                        self.index += 1;
                        break;
                    }
                    Some("(") => {
                        nested += 1;
                        words.push(ScriptWord::literal("("));
                        self.index += 1;
                    }
                    Some(")") => {
                        nested = nested.saturating_sub(1);
                        words.push(ScriptWord::literal(")"));
                        self.index += 1;
                    }
                    Some(operator) => {
                        words.push(ScriptWord::literal(operator));
                        self.index += 1;
                    }
                    None => {
                        let raw = self.take_word().expect("word checked");
                        words.push(self.parse_word(&raw)?);
                    }
                }
            }
        } else if self.consume_word("in") {
            while self.index < self.tokens.len()
                && self.peek_word() != Some("do")
                && self.peek_operator() != Some(";")
            {
                if let Some(raw) = self.take_word() {
                    words.push(self.parse_word(&raw)?);
                } else {
                    self.index += 1;
                }
            }
        }
        self.consume_separators();
        let body = if self.dialect == ScriptDialect::Zsh && self.peek_operator() == Some("{") {
            match self.parse_group(false)? {
                ScriptStatement::Group { body, .. } => body,
                _ => unreachable!("parse_group always returns a group"),
            }
        } else {
            self.expect_word("do")?;
            self.consume_separators();
            let body = self.parse_list(&["done"])?;
            self.expect_word("done")?;
            body
        };
        Ok(ScriptStatement::For {
            variables,
            words,
            body,
        })
    }

    fn parse_zsh_foreach(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("foreach")?;
        let variable = self
            .take_word()
            .ok_or_else(|| self.make_error("foreach missing variable"))?;
        let mut words = Vec::new();
        if self.consume_operator("(") {
            let mut nested = 0_usize;
            while self.index < self.tokens.len() {
                match self.peek_operator() {
                    Some(")") if nested == 0 => {
                        self.index += 1;
                        break;
                    }
                    Some("(") => {
                        nested += 1;
                        words.push(ScriptWord::literal("("));
                        self.index += 1;
                    }
                    Some(")") => {
                        nested = nested.saturating_sub(1);
                        words.push(ScriptWord::literal(")"));
                        self.index += 1;
                    }
                    Some(operator) => {
                        words.push(ScriptWord::literal(operator));
                        self.index += 1;
                    }
                    None => {
                        let raw = self.take_word().expect("word checked");
                        words.push(self.parse_word(&raw)?);
                    }
                }
            }
        } else {
            self.consume_word("in");
            while self.peek_operator() != Some(";") && self.index < self.tokens.len() {
                if let Some(raw) = self.take_word() {
                    words.push(self.parse_word(&raw)?);
                } else {
                    self.index += 1;
                }
            }
        }
        self.consume_separators();
        let body = if self.consume_word("do") {
            self.consume_separators();
            let body = self.parse_list(&["done"])?;
            self.expect_word("done")?;
            body
        } else {
            let body = self.parse_list(&["end"])?;
            self.expect_word("end")?;
            body
        };
        Ok(ScriptStatement::For {
            variables: vec![variable],
            words,
            body,
        })
    }

    fn parse_bourne_case(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("case")?;
        let word = if self.dialect == ScriptDialect::Zsh && self.consume_operator("(") {
            let mut word = ScriptWord {
                parts: Vec::new(),
                raw: None,
            };
            let mut nested = 0_usize;
            while self.index < self.tokens.len() {
                match self.peek_operator() {
                    Some(")") if nested == 0 => {
                        self.index += 1;
                        break;
                    }
                    Some("(") => {
                        nested += 1;
                        word.parts.push(ScriptWordPart::Literal {
                            value: "(".into(),
                            quoted: false,
                        });
                        self.index += 1;
                    }
                    Some(")") => {
                        nested = nested.saturating_sub(1);
                        word.parts.push(ScriptWordPart::Literal {
                            value: ")".into(),
                            quoted: false,
                        });
                        self.index += 1;
                    }
                    Some(operator) => {
                        word.parts.push(ScriptWordPart::Literal {
                            value: operator.to_owned(),
                            quoted: false,
                        });
                        self.index += 1;
                    }
                    None => {
                        let raw = self.take_word().expect("word checked");
                        word.parts.extend(self.parse_word(&raw)?.parts);
                    }
                }
            }
            word
        } else {
            let raw = self
                .take_word()
                .ok_or_else(|| self.make_error("case missing word"))?;
            self.parse_word(&raw)?
        };
        self.consume_separators();
        self.expect_word("in")?;
        self.consume_separators();
        let mut arms = Vec::new();
        while self.peek_word() != Some("esac") && self.index < self.tokens.len() {
            let arm_start_line = self.current_line();
            let mut patterns = Vec::new();
            let mut current = ScriptWord {
                parts: Vec::new(),
                raw: None,
            };
            let mut nested_parentheses = 0_usize;
            let mut zsh_parenthesized = false;
            let mut arm_closed = false;
            while self.index < self.tokens.len() {
                match self.peek_operator() {
                    Some(")") if nested_parentheses == 0 => break,
                    Some("((") => {
                        if self.dialect == ScriptDialect::Zsh
                            && current.parts.is_empty()
                            && patterns.is_empty()
                            && nested_parentheses == 0
                        {
                            zsh_parenthesized = true;
                            current.parts.push(ScriptWordPart::Literal {
                                value: "(".into(),
                                quoted: false,
                            });
                        } else {
                            current.parts.push(ScriptWordPart::Literal {
                                value: "((".into(),
                                quoted: false,
                            });
                        }
                        nested_parentheses += 2;
                        self.index += 1;
                    }
                    Some("(") => {
                        if self.dialect == ScriptDialect::Zsh
                            && current.parts.is_empty()
                            && patterns.is_empty()
                            && nested_parentheses == 0
                        {
                            zsh_parenthesized = true;
                        } else {
                            current.parts.push(ScriptWordPart::Literal {
                                value: "(".into(),
                                quoted: false,
                            });
                        }
                        nested_parentheses += 1;
                        self.index += 1;
                    }
                    Some("))") if zsh_parenthesized && nested_parentheses <= 2 => {
                        if nested_parentheses == 2 {
                            current.parts.push(ScriptWordPart::Literal {
                                value: ")".into(),
                                quoted: false,
                            });
                        }
                        self.index += 1;
                        arm_closed = true;
                        break;
                    }
                    Some("))") => {
                        current.parts.push(ScriptWordPart::Literal {
                            value: "))".into(),
                            quoted: false,
                        });
                        nested_parentheses = nested_parentheses.saturating_sub(2);
                        self.index += 1;
                    }
                    Some(")") if zsh_parenthesized && nested_parentheses == 1 => {
                        if self.has_later_case_closing_parenthesis() {
                            current.parts.insert(
                                0,
                                ScriptWordPart::Literal {
                                    value: "(".into(),
                                    quoted: false,
                                },
                            );
                            current.parts.push(ScriptWordPart::Literal {
                                value: ")".into(),
                                quoted: false,
                            });
                            nested_parentheses = 0;
                            zsh_parenthesized = false;
                            self.index += 1;
                        } else {
                            self.index += 1;
                            arm_closed = true;
                            break;
                        }
                    }
                    Some(")") => {
                        current.parts.push(ScriptWordPart::Literal {
                            value: ")".into(),
                            quoted: false,
                        });
                        nested_parentheses = nested_parentheses.saturating_sub(1);
                        self.index += 1;
                    }
                    Some("|") if nested_parentheses == 0 => {
                        if !current.parts.is_empty() {
                            patterns.push(std::mem::replace(
                                &mut current,
                                ScriptWord {
                                    parts: Vec::new(),
                                    raw: None,
                                },
                            ));
                        }
                        self.index += 1;
                    }
                    Some(operator) => {
                        current.parts.push(ScriptWordPart::Literal {
                            value: operator.to_owned(),
                            quoted: false,
                        });
                        self.index += 1;
                    }
                    None => {
                        let raw = self.take_word().expect("word checked");
                        current.parts.extend(self.parse_word(&raw)?.parts);
                    }
                }
            }
            if !current.parts.is_empty() {
                patterns.push(current);
            }
            if !arm_closed && !self.consume_operator(")") {
                let start = self.index.saturating_sub(12);
                return self.error(format!(
                    "case arm from line {arm_start_line} missing ); preceding tokens {:?}",
                    &self.tokens[start..self.index]
                ));
            }
            let body = self.parse_list(&[";;", ";&", ";;&", ";|", "esac", "__zsh_case_arm"])?;
            let terminator = self.peek_operator().map(str::to_owned);
            if terminator.is_some() {
                self.index += 1;
            }
            arms.push(ScriptCaseArm {
                patterns,
                body,
                fallthrough: matches!(terminator.as_deref(), Some(";&")),
                continue_matching: matches!(terminator.as_deref(), Some(";;&" | ";|")),
            });
            self.consume_separators();
        }
        self.expect_word("esac")?;
        Ok(ScriptStatement::Case { word, arms })
    }

    fn parse_bourne_function(
        &mut self,
        function_keyword: bool,
    ) -> Result<ScriptStatement, ScriptParseError> {
        if function_keyword {
            self.index += 1;
            if self.dialect == ScriptDialect::Zsh && self.peek_operator() == Some("{") {
                return self.parse_group(false);
            }
        }
        let mut name = self
            .take_word()
            .ok_or_else(|| self.make_error("function missing name"))?;
        if let Some(stripped) = name.strip_suffix("()") {
            name = stripped.to_owned();
        } else if self.peek_operator() == Some("(") {
            self.index += 1;
            self.consume_operator(")");
        }
        self.consume_separators();
        let body = match self.parse_bourne_statement()? {
            ScriptStatement::Group { body, .. } => body,
            statement => vec![statement],
        };
        Ok(ScriptStatement::Function {
            function: ScriptFunction {
                name,
                arguments: Vec::new(),
                body,
            },
        })
    }

    fn parse_group(&mut self, subshell: bool) -> Result<ScriptStatement, ScriptParseError> {
        let close = if subshell { ")" } else { "}" };
        self.index += 1;
        self.consume_separators();
        let body = self.parse_list(&[close])?;
        if self.peek_operator() == Some(close) {
            self.index += 1;
        } else {
            return self.error(format!(
                "group missing {close}; before {:?}",
                self.tokens.get(self.index)
            ));
        }
        Ok(ScriptStatement::Group { body, subshell })
    }

    fn parse_fish_function(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("function")?;
        let name = self
            .take_word()
            .ok_or_else(|| self.make_error("function missing name"))?;
        let mut arguments = Vec::new();
        while self.peek_operator() != Some(";") && self.index < self.tokens.len() {
            if let Some(raw) = self.take_word() {
                arguments.push(self.parse_word(&raw)?);
            } else {
                self.index += 1;
            }
        }
        self.consume_separators();
        let body = self.parse_list(&["end"])?;
        self.expect_word("end")?;
        Ok(ScriptStatement::Function {
            function: ScriptFunction {
                name,
                arguments,
                body,
            },
        })
    }

    fn parse_fish_if(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("if")?;
        let mut branches = Vec::new();
        loop {
            let condition = vec![self.parse_and_or()?];
            self.consume_separators();
            let body = self.parse_list(&["else", "end"])?;
            branches.push(ScriptConditionalBranch { condition, body });
            if self.consume_word("else") {
                if self.consume_word("if") {
                    continue;
                }
                self.consume_separators();
                let otherwise = self.parse_list(&["end"])?;
                self.expect_word("end")?;
                return Ok(ScriptStatement::If {
                    branches,
                    otherwise,
                });
            }
            self.expect_word("end")?;
            return Ok(ScriptStatement::If {
                branches,
                otherwise: Vec::new(),
            });
        }
    }

    fn parse_fish_while(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("while")?;
        let condition = vec![self.parse_and_or()?];
        self.consume_separators();
        let body = self.parse_list(&["end"])?;
        self.expect_word("end")?;
        Ok(ScriptStatement::While {
            condition,
            body,
            until: false,
        })
    }

    fn parse_fish_for(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("for")?;
        let variable = self
            .take_word()
            .ok_or_else(|| self.make_error("for missing variable"))?;
        self.consume_word("in");
        let mut words = Vec::new();
        while self.peek_operator() != Some(";") && self.index < self.tokens.len() {
            if let Some(raw) = self.take_word() {
                words.push(self.parse_word(&raw)?);
            } else {
                self.index += 1;
            }
        }
        self.consume_separators();
        let body = self.parse_list(&["end"])?;
        self.expect_word("end")?;
        Ok(ScriptStatement::For {
            variables: vec![variable],
            words,
            body,
        })
    }

    fn parse_fish_switch(&mut self) -> Result<ScriptStatement, ScriptParseError> {
        self.expect_word("switch")?;
        let raw = self
            .take_word()
            .ok_or_else(|| self.make_error("switch missing word"))?;
        let word = self.parse_word(&raw)?;
        self.consume_separators();
        let mut arms = Vec::new();
        while self.index < self.tokens.len() && self.peek_word() != Some("end") {
            self.expect_word("case")?;
            let mut patterns = Vec::new();
            while self.peek_operator() != Some(";") && self.index < self.tokens.len() {
                if let Some(raw) = self.take_word() {
                    patterns.push(self.parse_word(&raw)?);
                } else {
                    self.index += 1;
                }
            }
            self.consume_separators();
            let body = self.parse_list(&["case", "end"])?;
            arms.push(ScriptCaseArm {
                patterns,
                body,
                fallthrough: false,
                continue_matching: false,
            });
        }
        self.expect_word("end")?;
        Ok(ScriptStatement::Case { word, arms })
    }

    fn parse_word(&self, raw: &str) -> Result<ScriptWord, ScriptParseError> {
        let word = parse_word_parts(self.dialect, raw).map_err(|message| {
            let mut preview = raw.chars().take(256).collect::<String>();
            if preview.len() < raw.len() {
                preview.push('…');
            }
            ScriptParseError {
                line: self.current_line(),
                message: format!("{message} in word {preview:?}"),
            }
        })?;
        Ok(self.compile_deferred_completion_action(word))
    }

    fn compile_deferred_completion_action(&self, word: ScriptWord) -> ScriptWord {
        self.compile_deferred_completion_action_mode(word, false)
    }

    fn compile_deferred_completion_action_mode(
        &self,
        word: ScriptWord,
        completion_api_argument: bool,
    ) -> ScriptWord {
        if self.dialect != ScriptDialect::Zsh {
            return word;
        }
        let mut source = String::new();
        for part in &word.parts {
            let ScriptWordPart::Literal { value, .. } = part else {
                return word;
            };
            source.push_str(value);
        }
        if completion_api_argument {
            if let Some(guard) = source.strip_prefix('-').filter(|guard| {
                guard.starts_with("[[")
                    || guard.starts_with("((")
                    || guard.split_once('=').is_some_and(|(name, _)| {
                        let name = name.trim_end_matches('+');
                        !name.is_empty()
                            && name.bytes().enumerate().all(|(index, byte)| {
                                byte == b'_'
                                    || byte.is_ascii_alphabetic()
                                    || index > 0 && byte.is_ascii_digit()
                            })
                    })
            }) {
                if let Ok(tokens) = Lexer::new(self.dialect, guard).lex() {
                    let mut parser = Parser::new(self.dialect, tokens);
                    if let Ok(statements) = parser.parse_list(&[]) {
                        if !statements.is_empty() {
                            return ScriptWord {
                                parts: vec![ScriptWordPart::DeferredScript {
                                    source,
                                    statements,
                                    words: Vec::new(),
                                }],
                                raw: word.raw,
                            };
                        }
                    }
                }
            }
        }
        let mut action = if completion_api_argument {
            let mut colons = Vec::new();
            let mut depth = 0_i32;
            let mut escaped = false;
            for (index, character) in source.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                match character {
                    '\\' => escaped = true,
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth = depth.saturating_sub(1),
                    ':' if depth == 0 => colons.push(index),
                    _ => {}
                }
            }
            if colons.len() < 2 {
                return word;
            }
            let head = source[..colons[0]].trim();
            let head_is_excluded_option = head.starts_with('(')
                && matching_delimiter(self.dialect, head, 0, b'(', b')', false)
                    .ok()
                    .and_then(|close| head.get(close + 1..))
                    .is_some_and(|tail| {
                        tail.trim_start_matches(['*', '+', '!'])
                            .starts_with(['-', '{'])
                    });
            if head.chars().any(char::is_whitespace) && !head_is_excluded_option {
                return word;
            }
            let action_colon = if colons[1] == colons[0] + 1 {
                let Some(colon) = colons.get(2) else {
                    return word;
                };
                *colon
            } else {
                colons[1]
            };
            &source[action_colon + 1..]
        } else {
            let Some(action_start) = source.rfind(":{").map(|colon| colon + 1) else {
                return word;
            };
            &source[action_start..]
        };
        let normalized_action;
        if completion_api_argument && !action.starts_with('{') && action.contains('\n') {
            normalized_action = action
                .replace("\\\r\n", "")
                .replace("\\\n", "")
                .replace(['\r', '\n'], " ");
            action = &normalized_action;
        }
        if completion_api_argument && action.starts_with('(') && action.ends_with(')') {
            let mut body = &action[1..action.len() - 1];
            if body.starts_with('(')
                && body.ends_with(')')
                && matching_delimiter(self.dialect, body, 0, b'(', b')', false).ok()
                    == body.len().checked_sub(1)
            {
                body = &body[1..body.len() - 1];
            }
            let Ok(tokens) = Lexer::new(self.dialect, body).lex() else {
                return word;
            };
            let mut parser = Parser::new(self.dialect, tokens);
            let Ok(statements) = parser.parse_list(&[]) else {
                return word;
            };
            let words = statements
                .into_iter()
                .flat_map(|statement| match statement {
                    ScriptStatement::Command { command } => command.words,
                    _ => Vec::new(),
                })
                .collect::<Vec<_>>();
            if words.is_empty() {
                return word;
            }
            return ScriptWord {
                parts: vec![ScriptWordPart::DeferredScript {
                    source,
                    statements: Vec::new(),
                    words,
                }],
                raw: word.raw,
            };
        }
        let plain_action = action.trim_start();
        if action.starts_with("->")
            || plain_action.is_empty()
            || !completion_api_argument && !action.starts_with('{')
            || !action.starts_with(['(', '{'])
                && !plain_action.starts_with('_')
                && !plain_action.starts_with("compadd")
                && !plain_action.starts_with("noglob ")
                && !plain_action.starts_with("command ")
        {
            return word;
        }
        if action.starts_with('{')
            && matching_delimiter(self.dialect, action, 0, b'{', b'}', false).ok()
                != action.len().checked_sub(1)
        {
            return word;
        }
        let Ok(tokens) = Lexer::new(self.dialect, action).lex() else {
            return word;
        };
        let mut parser = Parser::new(self.dialect, tokens);
        let Ok(statements) = parser.parse_list(&[]) else {
            return word;
        };
        if statements.is_empty() {
            return word;
        }
        ScriptWord {
            parts: vec![ScriptWordPart::DeferredScript {
                source,
                statements,
                words: Vec::new(),
            }],
            raw: word.raw,
        }
    }

    fn looks_like_bourne_function(&self) -> bool {
        let Some(name) = self.tokens.get(self.index).and_then(Token::word) else {
            return false;
        };
        name.strip_suffix("()").is_some_and(is_function_name)
            || is_function_name(name)
                && self.tokens.get(self.index + 1).and_then(Token::operator) == Some("(")
                && self.tokens.get(self.index + 2).and_then(Token::operator) == Some(")")
    }

    fn simple_command_end(&self) -> bool {
        matches!(
            self.peek_operator(),
            Some(
                ";" | "&&"
                    | "||"
                    | "|"
                    | "|&"
                    | "&|"
                    | "2>|"
                    | "1>|"
                    | "&"
                    | ")"
                    | "}"
                    | ";;"
                    | ";&"
                    | ";;&"
                    | ";|"
            )
        )
    }

    fn at_stop(&self, stops: &[&str]) -> bool {
        stops.iter().any(|stop| {
            *stop == "__zsh_case_arm" && self.looks_like_zsh_case_arm()
                || self.peek_word() == Some(*stop)
                || self.peek_operator() == Some(*stop)
        })
    }

    fn has_later_case_closing_parenthesis(&self) -> bool {
        let line = self.tokens.get(self.index).map(|token| token.line);
        self.tokens[self.index + 1..].iter().any(|token| {
            if Some(token.line) != line
                || matches!(token.operator(), Some(";" | ";;" | ";&" | ";;&" | ";|"))
            {
                return false;
            }
            matches!(token.operator(), Some(")" | "))"))
        })
    }

    fn looks_like_zsh_case_arm(&self) -> bool {
        if self.dialect != ScriptDialect::Zsh {
            return false;
        }
        if matches!(
            self.peek_word(),
            Some(
                "if" | "while"
                    | "until"
                    | "for"
                    | "select"
                    | "case"
                    | "function"
                    | "return"
                    | "break"
                    | "continue"
            )
        ) {
            return false;
        }
        let line = match self.tokens.get(self.index) {
            Some(token) => token.line,
            None => return false,
        };
        let mut last = None;
        for token in &self.tokens[self.index..] {
            if token.line != line || token.operator() == Some(";") {
                break;
            }
            last = Some(token);
        }
        last.and_then(Token::operator) == Some(")")
    }

    fn consume_separators(&mut self) {
        while matches!(self.peek_operator(), Some(";" | "&")) {
            self.index += 1;
        }
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        if self.peek_word() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, expected: &str) -> Result<(), ScriptParseError> {
        if self.consume_word(expected) {
            Ok(())
        } else {
            self.error(format!(
                "expected {expected:?}, found {:?}",
                self.tokens.get(self.index).map(|token| &token.kind)
            ))
        }
    }

    fn consume_operator(&mut self, expected: &str) -> bool {
        if self.peek_operator() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek_word(&self) -> Option<&str> {
        self.tokens.get(self.index).and_then(Token::word)
    }

    fn peek_operator(&self) -> Option<&str> {
        self.tokens.get(self.index).and_then(Token::operator)
    }

    fn take_word(&mut self) -> Option<String> {
        let value = self.peek_word()?.to_owned();
        self.index += 1;
        Some(value)
    }

    fn current_line(&self) -> usize {
        self.tokens.get(self.index).map_or(1, |token| token.line)
    }

    fn make_error(&self, message: impl Into<String>) -> ScriptParseError {
        ScriptParseError {
            line: self.current_line(),
            message: message.into(),
        }
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, ScriptParseError> {
        Err(self.make_error(message))
    }
}

fn is_function_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte == b'-' || byte.is_ascii_alphanumeric())
}

fn split_inline_redirection(value: &str) -> Option<(Option<u16>, &str, &str)> {
    if matches!(value, "|" | "|&" | "&|" | "2>|" | "1>|") {
        return None;
    }
    let descriptor_end = value.bytes().take_while(u8::is_ascii_digit).count();
    let descriptor = if descriptor_end == 0 {
        None
    } else {
        value[..descriptor_end].parse().ok()
    };
    let rest = &value[descriptor_end..];
    for operator in [
        "<<<", "<<-", ">>!", ">!", ">>", "<<", ">&", "<&", ">|", "<>", ">", "<",
    ] {
        if let Some(target) = rest.strip_prefix(operator) {
            if !target.is_empty() {
                return Some((descriptor, operator, target));
            }
        }
    }
    None
}

fn is_redirection(value: &str) -> bool {
    matches!(
        value,
        "<" | ">"
            | ">>"
            | ">!"
            | ">>!"
            | "<<"
            | "<<-"
            | "<<<"
            | "<&"
            | ">&"
            | "<>"
            | ">|"
            | "&>"
            | "&>>"
    )
}

fn expand_raw_brace_once(raw: &str) -> Option<Vec<String>> {
    let bytes = raw.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut open = None;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'{' && (index == 0 || bytes[index - 1] != b'$') {
            open = Some(index);
            break;
        }
        index += 1;
    }
    let open = open?;
    let mut depth = 1_usize;
    let mut starts = vec![open + 1];
    let mut ranges = Vec::new();
    quote = None;
    escaped = false;
    index = open + 1;
    let close = loop {
        let byte = *bytes.get(index)?;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                ranges.push((*starts.last()?, index));
                break index;
            }
        } else if byte == b',' && depth == 1 {
            ranges.push((*starts.last()?, index));
            starts.push(index + 1);
        }
        index += 1;
    };
    let mut alternatives = ranges
        .iter()
        .map(|(start, end)| raw[*start..*end].to_owned())
        .collect::<Vec<_>>();
    if alternatives.len() == 1 {
        alternatives.clear();
        let body = &raw[open + 1..close];
        if let Some((first, last)) = body.split_once("..") {
            if let (Ok(first), Ok(last)) = (first.parse::<i64>(), last.parse::<i64>()) {
                if first.abs_diff(last) < 4096 {
                    if first <= last {
                        alternatives.extend((first..=last).map(|value| value.to_string()));
                    } else {
                        alternatives.extend((last..=first).rev().map(|value| value.to_string()));
                    }
                }
            } else if first.chars().count() == 1 && last.chars().count() == 1 {
                let first = first.chars().next()? as u32;
                let last = last.chars().next()? as u32;
                if first.abs_diff(last) < 4096 {
                    if first <= last {
                        alternatives
                            .extend((first..=last).filter_map(char::from_u32).map(String::from));
                    } else {
                        alternatives.extend(
                            (last..=first)
                                .rev()
                                .filter_map(char::from_u32)
                                .map(String::from),
                        );
                    }
                }
            }
        }
    }
    if alternatives.len() < 2 {
        return None;
    }
    let fixed_bytes = open.saturating_add(raw.len().saturating_sub(close + 1));
    let expanded_bytes = alternatives.iter().fold(0_usize, |total, alternative| {
        total
            .saturating_add(fixed_bytes)
            .saturating_add(alternative.len())
    });
    if alternatives.len() > 4096 || expanded_bytes > MAX_SCRIPT_SOURCE_BYTES {
        return Some(Vec::new());
    }
    Some(
        alternatives
            .into_iter()
            .map(|alternative| format!("{}{}{}", &raw[..open], alternative, &raw[close + 1..]))
            .collect(),
    )
}

fn parse_word_parts(dialect: ScriptDialect, raw: &str) -> Result<ScriptWord, String> {
    let _guard = enter_word_parse(raw.len())?;
    if dialect != ScriptDialect::Fish {
        if let Some(expanded) = expand_raw_brace_once(raw) {
            if expanded.is_empty() || expanded.len() > 4096 {
                return Err("brace expansion resource limit exceeded".into());
            }
            let alternatives = expanded
                .iter()
                .map(|value| parse_word_parts(dialect, value))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(ScriptWord {
                parts: vec![ScriptWordPart::BraceExpansion {
                    alternatives,
                    quoted: false,
                }],
                raw: Some(raw.to_owned()),
            });
        }
    }
    let bytes = raw.as_bytes();
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut index = 0;
    let mut quoted = false;
    while index < bytes.len() {
        match bytes[index] {
            b'$' if !quoted && bytes.get(index + 1) == Some(&b'\'') => {
                flush_literal(&mut parts, &mut literal, quoted);
                let mut end = index + 2;
                let mut escaped = false;
                while end < bytes.len() {
                    if escaped {
                        escaped = false;
                    } else if bytes[end] == b'\\' {
                        escaped = true;
                    } else if bytes[end] == b'\'' {
                        break;
                    }
                    end += 1;
                }
                if end >= bytes.len() {
                    return Err("unterminated ANSI-C quote".into());
                }
                parts.push(ScriptWordPart::Literal {
                    value: decode_ansi_c(&raw[index + 2..end]),
                    quoted: true,
                });
                index = end + 1;
            }
            b'\'' if !quoted => {
                flush_literal(&mut parts, &mut literal, quoted);
                let mut end = index + 1;
                let mut value = String::new();
                while end < bytes.len() {
                    if dialect == ScriptDialect::Fish
                        && bytes[end] == b'\\'
                        && end + 1 < bytes.len()
                        && matches!(bytes[end + 1], b'\\' | b'\'')
                    {
                        value.push(bytes[end + 1] as char);
                        end += 2;
                    } else if bytes[end] == b'\'' {
                        break;
                    } else if bytes[end].is_ascii() {
                        value.push(bytes[end] as char);
                        end += 1;
                    } else {
                        let character = raw[end..]
                            .chars()
                            .next()
                            .ok_or_else(|| "invalid UTF-8 quote".to_owned())?;
                        value.push(character);
                        end += character.len_utf8();
                    }
                }
                if end >= bytes.len() {
                    return Err("unterminated single quote".into());
                }
                parts.push(ScriptWordPart::Literal {
                    value,
                    quoted: true,
                });
                index = end + 1;
            }
            b'"' => {
                flush_literal(&mut parts, &mut literal, quoted);
                quoted = !quoted;
                index += 1;
            }
            b'\\' if index + 1 < bytes.len() => {
                if dialect == ScriptDialect::Fish && quoted {
                    match bytes[index + 1] {
                        b'$' | b'"' | b'\\' => literal.push(bytes[index + 1] as char),
                        b'\n' => {}
                        value => {
                            literal.push('\\');
                            literal.push(value as char);
                        }
                    }
                } else if quoted {
                    match bytes[index + 1] {
                        b'$' | b'`' | b'"' | b'\\' => literal.push(bytes[index + 1] as char),
                        b'\n' => {}
                        value => {
                            literal.push('\\');
                            literal.push(value as char);
                        }
                    }
                } else {
                    flush_literal(&mut parts, &mut literal, false);
                    if bytes[index + 1] != b'\n' {
                        let value = if dialect == ScriptDialect::Fish {
                            match bytes[index + 1] {
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                b'e' => '\u{1b}',
                                value => value as char,
                            }
                        } else {
                            bytes[index + 1] as char
                        };
                        parts.push(ScriptWordPart::Literal {
                            value: value.to_string(),
                            quoted: true,
                        });
                    }
                }
                index += 2;
            }
            b'`' if dialect != ScriptDialect::Fish => {
                let mut end = index + 1;
                let mut escaped = false;
                while end < bytes.len() {
                    if escaped {
                        escaped = false;
                    } else if bytes[end] == b'\\' {
                        escaped = true;
                    } else if bytes[end] == b'`' {
                        break;
                    }
                    end += 1;
                }
                if end >= bytes.len() {
                    literal.push('`');
                    index += 1;
                    continue;
                }
                flush_literal(&mut parts, &mut literal, quoted);
                let inner = &raw[index + 1..end];
                let tokens = Lexer::new(dialect, inner)
                    .lex()
                    .map_err(|error| error.to_string())?;
                let mut parser = Parser::new(dialect, tokens);
                let statements = parser.parse_list(&[]).map_err(|error| error.to_string())?;
                parts.push(ScriptWordPart::CommandSubstitution { statements, quoted });
                index = end + 1;
            }
            b'$' if index + 2 < bytes.len()
                && bytes[index + 1] == b'('
                && bytes[index + 2] == b'(' =>
            {
                flush_literal(&mut parts, &mut literal, quoted);
                let end = matching_delimiter(dialect, raw, index + 1, b'(', b')', false)?;
                if end <= index + 3 || bytes.get(end.wrapping_sub(1)) != Some(&b')') {
                    return Err("malformed arithmetic expansion".into());
                }
                parts.push(ScriptWordPart::Arithmetic {
                    expression: raw[index + 3..end - 1].to_owned(),
                    quoted,
                });
                index = end + 1;
            }
            b'$' if index + 1 < bytes.len() && bytes[index + 1] == b'(' => {
                flush_literal(&mut parts, &mut literal, quoted);
                let end = matching_delimiter(dialect, raw, index + 1, b'(', b')', false)?;
                let inner = &raw[index + 2..end];
                let tokens = Lexer::new(dialect, inner)
                    .lex()
                    .map_err(|error| error.to_string())?;
                let mut parser = Parser::new(dialect, tokens);
                let statements = parser.parse_list(&[]).map_err(|error| error.to_string())?;
                parts.push(ScriptWordPart::CommandSubstitution { statements, quoted });
                index = end + 1;
            }
            b'$' if index + 1 < bytes.len() && bytes[index + 1] == b'{' => {
                flush_literal(&mut parts, &mut literal, quoted);
                let end = matching_delimiter(dialect, raw, index + 1, b'{', b'}', quoted)?;
                let expression = &raw[index + 2..end];
                if dialect == ScriptDialect::Zsh {
                    if let Some(inner) = zsh_parameter_command_substitution(expression) {
                        let tokens = Lexer::new(dialect, inner)
                            .lex()
                            .map_err(|error| error.to_string())?;
                        let mut parser = Parser::new(dialect, tokens);
                        let statements =
                            parser.parse_list(&[]).map_err(|error| error.to_string())?;
                        parts.push(ScriptWordPart::CommandSubstitution {
                            statements,
                            quoted: false,
                        });
                    } else {
                        parts.push(ScriptWordPart::Parameter {
                            expression: expression.to_owned(),
                            quoted,
                        });
                    }
                } else {
                    parts.push(ScriptWordPart::Parameter {
                        expression: expression.to_owned(),
                        quoted,
                    });
                }
                index = end + 1;
            }
            b'$' => {
                flush_literal(&mut parts, &mut literal, quoted);
                let start = index + 1;
                let mut name_start = start;
                let mut end = start;
                if dialect == ScriptDialect::Zsh
                    && bytes
                        .get(start)
                        .is_some_and(|byte| matches!(byte, b'#' | b'+' | b'^' | b'='))
                    && bytes
                        .get(start + 1)
                        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
                {
                    name_start += 1;
                    end += 1;
                    while end < bytes.len()
                        && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric())
                    {
                        end += 1;
                    }
                } else if bytes.get(start).is_some_and(|byte| {
                    matches!(byte, b'@' | b'*' | b'#' | b'?' | b'!' | b'$' | b'-')
                }) {
                    end += 1;
                } else {
                    while end < bytes.len()
                        && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric())
                    {
                        end += 1;
                    }
                }
                if bytes
                    .get(name_start)
                    .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
                    && end < bytes.len()
                    && bytes[end] == b'['
                {
                    if let Ok(close) = matching_delimiter(dialect, raw, end, b'[', b']', quoted) {
                        end = close + 1;
                    }
                }
                if dialect == ScriptDialect::Zsh {
                    while bytes.get(end) == Some(&b':')
                        && bytes.get(end + 1).is_some_and(|modifier| {
                            matches!(modifier, b'e' | b'h' | b'l' | b'q' | b'r' | b't' | b'u')
                        })
                    {
                        end += 2;
                    }
                }
                if end == start {
                    literal.push('$');
                    index += 1;
                } else {
                    parts.push(ScriptWordPart::Parameter {
                        expression: raw[start..end].to_owned(),
                        quoted,
                    });
                    index = end;
                }
            }
            b'(' if dialect == ScriptDialect::Fish && !quoted => {
                flush_literal(&mut parts, &mut literal, quoted);
                let end = matching_delimiter(dialect, raw, index, b'(', b')', false)?;
                let inner = &raw[index + 1..end];
                let tokens = Lexer::new(dialect, inner)
                    .lex()
                    .map_err(|error| error.to_string())?;
                let mut parser = Parser::new(dialect, tokens);
                let statements = parser.parse_list(&[]).map_err(|error| error.to_string())?;
                parts.push(ScriptWordPart::CommandSubstitution { statements, quoted });
                index = end + 1;
            }
            byte if !byte.is_ascii() => {
                let character = raw[index..]
                    .chars()
                    .next()
                    .ok_or_else(|| "invalid UTF-8 word boundary".to_owned())?;
                literal.push(character);
                index += character.len_utf8();
            }
            byte => {
                literal.push(byte as char);
                index += 1;
            }
        }
    }
    flush_literal(&mut parts, &mut literal, quoted);
    if parts.is_empty() {
        parts.push(ScriptWordPart::Literal {
            value: String::new(),
            quoted,
        });
    }
    Ok(ScriptWord {
        parts,
        raw: Some(raw.to_owned()),
    })
}

fn decode_ansi_c(value: &str) -> String {
    let mut output = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('a') => output.push('\u{7}'),
            Some('b') => output.push('\u{8}'),
            Some('e' | 'E') => output.push('\u{1b}'),
            Some('f') => output.push('\u{c}'),
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some('t') => output.push('\t'),
            Some('v') => output.push('\u{b}'),
            Some('\\') => output.push('\\'),
            Some('\'') => output.push('\''),
            Some('"') => output.push('"'),
            Some(other) => {
                output.push('\\');
                output.push(other);
            }
            None => output.push('\\'),
        }
    }
    output
}

fn flush_literal(parts: &mut Vec<ScriptWordPart>, literal: &mut String, quoted: bool) {
    if !literal.is_empty() {
        parts.push(ScriptWordPart::Literal {
            value: std::mem::take(literal),
            quoted,
        });
    }
}

fn zsh_parameter_command_substitution(mut expression: &str) -> Option<&str> {
    expression = expression.trim();
    while expression.starts_with('(') {
        let close = expression.find(')')?;
        let flags = &expression[1..close];
        if flags.is_empty()
            || !flags
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@_%^=+-".contains(&byte))
        {
            break;
        }
        expression = expression[close + 1..].trim_start();
    }
    if expression.starts_with('"') && expression.ends_with('"') && expression.len() >= 2 {
        expression = &expression[1..expression.len() - 1];
    }
    expression.strip_prefix("$(")?;
    let close = matching_delimiter(ScriptDialect::Zsh, expression, 1, b'(', b')', true).ok()?;
    expression.get(2..close)
}

fn matching_delimiter(
    dialect: ScriptDialect,
    raw: &str,
    start: usize,
    open: u8,
    close: u8,
    inherited_double_quote: bool,
) -> Result<usize, String> {
    let bytes = raw.as_bytes();
    let mut depth = 0_usize;
    let mut implicit_zsh_parameters = Vec::new();
    let mut literal_braces = 0_usize;
    let mut parameter_brackets = 0_usize;
    let mut quote = None;
    let mut single_quote_escapes = false;
    let mut escaped = false;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if byte == b'\\'
            && (quote != Some(b'\'') || dialect == ScriptDialect::Fish || single_quote_escapes)
        {
            escaped = true;
            index += 1;
            continue;
        }
        if quote.is_none()
            && depth > 0
            && close == b')'
            && byte == b'#'
            && (index == start
                || bytes[index - 1].is_ascii_whitespace()
                || matches!(bytes[index - 1], b';' | b'&' | b'|'))
            && bytes
                .get(index + 1)
                .is_none_or(|next| !matches!(next, b'#' | b'(' | b'~'))
        {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if quote.is_none() && open != b'{' && byte == b'$' && bytes.get(index + 1) == Some(&b'{') {
            index = matching_delimiter(
                dialect,
                raw,
                index + 1,
                b'{',
                b'}',
                inherited_double_quote || quote == Some(b'"'),
            )? + 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == active {
                quote = None;
                single_quote_escapes = false;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') && !(byte == b'\'' && inherited_double_quote) {
            quote = Some(byte);
            single_quote_escapes = byte == b'\''
                && (dialect == ScriptDialect::Fish || index > start && bytes[index - 1] == b'$');
        } else if open == b'{' && byte == b'[' {
            parameter_brackets = parameter_brackets.saturating_add(1);
        } else if open == b'{' && byte == b']' && parameter_brackets > 0 {
            parameter_brackets -= 1;
        } else if byte == open {
            if open == b'{'
                && parameter_brackets > 0
                && bytes.get(index.wrapping_sub(1)) != Some(&b'$')
            {
                // Unprefixed braces in parameter-pattern bracket expressions are literals.
            } else if open == b'{'
                && index != start
                && bytes.get(index.wrapping_sub(1)) != Some(&b'$')
            {
                literal_braces = literal_braces.saturating_add(1);
            } else {
                let implicit_parameter = open == b'{'
                    && dialect == ScriptDialect::Zsh
                    && index != start
                    && index >= 2
                    && bytes[index - 2] == b'{';
                implicit_zsh_parameters.push(implicit_parameter);
                depth += 1;
            }
        } else if byte == close {
            if close == b'}' && literal_braces > 0 {
                literal_braces -= 1;
            } else {
                depth = depth.saturating_sub(1);
                let implicit_parameter = implicit_zsh_parameters.pop().unwrap_or(false);
                if implicit_parameter
                    && depth > 0
                    && bytes
                        .get(index + 1)
                        .is_none_or(|next| matches!(next, b'\'' | b'"' | b' ' | b'\t'))
                {
                    depth -= 1;
                    implicit_zsh_parameters.pop();
                }
                if depth == 0 {
                    return Ok(index);
                }
            }
        }
        index += 1;
    }
    Err("unterminated expansion".into())
}

fn update_fish_deferred_variable(command: &ScriptCommand, variables: &mut HashMap<String, String>) {
    if command.words.first().and_then(ScriptWord::as_plain_literal) != Some("set") {
        return;
    }
    let mut index = 1;
    while index < command.words.len()
        && command.words[index]
            .as_plain_literal()
            .is_some_and(|value| value.starts_with('-'))
    {
        index += 1;
    }
    let Some(name) = command
        .words
        .get(index)
        .and_then(ScriptWord::as_plain_literal)
    else {
        return;
    };
    if !is_variable_name(name) {
        return;
    }
    let value_words = &command.words[index + 1..];
    let values = value_words
        .iter()
        .map(|word| fish_static_word_value(word, variables))
        .collect::<Option<Vec<_>>>();
    let source = value_words
        .iter()
        .map(plain_word_source)
        .collect::<Option<Vec<_>>>();
    if let Some(value) = values.or(source).map(|values| values.join(" ")) {
        variables.insert(name.to_owned(), value);
    } else {
        variables.remove(name);
    }
}

fn fish_static_word_value(
    word: &ScriptWord,
    variables: &HashMap<String, String>,
) -> Option<String> {
    let mut value = String::new();
    for part in &word.parts {
        match part {
            ScriptWordPart::Literal { value: literal, .. } => value.push_str(literal),
            ScriptWordPart::Parameter { expression, .. } => {
                value.push_str(variables.get(expression)?);
            }
            _ => return None,
        }
    }
    Some(value)
}

fn fish_deferred_variable_source(
    word: &ScriptWord,
    variables: &HashMap<String, String>,
) -> Option<String> {
    let [ScriptWordPart::Parameter { expression, .. }] = word.parts.as_slice() else {
        return None;
    };
    variables.get(expression).cloned()
}

fn fish_completion_forwarders(
    statements: &[ScriptStatement],
) -> Result<HashSet<String>, ScriptParseError> {
    let mut functions = Vec::new();
    collect_functions(statements, &mut functions);
    if functions.len() > MAX_FISH_FORWARDER_FUNCTIONS {
        return Err(ScriptParseError {
            line: 1,
            message: "Fish completion forwarder limit exceeded".into(),
        });
    }
    let indices = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut reverse_edges = vec![Vec::<usize>::new(); functions.len()];
    let mut forwarder = vec![false; functions.len()];
    let mut queue = Vec::new();
    let mut edge_count = 0_usize;
    for (caller, function) in functions.iter().enumerate() {
        if indices.get(function.name.as_str()) != Some(&caller) {
            continue;
        }
        let mut names = HashSet::new();
        collect_fish_command_names(&function.body, &mut names);
        if names.contains("complete") {
            forwarder[caller] = true;
            queue.push(caller);
        }
        for called in names {
            let Some(&target) = indices.get(called.as_str()) else {
                continue;
            };
            edge_count = edge_count.saturating_add(1);
            if edge_count > MAX_FISH_FORWARDER_EDGES {
                return Err(ScriptParseError {
                    line: 1,
                    message: "Fish completion forwarder limit exceeded".into(),
                });
            }
            reverse_edges[target].push(caller);
        }
    }
    let mut cursor = 0_usize;
    while let Some(&target) = queue.get(cursor) {
        cursor += 1;
        for &caller in &reverse_edges[target] {
            if !forwarder[caller] {
                forwarder[caller] = true;
                queue.push(caller);
            }
        }
    }
    Ok(functions
        .iter()
        .enumerate()
        .filter(|(index, _)| forwarder[*index])
        .map(|(_, function)| function.name.clone())
        .collect())
}

fn collect_fish_command_names(statements: &[ScriptStatement], names: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                if let Some(name) = command.words.first().and_then(ScriptWord::as_plain_literal) {
                    names.insert(name.to_owned());
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_fish_command_names(commands, names);
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_fish_command_names(std::slice::from_ref(first), names);
                for arm in rest {
                    collect_fish_command_names(std::slice::from_ref(&arm.statement), names);
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_fish_command_names(&branch.condition, names);
                    collect_fish_command_names(&branch.body, names);
                }
                collect_fish_command_names(otherwise, names);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_fish_command_names(condition, names);
                collect_fish_command_names(body, names);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_fish_command_names(body, names);
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_fish_command_names(&arm.body, names);
                }
            }
            ScriptStatement::Function { function } => {
                collect_fish_command_names(&function.body, names);
            }
            ScriptStatement::Redirected { statement, .. } => {
                collect_fish_command_names(std::slice::from_ref(statement), names);
            }
            ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn compile_fish_deferred_scripts(
    statements: &mut [ScriptStatement],
    variables: &mut HashMap<String, String>,
    forwarders: &HashSet<String>,
) -> Result<(), ScriptParseError> {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                update_fish_deferred_variable(command, variables);
                compile_fish_complete_command(command, variables, forwarders)?;
                if command
                    .words
                    .first()
                    .and_then(ScriptWord::as_plain_literal)
                    .is_some_and(|name| forwarders.contains(name))
                {
                    compile_forwarded_fish_completion_arguments(&mut command.words)?;
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                let mut nested_variables = variables.clone();
                compile_fish_deferred_scripts(commands, &mut nested_variables, forwarders)?;
            }
            ScriptStatement::AndOr { first, rest } => {
                compile_fish_deferred_scripts(std::slice::from_mut(first), variables, forwarders)?;
                for arm in rest {
                    compile_fish_deferred_scripts(
                        std::slice::from_mut(&mut arm.statement),
                        variables,
                        forwarders,
                    )?;
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    let mut nested_variables = variables.clone();
                    compile_fish_deferred_scripts(
                        &mut branch.condition,
                        &mut nested_variables,
                        forwarders,
                    )?;
                    compile_fish_deferred_scripts(
                        &mut branch.body,
                        &mut nested_variables,
                        forwarders,
                    )?;
                }
                let mut nested_variables = variables.clone();
                compile_fish_deferred_scripts(otherwise, &mut nested_variables, forwarders)?;
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                let mut nested_variables = variables.clone();
                compile_fish_deferred_scripts(condition, &mut nested_variables, forwarders)?;
                compile_fish_deferred_scripts(body, &mut nested_variables, forwarders)?;
            }
            ScriptStatement::For { body, .. } => {
                let mut nested_variables = variables.clone();
                compile_fish_deferred_scripts(body, &mut nested_variables, forwarders)?
            }
            ScriptStatement::Group { body, .. } => {
                compile_fish_deferred_scripts(body, variables, forwarders)?
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    let mut nested_variables = variables.clone();
                    compile_fish_deferred_scripts(
                        &mut arm.body,
                        &mut nested_variables,
                        forwarders,
                    )?;
                }
            }
            ScriptStatement::Function { function } => {
                let mut nested_variables = variables.clone();
                compile_fish_deferred_scripts(
                    &mut function.body,
                    &mut nested_variables,
                    forwarders,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn compile_forwarded_fish_completion_arguments(
    words: &mut [ScriptWord],
) -> Result<(), ScriptParseError> {
    let mut index = 1;
    while index < words.len() {
        let option = words[index].as_plain_literal().unwrap_or("");
        let exact = matches!(option, "-a" | "--arguments" | "-n" | "--condition");
        let combined = option
            .strip_prefix('-')
            .filter(|option| !option.starts_with('-'))
            .is_some_and(|flags| flags.chars().any(|flag| matches!(flag, 'a' | 'n')));
        if (exact || combined) && index + 1 < words.len() {
            compile_forwarded_fish_completion_expression(&mut words[index + 1])?;
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn compile_forwarded_fish_completion_expression(
    word: &mut ScriptWord,
) -> Result<(), ScriptParseError> {
    if word.parts.iter().any(|part| {
        matches!(
            part,
            ScriptWordPart::CommandSubstitution { .. } | ScriptWordPart::DeferredScript { .. }
        )
    }) {
        return Ok(());
    }
    let Some(source) = plain_word_source(word) else {
        return Ok(());
    };
    if !source.trim_start().starts_with('(') {
        return Ok(());
    }
    let tokens = Lexer::new(ScriptDialect::Fish, &source).lex()?;
    let mut words = Vec::new();
    for token in tokens {
        match token.kind {
            TokenKind::Word(value) => {
                words.push(
                    parse_word_parts(ScriptDialect::Fish, &value).map_err(|message| {
                        ScriptParseError {
                            line: token.line,
                            message,
                        }
                    })?,
                );
            }
            TokenKind::Operator(value) if value != ";" => {
                words.push(ScriptWord::literal(value));
            }
            TokenKind::Operator(_) => {}
        }
    }
    *word = ScriptWord {
        parts: vec![ScriptWordPart::DeferredScript {
            source,
            statements: Vec::new(),
            words,
        }],
        raw: None,
    };
    Ok(())
}

fn compile_fish_complete_command(
    command: &mut ScriptCommand,
    variables: &HashMap<String, String>,
    forwarders: &HashSet<String>,
) -> Result<(), ScriptParseError> {
    if command.words.first().and_then(ScriptWord::as_plain_literal) != Some("complete") {
        return Ok(());
    }
    normalize_fish_complete_words(&mut command.words);
    let mut index = 1;
    while index + 1 < command.words.len() {
        let option = command.words[index].as_plain_literal().unwrap_or("");
        let condition = matches!(option, "-n" | "--condition");
        let arguments = matches!(option, "-a" | "--arguments");
        if condition || arguments {
            let literal_source = plain_word_source(&command.words[index + 1]);
            let variable_source =
                fish_deferred_variable_source(&command.words[index + 1], variables);
            if let Some(parsed_source) = variable_source.or_else(|| literal_source.clone()) {
                let source = literal_source.unwrap_or_else(|| parsed_source.clone());
                let dynamic_arguments = arguments && parsed_source.contains('(');
                if condition || dynamic_arguments {
                    let tokens = Lexer::new(ScriptDialect::Fish, &parsed_source).lex()?;
                    let mut parser = Parser::new(ScriptDialect::Fish, tokens.clone());
                    let mut deferred_statements = if condition {
                        parser.parse_list(&[])?
                    } else {
                        Vec::new()
                    };
                    let mut nested_variables = variables.clone();
                    compile_fish_deferred_scripts(
                        &mut deferred_statements,
                        &mut nested_variables,
                        forwarders,
                    )?;
                    let deferred_words = if dynamic_arguments {
                        parse_fish_deferred_words(&parsed_source)?
                    } else {
                        Vec::new()
                    };
                    command.words[index + 1] = ScriptWord {
                        parts: vec![ScriptWordPart::DeferredScript {
                            source,
                            statements: deferred_statements,
                            words: deferred_words,
                        }],
                        raw: None,
                    };
                }
            }
            index += 2;
        } else if fish_complete_option_takes_value(option)
            || matches!(option, "-c" | "--command" | "-p" | "--path")
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn parse_fish_deferred_words(source: &str) -> Result<Vec<ScriptWord>, ScriptParseError> {
    let wrapped = format!("__bashlume_deferred {source}");
    let tokens = Lexer::new(ScriptDialect::Fish, &wrapped).lex()?;
    let mut parser = Parser::new(ScriptDialect::Fish, tokens);
    let statements = parser.parse_list(&[])?;
    let Some(ScriptStatement::Command { command }) = statements.first() else {
        return Err(ScriptParseError {
            line: 1,
            message: "invalid deferred Fish completion arguments".into(),
        });
    };
    Ok(command.words.iter().skip(1).cloned().collect())
}

fn normalize_fish_complete_words(words: &mut Vec<ScriptWord>) {
    let mut normalized = Vec::with_capacity(words.len());
    let mut index = 0;
    while index < words.len() {
        let Some(argument) = words[index].as_plain_literal() else {
            if let Some(expanded) = normalize_dynamic_fish_complete_word(&words[index]) {
                normalized.extend(expanded);
            } else {
                normalized.push(words[index].clone());
            }
            index += 1;
            continue;
        };
        if index == 0 || !argument.starts_with('-') || argument == "-" {
            normalized.push(words[index].clone());
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            normalized.push(words[index].clone());
            let takes_next = !argument.contains('=')
                && matches!(
                    argument,
                    "--arguments"
                        | "--command"
                        | "--path"
                        | "--short-option"
                        | "--long-option"
                        | "--old-option"
                        | "--description"
                        | "--condition"
                        | "--wraps"
                        | "--color"
                );
            if takes_next {
                if let Some(value) = words.get(index + 1) {
                    normalized.push(value.clone());
                }
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if argument.len() == 2 {
            normalized.push(words[index].clone());
            let takes_next = argument.chars().nth(1).is_some_and(|character| {
                matches!(
                    character,
                    'c' | 'p' | 's' | 'l' | 'o' | 'a' | 'd' | 'n' | 'w'
                )
            });
            if takes_next {
                if let Some(value) = words.get(index + 1) {
                    normalized.push(value.clone());
                }
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        let body = &argument[1..];
        let mut consumed_next = false;
        for (byte_index, character) in body.char_indices() {
            normalized.push(ScriptWord::literal(format!("-{character}")));
            if matches!(
                character,
                'c' | 'p' | 's' | 'l' | 'o' | 'a' | 'd' | 'n' | 'w'
            ) {
                let value_start = byte_index + character.len_utf8();
                if value_start < body.len() {
                    normalized.push(ScriptWord::literal(body[value_start..].to_owned()));
                } else if let Some(value) = words.get(index + 1) {
                    normalized.push(value.clone());
                    consumed_next = true;
                }
                break;
            }
            if character == 'C' {
                let value_start = byte_index + character.len_utf8();
                if value_start < body.len() {
                    normalized.push(ScriptWord::literal(body[value_start..].to_owned()));
                }
                break;
            }
        }
        index += 1 + usize::from(consumed_next);
    }
    *words = normalized;
}

fn normalize_dynamic_fish_complete_word(word: &ScriptWord) -> Option<Vec<ScriptWord>> {
    let Some(ScriptWordPart::Literal {
        value: prefix,
        quoted: false,
    }) = word.parts.first()
    else {
        return None;
    };
    if !prefix.starts_with('-') || prefix.starts_with("--") || prefix == "-" {
        return None;
    }
    let body = &prefix[1..];
    let mut normalized = Vec::new();
    for (byte_index, character) in body.char_indices() {
        normalized.push(ScriptWord::literal(format!("-{character}")));
        if matches!(
            character,
            'c' | 'p' | 's' | 'l' | 'o' | 'a' | 'd' | 'n' | 'w'
        ) {
            let value_start = byte_index + character.len_utf8();
            let mut parts = word.parts.clone();
            if value_start < body.len() {
                if let ScriptWordPart::Literal { value, .. } = &mut parts[0] {
                    *value = body[value_start..].to_owned();
                }
            } else {
                parts.remove(0);
            }
            if parts.is_empty() {
                return None;
            }
            normalized.push(ScriptWord { parts, raw: None });
            return Some(normalized);
        }
        if character == 'C' {
            return Some(normalized);
        }
    }
    None
}

fn plain_word_source(word: &ScriptWord) -> Option<String> {
    if let Some(raw) = &word.raw {
        let raw = raw.trim();
        if raw.len() >= 2 {
            let first = raw.as_bytes()[0];
            let last = *raw.as_bytes().last()?;
            if first == last && first == b'\'' {
                return Some(raw[1..raw.len() - 1].to_owned());
            }
            if first == last && first == b'"' {
                return Some(unescape_fish_double_quoted_source(&raw[1..raw.len() - 1]));
            }
        }
        return Some(raw.to_owned());
    }
    let mut source = String::new();
    for part in &word.parts {
        match part {
            ScriptWordPart::Literal { value, .. } => source.push_str(value),
            _ => return None,
        }
    }
    Some(source)
}

fn unescape_fish_double_quoted_source(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some(next @ ('$' | '"' | '\\')) => output.push(next),
            Some('\n') => {}
            Some(next) => {
                output.push('\\');
                output.push(next);
            }
            None => output.push('\\'),
        }
    }
    output
}

fn collect_functions(statements: &[ScriptStatement], functions: &mut Vec<ScriptFunction>) {
    for statement in statements {
        match statement {
            ScriptStatement::Function { function } => functions.push(function.clone()),
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_functions(&branch.condition, functions);
                    collect_functions(&branch.body, functions);
                }
                collect_functions(otherwise, functions);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_functions(condition, functions);
                collect_functions(body, functions);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_functions(body, functions)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_functions(&arm.body, functions);
                }
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_functions(std::slice::from_ref(first), functions);
                for arm in rest {
                    collect_functions(std::slice::from_ref(&arm.statement), functions);
                }
            }
            _ => {}
        }
    }
}

fn extract_registrations(
    dialect: ScriptDialect,
    source_path: &str,
    source: &str,
    statements: &[ScriptStatement],
    functions: &[ScriptFunction],
) -> Result<Vec<ScriptRegistration>, ScriptParseError> {
    let mut registrations = Vec::new();
    match dialect {
        ScriptDialect::Fish | ScriptDialect::Bash => {
            let mut walker = StaticRegistrationWalker::new(dialect, &mut registrations);
            walker.walk(statements);
            if walker.limit_exceeded {
                return Err(ScriptParseError {
                    line: 1,
                    message: "static registration extraction limit exceeded".into(),
                });
            }
        }
        ScriptDialect::Zsh => {
            for line in source.lines().take(64) {
                let line = line.trim();
                if let Some(names) = line.strip_prefix("#compdef") {
                    let file_function = Path::new(source_path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| functions.iter().find(|function| function.name == name));
                    let entry = file_function.map_or(ScriptEntry::Module, |function| {
                        ScriptEntry::Function {
                            name: function.name.clone(),
                        }
                    });
                    let mut names = names.split_whitespace();
                    let mut order = 0_u32;
                    let mut registration_bytes = 0_usize;
                    while let Some(name) = names.next() {
                        let registration = match name {
                            "-P" | "-p" => names.next().map(|name| (name, None, false)),
                            "-S" | "-s" => names.next().map(|name| (name, None, true)),
                            "-N" | "-R" => {
                                names.next();
                                None
                            }
                            "-K" => {
                                names.next();
                                names.next();
                                None
                            }
                            value if value.starts_with('-') => None,
                            value => {
                                let (command, service) = value
                                    .split_once('=')
                                    .map_or((value, None), |(command, service)| {
                                        (command, Some(service))
                                    });
                                Some((command, service, false))
                            }
                        };
                        let Some((command, service, prefix_glob)) = registration else {
                            continue;
                        };
                        if command.is_empty() {
                            continue;
                        }
                        let command_bytes = command.len().saturating_add(usize::from(prefix_glob));
                        let bytes = std::mem::size_of::<ScriptRegistration>()
                            .saturating_add(command_bytes)
                            .saturating_add(service.map_or(0, str::len))
                            .saturating_add(match &entry {
                                ScriptEntry::Function { name } => name.len(),
                                ScriptEntry::Module | ScriptEntry::FishComplete { .. } => 0,
                            });
                        registration_bytes = registration_bytes.saturating_add(bytes);
                        if registrations.len() >= MAX_STATIC_REGISTRATIONS
                            || registration_bytes > MAX_STATIC_REGISTRATION_BYTES
                        {
                            return Err(ScriptParseError {
                                line: 1,
                                message: "static registration extraction limit exceeded".into(),
                            });
                        }
                        registrations.push(ScriptRegistration {
                            command: if prefix_glob {
                                format!("*{command}")
                            } else {
                                command.to_owned()
                            },
                            entry: entry.clone(),
                            service: service.map(str::to_owned),
                            source_order: order,
                        });
                        order = order.saturating_add(1);
                    }
                    break;
                }
            }
        }
    }
    if registrations.is_empty() {
        if let Some(file_name) = Path::new(source_path)
            .file_name()
            .and_then(|name| name.to_str())
        {
            let mut command = file_name
                .strip_suffix(".bash")
                .or_else(|| file_name.strip_suffix(".fish"))
                .unwrap_or(file_name)
                .to_owned();
            if dialect == ScriptDialect::Zsh {
                command = command.trim_start_matches('_').to_owned();
            }
            if !command.is_empty() {
                registrations.push(ScriptRegistration {
                    command,
                    entry: ScriptEntry::Module,
                    service: None,
                    source_order: 0,
                });
            }
        }
    }
    registrations.sort_by(|left, right| {
        left.command
            .cmp(&right.command)
            .then(left.source_order.cmp(&right.source_order))
    });
    registrations.dedup_by(|left, right| {
        left.command == right.command && left.entry == right.entry && left.service == right.service
    });
    Ok(registrations)
}

struct StaticRegistrationWalker<'a> {
    dialect: ScriptDialect,
    environment: HashMap<String, Vec<String>>,
    registrations: &'a mut Vec<ScriptRegistration>,
    order: u32,
    work: usize,
    registration_bytes: usize,
    limit_exceeded: bool,
}

impl<'a> StaticRegistrationWalker<'a> {
    fn new(dialect: ScriptDialect, registrations: &'a mut Vec<ScriptRegistration>) -> Self {
        Self {
            dialect,
            environment: HashMap::new(),
            registrations,
            order: 0,
            work: 0,
            registration_bytes: 0,
            limit_exceeded: false,
        }
    }

    fn push_registration(&mut self, registration: ScriptRegistration) {
        let bytes = std::mem::size_of::<ScriptRegistration>()
            .saturating_add(registration.command.len())
            .saturating_add(registration.service.as_ref().map_or(0, String::len))
            .saturating_add(match &registration.entry {
                ScriptEntry::Function { name } => name.len(),
                ScriptEntry::Module | ScriptEntry::FishComplete { .. } => 0,
            });
        self.registration_bytes = self.registration_bytes.saturating_add(bytes);
        if self.registrations.len() >= MAX_STATIC_REGISTRATIONS
            || self.registration_bytes > MAX_STATIC_REGISTRATION_BYTES
        {
            self.limit_exceeded = true;
            return;
        }
        self.registrations.push(registration);
    }

    fn walk(&mut self, statements: &[ScriptStatement]) {
        for statement in statements {
            if self.limit_exceeded {
                break;
            }
            self.statement(statement);
        }
    }

    fn statement(&mut self, statement: &ScriptStatement) {
        self.work = self.work.saturating_add(1);
        if self.work > MAX_STATIC_REGISTRATION_WALK_WORK {
            self.limit_exceeded = true;
            return;
        }
        match statement {
            ScriptStatement::Command { command } => self.command(command),
            ScriptStatement::Pipeline { commands, .. } => self.walk(commands),
            ScriptStatement::AndOr { first, rest } => {
                self.statement(first);
                for arm in rest {
                    self.statement(&arm.statement);
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                let environment = self.environment.clone();
                for branch in branches {
                    self.environment = environment.clone();
                    self.walk(&branch.condition);
                    self.walk(&branch.body);
                }
                self.environment = environment.clone();
                self.walk(otherwise);
                self.environment = environment;
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                let environment = self.environment.clone();
                self.walk(condition);
                self.walk(body);
                self.environment = environment;
            }
            ScriptStatement::For {
                variables,
                words,
                body,
            } => {
                let environment = self.environment.clone();
                let values = words
                    .iter()
                    .flat_map(|word| self.expand_word(word).unwrap_or_default())
                    .take(4096)
                    .collect::<Vec<_>>();
                if values.is_empty() || variables.is_empty() {
                    self.walk(body);
                } else {
                    for chunk in values.chunks(variables.len()) {
                        self.environment = environment.clone();
                        for (variable, value) in variables.iter().zip(chunk) {
                            self.environment
                                .insert(variable.clone(), vec![value.clone()]);
                        }
                        self.walk(body);
                    }
                }
                self.environment = environment;
            }
            ScriptStatement::Case { arms, .. } => {
                let environment = self.environment.clone();
                for arm in arms {
                    self.environment = environment.clone();
                    self.walk(&arm.body);
                }
                self.environment = environment;
            }
            ScriptStatement::Group { body, .. } => self.walk(body),
            ScriptStatement::Redirected { statement, .. } => self.statement(statement),
            // Function bodies are declarations. They are interpreted only if
            // called, rather than being mistaken for top-level registrations.
            ScriptStatement::Function { .. }
            | ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }

    fn command(&mut self, command: &ScriptCommand) {
        for assignment in &command.assignments {
            if let Some(values) = self.expand_word(&assignment.value) {
                if assignment.append {
                    self.environment
                        .entry(assignment.name.clone())
                        .or_default()
                        .extend(values);
                } else {
                    self.environment.insert(assignment.name.clone(), values);
                }
            }
        }
        let arguments = self.expand_words(&command.words);
        if self.dialect == ScriptDialect::Fish
            && arguments.first().is_some_and(|value| value == "set")
        {
            self.fish_set(&arguments[1..]);
            return;
        }
        if arguments.first().is_none_or(|value| value != "complete") {
            return;
        }
        match self.dialect {
            ScriptDialect::Fish => {
                let services = fish_complete_wraps(&arguments[1..]);
                for command_name in fish_complete_commands(&arguments[1..]) {
                    if services.is_empty() {
                        self.push_registration(ScriptRegistration {
                            command: command_name,
                            entry: ScriptEntry::FishComplete {
                                statement_index: self.order,
                            },
                            service: None,
                            source_order: self.order,
                        });
                    } else {
                        for service in &services {
                            self.push_registration(ScriptRegistration {
                                command: command_name.clone(),
                                entry: ScriptEntry::FishComplete {
                                    statement_index: self.order,
                                },
                                service: Some(service.clone()),
                                source_order: self.order,
                            });
                        }
                    }
                }
            }
            ScriptDialect::Bash => self.bash_complete(&arguments[1..]),
            ScriptDialect::Zsh => {}
        }
        self.order = self.order.saturating_add(1);
    }

    fn fish_set(&mut self, arguments: &[String]) {
        let append = arguments
            .iter()
            .any(|value| matches!(value.as_str(), "-a" | "--append"));
        let erase = arguments
            .iter()
            .any(|value| matches!(value.as_str(), "-e" | "--erase"));
        let mut index = 0;
        while index < arguments.len() && arguments[index].starts_with('-') {
            index += 1;
        }
        let Some(name) = arguments.get(index) else {
            return;
        };
        if !is_variable_name(name) {
            return;
        }
        if erase {
            self.environment.remove(name);
        } else if append {
            self.environment
                .entry(name.clone())
                .or_default()
                .extend_from_slice(&arguments[index + 1..]);
        } else {
            self.environment
                .insert(name.clone(), arguments[index + 1..].to_vec());
        }
    }

    fn bash_complete(&mut self, arguments: &[String]) {
        if arguments.iter().any(|argument| argument == "-r") {
            return;
        }
        let mut function = None;
        let mut commands = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if argument == "-F" && index + 1 < arguments.len() {
                function = Some(arguments[index + 1].clone());
                index += 2;
            } else if complete_option_takes_value(argument) {
                index += 2;
            } else if argument.starts_with('-') {
                index += 1;
            } else {
                commands.push(argument.clone());
                index += 1;
            }
        }
        let entry = function.map_or(ScriptEntry::Module, |name| ScriptEntry::Function { name });
        for command in commands {
            if !command.is_empty() && !command.contains('\0') {
                self.push_registration(ScriptRegistration {
                    command,
                    entry: entry.clone(),
                    service: None,
                    source_order: self.order,
                });
            }
        }
    }

    fn expand_words(&self, words: &[ScriptWord]) -> Vec<String> {
        let mut result = Vec::new();
        for word in words {
            if let Some(values) = self.expand_word(word) {
                result.extend(values);
            } else {
                result.push("\0".into());
            }
            if result.len() > 16_384 {
                result.truncate(16_384);
                break;
            }
        }
        result
    }

    fn expand_word(&self, word: &ScriptWord) -> Option<Vec<String>> {
        let mut values = vec![String::new()];
        for part in &word.parts {
            let additions = match part {
                ScriptWordPart::Literal { value, quoted } => {
                    if *quoted {
                        vec![value.clone()]
                    } else {
                        expand_literal_braces(value)
                    }
                }
                ScriptWordPart::Parameter { expression, .. } => {
                    let name = parameter_name(expression)?;
                    self.environment.get(name)?.clone()
                }
                ScriptWordPart::BraceExpansion { alternatives, .. } => alternatives
                    .iter()
                    .flat_map(|alternative| self.expand_word(alternative).unwrap_or_default())
                    .collect(),
                ScriptWordPart::Array { elements } => elements
                    .iter()
                    .flat_map(|element| self.expand_word(element).unwrap_or_default())
                    .collect(),
                ScriptWordPart::Arithmetic { .. }
                | ScriptWordPart::CommandSubstitution { .. }
                | ScriptWordPart::DeferredScript { .. } => return None,
            };
            if additions.is_empty() {
                return None;
            }
            let mut combined = Vec::new();
            for prefix in &values {
                for addition in &additions {
                    let mut value = prefix.clone();
                    value.push_str(addition);
                    combined.push(value);
                    if combined.len() > 16_384 {
                        return None;
                    }
                }
            }
            values = combined;
        }
        Some(values)
    }
}

fn is_variable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn parameter_name(expression: &str) -> Option<&str> {
    let expression = expression.trim_start_matches(['^', '=', '~']);
    let end = expression
        .char_indices()
        .take_while(|(_, character)| *character == '_' || character.is_ascii_alphanumeric())
        .map(|(index, character)| index + character.len_utf8())
        .last()?;
    let name = &expression[..end];
    is_variable_name(name).then_some(name)
}

fn expand_literal_braces(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let Some(open) = bytes.iter().position(|byte| *byte == b'{') else {
        return vec![value.to_owned()];
    };
    let mut depth = 0_usize;
    let mut close = None;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return vec![value.to_owned()];
    };
    let body = &value[open + 1..close];
    let mut alternatives = Vec::new();
    let mut nested = 0_usize;
    let mut start = 0_usize;
    for (index, byte) in body.bytes().enumerate() {
        match byte {
            b'{' => nested += 1,
            b'}' => nested = nested.saturating_sub(1),
            b',' if nested == 0 => {
                alternatives.push(body[start..index].to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    if !alternatives.is_empty() {
        alternatives.push(body[start..].to_owned());
    } else if let Some((first, last)) = body.split_once("..") {
        if let (Ok(first), Ok(last)) = (first.parse::<i64>(), last.parse::<i64>()) {
            let count = first.abs_diff(last).saturating_add(1);
            if count <= 4096 {
                alternatives = if first <= last {
                    (first..=last).map(|value| value.to_string()).collect()
                } else {
                    (last..=first)
                        .rev()
                        .map(|value| value.to_string())
                        .collect()
                };
            }
        } else if first.chars().count() == 1 && last.chars().count() == 1 {
            let first = first.chars().next().unwrap() as u32;
            let last = last.chars().next().unwrap() as u32;
            if first.abs_diff(last) < 4096 {
                let range: Box<dyn Iterator<Item = u32>> = if first <= last {
                    Box::new(first..=last)
                } else {
                    Box::new((last..=first).rev())
                };
                alternatives = range.filter_map(char::from_u32).map(String::from).collect();
            }
        }
    }
    if alternatives.is_empty() {
        return vec![value.to_owned()];
    }
    let mut result = Vec::new();
    for alternative in alternatives {
        let expanded = format!("{}{}{}", &value[..open], alternative, &value[close + 1..]);
        result.extend(expand_literal_braces(&expanded));
        if result.len() > 4096 {
            return vec![value.to_owned()];
        }
    }
    result
}

fn fish_complete_commands(arguments: &[String]) -> Vec<String> {
    let mut commands = Vec::new();
    let mut index = 0;
    if arguments
        .first()
        .is_some_and(|argument| !argument.starts_with('-'))
    {
        if !arguments[0].is_empty() && !arguments[0].contains('\0') {
            commands.push(arguments[0].clone());
        }
        index = 1;
    }
    while index < arguments.len() {
        let argument = &arguments[index];
        if matches!(argument.as_str(), "-c" | "--command" | "-p" | "--path")
            && index + 1 < arguments.len()
        {
            if !arguments[index + 1].is_empty()
                && !arguments[index + 1].starts_with('-')
                && !arguments[index + 1].contains('\0')
            {
                commands.push(arguments[index + 1].clone());
            }
            index += 2;
        } else if let Some(value) = argument
            .strip_prefix("--command=")
            .or_else(|| argument.strip_prefix("--path="))
        {
            if !value.is_empty() && !value.starts_with('-') && !value.contains('\0') {
                commands.push(value.to_owned());
            }
            index += 1;
        } else if fish_complete_option_takes_value(argument) {
            index += 2;
        } else {
            if commands.is_empty()
                && !argument.starts_with('-')
                && !argument.is_empty()
                && !argument.contains('\0')
            {
                commands.push(argument.clone());
            }
            index += 1;
        }
    }
    commands
}

fn fish_complete_wraps(arguments: &[String]) -> Vec<String> {
    let mut services = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if matches!(argument.as_str(), "-w" | "--wraps") {
            if let Some(service) = arguments
                .get(index + 1)
                .filter(|value| !value.is_empty() && !value.contains('\0'))
            {
                services.push(service.clone());
            }
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--wraps=") {
            if !value.is_empty() && !value.contains('\0') {
                services.push(value.to_owned());
            }
            index += 1;
            continue;
        }
        if fish_complete_option_takes_value(argument)
            || matches!(argument.as_str(), "-c" | "--command" | "-p" | "--path")
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    services.sort_unstable();
    services.dedup();
    services
}

fn fish_complete_option_takes_value(value: &str) -> bool {
    matches!(
        value,
        "-s" | "--short-option"
            | "-l"
            | "--long-option"
            | "-o"
            | "--old-option"
            | "-a"
            | "--arguments"
            | "-d"
            | "--description"
            | "-n"
            | "--condition"
            | "-w"
            | "--wraps"
    )
}

fn complete_option_takes_value(value: &str) -> bool {
    matches!(
        value,
        "-A" | "-C" | "-F" | "-G" | "-P" | "-S" | "-W" | "-X" | "-o"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bash_functions_and_registrations() {
        let source = r#"
_hello() {
    local value="${COMP_WORDS[COMP_CWORD]}"
    if [[ $value == --* ]]; then
        COMPREPLY=( $(compgen -W '--help --version' -- "$value") )
    fi
}
complete -F _hello hello hi
complete -F _hello -o bashdefault demo
"#;
        let module = parse_script(ScriptDialect::Bash, "hello", source).unwrap();
        assert!(
            module
                .functions
                .iter()
                .any(|function| function.name == "_hello")
        );
        assert_eq!(
            module
                .registrations
                .iter()
                .map(|registration| registration.command.as_str())
                .collect::<Vec<_>>(),
            ["demo", "hello", "hi"]
        );
    }

    #[test]
    fn case_terminators_distinguish_execution_from_pattern_retesting() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "case.zsh",
            "case x in\n  a) : ;&\n  b) : ;|\n  c) : ;;&\n  *) : ;;\nesac\n",
        )
        .unwrap();
        let ScriptStatement::Case { arms, .. } = &module.statements[0] else {
            panic!("expected case statement");
        };
        assert!(arms[0].fallthrough);
        assert!(!arms[0].continue_matching);
        assert!(!arms[1].fallthrough);
        assert!(arms[1].continue_matching);
        assert!(!arms[2].fallthrough);
        assert!(arms[2].continue_matching);
        assert!(!arms[3].fallthrough);
        assert!(!arms[3].continue_matching);
    }

    #[test]
    fn quoted_tab_stripping_here_documents_are_compiled_as_data() {
        let source = "cat <<-'HELP'\n\tliteral $value ( unmatched shell text\n\tHELP\necho done\n";
        let module = parse_script(ScriptDialect::Zsh, "heredoc.zsh", source).unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected redirected command");
        };
        assert_eq!(command.redirections[0].operator, "<<-");
        assert_eq!(
            command.redirections[0].target.as_plain_literal(),
            Some("literal $value ( unmatched shell text")
        );
        assert!(matches!(
            module.statements[1],
            ScriptStatement::Command { .. }
        ));
    }

    #[test]
    fn unquoted_here_document_substitutions_are_compiled_to_ir() {
        let source = "cat <<EOF\n$(_helper one)\nEOF\n";
        let module = parse_script(ScriptDialect::Bash, "heredoc.bash", source).unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected redirected command");
        };
        assert!(command.redirections[0].target.parts.iter().any(|part| {
            matches!(part, ScriptWordPart::CommandSubstitution { statements, .. }
                if matches!(statements.as_slice(), [ScriptStatement::Command { .. }]))
        }));
    }

    #[test]
    fn hostile_here_document_counts_and_termination_are_rejected() {
        let mut excessive = String::from("cat");
        for index in 0..=4096 {
            excessive.push_str(&format!(" <<EOF{index}"));
        }
        excessive.push('\n');
        let error =
            parse_script(ScriptDialect::Bash, "many-heredocs.bash", &excessive).unwrap_err();
        assert_eq!(error.message, "too many here-documents");

        let error = parse_script(
            ScriptDialect::Bash,
            "unterminated-heredoc.bash",
            "cat <<EOF\nbody without a delimiter\n",
        )
        .unwrap_err();
        assert!(error.message.starts_with("unterminated here-document"));
    }

    #[test]
    fn nested_static_registration_loops_are_work_bounded() {
        let values = (0..256)
            .map(|index| format!("v{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let source = format!(
            "for outer in {values}\nfor inner in {values}\ncomplete -c demo -l option\nend\nend\n"
        );
        let error = parse_script(ScriptDialect::Fish, "loops.fish", &source).unwrap_err();
        assert_eq!(
            error.message,
            "static registration extraction limit exceeded"
        );
    }

    #[test]
    fn nesting_preflight_ignores_comments_and_keyword_arguments() {
        let source = format!(
            "# {}\nprintf '%s' {}\ncomplete -F demo demo\n",
            "{".repeat(MAX_PARSE_NESTING + 32),
            "if ".repeat(MAX_PARSE_NESTING + 32),
        );
        parse_script(ScriptDialect::Bash, "flat.bash", &source).unwrap();
    }

    #[test]
    fn hostile_quoted_substitution_and_brace_expansion_are_parse_bounded() {
        let substitutions = format!(
            "echo \"{}true{}\"\n",
            "$(".repeat(MAX_WORD_PARSE_DEPTH + 32),
            ")".repeat(MAX_WORD_PARSE_DEPTH + 32),
        );
        let error = parse_script(
            ScriptDialect::Bash,
            "nested-substitution.bash",
            &substitutions,
        )
        .unwrap_err();
        assert!(error.message.contains("word parse depth limit"));

        let oversized_brace = format!("{{a,b}}{}", "x".repeat(5 * 1024 * 1024));
        let error =
            parse_script(ScriptDialect::Bash, "brace-budget.bash", &oversized_brace).unwrap_err();
        assert!(
            error
                .message
                .contains("brace expansion resource limit exceeded")
        );
        assert!(error.message.len() < 1024);
    }

    #[test]
    fn oversized_sources_are_rejected_before_heredoc_preprocessing() {
        let source = "x".repeat(MAX_SCRIPT_SOURCE_BYTES + 1);
        let error = parse_script(ScriptDialect::Bash, "oversized.bash", &source).unwrap_err();
        assert_eq!(error.message, "source byte limit exceeded");
    }

    #[test]
    fn oversized_redirection_descriptors_are_rejected_during_parsing() {
        for source in ["echo value 10>output\n", "echo value 65536 > output\n"] {
            let error = parse_script(ScriptDialect::Bash, "descriptor.bash", source).unwrap_err();
            assert_eq!(error.message, "redirection descriptor exceeds policy bound");
        }
    }

    #[test]
    fn adjacent_unbraced_parameters_remain_distinct_word_parts() {
        let module = parse_script(
            ScriptDialect::Bash,
            "adjacent.bash",
            "echo \"$first$second\"\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        assert!(matches!(
            command.words[1].parts.as_slice(),
            [
                ScriptWordPart::Parameter { expression: first, .. },
                ScriptWordPart::Parameter { expression: second, .. }
            ] if first == "first" && second == "second"
        ));
    }

    #[test]
    fn zsh_if_condition_can_begin_with_a_group_before_and_or_rhs() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "_default",
            "if { false || true } && [[ x = x ]]; then\n  print yes\nfi\n",
        )
        .unwrap();
        let ScriptStatement::If { branches, .. } = &module.statements[0] else {
            panic!("expected if statement");
        };
        assert_eq!(branches.len(), 1);
        assert!(matches!(
            branches[0].condition.as_slice(),
            [ScriptStatement::AndOr { .. }]
        ));
    }

    #[test]
    fn zsh_flagged_parameter_command_substitution_compiles_to_statements() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "_demo",
            "values=( ${(f)\"$(_call_program values demo --list)\"} ${$(_call_program ids demo --ids)// /} )\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected assignment command");
        };
        assert!(matches!(
            command.assignments[0].value.parts.as_slice(),
            [ScriptWordPart::Array { elements }]
                if elements.len() == 2
                    && elements.iter().all(|element| matches!(element.parts.as_slice(), [ScriptWordPart::CommandSubstitution { statements, .. }] if !statements.is_empty()))
        ));
    }

    #[test]
    fn zsh_force_split_unbraced_parameter_is_executable_ir() {
        let module = parse_script(ScriptDialect::Zsh, "_demo", "print -l $=values\n").unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        assert!(matches!(
            command.words[2].parts.as_slice(),
            [ScriptWordPart::Parameter { expression, .. }] if expression == "=values"
        ));
    }

    #[test]
    fn parses_fish_blocks_and_complete_calls() {
        let source = r#"
function __demo_condition
    contains -- sub (commandline -xpc)
end
complete -c demo -n __demo_condition -l help -d 'Show help'
"#;
        let module = parse_script(ScriptDialect::Fish, "demo", source).unwrap();
        assert!(
            module
                .functions
                .iter()
                .any(|function| function.name == "__demo_condition")
        );
        assert_eq!(module.registrations[0].command, "demo");
    }

    #[test]
    fn fish_combined_complete_flags_compile_deferred_arguments() {
        let module = parse_script(
            ScriptDialect::Fish,
            "source.fish",
            "complete -c source -kxa '(__fish_complete_suffix .fish)'\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected complete command");
        };
        assert_eq!(command.words[3].as_plain_literal(), Some("-k"));
        assert_eq!(command.words[4].as_plain_literal(), Some("-x"));
        assert_eq!(command.words[5].as_plain_literal(), Some("-a"));
        assert!(matches!(
            command.words[6].parts.as_slice(),
            [ScriptWordPart::DeferredScript { .. }]
        ));
    }

    #[test]
    fn fish_dynamic_attached_flags_and_continued_comments_are_normalized() {
        let module = parse_script(
            ScriptDialect::Fish,
            "dynamic.fish",
            "set -l values one \\\n    # omitted \\\n    two\ncomplete -c demo -loption$values\n",
        )
        .unwrap();
        let ScriptStatement::Command { command: set } = &module.statements[0] else {
            panic!("expected set command");
        };
        assert_eq!(set.words[4].as_plain_literal(), Some("two"));
        let ScriptStatement::Command { command: complete } = &module.statements[1] else {
            panic!("expected complete command");
        };
        assert_eq!(complete.words[3].as_plain_literal(), Some("-l"));
        assert_eq!(complete.words[4].parts.len(), 2);
    }

    #[test]
    fn fish_deferred_argument_variables_compile_as_executable_words() {
        let module = parse_script(
            ScriptDialect::Fish,
            "variable.fish",
            "set -l values '(helper --list) tail'\ncomplete -c demo -a \"$values\"\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[1] else {
            panic!("expected complete command");
        };
        assert!(matches!(
            command.words[4].parts.as_slice(),
            [ScriptWordPart::DeferredScript { words, .. }] if words.len() == 2
        ));
    }

    #[test]
    fn fish_forwarder_compiles_only_executable_complete_fields() {
        let module = parse_script(
            ScriptDialect::Fish,
            "forward.fish",
            "function forward\ncomplete -c demo $argv\nend\nforward -a '(helper)' -d '(Required) literal'\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[1] else {
            panic!("expected forwarder call");
        };
        assert!(matches!(
            command.words[2].parts.as_slice(),
            [ScriptWordPart::DeferredScript { .. }]
        ));
        assert!(!matches!(
            command.words[4].parts.as_slice(),
            [ScriptWordPart::DeferredScript { .. }]
        ));
    }

    #[test]
    fn fish_backticks_in_descriptions_remain_literal_data() {
        let module = parse_script(
            ScriptDialect::Fish,
            "description.fish",
            r#"complete -c demo -l search -d "Search for <value> using `%<value>`""#,
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected complete command");
        };
        assert!(matches!(
            command.words[6].parts.as_slice(),
            [ScriptWordPart::Literal { value, .. }] if value.contains("`%<value>`")
        ));
    }

    #[test]
    fn fish_complete_values_that_start_with_dash_are_not_reparsed_as_flags() {
        let module = parse_script(
            ScriptDialect::Fish,
            "demo.fish",
            r#"complete -c demo -a '-strip\t"strip metadata"'"#,
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected complete command");
        };
        assert_eq!(
            command.words[4].as_plain_literal(),
            Some("-strip\\t\"strip metadata\"")
        );
    }

    #[test]
    fn repeated_fish_command_flags_preserve_every_native_registration() {
        let module = parse_script(
            ScriptDialect::Fish,
            "legacy.fish",
            "complete -c demo -c 'legacy condition text' -l help\n",
        )
        .unwrap();
        assert_eq!(
            module
                .registrations
                .iter()
                .map(|registration| registration.command.as_str())
                .collect::<Vec<_>>(),
            ["demo", "legacy condition text"]
        );
    }

    #[test]
    fn fish_positional_commands_can_follow_complete_flags() {
        let module = parse_script(
            ScriptDialect::Fish,
            "positional.fish",
            "complete -f positional -a value\n",
        )
        .unwrap();
        assert!(
            module
                .registrations
                .iter()
                .any(|registration| registration.command == "positional")
        );
    }

    #[test]
    fn fish_deferred_condition_variables_use_each_lexical_assignment() {
        let module = parse_script(
            ScriptDialect::Fish,
            "conditions.fish",
            "set -l suffix check\nset -l condition \"first-$suffix\"\ncomplete -c demo -n $condition -a first\nset condition 'second-check'\ncomplete -c demo -n $condition -a second\n",
        )
        .unwrap();
        let deferred_name = |statement: &ScriptStatement| {
            let ScriptStatement::Command { command } = statement else {
                panic!("expected command");
            };
            let [ScriptWordPart::DeferredScript { statements, .. }] =
                command.words[4].parts.as_slice()
            else {
                panic!("expected deferred condition");
            };
            let ScriptStatement::Command { command } = &statements[0] else {
                panic!("expected deferred command");
            };
            command.words[0].as_plain_literal().unwrap_or("").to_owned()
        };
        assert_eq!(deferred_name(&module.statements[2]), "first-check");
        assert_eq!(deferred_name(&module.statements[4]), "second-check");
    }

    #[test]
    fn fish_double_quoted_command_substitutions_remain_executable_ir() {
        let module = parse_script(
            ScriptDialect::Fish,
            "quoted.fish",
            "complete -c demo -a \"$values (helper --list)\"\n",
        )
        .unwrap();
        let command = match &module.statements[0] {
            ScriptStatement::Command { command } => command,
            other => panic!("unexpected statement: {other:?}"),
        };
        let [ScriptWordPart::DeferredScript { words, .. }] = command.words[4].parts.as_slice()
        else {
            panic!("quoted completion expression was not deferred");
        };
        assert!(
            words
                .iter()
                .flat_map(|word| &word.parts)
                .any(|part| matches!(part, ScriptWordPart::CommandSubstitution { .. }))
        );
    }

    #[test]
    fn fish_wraps_are_retained_as_registration_services() {
        let module = parse_script(
            ScriptDialect::Fish,
            "alias.fish",
            "complete -c alias-command -w target-command\n",
        )
        .unwrap();
        assert_eq!(module.registrations[0].command, "alias-command");
        assert_eq!(
            module.registrations[0].service.as_deref(),
            Some("target-command")
        );
    }

    #[test]
    fn fragmented_zsh_backticks_remain_literal_until_a_complete_word_is_available() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "fragmented-backtick.zsh",
            "demo() { local value=\"`helper \"${words[1]} --list\"`\"; }\n",
        )
        .unwrap();
        assert_eq!(module.functions[0].name, "demo");
    }

    #[test]
    fn compound_redirection_binds_to_its_pipeline_component() {
        let source = "echo left && { echo right; } >out\n{ echo pipe; } 2>&1 | read value\n";
        let module =
            parse_script(ScriptDialect::Bash, "compound-redirection.bash", source).unwrap();
        let ScriptStatement::AndOr { rest, .. } = &module.statements[0] else {
            panic!("expected and-or statement");
        };
        assert!(matches!(
            rest[0].statement.as_ref(),
            ScriptStatement::Redirected { redirections, .. }
                if redirections[0].operator == ">"
        ));
        let ScriptStatement::Pipeline { commands, .. } = &module.statements[1] else {
            panic!("expected pipeline");
        };
        assert!(matches!(
            &commands[0],
            ScriptStatement::Redirected { redirections, .. }
                if redirections[0].descriptor == Some(2)
                    && redirections[0].operator == ">&"
        ));
    }

    #[test]
    fn eval_generated_functions_compile_to_deferred_script_ir() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "dynamic.zsh",
            "define() { local name=$1; eval \"$name () { target \\\"\\${name}\\\"; }\"; }\n",
        )
        .unwrap();
        let function = module
            .functions
            .iter()
            .find(|function| function.name == "define")
            .unwrap();
        let ScriptStatement::Command { command } = &function.body[1] else {
            panic!("expected eval command");
        };
        assert!(matches!(
            command.words[1].parts.as_slice(),
            [ScriptWordPart::DeferredScript { statements, words, .. }]
                if matches!(statements.as_slice(), [ScriptStatement::Function { .. }])
                    && !words.is_empty()
        ));
    }

    #[test]
    fn escaped_zsh_glob_prefix_remains_quoted_through_brace_expansion() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "arguments.zsh",
            "_arguments \\*{-v,--verbose}'[verbose mode]'\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        let Some(ScriptWordPart::BraceExpansion { alternatives, .. }) =
            command.words[1].parts.first()
        else {
            panic!("expected lexical brace expansion");
        };
        assert!(alternatives.iter().all(|alternative| matches!(
            alternative.parts.first(),
            Some(ScriptWordPart::Literal { value, quoted: true }) if value == "*"
        )));
    }

    #[test]
    fn zsh_noclobber_override_binds_as_one_compound_redirection() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "noclobber.zsh",
            "while true; do break; done >! output\n",
        )
        .unwrap();
        assert!(matches!(
            &module.statements[0],
            ScriptStatement::Redirected { redirections, .. }
                if redirections[0].operator == ">!"
                    && redirections[0].target.as_plain_literal() == Some("output")
        ));
    }

    #[test]
    fn fish_descriptor_pipes_are_not_compound_redirections() {
        let module = parse_script(
            ScriptDialect::Fish,
            "pipe.fish",
            "if command -h 2>| string match -q pattern\ncomplete -c command -a value\nend\n",
        )
        .unwrap();
        let ScriptStatement::If { branches, .. } = &module.statements[0] else {
            panic!("expected fish if");
        };
        assert!(matches!(
            branches[0].condition[0],
            ScriptStatement::Pipeline { .. }
        ));
    }

    #[test]
    fn attached_descriptor_redirections_are_not_command_arguments() {
        let module =
            parse_script(ScriptDialect::Bash, "redirect.bash", "demo 2>&1 3>>log\n").unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        assert_eq!(command.words.len(), 1);
        assert_eq!(command.redirections.len(), 2);
        assert_eq!(command.redirections[0].descriptor, Some(2));
        assert_eq!(command.redirections[0].operator, ">&");
        assert_eq!(command.redirections[0].target.as_plain_literal(), Some("1"));
        assert_eq!(command.redirections[1].descriptor, Some(3));
        assert_eq!(command.redirections[1].operator, ">>");
        assert_eq!(
            command.redirections[1].target.as_plain_literal(),
            Some("log")
        );
    }

    #[test]
    fn nested_zsh_parameter_indices_remain_one_ir_part() {
        let source = "#compdef demo\nprint ${cache[${key}]}\n";
        let module = parse_script(ScriptDialect::Zsh, "_demo", source).unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        assert!(command.words.iter().any(|word| {
            matches!(
                word.parts.as_slice(),
                [ScriptWordPart::Parameter { expression, .. }]
                    if expression == "cache[${key}]"
            )
        }));
    }

    #[test]
    fn bash_double_quotes_preserve_backslashes_before_non_special_characters() {
        let source = "printf '%s' \"s/^\\\\[\\\\!\\\\]//\"\n";
        let module = parse_script(ScriptDialect::Bash, "quoted.bash", source).unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected command");
        };
        assert_eq!(command.words[2].as_plain_literal(), Some("s/^\\[\\!\\]//"));
    }

    #[test]
    fn quoted_braces_are_retained_as_literal_data() {
        let source = "value='--{,no}feature'\n";
        let module = parse_script(ScriptDialect::Bash, "quoted.bash", source).unwrap();
        let ScriptStatement::Command { command } = &module.statements[0] else {
            panic!("expected assignment command");
        };
        assert!(matches!(
            command.assignments[0].value.parts.as_slice(),
            [ScriptWordPart::Literal {
                value,
                quoted: true
            }] if value == "--{,no}feature"
        ));
    }

    #[test]
    fn fish_forwarder_chains_use_bounded_linear_reachability() {
        let mut source = String::new();
        for index in 0..2048 {
            source.push_str(&format!("function f{index}\n"));
            if index + 1 == 2048 {
                source.push_str("complete -c demo -l ready\n");
            } else {
                source.push_str(&format!("f{}\n", index + 1));
            }
            source.push_str("end\n");
        }
        source.push_str("f0\n");
        let module = parse_script(ScriptDialect::Fish, "demo.fish", &source).unwrap();
        assert_eq!(module.functions.len(), 2048);
    }

    #[test]
    fn fish_character_brace_ranges_are_bounded_before_collection() {
        let value = format!("{{a..{}}}", char::MAX);
        assert_eq!(expand_literal_braces(&value), [value]);
    }

    #[test]
    fn reads_zsh_compdef_without_using_zsh_parser() {
        let source = "#compdef git-hub gh\n_arguments '*:file:_files'\n";
        let module = parse_script(ScriptDialect::Zsh, "_gh", source).unwrap();
        assert_eq!(module.registrations.len(), 2);
    }

    #[test]
    fn zsh_compdef_registrations_are_bounded_before_cloning() {
        let source = format!("#compdef {}\n", "x ".repeat(MAX_STATIC_REGISTRATIONS + 1));
        let error = parse_script(ScriptDialect::Zsh, "_x", &source).unwrap_err();
        assert!(error.message.contains("registration extraction limit"));
    }
}
