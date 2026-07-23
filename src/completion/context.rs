use super::matcher::{Candidate, CandidateKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteMode {
    Unquoted,
    Single,
    Double,
    AnsiC,
}

#[derive(Clone, Debug)]
pub struct CompletionContext {
    pub line: String,
    pub point: usize,
    pub replace_start: usize,
    pub replace_end: usize,
    pub query: String,
    pub quote: QuoteMode,
    pub command_position: bool,
    /// Dequoted words in the current simple command, including an empty
    /// current word after trailing whitespace.
    pub words: Vec<String>,
    pub word_index: usize,
    pub command_name: Option<String>,
    /// Heuristic command/subcommand path. Source-specific state machines can
    /// still inspect the complete `words` vector when positional arguments
    /// make this approximation insufficient.
    pub command_path: Vec<String>,
}

impl CompletionContext {
    pub fn analyze(line: &str, point: usize) -> Self {
        let point = floor_char_boundary(line, point.min(line.len()));
        let tokens = lex_shell(line, point);
        let (replace_start, quote) = current_word_start_and_quote(line, point);
        let replace_end = current_word_end(line, point, quote);
        let raw_word = line[replace_start..point].to_owned();
        let query = dequote_prefix(&raw_word);
        let command_position = command_position_before(&tokens, replace_start);
        let (words, word_index) = completion_words(&tokens, replace_start, &query);
        let command_index = words.iter().position(|word| !is_assignment(word));
        let command_name = command_index.and_then(|index| words.get(index)).cloned();
        let command_path = command_index.map_or_else(Vec::new, |index| {
            words[index..word_index]
                .iter()
                .filter(|word| !word.starts_with('-') && !is_assignment(word))
                .cloned()
                .collect()
        });

        Self {
            line: line.to_owned(),
            point,
            replace_start,
            replace_end,
            query,
            quote,
            command_position,
            words,
            word_index,
            command_name,
            command_path,
        }
    }

    pub fn replacement_for(&self, candidate: &Candidate) -> String {
        let mut replacement = match candidate.kind {
            CandidateKind::Variable => candidate.value.clone(),
            CandidateKind::User if candidate.value.starts_with('~') => candidate.value.clone(),
            _ => quote_shell_word(&candidate.value, self.quote),
        };
        if candidate.append_space {
            replacement.push(' ');
        }
        replacement
    }

    pub fn apply(&self, candidate: &Candidate) -> (String, usize) {
        let replacement = self.replacement_for(candidate);
        let mut line = String::with_capacity(
            self.line.len() - (self.replace_end - self.replace_start) + replacement.len(),
        );
        line.push_str(&self.line[..self.replace_start]);
        line.push_str(&replacement);
        let new_point = line.len();
        line.push_str(&self.line[self.replace_end..]);
        (line, new_point)
    }

    pub fn typed_parent_and_leaf(&self) -> (String, String) {
        let query = &self.query;
        match query.rfind('/') {
            Some(index) => (query[..=index].to_owned(), query[index + 1..].to_owned()),
            None => (String::new(), query.clone()),
        }
    }
}

/// Returns the first target of `cd`/`pushd` when the line is a simple
/// navigation command. The value is dequoted but not expanded.
pub fn existing_directory_target(line: &str) -> Option<String> {
    let tokens = lex_shell(line, line.len());
    let words = tokens
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Operator(_)))
        .filter_map(|token| match &token.kind {
            TokenKind::Word(word) => Some(word.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut index = 0_usize;
    while words.get(index).is_some_and(|word| is_assignment(word)) {
        index += 1;
    }
    loop {
        let command = *words.get(index)?;
        if !is_command_wrapper(command) {
            break;
        }
        index += 1;
        let mut skip_value = false;
        while let Some(word) = words.get(index).copied() {
            if skip_value {
                skip_value = false;
                index += 1;
            } else if is_assignment(word) {
                index += 1;
            } else if word.starts_with('-') {
                skip_value = wrapper_option_takes_value(command, word);
                index += 1;
            } else {
                break;
            }
        }
    }

    let command = *words.get(index)?;
    if !matches!(command, "cd" | "pushd") {
        return None;
    }
    index += 1;
    while let Some(word) = words.get(index).copied() {
        index += 1;
        if word == "--" || word.starts_with('-') && word != "-" {
            continue;
        }
        return Some(word.to_owned());
    }
    None
}

#[derive(Clone, Debug)]
enum TokenKind {
    Word(String),
    Operator(String),
    Redirect,
}

#[derive(Clone, Debug)]
struct Token {
    start: usize,
    kind: TokenKind,
}

fn completion_words(
    tokens: &[Token],
    current_start: usize,
    current_query: &str,
) -> (Vec<String>, usize) {
    let segment_start = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.start < current_start)
        .filter_map(|(index, token)| match &token.kind {
            TokenKind::Operator(operator)
                if matches!(operator.as_str(), ";" | "&" | "&&" | "|" | "||" | "(") =>
            {
                Some(index + 1)
            }
            _ => None,
        })
        .next_back()
        .unwrap_or(0);

    let mut words = Vec::new();
    let mut redirect_target = false;
    let mut current_present = false;
    for token in &tokens[segment_start..] {
        match &token.kind {
            TokenKind::Redirect => redirect_target = true,
            TokenKind::Operator(_) => {}
            TokenKind::Word(word) => {
                if redirect_target {
                    redirect_target = false;
                    continue;
                }
                if token.start == current_start {
                    words.push(current_query.to_owned());
                    current_present = true;
                } else if token.start < current_start {
                    words.push(word.clone());
                }
            }
        }
    }
    if !current_present {
        words.push(current_query.to_owned());
    }
    let word_index = words.len().saturating_sub(1);
    (words, word_index)
}

fn command_position_before(tokens: &[Token], current_start: usize) -> bool {
    let mut expect_command = true;
    let mut expect_redirect_target = false;
    let mut wrapper: Option<&str> = None;
    let mut skip_wrapper_value = false;

    for token in tokens.iter().filter(|token| token.start < current_start) {
        match &token.kind {
            TokenKind::Redirect => expect_redirect_target = true,
            TokenKind::Operator(operator) => {
                expect_redirect_target = false;
                if matches!(operator.as_str(), ";" | "&" | "&&" | "|" | "||" | "(" | "{") {
                    expect_command = true;
                    wrapper = None;
                    skip_wrapper_value = false;
                }
            }
            TokenKind::Word(word) => {
                if expect_redirect_target {
                    expect_redirect_target = false;
                    continue;
                }
                if skip_wrapper_value {
                    skip_wrapper_value = false;
                    continue;
                }
                if expect_command && is_assignment(word) {
                    continue;
                }
                if let Some(wrapper_name) = wrapper {
                    if word.starts_with('-') {
                        skip_wrapper_value = wrapper_option_takes_value(wrapper_name, word);
                        continue;
                    }
                    if is_command_wrapper(word) {
                        wrapper = Some(word);
                        continue;
                    }
                    wrapper = None;
                    expect_command = false;
                    continue;
                }
                if is_command_wrapper(word) {
                    wrapper = Some(word);
                    expect_command = true;
                } else if matches!(word.as_str(), "then" | "do" | "else" | "elif") {
                    expect_command = true;
                } else if !matches!(word.as_str(), "if" | "while" | "until" | "time" | "!") {
                    expect_command = false;
                }
            }
        }
    }

    expect_command && !expect_redirect_target
}

fn is_command_wrapper(word: &str) -> bool {
    matches!(
        word,
        "command"
            | "builtin"
            | "exec"
            | "env"
            | "sudo"
            | "doas"
            | "nohup"
            | "nice"
            | "setsid"
            | "stdbuf"
    )
}

fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    if option.contains('=') {
        return false;
    }
    match wrapper {
        "sudo" => matches!(
            option,
            "-u" | "--user"
                | "-g"
                | "--group"
                | "-h"
                | "--host"
                | "-p"
                | "--prompt"
                | "-C"
                | "--close-from"
                | "-T"
                | "--command-timeout"
                | "-R"
                | "--chroot"
                | "-D"
                | "--chdir"
        ),
        "env" => matches!(
            option,
            "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
        ),
        "nice" => matches!(option, "-n" | "--adjustment"),
        "stdbuf" => matches!(
            option,
            "-i" | "--input" | "-o" | "--output" | "-e" | "--error"
        ),
        _ => false,
    }
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && characters.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn lex_shell(line: &str, point: usize) -> Vec<Token> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut word_start = None;
    let mut quote = QuoteMode::Unquoted;
    let mut escaped = false;

    let flush_word = |end: usize, tokens: &mut Vec<Token>, word_start: &mut Option<usize>| {
        if let Some(start) = word_start.take() {
            tokens.push(Token {
                start,
                kind: TokenKind::Word(dequote_prefix(&line[start..end])),
            });
        }
    };

    while index < point {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }

        match quote {
            QuoteMode::Single => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                }
                index += 1;
                continue;
            }
            QuoteMode::Double => {
                if byte == b'"' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
                index += 1;
                continue;
            }
            QuoteMode::AnsiC => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
                index += 1;
                continue;
            }
            QuoteMode::Unquoted => {}
        }

        match byte {
            b'\\' => {
                word_start.get_or_insert(index);
                escaped = true;
                index += 1;
            }
            b'\'' => {
                word_start.get_or_insert(index);
                quote = if index > 0 && bytes[index - 1] == b'$' {
                    QuoteMode::AnsiC
                } else {
                    QuoteMode::Single
                };
                index += 1;
            }
            b'"' => {
                word_start.get_or_insert(index);
                quote = QuoteMode::Double;
                index += 1;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                flush_word(index, &mut tokens, &mut word_start);
                index += 1;
            }
            b';' | b'&' | b'|' | b'(' | b')' | b'{' | b'}' => {
                flush_word(index, &mut tokens, &mut word_start);
                let start = index;
                let mut end = index + 1;
                if end < point
                    && matches!(
                        (byte, bytes[end]),
                        (b'&', b'&') | (b'|', b'|') | (b';', b';')
                    )
                {
                    end += 1;
                }
                tokens.push(Token {
                    start,
                    kind: TokenKind::Operator(line[start..end].to_owned()),
                });
                index = end;
            }
            b'<' | b'>' => {
                flush_word(index, &mut tokens, &mut word_start);
                let start = index;
                index += 1;
                if index < point && bytes[index] == byte {
                    index += 1;
                }
                tokens.push(Token {
                    start,
                    kind: TokenKind::Redirect,
                });
            }
            _ => {
                word_start.get_or_insert(index);
                index += utf8_char_len(byte).min(point - index);
            }
        }
    }

    flush_word(point, &mut tokens, &mut word_start);
    tokens
}

fn current_word_start_and_quote(line: &str, point: usize) -> (usize, QuoteMode) {
    let bytes = line.as_bytes();
    let mut index = 0;
    let mut start = 0;
    let mut quote = QuoteMode::Unquoted;
    let mut escaped = false;

    while index < point {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match quote {
            QuoteMode::Single => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                }
            }
            QuoteMode::Double => {
                if byte == b'"' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
            }
            QuoteMode::AnsiC => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
            }
            QuoteMode::Unquoted => match byte {
                b'\\' => escaped = true,
                b'\'' => {
                    quote = if index > start && bytes[index - 1] == b'$' {
                        QuoteMode::AnsiC
                    } else {
                        QuoteMode::Single
                    };
                }
                b'"' => quote = QuoteMode::Double,
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => {
                    start = index + 1
                }
                _ => {}
            },
        }
        index += 1;
    }

    let preferred_quote = match line.as_bytes().get(start) {
        Some(b'\'') => QuoteMode::Single,
        Some(b'"') => QuoteMode::Double,
        Some(b'$') if line.as_bytes().get(start + 1) == Some(&b'\'') => QuoteMode::AnsiC,
        _ => quote,
    };
    (start, preferred_quote)
}

fn current_word_end(line: &str, point: usize, initial_quote: QuoteMode) -> usize {
    let bytes = line.as_bytes();
    let mut index = point;
    let mut quote = initial_quote;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match quote {
            QuoteMode::Single => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                }
            }
            QuoteMode::Double => {
                if byte == b'"' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
            }
            QuoteMode::AnsiC => {
                if byte == b'\'' {
                    quote = QuoteMode::Unquoted;
                } else if byte == b'\\' {
                    escaped = true;
                }
            }
            QuoteMode::Unquoted => {
                if matches!(
                    byte,
                    b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
                ) {
                    break;
                }
                if byte == b'\\' {
                    escaped = true;
                } else if byte == b'\'' {
                    quote = QuoteMode::Single;
                } else if byte == b'"' {
                    quote = QuoteMode::Double;
                }
            }
        }
        index += 1;
    }
    index
}

fn dequote_prefix(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut characters = raw.chars().peekable();
    let mut quote = QuoteMode::Unquoted;
    while let Some(character) = characters.next() {
        match quote {
            QuoteMode::Unquoted => match character {
                '\\' => {
                    if let Some(next) = characters.next() {
                        output.push(next);
                    }
                }
                '\'' => quote = QuoteMode::Single,
                '"' => quote = QuoteMode::Double,
                '$' if characters.peek() == Some(&'\'') => {
                    characters.next();
                    quote = QuoteMode::AnsiC;
                }
                _ => output.push(character),
            },
            QuoteMode::Single => {
                if character == '\'' {
                    quote = QuoteMode::Unquoted;
                } else {
                    output.push(character);
                }
            }
            QuoteMode::Double => {
                if character == '"' {
                    quote = QuoteMode::Unquoted;
                } else if character == '\\' {
                    if let Some(next) = characters.next() {
                        output.push(next);
                    }
                } else {
                    output.push(character);
                }
            }
            QuoteMode::AnsiC => {
                if character == '\'' {
                    quote = QuoteMode::Unquoted;
                } else if character == '\\' {
                    if let Some(next) = characters.next() {
                        output.push(next);
                    }
                } else {
                    output.push(character);
                }
            }
        }
    }
    output
}

pub fn quote_shell_word(value: &str, preference: QuoteMode) -> String {
    match preference {
        QuoteMode::Single => format!("'{}'", value.replace('\'', "'\\''")),
        QuoteMode::Double => {
            let escaped = value
                .replace('\\', "\\\\")
                .replace('$', "\\$")
                .replace('`', "\\`")
                .replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        QuoteMode::AnsiC => {
            let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
            format!("$'{escaped}'")
        }
        QuoteMode::Unquoted => {
            let mut output = String::with_capacity(value.len());
            for character in value.chars() {
                if character.is_whitespace()
                    || matches!(
                        character,
                        '\\' | '\''
                            | '"'
                            | '$'
                            | '`'
                            | ';'
                            | '&'
                            | '|'
                            | '('
                            | ')'
                            | '<'
                            | '>'
                            | '*'
                            | '?'
                            | '['
                            | ']'
                            | '{'
                            | '}'
                            | '!'
                    )
                {
                    output.push('\\');
                }
                output.push(character);
            }
            output
        }
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::matcher::{Candidate, CandidateKind};

    #[test]
    fn identifies_command_positions_across_shell_operators() {
        assert!(CompletionContext::analyze("ec", 2).command_position);
        assert!(!CompletionContext::analyze("echo fi", 7).command_position);
        assert!(CompletionContext::analyze("echo hi | gr", 12).command_position);
        assert!(CompletionContext::analyze("A=1 B=2 ec", 12).command_position);
        assert!(CompletionContext::analyze("echo > out; gr", 14).command_position);
        assert!(CompletionContext::analyze("sudo apt", 8).command_position);
        assert!(CompletionContext::analyze("env A=1 gi", 10).command_position);
        assert!(CompletionContext::analyze("sudo -u root sys", 16).command_position);
        assert!(CompletionContext::analyze("sudo env A=1 gi", 15).command_position);
    }

    #[test]
    fn exposes_current_simple_command_words_for_rule_evaluation() {
        let context = CompletionContext::analyze("echo done; git checkout ma", 26);
        assert_eq!(context.words, ["git", "checkout", "ma"]);
        assert_eq!(context.word_index, 2);
        assert_eq!(context.command_name.as_deref(), Some("git"));
        assert_eq!(context.command_path, ["git", "checkout"]);

        let trailing = CompletionContext::analyze("git status ", 11);
        assert_eq!(trailing.words, ["git", "status", ""]);
        assert_eq!(trailing.word_index, 2);
    }

    #[test]
    fn preserves_double_quote_style() {
        let context = CompletionContext::analyze("cat \"My F", 9);
        let candidate = Candidate::new(
            "My F",
            "My File".into(),
            "My File".into(),
            CandidateKind::File,
            true,
            0,
        )
        .unwrap();
        let (line, point) = context.apply(&candidate);
        assert_eq!(line, "cat \"My File\" ");
        assert_eq!(point, line.len());
    }

    #[test]
    fn extracts_only_real_navigation_targets() {
        assert_eq!(
            existing_directory_target("cd old-dir"),
            Some("old-dir".into())
        );
        assert_eq!(
            existing_directory_target("sudo -u root cd 'My Dir'"),
            Some("My Dir".into())
        );
        assert_eq!(existing_directory_target("echo cd old-dir"), None);
        assert_eq!(existing_directory_target("git -C old-dir status"), None);
    }

    #[test]
    fn minimal_unquoted_escaping_is_shell_safe() {
        assert_eq!(
            quote_shell_word("My File;ok", QuoteMode::Unquoted),
            "My\\ File\\;ok"
        );
    }

    #[test]
    fn splits_path_parent_from_leaf() {
        let context = CompletionContext::analyze("cat src/ma", 10);
        assert_eq!(
            context.typed_parent_and_leaf(),
            ("src/".into(), "ma".into())
        );
    }
}
