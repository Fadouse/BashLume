// SPDX-License-Identifier: GPL-2.0-or-later

//! Portable shell-completion script IR.
//!
//! The three source frontends compile shell syntax into this data model at
//! pack-build time. The runtime never parses or sources upstream shell text.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const MAX_SCRIPT_NODES: usize = 1_000_000;
pub const MAX_SCRIPT_DEPTH: usize = 32;
pub const MAX_SCRIPT_WORDS: usize = 4_000_000;
pub const MAX_SCRIPT_STRING_BYTES: usize = 32 * 1024 * 1024;
const MAX_SCRIPT_INDIVIDUAL_STRING_BYTES: usize = 1024 * 1024;
const MAX_REDIRECTION_DESCRIPTOR: u16 = 9;
const MAX_REGISTRATION_BYTES: usize = 4096;
const MAX_REGISTRATION_GROUP_DEPTH: usize = 128;
const MAX_REGISTRATION_MATCH_WORK: usize = 1_000_000;
const MAX_ZSH_FUNCTION_TABLE_BUCKETS: u32 = 458_752;
const MAX_ZSH_FUNCTION_NAMES: usize = 65_536;
const MAX_ZSH_FUNCTION_NAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptDialect {
    Bash,
    Zsh,
    Fish,
}

pub fn registration_matches(dialect: ScriptDialect, registration: &str, command: &str) -> bool {
    if registration.len() > MAX_REGISTRATION_BYTES || command.len() > MAX_REGISTRATION_BYTES {
        return false;
    }
    if registration == command {
        return true;
    }
    if dialect == ScriptDialect::Bash || !registration_has_pattern(registration) {
        return false;
    }
    let alternatives = if dialect == ScriptDialect::Zsh {
        expand_registration_groups(registration, 128)
    } else {
        vec![registration.to_owned()]
    };
    alternatives
        .iter()
        .any(|pattern| registration_glob_match(pattern, command, dialect == ScriptDialect::Zsh))
}

fn registration_has_pattern(value: &str) -> bool {
    value.contains('*')
        || value.contains('?')
        || value.contains('#')
        || value.contains('(') && value.contains(')')
        || value
            .find('[')
            .is_some_and(|open| value[open + 1..].contains(']'))
}

fn expand_registration_groups(pattern: &str, limit: usize) -> Vec<String> {
    expand_registration_groups_at_depth(pattern, limit, 0)
}

fn expand_registration_groups_at_depth(
    pattern: &str,
    limit: usize,
    depth_limit: usize,
) -> Vec<String> {
    if depth_limit >= MAX_REGISTRATION_GROUP_DEPTH || limit == 0 {
        return Vec::new();
    }
    let bytes = pattern.as_bytes();
    let mut bracket = 0_usize;
    let mut escaped = false;
    let mut open = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'(' if bracket == 0 => {
                open = Some(index);
                break;
            }
            _ => {}
        }
    }
    let Some(open) = open else {
        return vec![pattern.to_owned()];
    };
    let mut depth = 0_usize;
    let mut close = None;
    let mut escaped = false;
    for (offset, byte) in bytes[open..].iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'(' => depth += 1,
            b')' => {
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
        return vec![pattern.to_owned()];
    };
    let body = &pattern[open + 1..close];
    let mut parts = Vec::new();
    let mut depth = 0_usize;
    let mut bracket = 0_usize;
    let mut start = 0_usize;
    for (index, byte) in body.bytes().enumerate() {
        match byte {
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'(' if bracket == 0 => depth += 1,
            b')' if bracket == 0 => depth = depth.saturating_sub(1),
            b'|' if depth == 0 && bracket == 0 => {
                parts.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if parts.is_empty() {
        return vec![pattern.to_owned()];
    }
    parts.push(&body[start..]);
    let mut output = Vec::new();
    for part in parts {
        let expanded = format!("{}{}{}", &pattern[..open], part, &pattern[close + 1..]);
        for value in expand_registration_groups_at_depth(
            &expanded,
            limit.saturating_sub(output.len()),
            depth_limit + 1,
        ) {
            output.push(value);
            if output.len() >= limit {
                return output;
            }
        }
    }
    output
}

fn registration_glob_match(pattern: &str, value: &str, zsh_repetition: bool) -> bool {
    if pattern.len().saturating_mul(value.len().max(1)) > MAX_REGISTRATION_MATCH_WORK {
        return false;
    }
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    let mut pattern_index = 0_usize;
    while pattern_index < pattern.len() {
        if pattern[pattern_index] == b'*' {
            while pattern.get(pattern_index) == Some(&b'*') {
                pattern_index += 1;
            }
            for index in 1..=value.len() {
                row[index] |= row[index - 1];
            }
            continue;
        }
        let (atom_end, class, literal, any) = match pattern[pattern_index] {
            b'?' => (pattern_index + 1, None, None, true),
            b'[' => {
                if let Some(relative) = pattern[pattern_index + 1..]
                    .iter()
                    .position(|byte| *byte == b']')
                {
                    let end = pattern_index + 1 + relative;
                    (end + 1, Some(&pattern[pattern_index + 1..end]), None, false)
                } else {
                    (pattern_index + 1, None, Some(b'['), false)
                }
            }
            b'\\' if pattern_index + 1 < pattern.len() => (
                pattern_index + 2,
                None,
                Some(pattern[pattern_index + 1]),
                false,
            ),
            byte => (pattern_index + 1, None, Some(byte), false),
        };
        let matches = |byte| {
            any || class.is_some_and(|class| registration_class_match(class, byte))
                || literal == Some(byte)
        };
        let hashes = if zsh_repetition {
            pattern[atom_end..]
                .iter()
                .take_while(|byte| **byte == b'#')
                .count()
                .min(2)
        } else {
            0
        };
        let mut next = vec![false; value.len() + 1];
        if hashes == 1 {
            next.clone_from(&row);
            for index in 0..value.len() {
                if next[index] && matches(value[index]) {
                    next[index + 1] = true;
                }
            }
        } else if hashes == 2 {
            for index in 0..value.len() {
                if (row[index] || next[index]) && matches(value[index]) {
                    next[index + 1] = true;
                }
            }
        } else {
            for index in 0..value.len() {
                if row[index] && matches(value[index]) {
                    next[index + 1] = true;
                }
            }
        }
        row = next;
        pattern_index = atom_end + hashes;
    }
    row[value.len()]
}

fn registration_class_match(class: &[u8], value: u8) -> bool {
    let (inverted, class) = if class
        .first()
        .is_some_and(|byte| matches!(byte, b'!' | b'^'))
    {
        (true, &class[1..])
    } else {
        (false, class)
    };
    let mut matched = false;
    let mut index = 0;
    while index < class.len() {
        if index + 2 < class.len() && class[index + 1] == b'-' {
            matched |= (class[index]..=class[index + 2]).contains(&value);
            index += 3;
        } else {
            matched |= class[index] == value;
            index += 1;
        }
    }
    matched != inverted
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptModule {
    pub dialect: ScriptDialect,
    pub source_path: String,
    pub statements: Vec<ScriptStatement>,
    #[serde(default)]
    pub functions: Vec<ScriptFunction>,
    #[serde(default)]
    pub registrations: Vec<ScriptRegistration>,
    #[serde(default)]
    pub probe_capabilities: Vec<String>,
    /// Whether names-only Zsh function snapshot metadata is present. This is
    /// independent of the vector being empty so new packs do not fall back to
    /// the legacy fixed-table approximation.
    #[serde(default, skip_serializing_if = "is_false")]
    pub zsh_function_snapshot: bool,
    /// Native Zsh function-table high-water bucket count derived at build time.
    /// Zero preserves the legacy per-module approximation for older packs.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub zsh_function_table_size: u32,
    /// Ordered names-only Zsh `fpath` snapshot used for native hash scans.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zsh_function_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptFunction {
    pub name: String,
    #[serde(default)]
    pub arguments: Vec<ScriptWord>,
    pub body: Vec<ScriptStatement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptRegistration {
    pub command: String,
    pub entry: ScriptEntry,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub source_order: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScriptEntry {
    Function { name: String },
    FishComplete { statement_index: u32 },
    Module,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum ScriptStatement {
    Command {
        command: ScriptCommand,
    },
    AndOr {
        first: Box<ScriptStatement>,
        rest: Vec<ScriptAndOrArm>,
    },
    Pipeline {
        commands: Vec<ScriptStatement>,
        #[serde(default)]
        negated: bool,
    },
    If {
        branches: Vec<ScriptConditionalBranch>,
        #[serde(default)]
        otherwise: Vec<ScriptStatement>,
    },
    While {
        condition: Vec<ScriptStatement>,
        body: Vec<ScriptStatement>,
        #[serde(default)]
        until: bool,
    },
    For {
        variables: Vec<String>,
        words: Vec<ScriptWord>,
        body: Vec<ScriptStatement>,
    },
    Case {
        word: ScriptWord,
        arms: Vec<ScriptCaseArm>,
    },
    Function {
        function: ScriptFunction,
    },
    Group {
        body: Vec<ScriptStatement>,
        #[serde(default)]
        subshell: bool,
    },
    Return {
        status: Option<ScriptWord>,
    },
    Break,
    Continue,
    Noop,
    Redirected {
        statement: Box<ScriptStatement>,
        redirections: Vec<ScriptRedirection>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptAndOrArm {
    pub operator: ScriptBooleanOperator,
    pub statement: Box<ScriptStatement>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptBooleanOperator {
    And,
    Or,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptConditionalBranch {
    pub condition: Vec<ScriptStatement>,
    pub body: Vec<ScriptStatement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptCaseArm {
    pub patterns: Vec<ScriptWord>,
    pub body: Vec<ScriptStatement>,
    #[serde(default)]
    pub fallthrough: bool,
    #[serde(default)]
    pub continue_matching: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptCommand {
    #[serde(default)]
    pub assignments: Vec<ScriptAssignment>,
    #[serde(default)]
    pub words: Vec<ScriptWord>,
    #[serde(default)]
    pub redirections: Vec<ScriptRedirection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptAssignment {
    pub name: String,
    pub index: Option<ScriptWord>,
    pub value: ScriptWord,
    #[serde(default)]
    pub append: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptRedirection {
    pub descriptor: Option<u16>,
    pub operator: String,
    pub target: ScriptWord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScriptWord {
    pub parts: Vec<ScriptWordPart>,
    #[serde(skip)]
    pub(crate) raw: Option<String>,
}

impl ScriptWord {
    pub fn literal(value: impl Into<String>) -> Self {
        Self {
            parts: vec![ScriptWordPart::Literal {
                value: value.into(),
                quoted: false,
            }],
            raw: None,
        }
    }

    pub fn quoted_literal(value: impl Into<String>) -> Self {
        Self {
            parts: vec![ScriptWordPart::Literal {
                value: value.into(),
                quoted: true,
            }],
            raw: None,
        }
    }

    pub fn as_plain_literal(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [ScriptWordPart::Literal { value, .. }] => Some(value),
            _ => None,
        }
    }

    pub fn as_unquoted_plain_literal(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [
                ScriptWordPart::Literal {
                    value,
                    quoted: false,
                },
            ] => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScriptWordPart {
    Literal {
        value: String,
        #[serde(default)]
        quoted: bool,
    },
    Parameter {
        expression: String,
        #[serde(default)]
        quoted: bool,
    },
    CommandSubstitution {
        statements: Vec<ScriptStatement>,
        #[serde(default)]
        quoted: bool,
    },
    Arithmetic {
        expression: String,
        #[serde(default)]
        quoted: bool,
    },
    BraceExpansion {
        alternatives: Vec<ScriptWord>,
        #[serde(default)]
        quoted: bool,
    },
    Array {
        elements: Vec<ScriptWord>,
    },
    DeferredScript {
        source: String,
        #[serde(default)]
        statements: Vec<ScriptStatement>,
        #[serde(default)]
        words: Vec<ScriptWord>,
    },
}

fn statements_require_block_v4(statements: &[ScriptStatement]) -> bool {
    statements.iter().any(statement_requires_block_v4)
}

fn statement_requires_block_v4(statement: &ScriptStatement) -> bool {
    match statement {
        ScriptStatement::Redirected { .. } => true,
        ScriptStatement::Command { command } => command_requires_block_v4(command),
        ScriptStatement::AndOr { first, rest } => {
            statement_requires_block_v4(first)
                || rest
                    .iter()
                    .any(|arm| statement_requires_block_v4(&arm.statement))
        }
        ScriptStatement::Pipeline { commands, .. } => statements_require_block_v4(commands),
        ScriptStatement::If {
            branches,
            otherwise,
        } => {
            branches.iter().any(|branch| {
                statements_require_block_v4(&branch.condition)
                    || statements_require_block_v4(&branch.body)
            }) || statements_require_block_v4(otherwise)
        }
        ScriptStatement::While {
            condition, body, ..
        } => statements_require_block_v4(condition) || statements_require_block_v4(body),
        ScriptStatement::For { words, body, .. } => {
            words.iter().any(word_requires_block_v4) || statements_require_block_v4(body)
        }
        ScriptStatement::Case { word, arms } => {
            word_requires_block_v4(word)
                || arms.iter().any(|arm| {
                    arm.patterns.iter().any(word_requires_block_v4)
                        || statements_require_block_v4(&arm.body)
                })
        }
        ScriptStatement::Function { function } => {
            function.arguments.iter().any(word_requires_block_v4)
                || statements_require_block_v4(&function.body)
        }
        ScriptStatement::Group { body, .. } => statements_require_block_v4(body),
        ScriptStatement::Return { status } => status.as_ref().is_some_and(word_requires_block_v4),
        ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => false,
    }
}

fn command_requires_block_v4(command: &ScriptCommand) -> bool {
    command.words.iter().any(word_requires_block_v4)
        || command.assignments.iter().any(|assignment| {
            assignment
                .index
                .as_ref()
                .is_some_and(word_requires_block_v4)
                || word_requires_block_v4(&assignment.value)
        })
        || command
            .redirections
            .iter()
            .any(|redirection| word_requires_block_v4(&redirection.target))
}

fn word_requires_block_v4(word: &ScriptWord) -> bool {
    word.parts.iter().any(|part| match part {
        ScriptWordPart::CommandSubstitution { statements, .. } => {
            statements_require_block_v4(statements)
        }
        ScriptWordPart::BraceExpansion { alternatives, .. }
        | ScriptWordPart::Array {
            elements: alternatives,
        } => alternatives.iter().any(word_requires_block_v4),
        ScriptWordPart::DeferredScript {
            source,
            statements,
            words,
        } => {
            source.starts_with("eval-function:")
                || statements_require_block_v4(statements)
                || words.iter().any(word_requires_block_v4)
        }
        ScriptWordPart::Literal { .. }
        | ScriptWordPart::Parameter { .. }
        | ScriptWordPart::Arithmetic { .. } => false,
    })
}

#[derive(Debug)]
pub enum ScriptValidationError {
    Limit(&'static str),
    Invalid(&'static str),
}

impl std::fmt::Display for ScriptValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit(name) => write!(formatter, "script IR limit exceeded: {name}"),
            Self::Invalid(message) => write!(formatter, "invalid script IR: {message}"),
        }
    }
}

impl std::error::Error for ScriptValidationError {}

#[cfg(test)]
mod registration_tests {
    use super::*;

    #[test]
    fn quoted_literal_marks_captured_runtime_arguments_as_data() {
        let word = ScriptWord::quoted_literal("{ action:with:colons; }");
        assert!(matches!(
            word.parts.as_slice(),
            [ScriptWordPart::Literal { quoted: true, .. }]
        ));
    }

    #[test]
    fn fish_command_globs_match_without_affecting_exact_bash_names() {
        assert!(registration_matches(
            ScriptDialect::Fish,
            "*clang*",
            "clang-18"
        ));
        assert!(!registration_matches(
            ScriptDialect::Bash,
            "python*",
            "python3"
        ));
    }

    #[test]
    fn zsh_extended_registration_patterns_support_groups_and_repetition() {
        assert!(registration_matches(
            ScriptDialect::Zsh,
            "(ruby|[ei]rb)[0-9.]#",
            "ruby3.3"
        ));
        assert!(registration_matches(
            ScriptDialect::Zsh,
            "qemu(|-system-*)",
            "qemu-system-x86_64"
        ));
        assert!(!registration_matches(
            ScriptDialect::Zsh,
            "python[0-9.]#",
            "python-alpha"
        ));
    }

    #[test]
    fn hostile_registration_patterns_are_stack_bounded() {
        let nested = format!("{}a|b{}", "(".repeat(1024), ")".repeat(1024));
        assert!(!registration_matches(ScriptDialect::Zsh, &nested, "a"));
        let pattern = "a?".repeat(500);
        let value = "ab".repeat(500);
        assert!(registration_matches(ScriptDialect::Zsh, &pattern, &value));
    }

    #[test]
    fn hostile_nesting_is_rejected_during_transpilation() {
        let mut source = "{ ".repeat(MAX_SCRIPT_DEPTH + 4);
        source.push_str(":; ");
        source.push_str(&"}; ".repeat(MAX_SCRIPT_DEPTH + 4));
        assert!(crate::rules::script_parser::parse_script(
            ScriptDialect::Bash,
            "hostile.bash",
            &source,
        )
        .is_err());
    }

    #[test]
    fn excessive_redirection_descriptors_are_rejected() {
        let mut module = crate::rules::script_parser::parse_script(
            ScriptDialect::Bash,
            "descriptor.bash",
            "complete -W value demo 2>&1\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &mut module.statements[0] else {
            panic!("expected command")
        };
        command.redirections[0].descriptor = Some(MAX_REDIRECTION_DESCRIPTOR + 1);
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("redirection descriptor"))
        ));
    }

    #[test]
    fn invalid_redirection_operators_are_rejected() {
        let mut module = crate::rules::script_parser::parse_script(
            ScriptDialect::Bash,
            "redirect.bash",
            "echo value > output\n",
        )
        .unwrap();
        let ScriptStatement::Command { command } = &mut module.statements[0] else {
            panic!("expected command");
        };
        command.redirections[0].operator = "open-anything".into();
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("redirection operator"))
        ));
    }

    #[test]
    fn zsh_function_table_metadata_is_native_sized_and_bounded() {
        let mut module = crate::rules::script_parser::parse_script(
            ScriptDialect::Zsh,
            "_metadata",
            "#compdef metadata\ncompadd value\n",
        )
        .unwrap();
        module.zsh_function_table_size = 1792;
        assert!(module.validate().is_ok());
        module.zsh_function_table_size = 7;
        module.zsh_function_names = vec!["_alpha".into(), "_beta".into()];
        assert!(module.validate().is_ok());
        module.zsh_function_table_size = 28;
        assert!(module.validate().is_ok(), "high-water tables do not shrink");
        module.zsh_function_table_size = 7;
        module.zsh_function_names.push("_alpha".into());
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("Zsh function names"))
        ));
        module.zsh_function_names.clear();
        module.zsh_function_snapshot = true;
        assert!(module.validate().is_ok(), "empty snapshots remain explicit");
        module.zsh_function_table_size = 68;
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("Zsh function table size"))
        ));
    }

    #[test]
    fn invalid_probe_capability_names_are_rejected() {
        let mut module = ScriptModule {
            dialect: ScriptDialect::Bash,
            source_path: "test.bash".into(),
            statements: Vec::new(),
            functions: Vec::new(),
            registrations: Vec::new(),
            probe_capabilities: vec!["../shell".into()],
            zsh_function_snapshot: false,
            zsh_function_table_size: 0,
            zsh_function_names: Vec::new(),
        };
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("script probe capability"))
        ));
        module.probe_capabilities = vec!["bash".into()];
        assert!(matches!(
            module.validate(),
            Err(ScriptValidationError::Invalid("script probe capability"))
        ));
    }
}

impl ScriptModule {
    pub(crate) fn requires_block_v4(&self) -> bool {
        statements_require_block_v4(&self.statements)
            || self
                .functions
                .iter()
                .any(|function| statements_require_block_v4(&function.body))
    }

    pub fn approximate_bytes(&self) -> usize {
        let mut state = ValidationState::default();
        let _ = state.string(&self.source_path);
        let _ = state.statements(&self.statements, 0);
        for function in &self.functions {
            let _ = state.function(function, 0);
        }
        for registration in &self.registrations {
            let _ = state.string(&registration.command);
            if let Some(service) = &registration.service {
                let _ = state.string(service);
            }
            if let ScriptEntry::Function { name } = &registration.entry {
                let _ = state.string(name);
            }
        }
        for capability in &self.probe_capabilities {
            let _ = state.string(capability);
        }
        for name in &self.zsh_function_names {
            let _ = state.string(name);
        }
        std::mem::size_of::<Self>()
            .saturating_add(state.string_bytes)
            .saturating_add(state.nodes.saturating_mul(64))
            .saturating_add(
                self.registrations
                    .len()
                    .saturating_mul(std::mem::size_of::<ScriptRegistration>()),
            )
            .saturating_add(
                self.probe_capabilities
                    .len()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
    }

    pub fn validate(&self) -> Result<(), ScriptValidationError> {
        let has_zsh_function_snapshot =
            self.zsh_function_snapshot || !self.zsh_function_names.is_empty();
        if has_zsh_function_snapshot {
            if self.dialect != ScriptDialect::Zsh
                || self.zsh_function_table_size == 0
                || self.zsh_function_names.len() > MAX_ZSH_FUNCTION_NAMES
                || self
                    .zsh_function_names
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
                    > MAX_ZSH_FUNCTION_NAME_BYTES
            {
                return Err(ScriptValidationError::Invalid("Zsh function names"));
            }
            let mut seen = HashSet::with_capacity(self.zsh_function_names.len());
            for name in &self.zsh_function_names {
                if name.is_empty() || name.contains(['/', '\0']) || !seen.insert(name.as_str()) {
                    return Err(ScriptValidationError::Invalid("Zsh function names"));
                }
            }
            let mut expected_size = 7_u32;
            while self.zsh_function_names.len() >= expected_size as usize * 2 {
                expected_size = expected_size.saturating_mul(4);
            }
            if self.zsh_function_table_size < expected_size {
                return Err(ScriptValidationError::Invalid("Zsh function table size"));
            }
        }
        if self.zsh_function_snapshot && self.dialect != ScriptDialect::Zsh {
            return Err(ScriptValidationError::Invalid("Zsh function snapshot"));
        }
        if self.zsh_function_table_size != 0 {
            let mut size = self.zsh_function_table_size;
            while size > 7 && size % 4 == 0 {
                size /= 4;
            }
            if self.dialect != ScriptDialect::Zsh
                || size != 7
                || self.zsh_function_table_size > MAX_ZSH_FUNCTION_TABLE_BUCKETS
            {
                return Err(ScriptValidationError::Invalid("Zsh function table size"));
            }
        }
        let mut state = ValidationState::default();
        state.string(&self.source_path)?;
        state.statements(&self.statements, 0)?;
        for function in &self.functions {
            state.function(function, 0)?;
        }
        for name in &self.zsh_function_names {
            state.string(name)?;
        }
        for capability in &self.probe_capabilities {
            state.string(capability)?;
            if capability.is_empty()
                || capability.contains(['/', '\0'])
                || capability.starts_with('-')
                || matches!(capability.as_str(), "sh" | "bash" | "dash" | "zsh" | "fish")
            {
                return Err(ScriptValidationError::Invalid("script probe capability"));
            }
        }
        for registration in &self.registrations {
            state.string(&registration.command)?;
            if registration.command.is_empty()
                || registration.command.len() > MAX_REGISTRATION_BYTES
                || registration.command.contains('\0')
            {
                return Err(ScriptValidationError::Invalid("registration command"));
            }
            if let Some(service) = &registration.service {
                state.string(service)?;
                if service.is_empty() || service.contains('\0') {
                    return Err(ScriptValidationError::Invalid("registration service"));
                }
            }
            if let ScriptEntry::Function { name } = &registration.entry {
                state.string(name)?;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ValidationState {
    nodes: usize,
    words: usize,
    string_bytes: usize,
}

impl ValidationState {
    fn node(&mut self, depth: usize) -> Result<(), ScriptValidationError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_SCRIPT_NODES {
            return Err(ScriptValidationError::Limit("nodes"));
        }
        if depth > MAX_SCRIPT_DEPTH {
            return Err(ScriptValidationError::Limit("depth"));
        }
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), ScriptValidationError> {
        if value.len() > MAX_SCRIPT_INDIVIDUAL_STRING_BYTES {
            return Err(ScriptValidationError::Limit("individual string"));
        }
        if value.contains('\0') {
            return Err(ScriptValidationError::Invalid("NUL in string"));
        }
        self.string_bytes = self.string_bytes.saturating_add(value.len());
        if self.string_bytes > MAX_SCRIPT_STRING_BYTES {
            return Err(ScriptValidationError::Limit("string bytes"));
        }
        Ok(())
    }

    fn function(
        &mut self,
        function: &ScriptFunction,
        depth: usize,
    ) -> Result<(), ScriptValidationError> {
        self.node(depth)?;
        self.string(&function.name)?;
        for argument in &function.arguments {
            self.word(argument, depth + 1)?;
        }
        self.statements(&function.body, depth + 1)
    }

    fn statements(
        &mut self,
        statements: &[ScriptStatement],
        depth: usize,
    ) -> Result<(), ScriptValidationError> {
        for statement in statements {
            self.statement(statement, depth)?;
        }
        Ok(())
    }

    fn statement(
        &mut self,
        statement: &ScriptStatement,
        depth: usize,
    ) -> Result<(), ScriptValidationError> {
        self.node(depth)?;
        match statement {
            ScriptStatement::Command { command } => self.command(command, depth + 1),
            ScriptStatement::Pipeline { commands, .. } => {
                for command in commands {
                    self.statement(command, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::AndOr { first, rest } => {
                self.statement(first, depth + 1)?;
                for arm in rest {
                    self.statement(&arm.statement, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    self.statements(&branch.condition, depth + 1)?;
                    self.statements(&branch.body, depth + 1)?;
                }
                self.statements(otherwise, depth + 1)
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                self.statements(condition, depth + 1)?;
                self.statements(body, depth + 1)
            }
            ScriptStatement::For {
                variables,
                words,
                body,
            } => {
                for variable in variables {
                    self.string(variable)?;
                }
                for word in words {
                    self.word(word, depth + 1)?;
                }
                self.statements(body, depth + 1)
            }
            ScriptStatement::Case { word, arms } => {
                self.word(word, depth + 1)?;
                for arm in arms {
                    for pattern in &arm.patterns {
                        self.word(pattern, depth + 1)?;
                    }
                    self.statements(&arm.body, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::Function { function } => self.function(function, depth + 1),
            ScriptStatement::Group { body, .. } => self.statements(body, depth + 1),
            ScriptStatement::Return { status } => {
                if let Some(status) = status {
                    self.word(status, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::Redirected {
                statement,
                redirections,
            } => {
                self.statement(statement, depth + 1)?;
                for redirection in redirections {
                    self.redirection(redirection, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => Ok(()),
        }
    }

    fn command(
        &mut self,
        command: &ScriptCommand,
        depth: usize,
    ) -> Result<(), ScriptValidationError> {
        self.node(depth)?;
        for assignment in &command.assignments {
            self.string(&assignment.name)?;
            if let Some(index) = &assignment.index {
                self.word(index, depth + 1)?;
            }
            self.word(&assignment.value, depth + 1)?;
        }
        for word in &command.words {
            self.word(word, depth + 1)?;
        }
        for redirection in &command.redirections {
            self.redirection(redirection, depth + 1)?;
        }
        Ok(())
    }

    fn redirection(
        &mut self,
        redirection: &ScriptRedirection,
        depth: usize,
    ) -> Result<(), ScriptValidationError> {
        self.string(&redirection.operator)?;
        if redirection
            .descriptor
            .is_some_and(|descriptor| descriptor > MAX_REDIRECTION_DESCRIPTOR)
        {
            return Err(ScriptValidationError::Invalid("redirection descriptor"));
        }
        if !matches!(
            redirection.operator.as_str(),
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
        ) {
            return Err(ScriptValidationError::Invalid("redirection operator"));
        }
        self.word(&redirection.target, depth)
    }

    fn word(&mut self, word: &ScriptWord, depth: usize) -> Result<(), ScriptValidationError> {
        self.node(depth)?;
        self.words = self.words.saturating_add(1);
        if self.words > MAX_SCRIPT_WORDS {
            return Err(ScriptValidationError::Limit("words"));
        }
        for part in &word.parts {
            self.node(depth + 1)?;
            match part {
                ScriptWordPart::Literal { value, .. }
                | ScriptWordPart::Parameter {
                    expression: value, ..
                }
                | ScriptWordPart::Arithmetic {
                    expression: value, ..
                } => self.string(value)?,
                ScriptWordPart::CommandSubstitution { statements, .. } => {
                    self.statements(statements, depth + 2)?;
                }
                ScriptWordPart::BraceExpansion { alternatives, .. } => {
                    for alternative in alternatives {
                        self.word(alternative, depth + 2)?;
                    }
                }
                ScriptWordPart::Array { elements } => {
                    for element in elements {
                        self.word(element, depth + 2)?;
                    }
                }
                ScriptWordPart::DeferredScript {
                    source,
                    statements,
                    words,
                } => {
                    self.string(source)?;
                    self.statements(statements, depth + 2)?;
                    for word in words {
                        self.word(word, depth + 2)?;
                    }
                }
            }
        }
        Ok(())
    }
}
