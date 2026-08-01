// SPDX-License-Identifier: GPL-2.0-or-later

//! Portable shell-completion script IR.
//!
//! The three source frontends compile shell syntax into this data model at
//! pack-build time. The runtime never parses or sources upstream shell text.

use std::borrow::Cow;

use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

pub const MAX_SCRIPT_NODES: usize = 1_000_000;
pub const MAX_SCRIPT_DEPTH: usize = 32;
pub const MAX_SCRIPT_WORDS: usize = 4_000_000;
pub const MAX_SCRIPT_STRING_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_SCRIPT_TAG_DEFERRED_FIELDS: usize = 512 * 1024;
pub(crate) const MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES: usize = 16 * 1024 * 1024;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScriptEntry {
    Function { name: String },
    FishComplete { statement_index: u32 },
    Module,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScriptEntryKind {
    Function,
    FishComplete,
    Module,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScriptStatementOp {
    Command,
    AndOr,
    Pipeline,
    If,
    While,
    For,
    Case,
    Function,
    Group,
    Return,
    Break,
    Continue,
    Noop,
    Redirected,
}

#[derive(Default)]
struct ScriptStatementFields {
    command: Option<ScriptCommand>,
    first: Option<Box<ScriptStatement>>,
    rest: Option<Vec<ScriptAndOrArm>>,
    commands: Option<Vec<ScriptStatement>>,
    negated: Option<bool>,
    branches: Option<Vec<ScriptConditionalBranch>>,
    otherwise: Option<Vec<ScriptStatement>>,
    condition: Option<Vec<ScriptStatement>>,
    body: Option<Vec<ScriptStatement>>,
    until: Option<bool>,
    variables: Option<Vec<String>>,
    words: Option<Vec<ScriptWord>>,
    word: Option<ScriptWord>,
    arms: Option<Vec<ScriptCaseArm>>,
    function: Option<ScriptFunction>,
    subshell: Option<bool>,
    status: Option<Option<ScriptWord>>,
    statement: Option<Box<ScriptStatement>>,
    redirections: Option<Vec<ScriptRedirection>>,
}

struct ScriptFieldName<'de>(Cow<'de, str>);

struct ScriptFieldNameVisitor;

impl<'de> Visitor<'de> for ScriptFieldNameVisitor {
    type Value = ScriptFieldName<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a script IR field name")
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(ScriptFieldName(Cow::Borrowed(value)))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ScriptFieldName(Cow::Owned(value.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(ScriptFieldName(Cow::Owned(value)))
    }
}

impl<'de> Deserialize<'de> for ScriptFieldName<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_identifier(ScriptFieldNameVisitor)
    }
}

fn set_deserialized_field<T, E: serde::de::Error>(
    slot: &mut Option<T>,
    value: T,
    name: &'static str,
) -> Result<(), E> {
    if slot.is_some() {
        return Err(E::duplicate_field(name));
    }
    *slot = Some(value);
    Ok(())
}

fn json_field<T: DeserializeOwned, E: serde::de::Error>(value: &RawValue) -> Result<T, E> {
    serde_json::from_str(value.get()).map_err(E::custom)
}

#[derive(Default)]
struct ScriptEntryFields {
    name: Option<String>,
    statement_index: Option<u32>,
}

impl ScriptEntryFields {
    fn read_map<'de, A: MapAccess<'de>>(
        &mut self,
        kind: ScriptEntryKind,
        name: &str,
        map: &mut A,
    ) -> Result<(), A::Error> {
        match (kind, name) {
            (ScriptEntryKind::Function, "name") => {
                set_deserialized_field(&mut self.name, map.next_value()?, "name")
            }
            (ScriptEntryKind::FishComplete, "statement_index") => set_deserialized_field(
                &mut self.statement_index,
                map.next_value()?,
                "statement_index",
            ),
            _ => map.next_value::<IgnoredAny>().map(|_| ()),
        }
    }

    fn read_json<E: serde::de::Error>(
        &mut self,
        kind: ScriptEntryKind,
        name: &str,
        value: &RawValue,
    ) -> Result<(), E> {
        match (kind, name) {
            (ScriptEntryKind::Function, "name") => {
                set_deserialized_field(&mut self.name, json_field(value)?, "name")
            }
            (ScriptEntryKind::FishComplete, "statement_index") => set_deserialized_field(
                &mut self.statement_index,
                json_field(value)?,
                "statement_index",
            ),
            _ => Ok(()),
        }
    }

    fn finish<E: serde::de::Error>(self, kind: ScriptEntryKind) -> Result<ScriptEntry, E> {
        match kind {
            ScriptEntryKind::Function => Ok(ScriptEntry::Function {
                name: self.name.ok_or_else(|| E::missing_field("name"))?,
            }),
            ScriptEntryKind::FishComplete => Ok(ScriptEntry::FishComplete {
                statement_index: self
                    .statement_index
                    .ok_or_else(|| E::missing_field("statement_index"))?,
            }),
            ScriptEntryKind::Module => Ok(ScriptEntry::Module),
        }
    }
}

struct ScriptEntryVisitor;

impl<'de> Visitor<'de> for ScriptEntryVisitor {
    type Value = ScriptEntry;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a tagged script entry")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut kind = None;
        let mut fields = ScriptEntryFields::default();
        let mut deferred = Vec::<(Cow<'de, str>, &'de RawValue)>::new();
        let mut deferred_name_bytes = 0_usize;
        while let Some(ScriptFieldName(name)) = map.next_key()? {
            if name == "kind" {
                if kind.is_some() {
                    return Err(serde::de::Error::duplicate_field("kind"));
                }
                let parsed_kind = map.next_value()?;
                kind = Some(parsed_kind);
                for (name, value) in deferred.drain(..) {
                    fields.read_json::<A::Error>(parsed_kind, &name, value)?;
                }
            } else if let Some(kind) = kind {
                fields.read_map(kind, &name, &mut map)?;
            } else {
                deferred_name_bytes = deferred_name_bytes.saturating_add(name.len());
                if deferred.len() >= MAX_SCRIPT_TAG_DEFERRED_FIELDS
                    || deferred_name_bytes > MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES
                {
                    return Err(serde::de::Error::custom(
                        "script tag appears after the bounded field limit",
                    ));
                }
                deferred.push((name, map.next_value()?));
            }
        }
        let kind = kind.ok_or_else(|| serde::de::Error::missing_field("kind"))?;
        for (name, value) in deferred {
            fields.read_json::<A::Error>(kind, &name, value)?;
        }
        fields.finish(kind)
    }
}

impl<'de> Deserialize<'de> for ScriptEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ScriptEntryVisitor)
    }
}

impl ScriptStatementFields {
    fn read_map<'de, A: MapAccess<'de>>(
        &mut self,
        op: ScriptStatementOp,
        name: &str,
        map: &mut A,
    ) -> Result<(), A::Error> {
        match (op, name) {
            (ScriptStatementOp::Command, "command") => {
                set_deserialized_field(&mut self.command, map.next_value()?, "command")
            }
            (ScriptStatementOp::AndOr, "first") => {
                set_deserialized_field(&mut self.first, map.next_value()?, "first")
            }
            (ScriptStatementOp::AndOr, "rest") => {
                set_deserialized_field(&mut self.rest, map.next_value()?, "rest")
            }
            (ScriptStatementOp::Pipeline, "commands") => {
                set_deserialized_field(&mut self.commands, map.next_value()?, "commands")
            }
            (ScriptStatementOp::Pipeline, "negated") => {
                set_deserialized_field(&mut self.negated, map.next_value()?, "negated")
            }
            (ScriptStatementOp::If, "branches") => {
                set_deserialized_field(&mut self.branches, map.next_value()?, "branches")
            }
            (ScriptStatementOp::If, "otherwise") => {
                set_deserialized_field(&mut self.otherwise, map.next_value()?, "otherwise")
            }
            (ScriptStatementOp::While, "condition") => {
                set_deserialized_field(&mut self.condition, map.next_value()?, "condition")
            }
            (
                ScriptStatementOp::While | ScriptStatementOp::For | ScriptStatementOp::Group,
                "body",
            ) => set_deserialized_field(&mut self.body, map.next_value()?, "body"),
            (ScriptStatementOp::While, "until") => {
                set_deserialized_field(&mut self.until, map.next_value()?, "until")
            }
            (ScriptStatementOp::For, "variables") => {
                set_deserialized_field(&mut self.variables, map.next_value()?, "variables")
            }
            (ScriptStatementOp::For, "words") => {
                set_deserialized_field(&mut self.words, map.next_value()?, "words")
            }
            (ScriptStatementOp::Case, "word") => {
                set_deserialized_field(&mut self.word, map.next_value()?, "word")
            }
            (ScriptStatementOp::Case, "arms") => {
                set_deserialized_field(&mut self.arms, map.next_value()?, "arms")
            }
            (ScriptStatementOp::Function, "function") => {
                set_deserialized_field(&mut self.function, map.next_value()?, "function")
            }
            (ScriptStatementOp::Group, "subshell") => {
                set_deserialized_field(&mut self.subshell, map.next_value()?, "subshell")
            }
            (ScriptStatementOp::Return, "status") => {
                set_deserialized_field(&mut self.status, map.next_value()?, "status")
            }
            (ScriptStatementOp::Redirected, "statement") => {
                set_deserialized_field(&mut self.statement, map.next_value()?, "statement")
            }
            (ScriptStatementOp::Redirected, "redirections") => {
                set_deserialized_field(&mut self.redirections, map.next_value()?, "redirections")
            }
            _ => map.next_value::<IgnoredAny>().map(|_| ()),
        }
    }

    fn read_json<E: serde::de::Error>(
        &mut self,
        op: ScriptStatementOp,
        name: &str,
        value: &RawValue,
    ) -> Result<(), E> {
        match (op, name) {
            (ScriptStatementOp::Command, "command") => {
                set_deserialized_field(&mut self.command, json_field(value)?, "command")
            }
            (ScriptStatementOp::AndOr, "first") => {
                set_deserialized_field(&mut self.first, json_field(value)?, "first")
            }
            (ScriptStatementOp::AndOr, "rest") => {
                set_deserialized_field(&mut self.rest, json_field(value)?, "rest")
            }
            (ScriptStatementOp::Pipeline, "commands") => {
                set_deserialized_field(&mut self.commands, json_field(value)?, "commands")
            }
            (ScriptStatementOp::Pipeline, "negated") => {
                set_deserialized_field(&mut self.negated, json_field(value)?, "negated")
            }
            (ScriptStatementOp::If, "branches") => {
                set_deserialized_field(&mut self.branches, json_field(value)?, "branches")
            }
            (ScriptStatementOp::If, "otherwise") => {
                set_deserialized_field(&mut self.otherwise, json_field(value)?, "otherwise")
            }
            (ScriptStatementOp::While, "condition") => {
                set_deserialized_field(&mut self.condition, json_field(value)?, "condition")
            }
            (
                ScriptStatementOp::While | ScriptStatementOp::For | ScriptStatementOp::Group,
                "body",
            ) => set_deserialized_field(&mut self.body, json_field(value)?, "body"),
            (ScriptStatementOp::While, "until") => {
                set_deserialized_field(&mut self.until, json_field(value)?, "until")
            }
            (ScriptStatementOp::For, "variables") => {
                set_deserialized_field(&mut self.variables, json_field(value)?, "variables")
            }
            (ScriptStatementOp::For, "words") => {
                set_deserialized_field(&mut self.words, json_field(value)?, "words")
            }
            (ScriptStatementOp::Case, "word") => {
                set_deserialized_field(&mut self.word, json_field(value)?, "word")
            }
            (ScriptStatementOp::Case, "arms") => {
                set_deserialized_field(&mut self.arms, json_field(value)?, "arms")
            }
            (ScriptStatementOp::Function, "function") => {
                set_deserialized_field(&mut self.function, json_field(value)?, "function")
            }
            (ScriptStatementOp::Group, "subshell") => {
                set_deserialized_field(&mut self.subshell, json_field(value)?, "subshell")
            }
            (ScriptStatementOp::Return, "status") => {
                set_deserialized_field(&mut self.status, json_field(value)?, "status")
            }
            (ScriptStatementOp::Redirected, "statement") => {
                set_deserialized_field(&mut self.statement, json_field(value)?, "statement")
            }
            (ScriptStatementOp::Redirected, "redirections") => {
                set_deserialized_field(&mut self.redirections, json_field(value)?, "redirections")
            }
            _ => Ok(()),
        }
    }

    fn finish<E: serde::de::Error>(self, op: ScriptStatementOp) -> Result<ScriptStatement, E> {
        let missing = |name| E::missing_field(name);
        Ok(match op {
            ScriptStatementOp::Command => ScriptStatement::Command {
                command: self.command.ok_or_else(|| missing("command"))?,
            },
            ScriptStatementOp::AndOr => ScriptStatement::AndOr {
                first: self.first.ok_or_else(|| missing("first"))?,
                rest: compact_vec(self.rest.ok_or_else(|| missing("rest"))?),
            },
            ScriptStatementOp::Pipeline => ScriptStatement::Pipeline {
                commands: compact_vec(self.commands.ok_or_else(|| missing("commands"))?),
                negated: self.negated.unwrap_or(false),
            },
            ScriptStatementOp::If => ScriptStatement::If {
                branches: compact_vec(self.branches.ok_or_else(|| missing("branches"))?),
                otherwise: compact_vec(self.otherwise.unwrap_or_default()),
            },
            ScriptStatementOp::While => ScriptStatement::While {
                condition: compact_vec(self.condition.ok_or_else(|| missing("condition"))?),
                body: compact_vec(self.body.ok_or_else(|| missing("body"))?),
                until: self.until.unwrap_or(false),
            },
            ScriptStatementOp::For => ScriptStatement::For {
                variables: compact_vec(self.variables.ok_or_else(|| missing("variables"))?),
                words: compact_vec(self.words.ok_or_else(|| missing("words"))?),
                body: compact_vec(self.body.ok_or_else(|| missing("body"))?),
            },
            ScriptStatementOp::Case => ScriptStatement::Case {
                word: self.word.ok_or_else(|| missing("word"))?,
                arms: compact_vec(self.arms.ok_or_else(|| missing("arms"))?),
            },
            ScriptStatementOp::Function => ScriptStatement::Function {
                function: self.function.ok_or_else(|| missing("function"))?,
            },
            ScriptStatementOp::Group => ScriptStatement::Group {
                body: compact_vec(self.body.ok_or_else(|| missing("body"))?),
                subshell: self.subshell.unwrap_or(false),
            },
            ScriptStatementOp::Return => ScriptStatement::Return {
                status: self.status.unwrap_or(None),
            },
            ScriptStatementOp::Break => ScriptStatement::Break,
            ScriptStatementOp::Continue => ScriptStatement::Continue,
            ScriptStatementOp::Noop => ScriptStatement::Noop,
            ScriptStatementOp::Redirected => ScriptStatement::Redirected {
                statement: self.statement.ok_or_else(|| missing("statement"))?,
                redirections: compact_vec(
                    self.redirections.ok_or_else(|| missing("redirections"))?,
                ),
            },
        })
    }
}

struct ScriptStatementVisitor;

impl<'de> Visitor<'de> for ScriptStatementVisitor {
    type Value = ScriptStatement;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a tagged script statement")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut op = None;
        let mut fields = ScriptStatementFields::default();
        let mut deferred = Vec::<(Cow<'de, str>, &'de RawValue)>::new();
        let mut deferred_name_bytes = 0_usize;
        while let Some(ScriptFieldName(name)) = map.next_key()? {
            if name == "op" {
                if op.is_some() {
                    return Err(serde::de::Error::duplicate_field("op"));
                }
                let parsed_op = map.next_value()?;
                op = Some(parsed_op);
                for (name, value) in deferred.drain(..) {
                    fields.read_json::<A::Error>(parsed_op, &name, value)?;
                }
            } else if let Some(op) = op {
                fields.read_map(op, &name, &mut map)?;
            } else {
                deferred_name_bytes = deferred_name_bytes.saturating_add(name.len());
                if deferred.len() >= MAX_SCRIPT_TAG_DEFERRED_FIELDS
                    || deferred_name_bytes > MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES
                {
                    return Err(serde::de::Error::custom(
                        "script tag appears after the bounded field limit",
                    ));
                }
                deferred.push((name, map.next_value()?));
            }
        }
        let op = op.ok_or_else(|| serde::de::Error::missing_field("op"))?;
        for (name, value) in deferred {
            fields.read_json::<A::Error>(op, &name, value)?;
        }
        fields.finish(op)
    }
}

impl<'de> Deserialize<'de> for ScriptStatement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ScriptStatementVisitor)
    }
}

fn compact_vec<T>(mut values: Vec<T>) -> Vec<T> {
    values.shrink_to_fit();
    values
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScriptWordPartKind {
    Literal,
    Parameter,
    CommandSubstitution,
    Arithmetic,
    BraceExpansion,
    Array,
    DeferredScript,
}

#[derive(Default)]
struct ScriptWordPartFields {
    value: Option<String>,
    quoted: Option<bool>,
    expression: Option<String>,
    statements: Option<Vec<ScriptStatement>>,
    alternatives: Option<Vec<ScriptWord>>,
    elements: Option<Vec<ScriptWord>>,
    source: Option<String>,
    words: Option<Vec<ScriptWord>>,
}

impl ScriptWordPartFields {
    fn read_map<'de, A: MapAccess<'de>>(
        &mut self,
        kind: ScriptWordPartKind,
        name: &str,
        map: &mut A,
    ) -> Result<(), A::Error> {
        match (kind, name) {
            (ScriptWordPartKind::Literal, "value") => {
                set_deserialized_field(&mut self.value, map.next_value()?, "value")
            }
            (
                ScriptWordPartKind::Literal
                | ScriptWordPartKind::Parameter
                | ScriptWordPartKind::CommandSubstitution
                | ScriptWordPartKind::Arithmetic
                | ScriptWordPartKind::BraceExpansion,
                "quoted",
            ) => set_deserialized_field(&mut self.quoted, map.next_value()?, "quoted"),
            (ScriptWordPartKind::Parameter | ScriptWordPartKind::Arithmetic, "expression") => {
                set_deserialized_field(&mut self.expression, map.next_value()?, "expression")
            }
            (ScriptWordPartKind::CommandSubstitution, "statements")
            | (ScriptWordPartKind::DeferredScript, "statements") => {
                set_deserialized_field(&mut self.statements, map.next_value()?, "statements")
            }
            (ScriptWordPartKind::BraceExpansion, "alternatives") => {
                set_deserialized_field(&mut self.alternatives, map.next_value()?, "alternatives")
            }
            (ScriptWordPartKind::Array, "elements") => {
                set_deserialized_field(&mut self.elements, map.next_value()?, "elements")
            }
            (ScriptWordPartKind::DeferredScript, "source") => {
                set_deserialized_field(&mut self.source, map.next_value()?, "source")
            }
            (ScriptWordPartKind::DeferredScript, "words") => {
                set_deserialized_field(&mut self.words, map.next_value()?, "words")
            }
            _ => map.next_value::<IgnoredAny>().map(|_| ()),
        }
    }

    fn read_json<E: serde::de::Error>(
        &mut self,
        kind: ScriptWordPartKind,
        name: &str,
        value: &RawValue,
    ) -> Result<(), E> {
        match (kind, name) {
            (ScriptWordPartKind::Literal, "value") => {
                set_deserialized_field(&mut self.value, json_field(value)?, "value")
            }
            (
                ScriptWordPartKind::Literal
                | ScriptWordPartKind::Parameter
                | ScriptWordPartKind::CommandSubstitution
                | ScriptWordPartKind::Arithmetic
                | ScriptWordPartKind::BraceExpansion,
                "quoted",
            ) => set_deserialized_field(&mut self.quoted, json_field(value)?, "quoted"),
            (ScriptWordPartKind::Parameter | ScriptWordPartKind::Arithmetic, "expression") => {
                set_deserialized_field(&mut self.expression, json_field(value)?, "expression")
            }
            (ScriptWordPartKind::CommandSubstitution, "statements")
            | (ScriptWordPartKind::DeferredScript, "statements") => {
                set_deserialized_field(&mut self.statements, json_field(value)?, "statements")
            }
            (ScriptWordPartKind::BraceExpansion, "alternatives") => {
                set_deserialized_field(&mut self.alternatives, json_field(value)?, "alternatives")
            }
            (ScriptWordPartKind::Array, "elements") => {
                set_deserialized_field(&mut self.elements, json_field(value)?, "elements")
            }
            (ScriptWordPartKind::DeferredScript, "source") => {
                set_deserialized_field(&mut self.source, json_field(value)?, "source")
            }
            (ScriptWordPartKind::DeferredScript, "words") => {
                set_deserialized_field(&mut self.words, json_field(value)?, "words")
            }
            _ => Ok(()),
        }
    }

    fn finish<E: serde::de::Error>(self, kind: ScriptWordPartKind) -> Result<ScriptWordPart, E> {
        let missing = |name| E::missing_field(name);
        Ok(match kind {
            ScriptWordPartKind::Literal => ScriptWordPart::Literal {
                value: self.value.ok_or_else(|| missing("value"))?,
                quoted: self.quoted.unwrap_or(false),
            },
            ScriptWordPartKind::Parameter => ScriptWordPart::Parameter {
                expression: self.expression.ok_or_else(|| missing("expression"))?,
                quoted: self.quoted.unwrap_or(false),
            },
            ScriptWordPartKind::CommandSubstitution => ScriptWordPart::CommandSubstitution {
                statements: compact_vec(self.statements.ok_or_else(|| missing("statements"))?),
                quoted: self.quoted.unwrap_or(false),
            },
            ScriptWordPartKind::Arithmetic => ScriptWordPart::Arithmetic {
                expression: self.expression.ok_or_else(|| missing("expression"))?,
                quoted: self.quoted.unwrap_or(false),
            },
            ScriptWordPartKind::BraceExpansion => ScriptWordPart::BraceExpansion {
                alternatives: compact_vec(
                    self.alternatives.ok_or_else(|| missing("alternatives"))?,
                ),
                quoted: self.quoted.unwrap_or(false),
            },
            ScriptWordPartKind::Array => ScriptWordPart::Array {
                elements: compact_vec(self.elements.ok_or_else(|| missing("elements"))?),
            },
            ScriptWordPartKind::DeferredScript => ScriptWordPart::DeferredScript {
                source: self.source.ok_or_else(|| missing("source"))?,
                statements: compact_vec(self.statements.unwrap_or_default()),
                words: compact_vec(self.words.unwrap_or_default()),
            },
        })
    }
}

struct ScriptWordPartVisitor;

impl<'de> Visitor<'de> for ScriptWordPartVisitor {
    type Value = ScriptWordPart;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a tagged script word part")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut kind = None;
        let mut fields = ScriptWordPartFields::default();
        let mut deferred = Vec::<(Cow<'de, str>, &'de RawValue)>::new();
        let mut deferred_name_bytes = 0_usize;
        while let Some(ScriptFieldName(name)) = map.next_key()? {
            if name == "kind" {
                if kind.is_some() {
                    return Err(serde::de::Error::duplicate_field("kind"));
                }
                let parsed_kind = map.next_value()?;
                kind = Some(parsed_kind);
                for (name, value) in deferred.drain(..) {
                    fields.read_json::<A::Error>(parsed_kind, &name, value)?;
                }
            } else if let Some(kind) = kind {
                fields.read_map(kind, &name, &mut map)?;
            } else {
                deferred_name_bytes = deferred_name_bytes.saturating_add(name.len());
                if deferred.len() >= MAX_SCRIPT_TAG_DEFERRED_FIELDS
                    || deferred_name_bytes > MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES
                {
                    return Err(serde::de::Error::custom(
                        "script tag appears after the bounded field limit",
                    ));
                }
                deferred.push((name, map.next_value()?));
            }
        }
        let kind = kind.ok_or_else(|| serde::de::Error::missing_field("kind"))?;
        for (name, value) in deferred {
            fields.read_json::<A::Error>(kind, &name, value)?;
        }
        fields.finish(kind)
    }
}

impl<'de> Deserialize<'de> for ScriptWordPart {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ScriptWordPartVisitor)
    }
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
    fn tagged_ir_deserializes_without_requiring_tag_first() {
        let statement: ScriptStatement = serde_json::from_str(
            r#"{"command":{"assignments":[],"words":[],"redirections":[]},"op":"command"}"#,
        )
        .unwrap();
        assert!(matches!(statement, ScriptStatement::Command { .. }));

        let part: ScriptWordPart =
            serde_json::from_str(r#"{"value":"item","quoted":false,"kind":"literal"}"#).unwrap();
        assert!(matches!(part, ScriptWordPart::Literal { value, .. } if value == "item"));

        let entry: ScriptEntry =
            serde_json::from_str(r#"{"name":"_demo","kind":"function"}"#).unwrap();
        assert!(matches!(entry, ScriptEntry::Function { name } if name == "_demo"));

        assert!(serde_json::from_str::<ScriptStatement>(r#"{"op":"noop","body":0}"#).is_ok());
        assert!(serde_json::from_str::<ScriptEntry>(r#"{"kind":"module","name":0}"#).is_ok());
        assert!(
            serde_json::from_str::<ScriptWordPart>(
                r#"{"kind":"literal","value":"item","statements":0}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<ScriptStatement>(
                r#"{"op":"pipeline","commands":[],"negated":null}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ScriptWordPart>(
                r#"{"kind":"literal","value":"item","quoted":null}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<ScriptStatement>(
            r#"{"command":{"assignments":[],"assignments":[],"words":[],"redirections":[]},"op":"command"}"#
        )
        .is_err());

        let mut late = String::from("{");
        for index in 0..5000 {
            if index != 0 {
                late.push(',');
            }
            late.push_str(&format!(r#""unknown-{index}":null"#));
        }
        late.push_str(r#", "op":"noop"}"#);
        assert_eq!(
            serde_json::from_str::<ScriptStatement>(&late).unwrap(),
            ScriptStatement::Noop
        );
        assert_eq!(
            serde_json::from_str::<ScriptStatement>(r#"{"body":0,"\u006fp":"noop"}"#).unwrap(),
            ScriptStatement::Noop
        );
        assert_eq!(
            serde_json::from_str::<ScriptStatement>(
                r#"{"kind":null,"irrelevant":false,"op":"noop"}"#
            )
            .unwrap(),
            ScriptStatement::Noop
        );
        assert!(matches!(
            serde_json::from_str::<ScriptWordPart>(
                r#"{"op":null,"irrelevant":false,"kind":"literal","value":"item"}"#
            )
            .unwrap(),
            ScriptWordPart::Literal { value, .. } if value == "item"
        ));
    }

    #[test]
    fn validation_accounts_the_retained_script_tree_in_one_pass() {
        let module = crate::rules::script_parser::parse_script(
            ScriptDialect::Fish,
            "accounting.fish",
            "if true; complete -c demo -l value; end\n",
        )
        .unwrap();
        assert_eq!(
            module.validate_and_approximate_bytes().unwrap(),
            module.approximate_bytes()
        );
    }

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

fn string_vector_bytes(values: &Vec<String>) -> usize {
    values
        .capacity()
        .saturating_mul(std::mem::size_of::<String>())
        .saturating_add(values.iter().map(String::capacity).sum::<usize>())
}

fn script_statements_bytes(statements: &Vec<ScriptStatement>) -> usize {
    statements
        .capacity()
        .saturating_mul(std::mem::size_of::<ScriptStatement>())
        .saturating_add(
            statements
                .iter()
                .map(script_statement_heap_bytes)
                .sum::<usize>(),
        )
}

fn script_words_bytes(words: &Vec<ScriptWord>) -> usize {
    words
        .capacity()
        .saturating_mul(std::mem::size_of::<ScriptWord>())
        .saturating_add(words.iter().map(script_word_heap_bytes).sum::<usize>())
}

fn script_function_heap_bytes(function: &ScriptFunction) -> usize {
    function
        .name
        .capacity()
        .saturating_add(script_words_bytes(&function.arguments))
        .saturating_add(script_statements_bytes(&function.body))
}

fn script_registration_heap_bytes(registration: &ScriptRegistration) -> usize {
    registration
        .command
        .capacity()
        .saturating_add(registration.service.as_ref().map_or(0, String::capacity))
        .saturating_add(match &registration.entry {
            ScriptEntry::Function { name } => name.capacity(),
            ScriptEntry::FishComplete { .. } | ScriptEntry::Module => 0,
        })
}

fn script_statement_heap_bytes(statement: &ScriptStatement) -> usize {
    match statement {
        ScriptStatement::Command { command } => script_command_heap_bytes(command),
        ScriptStatement::AndOr { first, rest } => std::mem::size_of::<ScriptStatement>()
            .saturating_add(script_statement_heap_bytes(first))
            .saturating_add(
                rest.capacity()
                    .saturating_mul(std::mem::size_of::<ScriptAndOrArm>()),
            )
            .saturating_add(
                rest.iter()
                    .map(|arm| {
                        std::mem::size_of::<ScriptStatement>()
                            .saturating_add(script_statement_heap_bytes(&arm.statement))
                    })
                    .sum::<usize>(),
            ),
        ScriptStatement::Pipeline { commands, .. }
        | ScriptStatement::Group { body: commands, .. } => script_statements_bytes(commands),
        ScriptStatement::If {
            branches,
            otherwise,
        } => branches
            .capacity()
            .saturating_mul(std::mem::size_of::<ScriptConditionalBranch>())
            .saturating_add(
                branches
                    .iter()
                    .map(|branch| {
                        script_statements_bytes(&branch.condition)
                            .saturating_add(script_statements_bytes(&branch.body))
                    })
                    .sum::<usize>(),
            )
            .saturating_add(script_statements_bytes(otherwise)),
        ScriptStatement::While {
            condition, body, ..
        } => script_statements_bytes(condition).saturating_add(script_statements_bytes(body)),
        ScriptStatement::For {
            variables,
            words,
            body,
        } => string_vector_bytes(variables)
            .saturating_add(script_words_bytes(words))
            .saturating_add(script_statements_bytes(body)),
        ScriptStatement::Case { word, arms } => script_word_heap_bytes(word)
            .saturating_add(
                arms.capacity()
                    .saturating_mul(std::mem::size_of::<ScriptCaseArm>()),
            )
            .saturating_add(
                arms.iter()
                    .map(|arm| {
                        script_words_bytes(&arm.patterns)
                            .saturating_add(script_statements_bytes(&arm.body))
                    })
                    .sum::<usize>(),
            ),
        ScriptStatement::Function { function } => script_function_heap_bytes(function),
        ScriptStatement::Return { status } => status.as_ref().map_or(0, script_word_heap_bytes),
        ScriptStatement::Redirected {
            statement,
            redirections,
        } => std::mem::size_of::<ScriptStatement>()
            .saturating_add(script_statement_heap_bytes(statement))
            .saturating_add(
                redirections
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptRedirection>()),
            )
            .saturating_add(
                redirections
                    .iter()
                    .map(script_redirection_heap_bytes)
                    .sum::<usize>(),
            ),
        ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => 0,
    }
}

fn script_command_heap_bytes(command: &ScriptCommand) -> usize {
    command
        .assignments
        .capacity()
        .saturating_mul(std::mem::size_of::<ScriptAssignment>())
        .saturating_add(
            command
                .assignments
                .iter()
                .map(|assignment| {
                    assignment
                        .name
                        .capacity()
                        .saturating_add(assignment.index.as_ref().map_or(0, script_word_heap_bytes))
                        .saturating_add(script_word_heap_bytes(&assignment.value))
                })
                .sum::<usize>(),
        )
        .saturating_add(script_words_bytes(&command.words))
        .saturating_add(
            command
                .redirections
                .capacity()
                .saturating_mul(std::mem::size_of::<ScriptRedirection>()),
        )
        .saturating_add(
            command
                .redirections
                .iter()
                .map(script_redirection_heap_bytes)
                .sum::<usize>(),
        )
}

fn script_redirection_heap_bytes(redirection: &ScriptRedirection) -> usize {
    redirection
        .operator
        .capacity()
        .saturating_add(script_word_heap_bytes(&redirection.target))
}

fn script_word_heap_bytes(word: &ScriptWord) -> usize {
    word.parts
        .capacity()
        .saturating_mul(std::mem::size_of::<ScriptWordPart>())
        .saturating_add(
            word.parts
                .iter()
                .map(script_word_part_heap_bytes)
                .sum::<usize>(),
        )
        .saturating_add(word.raw.as_ref().map_or(0, String::capacity))
}

fn script_word_part_heap_bytes(part: &ScriptWordPart) -> usize {
    match part {
        ScriptWordPart::Literal { value, .. } => value.capacity(),
        ScriptWordPart::Parameter { expression, .. }
        | ScriptWordPart::Arithmetic { expression, .. } => expression.capacity(),
        ScriptWordPart::CommandSubstitution { statements, .. } => {
            script_statements_bytes(statements)
        }
        ScriptWordPart::BraceExpansion { alternatives, .. }
        | ScriptWordPart::Array {
            elements: alternatives,
        } => script_words_bytes(alternatives),
        ScriptWordPart::DeferredScript {
            source,
            statements,
            words,
        } => source
            .capacity()
            .saturating_add(script_statements_bytes(statements))
            .saturating_add(script_words_bytes(words)),
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
        std::mem::size_of::<Self>()
            .saturating_add(self.source_path.capacity())
            .saturating_add(script_statements_bytes(&self.statements))
            .saturating_add(
                self.functions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptFunction>()),
            )
            .saturating_add(
                self.functions
                    .iter()
                    .map(script_function_heap_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(
                self.registrations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptRegistration>()),
            )
            .saturating_add(
                self.registrations
                    .iter()
                    .map(script_registration_heap_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(string_vector_bytes(&self.probe_capabilities))
            .saturating_add(string_vector_bytes(&self.zsh_function_names))
    }

    pub fn validate(&self) -> Result<(), ScriptValidationError> {
        self.validate_and_approximate_bytes().map(|_| ())
    }

    pub(crate) fn validate_and_approximate_bytes(&self) -> Result<usize, ScriptValidationError> {
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
            // The exact-capacity borrowed view is covered by the preflight's
            // doubled String-slot charge. Sorting in place avoids a HashSet
            // whose bucket/control allocation jumps at load-factor boundaries
            // and is difficult to account before allocation.
            let mut sorted_names = Vec::with_capacity(self.zsh_function_names.len());
            sorted_names.extend(self.zsh_function_names.iter().map(String::as_str));
            sorted_names.sort_unstable();
            if sorted_names
                .iter()
                .any(|name| name.is_empty() || name.contains(['/', '\0']))
                || sorted_names.windows(2).any(|names| names[0] == names[1])
            {
                return Err(ScriptValidationError::Invalid("Zsh function names"));
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
        let mut state = ValidationState {
            heap_bytes: std::mem::size_of::<Self>()
                .saturating_add(
                    self.statements
                        .capacity()
                        .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                )
                .saturating_add(
                    self.functions
                        .capacity()
                        .saturating_mul(std::mem::size_of::<ScriptFunction>()),
                )
                .saturating_add(
                    self.registrations
                        .capacity()
                        .saturating_mul(std::mem::size_of::<ScriptRegistration>()),
                )
                .saturating_add(
                    self.probe_capabilities
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                )
                .saturating_add(
                    self.zsh_function_names
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                ),
            ..ValidationState::default()
        };
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
        Ok(state.heap_bytes)
    }
}

#[derive(Default)]
struct ValidationState {
    nodes: usize,
    words: usize,
    string_bytes: usize,
    heap_bytes: usize,
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

    fn string(&mut self, value: &String) -> Result<(), ScriptValidationError> {
        if value.len() > MAX_SCRIPT_INDIVIDUAL_STRING_BYTES {
            return Err(ScriptValidationError::Limit("individual string"));
        }
        if value.contains('\0') {
            return Err(ScriptValidationError::Invalid("NUL in string"));
        }
        self.string_bytes = self.string_bytes.saturating_add(value.len());
        self.heap_bytes = self.heap_bytes.saturating_add(value.capacity());
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
        self.heap_bytes = self
            .heap_bytes
            .saturating_add(
                function
                    .arguments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptWord>()),
            )
            .saturating_add(
                function
                    .body
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptStatement>()),
            );
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
                self.heap_bytes = self.heap_bytes.saturating_add(
                    commands
                        .capacity()
                        .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                );
                for command in commands {
                    self.statement(command, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::AndOr { first, rest } => {
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(std::mem::size_of::<ScriptStatement>())
                    .saturating_add(
                        rest.capacity()
                            .saturating_mul(std::mem::size_of::<ScriptAndOrArm>()),
                    )
                    .saturating_add(
                        rest.len()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    );
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
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(
                        branches
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptConditionalBranch>()),
                    )
                    .saturating_add(
                        otherwise
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    );
                for branch in branches {
                    self.heap_bytes = self
                        .heap_bytes
                        .saturating_add(
                            branch
                                .condition
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                        )
                        .saturating_add(
                            branch
                                .body
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                        );
                    self.statements(&branch.condition, depth + 1)?;
                    self.statements(&branch.body, depth + 1)?;
                }
                self.statements(otherwise, depth + 1)
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(
                        condition
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    )
                    .saturating_add(
                        body.capacity()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    );
                self.statements(condition, depth + 1)?;
                self.statements(body, depth + 1)
            }
            ScriptStatement::For {
                variables,
                words,
                body,
            } => {
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(
                        variables
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>()),
                    )
                    .saturating_add(
                        words
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptWord>()),
                    )
                    .saturating_add(
                        body.capacity()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    );
                for variable in variables {
                    self.string(variable)?;
                }
                for word in words {
                    self.word(word, depth + 1)?;
                }
                self.statements(body, depth + 1)
            }
            ScriptStatement::Case { word, arms } => {
                self.heap_bytes = self.heap_bytes.saturating_add(
                    arms.capacity()
                        .saturating_mul(std::mem::size_of::<ScriptCaseArm>()),
                );
                self.word(word, depth + 1)?;
                for arm in arms {
                    self.heap_bytes = self
                        .heap_bytes
                        .saturating_add(
                            arm.patterns
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptWord>()),
                        )
                        .saturating_add(
                            arm.body
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                        );
                    for pattern in &arm.patterns {
                        self.word(pattern, depth + 1)?;
                    }
                    self.statements(&arm.body, depth + 1)?;
                }
                Ok(())
            }
            ScriptStatement::Function { function } => self.function(function, depth + 1),
            ScriptStatement::Group { body, .. } => {
                self.heap_bytes = self.heap_bytes.saturating_add(
                    body.capacity()
                        .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                );
                self.statements(body, depth + 1)
            }
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
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(std::mem::size_of::<ScriptStatement>())
                    .saturating_add(
                        redirections
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptRedirection>()),
                    );
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
        self.heap_bytes = self
            .heap_bytes
            .saturating_add(
                command
                    .assignments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptAssignment>()),
            )
            .saturating_add(
                command
                    .words
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptWord>()),
            )
            .saturating_add(
                command
                    .redirections
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptRedirection>()),
            );
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
        self.heap_bytes = self
            .heap_bytes
            .saturating_add(
                word.parts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScriptWordPart>()),
            )
            .saturating_add(word.raw.as_ref().map_or(0, String::capacity));
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
                    self.heap_bytes = self.heap_bytes.saturating_add(
                        statements
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                    );
                    self.statements(statements, depth + 2)?;
                }
                ScriptWordPart::BraceExpansion { alternatives, .. } => {
                    self.heap_bytes = self.heap_bytes.saturating_add(
                        alternatives
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptWord>()),
                    );
                    for alternative in alternatives {
                        self.word(alternative, depth + 2)?;
                    }
                }
                ScriptWordPart::Array { elements } => {
                    self.heap_bytes = self.heap_bytes.saturating_add(
                        elements
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ScriptWord>()),
                    );
                    for element in elements {
                        self.word(element, depth + 2)?;
                    }
                }
                ScriptWordPart::DeferredScript {
                    source,
                    statements,
                    words,
                } => {
                    self.heap_bytes = self
                        .heap_bytes
                        .saturating_add(
                            statements
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptStatement>()),
                        )
                        .saturating_add(
                            words
                                .capacity()
                                .saturating_mul(std::mem::size_of::<ScriptWord>()),
                        );
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
