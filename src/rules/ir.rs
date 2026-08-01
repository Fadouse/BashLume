// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use super::script::{
    MAX_SCRIPT_TAG_DEFERRED_FIELDS, MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES, ScriptModule,
    ScriptStatement,
};

pub const COMMAND_BLOCK_MAGIC: &[u8; 4] = b"BLIR";
pub const COMMAND_BLOCK_VERSION: u16 = 4;
pub const PREVIOUS_COMMAND_BLOCK_VERSION: u16 = 3;
pub const LEGACY_COMMAND_BLOCK_VERSION: u16 = 1;
pub const MAX_COMMAND_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REGISTRATIONS: usize = 4096;
pub const MAX_RULES: usize = 65_536;
pub const MAX_PREDICATES_PER_RULE: usize = 4096;
pub const MAX_PROBES: usize = 4096;
const PROBE_ID_VALIDATION_SCRATCH_BYTES: usize = 64;
pub const MAX_STRINGS_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const MAX_SCRIPT_MODULES: usize = 4096;
pub const MAX_SCRIPT_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_COMMAND_DECODE_ALLOCATION_BYTES: usize =
    MAX_COMMAND_BLOCK_BYTES + MAX_SCRIPT_AGGREGATE_BYTES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleCandidateKind {
    Option,
    Subcommand,
    Value,
    Command,
    Directory,
    File,
    User,
    Group,
    Host,
    Service,
    Signal,
    Variable,
    Job,
}

impl RuleCandidateKind {
    fn encode(self) -> u8 {
        match self {
            Self::Option => 0,
            Self::Subcommand => 1,
            Self::Value => 2,
            Self::Command => 3,
            Self::Directory => 4,
            Self::File => 5,
            Self::User => 6,
            Self::Group => 7,
            Self::Host => 8,
            Self::Service => 9,
            Self::Signal => 10,
            Self::Variable => 11,
            Self::Job => 12,
        }
    }

    fn decode(value: u8) -> Result<Self, IrError> {
        match value {
            0 => Ok(Self::Option),
            1 => Ok(Self::Subcommand),
            2 => Ok(Self::Value),
            3 => Ok(Self::Command),
            4 => Ok(Self::Directory),
            5 => Ok(Self::File),
            6 => Ok(Self::User),
            7 => Ok(Self::Group),
            8 => Ok(Self::Host),
            9 => Ok(Self::Service),
            10 => Ok(Self::Signal),
            11 => Ok(Self::Variable),
            12 => Ok(Self::Job),
            _ => Err(IrError::InvalidEnum("candidate kind", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppendPolicy {
    Space,
    NoSpace,
    Slash,
}

impl AppendPolicy {
    fn encode(self) -> u8 {
        match self {
            Self::Space => 0,
            Self::NoSpace => 1,
            Self::Slash => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, IrError> {
        match value {
            0 => Ok(Self::Space),
            1 => Ok(Self::NoSpace),
            2 => Ok(Self::Slash),
            _ => Err(IrError::InvalidEnum("append policy", value)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", content = "value", rename_all = "kebab-case")]
pub enum PredicateOp {
    True,
    False,
    Not,
    And,
    Or,
    CurrentWordEquals(String),
    CurrentWordStartsWith(String),
    PreviousWordEquals(String),
    AnyWordEquals(String),
    WordNotPresent(String),
    WordIndexEquals(u32),
    WordIndexAtLeast(u32),
    CommandPathEquals(Vec<String>),
    EnvironmentSet(String),
    EnvironmentEquals { name: String, value: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateTemplate {
    pub value: String,
    #[serde(default)]
    pub display: String,
    #[serde(default)]
    pub description: Option<String>,
    pub kind: RuleCandidateKind,
    pub append: AppendPolicy,
    #[serde(default)]
    pub preserve_order: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathCompletion {
    #[default]
    Inherit,
    Suppress,
    Directories,
    Files,
}

impl PathCompletion {
    fn encode(self) -> u8 {
        match self {
            Self::Inherit => 0,
            Self::Suppress => 1,
            Self::Directories => 2,
            Self::Files => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, IrError> {
        match value {
            0 => Ok(Self::Inherit),
            1 => Ok(Self::Suppress),
            2 => Ok(Self::Directories),
            3 => Ok(Self::Files),
            _ => Err(IrError::InvalidEnum("path completion", value)),
        }
    }

    pub const fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Files, _) | (_, Self::Files) => Self::Files,
            (Self::Directories, _) | (_, Self::Directories) => Self::Directories,
            (Self::Suppress, _) | (_, Self::Suppress) => Self::Suppress,
            _ => Self::Inherit,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaticRule {
    #[serde(default = "default_true_program")]
    pub when: Vec<PredicateOp>,
    #[serde(default)]
    pub path_completion: PathCompletion,
    pub candidates: Vec<CandidateTemplate>,
}

fn default_true_program() -> Vec<PredicateOp> {
    vec![PredicateOp::True]
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeParser {
    Lines,
    Words,
    Nul,
    ColonFirst,
    TabFirst,
}

impl ProbeParser {
    fn encode(self) -> u8 {
        match self {
            Self::Lines => 0,
            Self::Words => 1,
            Self::Nul => 2,
            Self::ColonFirst => 3,
            Self::TabFirst => 4,
        }
    }

    fn decode(value: u8) -> Result<Self, IrError> {
        match value {
            0 => Ok(Self::Lines),
            1 => Ok(Self::Words),
            2 => Ok(Self::Nul),
            3 => Ok(Self::ColonFirst),
            4 => Ok(Self::TabFirst),
            _ => Err(IrError::InvalidEnum("probe parser", value)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeSpec {
    pub id: String,
    #[serde(default = "default_true_program")]
    pub when: Vec<PredicateOp>,
    pub executable: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: Vec<(String, String)>,
    pub parser: ProbeParser,
    pub candidate_kind: RuleCandidateKind,
    pub append: AppendPolicy,
    #[serde(default = "default_probe_timeout")]
    pub timeout_ms: u32,
    #[serde(default = "default_probe_output_limit")]
    pub output_limit: u32,
    #[serde(default = "default_probe_ttl")]
    pub cache_ttl_ms: u32,
    #[serde(default)]
    pub description: Option<String>,
}

const fn default_probe_timeout() -> u32 {
    2000
}

const fn default_probe_output_limit() -> u32 {
    1024 * 1024
}

const fn default_probe_ttl() -> u32 {
    1000
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandProgram {
    pub canonical_name: String,
    pub registrations: Vec<String>,
    pub source_path: String,
    pub source_commit: String,
    pub license: String,
    #[serde(default)]
    pub static_rules: Vec<StaticRule>,
    #[serde(default)]
    pub probes: Vec<ProbeSpec>,
    #[serde(default)]
    pub scripts: Vec<ScriptModule>,
}

fn json_key_equals(mut raw: &[u8], expected: &[u8]) -> bool {
    for expected_byte in expected {
        let Some((&byte, rest)) = raw.split_first() else {
            return false;
        };
        if byte == *expected_byte {
            raw = rest;
            continue;
        }
        if byte != b'\\' || rest.len() < 5 || rest[0] != b'u' {
            return false;
        }
        let hex = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let Some(value) = hex(rest[1])
            .zip(hex(rest[2]))
            .zip(hex(rest[3]))
            .zip(hex(rest[4]))
            .map(|(((a, b), c), d)| {
                (u16::from(a) << 12) | (u16::from(b) << 8) | (u16::from(c) << 4) | u16::from(d)
            })
        else {
            return false;
        };
        if value != u16::from(*expected_byte) {
            return false;
        }
        raw = &rest[5..];
    }
    raw.is_empty()
}

fn script_json_tag_value_is_known(tag_kind: &[u8], raw: &[u8]) -> bool {
    let expected: &[&[u8]] = match tag_kind {
        b"op" => &[
            b"command",
            b"and-or",
            b"pipeline",
            b"if",
            b"while",
            b"for",
            b"case",
            b"function",
            b"group",
            b"return",
            b"break",
            b"continue",
            b"noop",
            b"redirected",
        ],
        b"kind" => &[
            b"function",
            b"fish-complete",
            b"module",
            b"literal",
            b"parameter",
            b"command-substitution",
            b"arithmetic",
            b"brace-expansion",
            b"array",
            b"deferred-script",
        ],
        b"dialect" => &[b"bash", b"zsh", b"fish"],
        _ => return false,
    };
    expected
        .iter()
        .any(|expected| json_key_equals(raw, expected))
}

struct ScriptJsonPreflight<'a> {
    bytes: &'a [u8],
    cursor: usize,
    used: usize,
    scratch_by_container_depth: [usize; 130],
    scratch_total: usize,
    discriminator_error_peak: usize,
    limit: usize,
}

impl ScriptJsonPreflight<'_> {
    fn invalid<T>() -> Result<T, IrError> {
        Err(IrError::Invalid("invalid script encoding"))
    }

    fn charge(&mut self, bytes: usize) -> Result<(), IrError> {
        self.used = self.used.saturating_add(bytes);
        self.check_limit()
    }

    fn record_scratch(&mut self, reparse_depth: usize, bytes: usize) -> Result<(), IrError> {
        // Every object field is conservatively treated as a possible borrowed
        // RawValue reparse. Deserializers on one nested field path coexist;
        // sibling fields at the same level reuse one scratch capacity.
        let Some(slot) = self.scratch_by_container_depth.get_mut(reparse_depth) else {
            return Self::invalid();
        };
        if bytes > *slot {
            self.scratch_total = self.scratch_total.saturating_add(bytes - *slot);
            *slot = bytes;
        }
        self.check_limit()
    }

    fn record_discriminator_error(&mut self, raw_length: usize) -> Result<(), IrError> {
        // Deserialization aborts at the first applicable unknown variant, so
        // at most one formatted error string coexists with parser scratch.
        self.discriminator_error_peak = self.discriminator_error_peak.max(
            raw_length
                .saturating_mul(2)
                .saturating_add(2 * std::mem::size_of::<String>())
                .saturating_add(256),
        );
        self.check_limit()
    }

    fn check_limit(&self) -> Result<(), IrError> {
        if self
            .used
            .saturating_add(self.scratch_total)
            .saturating_add(self.discriminator_error_peak)
            > self.limit
        {
            return Err(IrError::Limit("aggregate shell script IR"));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.cursor += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        self.skip_whitespace();
        if self.bytes.get(self.cursor) == Some(&byte) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, value: &[u8]) -> Result<(), IrError> {
        if self
            .bytes
            .get(self.cursor..self.cursor.saturating_add(value.len()))
            != Some(value)
        {
            return Self::invalid();
        }
        self.cursor += value.len();
        self.charge(16)
    }

    fn number(&mut self) -> Result<(), IrError> {
        if self.bytes.get(self.cursor) == Some(&b'-') {
            self.cursor += 1;
        }
        match self.bytes.get(self.cursor) {
            Some(b'0') => self.cursor += 1,
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                    self.cursor += 1;
                }
            }
            _ => return Self::invalid(),
        }
        if self.bytes.get(self.cursor) == Some(&b'.') {
            self.cursor += 1;
            let start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if self.cursor == start {
                return Self::invalid();
            }
        }
        if self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            self.cursor += 1;
            if self
                .bytes
                .get(self.cursor)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.cursor += 1;
            }
            let start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if self.cursor == start {
                return Self::invalid();
            }
        }
        self.charge(16)
    }

    fn hex_quad(&mut self) -> Result<u16, IrError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let Some(byte) = self.bytes.get(self.cursor).copied() else {
                return Self::invalid();
            };
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a' + 10),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => return Self::invalid(),
            };
            value = value * 16 + digit;
            self.cursor += 1;
        }
        Ok(value)
    }

    fn string(
        &mut self,
        reparse_depth: usize,
        charge: bool,
        additional_slot_bytes: usize,
    ) -> Result<(usize, usize), IrError> {
        if self.bytes.get(self.cursor) != Some(&b'"') {
            return Self::invalid();
        }
        self.cursor += 1;
        let start = self.cursor;
        let mut escaped = false;
        loop {
            let Some(byte) = self.bytes.get(self.cursor).copied() else {
                return Self::invalid();
            };
            match byte {
                b'"' => {
                    let raw_length = self.cursor.saturating_sub(start);
                    self.cursor += 1;
                    if escaped {
                        // serde_json decodes escaped keys and enum/string
                        // values through an owned scratch buffer even when the
                        // final field is ignored or rejected.
                        self.record_scratch(
                            reparse_depth,
                            raw_length.saturating_mul(2).saturating_add(1),
                        )?;
                    }
                    if charge {
                        self.charge(
                            raw_length
                                .saturating_add(2 * std::mem::size_of::<String>())
                                .saturating_add(additional_slot_bytes),
                        )?;
                    }
                    return Ok((start, raw_length));
                }
                b'\\' => {
                    escaped = true;
                    self.cursor += 1;
                    let Some(escape) = self.bytes.get(self.cursor).copied() else {
                        return Self::invalid();
                    };
                    self.cursor += 1;
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            let code = self.hex_quad()?;
                            if (0xd800..=0xdbff).contains(&code) {
                                if self.bytes.get(self.cursor..self.cursor.saturating_add(2))
                                    != Some(br"\u")
                                {
                                    return Self::invalid();
                                }
                                self.cursor += 2;
                                if !(0xdc00..=0xdfff).contains(&self.hex_quad()?) {
                                    return Self::invalid();
                                }
                            } else if (0xdc00..=0xdfff).contains(&code) {
                                return Self::invalid();
                            }
                        }
                        _ => return Self::invalid(),
                    }
                }
                0x00..=0x1f => return Self::invalid(),
                _ => self.cursor += 1,
            }
        }
    }

    fn value(
        &mut self,
        depth: usize,
        reparse_depth: usize,
        charge_string: bool,
        additional_string_slot_bytes: usize,
    ) -> Result<(), IrError> {
        if depth > 128 {
            return Self::invalid();
        }
        self.skip_whitespace();
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.object(depth + 1, reparse_depth),
            Some(b'[') => self.array(depth + 1, reparse_depth, additional_string_slot_bytes),
            Some(b'"') => self
                .string(reparse_depth, charge_string, additional_string_slot_bytes)
                .map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Self::invalid(),
        }
    }

    fn array(
        &mut self,
        depth: usize,
        reparse_depth: usize,
        additional_string_slot_bytes: usize,
    ) -> Result<(), IrError> {
        if !self.consume(b'[') {
            return Self::invalid();
        }
        self.charge(2 * std::mem::size_of::<Vec<ScriptStatement>>())?;
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.value(depth, reparse_depth, true, additional_string_slot_bytes)?;
            if self.consume(b']') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Self::invalid();
            }
        }
    }

    fn object(&mut self, depth: usize, reparse_depth: usize) -> Result<(), IrError> {
        if !self.consume(b'{') {
            return Self::invalid();
        }
        self.charge(2 * std::mem::size_of::<ScriptStatement>())?;
        if self.consume(b'}') {
            return Ok(());
        }
        let mut deferred_fields = 0_usize;
        let mut deferred_name_bytes = 0_usize;
        let mut discriminator_seen = false;
        loop {
            self.skip_whitespace();
            let key_start = self.cursor.saturating_add(1);
            self.string(reparse_depth, false, 0)?;
            let key_end = self.cursor.saturating_sub(1);
            let additional_string_slot_bytes = self
                .bytes
                .get(key_start..key_end)
                .filter(|key| json_key_equals(key, b"zsh_function_names"))
                .map_or(0, |_| std::mem::size_of::<&str>());
            let key_length = key_end.saturating_sub(key_start);
            if !discriminator_seen {
                deferred_fields = deferred_fields.saturating_add(1);
                deferred_name_bytes = deferred_name_bytes.saturating_add(key_length);
            }
            // Conservatively budget every object as a possible internally
            // tagged enum. Statement and word-part visitors defer different
            // discriminator names, and ScriptEntry has the same bounded
            // tag-last representation; a decoy tag must not stop this
            // accounting. This also covers Vec geometric growth and deferred
            // scalar slots before typed deserialization.
            const DEFERRED_FIELD_BYTES: usize = 10 * std::mem::size_of::<usize>();
            self.charge(DEFERRED_FIELD_BYTES.saturating_add(key_end.saturating_sub(key_start)))?;
            if !self.consume(b':') {
                return Self::invalid();
            }
            self.skip_whitespace();
            let key = &self.bytes[key_start..key_end];
            let tag_kind = if json_key_equals(key, b"op") {
                Some(b"op".as_slice())
            } else if json_key_equals(key, b"kind") {
                Some(b"kind".as_slice())
            } else if json_key_equals(key, b"dialect") {
                Some(b"dialect".as_slice())
            } else {
                None
            };
            let mut recognized_discriminator = false;
            if let Some(tag_kind) = tag_kind.filter(|_| self.bytes.get(self.cursor) == Some(&b'"'))
            {
                let (value_start, value_length) = self.string(
                    reparse_depth.saturating_add(1),
                    false,
                    additional_string_slot_bytes,
                )?;
                let value = &self.bytes[value_start..value_start.saturating_add(value_length)];
                recognized_discriminator = script_json_tag_value_is_known(tag_kind, value);
                if !recognized_discriminator {
                    self.record_discriminator_error(value_length)?;
                }
            } else {
                self.value(
                    depth,
                    reparse_depth.saturating_add(1),
                    true,
                    additional_string_slot_bytes,
                )?;
            }
            if recognized_discriminator && !discriminator_seen {
                deferred_fields = deferred_fields.saturating_sub(1);
                deferred_name_bytes = deferred_name_bytes.saturating_sub(key_length);
                discriminator_seen = true;
            }
            if deferred_fields > MAX_SCRIPT_TAG_DEFERRED_FIELDS
                || deferred_name_bytes > MAX_SCRIPT_TAG_DEFERRED_NAME_BYTES
            {
                return Err(IrError::Limit("aggregate shell script IR"));
            }
            if self.consume(b'}') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Self::invalid();
            }
        }
    }

    fn modules(&mut self) -> Result<(), IrError> {
        if !self.consume(b'[') {
            return Self::invalid();
        }
        if self.consume(b']') {
            self.skip_whitespace();
            return (self.cursor == self.bytes.len())
                .then_some(())
                .ok_or(IrError::Invalid("invalid script encoding"));
        }
        let mut modules = 0_usize;
        loop {
            self.value(1, 0, true, 0)?;
            modules = modules.saturating_add(1);
            if modules > MAX_SCRIPT_MODULES {
                return Err(IrError::Limit("aggregate shell script IR"));
            }
            if self.consume(b']') {
                self.skip_whitespace();
                return (self.cursor == self.bytes.len())
                    .then_some(())
                    .ok_or(IrError::Invalid("invalid script encoding"));
            }
            if !self.consume(b',') {
                return Self::invalid();
            }
        }
    }
}

fn preflight_script_encoding_with_limit(
    bytes: &[u8],
    allocation_limit: usize,
    charge_encoded_bytes: bool,
) -> Result<usize, IrError> {
    // Validate and budget the complete JSON without allocating. The compact
    // encoding normally remains live while serde allocates the typed AST;
    // callers that reserved the enclosing command buffer can omit that charge.
    std::str::from_utf8(bytes).map_err(|_| IrError::Invalid("invalid script encoding"))?;
    let limit = allocation_limit.min(MAX_SCRIPT_AGGREGATE_BYTES);
    let used = (if charge_encoded_bytes { bytes.len() } else { 0 })
        .saturating_add(2 * std::mem::size_of::<Vec<ScriptModule>>());
    if used > limit {
        return Err(IrError::Limit("aggregate shell script IR"));
    }
    let mut preflight = ScriptJsonPreflight {
        bytes,
        cursor: 0,
        used,
        scratch_by_container_depth: [0; 130],
        scratch_total: 0,
        discriminator_error_peak: 0,
        limit,
    };
    preflight.modules()?;
    Ok(preflight.used.saturating_add(preflight.scratch_total))
}

#[cfg(test)]
fn preflight_script_encoding(bytes: &[u8]) -> Result<(), IrError> {
    preflight_script_encoding_with_limit(bytes, MAX_SCRIPT_AGGREGATE_BYTES, true).map(|_| ())
}

impl CommandProgram {
    pub fn validate(&self) -> Result<(), IrError> {
        self.validate_and_approximate_bytes().map(|_| ())
    }

    fn validate_and_approximate_bytes(&self) -> Result<usize, IrError> {
        if self.canonical_name.is_empty() {
            return Err(IrError::Invalid("canonical command name is empty"));
        }
        if self.registrations.is_empty() || self.registrations.len() > MAX_REGISTRATIONS {
            return Err(IrError::Limit("command registrations"));
        }
        if self.static_rules.len() > MAX_RULES {
            return Err(IrError::Limit("static rules"));
        }
        if self.probes.len() > MAX_PROBES {
            return Err(IrError::Limit("dynamic probes"));
        }
        if self.scripts.len() > MAX_SCRIPT_MODULES {
            return Err(IrError::Limit("script modules"));
        }
        let mut approximate_bytes = std::mem::size_of::<Self>()
            .saturating_add(self.canonical_name.capacity())
            .saturating_add(self.source_path.capacity())
            .saturating_add(self.source_commit.capacity())
            .saturating_add(self.license.capacity())
            .saturating_add(
                self.registrations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.static_rules
                    .capacity()
                    .saturating_mul(std::mem::size_of::<StaticRule>()),
            )
            .saturating_add(
                self.probes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ProbeSpec>()),
            );
        let mut script_bytes = self
            .scripts
            .capacity()
            .saturating_mul(std::mem::size_of::<ScriptModule>());
        for script in &self.scripts {
            let retained_bytes = script
                .validate_and_approximate_bytes()
                .map_err(|_| IrError::Invalid("invalid shell script IR"))?;
            script_bytes = script_bytes
                .saturating_add(retained_bytes.saturating_sub(std::mem::size_of::<ScriptModule>()));
            if script_bytes > MAX_SCRIPT_AGGREGATE_BYTES {
                return Err(IrError::Limit("aggregate shell script IR"));
            }
        }
        let mut string_bytes = self
            .canonical_name
            .len()
            .saturating_add(self.source_path.len())
            .saturating_add(self.source_commit.len())
            .saturating_add(self.license.len());
        for registration in &self.registrations {
            validate_string(registration)?;
            string_bytes = string_bytes.saturating_add(registration.len());
            approximate_bytes = approximate_bytes.saturating_add(registration.capacity());
        }
        for rule in &self.static_rules {
            validate_predicates(&rule.when)?;
            string_bytes = string_bytes.saturating_add(predicate_string_bytes(&rule.when));
            approximate_bytes = approximate_bytes
                .saturating_add(
                    rule.when
                        .capacity()
                        .saturating_mul(std::mem::size_of::<PredicateOp>()),
                )
                .saturating_add(predicate_allocation_bytes(&rule.when))
                .saturating_add(
                    rule.candidates
                        .capacity()
                        .saturating_mul(std::mem::size_of::<CandidateTemplate>()),
                );
            if rule.candidates.len() > MAX_RULES {
                return Err(IrError::Limit("candidates per static rule"));
            }
            for candidate in &rule.candidates {
                validate_candidate(candidate)?;
                string_bytes = string_bytes
                    .saturating_add(candidate.value.len())
                    .saturating_add(candidate.display.len())
                    .saturating_add(candidate.description.as_ref().map_or(0, String::len));
                approximate_bytes = approximate_bytes
                    .saturating_add(candidate.value.capacity())
                    .saturating_add(candidate.display.capacity())
                    .saturating_add(candidate.description.as_ref().map_or(0, String::capacity));
            }
        }
        let mut probe_ids = HashSet::with_capacity(self.probes.len());
        for probe in &self.probes {
            if !probe_ids.insert(probe.id.as_str()) {
                return Err(IrError::Invalid("duplicate probe id"));
            }
            validate_predicates(&probe.when)?;
            string_bytes = string_bytes.saturating_add(predicate_string_bytes(&probe.when));
            approximate_bytes = approximate_bytes
                .saturating_add(probe.id.capacity())
                .saturating_add(probe.executable.capacity())
                .saturating_add(
                    probe
                        .when
                        .capacity()
                        .saturating_mul(std::mem::size_of::<PredicateOp>()),
                )
                .saturating_add(predicate_allocation_bytes(&probe.when))
                .saturating_add(
                    probe
                        .arguments
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                )
                .saturating_add(
                    probe
                        .environment
                        .capacity()
                        .saturating_mul(std::mem::size_of::<(String, String)>()),
                )
                .saturating_add(probe.description.as_ref().map_or(0, String::capacity));
            validate_string(&probe.id)?;
            validate_executable(&probe.executable)?;
            if probe.arguments.len() > 1024 || probe.environment.len() > 256 {
                return Err(IrError::Limit("probe arguments or environment"));
            }
            for argument in &probe.arguments {
                validate_string(argument)?;
                approximate_bytes = approximate_bytes.saturating_add(argument.capacity());
            }
            for (name, value) in &probe.environment {
                validate_string(name)?;
                validate_string(value)?;
                approximate_bytes = approximate_bytes
                    .saturating_add(name.capacity())
                    .saturating_add(value.capacity());
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                    || name
                        .as_bytes()
                        .first()
                        .is_none_or(|byte| !(byte == &b'_' || byte.is_ascii_alphabetic()))
                {
                    return Err(IrError::Invalid("invalid probe environment name"));
                }
            }
            if let Some(description) = &probe.description {
                validate_string(description)?;
            }
            if !(10..=30_000).contains(&probe.timeout_ms) {
                return Err(IrError::Invalid("probe timeout is outside policy bounds"));
            }
            if !(1024..=8 * 1024 * 1024).contains(&probe.output_limit) {
                return Err(IrError::Invalid(
                    "probe output limit is outside policy bounds",
                ));
            }
            if probe.cache_ttl_ms > 3_600_000 {
                return Err(IrError::Invalid("probe cache TTL is outside policy bounds"));
            }
            string_bytes = string_bytes
                .saturating_add(probe.id.len())
                .saturating_add(probe.executable.len())
                .saturating_add(probe.arguments.iter().map(String::len).sum::<usize>())
                .saturating_add(
                    probe
                        .environment
                        .iter()
                        .map(|(name, value)| name.len().saturating_add(value.len()))
                        .sum::<usize>(),
                )
                .saturating_add(probe.description.as_ref().map_or(0, String::len));
        }
        if string_bytes > MAX_STRINGS_BYTES {
            return Err(IrError::Limit("command string table"));
        }
        validate_string(&self.canonical_name)?;
        validate_string(&self.source_path)?;
        validate_string(&self.source_commit)?;
        validate_string(&self.license)?;
        Ok(approximate_bytes.saturating_add(script_bytes))
    }

    pub fn encode(&self) -> Result<Vec<u8>, IrError> {
        self.encode_version(COMMAND_BLOCK_VERSION)
    }

    fn encode_version(&self, block_version: u16) -> Result<Vec<u8>, IrError> {
        self.validate()?;
        if !(LEGACY_COMMAND_BLOCK_VERSION..=COMMAND_BLOCK_VERSION).contains(&block_version) {
            return Err(IrError::Invalid("unsupported command block version"));
        }
        if block_version < 4 && self.scripts.iter().any(ScriptModule::requires_block_v4) {
            return Err(IrError::Invalid(
                "script feature requires command block version 4",
            ));
        }
        let mut encoder = Encoder::new();
        encoder.bytes.extend_from_slice(COMMAND_BLOCK_MAGIC);
        encoder.u16(block_version);
        encoder.u16(0);
        encoder.string(&self.canonical_name)?;
        encoder.strings(&self.registrations)?;
        encoder.string(&self.source_path)?;
        encoder.string(&self.source_commit)?;
        encoder.string(&self.license)?;
        encoder.count(self.static_rules.len())?;
        for rule in &self.static_rules {
            encode_predicates(&mut encoder, &rule.when)?;
            if block_version >= 2 {
                encoder.u8(rule.path_completion.encode());
            }
            encoder.count(rule.candidates.len())?;
            for candidate in &rule.candidates {
                encode_candidate(&mut encoder, candidate)?;
            }
        }
        encoder.count(self.probes.len())?;
        for probe in &self.probes {
            encoder.string(&probe.id)?;
            encode_predicates(&mut encoder, &probe.when)?;
            encoder.string(&probe.executable)?;
            encoder.strings(&probe.arguments)?;
            encoder.count(probe.environment.len())?;
            for (name, value) in &probe.environment {
                encoder.string(name)?;
                encoder.string(value)?;
            }
            encoder.u8(probe.parser.encode());
            encoder.u8(probe.candidate_kind.encode());
            encoder.u8(probe.append.encode());
            encoder.u8(0);
            encoder.u32(probe.timeout_ms);
            encoder.u32(probe.output_limit);
            encoder.u32(probe.cache_ttl_ms);
            encoder.optional_string(probe.description.as_deref())?;
        }
        if block_version >= 3 {
            // Stream into an allocation-capped buffer. Validation bounds the
            // in-memory Script IR, while this bound also covers JSON escaping
            // expansion before the command-block size check.
            let script_limit = MAX_COMMAND_BLOCK_BYTES
                .saturating_sub(encoder.bytes.len())
                .saturating_sub(std::mem::size_of::<u32>());
            let mut scripts = BoundedJsonBuffer::new(script_limit);
            if serde_json::to_writer(&mut scripts, &self.scripts).is_err() {
                return Err(if scripts.exceeded {
                    IrError::Limit("encoded command block")
                } else {
                    IrError::Invalid("script serialization failed")
                });
            }
            encoder.blob(&scripts.bytes)?;
        }
        if encoder.bytes.len() > MAX_COMMAND_BLOCK_BYTES {
            return Err(IrError::Limit("encoded command block"));
        }
        Ok(encoder.bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IrError> {
        Self::decode_with_allocation_limit(bytes, MAX_COMMAND_DECODE_ALLOCATION_BYTES)
    }

    pub(crate) fn decode_with_allocation_limit(
        bytes: &[u8],
        allocation_limit: usize,
    ) -> Result<Self, IrError> {
        Self::decode_with_allocation_limit_and_size(bytes, allocation_limit)
            .map(|(program, _)| program)
    }

    pub(crate) fn decode_with_allocation_limit_and_size(
        bytes: &[u8],
        allocation_limit: usize,
    ) -> Result<(Self, usize), IrError> {
        if bytes.len() > MAX_COMMAND_BLOCK_BYTES || bytes.len() > allocation_limit {
            return Err(IrError::Limit("encoded command block"));
        }
        let mut decoder = Decoder::new(bytes, allocation_limit);
        if decoder.take(4)? != COMMAND_BLOCK_MAGIC {
            return Err(IrError::Invalid("invalid command block magic"));
        }
        let block_version = decoder.u16()?;
        if !(LEGACY_COMMAND_BLOCK_VERSION..=COMMAND_BLOCK_VERSION).contains(&block_version) {
            return Err(IrError::Invalid("unsupported command block version"));
        }
        if decoder.u16()? != 0 {
            return Err(IrError::Invalid("nonzero command block flags"));
        }
        let canonical_name = decoder.string()?;
        let registrations = decoder.strings(MAX_REGISTRATIONS)?;
        let source_path = decoder.string()?;
        let source_commit = decoder.string()?;
        let license = decoder.string()?;
        let rule_count = decoder.count(MAX_RULES)?;
        decoder.charge_array::<StaticRule>(rule_count)?;
        let mut static_rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            let when = decode_predicates(&mut decoder)?;
            let path_completion = if block_version >= 2 {
                PathCompletion::decode(decoder.u8()?)?
            } else {
                PathCompletion::Inherit
            };
            let candidate_count = decoder.count(MAX_RULES)?;
            decoder.charge_array::<CandidateTemplate>(candidate_count)?;
            let mut candidates = Vec::with_capacity(candidate_count);
            for _ in 0..candidate_count {
                candidates.push(decode_candidate(&mut decoder)?);
            }
            static_rules.push(StaticRule {
                when,
                path_completion,
                candidates,
            });
        }
        let probe_count = decoder.count(MAX_PROBES)?;
        decoder.charge_array::<ProbeSpec>(probe_count)?;
        decoder.charge(probe_count.saturating_mul(PROBE_ID_VALIDATION_SCRATCH_BYTES))?;
        let mut probes = Vec::with_capacity(probe_count);
        for _ in 0..probe_count {
            let id = decoder.string()?;
            let when = decode_predicates(&mut decoder)?;
            let executable = decoder.string()?;
            let arguments = decoder.strings(1024)?;
            let environment_count = decoder.count(256)?;
            decoder.charge_array::<(String, String)>(environment_count)?;
            let mut environment = Vec::with_capacity(environment_count);
            for _ in 0..environment_count {
                environment.push((decoder.string()?, decoder.string()?));
            }
            let parser = ProbeParser::decode(decoder.u8()?)?;
            let candidate_kind = RuleCandidateKind::decode(decoder.u8()?)?;
            let append = AppendPolicy::decode(decoder.u8()?)?;
            if decoder.u8()? != 0 {
                return Err(IrError::Invalid("nonzero probe flags"));
            }
            let timeout_ms = decoder.u32()?;
            let output_limit = decoder.u32()?;
            let cache_ttl_ms = decoder.u32()?;
            let description = decoder.optional_string()?;
            probes.push(ProbeSpec {
                id,
                when,
                executable,
                arguments,
                environment,
                parser,
                candidate_kind,
                append,
                timeout_ms,
                output_limit,
                cache_ttl_ms,
                description,
            });
        }
        let scripts = if block_version >= 3 {
            let bytes = decoder.blob(MAX_COMMAND_BLOCK_BYTES)?;
            let script_allocation_limit = decoder.remaining_allocation();
            let script_allocation =
                preflight_script_encoding_with_limit(bytes, script_allocation_limit, false)?;
            decoder.charge(script_allocation)?;
            let scripts: Vec<ScriptModule> = serde_json::from_slice(bytes)
                .map_err(|_| IrError::Invalid("invalid script encoding"))?;
            if block_version < 4 && scripts.iter().any(ScriptModule::requires_block_v4) {
                return Err(IrError::Invalid(
                    "script feature requires command block version 4",
                ));
            }
            scripts
        } else {
            Vec::new()
        };
        if !decoder.remaining().is_empty() {
            return Err(IrError::Invalid("trailing command block bytes"));
        }
        // `Decoder` has already enforced the transient input-plus-AST peak.
        // Return only allocations retained after the input buffer is released.
        let program = Self {
            canonical_name,
            registrations,
            source_path,
            source_commit,
            license,
            static_rules,
            probes,
            scripts,
        };
        let actual_allocation_bytes = program.validate_and_approximate_bytes()?;
        Ok((program, actual_allocation_bytes))
    }
}

fn validate_executable(value: &str) -> Result<(), IrError> {
    validate_string(value)?;
    if value.is_empty()
        || value.contains(['/', '\0'])
        || value.contains(char::is_whitespace)
        || matches!(value, "sh" | "bash" | "dash" | "zsh" | "fish")
        || value.ends_with("/sh")
        || value.ends_with("/bash")
        || value.ends_with("/dash")
        || value.ends_with("/zsh")
        || value.ends_with("/fish")
    {
        return Err(IrError::Invalid("probe executable is forbidden"));
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateTemplate) -> Result<(), IrError> {
    validate_string(&candidate.value)?;
    validate_string(&candidate.display)?;
    if let Some(description) = &candidate.description {
        validate_string(description)?;
    }
    if candidate.value.is_empty() {
        return Err(IrError::Invalid("candidate insertion value is empty"));
    }
    if candidate.value.chars().any(char::is_control)
        || candidate.display.chars().any(char::is_control)
        || candidate
            .description
            .as_ref()
            .is_some_and(|description| description.chars().any(char::is_control))
    {
        return Err(IrError::Invalid("candidate contains a control character"));
    }
    Ok(())
}

fn validate_string(value: &str) -> Result<(), IrError> {
    if value.len() > MAX_STRING_BYTES {
        return Err(IrError::Limit("individual string"));
    }
    if value.contains('\0') {
        return Err(IrError::Invalid("string contains NUL"));
    }
    Ok(())
}

fn predicate_string_bytes(program: &[PredicateOp]) -> usize {
    program.iter().fold(0_usize, |total, predicate| {
        let bytes = match predicate {
            PredicateOp::CurrentWordEquals(value)
            | PredicateOp::CurrentWordStartsWith(value)
            | PredicateOp::PreviousWordEquals(value)
            | PredicateOp::AnyWordEquals(value)
            | PredicateOp::WordNotPresent(value)
            | PredicateOp::EnvironmentSet(value) => value.len(),
            PredicateOp::CommandPathEquals(values) => values
                .iter()
                .map(String::len)
                .fold(0_usize, usize::saturating_add),
            PredicateOp::EnvironmentEquals { name, value } => {
                name.len().saturating_add(value.len())
            }
            PredicateOp::True
            | PredicateOp::False
            | PredicateOp::Not
            | PredicateOp::And
            | PredicateOp::Or
            | PredicateOp::WordIndexEquals(_)
            | PredicateOp::WordIndexAtLeast(_) => 0,
        };
        total.saturating_add(bytes)
    })
}

fn predicate_allocation_bytes(program: &[PredicateOp]) -> usize {
    program.iter().fold(0_usize, |total, predicate| {
        let bytes = match predicate {
            PredicateOp::CurrentWordEquals(value)
            | PredicateOp::CurrentWordStartsWith(value)
            | PredicateOp::PreviousWordEquals(value)
            | PredicateOp::AnyWordEquals(value)
            | PredicateOp::WordNotPresent(value)
            | PredicateOp::EnvironmentSet(value) => value.capacity(),
            PredicateOp::CommandPathEquals(values) => values
                .capacity()
                .saturating_mul(std::mem::size_of::<String>())
                .saturating_add(
                    values
                        .iter()
                        .map(String::capacity)
                        .fold(0_usize, usize::saturating_add),
                ),
            PredicateOp::EnvironmentEquals { name, value } => {
                name.capacity().saturating_add(value.capacity())
            }
            PredicateOp::True
            | PredicateOp::False
            | PredicateOp::Not
            | PredicateOp::And
            | PredicateOp::Or
            | PredicateOp::WordIndexEquals(_)
            | PredicateOp::WordIndexAtLeast(_) => 0,
        };
        total.saturating_add(bytes)
    })
}

fn validate_predicates(program: &[PredicateOp]) -> Result<(), IrError> {
    if program.is_empty() || program.len() > MAX_PREDICATES_PER_RULE {
        return Err(IrError::Limit("predicate program"));
    }
    let mut depth = 0_usize;
    for instruction in program {
        match instruction {
            PredicateOp::True
            | PredicateOp::False
            | PredicateOp::CurrentWordEquals(_)
            | PredicateOp::CurrentWordStartsWith(_)
            | PredicateOp::PreviousWordEquals(_)
            | PredicateOp::AnyWordEquals(_)
            | PredicateOp::WordNotPresent(_)
            | PredicateOp::WordIndexEquals(_)
            | PredicateOp::WordIndexAtLeast(_)
            | PredicateOp::CommandPathEquals(_)
            | PredicateOp::EnvironmentSet(_)
            | PredicateOp::EnvironmentEquals { .. } => depth = depth.saturating_add(1),
            PredicateOp::Not => {
                if depth < 1 {
                    return Err(IrError::Invalid("predicate stack underflow"));
                }
            }
            PredicateOp::And | PredicateOp::Or => {
                if depth < 2 {
                    return Err(IrError::Invalid("predicate stack underflow"));
                }
                depth -= 1;
            }
        }
        if depth > 256 {
            return Err(IrError::Limit("predicate stack"));
        }
        validate_predicate_strings(instruction)?;
    }
    if depth != 1 {
        return Err(IrError::Invalid("predicate program must leave one value"));
    }
    Ok(())
}

fn validate_predicate_strings(instruction: &PredicateOp) -> Result<(), IrError> {
    match instruction {
        PredicateOp::CurrentWordEquals(value)
        | PredicateOp::CurrentWordStartsWith(value)
        | PredicateOp::PreviousWordEquals(value)
        | PredicateOp::AnyWordEquals(value)
        | PredicateOp::WordNotPresent(value)
        | PredicateOp::EnvironmentSet(value) => validate_string(value),
        PredicateOp::CommandPathEquals(values) => {
            if values.len() > 256 {
                return Err(IrError::Limit("command path"));
            }
            values.iter().try_for_each(|value| validate_string(value))
        }
        PredicateOp::EnvironmentEquals { name, value } => {
            validate_string(name)?;
            validate_string(value)
        }
        _ => Ok(()),
    }
}

fn encode_predicates(encoder: &mut Encoder, predicates: &[PredicateOp]) -> Result<(), IrError> {
    validate_predicates(predicates)?;
    encoder.count(predicates.len())?;
    for predicate in predicates {
        match predicate {
            PredicateOp::True => encoder.u8(0),
            PredicateOp::False => encoder.u8(1),
            PredicateOp::Not => encoder.u8(2),
            PredicateOp::And => encoder.u8(3),
            PredicateOp::Or => encoder.u8(4),
            PredicateOp::CurrentWordEquals(value) => {
                encoder.u8(5);
                encoder.string(value)?;
            }
            PredicateOp::CurrentWordStartsWith(value) => {
                encoder.u8(6);
                encoder.string(value)?;
            }
            PredicateOp::PreviousWordEquals(value) => {
                encoder.u8(7);
                encoder.string(value)?;
            }
            PredicateOp::AnyWordEquals(value) => {
                encoder.u8(8);
                encoder.string(value)?;
            }
            PredicateOp::WordNotPresent(value) => {
                encoder.u8(9);
                encoder.string(value)?;
            }
            PredicateOp::WordIndexEquals(value) => {
                encoder.u8(10);
                encoder.u32(*value);
            }
            PredicateOp::WordIndexAtLeast(value) => {
                encoder.u8(11);
                encoder.u32(*value);
            }
            PredicateOp::CommandPathEquals(values) => {
                encoder.u8(12);
                encoder.strings(values)?;
            }
            PredicateOp::EnvironmentSet(value) => {
                encoder.u8(13);
                encoder.string(value)?;
            }
            PredicateOp::EnvironmentEquals { name, value } => {
                encoder.u8(14);
                encoder.string(name)?;
                encoder.string(value)?;
            }
        }
    }
    Ok(())
}

fn decode_predicates(decoder: &mut Decoder<'_>) -> Result<Vec<PredicateOp>, IrError> {
    let count = decoder.count(MAX_PREDICATES_PER_RULE)?;
    decoder.charge_array::<PredicateOp>(count)?;
    let mut predicates = Vec::with_capacity(count);
    for _ in 0..count {
        predicates.push(match decoder.u8()? {
            0 => PredicateOp::True,
            1 => PredicateOp::False,
            2 => PredicateOp::Not,
            3 => PredicateOp::And,
            4 => PredicateOp::Or,
            5 => PredicateOp::CurrentWordEquals(decoder.string()?),
            6 => PredicateOp::CurrentWordStartsWith(decoder.string()?),
            7 => PredicateOp::PreviousWordEquals(decoder.string()?),
            8 => PredicateOp::AnyWordEquals(decoder.string()?),
            9 => PredicateOp::WordNotPresent(decoder.string()?),
            10 => PredicateOp::WordIndexEquals(decoder.u32()?),
            11 => PredicateOp::WordIndexAtLeast(decoder.u32()?),
            12 => PredicateOp::CommandPathEquals(decoder.strings(256)?),
            13 => PredicateOp::EnvironmentSet(decoder.string()?),
            14 => PredicateOp::EnvironmentEquals {
                name: decoder.string()?,
                value: decoder.string()?,
            },
            value => return Err(IrError::InvalidEnum("predicate opcode", value)),
        });
    }
    validate_predicates(&predicates)?;
    Ok(predicates)
}

fn encode_candidate(encoder: &mut Encoder, candidate: &CandidateTemplate) -> Result<(), IrError> {
    validate_candidate(candidate)?;
    encoder.string(&candidate.value)?;
    encoder.string(&candidate.display)?;
    encoder.optional_string(candidate.description.as_deref())?;
    encoder.u8(candidate.kind.encode());
    encoder.u8(candidate.append.encode());
    encoder.u8(u8::from(candidate.preserve_order));
    encoder.u8(0);
    Ok(())
}

fn decode_candidate(decoder: &mut Decoder<'_>) -> Result<CandidateTemplate, IrError> {
    let candidate = CandidateTemplate {
        value: decoder.string()?,
        display: decoder.string()?,
        description: decoder.optional_string()?,
        kind: RuleCandidateKind::decode(decoder.u8()?)?,
        append: AppendPolicy::decode(decoder.u8()?)?,
        preserve_order: match decoder.u8()? {
            0 => false,
            1 => true,
            value => return Err(IrError::InvalidEnum("candidate ordering flag", value)),
        },
    };
    if decoder.u8()? != 0 {
        return Err(IrError::Invalid("nonzero candidate flags"));
    }
    validate_candidate(&candidate)?;
    Ok(candidate)
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4096)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON buffer exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), IrError> {
        self.u32(u32::try_from(value).map_err(|_| IrError::Limit("encoded count"))?);
        Ok(())
    }

    fn blob(&mut self, value: &[u8]) -> Result<(), IrError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), IrError> {
        validate_string(value)?;
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn optional_string(&mut self, value: Option<&str>) -> Result<(), IrError> {
        match value {
            Some(value) => {
                self.u8(1);
                self.string(value)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    fn strings(&mut self, values: &[String]) -> Result<(), IrError> {
        self.count(values.len())?;
        for value in values {
            self.string(value)?;
        }
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    string_bytes: usize,
    allocation_bytes: usize,
    allocation_limit: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], allocation_limit: usize) -> Self {
        Self {
            bytes,
            position: 0,
            string_bytes: 0,
            allocation_bytes: bytes.len(),
            allocation_limit,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), IrError> {
        self.allocation_bytes = self.allocation_bytes.saturating_add(bytes);
        if self.allocation_bytes > self.allocation_limit {
            return Err(IrError::Limit("decoded command allocation"));
        }
        Ok(())
    }

    fn charge_array<T>(&mut self, count: usize) -> Result<(), IrError> {
        self.charge(count.saturating_mul(std::mem::size_of::<T>()))
    }

    fn remaining_allocation(&self) -> usize {
        self.allocation_limit.saturating_sub(self.allocation_bytes)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], IrError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(IrError::Invalid("offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(IrError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, IrError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, IrError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| IrError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, IrError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| IrError::Truncated)?,
        ))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, IrError> {
        let value = usize::try_from(self.u32()?).map_err(|_| IrError::Limit("decoded count"))?;
        if value > maximum {
            return Err(IrError::Limit("decoded count"));
        }
        Ok(value)
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], IrError> {
        let length = self.count(maximum)?;
        self.take(length)
    }

    fn string(&mut self) -> Result<String, IrError> {
        let length = self.count(MAX_STRING_BYTES)?;
        self.string_bytes = self.string_bytes.saturating_add(length);
        self.charge(length)?;
        if self.string_bytes > MAX_STRINGS_BYTES {
            return Err(IrError::Limit("decoded string table"));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| IrError::Invalid("invalid UTF-8"))?
            .to_owned();
        validate_string(&value)?;
        Ok(value)
    }

    fn optional_string(&mut self) -> Result<Option<String>, IrError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            value => Err(IrError::InvalidEnum("optional string flag", value)),
        }
    }

    fn strings(&mut self, maximum: usize) -> Result<Vec<String>, IrError> {
        let count = self.count(maximum)?;
        self.charge_array::<String>(count)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.string()?);
        }
        Ok(values)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrError {
    Truncated,
    Invalid(&'static str),
    InvalidEnum(&'static str, u8),
    Limit(&'static str),
}

impl fmt::Display for IrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated IR block"),
            Self::Invalid(message) => write!(formatter, "invalid IR: {message}"),
            Self::InvalidEnum(name, value) => write!(formatter, "invalid IR {name}: {value}"),
            Self::Limit(name) => write!(formatter, "IR limit exceeded: {name}"),
        }
    }
}

impl std::error::Error for IrError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CommandProgram {
        CommandProgram {
            canonical_name: "git".into(),
            registrations: vec!["git".into()],
            source_path: "completions/git".into(),
            source_commit: "0123456789abcdef".into(),
            license: "GPL-2.0-or-later".into(),
            static_rules: vec![StaticRule {
                when: vec![PredicateOp::PreviousWordEquals("checkout".into())],
                path_completion: PathCompletion::Directories,
                candidates: vec![CandidateTemplate {
                    value: "--detach".into(),
                    display: "--detach".into(),
                    description: Some("Detach HEAD at the named commit".into()),
                    kind: RuleCandidateKind::Option,
                    append: AppendPolicy::Space,
                    preserve_order: false,
                }],
            }],
            probes: vec![ProbeSpec {
                id: "refs".into(),
                when: vec![PredicateOp::True],
                executable: "git".into(),
                arguments: vec!["for-each-ref".into(), "--format=%(refname:short)".into()],
                environment: Vec::new(),
                parser: ProbeParser::Lines,
                candidate_kind: RuleCandidateKind::Value,
                append: AppendPolicy::Space,
                timeout_ms: 2000,
                output_limit: 1024 * 1024,
                cache_ttl_ms: 1000,
                description: Some("Git ref".into()),
            }],
            scripts: Vec::new(),
        }
    }

    #[test]
    fn command_program_round_trips_without_native_layout() {
        let expected = fixture();
        let bytes = expected.encode().unwrap();
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), expected);
    }

    #[test]
    fn static_candidate_control_characters_are_rejected() {
        let mut program = fixture();
        program.static_rules[0].candidates[0].display = "unsafe\nrow".into();
        assert!(matches!(program.validate(), Err(IrError::Invalid(_))));
    }

    #[test]
    fn previous_command_block_versions_remain_decodable() {
        let program = fixture();
        let bytes = program
            .encode_version(PREVIOUS_COMMAND_BLOCK_VERSION)
            .unwrap();
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), program);

        let bytes = program.encode_version(2).unwrap();
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), program);

        let bytes = program
            .encode_version(LEGACY_COMMAND_BLOCK_VERSION)
            .unwrap();
        let mut legacy_expected = program;
        legacy_expected.static_rules[0].path_completion = PathCompletion::Inherit;
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), legacy_expected);
    }

    #[test]
    fn compound_redirection_requires_command_block_version_four() {
        let mut program = fixture();
        program.scripts.push(
            crate::rules::script_parser::parse_script(
                crate::rules::script::ScriptDialect::Bash,
                "redirected.bash",
                "while read value; do :; done <<< input\n",
            )
            .unwrap(),
        );
        assert!(matches!(
            program.encode_version(PREVIOUS_COMMAND_BLOCK_VERSION),
            Err(IrError::Invalid(
                "script feature requires command block version 4"
            ))
        ));
        let bytes = program.encode().unwrap();
        let decoded = CommandProgram::decode(&bytes).unwrap();
        assert_eq!(decoded.canonical_name, program.canonical_name);
        assert!(matches!(
            decoded.scripts[0].statements[0],
            crate::rules::script::ScriptStatement::Redirected { .. }
        ));

        program.scripts = vec![
            crate::rules::script_parser::parse_script(
                crate::rules::script::ScriptDialect::Zsh,
                "dynamic.zsh",
                "define() { local name=$1; eval \"$name () { true; }\"; }\n",
            )
            .unwrap(),
        ];
        assert!(matches!(
            program.encode_version(PREVIOUS_COMMAND_BLOCK_VERSION),
            Err(IrError::Invalid(
                "script feature requires command block version 4"
            ))
        ));
    }

    #[test]
    fn predicate_strings_share_the_encoded_string_budget() {
        let mut program = fixture();
        let value = "x".repeat(MAX_STRING_BYTES);
        program.static_rules = (0..9)
            .map(|_| StaticRule {
                when: vec![PredicateOp::CurrentWordEquals(value.clone())],
                path_completion: PathCompletion::Inherit,
                candidates: Vec::new(),
            })
            .collect();
        assert!(matches!(
            program.validate(),
            Err(IrError::Limit("command string table"))
        ));
        assert!(matches!(
            program.encode(),
            Err(IrError::Limit("command string table"))
        ));
    }

    #[test]
    fn duplicate_probe_ids_are_rejected_before_encoding() {
        let mut program = fixture();
        program.probes.push(program.probes[0].clone());
        assert!(matches!(
            program.validate(),
            Err(IrError::Invalid("duplicate probe id"))
        ));
    }

    #[test]
    fn aggregate_script_module_count_is_validated_before_encoding() {
        let module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Fish,
            "demo.fish",
            ":\n",
        )
        .unwrap();
        let mut program = fixture();
        program.scripts = vec![module; MAX_SCRIPT_MODULES + 1];
        assert!(matches!(
            program.encode(),
            Err(IrError::Limit("script modules"))
        ));
    }

    #[test]
    fn script_json_serialization_is_capped_by_the_command_block_limit() {
        let mut program = fixture();
        program.scripts = (0..17)
            .map(|_| {
                let mut module = crate::rules::script_parser::parse_script(
                    crate::rules::script::ScriptDialect::Fish,
                    "demo.fish",
                    ":\n",
                )
                .unwrap();
                module.source_path = "x".repeat(MAX_STRING_BYTES);
                module
            })
            .collect();
        assert!(matches!(
            program.encode(),
            Err(IrError::Limit("encoded command block"))
        ));
    }

    #[test]
    fn valid_script_json_above_eight_mib_round_trips() {
        let mut program = fixture();
        program.scripts = (0..14)
            .map(|index| {
                let mut module = crate::rules::script_parser::parse_script(
                    crate::rules::script::ScriptDialect::Fish,
                    "demo.fish",
                    ":\n",
                )
                .unwrap();
                module.source_path = format!("{index}{}", "x".repeat(950_000));
                module
            })
            .collect();
        let encoded = program.encode().unwrap();
        assert!(encoded.len() > 12 * 1024 * 1024);
        let decoded = CommandProgram::decode(&encoded).unwrap();
        assert_eq!(decoded.scripts.len(), program.scripts.len());
        assert_eq!(
            decoded
                .scripts
                .iter()
                .map(|module| module.source_path.as_str())
                .collect::<Vec<_>>(),
            program
                .scripts
                .iter()
                .map(|module| module.source_path.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn tag_late_raw_fields_are_charged_before_typed_deserialization() {
        let mut json = String::from("[{");
        for index in 0..20_000 {
            if index != 0 {
                json.push(',');
            }
            json.push_str(&format!(r#""unknown-{index}":null"#));
        }
        json.push_str(r#", "op":"noop"}]"#);
        assert!(matches!(
            preflight_script_encoding_with_limit(json.as_bytes(), 1536 * 1024, false),
            Err(IrError::Limit("aggregate shell script IR"))
        ));
    }

    #[test]
    fn decoy_enum_tags_cannot_bypass_deferred_field_accounting() {
        for (decoy, real) in [("kind", "op"), ("op", "kind")] {
            let mut json = format!(r#"[{{"{decoy}":null"#);
            for index in 0..20_000 {
                json.push_str(&format!(r#", "unknown-{index}":null"#));
            }
            json.push_str(&format!(r#", "{real}":"noop"}}]"#));
            assert!(matches!(
                preflight_script_encoding_with_limit(json.as_bytes(), 1536 * 1024, false),
                Err(IrError::Limit("aggregate shell script IR"))
            ));
        }
    }

    #[test]
    fn known_discriminators_and_sequential_scratch_are_not_cumulative() {
        let module_prefix = r#"[{"dialect":"fish","source_path":"x","statements":["#;
        let module_suffix = r#"],"functions":[],"registrations":[],"probe_capabilities":[]}]"#;
        let mut plain = String::from(module_prefix);
        for index in 0..250_000 {
            if index != 0 {
                plain.push(',');
            }
            plain.push_str(r#"{"op":"noop"}"#);
        }
        plain.push_str(module_suffix);
        preflight_script_encoding_with_limit(plain.as_bytes(), MAX_SCRIPT_AGGREGATE_BYTES, false)
            .unwrap();

        let mut escaped = String::from(module_prefix);
        for index in 0..215_000 {
            if index != 0 {
                escaped.push(',');
            }
            escaped.push_str(r#"{"op":"n\u006fop"}"#);
        }
        escaped.push_str(module_suffix);
        preflight_script_encoding_with_limit(escaped.as_bytes(), MAX_SCRIPT_AGGREGATE_BYTES, false)
            .unwrap();
    }

    #[test]
    fn deferred_field_boundary_excludes_the_discriminator() {
        let mut json = String::from("[{");
        for _ in 0..MAX_SCRIPT_TAG_DEFERRED_FIELDS {
            json.push_str(r#""x":null,"#);
        }
        json.push_str(r#""op":"noop"}]"#);
        preflight_script_encoding_with_limit(json.as_bytes(), MAX_SCRIPT_AGGREGATE_BYTES, false)
            .unwrap();

        let mut post_tag = String::from(r#"[{"op":"noop","#);
        for index in 0..=MAX_SCRIPT_TAG_DEFERRED_FIELDS {
            if index != 0 {
                post_tag.push(',');
            }
            post_tag.push_str(r#""x":null"#);
        }
        post_tag.push_str("}]");
        preflight_script_encoding_with_limit(
            post_tag.as_bytes(),
            MAX_SCRIPT_AGGREGATE_BYTES,
            false,
        )
        .unwrap();
    }

    #[test]
    fn unknown_discriminator_error_text_is_preflighted() {
        let json = format!(r#"[{{"body":null,"op":"{}"}}]"#, "x".repeat(1024 * 1024));
        assert!(matches!(
            preflight_script_encoding_with_limit(json.as_bytes(), 512 * 1024, false),
            Err(IrError::Limit("aggregate shell script IR"))
        ));
    }

    #[test]
    fn escaped_key_scratch_is_included_in_preflight_peak() {
        let escaped_key = r"\u0061".repeat(200_000);
        let json = format!(r#"[{{"{escaped_key}":null}}]"#);
        assert!(matches!(
            preflight_script_encoding_with_limit(json.as_bytes(), 2 * 1024 * 1024, false),
            Err(IrError::Limit("aggregate shell script IR"))
        ));
    }

    #[test]
    fn nested_tag_late_reparse_scratch_is_cumulative() {
        let escaped_name = r"\u0061".repeat(10_000);
        let mut statement = String::from(r#"{"op":"noop"}"#);
        for _ in 0..16 {
            statement = format!(
                r#"{{"function":{{"name":"{escaped_name}","arguments":[],"body":[{statement}]}},"op":"function"}}"#
            );
        }
        let json = format!("[{statement}]");
        assert!(matches!(
            preflight_script_encoding_with_limit(json.as_bytes(), 2 * 1024 * 1024, false),
            Err(IrError::Limit("aggregate shell script IR"))
        ));
    }

    #[test]
    fn zsh_name_uniqueness_sort_scratch_is_preflighted() {
        let mut json = String::from(
            r#"[{"dialect":"zsh","source_path":"x","statements":[],"functions":[],"registrations":[],"probe_capabilities":[],"zsh_function_names":["#,
        );
        json.push('"');
        for index in 0..32_769 {
            if index != 0 {
                json.push_str(r#"",""#);
            }
            json.push_str(&format!("name-{index}"));
        }
        json.push_str(r#""]}]"#);
        let result = preflight_script_encoding_with_limit(json.as_bytes(), 2 * 1024 * 1024, false);
        assert!(
            matches!(result, Err(IrError::Limit("aggregate shell script IR"))),
            "{result:?}"
        );
    }

    #[test]
    fn compact_script_json_is_allocation_budgeted_before_deserialization() {
        let mut json =
            String::from(r#"[{"dialect":"fish","source_path":"hostile.fish","statements":["#);
        for index in 0..500_000 {
            if index != 0 {
                json.push(',');
            }
            json.push_str(r#"{"op":"noop"}"#);
        }
        json.push_str("],\"functions\":[],\"registrations\":[],\"probe_capabilities\":[]}]");
        assert!(json.len() < MAX_COMMAND_BLOCK_BYTES);
        assert!(matches!(
            preflight_script_encoding(json.as_bytes()),
            Err(IrError::Limit("aggregate shell script IR"))
        ));
    }

    #[test]
    fn escaped_script_string_is_charged_without_false_rejection() {
        let escaped = r"\u0061".repeat(2_000_000);
        let json = format!(
            r#"[{{"dialect":"fish","source_path":"{escaped}","statements":[],"functions":[],"registrations":[],"probe_capabilities":[]}}]"#
        );
        assert!(json.len() < MAX_COMMAND_BLOCK_BYTES);
        preflight_script_encoding(json.as_bytes()).unwrap();
    }

    #[test]
    fn script_json_preflight_rejects_malformed_structure_without_allocation() {
        for json in [
            br#"[{"source_path":"\uD800"}]"#.as_slice(),
            br#"[{"source_path":"\uDC00"}]"#.as_slice(),
            br#"[{"source_path":"unterminated}]"#.as_slice(),
            br#"[{"value":1e}]"#.as_slice(),
            br#"[{"values":[true,]}]"#.as_slice(),
        ] {
            assert!(matches!(
                preflight_script_encoding(json),
                Err(IrError::Invalid("invalid script encoding"))
            ));
        }
    }

    #[test]
    fn predicate_stack_is_verified() {
        let mut invalid = fixture();
        invalid.static_rules[0].when = vec![PredicateOp::And];
        assert!(matches!(invalid.validate(), Err(IrError::Invalid(_))));
    }

    #[test]
    fn shell_executables_are_forbidden_as_probe_targets() {
        let mut invalid = fixture();
        invalid.probes[0].executable = "bash".into();
        assert!(matches!(invalid.validate(), Err(IrError::Invalid(_))));
    }

    #[test]
    fn truncated_blocks_are_rejected() {
        let bytes = fixture().encode().unwrap();
        for end in 0..bytes.len() {
            assert!(CommandProgram::decode(&bytes[..end]).is_err());
        }
    }
}
