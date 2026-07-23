// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use serde::{Deserialize, Serialize};

pub const COMMAND_BLOCK_MAGIC: &[u8; 4] = b"BLIR";
pub const COMMAND_BLOCK_VERSION: u16 = 2;
pub const PREVIOUS_COMMAND_BLOCK_VERSION: u16 = 1;
pub const MAX_COMMAND_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REGISTRATIONS: usize = 4096;
pub const MAX_RULES: usize = 65_536;
pub const MAX_PREDICATES_PER_RULE: usize = 4096;
pub const MAX_PROBES: usize = 4096;
pub const MAX_STRINGS_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;

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
}

impl CommandProgram {
    pub fn validate(&self) -> Result<(), IrError> {
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
        let mut string_bytes = self
            .canonical_name
            .len()
            .saturating_add(self.source_path.len())
            .saturating_add(self.source_commit.len())
            .saturating_add(self.license.len());
        for registration in &self.registrations {
            validate_string(registration)?;
            string_bytes = string_bytes.saturating_add(registration.len());
        }
        for rule in &self.static_rules {
            validate_predicates(&rule.when)?;
            if rule.candidates.len() > MAX_RULES {
                return Err(IrError::Limit("candidates per static rule"));
            }
            for candidate in &rule.candidates {
                validate_candidate(candidate)?;
                string_bytes = string_bytes
                    .saturating_add(candidate.value.len())
                    .saturating_add(candidate.display.len())
                    .saturating_add(candidate.description.as_ref().map_or(0, String::len));
            }
        }
        for probe in &self.probes {
            validate_predicates(&probe.when)?;
            validate_string(&probe.id)?;
            validate_executable(&probe.executable)?;
            if probe.arguments.len() > 1024 || probe.environment.len() > 256 {
                return Err(IrError::Limit("probe arguments or environment"));
            }
            for argument in &probe.arguments {
                validate_string(argument)?;
            }
            for (name, value) in &probe.environment {
                validate_string(name)?;
                validate_string(value)?;
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
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, IrError> {
        self.encode_version(COMMAND_BLOCK_VERSION)
    }

    fn encode_version(&self, block_version: u16) -> Result<Vec<u8>, IrError> {
        self.validate()?;
        if block_version != COMMAND_BLOCK_VERSION && block_version != PREVIOUS_COMMAND_BLOCK_VERSION
        {
            return Err(IrError::Invalid("unsupported command block version"));
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
        if encoder.bytes.len() > MAX_COMMAND_BLOCK_BYTES {
            return Err(IrError::Limit("encoded command block"));
        }
        Ok(encoder.bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IrError> {
        if bytes.len() > MAX_COMMAND_BLOCK_BYTES {
            return Err(IrError::Limit("encoded command block"));
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != COMMAND_BLOCK_MAGIC {
            return Err(IrError::Invalid("invalid command block magic"));
        }
        let block_version = decoder.u16()?;
        if block_version != COMMAND_BLOCK_VERSION && block_version != PREVIOUS_COMMAND_BLOCK_VERSION
        {
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
        let mut static_rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            let when = decode_predicates(&mut decoder)?;
            let path_completion = if block_version >= 2 {
                PathCompletion::decode(decoder.u8()?)?
            } else {
                PathCompletion::Inherit
            };
            let candidate_count = decoder.count(MAX_RULES)?;
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
        let mut probes = Vec::with_capacity(probe_count);
        for _ in 0..probe_count {
            let id = decoder.string()?;
            let when = decode_predicates(&mut decoder)?;
            let executable = decoder.string()?;
            let arguments = decoder.strings(1024)?;
            let environment_count = decoder.count(256)?;
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
        if !decoder.remaining().is_empty() {
            return Err(IrError::Invalid("trailing command block bytes"));
        }
        let program = Self {
            canonical_name,
            registrations,
            source_path,
            source_commit,
            license,
            static_rules,
            probes,
        };
        program.validate()?;
        Ok(program)
    }
}

fn validate_executable(value: &str) -> Result<(), IrError> {
    validate_string(value)?;
    if value.is_empty()
        || value.contains('\0')
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
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            string_bytes: 0,
        }
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

    fn string(&mut self) -> Result<String, IrError> {
        let length = self.count(MAX_STRING_BYTES)?;
        self.string_bytes = self.string_bytes.saturating_add(length);
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
        }
    }

    #[test]
    fn command_program_round_trips_without_native_layout() {
        let expected = fixture();
        let bytes = expected.encode().unwrap();
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), expected);
    }

    #[test]
    fn previous_command_block_version_remains_decodable() {
        let program = fixture();
        let bytes = program
            .encode_version(PREVIOUS_COMMAND_BLOCK_VERSION)
            .unwrap();
        let mut expected = program;
        expected.static_rules[0].path_completion = PathCompletion::Inherit;
        assert_eq!(CommandProgram::decode(&bytes).unwrap(), expected);
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
