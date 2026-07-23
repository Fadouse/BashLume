// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use super::format::{SourceKind, TrustStatus};
use super::ir::{CandidateTemplate, CommandProgram, PredicateOp, ProbeParser, RuleCandidateKind};

pub const MAX_EVALUATED_RULES: usize = 65_536;
pub const MAX_EMITTED_CANDIDATES: usize = 65_536;
pub const MAX_PROBE_REQUESTS: usize = 4096;

pub struct EvaluationContext<'a> {
    pub current_word: &'a str,
    pub words: &'a [String],
    pub word_index: usize,
    pub command_path: &'a [String],
    pub environment: &'a HashMap<String, String>,
    pub working_directory: &'a Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationMode {
    Passive,
    ExplicitTab,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmittedCandidate {
    pub candidate: CandidateTemplate,
    pub source: SourceKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProbeKey {
    pub executable: String,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub working_directory: String,
    pub parser: ProbeParser,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRequest {
    pub key: ProbeKey,
    pub probe_id: String,
    pub candidate_kind: RuleCandidateKind,
    pub append: super::ir::AppendPolicy,
    pub timeout_ms: u32,
    pub output_limit: u32,
    pub cache_ttl_ms: u32,
    pub description: Option<String>,
    pub source: SourceKind,
    pub dynamic_authorized: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvaluationResult {
    pub candidates: Vec<EmittedCandidate>,
    pub probes: Vec<ProbeRequest>,
    pub denied_probe_count: usize,
}

pub fn evaluate(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
) -> Result<EvaluationResult, VmError> {
    program.validate().map_err(VmError::InvalidProgram)?;
    let candidate_limit = candidate_limit.clamp(1, MAX_EMITTED_CANDIDATES);
    let mut result = EvaluationResult::default();
    let mut evaluated_rules = 0_usize;

    for rule in &program.static_rules {
        evaluated_rules = evaluated_rules.saturating_add(1);
        if evaluated_rules > MAX_EVALUATED_RULES {
            return Err(VmError::Limit("evaluated rules"));
        }
        if evaluate_predicates(&rule.when, context)? {
            for candidate in &rule.candidates {
                if result.candidates.len() >= candidate_limit {
                    break;
                }
                result.candidates.push(EmittedCandidate {
                    candidate: candidate.clone(),
                    source,
                });
            }
        }
    }

    for probe in &program.probes {
        if !evaluate_predicates(&probe.when, context)? {
            continue;
        }
        let authorized = trust.permits_dynamic_probes();
        if mode != EvaluationMode::ExplicitTab || !authorized {
            if mode == EvaluationMode::ExplicitTab && !authorized {
                result.denied_probe_count = result.denied_probe_count.saturating_add(1);
            }
            continue;
        }
        if result.probes.len() >= MAX_PROBE_REQUESTS {
            return Err(VmError::Limit("probe requests"));
        }
        let arguments = probe
            .arguments
            .iter()
            .map(|argument| expand_template(argument, context))
            .collect::<Result<Vec<_>, _>>()?;
        let mut environment = Vec::with_capacity(probe.environment.len());
        for (name, value) in &probe.environment {
            environment.push((name.clone(), expand_template(value, context)?));
        }
        result.probes.push(ProbeRequest {
            key: ProbeKey {
                executable: probe.executable.clone(),
                arguments,
                environment,
                working_directory: context.working_directory.to_string_lossy().into_owned(),
                parser: probe.parser,
            },
            probe_id: probe.id.clone(),
            candidate_kind: probe.candidate_kind,
            append: probe.append,
            timeout_ms: probe.timeout_ms,
            output_limit: probe.output_limit,
            cache_ttl_ms: probe.cache_ttl_ms,
            description: probe.description.clone(),
            source,
            dynamic_authorized: true,
        });
    }
    Ok(result)
}

pub fn evaluate_predicates(
    program: &[PredicateOp],
    context: &EvaluationContext<'_>,
) -> Result<bool, VmError> {
    if program.is_empty() || program.len() > 4096 {
        return Err(VmError::Limit("predicate instructions"));
    }
    let mut stack = Vec::with_capacity(program.len().min(64));
    for instruction in program {
        match instruction {
            PredicateOp::True => stack.push(true),
            PredicateOp::False => stack.push(false),
            PredicateOp::Not => {
                let value = stack.pop().ok_or(VmError::StackUnderflow)?;
                stack.push(!value);
            }
            PredicateOp::And => {
                let right = stack.pop().ok_or(VmError::StackUnderflow)?;
                let left = stack.pop().ok_or(VmError::StackUnderflow)?;
                stack.push(left && right);
            }
            PredicateOp::Or => {
                let right = stack.pop().ok_or(VmError::StackUnderflow)?;
                let left = stack.pop().ok_or(VmError::StackUnderflow)?;
                stack.push(left || right);
            }
            PredicateOp::CurrentWordEquals(value) => stack.push(context.current_word == value),
            PredicateOp::CurrentWordStartsWith(value) => {
                stack.push(context.current_word.starts_with(value));
            }
            PredicateOp::PreviousWordEquals(value) => stack.push(
                context
                    .word_index
                    .checked_sub(1)
                    .and_then(|index| context.words.get(index))
                    == Some(value),
            ),
            PredicateOp::AnyWordEquals(value) => {
                stack.push(context.words.iter().any(|word| word == value));
            }
            PredicateOp::WordNotPresent(value) => {
                stack.push(context.words.iter().all(|word| word != value));
            }
            PredicateOp::WordIndexEquals(value) => {
                stack.push(context.word_index == *value as usize);
            }
            PredicateOp::WordIndexAtLeast(value) => {
                stack.push(context.word_index >= *value as usize);
            }
            PredicateOp::CommandPathEquals(value) => stack.push(context.command_path == value),
            PredicateOp::EnvironmentSet(name) => stack.push(context.environment.contains_key(name)),
            PredicateOp::EnvironmentEquals { name, value } => {
                stack.push(context.environment.get(name) == Some(value));
            }
        }
        if stack.len() > 256 {
            return Err(VmError::Limit("predicate stack"));
        }
    }
    match stack.as_slice() {
        [result] => Ok(*result),
        _ => Err(VmError::InvalidResultStack),
    }
}

fn expand_template(template: &str, context: &EvaluationContext<'_>) -> Result<String, VmError> {
    if !template.contains('{') {
        return Ok(template.to_owned());
    }
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        output.push_str(&rest[..open]);
        rest = &rest[open + 1..];
        let close = rest
            .find('}')
            .ok_or(VmError::InvalidTemplate("unclosed placeholder"))?;
        let placeholder = &rest[..close];
        match placeholder {
            "current" => output.push_str(context.current_word),
            "command" => output.push_str(context.command_path.first().map_or("", String::as_str)),
            "cwd" => output.push_str(&context.working_directory.to_string_lossy()),
            value if value.starts_with("word:") => {
                let index = value[5..]
                    .parse::<usize>()
                    .map_err(|_| VmError::InvalidTemplate("invalid word index"))?;
                output.push_str(context.words.get(index).map_or("", String::as_str));
            }
            _ => return Err(VmError::InvalidTemplate("unknown placeholder")),
        }
        rest = &rest[close + 1..];
        if output.len() > 1024 * 1024 {
            return Err(VmError::Limit("expanded probe argument"));
        }
    }
    output.push_str(rest);
    if output.contains('\0') {
        return Err(VmError::InvalidTemplate("expanded argument contains NUL"));
    }
    Ok(output)
}

#[derive(Debug)]
pub enum VmError {
    InvalidProgram(super::ir::IrError),
    StackUnderflow,
    InvalidResultStack,
    InvalidTemplate(&'static str),
    Limit(&'static str),
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram(error) => write!(formatter, "invalid completion program: {error}"),
            Self::StackUnderflow => formatter.write_str("completion predicate stack underflow"),
            Self::InvalidResultStack => {
                formatter.write_str("completion predicate did not produce one result")
            }
            Self::InvalidTemplate(message) => {
                write!(formatter, "invalid probe template: {message}")
            }
            Self::Limit(message) => write!(formatter, "completion VM limit exceeded: {message}"),
        }
    }
}

impl std::error::Error for VmError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::format::SourceKind;
    use crate::rules::ir::{
        AppendPolicy, CandidateTemplate, PredicateOp, RuleCandidateKind, StaticRule,
    };

    fn context<'a>(
        words: &'a [String],
        environment: &'a HashMap<String, String>,
    ) -> EvaluationContext<'a> {
        EvaluationContext {
            current_word: words.last().map_or("", String::as_str),
            words,
            word_index: words.len().saturating_sub(1),
            command_path: words.get(..1).unwrap_or_default(),
            environment,
            working_directory: Path::new("/tmp"),
        }
    }

    #[test]
    fn postfix_predicates_are_bounded_and_deterministic() {
        let words = vec!["git".into(), "checkout".into(), "ma".into()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let predicate = vec![
            PredicateOp::PreviousWordEquals("checkout".into()),
            PredicateOp::WordNotPresent("--detach".into()),
            PredicateOp::And,
        ];
        assert!(evaluate_predicates(&predicate, &context).unwrap());
    }

    #[test]
    fn passive_evaluation_never_returns_process_requests() {
        let program = CommandProgram {
            canonical_name: "git".into(),
            registrations: vec!["git".into()],
            source_path: "git".into(),
            source_commit: "abc".into(),
            license: "GPL-2.0-or-later".into(),
            static_rules: vec![StaticRule {
                when: vec![PredicateOp::True],
                candidates: vec![CandidateTemplate {
                    value: "checkout".into(),
                    display: "checkout".into(),
                    description: Some("Switch branches".into()),
                    kind: RuleCandidateKind::Subcommand,
                    append: AppendPolicy::Space,
                    preserve_order: false,
                }],
            }],
            probes: Vec::new(),
        };
        let words = vec!["git".into(), "ch".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(result.probes.is_empty());
    }
}
