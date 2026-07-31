// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::format::{SourceKind, TrustStatus};
use super::ir::{
    CandidateTemplate, CommandProgram, PathCompletion, PredicateOp, ProbeParser, RuleCandidateKind,
};
use super::script::ScriptDialect;

pub const MAX_EVALUATED_RULES: usize = 65_536;
pub const MAX_EMITTED_CANDIDATES: usize = 65_536;
pub const MAX_PROBE_REQUESTS: usize = 4096;
pub const MAX_COMPLETION_REQUESTS: usize = 128;
pub const MAX_FILESYSTEM_REQUESTS: usize = 128;

pub(crate) fn platform_signal_snapshot() -> Vec<String> {
    super::script_vm::LINUX_SIGNAL_NAMES
        .iter()
        .map(|signal| (*signal).to_owned())
        .collect()
}

pub struct EvaluationContext<'a> {
    pub current_word: &'a str,
    pub words: &'a [String],
    pub word_index: usize,
    pub command_path: &'a [String],
    pub environment: &'a HashMap<String, String>,
    pub working_directory: &'a Path,
    /// Commands confirmed by the asynchronous command cache. `None` means the
    /// caller does not provide command-availability semantics.
    pub available_commands: Option<&'a HashSet<String>>,
    /// Ordered command names captured from shell state and the asynchronous PATH cache.
    pub shell_commands: Option<&'a [String]>,
    /// Function names captured from the host shell outside the completion VM.
    pub shell_functions: Option<&'a [String]>,
    /// Variable names captured from the host shell outside the completion VM.
    pub shell_variables: Option<&'a [String]>,
    /// Bounded scalar/list values captured with the host-shell variables.
    pub shell_variable_values: Option<&'a HashMap<String, Vec<String>>>,
    /// User names loaded asynchronously by the generic completion cache.
    pub users: Option<&'a [String]>,
    /// Group names loaded asynchronously by the generic completion cache.
    pub groups: Option<&'a [String]>,
    /// Host names loaded asynchronously from bounded hosts and SSH snapshots.
    pub hosts: Option<&'a [String]>,
    /// Process IDs and names loaded asynchronously from a bounded process snapshot.
    pub process_ids: Option<&'a [String]>,
    pub process_names: Option<&'a [String]>,
    /// Network interfaces loaded asynchronously from a bounded system snapshot.
    pub network_interfaces: Option<&'a [String]>,
    /// Signal names supplied by a fixed platform snapshot when one is available.
    pub signals: Option<&'a [String]>,
    /// Bounded passwd records captured alongside `users`, in source order.
    pub passwd_records: Option<&'a [String]>,
    /// Bounded group records captured alongside `groups`, in source order.
    pub group_records: Option<&'a [String]>,
    /// Effective user ID captured with the shell snapshot.
    pub effective_user_id: u32,
}

impl EvaluationContext<'_> {
    pub fn command_available(&self, name: &str) -> Option<bool> {
        self.available_commands
            .map(|commands| commands.contains(name))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationMode {
    Passive,
    ExplicitTab,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EmittedCandidate {
    pub candidate: CandidateTemplate,
    pub source: SourceKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ProbeKey {
    pub executable: String,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub working_directory: String,
    pub parser: ProbeParser,
    pub include_stderr: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeResult {
    pub status: i32,
    pub values: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct CompletionRequest {
    pub line: String,
}

pub(crate) const NESTED_COMPLETION_PATH_PREFIX: &str = "\0bashlume:path:";

pub(crate) fn nested_completion_path_marker(path: PathCompletion) -> Option<String> {
    let value = match path {
        PathCompletion::Inherit => return None,
        PathCompletion::Suppress => "suppress",
        PathCompletion::Directories => "directories",
        PathCompletion::Files => "files",
    };
    Some(format!("{NESTED_COMPLETION_PATH_PREFIX}{value}"))
}

pub(crate) fn nested_completion_path(value: &str) -> Option<PathCompletion> {
    match value.strip_prefix(NESTED_COMPLETION_PATH_PREFIX)? {
        "suppress" => Some(PathCompletion::Suppress),
        "directories" => Some(PathCompletion::Directories),
        "files" => Some(PathCompletion::Files),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemRequestKind {
    Test,
    Glob,
    Read,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct FilesystemRequest {
    pub request_id: String,
    pub kind: FilesystemRequestKind,
    pub dialect: ScriptDialect,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EvaluationResult {
    pub candidates: Vec<EmittedCandidate>,
    /// Candidates emitted before this evaluation encountered any unresolved
    /// asynchronous dependency. Runtime menus may display these while replay
    /// workers finish without exposing dependency-derived false positives.
    #[serde(skip)]
    pub(crate) provisional_candidates: Vec<EmittedCandidate>,
    #[serde(skip)]
    pub(crate) provisional_yielded: bool,
    #[serde(skip)]
    pub(crate) optimization_incomplete: bool,
    pub truncated: bool,
    pub probes: Vec<ProbeRequest>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completion_requests: Vec<CompletionRequest>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filesystem_requests: Vec<FilesystemRequest>,
    /// Explicit asynchronous/shell snapshot classes consumed by this evaluation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshot_providers: Vec<String>,
    pub denied_probe_count: usize,
    pub path_completion: PathCompletion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_status: Option<i32>,
}

pub fn evaluate(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
) -> Result<EvaluationResult, VmError> {
    evaluate_with_probe_results(
        program,
        context,
        source,
        trust,
        mode,
        candidate_limit,
        &HashMap::new(),
    )
}

pub fn evaluate_with_probe_results(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, Vec<String>>,
) -> Result<EvaluationResult, VmError> {
    evaluate_with_results(
        program,
        context,
        source,
        trust,
        mode,
        candidate_limit,
        probe_results,
        &HashMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_results(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, Vec<String>>,
    completion_results: &HashMap<String, Vec<String>>,
) -> Result<EvaluationResult, VmError> {
    let outcomes = probe_results
        .iter()
        .map(|(key, values)| {
            (
                key.clone(),
                ProbeResult {
                    status: 0,
                    values: values.clone(),
                    truncated: false,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    evaluate_with_outcomes(
        program,
        context,
        source,
        trust,
        mode,
        candidate_limit,
        &outcomes,
        completion_results,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_outcomes(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
) -> Result<EvaluationResult, VmError> {
    program.validate().map_err(VmError::InvalidProgram)?;
    evaluate_validated_with_outcomes(
        program,
        context,
        source,
        trust,
        mode,
        candidate_limit,
        probe_results,
        completion_results,
    )
}

/// Evaluate a command block that was already fully validated while decoding a
/// trusted pack block. Runtime pack providers use this path to avoid traversing
/// immutable Script IR again on every replay round.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_validated_with_outcomes(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
) -> Result<EvaluationResult, VmError> {
    evaluate_runtime_with_outcomes(
        program,
        context,
        source,
        trust,
        mode,
        candidate_limit,
        probe_results,
        completion_results,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_runtime_with_outcomes(
    program: &CommandProgram,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
    allow_provisional_yield: bool,
    runtime_optimizations: bool,
) -> Result<EvaluationResult, VmError> {
    evaluate_runtime_programs_with_outcomes(
        &[(program, trust)],
        context,
        source,
        mode,
        candidate_limit,
        probe_results,
        completion_results,
        allow_provisional_yield,
        runtime_optimizations,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_runtime_programs_with_outcomes(
    programs: &[(&CommandProgram, TrustStatus)],
    context: &EvaluationContext<'_>,
    source: SourceKind,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
    allow_provisional_yield: bool,
    runtime_optimizations: bool,
) -> Result<EvaluationResult, VmError> {
    let candidate_limit = candidate_limit.clamp(1, MAX_EMITTED_CANDIDATES);
    let mut result = EvaluationResult::default();
    let mut evaluated_rules = 0_usize;

    for &(program, trust) in programs {
        for rule in &program.static_rules {
            evaluated_rules = evaluated_rules.saturating_add(1);
            if evaluated_rules > MAX_EVALUATED_RULES {
                return Err(VmError::Limit("evaluated rules"));
            }
            if evaluate_predicates(&rule.when, context)? {
                result.path_completion = result.path_completion.merge(rule.path_completion);
                for candidate in &rule.candidates {
                    if result.candidates.len() >= candidate_limit {
                        result.truncated = true;
                        break;
                    }
                    let emitted = EmittedCandidate {
                        candidate: candidate.clone(),
                        source,
                    };
                    result.candidates.push(emitted);
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
                    include_stderr: false,
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
    }
    let module_groups = programs
        .iter()
        .filter(|(program, _)| !program.scripts.is_empty())
        .map(|(program, trust)| (program.scripts.as_slice(), *trust))
        .collect::<Vec<_>>();
    if !module_groups.is_empty() {
        let canonical_name = programs
            .first()
            .map_or("", |(program, _)| program.canonical_name.as_str());
        let command = context.words.first().map_or(canonical_name, String::as_str);
        let script_allow_provisional_yield = allow_provisional_yield
            && result.probes.is_empty()
            && result.completion_requests.is_empty()
            && result.filesystem_requests.is_empty();
        super::script_vm::evaluate_module_groups(
            &module_groups,
            command,
            context,
            source,
            mode,
            candidate_limit,
            probe_results,
            completion_results,
            &mut result,
            script_allow_provisional_yield,
            runtime_optimizations,
        )?;
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
    use crate::rules::script::ScriptDialect;
    use crate::rules::script_parser::parse_script;

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
            available_commands: None,
            shell_commands: None,
            shell_functions: None,
            shell_variables: None,
            shell_variable_values: None,
            users: None,
            groups: None,
            hosts: None,
            process_ids: None,
            process_names: None,
            network_interfaces: None,
            signals: None,
            passwd_records: None,
            group_records: None,
            effective_user_id: 1000,
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

    fn script_program(
        dialect: ScriptDialect,
        source_path: &str,
        command: &str,
        source: &str,
    ) -> CommandProgram {
        let module = parse_script(dialect, source_path, source).unwrap();
        CommandProgram {
            canonical_name: command.into(),
            registrations: vec![command.into()],
            source_path: source_path.into(),
            source_commit: "0123456789abcdef".into(),
            license: "GPL-2.0-or-later".into(),
            static_rules: Vec::new(),
            probes: Vec::new(),
            scripts: vec![module],
        }
    }

    fn script_probe_program() -> CommandProgram {
        let mut module = parse_script(
            ScriptDialect::Bash,
            "completions/demo.bash",
            "_demo() { COMPREPLY=( $({ probe-tool --list; } 2>&1) ); }\ncomplete -F _demo demo\n",
        )
        .unwrap();
        module.probe_capabilities = vec!["probe-tool".into()];
        CommandProgram {
            canonical_name: "demo".into(),
            registrations: vec!["demo".into()],
            source_path: "completions/demo.bash".into(),
            source_commit: "0123456789abcdef".into(),
            license: "GPL-2.0-or-later".into(),
            static_rules: Vec::new(),
            probes: Vec::new(),
            scripts: vec![module],
        }
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
                path_completion: PathCompletion::Inherit,
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
            scripts: Vec::new(),
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

    #[test]
    fn bash_conditional_extglobs_and_regex_captures_drive_array_results() {
        let program = script_program(
            ScriptDialect::Bash,
            "demo.bash",
            "demo",
            r#"_demo() {
  local -a options=()
  local line='   -h, --help text'
  if [[ $line == *([[:blank:]])-* ]]; then options+=(--extglob); fi
  if [[ $line =~ (^|[^-])(-[A-Za-z0-9?]+) ]]; then options+=("${BASH_REMATCH[2]}"); fi
  local usage='before [-a] after' match='[-a]'
  usage=${usage#*"$match"}
  [[ $usage == ' after' ]] && options+=(--trimmed)
  local option=--binary
  if [[ $option =~ ^([^=<{().[]|\.[A-Za-z0-9])+=? ]]; then options+=("$BASH_REMATCH"); fi
  [[ array == @(*[^_a-zA-Z0-9]*|[0-9]*|''|_*|IFS|OPTIND|OPTARG|OPTERR) ]] || options+=(--valid-array)
  local tarline='  -A, --catenate, --concatenate   append files'
  [[ $tarline =~ ^[[:blank:]]{1,10}(((,[[:blank:]])?(--?([\]\[a-zA-Z0-9?=-]+))(,[[:space:]])?)+).*$ ]] && options+=(--tar-regex)
  local optional='--occurrence[=NUMBER]'
  [[ $optional =~ --[A-Za-z0-9-]+(\[?)= ]] && [[ ${BASH_REMATCH[1]} == '[' ]] && options+=(--optional-capture)
  local unset_value
  [[ ! $unset_value ]] && options+=(--unset-conditional)
  COMPREPLY=("${options[@]}")
}
complete -F _demo demo
"#,
        );
        let words = vec!["demo".into(), "-".into()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            [
                "--extglob",
                "-h",
                "--trimmed",
                "--binary",
                "--valid-array",
                "--tar-regex",
                "--optional-capture",
                "--unset-conditional"
            ]
        );
    }

    #[test]
    fn bash_compreply_preserves_native_duplicate_order() {
        let program = script_program(
            ScriptDialect::Bash,
            "duplicates.bash",
            "duplicates",
            "_duplicates() { COMPREPLY=(same same other); }\ncomplete -F _duplicates duplicates\n",
        );
        let words = vec!["duplicates".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["same", "same", "other"]
        );
    }

    #[test]
    fn bash_empty_array_length_drives_return_status() {
        let program = script_program(
            ScriptDialect::Bash,
            "array-status.bash",
            "array-status",
            r#"_array_status() {
  local -a values=()
  ((${#values[@]})) || return 1
  return 0
}
complete -F _array_status array-status
"#,
        );
        let words = vec!["array-status".into(), String::new()];
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
        assert_eq!(result.completion_status, Some(1));
    }

    #[test]
    fn bash_arithmetic_for_builds_values_from_scalar_slices() {
        let program = script_program(
            ScriptDialect::Bash,
            "mode.bash",
            "mode-demo",
            r#"_mode_demo() {
  local basic_tar short_modes=ctx generated="" i
  [[ ! $basic_tar ]] && short_modes=ctxurdA
  for ((i = 0; 1; i++)); do
    local c="${short_modes:i:1}"
    [[ ! $c ]] && break
    generated+=" -$c"
  done
  COMPREPLY=($generated)
}
complete -F _mode_demo mode-demo
"#,
        );
        let words = vec!["mode-demo".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["-c", "-t", "-x", "-u", "-r", "-d", "-A"]
        );
    }

    #[test]
    fn bash_glob_parameter_replacements_strip_option_arguments() {
        let program = script_program(
            ScriptDialect::Bash,
            "replace.bash",
            "replace-demo",
            r#"_replace_demo() {
  local first='--occurrence[=NUMBER]' second='--file=ARCHIVE'
  first=${first//\[*/}
  second=${second//=*/=}
  COMPREPLY=("$first" "$second")
}
complete -F _replace_demo replace-demo
"#,
        );
        let words = vec!["replace-demo".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--occurrence", "--file="]
        );
    }

    #[test]
    fn bash_eval_composes_adjacent_dynamic_parameters_in_the_caller_scope() {
        let program = script_program(
            ScriptDialect::Bash,
            "eval-adjacent.bash",
            "eval-adjacent",
            r#"append() {
  local variable=output separator=" " value="$1"
  eval "$variable=\"\$$variable$separator\"\"$value\""
}
_eval_adjacent() {
  local output=""
  append --one
  append --two
  COMPREPLY=($output)
}
complete -F _eval_adjacent eval-adjacent
"#,
        );
        let words = vec!["eval-adjacent".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--one", "--two"]
        );
    }

    #[test]
    fn bash_standard_completion_actions_expose_help_and_readline_names() {
        let program = script_program(
            ScriptDialect::Bash,
            "actions.bash",
            "actions",
            "_actions() { local values=(); compgen -A helptopic -V values -- \"$2\"; compgen -A binding -V COMPREPLY -- \"$2\"; COMPREPLY+=(\"${values[@]}\"); }\ncomplete -F _actions actions\n",
        );
        let words = vec!["actions".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            512,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 221);
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "accept-line")
        );
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "variables")
        );
    }

    #[test]
    fn bash_array_slices_select_elements_instead_of_scalar_characters() {
        let program = script_program(
            ScriptDialect::Bash,
            "slice.bash",
            "slice",
            "_slice() { local -a values=(qdbus second); COMPREPLY=(\"${values[@]::1}\"); }\ncomplete -F _slice slice\n",
        );
        let words = vec!["slice".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "qdbus");
    }

    #[test]
    fn bash_array_pathname_expansion_uses_bounded_glob_replay() {
        let program = script_program(
            ScriptDialect::Bash,
            "glob-array.bash",
            "glob-array",
            "_glob_array() { COMPREPLY=(/virtual/tty*); }\ncomplete -F _glob_array glob-array\n",
        );
        let words = vec!["glob-array".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(initial.filesystem_requests.len(), 1);
        let replay = HashMap::from([(
            initial.filesystem_requests[0].request_id.clone(),
            vec!["/virtual/tty0".into(), "/virtual/tty1".into()],
        )]);
        let result = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &replay,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["/virtual/tty0", "/virtual/tty1"]
        );
    }

    #[test]
    fn bash_compgen_wordlist_evaluates_multiple_array_expressions() {
        let program = script_program(
            ScriptDialect::Bash,
            "wordlist-arrays.bash",
            "wordlist-arrays",
            r#"_wordlist_arrays() {
  COMPREPLY=(/dev/tty0 /dev/tty1)
  COMPREPLY=( $(compgen -W '"${COMPREPLY[@]}" "${COMPREPLY[@]#/dev/}"') )
}
complete -F _wordlist_arrays wordlist-arrays
"#,
        );
        let words = vec!["wordlist-arrays".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["/dev/tty0", "/dev/tty1", "tty0", "tty1"]
        );
    }

    #[test]
    fn bash_eval_array_pathname_expansion_uses_bounded_replay() {
        let program = script_program(
            ScriptDialect::Bash,
            "eval-glob.bash",
            "eval-glob",
            "_eval_glob() { shopt -s nullglob; eval -- 'COMPREPLY=(/virtual/tty*)'; }\ncomplete -F _eval_glob eval-glob\n",
        );
        let words = vec!["eval-glob".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(initial.filesystem_requests.len(), 1);
        let replay = HashMap::from([(
            initial.filesystem_requests[0].request_id.clone(),
            vec!["/virtual/tty0".into(), "/virtual/tty1".into()],
        )]);
        let result = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &replay,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["/virtual/tty0", "/virtual/tty1"]
        );
    }

    #[test]
    fn bash_command_offset_uses_the_explicit_command_snapshot() {
        let program = script_program(
            ScriptDialect::Bash,
            "offset.bash",
            "offset",
            "_offset() { _comp_command_offset 1; }\ncomplete -F _offset offset\n",
        );
        let words = vec!["offset".into(), String::new()];
        let environment = HashMap::new();
        let available = HashSet::from(["beta".to_owned(), "alpha".to_owned()]);
        let mut ctx = context(&words, &environment);
        ctx.available_commands = Some(&available);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(result.path_completion, PathCompletion::Files);
    }

    #[test]
    fn bash_empty_filedir_replay_preserves_inherited_path_policy() {
        let program = script_program(
            ScriptDialect::Bash,
            "filedir.bash",
            "filedir",
            "_filedir_demo() { _comp_compgen_filedir; }\ncomplete -F _filedir_demo filedir\n",
        );
        let words = vec!["filedir".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let request_id = initial.filesystem_requests[0].request_id.clone();
        let completion_results = HashMap::from([(request_id, Vec::new())]);
        let replayed = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &completion_results,
        )
        .unwrap();
        assert!(replayed.candidates.is_empty());
        assert_eq!(replayed.path_completion, PathCompletion::Inherit);
        assert_eq!(replayed.completion_status, Some(1));
    }

    #[test]
    fn bash_compgen_wordlists_apply_numeric_and_alternative_braces() {
        let program = script_program(
            ScriptDialect::Bash,
            "braces.bash",
            "braces",
            "_braces() { COMPREPLY=( $(compgen -W '{1..3} --{,no}color' -- \"$2\") ); }\ncomplete -F _braces braces\n",
        );
        let words = vec!["braces".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["1", "2", "3", "--color", "--nocolor"]
        );
    }

    #[test]
    fn bash_eval_array_assignment_honors_a_local_newline_ifs() {
        let program = script_program(
            ScriptDialect::Bash,
            "split.bash",
            "split-demo",
            r#"_split_demo() {
  local IFS=$'\n' text=$'--one\n--two'
  local -a values
  eval "values=(\$text)"
  COMPREPLY=("${values[@]}")
}
complete -F _split_demo split-demo
"#,
        );
        let words = vec!["split-demo".into(), "--".into()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--one", "--two"]
        );
    }

    #[test]
    fn bounded_recursive_shell_functions_can_reenter_the_same_definition() {
        let program = script_program(
            ScriptDialect::Bash,
            "recursive.bash",
            "recursive-demo",
            r#"recurse() {
  if (( $1 > 0 )); then recurse $(($1 - 1)); else COMPREPLY=(done); fi
}
_recursive_demo() { recurse 3; }
complete -F _recursive_demo recursive-demo
"#,
        );
        let words = vec!["recursive-demo".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "done");
    }

    #[test]
    fn compound_here_strings_feed_bounded_loop_input() {
        let program = script_program(
            ScriptDialect::Bash,
            "redirected.bash",
            "redirected-demo",
            r#"_redirected_demo() {
  local -a values=()
  while IFS= read -r line; do values+=("$line"); done <<< "$(printf '%s\n' '  one' two)"
  while read -ra fields; do values+=("${fields[@]}"); done <<< "three four"
  COMPREPLY=("${values[@]}")
}
complete -F _redirected_demo redirected-demo
"#,
        );
        let words = vec!["redirected-demo".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["  one", "two", "three", "four"]
        );
    }

    #[test]
    fn simple_function_redirection_is_visible_to_nested_builtins() {
        let program = script_program(
            ScriptDialect::Bash,
            "function-input.bash",
            "function-input",
            r#"consume() { while read -r line; do echo "$line"; done; }
_function_input() {
  local output
  output=$(consume <<< $'one\ntwo')
  COMPREPLY=($output)
}
complete -F _function_input function-input
"#,
        );
        let words = vec!["function-input".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn bash_compound_file_input_uses_bounded_replay_data() {
        let program = script_program(
            ScriptDialect::Bash,
            "read-file.bash",
            "read-file",
            r#"_read_file() {
  local -a values=()
  while IFS= read -r line; do values+=("$line"); done < /virtual/input
  COMPREPLY=("${values[@]}")
}
complete -F _read_file read-file
"#,
        );
        let words = vec!["read-file".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(initial.filesystem_requests.len(), 1);
        assert_eq!(
            initial.filesystem_requests[0].kind,
            FilesystemRequestKind::Read
        );
        let results = HashMap::from([(
            initial.filesystem_requests[0].request_id.clone(),
            vec!["first line".into(), "second".into()],
        )]);
        let replayed = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &results,
        )
        .unwrap();
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first line", "second"]
        );
    }

    #[test]
    fn fish_zero_delimited_read_streams_replayed_file_data() {
        let program = script_program(
            ScriptDialect::Fish,
            "read-zero.fish",
            "read-zero",
            "complete -c read-zero -a '(read -z < /virtual/input)'\n",
        );
        let words = vec!["read-zero".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let results = HashMap::from([(
            initial.filesystem_requests[0].request_id.clone(),
            vec!["first".into(), "second".into()],
        )]);
        let replayed = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &results,
        )
        .unwrap();
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn fish_read_array_skips_delimiter_option_values() {
        let program = script_program(
            ScriptDialect::Fish,
            "read-array.fish",
            "read-array",
            "function replayed_lines\n  read -alz -d \\n contents </virtual/input\n  printf '%s\\n' $contents\nend\ncomplete -c read-array -a '(replayed_lines)'\n",
        );
        let words = vec!["read-array".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let initial = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let results = HashMap::from([(
            initial.filesystem_requests[0].request_id.clone(),
            vec!["first".into(), "second".into()],
        )]);
        let replayed = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &results,
        )
        .unwrap();
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn bash_compgen_wordlists_evaluate_scalar_variables_with_ifs() {
        let program = script_program(
            ScriptDialect::Bash,
            "compgen.bash",
            "compgen-demo",
            r#"_compgen_demo() {
  local input=$'--one\n--two' IFS=$'\n'
  local -a result
  compgen -V result -X '' -- -W '$input'
  COMPREPLY=("${result[@]}")
}
complete -F _compgen_demo compgen-demo
"#,
        );
        let words = vec!["compgen-demo".into(), "--".into()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--one", "--two"]
        );
    }

    #[test]
    fn bash_direct_complete_actions_use_snapshot_and_path_policies() {
        let program = script_program(
            ScriptDialect::Bash,
            "direct.bash",
            "direct",
            "complete -u -d -W 'static-value' direct\n",
        );
        let words = vec!["direct".into(), String::new()];
        let environment = HashMap::new();
        let users = vec!["alice".into(), "bob".into()];
        let mut ctx = context(&words, &environment);
        ctx.users = Some(&users);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let values = result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.value.as_str())
            .collect::<Vec<_>>();
        assert!(values.contains(&"alice"));
        assert!(values.contains(&"bob"));
        assert!(values.contains(&"static-value"));
        assert_eq!(result.path_completion, PathCompletion::Directories);
    }

    #[test]
    fn bash_xfunc_dispatches_only_the_constructed_data_target() {
        let program = script_program(
            ScriptDialect::Bash,
            "xfunc.bash",
            "xfunc",
            "_comp_xfunc_demo_values() { COMPREPLY=(linked); }\n_entry() { _comp_xfunc demo values; }\ncomplete -F _entry xfunc\n",
        );
        let words = vec!["xfunc".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "linked");
    }

    #[test]
    fn bash_user_and_group_compgen_use_async_snapshot_data() {
        let program = script_program(
            ScriptDialect::Bash,
            "accounts.bash",
            "accounts",
            r#"_accounts() {
  local -a result=()
  compgen -V users -u
  compgen -V groups -g
  COMPREPLY=("${users[@]}" "${groups[@]}")
}
complete -F _accounts accounts
"#,
        );
        let words = vec!["accounts".into(), String::new()];
        let environment = HashMap::new();
        let users = vec!["alice".into(), "bob".into()];
        let groups = vec!["audio".into(), "wheel".into()];
        let mut ctx = context(&words, &environment);
        ctx.users = Some(&users);
        ctx.groups = Some(&groups);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alice", "bob", "audio", "wheel"]
        );
    }

    #[test]
    fn bash_pipeline_read_consumes_each_input_line_once() {
        let program = script_program(
            ScriptDialect::Bash,
            "read.bash",
            "read-demo",
            r#"_read_demo() {
  local output
  output=$(printf '%s\n' one two | while read -r line; do echo "$line"; done)
  COMPREPLY=($output)
}
complete -F _read_demo read-demo
"#,
        );
        let words = vec!["read-demo".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn bash_help_option_tokenization_composes_ifs_case_and_regex() {
        let program = script_program(
            ScriptDialect::Bash,
            "help.bash",
            "help-demo",
            r#"split_fields() {
  local IFS=$' \t\n,/|'
  eval "$1=(\$2)"
}
_help_demo() {
  local option='' i
  local -a array
  split_fields array '  -b, --binary read input'
  for i in "${array[@]}"; do
    case "$i" in
      ---*) break ;;
      --?*) option=$i; break ;;
      -?*) [[ $option ]] || option=$i ;;
      *) break ;;
    esac
  done
  [[ $option =~ ^([^=<{().[]|\.[A-Za-z0-9])+=? ]]
  COMPREPLY=("$BASH_REMATCH")
}
complete -F _help_demo help-demo
"#,
        );
        let words = vec!["help-demo".into(), "--".into()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--binary"]
        );
    }

    #[test]
    fn bash_posix_class_extglob_matches_leading_help_indentation() {
        let program = script_program(
            ScriptDialect::Bash,
            "help-indent.bash",
            "help-indent",
            "_help_indent() { if [[ ' -0, --null Use \\0' == *([[:blank:]])-* ]]; then COMPREPLY=(matched); fi; }\ncomplete -F _help_indent help-indent\n",
        );
        let words = vec!["help-indent".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn bash_eval_does_not_brace_expand_text_from_a_parameter() {
        let program = script_program(
            ScriptDialect::Bash,
            "eval-braces.bash",
            "eval-braces",
            r#"_eval_braces() {
  local IFS=$'\n' text='--radix={o,d,x}'
  eval 'COMPREPLY=($text)'
}
complete -F _eval_braces eval-braces
"#,
        );
        let words = vec!["eval-braces".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "--radix={o,d,x}");
    }

    #[test]
    fn bash_eval_applies_multiple_shell_escaped_assignments() {
        let program = script_program(
            ScriptDialect::Bash,
            "eval-assignments.bash",
            "eval-assignments",
            r#"_eval_assignments() {
  local saved
  printf -v saved '%s=%q ' first one second 'two words' third three
  eval -- "$saved"
  COMPREPLY=("$first" "$second" "$third")
}
complete -F _eval_assignments eval-assignments
"#,
        );
        let words = vec!["eval-assignments".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two words", "three"]
        );
    }

    #[test]
    fn bash_compgen_wordlist_expands_array_prefix_removal() {
        let program = script_program(
            ScriptDialect::Bash,
            "array-prefix.bash",
            "array-prefix",
            r#"_array_prefix() {
  local -a paths=(/dev/tty0 /dev/tty1)
  COMPREPLY=( $(compgen -W '"${paths[@]}" "${paths[@]#/dev/}"' -- '') )
}
complete -F _array_prefix array-prefix
"#,
        );
        let words = vec!["array-prefix".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["/dev/tty0", "/dev/tty1", "tty0", "tty1"]
        );
    }

    #[test]
    fn bash_eval_array_respects_custom_ifs_and_keeps_the_first_option() {
        let program = script_program(
            ScriptDialect::Bash,
            "usage-split.bash",
            "usage-split",
            r#"_usage_split() {
  local IFS=$' \t\n,/|' array option i text='-a|-A|-d'
  eval "array=($text)"
  for i in "${array[@]}"; do
    case "$i" in -?*) [[ $option ]] || option=$i ;; esac
  done
  COMPREPLY=("${array[@]}" "$option")
}
complete -F _usage_split usage-split
"#,
        );
        let words = vec!["usage-split".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["-a", "-A", "-d", "-a"]
        );
    }

    #[test]
    fn bash_case_extglob_matches_bundled_usage_options() {
        let program = script_program(
            ScriptDialect::Bash,
            "usage-extglob.bash",
            "usage-extglob",
            "_usage_extglob() { case -LP in -?(\\[)+([a-zA-Z0-9?])) COMPREPLY=(matched) ;; esac; }\ncomplete -F _usage_extglob usage-extglob\n",
        );
        let words = vec!["usage-extglob".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn bash_compound_or_accepts_an_empty_negated_operand() {
        let program = script_program(
            ScriptDialect::Bash,
            "compound-or.bash",
            "compound-or",
            "_compound_or() { local cur=; if [[ ! $cur || $cur != -* ]]; then COMPREPLY=(matched); fi; }\ncomplete -F _compound_or compound-or\n",
        );
        let words = vec!["compound-or".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn bounded_awk_filters_records_before_printing_fields() {
        let program = script_program(
            ScriptDialect::Bash,
            "awk-filter.bash",
            "awk-filter",
            r#"_awk_filter() {
  COMPREPLY=( $(printf '%s\n' 'header text' '  first details' $'\tsecond details' |
    awk '/^[ \t]/ { print $1 }') )
}
complete -F _awk_filter awk-filter
"#,
        );
        let words = vec!["awk-filter".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn bounded_sed_supports_address_ranges_and_negation() {
        let program = script_program(
            ScriptDialect::Bash,
            "sed-range.bash",
            "sed-range",
            r#"_sed_range() {
  COMPREPLY=( $(printf '%s\n' before 'VALUES := {' alpha beta '}' after |
    sed -e '/VALUES := {/,/}/!d' -e 's/.*{//' -e 's/}.*//' ) )
}
complete -F _sed_range sed-range
"#,
        );
        let words = vec!["sed-range".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn bounded_sed_treats_escaped_bre_punctuation_as_literals() {
        let program = script_program(
            ScriptDialect::Bash,
            "sed-punctuation.bash",
            "sed-punctuation",
            r#"_sed_punctuation() {
  COMPREPLY=( $(printf '%s\n' '[!] --protocol' ' --jump' | sed -e 's/^\[\!\]//') )
}
complete -F _sed_punctuation sed-punctuation
"#,
        );
        let words = vec!["sed-punctuation".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--protocol", "--jump"]
        );
    }

    #[test]
    fn bounded_sed_supports_bre_captures_filters_and_print_flags() {
        let program = script_program(
            ScriptDialect::Bash,
            "sed.bash",
            "sed-demo",
            r#"_sed_demo() {
  COMPREPLY=( $(printf '%s\n' 'skip this' '  item alpha extra' '  item beta extra' |
    sed -ne '/item/!d;s/^ *item  *\([^ ]*\).*/\1/p') )
}
complete -F _sed_demo sed-demo
"#,
        );
        let words = vec!["sed-demo".into(), String::new()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn bash_help_argument_placeholders_are_removed_before_long_options() {
        let expression = crate::rules::script_vm::normalize_bash_ere(
            r"((^|[^-])-[A-Za-z0-9?][[:space:]]+)(\[,?)?[A-Z0-9+]+([,_-]+[A-Z0-9]+)?(\.\.+)?\]*",
        );
        assert!(
            regex::Regex::new(&expression)
                .unwrap()
                .is_match("  -C DIRECTORY, --directory=DIRECTORY")
        );
        let program = script_program(
            ScriptDialect::Bash,
            "placeholder.bash",
            "placeholder",
            r#"_placeholder() {
  local line='  -C DIRECTORY, --directory=DIRECTORY'
  while [[ $line =~ ((^|[^-])-[A-Za-z0-9?][[:space:]]+)(\[,?)?[A-Z0-9+]+([,_-]+[A-Z0-9]+)?(\.\.+)?\]* ]]; do
    line=${line/"${BASH_REMATCH[0]}"/"${BASH_REMATCH[1]}"}
  done
  COMPREPLY=("$line")
}
complete -F _placeholder placeholder
"#,
        );
        let words = vec!["placeholder".into(), String::new()];
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
        assert_eq!(
            result.candidates[0].candidate.value,
            "  -C , --directory=DIRECTORY"
        );
    }

    #[test]
    fn bash_getopts_shift_and_eval_write_arrays_in_the_caller_scope() {
        let program = script_program(
            ScriptDialect::Bash,
            "split.bash",
            "split-demo",
            r#"split_lines() {
  local IFS=$' \t\n' OPTIND=1 OPTARG='' option
  while getopts ':l' option "$@"; do
    case $option in l) IFS=$'\n' ;; esac
  done
  shift "$((OPTIND - 1))"
  eval "$1=(\$2)"
}
_split_demo() {
  local text=$'--one\n--two'
  local -a values
  split_lines -l values "$text"
  COMPREPLY=("${values[@]}")
}
complete -F _split_demo split-demo
"#,
        );
        let words = vec!["split-demo".into(), "--".into()];
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
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--one", "--two"]
        );
    }

    #[test]
    fn fish_set_flags_are_parsed_only_before_the_variable_and_erase_all_references() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "function helper\n  set -l output first second\n  set -e output[1] output[1]\n  count $output\nend\ncomplete -c demo -a '(helper)'\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "0");
    }

    #[test]
    fn fish_array_range_erasure_preserves_forwarded_completion_arguments() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "function helper -a value shortcut\n  set -e argv[1..2]\n  complete -c demo -a $value $argv\nend\nfunction direct\n  complete -c demo -a $argv[1] $argv[2..-1]\nend\nfunction generated\n  echo generated\nend\nhelper command alias -d Description\ndirect second -d 'Second description'\ndirect third -a '(generated)' -d 'Forwarded description'\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let values = result
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            [
                ("command", Some("Description")),
                ("generated", Some("Forwarded description")),
                ("second", Some("Second description")),
                ("third", Some("Forwarded description"))
            ]
        );
    }

    #[test]
    fn fish_switch_treats_quoted_stars_as_patterns() {
        let program = script_program(
            ScriptDialect::Fish,
            "switch.fish",
            "switch-demo",
            "function generated\n  switch ''\n    case '*'\n      echo matched\n  end\nend\ncomplete -c switch-demo -a '(generated)'\n",
        );
        let words = vec!["switch-demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn fish_completion_tabs_and_double_quoted_backslashes_are_preserved() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            r#"function generated
  echo hidden >/dev/null
  echo -en "one\tFirst generated\ntwo\tSecond generated\n"
  printf "%s\tPrintf generated\n" three four
  printf "same\n" | string replace -rf '^([^-].*)' '$1'
  printf "pipeline-item Pipeline description\n" | string replace -r '\\s+' '\\t'
  printf "0\tBlack\n" | awk -F '\\t' '{ printf "--%s\\t%s\\n", $1, $2 }'
end
set -l items array-one array-two
complete -c demo -a 'bash\t"Compile to Bash"'
complete -c demo -a list -d "package\(s\)"
complete -c demo -a 'mode={one,two}'
complete -c demo -a "$items"
complete -c demo -a '(generated)'
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref()
                ))
                .collect::<Vec<_>>(),
            [
                ("array-one", None),
                ("array-two", None),
                ("bash", Some("Compile to Bash")),
                ("four", Some("Printf generated")),
                ("list", Some("package\\(s\\)")),
                ("mode=one", None),
                ("mode=two", None),
                ("one", Some("First generated")),
                ("pipeline-item", Some("Pipeline description")),
                ("same", None),
                ("three", Some("Printf generated")),
                ("two", Some("Second generated")),
                ("--0", Some("Black"))
            ]
        );
    }

    #[test]
    fn fish_nested_completion_requests_are_pure_data_and_replayable() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "function nested\n  complete -C ''\nend\ncomplete -c demo -a '(nested)'\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let initial = evaluate(
            &program,
            &context,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(initial.candidates.is_empty());
        assert_eq!(initial.completion_requests[0].line, "");

        let completion_results = HashMap::from([(
            String::new(),
            vec![
                "nested-value\tNested description".into(),
                nested_completion_path_marker(PathCompletion::Directories).unwrap(),
            ],
        )]);
        let replayed = evaluate_with_results(
            &program,
            &context,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &completion_results,
        )
        .unwrap();
        assert_eq!(replayed.candidates[0].candidate.value, "nested-value");
        assert_eq!(
            replayed.candidates[0].candidate.description.as_deref(),
            Some("Nested description")
        );
        assert_eq!(replayed.path_completion, PathCompletion::Directories);
    }

    #[test]
    fn fish_set_uses_command_substitution_status_in_conditions() {
        let program = script_program(
            ScriptDialect::Fish,
            "substitution-status.fish",
            "substitution-status",
            "function empty_failure\n  false\nend\nfunction guarded\n  if set -l values (empty_failure)\n    echo wrong\n  end\nend\ncomplete -c substitution-status -a '(guarded)'\n",
        );
        let words = vec!["substitution-status".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty(), "{:?}", result.candidates);
    }

    #[test]
    fn fish_shell_snapshot_names_and_values_are_available_without_hot_path_discovery() {
        let program = script_program(
            ScriptDialect::Fish,
            "snapshot.fish",
            "snapshot",
            "complete -c snapshot -a '(functions --names; set --names; set -g | string replace \" \" \\t)'\n",
        );
        let words = vec!["snapshot".into(), String::new()];
        let environment = HashMap::new();
        let functions = vec!["alpha_function".into(), "beta_function".into()];
        let variables = vec!["ALPHA_VARIABLE".into(), "BETA_VARIABLE".into()];
        let variable_values = HashMap::from([
            ("ALPHA_VARIABLE".into(), vec!["alpha-value".into()]),
            ("BETA_VARIABLE".into(), vec!["beta-value".into()]),
        ]);
        let mut ctx = context(&words, &environment);
        ctx.shell_functions = Some(&functions);
        ctx.shell_variables = Some(&variables);
        ctx.shell_variable_values = Some(&variable_values);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let values = result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.value.as_str())
            .collect::<Vec<_>>();
        assert!(values.contains(&"alpha_function"), "{values:?}");
        assert!(values.contains(&"beta_function"));
        assert!(values.contains(&"ALPHA_VARIABLE"));
        assert!(values.contains(&"BETA_VARIABLE"));
        assert!(result.candidates.iter().any(|candidate| {
            candidate.candidate.value == "ALPHA_VARIABLE"
                && candidate.candidate.description.as_deref() == Some("alpha-value")
        }));
    }

    #[test]
    fn fish_exported_variable_snapshot_filters_local_variables() {
        let program = script_program(
            ScriptDialect::Fish,
            "exports.fish",
            "exports",
            "complete -c exports -a '(set --names -x)'\n",
        );
        let words = vec!["exports".into(), String::new()];
        let environment = HashMap::from([("EXPORTED".into(), "value".into())]);
        let variable_values = HashMap::from([
            ("EXPORTED".into(), vec!["snapshot-value".into()]),
            ("LOCAL".into(), vec!["local-value".into()]),
        ]);
        let variables = vec!["EXPORTED".into(), "LOCAL".into()];
        let mut ctx = context(&words, &environment);
        ctx.shell_variables = Some(&variables);
        ctx.shell_variable_values = Some(&variable_values);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["EXPORTED"]
        );
    }

    #[test]
    fn cumulative_output_and_candidate_bytes_are_vm_bounded() {
        let payload = "x".repeat(64 * 1024);
        let source = format!(
            "_output() {{ local i; for ((i=0; i<32; i++)); do printf '%s' '{payload}'; done; }}\ncomplete -F _output output\n"
        );
        let program = script_program(ScriptDialect::Bash, "output.bash", "output", &source);
        let words = vec!["output".into(), String::new()];
        let environment = HashMap::new();
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Bash,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("shell command output"))
        ));

        let source = format!(
            "_discard() {{ local i value; for ((i=0; i<256; i++)); do value=$(printf '%s' '{payload}'); done; }}\ncomplete -F _discard discard\n"
        );
        let program = script_program(ScriptDialect::Bash, "discard.bash", "discard", &source);
        let words = vec!["discard".into(), String::new()];
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Bash,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("shell command output work"))
        ));

        let source = format!(
            "_candidate() {{ COMPREPLY=('{payload}overflow'); }}\ncomplete -F _candidate candidate\n"
        );
        let program = script_program(ScriptDialect::Bash, "candidate.bash", "candidate", &source);
        let words = vec!["candidate".into(), String::new()];
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Bash,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("candidate bytes"))
        ));

        let large_values = (0..15)
            .map(|index| format!("{}-{index}", "v".repeat(60 * 1024)))
            .collect::<Vec<_>>();
        let reply = large_values
            .iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let first_source =
            format!("_many_one() {{ COMPREPLY=({reply}); }}\ncomplete -F _many_one many\n");
        let mut program =
            script_program(ScriptDialect::Bash, "many-one.bash", "many", &first_source);
        for index in 2..=5 {
            let function = format!("_many_{index}");
            let source =
                format!("{function}() {{ COMPREPLY=({reply}); }}\ncomplete -F {function} many\n");
            let source_path = format!("many-{index}.bash");
            let mut additional = script_program(ScriptDialect::Bash, &source_path, "many", &source);
            program.scripts.push(additional.scripts.remove(0));
        }
        let words = vec!["many".into(), String::new()];
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Bash,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("candidate bytes"))
        ));
    }

    #[test]
    fn oversized_external_context_is_rejected_before_script_evaluation() {
        let program = script_program(
            ScriptDialect::Bash,
            "large.bash",
            "large",
            "_large() { [[ $cur =~ .* ]]; }\ncomplete -F _large large\n",
        );
        let oversized = "x".repeat(1024 * 1024 + 1);
        let words = vec!["large".into(), oversized.clone()];
        let environment = HashMap::new();
        let mut ctx = context(&words, &environment);
        ctx.current_word = &oversized;
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        );
        assert!(matches!(result, Err(VmError::Limit("evaluation context"))));
    }

    #[test]
    fn process_network_signal_and_command_snapshots_are_explicit_vm_inputs() {
        let bash = script_program(
            ScriptDialect::Bash,
            "process.bash",
            "process",
            "_process() { COMPREPLY=( $(_pids) ); }\ncomplete -F _process process\n",
        );
        let words = vec!["process".into(), String::new()];
        let environment = HashMap::new();
        let process_ids = vec!["17".into(), "42".into()];
        let process_names = vec!["alpha".into(), "beta".into()];
        let mut ctx = context(&words, &environment);
        ctx.process_ids = Some(&process_ids);
        ctx.process_names = Some(&process_names);
        let result = evaluate(
            &bash,
            &ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["17", "42"]
        );
        assert_eq!(result.snapshot_providers, ["process"]);

        let zsh = script_program(
            ScriptDialect::Zsh,
            "_network",
            "network",
            "#compdef network\n_network() { _net_interfaces; }\n",
        );
        let interfaces = vec!["eth-test".into(), "loop-test".into()];
        let network_words = vec!["network".into(), String::new()];
        let mut network_ctx = context(&network_words, &environment);
        network_ctx.network_interfaces = Some(&interfaces);
        let result = evaluate(
            &zsh,
            &network_ctx,
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["eth-test", "loop-test"],
            "{result:?}"
        );
        assert_eq!(result.snapshot_providers, ["network"]);

        let signals = vec!["SNAPSHOT_SIGNAL".into()];
        let signal_words = vec!["signal".into(), String::new()];
        let mut signal_ctx = context(&signal_words, &environment);
        signal_ctx.signals = Some(&signals);
        let signal_program = script_program(
            ScriptDialect::Bash,
            "signal.bash",
            "signal",
            "_signal() { compgen -A signal -V COMPREPLY; }\ncomplete -F _signal signal\n",
        );
        let result = evaluate(
            &signal_program,
            &signal_ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "SNAPSHOT_SIGNAL");
        assert_eq!(result.snapshot_providers, ["signal"]);

        let command_words = vec!["commands".into(), String::new()];
        let shell_commands = vec!["first-command".into(), "second-command".into()];
        let mut command_ctx = context(&command_words, &environment);
        command_ctx.shell_commands = Some(&shell_commands);
        let command_program = script_program(
            ScriptDialect::Bash,
            "commands.bash",
            "commands",
            "_commands() { compgen -A command -V COMPREPLY; }\ncomplete -F _commands commands\n",
        );
        let result = evaluate(
            &command_program,
            &command_ctx,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first-command", "second-command"]
        );
        assert_eq!(result.snapshot_providers, ["command"]);
    }

    #[test]
    fn fish_account_records_preserve_completion_descriptions() {
        let program = script_program(
            ScriptDialect::Fish,
            "accounts.fish",
            "accounts",
            "function listed_groups\n  getent group | while read -l line\n    string split -f 1,4 : -- $line | string join \\t\n  end\nend\ncomplete -c accounts -a '(listed_groups)'\n",
        );
        let words = vec!["accounts".into(), String::new()];
        let environment = HashMap::new();
        let groups = vec!["network".into(), "wheel".into()];
        let records = vec!["network:x:10:alice,bob".into(), "wheel:x:20:alice".into()];
        let mut ctx = context(&words, &environment);
        ctx.groups = Some(&groups);
        ctx.group_records = Some(&records);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "network");
        assert_eq!(
            result.candidates[0].candidate.description.as_deref(),
            Some("alice,bob")
        );
        assert_eq!(result.candidates[1].candidate.value, "wheel");
    }

    #[test]
    fn fish_bounded_leading_negative_lookahead_filters_host_records() {
        let program = script_program(
            ScriptDialect::Fish,
            "hosts.fish",
            "hosts",
            r#"complete -c hosts -a "(printf '%s\n' '127.0.0.1 localhost' '10.0.0.1 machine alias' | string replace -irf '^\s*?(?!(?:0\.|127\.|ff0|fe0|::1))\S+\s*(.*?)\s*$' '$1' | string split ' ')"
"#,
        );
        let words = vec!["hosts".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alias", "machine"]
        );
    }

    #[test]
    fn fish_nested_double_quotes_unescape_deferred_capture_references() {
        let program = script_program(
            ScriptDialect::Fish,
            "captures.fish",
            "captures",
            r#"complete -c captures -a "(echo '/dev /mnt rest' | string replace -r ' (\S*) .*' '\tMount point \$1')"
"#,
        );
        let words = vec!["captures".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "/dev");
        assert_eq!(
            result.candidates[0].candidate.description.as_deref(),
            Some("Mount point /mnt")
        );
    }

    #[test]
    fn fish_return_without_argument_uses_failed_and_or_status() {
        let program = script_program(
            ScriptDialect::Fish,
            "return.fish",
            "return-status",
            "function failed_helper\n  false; or return\n  true\nend\ncomplete -c return-status -n failed_helper -a wrong\n",
        );
        let words = vec!["return-status".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty(), "{:?}", result.candidates);
    }

    #[test]
    fn fish_empty_helper_argument_composes_with_failed_early_return() {
        let program = script_program(
            ScriptDialect::Fish,
            "composed.fish",
            "composed",
            "function unavailable\n  false; or return\nend\nfunction seen_empty\n  string match -rq -- '^()$' $argv\nend\nfunction needs_value\n  set -l value \"\"\n  if unavailable\n    set value present\n  end\n  not seen_empty fixed $value\nend\ncomplete -c composed -n needs_value -a wrong\n",
        );
        let words = vec!["composed".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty(), "{:?}", result.candidates);
    }

    #[test]
    fn fish_empty_array_elements_remain_condition_arguments() {
        let program = script_program(
            ScriptDialect::Fish,
            "empty.fish",
            "empty",
            "function matches_empty --argument value\n  string match -rq -- '^$' $value\nend\nfunction rejects_empty\n  set -l value \"\"\n  not matches_empty $value\nend\ncomplete -c empty -n rejects_empty -a wrong\n",
        );
        let words = vec!["empty".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty(), "{:?}", result.candidates);
    }

    #[test]
    fn fish_status_variable_preserves_the_previous_command_status() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "function no_args\n  set -q argv[1]\n  set -l saved $status\n  return $saved\nend\ncomplete -c demo -n 'not no_args' -a matched\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn fish_filesystem_tests_and_globs_use_bounded_replay_requests() {
        let program = script_program(
            ScriptDialect::Fish,
            "interfaces.fish",
            "interfaces",
            "if test -d /virtual/net\ncomplete -c interfaces -a '(path basename /virtual/net/*)'\nend\n",
        );
        let words = vec!["interfaces".into(), String::new()];
        let environment = HashMap::new();
        let ctx = context(&words, &environment);
        let first = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(first.filesystem_requests.len(), 1);
        let mut results = HashMap::from([(
            first.filesystem_requests[0].request_id.clone(),
            vec!["true".into()],
        )]);
        let second = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &results,
        )
        .unwrap();
        assert_eq!(second.filesystem_requests.len(), 1);
        results.insert(
            second.filesystem_requests[0].request_id.clone(),
            vec!["/virtual/net/lo".into(), "/virtual/net/eth0".into()],
        );
        let third = evaluate_with_results(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &results,
        )
        .unwrap();
        assert_eq!(
            third
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["eth0", "lo"]
        );
    }

    #[test]
    fn unix_special_file_tests_are_bounded_replay_requests() {
        let program = script_program(
            ScriptDialect::Fish,
            "block.fish",
            "block",
            "complete -c block -n 'test -b /virtual/block0' -a matched\n",
        );
        let words = vec!["block".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate_with_results(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(result.filesystem_requests.len(), 1);
        assert_eq!(
            result.filesystem_requests[0].operator.as_deref(),
            Some("-b")
        );
    }

    #[test]
    fn fish_wrappers_treat_standard_builtins_as_available() {
        let program = script_program(
            ScriptDialect::Fish,
            "not.fish",
            "!",
            "complete -c ! --wraps not\ncomplete -c not -a nested\n",
        );
        let words = vec!["!".into(), String::new()];
        let environment = HashMap::new();
        let available = HashSet::new();
        let mut ctx = context(&words, &environment);
        ctx.available_commands = Some(&available);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "nested")
        );
    }

    #[test]
    fn fish_builtin_names_are_a_pure_standard_builtin_primitive() {
        let program = script_program(
            ScriptDialect::Fish,
            "builtin.fish",
            "builtin",
            "complete -c builtin -a '(builtin -n)'\n",
        );
        let words = vec!["builtin".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 64);
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "string")
        );
    }

    #[test]
    fn linux_signal_names_are_a_pure_standard_builtin_primitive() {
        let program = script_program(
            ScriptDialect::Fish,
            "trap.fish",
            "trap",
            "complete -c trap -a '(trap -l)' -d Signal\n",
        );
        let words = vec!["trap".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 37);
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "TERM")
        );
    }

    #[test]
    fn fish_bind_named_keys_are_a_pure_standard_builtin_primitive() {
        let program = script_program(
            ScriptDialect::Fish,
            "bind.fish",
            "bind",
            "complete -c bind -k -a '(bind --key-names)'\n",
        );
        let words = vec!["bind".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .take(4)
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["backspace", "comma", "delete", "down"]
        );
    }

    #[test]
    fn fish_combined_string_flags_drive_completion_conditions() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -n 'string match -qr -- \"^-\" (commandline -ct)' -a matched\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "matched");
    }

    #[test]
    fn fish_quick_pass_never_yields_dependency_derived_fallbacks() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "if test -e /virtual/state\n    complete -c demo -l exists\nelse\n    complete -c demo -l missing\nend\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            true,
            true,
        )
        .unwrap();
        assert!(!result.provisional_yielded);
        assert!(result.provisional_candidates.is_empty());
        assert_eq!(result.filesystem_requests.len(), 1);
    }

    #[test]
    fn fish_quick_pass_does_not_cross_skipped_argument_side_effects() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "set -g gate yes\ncomplete -c demo -l other -a '(set -g gate no; echo unrelated)'\ncomplete -c demo -n 'test $gate = yes' -l version\n",
        );
        let words = vec!["demo".into(), "--ver".into()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            true,
            true,
        )
        .unwrap();
        assert!(!result.provisional_yielded);
        assert!(result.provisional_candidates.is_empty());
        assert!(result.optimization_incomplete);
    }

    #[test]
    fn fish_quick_pass_yields_only_after_prior_dependencies_are_replayed() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "test -e /virtual/state\ncomplete -c demo -l ready\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let mut completion_results = HashMap::new();
        completion_results.insert(
            "filesystem:fish:test:-e:/virtual/state".into(),
            vec!["true".into()],
        );
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &completion_results,
            true,
            true,
        )
        .unwrap();
        assert!(result.provisional_yielded);
        assert_eq!(
            result
                .provisional_candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--ready"]
        );
    }

    #[test]
    fn fish_quick_pass_does_not_publish_candidates_erased_after_a_dependency() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -l removed\ntest -e /virtual/state\ncomplete -c demo -e -l removed\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            true,
            true,
        )
        .unwrap();
        assert!(!result.provisional_yielded);
        assert!(result.provisional_candidates.is_empty());
    }

    #[test]
    fn fish_quick_pass_recognizes_combined_erase_flags() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -l removed\ntest -e /virtual/state\ncomplete -ec demo -l removed\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            true,
            true,
        )
        .unwrap();
        assert!(!result.provisional_yielded);
        assert!(result.provisional_candidates.is_empty());
    }

    #[test]
    fn fish_erase_removes_argument_candidates_and_path_policy() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -l color -r -f -a 'red blue'\ncomplete -ec demo -l color\n",
        );
        let words = vec!["demo".into(), "--color=".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.path_completion, PathCompletion::Inherit);
    }

    #[test]
    fn fish_erase_applies_across_ordered_script_modules() {
        let mut program = script_program(
            ScriptDialect::Fish,
            "first.fish",
            "demo",
            "complete -c demo -l old -f\n",
        );
        program.scripts.push(
            crate::rules::script_parser::parse_script(
                ScriptDialect::Fish,
                "second.fish",
                "complete -ec demo\n",
            )
            .unwrap(),
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.path_completion, PathCompletion::Inherit);
    }

    #[test]
    fn fish_dynamic_combined_flags_are_normalized_before_erase() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -l old\nset flags -ec demo\ncomplete $flags -l old\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn fish_pack_defined_functions_are_available_wrapper_services() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "wrapper",
            "function target\nend\ncomplete -c wrapper -w target\ncomplete -c target -l provided\n",
        );
        let words = vec!["wrapper".into(), "--".into()];
        let environment = HashMap::new();
        let mut evaluation_context = context(&words, &environment);
        let available = HashSet::from(["wrapper".to_owned()]);
        evaluation_context.available_commands = Some(&available);
        let result = evaluate(
            &program,
            &evaluation_context,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--provided")
        );
    }

    #[test]
    fn fish_dynamic_option_selectors_are_not_skipped_by_the_fast_matcher() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "set opts -l target\ncomplete -c demo -l other $opts\n",
        );
        let words = vec!["demo".into(), "--tar".into()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            false,
            true,
        )
        .unwrap();
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--target")
        );
    }

    #[test]
    fn fish_selective_erase_restores_an_older_duplicate_contribution() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -a shared\ncomplete -c demo -l mode -r -a shared\ncomplete -c demo -e -l mode\n",
        );
        let words = vec!["demo".into(), "shared".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .filter(|candidate| candidate.candidate.value == "shared")
                .count(),
            1
        );
    }

    #[test]
    fn fish_erase_and_wrappers_compose_across_command_programs() {
        let first = script_program(
            ScriptDialect::Fish,
            "first.fish",
            "wrapper",
            "function target\nend\ncomplete -c wrapper -w target\ncomplete -c target -l old\ncomplete -c target -f\n",
        );
        let second = script_program(
            ScriptDialect::Fish,
            "second.fish",
            "wrapper",
            "complete -ec target\ncomplete -c target -l new\n",
        );
        let words = vec!["wrapper".into(), "--".into()];
        let environment = HashMap::new();
        let available = HashSet::from(["wrapper".to_owned()]);
        let mut evaluation_context = context(&words, &environment);
        evaluation_context.available_commands = Some(&available);
        let result = evaluate_runtime_programs_with_outcomes(
            &[
                (&first, TrustStatus::Unsigned),
                (&second, TrustStatus::Unsigned),
            ],
            &evaluation_context,
            SourceKind::Fish,
            EvaluationMode::Passive,
            128,
            &HashMap::new(),
            &HashMap::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--new")
        );
        assert!(
            !result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--old")
        );
        assert_eq!(result.path_completion, PathCompletion::Inherit);
    }

    #[test]
    fn runtime_fish_condition_memoization_rejects_stateful_predicates() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            r#"
function flip
    if set -q hit
        return 1
    end
    set -g hit yes
    return 0
end
complete -c demo -n flip -a first
complete -c demo -n flip -a second
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate_runtime_with_outcomes(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first"]
        );
    }

    #[test]
    fn fish_keep_order_reverses_registration_groups_but_not_each_group() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "complete -c demo -k -a 'first-a first-b'\ncomplete -c demo -k -a 'second-a second-b'\ncomplete -c demo -k -a shared -d first\ncomplete -c demo -k -a shared -d second\ncomplete -c demo -s h -d removed\ncomplete -c demo -s h -e\ncomplete -c demo -a '*.txt'\n",
        );
        let words = vec!["demo".into(), "-".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["shared", "second-a", "second-b", "first-a", "first-b"]
        );
        assert_eq!(
            result.candidates[0].candidate.description.as_deref(),
            Some("second")
        );
    }

    #[test]
    fn fish_semicolon_and_conditions_preserve_failed_helper_status() {
        let program = script_program(
            ScriptDialect::Fish,
            "conditions.fish",
            "demo",
            r#"function seen
    set -l regex (string escape --style=regex -- (commandline -pxc)[2..] | string join '|')
    string match -rq -- "^($regex)\$" $argv
end
set -l commands "start stop check"
complete -c demo -n "not seen $commands" -a "$commands"
complete -c demo -n "seen $commands; and not seen (echo interface)" -a interface
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["check", "start", "stop"]
        );
    }

    #[test]
    fn fish_exclusive_options_require_a_separate_parameter_and_suppress_files() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            "set -l suffix \"\"\ncomplete -c demo -x -l list -a 'one two'\ncomplete -c demo -f -l quiet\ncomplete -c demo -l dynamic -a '(false)'\ncomplete -c demo -s -x\ncomplete -c demo -lformat$suffix\n",
        );
        let environment = HashMap::new();
        let option_words = vec!["demo".into(), "--".into()];
        let option_result = evaluate(
            &program,
            &context(&option_words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let option = option_result
            .candidates
            .iter()
            .find(|candidate| candidate.candidate.value == "--list")
            .unwrap();
        assert_eq!(option.candidate.append, AppendPolicy::Space);
        assert!(
            option_result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--dynamic=")
        );
        assert!(
            option_result
                .candidates
                .iter()
                .all(|candidate| candidate.candidate.value != "--x")
        );
        assert!(
            option_result
                .candidates
                .iter()
                .any(|candidate| candidate.candidate.value == "--format")
        );
        assert_eq!(option_result.path_completion, PathCompletion::Inherit);

        let parameter_words = vec!["demo".into(), "--list".into(), String::new()];
        let parameter_result = evaluate(
            &program,
            &context(&parameter_words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(parameter_result.path_completion, PathCompletion::Suppress);
    }

    #[test]
    fn zsh_function_local_getopts_arithmetic_loops_and_split_flags_compose() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
_demo() {
  generate() {
    local opt OPTARG
    while getopts 'x:' opt; do :; done
    shift $((OPTIND - 1))
    local -a fields
    integer i
    for (( i = 1; i <= $#; i++ )); do
      fields=(${(s.:.)argv[i]})
      reply+=("${fields[1]}")
    done
  }
  local -a reply
  generate alpha:first beta:second
  compadd -- "${reply[@]}"
}
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn zsh_eval_generated_functions_use_build_time_compiled_ir() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_dynamic_demo",
            "dynamic-demo",
            r#"#compdef dynamic-demo
define() {
  local name=_generated captured='one two'
  eval "$name () { local values=($captured); compadd -- \"\${values[@]}\"; }"
}
define
_generated
"#,
        );
        let words = vec!["dynamic-demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn zsh_argument_actions_expand_nested_brace_candidates() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
_arguments '*:parameter:compadd -r "\\n\\t\\- =" - persist allow.{set_hostname,sysvipc,raw_sockets,chflags,mount{,.devfs,.fdescfs,.fusefs,.nullfs,.procfs,.linprocfs,.linsysfs,.tmpfs,.zfs},vmm,quotas,read_msgbuf,socket_af,mlock,nfsd,reserved_ports,unprivileged_{parent_tampering,proc_debug},suser,extattr,adjtime,settime,routing,setaudit}'
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            [
                "persist",
                "allow.set_hostname",
                "allow.sysvipc",
                "allow.raw_sockets",
                "allow.chflags",
                "allow.mount",
                "allow.mount.devfs",
                "allow.mount.fdescfs",
                "allow.mount.fusefs",
                "allow.mount.nullfs",
                "allow.mount.procfs",
                "allow.mount.linprocfs",
                "allow.mount.linsysfs",
                "allow.mount.tmpfs",
                "allow.mount.zfs",
                "allow.vmm",
                "allow.quotas",
                "allow.read_msgbuf",
                "allow.socket_af",
                "allow.mlock",
                "allow.nfsd",
                "allow.reserved_ports",
                "allow.unprivileged_parent_tampering",
                "allow.unprivileged_proc_debug",
                "allow.suser",
                "allow.extattr",
                "allow.adjtime",
                "allow.settime",
                "allow.routing",
                "allow.setaudit",
            ]
        );
    }

    #[test]
    fn zsh_values_group_plain_items_before_actions_and_apply_literal_suffixes() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
compadd -S '/' -r '-=' ''
_values -w -s ' ' -S ' ' filter \
  '*state[state]' '*dport[peer port]: :(lt gt)' '*sport[local]'
compadd -n -S '' con
_values -C -w option \
  'mem[memory]:amount' 'debug[debug]' '*con[console]:channel:->channel'
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref(),
                    candidate.candidate.append,
                ))
                .collect::<Vec<_>>(),
            [
                ("/", None, AppendPolicy::Space),
                ("state ", Some("state"), AppendPolicy::Space),
                ("sport ", Some("local"), AppendPolicy::Space),
                ("dport ", Some("peer port"), AppendPolicy::Space),
                ("con", Some("console"), AppendPolicy::NoSpace),
                ("debug", Some("debug"), AppendPolicy::Space),
                ("mem=", Some("memory"), AppendPolicy::NoSpace),
                ("con=", Some("console"), AppendPolicy::NoSpace),
            ]
        );
    }

    #[test]
    fn zsh_quoted_compadd_prefix_uses_shell_escaped_literal_suffix() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local open='('
open=${(q)open}
compadd -P '"(' -S ${(Q)open} -- '|' '&'
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            [r"|\(", r"&\("]
        );
    }

    #[test]
    fn zsh_function_prelude_does_not_emit_completion_candidates() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "alias-demo",
            "#compdef alias-demo=demo\nlocal -a args=( '--raw:value:' )\n[[ $service = demo ]] && args+=( '--described[described]' )\n_arguments $args\n",
        );
        let words = vec!["alias-demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--described", "--raw"]
        );
    }

    #[test]
    fn zsh_indirect_parameter_applies_subscript_before_dereference() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\nlocal -a parts=( users roles ) users=( -qS : ) roles=( -qS / )\ncompadd ${(P)parts[1]} -- value\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "value:");
    }

    #[test]
    fn zsh_empty_provider_output_activates_static_array_fallback() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
_demo_users() {
  local -a values displays
  values=( ${(f)"$(_call_program users missing-tool --list)"} )
  (( $#values )) || values=( guest_u root user_u )
  displays=( ${(Q)values} )
  compadd -S: -d displays -a values
}
_demo_users
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["guest_u:", "root:", "user_u:"]
        );
    }

    #[test]
    fn zsh_argument_actions_keep_colons_inside_matcher_quotes() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_usbconfig",
            "usbconfig",
            r#"#compdef usbconfig
_arguments '1:command:compadd -M "r:|_=* r:|=*"
  set_config set_alt'
"#,
        );
        let words = vec!["usbconfig".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["set_config", "set_alt"]
        );
    }

    #[test]
    fn zsh_regex_first_sets_follow_nullable_groups_in_source_order() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
_regex_arguments _generated '/[^\0]#\0/' '(' '/a[ \0]/' ':first:first:(a b)' '|' '(' '//' ')' '#' '/c[ \0]/' ':second:second:(c)' ')'
_generated
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn zsh_user_at_host_respects_literal_suffix_and_combination_snapshot_absence() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_sshfs",
            "sshfs",
            "#compdef sshfs\n_arguments '1:remote:_user_at_host -S:'\n_combination users\n",
        );
        let words = vec!["sshfs".into(), String::new()];
        let environment = HashMap::new();
        let users = vec!["root".into(), "alice".into()];
        let mut snapshot = context(&words, &environment);
        snapshot.users = Some(&users);
        let result = evaluate(
            &program,
            &snapshot,
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.kind,
                    candidate.candidate.append,
                ))
                .collect::<Vec<_>>(),
            [
                ("root:", RuleCandidateKind::Subcommand, AppendPolicy::Space),
                ("alice:", RuleCandidateKind::Subcommand, AppendPolicy::Space),
            ]
        );
    }

    #[test]
    fn zsh_parameter_default_assignment_updates_completion_prefix() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\n: ${PREFIX:=-}\ncompadd -- --one value\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--one"]
        );
    }

    #[test]
    fn zsh_indexed_array_append_exposes_implied_service_options() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_zstd",
            "unzstd",
            "#compdef unzstd\nlocal -a implied\ncase $service in unzstd) implied=( -d );; esac\nwords[1]+=( $implied )\nif (( $words[(I)(-d|--decompress)] )); then compadd -- --decompress-mode; else compadd -- --compress-mode; fi\n",
        );
        let words = vec!["unzstd".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "--decompress-mode");
    }

    #[test]
    fn zsh_unquoted_path_glob_can_annihilate_a_completion_specification() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_rake",
            "rake",
            "#compdef rake\n_arguments '(--system -g)'{--system,-g}'[use '~/.rake/*.rake']' '--tasks[tasks]'\n",
        );
        let words = vec!["rake".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--tasks"]
        );
        assert_eq!(result.filesystem_requests.len(), 2);
    }

    #[test]
    fn zsh_active_option_set_suppresses_implied_mode_options() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_zstd",
            "unzstd",
            "#compdef unzstd\nlocal -a implied=( -d )\nwords[1]+=( $implied )\n(( CURRENT += $#implied ))\n_arguments '--common[common]' + '(M)' '(-B)'{-d,--decompress}'[decompress]' '(-B)'{-l,--list}'[list]'\n",
        );
        let words = vec!["unzstd".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--common"]
        );
    }

    #[test]
    fn zsh_arguments_group_described_plain_and_equals_options_globally() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\nlocal -a args=( '--first[first]' '--key=[key]:value:' '--raw:value:' '--second[second]' )\n_arguments $args\n",
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--first", "--second", "--raw", "--key="]
        );
    }

    #[test]
    fn zsh_arguments_literal_plus_precedes_repeatable_options() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\n_arguments - list '+[list values]' - others '-a[plain]' '-o+[repeatable]'\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["-a", "+", "-o"]
        );
    }

    #[test]
    fn zsh_arguments_literal_plus_consumes_its_argument() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\n_arguments '+[mode]:mode:(one two)' '*:file:_files'\n",
        );
        let words = vec!["demo".into(), "+".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(result.path_completion, PathCompletion::Inherit);
    }

    #[test]
    fn zsh_negated_prefix_condition_selects_non_option_completion() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_configure",
            "configure",
            "#compdef configure\nif [[ ! -prefix - ]]; then compadd -S = -- CC CFLAGS; fi\n",
        );
        let words = vec!["configure".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["CC=", "CFLAGS="]
        );
    }

    #[test]
    fn zsh_force_split_parameter_expansion_uses_shell_fields() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\nlocal -a values=( 'one two' )\ncompadd -- $=values\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn zsh_bare_arguments_delimiter_does_not_mask_a_failed_fallback() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_curl",
            "curl",
            "#compdef curl\n_arguments '*:arg:_missing' -- || _urls\n",
        );
        let words = vec!["curl".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["file:", "ftp://", "gopher://", "http://", "https://"]
        );
    }

    #[test]
    fn zsh_urls_builtin_emits_stable_scheme_prefixes() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_curl",
            "curl",
            "#compdef curl\n_urls\n",
        );
        let words = vec!["curl".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["file:", "ftp://", "gopher://", "http://", "https://"]
        );
    }

    #[test]
    fn zsh_file_modes_builtin_emits_symbolic_mode_prefixes() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_chmod",
            "chmod",
            "#compdef chmod\n_arguments '1:mode:_file_modes'\n",
        );
        let words = vec!["chmod".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["a", "u", "g", "o", "+", "-", "="]
        );
        assert!(
            result
                .candidates
                .iter()
                .all(|candidate| candidate.candidate.append == AppendPolicy::NoSpace)
        );
    }

    #[test]
    fn zsh_describe_scalar_lists_split_only_unescaped_whitespace() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
_describe items item '( "quoted:two words" plain:escaped\ words )'
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref(),
                ))
                .collect::<Vec<_>>(),
            [
                ("\"quoted", Some("two")),
                ("plain", Some("escaped words")),
                ("words\"", None),
            ]
        );
    }

    #[test]
    fn zsh_print_v_formats_each_target_array_element() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local -a pairs=( one 'first value' two 'second value' ) specifications
print -v specifications -f '%s\\:%s' ${(q)pairs}
_arguments "1:item:(($specifications))"
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref(),
                ))
                .collect::<Vec<_>>(),
            [("one", Some("first value")), ("two", Some("second value")),]
        );
    }

    #[test]
    fn zsh_quoted_preserved_empty_arrays_expand_to_zero_fields() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_empty_array",
            "empty-array",
            r#"#compdef empty-array
local -A missing
local item ret=1
for item in "${(@)missing[(K)value]}"; do
  ret=0
done
return ret
"#,
        );
        let words = vec!["empty-array".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.completion_status, Some(1));
    }

    #[test]
    fn zsh_function_keys_include_names_only_fpath_metadata() {
        let mut program = script_program(
            ScriptDialect::Zsh,
            "_function_keys",
            "function-keys",
            "#compdef function-keys\ncompadd -- ${(k)functions}\n",
        );
        program.scripts[0].zsh_function_names = vec!["_hidden".into(), "_another".into()];
        program.scripts[0].zsh_function_table_size = 7;
        let words = vec!["function-keys".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let values = result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.value.as_str())
            .collect::<HashSet<_>>();
        assert!(values.contains("_hidden"));
        assert!(values.contains("_another"));
    }

    #[test]
    fn zsh_arguments_can_complete_names_only_function_snapshots() {
        let mut program = script_program(
            ScriptDialect::Zsh,
            "_disable_like",
            "disable-like",
            r#"#compdef disable-like
local -a func_arr
func_arr=(${(k)functions})
_arguments '-f[functions]:*:function:compadd -k func_arr'
"#,
        );
        program.scripts[0].zsh_function_names = vec!["_hidden".into(), "_another".into()];
        program.scripts[0].zsh_function_table_size = 7;
        let words = vec!["disable-like".into(), "-f".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        let values = result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.value.as_str())
            .collect::<HashSet<_>>();
        assert!(values.contains("_hidden"));
        assert!(values.contains("_another"));
    }

    #[test]
    fn zsh_associative_unset_and_print_preserve_native_scan_order() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local -A commands=(
  add 'add a route'
  flush 'remove all routes'
  delete 'delete a specific route'
  change 'change a route'
  get 'get a route'
  monitor 'monitor routes'
)
commands[del]=$commands[delete]
unset 'commands[monitor]' 'commands[get]' 'commands[change]'
local -a specifications
print -v specifications -f '%s\\:%s' ${(kvq)commands}
_arguments "1:command:(($specifications))"
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["del", "add", "delete", "flush"]
        );
    }

    #[test]
    fn zsh_tag_loops_select_associative_array_descriptions() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local -a alpha=( 'one:first' 'two:second' ) beta=( 'three:third' )
local -A groups=( [alpha]='alpha values' [beta]='beta values' )
local key ret=1
_tags ${groups// /-}
while _tags; do
  for key in ${(ok)groups}; do
    if _requested ${groups[$key]// /-}; then
      _describe -t ${groups[$key]// /-} ${groups[$key]} $key && ret=0
    fi
  done
done
return ret
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        assert_eq!(result.completion_status, Some(0));
    }

    #[test]
    fn zsh_completion_tag_state_is_resource_bounded() {
        let tags = (0..300)
            .map(|index| format!("tag-{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let source = format!("#compdef tag-limit\n_tags {tags}\n");
        let program = script_program(ScriptDialect::Zsh, "_tag_limit", "tag-limit", &source);
        let words = vec!["tag-limit".into(), String::new()];
        let environment = HashMap::new();
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Zsh,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("Zsh completion tag state"))
        ));

        let oversized = "x".repeat(16 * 1024 + 1);
        let source = format!(
            "#compdef wanted-tag-limit\n_wanted {oversized} expl description compadd -- value\n"
        );
        let program = script_program(
            ScriptDialect::Zsh,
            "_wanted_tag_limit",
            "wanted-tag-limit",
            &source,
        );
        let words = vec!["wanted-tag-limit".into(), String::new()];
        assert!(matches!(
            evaluate(
                &program,
                &context(&words, &environment),
                SourceKind::Zsh,
                TrustStatus::Unsigned,
                EvaluationMode::Passive,
                128,
            ),
            Err(VmError::Limit("Zsh completion tag state"))
        ));
    }

    #[test]
    fn zsh_tag_labels_filter_actions_and_preserve_presentation_options() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_tag_labels",
            "tag-labels",
            r#"#compdef tag-labels
_tags -C inner alpha
while _tags; do
  while _next_label -V grouped alpha expl 'alpha description' -S '='; do
    compadd "$expl[@]" -- one
  done
  _requested beta expl 'wrong description' compadd -- wrong
  _all_labels -J grouped alpha expl 'all description' compadd -- two
 done
"#,
        );
        let words = vec!["tag-labels".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.candidate.value.as_str(),
                    candidate.candidate.description.as_deref(),
                    candidate.candidate.append,
                ))
                .collect::<Vec<_>>(),
            [
                ("one=", None, AppendPolicy::NoSpace),
                ("two", None, AppendPolicy::Space),
            ]
        );
    }

    #[test]
    fn zsh_wanted_restores_the_callers_tag_context() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_wanted_scope",
            "wanted-scope",
            r#"#compdef wanted-scope
_tags alpha beta
while _tags; do
  _wanted alpha expl alpha compadd -- first
  _wanted gamma expl gamma compadd -- wrong
  _requested beta expl beta compadd -- second
 done
"#,
        );
        let words = vec!["wanted-scope".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn nested_zsh_tag_contexts_restore_the_callers_active_set() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_tag_scope",
            "tag-scope",
            r#"#compdef tag-scope
_nested() {
  _tags -C nested inner
  while _tags; do
    _requested inner
  done
}
_tags -C outer-context outer
while _tags; do
  _nested
  _requested outer expl '' compadd restored
 done
"#,
        );
        let words = vec!["tag-scope".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "restored");
    }

    #[test]
    fn nested_zsh_function_definition_replaces_the_outer_binding() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            "#compdef demo\n_demo() { inner() { compadd -- nested; }; inner; }\n",
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "nested");
    }

    #[test]
    fn zsh_zero_or_more_patterns_and_nested_braces_select_service_options() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local -a opts
opts=( {-a,--alpha{,bet}}'[demo option]' )
case "$service" in
  demo[0-9.]#) _arguments : $opts ;;
esac
"#,
        );
        let words = vec!["demo".into(), "--".into()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--alpha", "--alphabet"]
        );
    }

    #[test]
    fn zsh_array_lengths_reverse_subscripts_and_availability_queries_are_data_driven() {
        let grep_filter = "(|*\\))(\\*|)-[aABCdDfGHILmorVy-]*";
        assert!(crate::rules::script::registration_matches(
            ScriptDialect::Zsh,
            grep_filter,
            "--label"
        ));
        assert!(!crate::rules::script::registration_matches(
            ScriptDialect::Zsh,
            grep_filter,
            "-b"
        ));
        assert!(!crate::rules::script::registration_matches(
            ScriptDialect::Zsh,
            "(|g|z|gz|bz)[ef]grep",
            "bsdgrep"
        ));
        let program = script_program(
            ScriptDialect::Zsh,
            "_demo",
            "demo",
            r#"#compdef demo
local -a opts selected
opts=( '-a[first]' '(-d --debug)'{-d,--debug}'[debug]' '--tail[last]' )
selected=( $opts[(r)*-d\[*] )
if (( $#opts && $+commands[present] && ! $+commands[absent] )); then
  _arguments : $selected
  _arguments : '::action:compadd - create view'
  local -a suffix alternatives empty_values
  suffix=( -qS: )
  alternatives=( 'empty:empty:compadd $suffix -a empty_values' )
  _alternative $alternatives
  local -a nested_source nested_result
  nested_source=( --one --two )
  nested_result=( ${${nested_source}#--} )
  compadd -- "${nested_result[@]}"
  local -a filter_source filtered matched
  filter_source=( -a --long -b )
  filtered=( ${filter_source:#(#s)--*} )
  matched=( ${(M)filter_source:#(#s)--*} )
  compadd -- "${filtered[@]}" "${matched[@]}"
  local empty_prefix
  local -a base_options combined_options
  base_options=( '--help[help]' '--version[version]' '-h --help[combined help]' )
  combined_options=( ${empty_prefix}${^base_options} )
  _arguments : $combined_options
  if [[ $service != (csh|?csh|rc) ]]; then
    compadd -- condition-ok
  fi
  local numeric_test=1
  [[ numeric_test -eq 1 ]] && compadd -- numeric-variable-ok
  [[ user:add:linux-gnu = user:add:(^solaris2.<-10>) ]] && compadd -- embedded-complement-ok
  if [[ bsdgrep != (|g|z|gz|bz)[ef]grep ]]; then
    compadd -- grep-condition-ok
  fi
  if (( $# == 0 )); then
    compadd -- positional-ok
  fi
  if [ -z "$missing_value" ]; then
    compadd -- bracket-ok
  fi
  local -a grep_source grep_filtered
  grep_source=( -E -F --label -b )
  grep_filtered=( ${grep_source:#((#s)|*\))(\*|)-[aABCdDfGHILmorVy-]*} )
  compadd -- "${grep_filtered[@]}"
  _arguments ':first positional:' ':second positional:_files'
  local -A lookup
  local letters=AB
  lookup=( A alpha B beta )
  lookup[C]=gamma
  compadd -- $lookup[A] $lookup[C] ${(k)lookup} ${(s::)letters[2]}
  local service_name=groupadd
  compadd -- ${(M)service_name%???} ${service_name%???}
  local -a reverse_search=( foo -d )
  if (( $reverse_search[(I)(-d|--decompress)] )); then
    compadd -- reverse-search-ok
  fi
  words[1]+=( -d )
  [[ $words[2] == -d ]] && compadd -- indexed-insert-ok
  local -a empty_values
  [[ $#empty_values == 0 ]] && compadd -- empty-array-length-ok
  local -A nested_lookup
  nested_lookup=( U generic Uf function )
  local nested_use=U nested_func=f nested_i=1
  compadd -- $nested_lookup[${nested_use[$nested_i]}${${(s::)nested_use[$nested_i]}[(r)[U]]:+$nested_func}]
  local modifier_value=HTML
  compadd -- $modifier_value:l
fi
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let available = HashSet::from(["present".into()]);
        let mut ctx = context(&words, &environment);
        ctx.available_commands = Some(&available);
        let result = evaluate(
            &program,
            &ctx,
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.filesystem_requests.is_empty());
        assert_eq!(result.path_completion, PathCompletion::Inherit);
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            [
                "-d",
                "create",
                "view",
                "one",
                "two",
                "-a",
                "-b",
                "--long",
                "--help",
                "--version",
                "-h --help",
                "condition-ok",
                "numeric-variable-ok",
                "embedded-complement-ok",
                "grep-condition-ok",
                "positional-ok",
                "bracket-ok",
                "-E",
                "-F",
                "alpha",
                "gamma",
                "A",
                "B",
                "C",
                "add",
                "group",
                "reverse-search-ok",
                "indexed-insert-ok",
                "empty-array-length-ok",
                "function",
                "html"
            ]
        );
    }

    #[test]
    fn shell_arithmetic_saturates_hostile_overflow_instead_of_panicking() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_arithmetic",
            "arithmetic",
            r#"#compdef arithmetic
integer maximum=9223372036854775807
integer minimum=-9223372036854775808
(( maximum += 1 ))
(( maximum++ ))
(( minimum -= 1 ))
(( minimum-- ))
compadd -- $maximum $minimum
"#,
        );
        let words = vec!["arithmetic".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["9223372036854775807", "-9223372036854775808"]
        );
    }

    #[test]
    fn zsh_module_can_reenter_itself_as_a_completion_action_with_positionals() {
        let program = script_program(
            ScriptDialect::Zsh,
            "_self_action",
            "self-action",
            r#"#compdef self-action
if (( $# )); then
  _files
  return
fi
_arguments '*:file:_self_action'
"#,
        );
        let words = vec!["self-action".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Zsh,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.path_completion, PathCompletion::Files);
    }

    #[test]
    fn fish_commandline_process_tokens_exclude_the_current_token() {
        let program = script_program(
            ScriptDialect::Fish,
            "demo.fish",
            "demo",
            r#"function no_arguments
  set -l cmd (commandline -pxc) (commandline -tc)
  set -e cmd[1]
  for item in $cmd
    switch $item
      case '-*'
      case '*'
        return 1
    end
  end
  return 0
end
complete -c demo -n no_arguments -l version
"#,
        );
        let environment = HashMap::new();
        let option_words = vec!["demo".into(), "--".into()];
        let option_result = evaluate(
            &program,
            &context(&option_words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(option_result.candidates[0].candidate.value, "--version");

        let argument_words = vec!["demo".into(), "argument".into(), String::new()];
        let argument_result = evaluate(
            &program,
            &context(&argument_words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(argument_result.candidates.is_empty());
    }

    #[test]
    fn fish_empty_sliced_command_substitution_does_not_create_an_argv_element() {
        let program = script_program(
            ScriptDialect::Fish,
            "slice.fish",
            "demo",
            r#"function needs_first_argument
  set -l values (commandline -xpc)[2..-1]
  argparse -u -- $values
  not set -q argv[1]
end
complete -c demo -n needs_first_argument -a first
"#,
        );
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(result.candidates[0].candidate.value, "first");
    }

    #[test]
    fn fish_command_queries_and_wrappers_use_declared_command_availability() {
        let mut program = script_program(
            ScriptDialect::Fish,
            "alias.fish",
            "alias",
            "complete -c alias -w target\ncomplete -c alias -n 'command -sq helper' -l local\n",
        );
        program.scripts.push(
            parse_script(
                ScriptDialect::Fish,
                "target.fish",
                "complete -c target -l wrapped\n",
            )
            .unwrap(),
        );
        program.registrations.push("target".into());
        let words = vec!["alias".into(), "--".into()];
        let environment = HashMap::new();

        let unavailable = HashSet::new();
        let mut unavailable_context = context(&words, &environment);
        unavailable_context.available_commands = Some(&unavailable);
        let unavailable_result = evaluate(
            &program,
            &unavailable_context,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(unavailable_result.candidates.is_empty());

        let available = HashSet::from(["target".into(), "helper".into()]);
        let mut available_context = context(&words, &environment);
        available_context.available_commands = Some(&available);
        let available_result = evaluate(
            &program,
            &available_context,
            SourceKind::Fish,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert_eq!(
            available_result
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["--local", "--wrapped"]
        );
    }

    #[test]
    fn bash_top_level_status_and_remove_all_control_runtime_registrations() {
        let program = script_program(
            ScriptDialect::Bash,
            "status-registration.bash",
            "status-registration",
            "_good() { COMPREPLY=(good); }\n_bad() { COMPREPLY=(bad); }\nfalse\nif (( $? == 0 )); then complete -F _bad status-registration; else complete -F _good status-registration; fi\n",
        );
        let words = vec!["status-registration".into(), String::new()];
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
        assert_eq!(result.candidates[0].candidate.value, "good");

        let program = script_program(
            ScriptDialect::Bash,
            "removed-registration.bash",
            "removed-registration",
            "_removed() { COMPREPLY=(unexpected); }\ncomplete -F _removed removed-registration\ncomplete -r\n",
        );
        let words = vec!["removed-registration".into(), String::new()];
        let result = evaluate(
            &program,
            &context(&words, &environment),
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.completion_status, None);
    }

    #[test]
    fn bash_top_level_probe_selects_only_the_runtime_registration() {
        let mut program = script_program(
            ScriptDialect::Bash,
            "registration.bash",
            "registration-demo",
            "_fallback() { COMPREPLY=(fallback); }\n_strong() { COMPREPLY=(strong); }\ncase \"$(probe-tool)\" in strong*) complete -F _strong registration-demo ;; *) complete -F _fallback registration-demo ;; esac\n",
        );
        program.scripts[0].probe_capabilities = vec!["probe-tool".into()];
        let words = vec!["registration-demo".into(), String::new()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let initial = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        assert_eq!(initial.candidates[0].candidate.value, "fallback");
        let outcomes = HashMap::from([(
            initial.probes[0].key.clone(),
            ProbeResult {
                status: 0,
                values: vec!["strongSwan".into()],
                truncated: true,
            },
        )]);
        let replayed = evaluate_with_outcomes(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &outcomes,
            &HashMap::new(),
        )
        .unwrap();
        assert!(replayed.truncated);
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["strong"]
        );
    }

    #[test]
    fn failed_probe_outcomes_drive_shell_else_branches() {
        let mut program = script_program(
            ScriptDialect::Bash,
            "demo.bash",
            "demo",
            "_demo() { local output=$(probe-tool); if probe-tool; then COMPREPLY=(success); else COMPREPLY=(\"$output\" failure); fi; }\ncomplete -F _demo demo\n",
        );
        program.scripts[0].probe_capabilities = vec!["probe-tool".into()];
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let initial = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        let outcomes = HashMap::from([(
            initial.probes[0].key.clone(),
            ProbeResult {
                status: 1,
                values: vec!["diagnostic".into()],
                truncated: false,
            },
        )]);
        let replayed = evaluate_with_outcomes(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &outcomes,
            &HashMap::new(),
        )
        .unwrap();
        assert!(replayed.probes.is_empty());
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["diagnostic", "failure"]
        );
    }

    #[test]
    fn script_probe_ids_remain_stable_when_an_earlier_probe_is_replayed() {
        let mut program = script_program(
            ScriptDialect::Bash,
            "demo.bash",
            "demo",
            "_demo() { local first=$(probe-one); local second=$(probe-two); COMPREPLY=($first $second); }\ncomplete -F _demo demo\n",
        );
        program.scripts[0].probe_capabilities = vec!["probe-one".into(), "probe-two".into()];
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let initial = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        assert_eq!(initial.probes.len(), 2);
        let second_id = initial.probes[1].probe_id.clone();
        let results = HashMap::from([(initial.probes[0].key.clone(), vec!["one".into()])]);
        let replayed = evaluate_with_probe_results(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &results,
        )
        .unwrap();
        assert_eq!(replayed.probes.len(), 1);
        assert_eq!(replayed.probes[0].probe_id, second_id);
    }

    #[test]
    fn trusted_explicit_evaluation_can_replay_top_level_data_probes() {
        let mut program = script_program(
            ScriptDialect::Bash,
            "top-level.bash",
            "top-level-demo",
            "values=$(probe-tool --list)\n_demo() { COMPREPLY=($values); }\ncomplete -F _demo top-level-demo\n",
        );
        program.scripts[0].probe_capabilities = vec!["probe-tool".into()];
        let words = vec!["top-level-demo".into(), String::new()];
        let environment = HashMap::new();
        let context = context(&words, &environment);
        let requested = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        assert_eq!(requested.probes.len(), 1);
        let replay =
            HashMap::from([(requested.probes[0].key.clone(), vec!["first second".into()])]);
        let evaluated = evaluate_with_probe_results(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &replay,
        )
        .unwrap();
        assert_eq!(
            evaluated
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn script_probes_require_explicit_tab_and_verified_trust_then_replay() {
        let program = script_probe_program();
        let words = vec!["demo".into(), String::new()];
        let environment = HashMap::from([
            ("Z_LAST".into(), "z".into()),
            ("A_FIRST".into(), "a".into()),
        ]);
        let context = context(&words, &environment);

        let passive = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::Passive,
            128,
        )
        .unwrap();
        assert!(passive.probes.is_empty());

        let unsigned = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Unsigned,
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        assert!(unsigned.probes.is_empty());
        assert_eq!(unsigned.denied_probe_count, 1);

        let requested = evaluate(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
        )
        .unwrap();
        assert_eq!(requested.probes.len(), 1);
        assert_eq!(requested.probes[0].key.executable, "probe-tool");
        assert_eq!(requested.probes[0].key.arguments, ["--list"]);
        assert!(requested.probes[0].key.include_stderr);
        assert_eq!(
            requested.probes[0]
                .key
                .environment
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["A_FIRST", "Z_LAST"]
        );

        let results = HashMap::from([(
            requested.probes[0].key.clone(),
            vec!["alpha".into(), "beta".into()],
        )]);
        let replayed = evaluate_with_probe_results(
            &program,
            &context,
            SourceKind::Bash,
            TrustStatus::Verified { key_id: [1; 32] },
            EvaluationMode::ExplicitTab,
            128,
            &results,
        )
        .unwrap();
        assert!(replayed.probes.is_empty());
        assert_eq!(
            replayed
                .candidates
                .iter()
                .map(|candidate| candidate.candidate.value.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }
}
