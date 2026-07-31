use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::CompletionMode;
use super::context::{CompletionContext, MAX_COMPLETION_CONTEXT_BYTES};
use super::matcher::{Candidate, CandidateKind, CandidateSink};
use super::worker::{CompletionCache, EntryKind};
use crate::rules::format::SourceKind;
use crate::rules::ir::{AppendPolicy, PathCompletion, RuleCandidateKind};
use crate::rules::loader::LoadedProgram;
use crate::rules::vm::{
    CompletionRequest, EmittedCandidate, EvaluationContext, EvaluationMode, EvaluationResult,
    FilesystemRequest, FilesystemRequestKind, ProbeKey, ProbeRequest, ProbeResult,
    evaluate_runtime_programs_with_outcomes, evaluate_runtime_with_outcomes,
    nested_completion_path_marker, platform_signal_snapshot,
};
use crate::shell::ShellSnapshot;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderStatus {
    pub pending: bool,
    pub path_completion: PathCompletion,
}

/// Compile-time extension point for command-aware completers.
///
/// The first release registers only [`GenericProvider`]. A future provider can
/// inspect the same immutable context and emit candidates without changing the
/// Readline or rendering layers.
pub trait CompletionProvider: Send {
    fn name(&self) -> &'static str;

    fn complete(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        cache: &mut CompletionCache,
        sink: &mut CandidateSink,
        mode: CompletionMode,
        path_completion: PathCompletion,
    ) -> ProviderStatus;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    pack_id: [u8; 32],
    source_path: String,
    depth: usize,
    explicit: bool,
}

#[derive(Default)]
struct ReplayState {
    probe_results: HashMap<ProbeKey, ProbeResult>,
    completion_results: HashMap<String, Vec<String>>,
    probes: Vec<ProbeRequest>,
    completion_requests: Vec<CompletionRequest>,
    filesystem_requests: Vec<FilesystemRequest>,
    evaluated: Option<(u64, Arc<EvaluationResult>)>,
    provisional_candidates: Arc<[EmittedCandidate]>,
    provisional_path_completion: PathCompletion,
    provisional_redraws: u8,
}

#[derive(Default)]
pub struct RuleProvider {
    replay_context: Option<(String, usize, PathBuf, u64)>,
    replay_states: HashMap<ReplayKey, ReplayState>,
    quick_provisional: Arc<[EmittedCandidate]>,
    quick_path_completion: PathCompletion,
    quick_redraws: u8,
    quick_evaluated: bool,
}

const MAX_COMMAND_SNAPSHOT: usize = 4096;
const MAX_REPLAY_BYTES: usize = 8 * 1024 * 1024;

fn owned_strings_bytes(values: &Vec<String>) -> usize {
    values
        .capacity()
        .saturating_mul(std::mem::size_of::<String>())
        .saturating_add(values.iter().map(String::capacity).sum::<usize>())
}

fn emitted_candidate_bytes(candidate: &EmittedCandidate) -> usize {
    std::mem::size_of::<EmittedCandidate>()
        .saturating_add(candidate.candidate.value.capacity())
        .saturating_add(candidate.candidate.display.capacity())
        .saturating_add(
            candidate
                .candidate
                .description
                .as_ref()
                .map_or(0, String::capacity),
        )
}

fn probe_key_bytes(key: &ProbeKey) -> usize {
    std::mem::size_of::<ProbeKey>()
        .saturating_add(key.executable.capacity())
        .saturating_add(key.working_directory.capacity())
        .saturating_add(owned_strings_bytes(&key.arguments))
        .saturating_add(
            key.environment
                .capacity()
                .saturating_mul(std::mem::size_of::<(String, String)>()),
        )
        .saturating_add(
            key.environment
                .iter()
                .map(|(name, value)| name.capacity().saturating_add(value.capacity()))
                .sum::<usize>(),
        )
}

fn probe_request_bytes(request: &ProbeRequest) -> usize {
    probe_key_bytes(&request.key)
        .saturating_add(request.probe_id.capacity())
        .saturating_add(request.description.as_ref().map_or(0, String::capacity))
}

fn completion_request_bytes(request: &CompletionRequest) -> usize {
    std::mem::size_of::<CompletionRequest>().saturating_add(request.line.capacity())
}

fn filesystem_request_bytes(request: &FilesystemRequest) -> usize {
    std::mem::size_of::<FilesystemRequest>()
        .saturating_add(request.request_id.capacity())
        .saturating_add(request.path.capacity())
        .saturating_add(request.operator.as_ref().map_or(0, String::capacity))
}

fn replay_dependency_bytes(
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
) -> usize {
    probe_results
        .capacity()
        .saturating_mul(std::mem::size_of::<(ProbeKey, ProbeResult)>().saturating_add(1))
        .saturating_add(
            probe_results
                .iter()
                .map(|(key, result)| {
                    probe_key_bytes(key).saturating_add(owned_strings_bytes(&result.values))
                })
                .sum::<usize>(),
        )
        .saturating_add(
            completion_results
                .capacity()
                .saturating_mul(std::mem::size_of::<(String, Vec<String>)>().saturating_add(1)),
        )
        .saturating_add(
            completion_results
                .iter()
                .map(|(key, values)| key.capacity().saturating_add(owned_strings_bytes(values)))
                .sum::<usize>(),
        )
}

fn evaluation_result_bytes(result: &EvaluationResult) -> usize {
    result
        .candidates
        .capacity()
        .saturating_mul(std::mem::size_of::<EmittedCandidate>())
        .saturating_add(
            result
                .candidates
                .iter()
                .map(emitted_candidate_bytes)
                .sum::<usize>(),
        )
        .saturating_add(
            result
                .provisional_candidates
                .iter()
                .map(emitted_candidate_bytes)
                .sum::<usize>(),
        )
        .saturating_add(
            result
                .probes
                .capacity()
                .saturating_mul(std::mem::size_of::<ProbeRequest>()),
        )
        .saturating_add(result.probes.iter().map(probe_request_bytes).sum::<usize>())
        .saturating_add(
            result
                .completion_requests
                .capacity()
                .saturating_mul(std::mem::size_of::<CompletionRequest>()),
        )
        .saturating_add(
            result
                .completion_requests
                .iter()
                .map(completion_request_bytes)
                .sum::<usize>(),
        )
        .saturating_add(
            result
                .filesystem_requests
                .capacity()
                .saturating_mul(std::mem::size_of::<FilesystemRequest>()),
        )
        .saturating_add(
            result
                .filesystem_requests
                .iter()
                .map(filesystem_request_bytes)
                .sum::<usize>(),
        )
        .saturating_add(owned_strings_bytes(&result.snapshot_providers))
}

fn replay_state_bytes(state: &ReplayState) -> usize {
    replay_dependency_bytes(&state.probe_results, &state.completion_results)
        .saturating_add(
            state
                .probes
                .capacity()
                .saturating_mul(std::mem::size_of::<ProbeRequest>()),
        )
        .saturating_add(state.probes.iter().map(probe_request_bytes).sum::<usize>())
        .saturating_add(
            state
                .completion_requests
                .capacity()
                .saturating_mul(std::mem::size_of::<CompletionRequest>()),
        )
        .saturating_add(
            state
                .completion_requests
                .iter()
                .map(completion_request_bytes)
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .filesystem_requests
                .capacity()
                .saturating_mul(std::mem::size_of::<FilesystemRequest>()),
        )
        .saturating_add(
            state
                .filesystem_requests
                .iter()
                .map(filesystem_request_bytes)
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .evaluated
                .as_ref()
                .map_or(0, |(_, result)| evaluation_result_bytes(result)),
        )
        .saturating_add(
            state
                .provisional_candidates
                .iter()
                .map(emitted_candidate_bytes)
                .sum::<usize>(),
        )
}

fn trim_replay_states(states: &mut HashMap<ReplayKey, ReplayState>, configured_limit: usize) {
    let limit = configured_limit.min(MAX_REPLAY_BYTES);
    let mut retained = states
        .iter()
        .map(|(key, state)| {
            (
                key.clone(),
                std::mem::size_of::<ReplayKey>()
                    .saturating_add(key.source_path.capacity())
                    .saturating_add(replay_state_bytes(state)),
            )
        })
        .collect::<Vec<_>>();
    let map_bytes = states
        .capacity()
        .saturating_mul(std::mem::size_of::<(ReplayKey, ReplayState)>().saturating_add(1));
    let mut total =
        map_bytes.saturating_add(retained.iter().map(|(_, bytes)| *bytes).sum::<usize>());
    if total <= limit {
        return;
    }
    retained.sort_unstable_by(|left, right| right.1.cmp(&left.1));
    for (key, bytes) in retained {
        states.remove(&key);
        total = total.saturating_sub(bytes);
        if total <= limit {
            break;
        }
    }
    states.shrink_to_fit();
    if states
        .capacity()
        .saturating_mul(std::mem::size_of::<(ReplayKey, ReplayState)>().saturating_add(1))
        > limit
    {
        states.clear();
        states.shrink_to_fit();
    }
}

fn command_snapshot(
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
) -> (HashSet<String>, Vec<String>, bool) {
    let mut available = HashSet::new();
    let mut ordered = Vec::new();
    'sources: for commands in [&shell.aliases, &shell.functions, &shell.builtins] {
        let mut commands = commands.iter().cloned().collect::<Vec<_>>();
        commands.sort_unstable();
        for command in commands {
            if available.insert(command.clone()) {
                ordered.push(command);
                if ordered.len() >= MAX_COMMAND_SNAPSHOT {
                    break 'sources;
                }
            }
        }
    }
    let pending = if ordered.len() < MAX_COMMAND_SNAPSHOT {
        cache.for_each_command("", |command| {
            if available.insert(command.to_owned()) {
                ordered.push(command.to_owned());
            }
            ordered.len() < MAX_COMMAND_SNAPSHOT
        })
    } else {
        false
    };
    (available, ordered, pending)
}

impl CompletionProvider for RuleProvider {
    fn name(&self) -> &'static str {
        "rule-packs"
    }

    fn complete(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        cache: &mut CompletionCache,
        sink: &mut CandidateSink,
        mode: CompletionMode,
        _path_completion: PathCompletion,
    ) -> ProviderStatus {
        let Some(command) = context.command_name.as_deref() else {
            return ProviderStatus::default();
        };
        let replay_context = (
            context.line.clone(),
            context.point,
            shell.cwd.clone(),
            shell.generation,
        );
        if self.replay_context.as_ref() != Some(&replay_context) {
            self.replay_context = Some(replay_context);
            self.replay_states.clear();
            self.quick_provisional = Arc::default();
            self.quick_path_completion = PathCompletion::Inherit;
            self.quick_redraws = 0;
            self.quick_evaluated = false;
        }
        let (programs, pending) = cache.rule_programs(command);
        let mut status = ProviderStatus {
            pending,
            path_completion: if pending && programs.is_none() {
                PathCompletion::Suppress
            } else {
                PathCompletion::Inherit
            },
        };
        let Some(programs) = programs else {
            return status;
        };
        if programs.is_empty() {
            self.replay_states.clear();
            self.quick_provisional = Arc::default();
            self.quick_path_completion = PathCompletion::Inherit;
            self.quick_redraws = 0;
            self.quick_evaluated = false;
            return status;
        }
        status.pending |= cache.snapshots_pending();
        let fish_program_count = programs
            .iter()
            .filter(|loaded| loaded.source == SourceKind::Fish)
            .count();
        let (mut available_commands, shell_commands, command_snapshot_pending) =
            command_snapshot(shell, cache);
        status.pending |= command_snapshot_pending;
        if mode == CompletionMode::ExplicitTab && context.query.starts_with("--") {
            if self.quick_redraws > 0 {
                self.quick_redraws -= 1;
                push_emitted_candidates(context, sink, &self.quick_provisional);
                status.path_completion = status.path_completion.merge(self.quick_path_completion);
                status.pending = true;
                return status;
            }
            if !self.quick_evaluated
                && fish_program_count == 1
                && programs
                    .iter()
                    .any(|loaded| loaded.source == SourceKind::Fish)
            {
                self.quick_evaluated = true;
                let quick_context = EvaluationContext {
                    current_word: &context.query,
                    words: &context.words,
                    word_index: context.word_index,
                    command_path: &context.command_path,
                    environment: &shell.environment,
                    working_directory: &shell.cwd,
                    available_commands: Some(&available_commands),
                    shell_commands: Some(&shell_commands),
                    shell_functions: None,
                    shell_variables: Some(&shell.variables),
                    shell_variable_values: Some(&shell.variable_values),
                    users: None,
                    groups: None,
                    hosts: None,
                    process_ids: None,
                    process_names: None,
                    network_interfaces: None,
                    signals: None,
                    passwd_records: None,
                    group_records: None,
                    effective_user_id: shell.effective_user_id,
                };
                for loaded in programs
                    .iter()
                    .filter(|loaded| loaded.source == SourceKind::Fish)
                {
                    match evaluate_runtime_with_outcomes(
                        &loaded.program,
                        &quick_context,
                        loaded.source,
                        loaded.trust,
                        EvaluationMode::ExplicitTab,
                        sink.remaining_capacity_hint(),
                        &HashMap::new(),
                        &HashMap::new(),
                        true,
                        true,
                    ) {
                        Ok(mut evaluated) if evaluated.provisional_yielded => {
                            let provisional = std::mem::take(&mut evaluated.provisional_candidates);
                            let retained_bytes = provisional
                                .iter()
                                .map(emitted_candidate_bytes)
                                .sum::<usize>();
                            if retained_bytes <= cache.replay_byte_limit().min(MAX_REPLAY_BYTES) {
                                self.quick_provisional = Arc::from(provisional);
                                // Provisional candidates may precede deterministic
                                // Fish path-policy statements. Suppress generic path
                                // candidates until the complete replay publishes the
                                // final policy.
                                self.quick_path_completion = PathCompletion::Suppress;
                                push_emitted_candidates(context, sink, &self.quick_provisional);
                                status.path_completion =
                                    status.path_completion.merge(self.quick_path_completion);
                                self.quick_redraws = 1;
                                status.pending = true;
                                return status;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            cache.record_rule_error(format!("{}: {error}", loaded.pack_name));
                        }
                    }
                }
            }
        }
        if self.quick_evaluated && self.quick_redraws == 0 {
            self.quick_provisional = Arc::default();
            self.quick_path_completion = PathCompletion::Inherit;
        }
        for required in programs
            .iter()
            .flat_map(|loaded| loaded.required_commands.iter())
        {
            if shell.known_shell_command(required).is_some() {
                available_commands.insert(required.clone());
                continue;
            }
            match cache.command_available(required) {
                Some(true) => {
                    available_commands.insert(required.clone());
                }
                Some(false) => {}
                None => status.pending = true,
            }
        }
        let mut shell_functions = shell.functions.iter().cloned().collect::<Vec<_>>();
        shell_functions.sort_unstable();
        let users = cache.users().to_vec();
        let groups = cache.groups().to_vec();
        let hosts = cache.hosts().to_vec();
        let process_ids = cache.process_ids().to_vec();
        let process_names = cache.process_names().to_vec();
        let network_interfaces = cache.network_interfaces().to_vec();
        let signals = platform_signal_snapshot();
        let passwd_records = cache.passwd_records().to_vec();
        let group_records = cache.group_records().to_vec();
        let evaluation_context = EvaluationContext {
            current_word: &context.query,
            words: &context.words,
            word_index: context.word_index,
            command_path: &context.command_path,
            environment: &shell.environment,
            working_directory: &shell.cwd,
            available_commands: Some(&available_commands),
            shell_commands: Some(&shell_commands),
            shell_functions: Some(&shell_functions),
            shell_variables: Some(&shell.variables),
            shell_variable_values: Some(&shell.variable_values),
            users: Some(&users),
            groups: Some(&groups),
            hosts: Some(&hosts),
            process_ids: Some(&process_ids),
            process_names: Some(&process_names),
            network_interfaces: Some(&network_interfaces),
            signals: Some(&signals),
            passwd_records: Some(&passwd_records),
            group_records: Some(&group_records),
            effective_user_id: shell.effective_user_id,
        };
        let evaluation_mode = match mode {
            CompletionMode::Passive => EvaluationMode::Passive,
            CompletionMode::ExplicitTab => EvaluationMode::ExplicitTab,
        };
        let fish_programs = programs
            .iter()
            .filter(|loaded| loaded.source == SourceKind::Fish)
            .collect::<Vec<_>>();
        let mut fish_evaluated = false;
        for loaded in programs.iter() {
            let evaluated = if loaded.source == SourceKind::Fish {
                if fish_evaluated {
                    continue;
                }
                fish_evaluated = true;
                complete_loaded_programs(
                    &fish_programs,
                    &evaluation_context,
                    context,
                    shell,
                    cache,
                    sink,
                    mode,
                    evaluation_mode,
                    0,
                    true,
                    Some(&mut self.replay_states),
                )
            } else {
                complete_loaded_program(
                    loaded,
                    &evaluation_context,
                    context,
                    shell,
                    cache,
                    sink,
                    mode,
                    evaluation_mode,
                    0,
                    false,
                    Some(&mut self.replay_states),
                )
            };
            status.pending |= evaluated.pending;
            status.path_completion = status.path_completion.merge(evaluated.path_completion);
            trim_replay_states(&mut self.replay_states, cache.replay_byte_limit());
        }
        status
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_replay_dependencies(
    pack_name: &str,
    probes: &[ProbeRequest],
    completion_requests: &[CompletionRequest],
    filesystem_requests: &[FilesystemRequest],
    evaluation_context: &EvaluationContext<'_>,
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
    mode: CompletionMode,
    depth: usize,
    probe_results: &mut HashMap<ProbeKey, ProbeResult>,
    completion_results: &mut HashMap<String, Vec<String>>,
    status: &mut ProviderStatus,
    refresh_existing: bool,
) -> Result<(bool, bool), ()> {
    let mut progressed = false;
    let mut unresolved = false;
    for request in filesystem_requests {
        if !refresh_existing && completion_results.contains_key(&request.request_id) {
            continue;
        }
        let (values, filesystem_pending, filesystem_limited) =
            cache.filesystem_values(request, evaluation_context.working_directory);
        if filesystem_limited {
            cache.record_rule_error(format!(
                "{}: filesystem replay cache resource limit",
                pack_name
            ));
            return Err(());
        }
        status.pending |= filesystem_pending;
        if let Some(values) = values {
            let changed = completion_results.get(&request.request_id) != Some(&values);
            completion_results.insert(request.request_id.clone(), values);
            if replay_dependency_bytes(probe_results, completion_results)
                > cache.replay_byte_limit().min(MAX_REPLAY_BYTES)
            {
                cache.record_rule_error(format!(
                    "{}: completion replay state exceeds the configured limit",
                    pack_name
                ));
                return Err(());
            }
            progressed |= changed;
        } else {
            unresolved = true;
        }
    }
    for request in completion_requests {
        if !refresh_existing && completion_results.contains_key(&request.line) {
            continue;
        }
        let (values, nested_pending) =
            nested_completion_values_at_depth(request, shell, cache, mode, depth);
        status.pending |= nested_pending;
        if let Some(values) = values {
            let changed = completion_results.get(&request.line) != Some(&values);
            completion_results.insert(request.line.clone(), values);
            if replay_dependency_bytes(probe_results, completion_results)
                > cache.replay_byte_limit().min(MAX_REPLAY_BYTES)
            {
                cache.record_rule_error(format!(
                    "{}: completion replay state exceeds the configured limit",
                    pack_name
                ));
                return Err(());
            }
            progressed |= changed;
        } else {
            unresolved = true;
        }
    }
    for probe in probes {
        let (outcome, probe_pending) = cache.probe_outcome(probe);
        status.pending |= probe_pending;
        if probe.probe_id.starts_with("script:") {
            if !refresh_existing && probe_results.contains_key(&probe.key) {
                continue;
            }
            if let Some(outcome) = outcome {
                let changed = probe_results.get(&probe.key) != Some(&outcome);
                probe_results.insert(probe.key.clone(), outcome);
                if replay_dependency_bytes(probe_results, completion_results)
                    > cache.replay_byte_limit().min(MAX_REPLAY_BYTES)
                {
                    cache.record_rule_error(format!(
                        "{}: completion replay state exceeds the configured limit",
                        pack_name
                    ));
                    return Err(());
                }
                progressed |= changed;
            } else {
                unresolved = true;
            }
        } else if let Some(outcome) = outcome.filter(|outcome| outcome.status == 0) {
            push_probe_values(context, sink, probe, &outcome.values);
        }
    }
    Ok((progressed, unresolved))
}

fn push_emitted_candidates(
    context: &CompletionContext,
    sink: &mut CandidateSink,
    candidates: &[EmittedCandidate],
) {
    for emitted in candidates {
        push_rule_candidate(
            context,
            sink,
            emitted.candidate.preserve_order,
            emitted.candidate.value.clone(),
            emitted.candidate.display.clone(),
            emitted.candidate.description.clone(),
            emitted.candidate.kind,
            emitted.candidate.append,
            emitted.source,
        );
    }
}

fn push_evaluation_result(
    context: &CompletionContext,
    sink: &mut CandidateSink,
    status: &mut ProviderStatus,
    evaluated: &EvaluationResult,
) {
    status.path_completion = status.path_completion.merge(evaluated.path_completion);
    push_emitted_candidates(context, sink, &evaluated.candidates);
}

fn loaded_replay_key(loaded: &[&LoadedProgram], depth: usize, explicit: bool) -> ReplayKey {
    if let [loaded] = loaded {
        return ReplayKey {
            pack_id: loaded.pack_id,
            source_path: loaded.program.source_path.clone(),
            depth,
            explicit,
        };
    }
    let mut hasher = Sha256::new();
    for program in loaded {
        hasher.update(program.pack_id);
        hasher.update((program.program.source_path.len() as u64).to_le_bytes());
        hasher.update(program.program.source_path.as_bytes());
    }
    let pack_id: [u8; 32] = hasher.finalize().into();
    ReplayKey {
        pack_id,
        source_path: format!(
            "fish-program-group:{:02x}{:02x}{:02x}{:02x}",
            pack_id[0], pack_id[1], pack_id[2], pack_id[3]
        ),
        depth,
        explicit,
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_loaded_programs(
    loaded: &[&LoadedProgram],
    evaluation_context: &EvaluationContext<'_>,
    evaluation_mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
    allow_provisional_yield: bool,
    runtime_optimizations: bool,
) -> Result<EvaluationResult, crate::rules::vm::VmError> {
    if let [loaded] = loaded {
        return evaluate_runtime_with_outcomes(
            &loaded.program,
            evaluation_context,
            loaded.source,
            loaded.trust,
            evaluation_mode,
            candidate_limit,
            probe_results,
            completion_results,
            allow_provisional_yield,
            runtime_optimizations,
        );
    }
    let programs = loaded
        .iter()
        .map(|loaded| (loaded.program.as_ref(), loaded.trust))
        .collect::<Vec<_>>();
    evaluate_runtime_programs_with_outcomes(
        &programs,
        evaluation_context,
        SourceKind::Fish,
        evaluation_mode,
        candidate_limit,
        probe_results,
        completion_results,
        allow_provisional_yield,
        runtime_optimizations,
    )
}

#[allow(clippy::too_many_arguments)]
fn complete_loaded_program(
    loaded: &LoadedProgram,
    evaluation_context: &EvaluationContext<'_>,
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
    mode: CompletionMode,
    evaluation_mode: EvaluationMode,
    depth: usize,
    allow_cross_program_provisional: bool,
    replay_states: Option<&mut HashMap<ReplayKey, ReplayState>>,
) -> ProviderStatus {
    complete_loaded_programs(
        &[loaded],
        evaluation_context,
        context,
        shell,
        cache,
        sink,
        mode,
        evaluation_mode,
        depth,
        allow_cross_program_provisional,
        replay_states,
    )
}

#[allow(clippy::too_many_arguments)]
fn complete_loaded_programs(
    loaded: &[&LoadedProgram],
    evaluation_context: &EvaluationContext<'_>,
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
    mode: CompletionMode,
    evaluation_mode: EvaluationMode,
    depth: usize,
    allow_cross_program_provisional: bool,
    mut replay_states: Option<&mut HashMap<ReplayKey, ReplayState>>,
) -> ProviderStatus {
    let mut status = ProviderStatus::default();
    let Some(first_loaded) = loaded.first().copied() else {
        return status;
    };
    let pack_name = if loaded.len() == 1 {
        first_loaded.pack_name.as_str()
    } else {
        "Fish rule program group"
    };
    let all_fish = loaded
        .iter()
        .all(|loaded| loaded.source == SourceKind::Fish);
    let replay_key = loaded_replay_key(
        loaded,
        depth,
        evaluation_mode == EvaluationMode::ExplicitTab,
    );
    let replay = replay_states
        .as_deref_mut()
        .and_then(|states| states.remove(&replay_key))
        .unwrap_or_default();
    let mut probe_results = replay.probe_results;
    let mut completion_results = replay.completion_results;
    let mut probes = replay.probes;
    let mut completion_requests = replay.completion_requests;
    let mut filesystem_requests = replay.filesystem_requests;
    let mut cached_evaluated = replay.evaluated;
    let mut provisional_candidates = replay.provisional_candidates;
    let mut provisional_path_completion = replay.provisional_path_completion;
    let mut provisional_redraws = replay.provisional_redraws;
    if provisional_redraws > 0 {
        provisional_redraws -= 1;
        push_emitted_candidates(context, sink, &provisional_candidates);
        status.path_completion = status.path_completion.merge(provisional_path_completion);
        status.pending = true;
        if let Some(states) = replay_states.as_deref_mut() {
            states.insert(
                replay_key,
                ReplayState {
                    probe_results,
                    completion_results,
                    probes,
                    completion_requests,
                    filesystem_requests,
                    evaluated: cached_evaluated,
                    provisional_candidates,
                    provisional_path_completion,
                    provisional_redraws,
                },
            );
        }
        return status;
    }
    let allow_provisional_yield = allow_cross_program_provisional
        && all_fish
        && evaluation_mode == EvaluationMode::ExplicitTab
        && context.query.starts_with("--")
        && provisional_candidates.is_empty();
    if !probes.is_empty() || !completion_requests.is_empty() || !filesystem_requests.is_empty() {
        let Ok((dependencies_changed, unresolved)) = resolve_replay_dependencies(
            pack_name,
            &probes,
            &completion_requests,
            &filesystem_requests,
            evaluation_context,
            context,
            shell,
            cache,
            sink,
            mode,
            depth,
            &mut probe_results,
            &mut completion_results,
            &mut status,
            true,
        ) else {
            return status;
        };
        if unresolved {
            push_emitted_candidates(context, sink, &provisional_candidates);
            status.path_completion = status.path_completion.merge(provisional_path_completion);
            if let Some(states) = replay_states.as_deref_mut() {
                states.insert(
                    replay_key,
                    ReplayState {
                        probe_results,
                        completion_results,
                        probes,
                        completion_requests,
                        filesystem_requests,
                        evaluated: None,
                        provisional_candidates,
                        provisional_path_completion,
                        provisional_redraws: 0,
                    },
                );
            }
            return status;
        }
        if !dependencies_changed {
            if let Some((generation, evaluated)) = cached_evaluated.take() {
                if generation == cache.response_generation() {
                    push_evaluation_result(context, sink, &mut status, &evaluated);
                    if let Some(states) = replay_states.as_deref_mut() {
                        states.insert(
                            replay_key,
                            ReplayState {
                                probe_results,
                                completion_results,
                                probes,
                                completion_requests,
                                filesystem_requests,
                                evaluated: Some((generation, evaluated)),
                                provisional_candidates: Arc::default(),
                                provisional_path_completion: PathCompletion::Inherit,
                                provisional_redraws: 0,
                            },
                        );
                    }
                    return status;
                }
            }
        }
    } else if let Some((generation, evaluated)) = cached_evaluated.take() {
        if generation == cache.response_generation() {
            push_evaluation_result(context, sink, &mut status, &evaluated);
            if let Some(states) = replay_states.as_deref_mut() {
                states.insert(
                    replay_key,
                    ReplayState {
                        probe_results,
                        completion_results,
                        probes,
                        completion_requests,
                        filesystem_requests,
                        evaluated: Some((generation, evaluated)),
                        provisional_candidates: Arc::default(),
                        provisional_path_completion: PathCompletion::Inherit,
                        provisional_redraws: 0,
                    },
                );
            }
            return status;
        }
    }
    for round in 0..=8 {
        let mut evaluated = match evaluate_loaded_programs(
            loaded,
            evaluation_context,
            evaluation_mode,
            sink.remaining_capacity_hint(),
            &probe_results,
            &completion_results,
            allow_provisional_yield,
            allow_provisional_yield,
        ) {
            Ok(evaluated) => evaluated,
            Err(error) => {
                cache.record_rule_error(format!("{pack_name}: {error}"));
                return status;
            }
        };
        if evaluated.optimization_incomplete
            && evaluated.probes.is_empty()
            && evaluated.completion_requests.is_empty()
            && evaluated.filesystem_requests.is_empty()
        {
            evaluated = match evaluate_loaded_programs(
                loaded,
                evaluation_context,
                evaluation_mode,
                sink.remaining_capacity_hint(),
                &probe_results,
                &completion_results,
                false,
                false,
            ) {
                Ok(evaluated) => evaluated,
                Err(error) => {
                    cache.record_rule_error(format!("{pack_name}: {error}"));
                    return status;
                }
            };
        }
        if evaluated.provisional_yielded {
            provisional_candidates =
                Arc::from(std::mem::take(&mut evaluated.provisional_candidates));
            // The remaining Fish program can still refine path policy even
            // though it cannot invalidate this provisional option. Avoid
            // exposing filesystem false positives before full replay.
            provisional_path_completion = PathCompletion::Suppress;
            push_emitted_candidates(context, sink, &provisional_candidates);
            status.path_completion = status.path_completion.merge(provisional_path_completion);
            status.pending = true;
            if let Some(states) = replay_states.as_deref_mut() {
                states.insert(
                    replay_key,
                    ReplayState {
                        probe_results,
                        completion_results,
                        probes,
                        completion_requests,
                        filesystem_requests,
                        evaluated: None,
                        provisional_candidates,
                        provisional_path_completion,
                        provisional_redraws: 1,
                    },
                );
            }
            return status;
        }
        probes = evaluated.probes.clone();
        completion_requests = evaluated.completion_requests.clone();
        filesystem_requests = evaluated.filesystem_requests.clone();
        let Ok((progressed, unresolved)) = resolve_replay_dependencies(
            pack_name,
            &probes,
            &completion_requests,
            &filesystem_requests,
            evaluation_context,
            context,
            shell,
            cache,
            sink,
            mode,
            depth,
            &mut probe_results,
            &mut completion_results,
            &mut status,
            false,
        ) else {
            return status;
        };
        // Keep both dependency keys and their partial outcomes while workers
        // run. A later event-hook turn can poll them before replaying the VM,
        // rather than repeatedly rediscovering the same pending requests.
        if unresolved {
            let newly_provisional = std::mem::take(&mut evaluated.provisional_candidates);
            if !newly_provisional.is_empty() {
                provisional_candidates = Arc::from(newly_provisional);
            }
            push_emitted_candidates(context, sink, &provisional_candidates);
            status.path_completion = status.path_completion.merge(provisional_path_completion);
            if let Some(states) = replay_states.as_deref_mut() {
                states.insert(
                    replay_key,
                    ReplayState {
                        probe_results,
                        completion_results,
                        probes,
                        completion_requests,
                        filesystem_requests,
                        evaluated: None,
                        provisional_candidates,
                        provisional_path_completion,
                        provisional_redraws: 0,
                    },
                );
            }
            return status;
        }
        if progressed {
            if round == 8 {
                cache.record_rule_error(format!(
                    "{pack_name}: completion replay dependency limit exceeded"
                ));
                status.pending = false;
                return status;
            }
            continue;
        }
        let reusable = (!evaluated.truncated)
            .then(|| (cache.response_generation(), Arc::new(evaluated.clone())));
        if let Some(states) = replay_states.as_deref_mut() {
            states.insert(
                replay_key,
                ReplayState {
                    probe_results,
                    completion_results,
                    probes,
                    completion_requests,
                    filesystem_requests,
                    evaluated: reusable,
                    provisional_candidates: Arc::default(),
                    provisional_path_completion: PathCompletion::Inherit,
                    provisional_redraws: 0,
                },
            );
        }
        status.path_completion = status.path_completion.merge(evaluated.path_completion);
        for emitted in evaluated.candidates {
            push_rule_candidate(
                context,
                sink,
                emitted.candidate.preserve_order,
                emitted.candidate.value,
                emitted.candidate.display,
                emitted.candidate.description,
                emitted.candidate.kind,
                emitted.candidate.append,
                emitted.source,
            );
        }
        return status;
    }
    status
}

fn effective_access(path: &Path, mode: libc::c_int) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), mode, libc::AT_EACCESS) == 0 }
}

pub(super) fn resolve_filesystem_request(request: &FilesystemRequest, cwd: &Path) -> Vec<String> {
    match request.kind {
        FilesystemRequestKind::Test => {
            if request.path.is_empty() || request.path.len() > 4096 || request.path.contains('\0') {
                return Vec::new();
            }
            let path = resolve_request_path(&request.path, cwd);
            let followed = fs::metadata(&path).ok();
            let link = fs::symlink_metadata(&path).ok();
            let matched =
                match request.operator.as_deref() {
                    Some("-L" | "-h") => link.is_some_and(|metadata| metadata.is_symlink()),
                    Some("-f") => followed.is_some_and(|metadata| metadata.is_file()),
                    Some("-d") => followed.is_some_and(|metadata| metadata.is_dir()),
                    Some("-b") => {
                        followed.is_some_and(|metadata| metadata.file_type().is_block_device())
                    }
                    Some("-c") => {
                        followed.is_some_and(|metadata| metadata.file_type().is_char_device())
                    }
                    Some("-p") => followed.is_some_and(|metadata| metadata.file_type().is_fifo()),
                    Some("-S") => followed.is_some_and(|metadata| metadata.file_type().is_socket()),
                    Some("-s") => followed.is_some_and(|metadata| metadata.len() > 0),
                    Some("-r") => effective_access(&path, libc::R_OK),
                    Some("-w") => effective_access(&path, libc::W_OK),
                    Some("-x") => effective_access(&path, libc::X_OK),
                    Some("-u") => followed.is_some_and(|metadata| metadata.mode() & 0o4000 != 0),
                    Some("-g") => followed.is_some_and(|metadata| metadata.mode() & 0o2000 != 0),
                    Some("-k") => followed.is_some_and(|metadata| metadata.mode() & 0o1000 != 0),
                    Some("-O") => followed
                        .is_some_and(|metadata| metadata.uid() == unsafe { libc::geteuid() }),
                    Some("-G") => followed
                        .is_some_and(|metadata| metadata.gid() == unsafe { libc::getegid() }),
                    Some("-e") | None => followed.is_some(),
                    Some(_) => false,
                };
            if matched {
                vec!["true".into()]
            } else {
                Vec::new()
            }
        }
        FilesystemRequestKind::Glob => resolve_filesystem_glob(&request.path, cwd, request.dialect),
        FilesystemRequestKind::Read => resolve_filesystem_read(&request.path, cwd),
    }
}

fn resolve_filesystem_read(path: &str, cwd: &Path) -> Vec<String> {
    const MAX_READ_BYTES: u64 = 1024 * 1024;
    const MAX_READ_LINES: usize = 4096;

    if path.len() > 4096 || path.contains('\0') {
        return Vec::new();
    }
    let Ok(mut file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(resolve_request_path(path, cwd))
    else {
        return Vec::new();
    };
    let Ok(metadata) = file.metadata() else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_READ_BYTES {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if file
        .by_ref()
        .take(MAX_READ_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_READ_BYTES
    {
        return Vec::new();
    }
    String::from_utf8_lossy(&bytes)
        .split_terminator('\n')
        .take(MAX_READ_LINES)
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
        .filter(|line| line.len() <= 64 * 1024)
        .collect()
}

fn resolve_request_path(path: &str, cwd: &Path) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    }
}

fn resolve_filesystem_glob(
    pattern: &str,
    cwd: &Path,
    dialect: crate::rules::script::ScriptDialect,
) -> Vec<String> {
    if pattern.len() > 4096 || pattern.contains('\0') {
        return Vec::new();
    }
    let wildcard = first_path_glob(pattern, dialect);
    let Some(wildcard) = wildcard else {
        return if fs::metadata(resolve_request_path(pattern, cwd)).is_ok() {
            vec![pattern.to_owned()]
        } else {
            Vec::new()
        };
    };
    let separator = pattern[..wildcard].rfind('/');
    let (base_text, remainder) = match separator {
        Some(0) if pattern.starts_with('/') => ("/", &pattern[1..]),
        Some(index) => (&pattern[..index], &pattern[index + 1..]),
        None => (".", pattern),
    };
    let mut paths = vec![resolve_request_path(base_text, cwd)];
    for component in remainder
        .split('/')
        .filter(|component| !component.is_empty())
    {
        let wildcard_component = path_component_has_glob(component, dialect);
        let mut next = Vec::new();
        for base in paths {
            if wildcard_component {
                let Ok(entries) = fs::read_dir(&base) else {
                    continue;
                };
                for entry in entries.flatten().take(4096 - next.len()) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') && !component.starts_with('.') {
                        continue;
                    }
                    let pattern = if dialect == crate::rules::script::ScriptDialect::Fish {
                        component
                            .replace('?', "\\?")
                            .replace('[', "\\[")
                            .replace(']', "\\]")
                    } else {
                        component.to_owned()
                    };
                    if crate::rules::script::registration_matches(dialect, &pattern, &name) {
                        next.push(entry.path());
                    }
                }
            } else {
                let path = base.join(component);
                if fs::symlink_metadata(&path).is_ok() {
                    next.push(path);
                }
            }
            if next.len() >= 4096 {
                break;
            }
        }
        paths = next;
        if paths.is_empty() {
            break;
        }
    }
    paths.sort();
    paths.truncate(4096);
    paths
        .into_iter()
        .filter_map(|path| {
            if pattern.starts_with('/') {
                Some(path.to_string_lossy().into_owned())
            } else {
                let relative = path.strip_prefix(cwd).ok()?.to_string_lossy();
                Some(if pattern.starts_with("./") {
                    format!("./{relative}")
                } else {
                    relative.into_owned()
                })
            }
        })
        .collect()
}

fn first_path_glob(pattern: &str, dialect: crate::rules::script::ScriptDialect) -> Option<usize> {
    let mut escaped = false;
    pattern.char_indices().find_map(|(index, character)| {
        if escaped {
            escaped = false;
            return None;
        }
        if character == '\\' {
            escaped = true;
            return None;
        }
        (character == '*'
            || dialect != crate::rules::script::ScriptDialect::Fish
                && matches!(character, '?' | '['))
        .then_some(index)
    })
}

fn path_component_has_glob(component: &str, dialect: crate::rules::script::ScriptDialect) -> bool {
    let mut escaped = false;
    component.chars().any(|character| {
        if escaped {
            escaped = false;
            return false;
        }
        if character == '\\' {
            escaped = true;
            return false;
        }
        character == '*'
            || dialect != crate::rules::script::ScriptDialect::Fish
                && matches!(character, '?' | '[')
    })
}

fn nested_completion_values_at_depth(
    request: &CompletionRequest,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    mode: CompletionMode,
    depth: usize,
) -> (Option<Vec<String>>, bool) {
    if depth >= 4 || request.line.len() > MAX_COMPLETION_CONTEXT_BYTES {
        return (Some(Vec::new()), false);
    }
    let context = CompletionContext::analyze(&request.line, request.line.len());
    let mut sink = CandidateSink::new(4096);
    let mut pending = false;
    let mut path_completion = PathCompletion::Inherit;
    if context.command_position {
        pending |= command_candidates(&context, shell, cache, &mut sink);
        path_completion = PathCompletion::Directories;
    } else {
        let status = complete_nested_rules(&context, shell, cache, &mut sink, mode, depth + 1);
        pending |= status.pending;
        path_completion = path_completion.merge(status.path_completion);
        let mut generic = GenericProvider;
        let status = generic.complete(&context, shell, cache, &mut sink, mode, path_completion);
        pending |= status.pending;
    }
    if pending {
        return (None, true);
    }
    let mut values = sink
        .finish()
        .into_iter()
        .map(|candidate| {
            let value = candidate.value;
            match candidate.description {
                Some(description) => format!("{value}\t{description}"),
                None => value.to_string(),
            }
        })
        .collect::<Vec<_>>();
    if let Some(marker) = nested_completion_path_marker(path_completion) {
        values.push(marker);
    }
    (Some(values), false)
}

fn complete_nested_rules(
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
    mode: CompletionMode,
    depth: usize,
) -> ProviderStatus {
    let Some(command) = context.command_name.as_deref() else {
        return ProviderStatus::default();
    };
    let (programs, pending) = cache.rule_programs(command);
    let mut status = ProviderStatus {
        pending,
        path_completion: if pending && programs.is_none() {
            PathCompletion::Suppress
        } else {
            PathCompletion::Inherit
        },
    };
    let Some(programs) = programs else {
        return status;
    };
    if programs.is_empty() {
        return status;
    }
    let (mut available_commands, shell_commands, command_snapshot_pending) =
        command_snapshot(shell, cache);
    status.pending |= command_snapshot_pending;
    for required in programs
        .iter()
        .flat_map(|loaded| loaded.required_commands.iter())
    {
        if shell.known_shell_command(required).is_some() {
            available_commands.insert(required.clone());
            continue;
        }
        match cache.command_available(required) {
            Some(true) => {
                available_commands.insert(required.clone());
            }
            Some(false) => {}
            None => status.pending = true,
        }
    }
    let mut shell_functions = shell.functions.iter().cloned().collect::<Vec<_>>();
    shell_functions.sort_unstable();
    let users = cache.users().to_vec();
    let groups = cache.groups().to_vec();
    let hosts = cache.hosts().to_vec();
    let process_ids = cache.process_ids().to_vec();
    let process_names = cache.process_names().to_vec();
    let network_interfaces = cache.network_interfaces().to_vec();
    let signals = platform_signal_snapshot();
    let passwd_records = cache.passwd_records().to_vec();
    let group_records = cache.group_records().to_vec();
    let evaluation_context = EvaluationContext {
        current_word: &context.query,
        words: &context.words,
        word_index: context.word_index,
        command_path: &context.command_path,
        environment: &shell.environment,
        working_directory: &shell.cwd,
        available_commands: Some(&available_commands),
        shell_commands: Some(&shell_commands),
        shell_functions: Some(&shell_functions),
        shell_variables: Some(&shell.variables),
        shell_variable_values: Some(&shell.variable_values),
        users: Some(&users),
        groups: Some(&groups),
        hosts: Some(&hosts),
        process_ids: Some(&process_ids),
        process_names: Some(&process_names),
        network_interfaces: Some(&network_interfaces),
        signals: Some(&signals),
        passwd_records: Some(&passwd_records),
        group_records: Some(&group_records),
        effective_user_id: shell.effective_user_id,
    };
    let evaluation_mode = match mode {
        CompletionMode::Passive => EvaluationMode::Passive,
        CompletionMode::ExplicitTab => EvaluationMode::ExplicitTab,
    };
    let fish_programs = programs
        .iter()
        .filter(|loaded| loaded.source == SourceKind::Fish)
        .collect::<Vec<_>>();
    let mut fish_evaluated = false;
    for loaded in programs.iter() {
        let evaluated = if loaded.source == SourceKind::Fish {
            if fish_evaluated {
                continue;
            }
            fish_evaluated = true;
            complete_loaded_programs(
                &fish_programs,
                &evaluation_context,
                context,
                shell,
                cache,
                sink,
                mode,
                evaluation_mode,
                depth,
                false,
                None,
            )
        } else {
            complete_loaded_program(
                loaded,
                &evaluation_context,
                context,
                shell,
                cache,
                sink,
                mode,
                evaluation_mode,
                depth,
                false,
                None,
            )
        };
        status.pending |= evaluated.pending;
        status.path_completion = status.path_completion.merge(evaluated.path_completion);
    }
    status
}

fn push_probe_values(
    context: &CompletionContext,
    sink: &mut CandidateSink,
    probe: &ProbeRequest,
    values: &[String],
) {
    for value in values {
        push_rule_candidate(
            context,
            sink,
            false,
            value.clone(),
            value.clone(),
            probe.description.clone(),
            probe.candidate_kind,
            probe.append,
            probe.source,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_rule_candidate(
    context: &CompletionContext,
    sink: &mut CandidateSink,
    preserve_order: bool,
    mut value: String,
    display: String,
    description: Option<String>,
    kind: RuleCandidateKind,
    append: AppendPolicy,
    source: SourceKind,
) {
    let append_space = match append {
        AppendPolicy::Space => true,
        AppendPolicy::NoSpace => false,
        AppendPolicy::Slash => {
            if !value.ends_with('/') {
                value.push('/');
            }
            false
        }
    };
    let display = if display.is_empty() {
        value.clone()
    } else {
        display
    };
    if let Some(candidate) = Candidate::new(
        &context.query,
        display,
        value,
        rule_candidate_kind(kind),
        append_space,
        source_bonus(source),
    ) {
        let candidate = candidate
            .with_source_mask(source_mask(source))
            .with_preserve_order(preserve_order);
        sink.push(match description {
            Some(description) => candidate.with_description(description),
            None => candidate,
        });
    }
}

fn source_mask(source: SourceKind) -> u8 {
    match source {
        SourceKind::Bash => 1 << 0,
        SourceKind::Fish => 1 << 1,
        SourceKind::Zsh => 1 << 2,
        SourceKind::User => 1 << 3,
    }
}

fn source_bonus(source: SourceKind) -> i64 {
    i64::from(source.priority()) * 4
}

fn rule_candidate_kind(kind: RuleCandidateKind) -> CandidateKind {
    match kind {
        RuleCandidateKind::Option => CandidateKind::Option,
        RuleCandidateKind::Subcommand => CandidateKind::Subcommand,
        RuleCandidateKind::Value => CandidateKind::Value,
        RuleCandidateKind::Command => CandidateKind::Command,
        RuleCandidateKind::Directory => CandidateKind::Directory,
        RuleCandidateKind::File => CandidateKind::File,
        RuleCandidateKind::User => CandidateKind::User,
        RuleCandidateKind::Group => CandidateKind::Group,
        RuleCandidateKind::Host => CandidateKind::Host,
        RuleCandidateKind::Service => CandidateKind::Service,
        RuleCandidateKind::Signal => CandidateKind::Signal,
        RuleCandidateKind::Variable => CandidateKind::Variable,
        RuleCandidateKind::Job => CandidateKind::Job,
    }
}

#[derive(Default)]
pub struct GenericProvider;

impl CompletionProvider for GenericProvider {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn complete(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        cache: &mut CompletionCache,
        sink: &mut CandidateSink,
        _mode: CompletionMode,
        path_completion: PathCompletion,
    ) -> ProviderStatus {
        let mut status = ProviderStatus::default();

        if variable_query(context, shell, sink) {
            return status;
        }
        if user_query(context, cache, sink) {
            status.pending |= cache.snapshots_pending();
            return status;
        }
        if host_query(context, cache, sink) {
            status.pending |= cache.snapshots_pending();
        }

        if context.command_position {
            status.pending |= command_candidates(context, shell, cache, sink);
        }

        let explicit_path = context.query.contains('/')
            || context.query.starts_with('.')
            || context.query.starts_with('~');
        if (!context.command_position || explicit_path)
            && path_completion != PathCompletion::Suppress
        {
            let path_status = path_candidates(
                context,
                shell,
                cache,
                sink,
                path_completion == PathCompletion::Directories,
            );
            status.pending |= path_status.pending;
        }

        status
    }
}

const KEYWORDS: &[(&str, &str)] = &[
    ("if", "Begin a conditional command"),
    ("then", "Begin the successful conditional branch"),
    ("elif", "Add another conditional branch"),
    ("else", "Begin the fallback conditional branch"),
    ("fi", "End a conditional command"),
    ("for", "Iterate over a list of words"),
    ("while", "Repeat while a command succeeds"),
    ("until", "Repeat until a command succeeds"),
    ("do", "Begin a loop body"),
    ("done", "End a loop body"),
    ("case", "Match a word against patterns"),
    ("in", "Introduce a word list or case patterns"),
    ("esac", "End a case command"),
    ("select", "Build an interactive selection loop"),
    ("function", "Define a shell function"),
    ("time", "Measure pipeline execution time"),
    ("coproc", "Start an asynchronous coprocess"),
    ("[[", "Begin a conditional expression"),
    ("((", "Begin an arithmetic expression"),
    ("!", "Negate a pipeline's exit status"),
    ("{", "Begin a grouped command"),
];

fn command_candidates(
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
) -> bool {
    let query = &context.query;
    for name in &shell.aliases {
        push_named(query, name, CandidateKind::Alias, shell, sink);
    }
    for name in &shell.functions {
        push_named(query, name, CandidateKind::Function, shell, sink);
    }
    for name in &shell.builtins {
        push_named(query, name, CandidateKind::Builtin, shell, sink);
    }
    for &(name, description) in KEYWORDS {
        if let Some(candidate) = Candidate::from_borrowed(
            query,
            name,
            name,
            CandidateKind::Keyword,
            true,
            shell.command_recency_bonus(name),
        ) {
            sink.push(candidate.with_description(description));
        }
    }
    cache.for_each_command(query, |name| {
        push_named(query, name, CandidateKind::Command, shell, sink);
        true
    })
}

fn push_named(
    query: &str,
    name: &str,
    kind: CandidateKind,
    shell: &ShellSnapshot,
    sink: &mut CandidateSink,
) {
    if let Some(candidate) = Candidate::from_borrowed(
        query,
        name,
        name,
        kind,
        true,
        shell.command_recency_bonus(name),
    ) {
        sink.push(candidate);
    }
}

fn variable_query(
    context: &CompletionContext,
    shell: &ShellSnapshot,
    sink: &mut CandidateSink,
) -> bool {
    let (prefix, braced) = if let Some(prefix) = context.query.strip_prefix("${") {
        (prefix, true)
    } else if let Some(prefix) = context.query.strip_prefix('$') {
        (prefix, false)
    } else {
        return false;
    };

    for name in &shell.variables {
        let display = if braced {
            format!("${{{name}}}")
        } else {
            format!("${name}")
        };
        if let Some(candidate) = Candidate::new(
            prefix,
            name.clone(),
            display.clone(),
            CandidateKind::Variable,
            false,
            0,
        ) {
            sink.push(Candidate {
                display: display.into(),
                ..candidate
            });
        }
    }
    true
}

fn user_query(
    context: &CompletionContext,
    cache: &CompletionCache,
    sink: &mut CandidateSink,
) -> bool {
    let Some(prefix) = context.query.strip_prefix('~') else {
        return false;
    };
    if prefix.contains('/') {
        return false;
    }
    for user in cache.users() {
        if let Some(candidate) = Candidate::new(
            prefix,
            user.clone(),
            format!("~{user}/"),
            CandidateKind::User,
            false,
            0,
        ) {
            sink.push(candidate);
        }
    }
    true
}

fn host_query(
    context: &CompletionContext,
    cache: &CompletionCache,
    sink: &mut CandidateSink,
) -> bool {
    let Some((user, prefix)) = context.query.rsplit_once('@') else {
        return false;
    };
    for host in cache.hosts() {
        if let Some(candidate) = Candidate::new(
            prefix,
            host.clone(),
            format!("{user}@{host}"),
            CandidateKind::Host,
            false,
            0,
        ) {
            sink.push(candidate);
        }
    }
    true
}

fn path_candidates(
    context: &CompletionContext,
    shell: &ShellSnapshot,
    cache: &mut CompletionCache,
    sink: &mut CandidateSink,
    directories_only: bool,
) -> ProviderStatus {
    let (typed_parent, leaf) = context.typed_parent_and_leaf();
    let Some(directory) = resolve_parent(&typed_parent, shell) else {
        return ProviderStatus::default();
    };
    let key = cache.request_directory(directory, &leaf);
    let Some((entries, _truncated, refreshing)) = cache.directory_entries(&key) else {
        return ProviderStatus {
            pending: cache.scan_available(),
            ..ProviderStatus::default()
        };
    };

    for entry in entries {
        if directories_only && entry.kind != EntryKind::Directory {
            continue;
        }
        if context.command_position
            && entry.kind != EntryKind::Directory
            && entry.kind != EntryKind::Executable
        {
            continue;
        }
        let mut value = format!("{typed_parent}{}", entry.name);
        let (kind, append_space) = match entry.kind {
            EntryKind::Directory => {
                value.push('/');
                (CandidateKind::Directory, false)
            }
            EntryKind::Executable => (CandidateKind::Executable, true),
            EntryKind::File => (CandidateKind::File, true),
        };
        if let Some(candidate) =
            Candidate::new(&leaf, entry.name.clone(), value, kind, append_space, 0)
        {
            sink.push(candidate);
        }
    }

    ProviderStatus {
        pending: refreshing,
        ..ProviderStatus::default()
    }
}

fn resolve_parent(typed_parent: &str, shell: &ShellSnapshot) -> Option<PathBuf> {
    if typed_parent.is_empty() {
        return Some(shell.cwd.clone());
    }
    if typed_parent == "~/" {
        return shell.home.clone();
    }
    if let Some(relative) = typed_parent.strip_prefix("~/") {
        return shell.home.as_ref().map(|home| home.join(relative));
    }
    let path = PathBuf::from(typed_parent);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(shell.cwd.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_test_replay_distinguishes_unix_file_types() {
        let request = |path: &str, operator: &str| FilesystemRequest {
            request_id: "test".into(),
            kind: FilesystemRequestKind::Test,
            dialect: crate::rules::script::ScriptDialect::Fish,
            path: path.into(),
            operator: Some(operator.into()),
        };
        assert_eq!(
            resolve_filesystem_request(&request("/dev/null", "-c"), Path::new("/")),
            ["true"]
        );
        assert!(resolve_filesystem_request(&request("/dev/null", "-b"), Path::new("/")).is_empty());
        assert!(resolve_filesystem_request(&request("", "-r"), Path::new("/")).is_empty());

        let directory = std::env::temp_dir().join(format!(
            "bashlume-provider-types-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        let link = directory.join("link");
        fs::write(&target, "value").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            resolve_filesystem_request(&request(link.to_str().unwrap(), "-L"), Path::new("/"),),
            ["true"]
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn filesystem_replay_refreshes_a_pending_rule_evaluation() {
        let directory = std::env::temp_dir().join(format!(
            "bashlume-provider-replay-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("values"), "alpha\nbeta\n").unwrap();
        let module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Bash,
            "replay.bash",
            r#"_replay() {
  local value
  while IFS= read -r value; do COMPREPLY+=("$value"); done < values
}
complete -F _replay replay
"#,
        )
        .unwrap();
        let loaded = LoadedProgram {
            pack_id: [0; 32],
            pack_name: "replay-test".into(),
            pack_version: "1.0.0".into(),
            source: SourceKind::Bash,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "replay".into(),
                registrations: vec!["replay".into()],
                source_path: "replay.bash".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-or-later".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![module],
            }),
        };
        let shell = ShellSnapshot {
            cwd: directory.clone(),
            ..ShellSnapshot::default()
        };
        let completion_context = CompletionContext::analyze("replay ", 7);
        let evaluation_context = EvaluationContext {
            current_word: &completion_context.query,
            words: &completion_context.words,
            word_index: completion_context.word_index,
            command_path: &completion_context.command_path,
            environment: &shell.environment,
            working_directory: &shell.cwd,
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
            effective_user_id: 0,
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let mut sink = CandidateSink::new(128);
        let first = complete_loaded_program(
            &loaded,
            &evaluation_context,
            &completion_context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            EvaluationMode::ExplicitTab,
            0,
            false,
            None,
        );
        assert!(first.pending);
        assert!(sink.finish().is_empty());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            cache.poll();
            let mut sink = CandidateSink::new(128);
            let status = complete_loaded_program(
                &loaded,
                &evaluation_context,
                &completion_context,
                &shell,
                &mut cache,
                &mut sink,
                CompletionMode::ExplicitTab,
                EvaluationMode::ExplicitTab,
                0,
                false,
                None,
            );
            if !status.pending {
                assert_eq!(
                    sink.finish()
                        .into_iter()
                        .map(|candidate| candidate.value.to_string())
                        .collect::<Vec<_>>(),
                    ["alpha", "beta"]
                );
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn replay_candidate_retention_is_aggregate_bounded() {
        let large_candidate = |suffix: u8| {
            let mut value = String::with_capacity(3 * 1024 * 1024);
            value.push(char::from(b'a' + suffix));
            let mut display = String::with_capacity(3 * 1024 * 1024);
            display.push(char::from(b'a' + suffix));
            EmittedCandidate {
                candidate: crate::rules::ir::CandidateTemplate {
                    value,
                    display,
                    description: None,
                    kind: RuleCandidateKind::Option,
                    append: AppendPolicy::Space,
                    preserve_order: false,
                },
                source: SourceKind::Fish,
            }
        };
        let mut states = HashMap::new();
        for suffix in 0..3 {
            states.insert(
                ReplayKey {
                    pack_id: [suffix; 32],
                    source_path: format!("{suffix}.fish"),
                    depth: 0,
                    explicit: true,
                },
                ReplayState {
                    evaluated: Some((
                        1,
                        Arc::new(EvaluationResult {
                            candidates: vec![large_candidate(suffix)],
                            ..EvaluationResult::default()
                        }),
                    )),
                    ..ReplayState::default()
                },
            );
        }
        trim_replay_states(&mut states, MAX_REPLAY_BYTES);
        assert!(states.values().map(replay_state_bytes).sum::<usize>() <= MAX_REPLAY_BYTES);
        assert!(states.len() < 3);
    }

    #[test]
    fn filesystem_read_replay_accepts_only_bounded_regular_files() {
        let directory = std::env::temp_dir().join(format!(
            "bashlume-provider-read-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("input");
        fs::write(&path, "first\n\nsecond\n").unwrap();
        assert_eq!(
            resolve_filesystem_read(path.to_str().unwrap(), Path::new("/")),
            ["first", "", "second"]
        );
        assert!(resolve_filesystem_read("/dev/null", Path::new("/")).is_empty());
        fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(resolve_filesystem_read(path.to_str().unwrap(), Path::new("/")).is_empty());
        fs::remove_dir_all(directory).unwrap();
    }
}
