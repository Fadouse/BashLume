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
    evaluate_runtime_program_dependencies_with_outcomes, evaluate_runtime_programs_with_outcomes,
    evaluate_runtime_with_outcomes, nested_completion_path_marker, platform_signal_snapshot,
};
use crate::shell::ShellSnapshot;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderStatus {
    pub pending: bool,
    pub path_completion: PathCompletion,
    // Internal provenance used to decide whether an otherwise complete
    // candidate set is safe to publish while snapshot workers are pending.
    pub(super) snapshot_dependent: bool,
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

    fn reset_transient(&mut self, _cache: &mut CompletionCache) {}
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    pack_id: [u8; 32],
    source_path: String,
    depth: usize,
    explicit: bool,
    // Distinct blocks may legitimately share pack/source metadata. Arc
    // identities remain stable for the lifetime of one immutable cache
    // revision and prevent those programs from aliasing replay state.
    program_identities: Vec<usize>,
    // Quick provisional results must not survive a cache replacement that
    // happens to retain the same pack metadata and source path. Ordinary
    // replay keys leave this at zero and use `response_generation` for their
    // accepted-outcome cache validation.
    program_revision: u64,
    // Evaluation can stop at this bound, so a result produced for a smaller
    // sink must never be reused after max_candidates grows.
    candidate_limit: usize,
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
    provisional_snapshot_dependent: bool,
    dependencies_discovered: bool,
}

#[derive(Default)]
pub struct RuleProvider {
    replay_context: Option<(String, usize, PathBuf, u64)>,
    replay_states: HashMap<ReplayKey, ReplayState>,
    quick_provisional: Arc<[EmittedCandidate]>,
    quick_program_key: Option<ReplayKey>,
    quick_path_completion: PathCompletion,
    quick_redraws: u8,
    quick_evaluated: bool,
    cross_source_deferred: bool,
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

fn replay_map_bytes(states: &HashMap<ReplayKey, ReplayState>) -> usize {
    states
        .capacity()
        .saturating_mul(std::mem::size_of::<(ReplayKey, ReplayState)>().saturating_add(1))
}

fn replay_key_bytes(key: &ReplayKey) -> usize {
    std::mem::size_of::<ReplayKey>()
        .saturating_add(key.source_path.capacity())
        .saturating_add(
            key.program_identities
                .capacity()
                .saturating_mul(std::mem::size_of::<usize>()),
        )
}

fn replay_entry_bytes(key: &ReplayKey, state: &ReplayState) -> usize {
    replay_key_bytes(key).saturating_add(replay_state_bytes(state))
}

fn invalidate_replay_program_revision(
    states: &mut HashMap<ReplayKey, ReplayState>,
    current: &ReplayKey,
) {
    states.retain(|key, _| {
        key.program_revision == current.program_revision
            || key.pack_id != current.pack_id
            || key.source_path != current.source_path
            || key.depth != current.depth
            || key.explicit != current.explicit
    });
}

fn replay_states_bytes(states: &HashMap<ReplayKey, ReplayState>) -> usize {
    replay_map_bytes(states).saturating_add(
        states
            .iter()
            .map(|(key, state)| replay_entry_bytes(key, state))
            .sum::<usize>(),
    )
}

fn emitted_candidates_bytes(candidates: &[EmittedCandidate]) -> usize {
    if candidates.is_empty() {
        return 0;
    }
    candidates
        .iter()
        .map(emitted_candidate_bytes)
        .sum::<usize>()
        .saturating_add(2 * std::mem::size_of::<usize>())
}

fn replay_context_bytes(context: &Option<(String, usize, PathBuf, u64)>) -> usize {
    context.as_ref().map_or(0, |(line, _, cwd, _)| {
        std::mem::size_of::<(String, usize, PathBuf, u64)>()
            .saturating_add(line.capacity())
            .saturating_add(cwd.as_os_str().as_bytes().len())
    })
}

fn quick_replay_bytes(provider: &RuleProvider) -> usize {
    emitted_candidates_bytes(&provider.quick_provisional).saturating_add(
        provider
            .quick_program_key
            .as_ref()
            .map_or(0, replay_key_bytes),
    )
}

fn trim_replay_states(
    states: &mut HashMap<ReplayKey, ReplayState>,
    configured_limit: usize,
    reserved_bytes: usize,
) {
    let limit = configured_limit.min(MAX_REPLAY_BYTES);
    if reserved_bytes >= limit {
        states.clear();
        states.shrink_to_fit();
        return;
    }
    let mut total = reserved_bytes.saturating_add(replay_states_bytes(states));
    while total > limit {
        // Clone only the one key being evicted. Building a complete cloned-key
        // vector here would itself bypass the replay reservation.
        let Some((key, bytes)) = states
            .iter()
            .max_by_key(|(key, state)| replay_entry_bytes(key, state))
            .map(|(key, state)| (key.clone(), replay_entry_bytes(key, state)))
        else {
            break;
        };
        states.remove(&key);
        total = total.saturating_sub(bytes);
    }
    states.shrink_to_fit();
    if reserved_bytes.saturating_add(replay_states_bytes(states)) > limit {
        states.clear();
        states.shrink_to_fit();
    }
}

impl RuleProvider {
    fn clear_retained_semantics(&mut self) {
        self.replay_states.clear();
        self.quick_provisional = Arc::default();
        self.quick_program_key = None;
        self.quick_path_completion = PathCompletion::Inherit;
        self.quick_redraws = 0;
        self.quick_evaluated = false;
        self.cross_source_deferred = false;
    }

    fn retained_replay_bytes(&self) -> usize {
        replay_states_bytes(&self.replay_states)
            .saturating_add(quick_replay_bytes(self))
            .saturating_add(replay_context_bytes(&self.replay_context))
    }

    fn sync_replay_reservation(&self, cache: &mut CompletionCache) {
        cache.set_replay_reservation(self.retained_replay_bytes());
    }

    fn trim_and_sync_replay(&mut self, cache: &mut CompletionCache) {
        let limit = cache.replay_byte_limit().min(MAX_REPLAY_BYTES);
        let mut context_bytes = replay_context_bytes(&self.replay_context);
        if context_bytes > limit {
            self.clear_retained_semantics();
            self.replay_context = None;
            context_bytes = 0;
        }
        let mut quick_bytes = quick_replay_bytes(self);
        if context_bytes.saturating_add(quick_bytes) > limit {
            self.quick_provisional = Arc::default();
            self.quick_program_key = None;
            self.quick_path_completion = PathCompletion::Inherit;
            self.quick_redraws = 0;
            self.quick_evaluated = false;
            quick_bytes = 0;
        }
        trim_replay_states(
            &mut self.replay_states,
            limit,
            context_bytes.saturating_add(quick_bytes),
        );
        self.sync_replay_reservation(cache);
    }

    fn invalidate_quick_program_if_changed(&mut self, current: Option<&ReplayKey>) {
        if self
            .quick_program_key
            .as_ref()
            .is_some_and(|stored| Some(stored) != current)
        {
            self.quick_provisional = Arc::default();
            self.quick_program_key = None;
            self.quick_path_completion = PathCompletion::Inherit;
            self.quick_redraws = 0;
            self.quick_evaluated = false;
        }
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

    fn reset_transient(&mut self, cache: &mut CompletionCache) {
        self.clear_retained_semantics();
        self.replay_states.shrink_to_fit();
        self.replay_context = None;
        self.sync_replay_reservation(cache);
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
        self.trim_and_sync_replay(cache);
        let Some(command) = context.command_name.as_deref() else {
            self.clear_retained_semantics();
            self.replay_context = None;
            self.sync_replay_reservation(cache);
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
            self.clear_retained_semantics();
            self.sync_replay_reservation(cache);
        }
        let (programs, pending) = cache.rule_programs(command);
        let mut status = ProviderStatus {
            pending,
            path_completion: if pending {
                PathCompletion::Suppress
            } else {
                PathCompletion::Inherit
            },
            snapshot_dependent: false,
        };
        if pending {
            // A non-final incremental response is decode progress only. Clear
            // every retained semantic result, including the empty-chunk case,
            // until the terminal response establishes the complete program.
            self.clear_retained_semantics();
            self.sync_replay_reservation(cache);
            return status;
        }
        let Some(programs) = programs else {
            self.sync_replay_reservation(cache);
            return status;
        };
        if programs.is_empty() {
            self.clear_retained_semantics();
            self.sync_replay_reservation(cache);
            return status;
        }
        status.pending |= cache.snapshots_pending();
        let snapshots_unavailable = cache.snapshots_unavailable();
        let fish_program_count = programs
            .iter()
            .filter(|loaded| loaded.source == SourceKind::Fish)
            .count();
        let quick_program_key = (fish_program_count == 1).then(|| {
            let loaded = programs
                .iter()
                .find(|loaded| loaded.source == SourceKind::Fish)
                .expect("the counted Fish program must exist");
            let mut key = loaded_replay_key(&[loaded], 0, true, sink.candidate_limit());
            key.program_revision = cache.rule_program_revision(command).unwrap_or(0);
            key
        });
        self.invalidate_quick_program_if_changed(quick_program_key.as_ref());
        let (mut available_commands, shell_commands, command_snapshot_pending) =
            command_snapshot(shell, cache);
        let mut command_availability_pending = command_snapshot_pending;
        status.pending |= command_snapshot_pending;
        // A non-final incremental chunk is not a complete rule program: a
        // later source can erase or replace every candidate seen so far.
        // Neither a newly evaluated nor a retained quick result may be
        // published until the worker has delivered the terminal chunk.
        if !pending && mode == CompletionMode::ExplicitTab && context.query.starts_with("--") {
            if self.quick_redraws > 0 && !command_snapshot_pending && !snapshots_unavailable {
                self.quick_redraws -= 1;
                push_emitted_candidates(context, sink, &self.quick_provisional);
                status.path_completion = status.path_completion.merge(self.quick_path_completion);
                status.pending = true;
                self.trim_and_sync_replay(cache);
                return status;
            }
            if command_snapshot_pending || snapshots_unavailable {
                self.quick_provisional = Arc::default();
                self.quick_path_completion = PathCompletion::Inherit;
                self.quick_redraws = 0;
                self.quick_evaluated = false;
            }
            if !command_snapshot_pending
                && !snapshots_unavailable
                && !self.quick_evaluated
                && fish_program_count == 1
                && programs
                    .iter()
                    .any(|loaded| loaded.source == SourceKind::Fish)
            {
                self.quick_evaluated = true;
                self.quick_program_key = quick_program_key.clone();
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
                        sink.candidate_limit(),
                        &HashMap::new(),
                        &HashMap::new(),
                        true,
                        true,
                    ) {
                        Ok(mut evaluated)
                            if evaluated.provisional_yielded
                                && (!status.pending || evaluated.snapshot_providers.is_empty()) =>
                        {
                            let provisional = std::mem::take(&mut evaluated.provisional_candidates);
                            let retained_bytes = emitted_candidates_bytes(&provisional);
                            let replay_limit = cache.replay_byte_limit().min(MAX_REPLAY_BYTES);
                            let quick_key_bytes =
                                quick_program_key.as_ref().map_or(0, replay_key_bytes);
                            let retained_total = replay_context_bytes(&self.replay_context)
                                .saturating_add(quick_key_bytes)
                                .saturating_add(retained_bytes);
                            if retained_total <= replay_limit {
                                trim_replay_states(
                                    &mut self.replay_states,
                                    cache.replay_byte_limit(),
                                    retained_total,
                                );
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
                                self.trim_and_sync_replay(cache);
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
                None => {
                    status.pending = true;
                    command_availability_pending = true;
                }
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
        if !snapshots_unavailable
            && !self.cross_source_deferred
            && replay_context_bytes(&self.replay_context)
                <= cache.replay_byte_limit().min(MAX_REPLAY_BYTES)
            && mode == CompletionMode::ExplicitTab
            && context.query.starts_with("--")
            && programs
                .iter()
                .any(|loaded| loaded.source == SourceKind::Fish)
            && programs
                .iter()
                .any(|loaded| loaded.source != SourceKind::Fish)
        {
            let mut non_fish_pending = false;
            let mut non_fish_snapshot_dependent = false;
            for loaded in programs
                .iter()
                .filter(|loaded| loaded.source != SourceKind::Fish)
            {
                let evaluated = complete_loaded_program(
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
                );
                non_fish_pending |= evaluated.pending;
                non_fish_snapshot_dependent |= evaluated.snapshot_dependent;
                status.path_completion = status.path_completion.merge(evaluated.path_completion);
                self.trim_and_sync_replay(cache);
            }
            if !non_fish_pending
                && !command_availability_pending
                && (!status.pending || !non_fish_snapshot_dependent)
                && sink.has_strong_matches()
            {
                // A completely evaluated source cannot be invalidated by Fish
                // registration erasure, which is scoped to Fish provenance.
                // Publish that source now and finish the independent Fish
                // evaluator on the next redraw instead of blocking Readline.
                self.cross_source_deferred = true;
                status.pending = true;
                status.path_completion = PathCompletion::Suppress;
                self.trim_and_sync_replay(cache);
                return status;
            }
        }
        let fish_programs = programs
            .iter()
            .filter(|loaded| loaded.source == SourceKind::Fish)
            .collect::<Vec<_>>();
        let mut fish_evaluated = false;
        let mut unresolved_fish = false;
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
            status.snapshot_dependent |= evaluated.snapshot_dependent;
            if loaded.source == SourceKind::Fish
                && (evaluated.pending || evaluated.snapshot_dependent && cache.snapshots_pending())
            {
                unresolved_fish = true;
            }
            status.path_completion = status.path_completion.merge(evaluated.path_completion);
            self.trim_and_sync_replay(cache);
        }
        if unresolved_fish {
            // No other source may override this temporary policy: a later
            // Fish registration can still select --no-files.
            status.path_completion = PathCompletion::Suppress;
        }
        self.trim_and_sync_replay(cache);
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
    status.snapshot_dependent |= !evaluated.snapshot_providers.is_empty();
    push_emitted_candidates(context, sink, &evaluated.candidates);
}

fn loaded_replay_key(
    loaded: &[&LoadedProgram],
    depth: usize,
    explicit: bool,
    candidate_limit: usize,
) -> ReplayKey {
    if let [loaded] = loaded {
        return ReplayKey {
            pack_id: loaded.pack_id,
            source_path: loaded.program.source_path.clone(),
            depth,
            explicit,
            program_identities: vec![Arc::as_ptr(&loaded.program) as usize],
            program_revision: 0,
            candidate_limit,
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
        program_identities: loaded
            .iter()
            .map(|loaded| Arc::as_ptr(&loaded.program) as usize)
            .collect(),
        program_revision: 0,
        candidate_limit,
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
    dependency_discovery: bool,
) -> Result<EvaluationResult, crate::rules::vm::VmError> {
    if dependency_discovery {
        let programs = loaded
            .iter()
            .map(|loaded| (loaded.program.as_ref(), loaded.trust))
            .collect::<Vec<_>>();
        return evaluate_runtime_program_dependencies_with_outcomes(
            &programs,
            evaluation_context,
            SourceKind::Fish,
            evaluation_mode,
            candidate_limit,
            probe_results,
            completion_results,
        );
    }
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
    let mut replay_key = loaded_replay_key(
        loaded,
        depth,
        evaluation_mode == EvaluationMode::ExplicitTab,
        sink.candidate_limit(),
    );
    replay_key.program_revision = context
        .command_name
        .as_deref()
        .and_then(|command| cache.rule_program_revision(command))
        .unwrap_or(0);
    if let Some(states) = replay_states.as_deref_mut() {
        invalidate_replay_program_revision(states, &replay_key);
    }
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
    let mut provisional_snapshot_dependent = replay.provisional_snapshot_dependent;
    let mut dependencies_discovered = replay.dependencies_discovered;
    let mut force_dependency_discovery = false;
    status.snapshot_dependent |= provisional_snapshot_dependent;
    if cache.snapshots_unavailable() && provisional_snapshot_dependent {
        provisional_candidates = Arc::default();
        provisional_redraws = 0;
    }
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
                    provisional_snapshot_dependent,
                    dependencies_discovered,
                },
            );
        }
        return status;
    }
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
            if dependencies_discovered && !dependencies_changed {
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
                            provisional_snapshot_dependent,
                            dependencies_discovered,
                        },
                    );
                }
                return status;
            }
            // A quick Fish pass stops at its first asynchronous dependency.
            // Run one complete, non-publishing replay with unresolved outcomes
            // to discover the remaining independent requests, so probes can
            // execute concurrently instead of forming serial worker waves.
            force_dependency_discovery = true;
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
                                provisional_snapshot_dependent: false,
                                dependencies_discovered: true,
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
                        provisional_snapshot_dependent: false,
                        dependencies_discovered: true,
                    },
                );
            }
            return status;
        }
    }
    let allow_provisional_yield = !cache.snapshots_unavailable()
        && !force_dependency_discovery
        && !dependencies_discovered
        && allow_cross_program_provisional
        && all_fish
        && evaluation_mode == EvaluationMode::ExplicitTab
        && context.query.starts_with("--")
        && provisional_candidates.is_empty();
    for round in 0..=8 {
        let mut evaluated = match evaluate_loaded_programs(
            loaded,
            evaluation_context,
            evaluation_mode,
            sink.candidate_limit(),
            &probe_results,
            &completion_results,
            allow_provisional_yield,
            true,
            force_dependency_discovery,
        ) {
            Ok(evaluated) => evaluated,
            Err(error) => {
                cache.record_rule_error(format!("{pack_name}: {error}"));
                return status;
            }
        };
        if evaluated.optimization_incomplete {
            evaluated = match evaluate_loaded_programs(
                loaded,
                evaluation_context,
                evaluation_mode,
                sink.candidate_limit(),
                &probe_results,
                &completion_results,
                false,
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
        let evaluation_snapshot_dependent = !evaluated.snapshot_providers.is_empty();
        status.snapshot_dependent |= evaluation_snapshot_dependent;
        probes = evaluated.probes.clone();
        completion_requests = evaluated.completion_requests.clone();
        filesystem_requests = evaluated.filesystem_requests.clone();
        if evaluated.provisional_yielded {
            provisional_snapshot_dependent = evaluation_snapshot_dependent;
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
                        provisional_redraws: 0,
                        provisional_snapshot_dependent,
                        dependencies_discovered: false,
                    },
                );
            }
            return status;
        }
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
            provisional_snapshot_dependent |= evaluation_snapshot_dependent;
            dependencies_discovered |= !allow_provisional_yield;
            if all_fish {
                // Until every Fish dependency resolves, a later registration
                // can still select --no-files. Never expose generic paths from
                // an incomplete Fish replay, even when it yielded no option.
                provisional_path_completion = PathCompletion::Suppress;
            }
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
                        provisional_snapshot_dependent,
                        dependencies_discovered,
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
                    provisional_snapshot_dependent: false,
                    dependencies_discovered: true,
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

fn literal_shell_word_is_empty(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0_usize;
    let mut saw_quotes = false;
    while index < bytes.len() {
        if index + 1 < bytes.len()
            && matches!(
                (bytes[index], bytes[index + 1]),
                (b'\'', b'\'') | (b'"', b'"')
            )
        {
            saw_quotes = true;
            index += 2;
        } else {
            return false;
        }
    }
    saw_quotes
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
    let context = CompletionContext::analyze_with_interactive_comments(
        &request.line,
        request.line.len(),
        !shell.interactive_comments_disabled,
    );
    if context.in_comment {
        return (Some(Vec::new()), false);
    }
    if context
        .command_name
        .as_deref()
        .is_some_and(literal_shell_word_is_empty)
    {
        return (Some(Vec::new()), false);
    }
    let mut sink = CandidateSink::new(4096);
    let mut pending = false;
    let mut path_completion = PathCompletion::Inherit;
    if context.command_position {
        pending |= command_candidates(&context, shell, cache, &mut sink);
        path_completion = PathCompletion::Directories;
    } else {
        let status = complete_nested_rules(&context, shell, cache, &mut sink, mode, depth + 1);
        if status.snapshot_dependent && cache.snapshots_unavailable() {
            return (Some(Vec::new()), false);
        }
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
        path_completion: if pending {
            PathCompletion::Suppress
        } else {
            PathCompletion::Inherit
        },
        snapshot_dependent: false,
    };
    let Some(programs) = programs else {
        return status;
    };
    if pending || programs.is_empty() {
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
    let mut unresolved_fish = false;
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
        status.snapshot_dependent |= evaluated.snapshot_dependent;
        let unresolved_snapshot = evaluated.snapshot_dependent && cache.snapshots_pending();
        status.pending |= unresolved_snapshot;
        if loaded.source == SourceKind::Fish && (evaluated.pending || unresolved_snapshot) {
            unresolved_fish = true;
        }
        status.path_completion = status.path_completion.merge(evaluated.path_completion);
    }
    if unresolved_fish {
        status.path_completion = PathCompletion::Suppress;
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
        if context.in_comment {
            return status;
        }

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
    fn nested_completion_inside_a_comment_emits_nothing() {
        let request = CompletionRequest {
            line: "echo value # Cargo".into(),
        };
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let (values, pending) = nested_completion_values_at_depth(
            &request,
            &shell,
            &mut cache,
            CompletionMode::ExplicitTab,
            0,
        );
        assert_eq!(values, Some(Vec::new()));
        assert!(!pending);
    }

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
            retained_bytes: 0,
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
    fn fish_dependency_discovery_schedules_independent_probes_without_publishing() {
        let mut module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Fish,
            "discovery.fish",
            "complete -c discovery -n 'sleep 0.05; and sleep 0.2' -l first\ncomplete -c discovery -n 'sleep 1' -l second\n",
        )
        .unwrap();
        module.probe_capabilities = vec!["sleep".into()];
        let loaded = LoadedProgram {
            pack_id: [1; 32],
            pack_name: "discovery-test".into(),
            pack_version: "1.0.0".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Verified { key_id: [2; 32] },
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "discovery".into(),
                registrations: vec!["discovery".into()],
                source_path: "discovery.fish".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-or-later".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![module],
            }),
        };
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let completion_context = CompletionContext::analyze("discovery --", 12);
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
            effective_user_id: 1000,
        };
        let full = evaluate_loaded_programs(
            &[&loaded],
            &evaluation_context,
            EvaluationMode::ExplicitTab,
            128,
            &HashMap::new(),
            &HashMap::new(),
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(full.probes.len(), 2);

        // Each probe admission reserves raw, lossy, and parsed output at its
        // one-MiB VM limit. Keep this concurrency test above that independent
        // safety budget so it exercises scheduling rather than rejection.
        let mut cache = CompletionCache::new(64 * 1024 * 1024, 128);
        let mut replay_states = HashMap::new();

        for expected_probes in [1, 2] {
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
                true,
                Some(&mut replay_states),
            );
            let candidates = sink.finish();
            let state = replay_states.values().next().unwrap();
            assert!(
                status.pending,
                "round={expected_probes} probes={} completions={} candidates={:?}",
                state.probes.len(),
                state.completion_requests.len(),
                candidates
                    .iter()
                    .map(|candidate| candidate.value.as_ref())
                    .collect::<Vec<_>>()
            );
            assert!(candidates.is_empty());
            assert_eq!(
                state.probes.len(),
                expected_probes,
                "requests={:?}",
                state
                    .probes
                    .iter()
                    .map(|request| (&request.key.executable, &request.key.arguments))
                    .collect::<Vec<_>>()
            );
        }
        assert!(
            replay_states
                .values()
                .next()
                .unwrap()
                .dependencies_discovered
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
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
                true,
                Some(&mut replay_states),
            );
            assert!(
                status.pending,
                "dependency replay settled early: errors={:?} state={:?}",
                cache.probe_errors(),
                replay_states.values().next().map(|state| (
                    state.probes.len(),
                    state.probe_results.len(),
                    state.dependencies_discovered
                ))
            );
            assert!(sink.finish().is_empty());
            if replay_states
                .values()
                .next()
                .unwrap()
                .probe_results
                .keys()
                .any(|key| key.arguments == ["0.2"])
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a completed dependency was not replayed while another remained unresolved: probes={:?} results={:?} errors={:?}",
                replay_states
                    .values()
                    .next()
                    .unwrap()
                    .probes
                    .iter()
                    .map(|probe| (&probe.key.executable, &probe.key.arguments))
                    .collect::<Vec<_>>(),
                replay_states.values().next().unwrap().probe_results,
                cache.probe_errors(),
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        cache.cancel_probes();
    }

    #[test]
    fn unrelated_snapshot_pending_does_not_block_strong_non_fish_source() {
        let program = |source, path: &str, static_rules| LoadedProgram {
            pack_id: [path.len() as u8; 32],
            pack_name: path.into(),
            pack_version: "1".into(),
            source,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: path.into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules,
                probes: Vec::new(),
                scripts: Vec::new(),
            }),
        };
        let fish = program(SourceKind::Fish, "empty.fish", Vec::new());
        let bash = program(
            SourceKind::Bash,
            "strong.bash",
            vec![crate::rules::ir::StaticRule {
                when: vec![crate::rules::ir::PredicateOp::True],
                path_completion: PathCompletion::Inherit,
                candidates: vec![crate::rules::ir::CandidateTemplate {
                    value: "--strong".into(),
                    display: "--strong".into(),
                    description: None,
                    kind: RuleCandidateKind::Option,
                    append: AppendPolicy::Space,
                    preserve_order: false,
                }],
            }],
        );
        let context = CompletionContext::analyze("demo --", 7);
        let shell = ShellSnapshot {
            builtins: (0..MAX_COMMAND_SNAPSHOT)
                .map(|index| format!("builtin-{index}"))
                .collect(),
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(64 * 1024 * 1024, 128);
        cache.load_snapshots(None);
        cache.install_rule_chunk_for_test("demo", vec![fish, bash], false, 1);
        assert!(cache.snapshots_pending());
        let mut provider = RuleProvider::default();
        let mut sink = CandidateSink::new(128);

        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );
        let candidates = sink.finish();

        assert!(status.pending);
        assert!(provider.cross_source_deferred);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.value.as_ref() == "--strong")
        );
    }

    #[test]
    fn snapshot_dependent_non_fish_source_is_not_finalized_early() {
        let fish = LoadedProgram {
            pack_id: [10; 32],
            pack_name: "empty-fish".into(),
            pack_version: "1".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "empty.fish".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: Vec::new(),
            }),
        };
        let bash_module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Bash,
            "snapshot.bash",
            "_demo() { compgen -A user -V ignored; COMPREPLY=( --strong ); }\ncomplete -F _demo demo\n",
        )
        .unwrap();
        let bash = LoadedProgram {
            pack_id: [11; 32],
            pack_name: "snapshot-bash".into(),
            pack_version: "1".into(),
            source: SourceKind::Bash,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "snapshot.bash".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![bash_module],
            }),
        };
        let context = CompletionContext::analyze("demo --", 7);
        let shell = ShellSnapshot {
            builtins: (0..MAX_COMMAND_SNAPSHOT)
                .map(|index| format!("builtin-{index}"))
                .collect(),
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(64 * 1024 * 1024, 128);
        cache.load_snapshots(None);
        cache.install_rule_chunk_for_test("demo", vec![fish, bash], false, 1);
        let mut provider = RuleProvider::default();
        let mut sink = CandidateSink::new(128);

        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );

        assert!(status.pending);
        assert!(status.snapshot_dependent);
        assert!(!provider.cross_source_deferred);
        assert!(
            sink.finish()
                .iter()
                .any(|candidate| candidate.value.as_ref() == "--strong")
        );
    }

    #[test]
    fn pending_fish_snapshot_dependency_suppresses_other_source_paths() {
        let fish_module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Fish,
            "snapshot.fish",
            "complete -c demo -a '(getent passwd)'\n",
        )
        .unwrap();
        let fish = LoadedProgram {
            pack_id: [12; 32],
            pack_name: "snapshot-fish".into(),
            pack_version: "1".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "snapshot.fish".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![fish_module],
            }),
        };
        let paths = LoadedProgram {
            pack_id: [13; 32],
            pack_name: "paths".into(),
            pack_version: "1".into(),
            source: SourceKind::User,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "paths.json".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules: vec![crate::rules::ir::StaticRule {
                    when: vec![crate::rules::ir::PredicateOp::True],
                    path_completion: PathCompletion::Files,
                    candidates: Vec::new(),
                }],
                probes: Vec::new(),
                scripts: Vec::new(),
            }),
        };
        let context = CompletionContext::analyze("demo ", 5);
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(64 * 1024 * 1024, 128);
        cache.load_snapshots(None);
        let programs = vec![fish, paths];
        cache.install_rule_chunk_for_test("demo", programs.clone(), false, 1);
        let mut provider = RuleProvider::default();
        let mut sink = CandidateSink::new(128);

        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );

        assert!(status.pending);
        assert!(status.snapshot_dependent);
        assert_eq!(status.path_completion, PathCompletion::Suppress);

        let mut nested_sink = CandidateSink::new(128);
        let nested = complete_nested_rules(
            &context,
            &shell,
            &mut cache,
            &mut nested_sink,
            CompletionMode::ExplicitTab,
            1,
        );
        assert!(nested.pending);
        assert!(nested.snapshot_dependent);
        assert_eq!(nested.path_completion, PathCompletion::Suppress);

        let unavailable_context = CompletionContext::analyze("demo --", 7);
        let mut unavailable_cache = CompletionCache::new(16 * 1024 * 1024, 128);
        unavailable_cache.load_snapshots(None);
        unavailable_cache.install_rule_chunk_for_test("demo", programs, false, 1);
        let mut unavailable_provider = RuleProvider::default();
        let mut unavailable_sink = CandidateSink::new(128);
        let unavailable = unavailable_provider.complete(
            &unavailable_context,
            &shell,
            &mut unavailable_cache,
            &mut unavailable_sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );
        assert!(unavailable.snapshot_dependent);
        assert!(!unavailable_provider.cross_source_deferred);
        assert_eq!(unavailable_provider.quick_redraws, 0);
    }

    #[test]
    fn unresolved_fish_replay_overrides_other_source_path_policy() {
        let mut fish_module = crate::rules::script_parser::parse_script(
            crate::rules::script::ScriptDialect::Fish,
            "pending.fish",
            "complete -c demo -n 'sleep 1' -l delayed\n",
        )
        .unwrap();
        fish_module.probe_capabilities = vec!["sleep".into()];
        let fish = LoadedProgram {
            pack_id: [4; 32],
            pack_name: "pending-fish".into(),
            pack_version: "1".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Verified { key_id: [5; 32] },
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "pending.fish".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-or-later".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![fish_module],
            }),
        };
        let paths = LoadedProgram {
            pack_id: [6; 32],
            pack_name: "paths".into(),
            pack_version: "1".into(),
            source: SourceKind::User,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "paths.json".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-only".into(),
                static_rules: vec![crate::rules::ir::StaticRule {
                    when: vec![crate::rules::ir::PredicateOp::True],
                    path_completion: PathCompletion::Files,
                    candidates: Vec::new(),
                }],
                probes: Vec::new(),
                scripts: Vec::new(),
            }),
        };
        let context = CompletionContext::analyze("demo ", 5);
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(64 * 1024 * 1024, 128);
        cache.install_rule_chunk_for_test("demo", vec![fish, paths], false, 1);
        let mut provider = RuleProvider::default();
        let mut sink = CandidateSink::new(128);

        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );

        assert!(status.pending);
        assert_eq!(status.path_completion, PathCompletion::Suppress);
        cache.cancel_probes();
    }

    #[test]
    fn replay_keys_distinguish_blocks_with_the_same_source_path() {
        let program = Arc::new(crate::rules::ir::CommandProgram {
            canonical_name: "demo".into(),
            registrations: vec!["demo".into()],
            source_path: "shared.fish".into(),
            source_commit: "test".into(),
            license: "GPL-2.0-only".into(),
            static_rules: Vec::new(),
            probes: Vec::new(),
            scripts: Vec::new(),
        });
        let loaded = |program| LoadedProgram {
            pack_id: [7; 32],
            pack_name: "shared".into(),
            pack_version: "1".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program,
        };
        let first = loaded(Arc::clone(&program));
        let second = loaded(Arc::new((*program).clone()));
        assert_ne!(
            loaded_replay_key(&[&first], 0, true, 128),
            loaded_replay_key(&[&second], 0, true, 128)
        );
        assert_ne!(
            loaded_replay_key(&[&first], 0, true, 64),
            loaded_replay_key(&[&first], 0, true, 128),
            "candidate limit is part of replay identity"
        );
    }

    #[test]
    fn ordinary_replay_is_invalidated_when_its_program_revision_changes() {
        let old_key = ReplayKey {
            pack_id: [1; 32],
            source_path: "same.fish".into(),
            depth: 0,
            explicit: true,
            program_identities: vec![1],
            program_revision: 7,
            candidate_limit: 128,
        };
        let current_key = ReplayKey {
            program_revision: 8,
            ..old_key.clone()
        };
        let unrelated_key = ReplayKey {
            pack_id: [2; 32],
            source_path: "other.fish".into(),
            program_revision: 7,
            ..old_key.clone()
        };
        let mut states = HashMap::from([
            (old_key.clone(), ReplayState::default()),
            (unrelated_key.clone(), ReplayState::default()),
        ]);

        invalidate_replay_program_revision(&mut states, &current_key);

        assert!(!states.contains_key(&old_key));
        assert!(states.contains_key(&unrelated_key));
    }

    #[test]
    fn quick_provisional_is_invalidated_when_its_program_changes() {
        let old_key = ReplayKey {
            pack_id: [1; 32],
            source_path: "same.fish".into(),
            depth: 0,
            explicit: true,
            program_identities: vec![1],
            program_revision: 7,
            candidate_limit: 128,
        };
        let new_key = ReplayKey {
            pack_id: [1; 32],
            source_path: "same.fish".into(),
            depth: 0,
            explicit: true,
            program_identities: vec![2],
            program_revision: 8,
            candidate_limit: 128,
        };
        let candidate = EmittedCandidate {
            candidate: crate::rules::ir::CandidateTemplate {
                value: "--old".into(),
                display: "--old".into(),
                description: None,
                kind: RuleCandidateKind::Option,
                append: AppendPolicy::Space,
                preserve_order: false,
            },
            source: SourceKind::Fish,
        };
        let mut provider = RuleProvider {
            quick_provisional: Arc::from(vec![candidate]),
            quick_program_key: Some(old_key),
            quick_path_completion: PathCompletion::Suppress,
            quick_redraws: 1,
            quick_evaluated: true,
            ..RuleProvider::default()
        };

        provider.invalidate_quick_program_if_changed(Some(&new_key));

        assert!(provider.quick_provisional.is_empty());
        assert!(provider.quick_program_key.is_none());
        assert_eq!(provider.quick_path_completion, PathCompletion::Inherit);
        assert_eq!(provider.quick_redraws, 0);
        assert!(!provider.quick_evaluated);
    }

    #[test]
    fn transient_reset_releases_replay_reservation_without_evaluation() {
        let key = ReplayKey {
            pack_id: [8; 32],
            source_path: "stale.fish".into(),
            depth: 0,
            explicit: false,
            program_identities: vec![8],
            program_revision: 1,
            candidate_limit: 128,
        };
        let mut provider = RuleProvider {
            replay_context: Some(("demo --".into(), 7, PathBuf::from("/tmp"), 1)),
            replay_states: HashMap::from([(key, ReplayState::default())]),
            ..RuleProvider::default()
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        provider.sync_replay_reservation(&mut cache);
        assert!(cache.used_bytes() > 0);

        provider.reset_transient(&mut cache);

        assert!(provider.replay_context.is_none());
        assert!(provider.replay_states.is_empty());
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn pending_empty_rule_chunk_clears_retained_semantic_state() {
        let key = ReplayKey {
            pack_id: [3; 32],
            source_path: "demo.fish".into(),
            depth: 0,
            explicit: true,
            program_identities: vec![3],
            program_revision: 1,
            candidate_limit: 128,
        };
        let mut provider = RuleProvider {
            replay_states: HashMap::from([(key.clone(), ReplayState::default())]),
            quick_program_key: Some(key),
            quick_path_completion: PathCompletion::Suppress,
            quick_redraws: 1,
            quick_evaluated: true,
            ..RuleProvider::default()
        };
        let context = CompletionContext::analyze("demo --", 7);
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        cache.install_rule_chunk_for_test("demo", Vec::new(), true, 2);
        let mut sink = CandidateSink::new(128);

        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );

        assert!(status.pending);
        assert_eq!(status.path_completion, PathCompletion::Suppress);
        assert!(sink.finish().is_empty());
        assert!(provider.replay_states.is_empty());
        assert!(provider.quick_program_key.is_none());
        assert_eq!(provider.quick_path_completion, PathCompletion::Inherit);
        assert_eq!(provider.quick_redraws, 0);
        assert!(!provider.quick_evaluated);
    }

    #[test]
    fn pending_rule_chunks_never_publish_quick_provisional_semantics() {
        let loaded = |source: &str| LoadedProgram {
            pack_id: [9; 32],
            pack_name: "chunk-test".into(),
            pack_version: "1.0.0".into(),
            source: SourceKind::Fish,
            trust: crate::rules::format::TrustStatus::Unsigned,
            required_commands: Vec::new(),
            retained_bytes: 0,
            program: Arc::new(crate::rules::ir::CommandProgram {
                canonical_name: "demo".into(),
                registrations: vec!["demo".into()],
                source_path: "demo.fish".into(),
                source_commit: "test".into(),
                license: "GPL-2.0-or-later".into(),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: vec![
                    crate::rules::script_parser::parse_script(
                        crate::rules::script::ScriptDialect::Fish,
                        "demo.fish",
                        source,
                    )
                    .unwrap(),
                ],
            }),
        };
        let partial = loaded("complete -c demo -l removed\n");
        let complete = loaded(
            "complete -c demo -l removed\ncomplete -ec demo -l removed\ncomplete -c demo -l retained\n",
        );
        let context = CompletionContext::analyze("demo --", 7);
        let shell = ShellSnapshot {
            cwd: PathBuf::from("/tmp"),
            ..ShellSnapshot::default()
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let mut provider = RuleProvider::default();

        cache.install_rule_chunk_for_test("demo", vec![partial], true, 1);
        let mut sink = CandidateSink::new(128);
        let status = provider.complete(
            &context,
            &shell,
            &mut cache,
            &mut sink,
            CompletionMode::ExplicitTab,
            PathCompletion::Inherit,
        );
        assert!(status.pending);
        assert!(sink.finish().is_empty());
        assert!(!provider.quick_evaluated);

        cache.install_rule_chunk_for_test("demo", vec![complete], false, 2);
        for attempt in 0..4 {
            let mut sink = CandidateSink::new(128);
            let status = provider.complete(
                &context,
                &shell,
                &mut cache,
                &mut sink,
                CompletionMode::ExplicitTab,
                PathCompletion::Inherit,
            );
            let values = sink
                .finish()
                .into_iter()
                .map(|candidate| candidate.value.to_string())
                .collect::<Vec<_>>();
            assert_eq!(values, ["--retained"]);
            if !status.pending {
                assert_eq!(provider.quick_redraws, 0);
                break;
            }
            assert!(attempt < 3, "the complete program never stabilized");
        }
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
                    program_identities: vec![usize::from(suffix)],
                    program_revision: 0,
                    candidate_limit: 128,
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
        trim_replay_states(&mut states, MAX_REPLAY_BYTES, 0);
        assert!(replay_states_bytes(&states) <= MAX_REPLAY_BYTES);
        assert!(states.len() < 3);

        let reserved = MAX_REPLAY_BYTES / 2;
        trim_replay_states(&mut states, MAX_REPLAY_BYTES, reserved);
        assert!(reserved.saturating_add(replay_states_bytes(&states)) <= MAX_REPLAY_BYTES);

        let mut provider = RuleProvider {
            replay_states: states,
            ..RuleProvider::default()
        };
        let mut cache = CompletionCache::new(MAX_REPLAY_BYTES, 128);
        provider.trim_and_sync_replay(&mut cache);
        assert_eq!(cache.used_bytes(), provider.retained_replay_bytes());
        assert!(cache.used_bytes() <= MAX_REPLAY_BYTES);
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
