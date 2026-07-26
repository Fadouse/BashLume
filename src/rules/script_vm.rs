// SPDX-License-Identifier: GPL-2.0-or-later

//! Deterministic runtime for build-time parsed shell-completion IR.
//!
//! This is deliberately a shell *semantic* VM, not a source evaluator. It
//! receives only validated [`ScriptModule`] trees from signed rule packs. No
//! Bash, Zsh, or Fish source is parsed or sourced at runtime.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use super::format::{SourceKind, TrustStatus};
use super::ir::{AppendPolicy, CandidateTemplate, PathCompletion, ProbeParser, RuleCandidateKind};
use super::script::{
    ScriptAssignment, ScriptBooleanOperator, ScriptCommand, ScriptDialect, ScriptEntry,
    ScriptFunction, ScriptModule, ScriptRedirection, ScriptStatement, ScriptWord, ScriptWordPart,
    registration_matches,
};
use super::vm::{
    CompletionRequest, EmittedCandidate, EvaluationContext, EvaluationMode, EvaluationResult,
    FilesystemRequest, FilesystemRequestKind, MAX_COMPLETION_REQUESTS, MAX_EMITTED_CANDIDATES,
    MAX_FILESYSTEM_REQUESTS, MAX_PROBE_REQUESTS, ProbeKey, ProbeRequest, ProbeResult, VmError,
    nested_completion_path,
};

const MAX_STEPS: usize = 250_000;
const MAX_CALL_DEPTH: usize = 256;
const MAX_LOOP_ITERATIONS: usize = 32_768;
const MAX_VALUES: usize = 65_536;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_CONTEXT_ENVIRONMENT: usize = 4096;
const MAX_ARITHMETIC_DEPTH: usize = 256;
const MAX_ARITHMETIC_TOKENS: usize = 65_536;
const MAX_PATTERN_RECURSION: usize = 128;
const MAX_MACHINE_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MACHINE_VARIABLES: usize = 4096;
const MAX_EMITTED_CANDIDATE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_CANDIDATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_WORK_BYTES: usize = 8 * 1024 * 1024;
const MAX_ZSH_TAG_STATE_ITEMS: usize = 256;
const MAX_ZSH_TAG_STATE_BYTES: usize = 16 * 1024;

fn bounded_string_snapshot<'a>(values: impl IntoIterator<Item = &'a String>) -> bool {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for value in values {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(value.len());
        if count > MAX_VALUES || bytes > MAX_VALUE_BYTES {
            return false;
        }
    }
    true
}

fn validate_evaluation_context(context: &EvaluationContext<'_>) -> Result<(), VmError> {
    let strings_are_bounded = context.current_word.len() <= MAX_VALUE_BYTES
        && bounded_string_snapshot(context.words)
        && bounded_string_snapshot(context.command_path)
        && context.environment.len() <= MAX_CONTEXT_ENVIRONMENT
        && bounded_string_snapshot(
            context
                .environment
                .iter()
                .flat_map(|(name, value)| [name, value]),
        )
        && context
            .available_commands
            .is_none_or(bounded_string_snapshot)
        && context.shell_commands.is_none_or(bounded_string_snapshot)
        && context.shell_functions.is_none_or(bounded_string_snapshot)
        && context.shell_variables.is_none_or(bounded_string_snapshot)
        && context.users.is_none_or(bounded_string_snapshot)
        && context.groups.is_none_or(bounded_string_snapshot)
        && context.hosts.is_none_or(bounded_string_snapshot)
        && context.process_ids.is_none_or(bounded_string_snapshot)
        && context.process_names.is_none_or(bounded_string_snapshot)
        && context
            .network_interfaces
            .is_none_or(bounded_string_snapshot)
        && context.signals.is_none_or(bounded_string_snapshot)
        && context.passwd_records.is_none_or(bounded_string_snapshot)
        && context.group_records.is_none_or(bounded_string_snapshot);
    let variable_values_are_bounded = context.shell_variable_values.is_none_or(|variables| {
        variables.len() <= MAX_VALUES
            && bounded_string_snapshot(variables.keys())
            && variables.values().all(bounded_string_snapshot)
            && variables
                .values()
                .flatten()
                .map(String::len)
                .fold(0_usize, usize::saturating_add)
                <= MAX_VALUE_BYTES
    });
    if !strings_are_bounded || !variable_values_are_bounded {
        return Err(VmError::Limit("evaluation context"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_modules(
    modules: &[ScriptModule],
    command: &str,
    context: &EvaluationContext<'_>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    probe_results: &HashMap<ProbeKey, ProbeResult>,
    completion_results: &HashMap<String, Vec<String>>,
    result: &mut EvaluationResult,
) -> Result<(), VmError> {
    validate_evaluation_context(context)?;
    let candidate_limit = candidate_limit.clamp(1, MAX_EMITTED_CANDIDATES);
    let mut candidate_bytes = result.candidates.iter().fold(0_usize, |total, emitted| {
        total
            .saturating_add(emitted.candidate.value.len())
            .saturating_add(emitted.candidate.display.len())
            .saturating_add(
                emitted
                    .candidate
                    .description
                    .as_ref()
                    .map_or(0, String::len),
            )
    });
    if candidate_bytes > MAX_TOTAL_CANDIDATE_BYTES {
        return Err(VmError::Limit("candidate bytes"));
    }
    let mut output_work_bytes = 0_usize;
    let mut candidate_indices = result
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| (candidate.candidate.value.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut effective_commands = vec![command.to_owned()];
    loop {
        let mut changed = false;
        for module in modules {
            for registration in &module.registrations {
                if effective_commands.iter().any(|effective| {
                    registration_matches(module.dialect, &registration.command, effective)
                }) {
                    if let Some(service) = &registration.service {
                        let available = module.dialect != ScriptDialect::Fish
                            || fish_builtin_available(service)
                            || context.command_available(service).unwrap_or(true);
                        if available && !effective_commands.contains(service) {
                            effective_commands.push(service.clone());
                            changed = true;
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    for module in modules {
        if !module.registrations.iter().any(|registration| {
            let available = module.dialect != ScriptDialect::Fish
                || registration.service.as_deref().is_none_or(|service| {
                    fish_builtin_available(service)
                        || context.command_available(service).unwrap_or(true)
                });
            available
                && effective_commands.iter().any(|effective| {
                    registration_matches(module.dialect, &registration.command, effective)
                })
        }) {
            continue;
        }
        let mut machine = Machine::new(
            module,
            command,
            context,
            source,
            trust,
            mode,
            candidate_limit.saturating_sub(result.candidates.len()),
            candidate_bytes,
            output_work_bytes,
            probe_results,
            completion_results,
            &effective_commands,
        );
        let execution = machine.run();
        candidate_bytes = machine.candidate_bytes;
        output_work_bytes = machine.output_work_bytes;
        if module.dialect == ScriptDialect::Fish {
            machine.candidates.sort_by(|left, right| {
                match (
                    left.emitted.candidate.preserve_order,
                    right.emitted.candidate.preserve_order,
                ) {
                    (true, true) => right
                        .fish_group
                        .cmp(&left.fish_group)
                        .then_with(|| left.fish_item.cmp(&right.fish_item)),
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    (false, false) => fish_file_cmp(
                        &left.emitted.candidate.value,
                        &right.emitted.candidate.value,
                    )
                    .then_with(|| {
                        left.emitted
                            .candidate
                            .display
                            .cmp(&right.emitted.candidate.display)
                    }),
                }
            });
            for candidate in &mut machine.candidates {
                candidate.emitted.candidate.preserve_order = true;
            }
        }
        if execution.is_ok() && machine.completion_invoked {
            result.completion_status = Some(
                if matches!(module.dialect, ScriptDialect::Bash | ScriptDialect::Zsh) {
                    i32::from(machine.last_status != 0)
                } else {
                    0
                },
            );
        }
        for record in machine.candidates {
            let emitted = record.emitted;
            if module.dialect == ScriptDialect::Bash {
                result.candidates.push(emitted);
            } else if let Some(index) = candidate_indices.get(&emitted.candidate.value).copied() {
                let existing = &mut result.candidates[index].candidate;
                if existing.description.is_none() {
                    existing.description = emitted.candidate.description;
                }
                if emitted.candidate.append == AppendPolicy::NoSpace {
                    existing.append = AppendPolicy::NoSpace;
                }
                existing.preserve_order |= emitted.candidate.preserve_order;
            } else {
                candidate_indices.insert(emitted.candidate.value.clone(), result.candidates.len());
                result.candidates.push(emitted);
            }
        }
        for request in machine.completion_requests {
            if !result.completion_requests.contains(&request) {
                result.completion_requests.push(request);
            }
        }
        for request in machine.filesystem_requests {
            if !result.filesystem_requests.contains(&request) {
                result.filesystem_requests.push(request);
            }
        }
        for provider in machine.snapshot_providers {
            if !result.snapshot_providers.contains(&provider) {
                result.snapshot_providers.push(provider);
            }
        }
        result.probes.extend(machine.probes);
        result.denied_probe_count = result
            .denied_probe_count
            .saturating_add(machine.denied_probe_count);
        result.truncated |= machine.truncated;
        result.path_completion = result.path_completion.merge(machine.path_completion);
        execution?;
        if result.candidates.len() >= candidate_limit {
            result.candidates.truncate(candidate_limit);
            break;
        }
        if result.probes.len() > MAX_PROBE_REQUESTS {
            return Err(VmError::Limit("script probe requests"));
        }
        if result.completion_requests.len() > MAX_COMPLETION_REQUESTS {
            return Err(VmError::Limit("nested completion requests"));
        }
        if result.filesystem_requests.len() > MAX_FILESYSTEM_REQUESTS {
            return Err(VmError::Limit("filesystem requests"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct Variable {
    values: Vec<String>,
    exported: bool,
    readonly: bool,
    array: bool,
    associative: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    None,
    Return(i32),
    Exit(i32),
    Break,
    Continue,
}

#[derive(Clone, Debug)]
struct CommandResult {
    status: i32,
    output: Vec<String>,
    control: Control,
}

fn append_bounded_output(
    target: &mut Vec<String>,
    target_bytes: &mut usize,
    source: &mut Vec<String>,
) -> Result<(), VmError> {
    let source_bytes = source
        .iter()
        .map(String::len)
        .fold(0_usize, usize::saturating_add);
    if target.len().saturating_add(source.len()) > MAX_VALUES
        || target_bytes.saturating_add(source_bytes) > MAX_VALUE_BYTES
    {
        return Err(VmError::Limit("shell command output"));
    }
    *target_bytes = target_bytes.saturating_add(source_bytes);
    target.append(source);
    Ok(())
}

#[derive(Clone, Copy)]
enum AvailabilityKind {
    Command,
    Function,
    Builtin,
}

fn fish_option_present(arguments: &[String], short: char, long: &str) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| {
            argument == long
                || argument
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                    .is_some_and(|flags| flags.contains(short))
        })
}

fn availability_query(arguments: &[String]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.starts_with('-'))
        .any(|argument| {
            matches!(
                argument.as_str(),
                "--query" | "--search" | "--verbose" | "--path"
            ) || argument
                .strip_prefix('-')
                .filter(|flags| !flags.starts_with('-'))
                .is_some_and(|flags| {
                    flags
                        .chars()
                        .any(|flag| matches!(flag, 'q' | 's' | 'v' | 'V'))
                })
        })
}

impl CommandResult {
    fn success() -> Self {
        Self {
            status: 0,
            output: Vec::new(),
            control: Control::None,
        }
    }

    fn status(status: i32) -> Self {
        Self {
            status,
            output: Vec::new(),
            control: Control::None,
        }
    }

    fn output(output: Vec<String>) -> Self {
        Self {
            status: 0,
            output,
            control: Control::None,
        }
    }
}

struct CandidateRecord {
    emitted: EmittedCandidate,
    fish_group: u64,
    fish_item: u64,
}

#[derive(Clone)]
struct DeferredCompletion {
    statements: Vec<ScriptStatement>,
    words: Vec<ScriptWord>,
}

struct Machine<'a> {
    module: &'a ScriptModule,
    command: &'a str,
    context: &'a EvaluationContext<'a>,
    source: SourceKind,
    trust: TrustStatus,
    mode: EvaluationMode,
    candidate_limit: usize,
    variables: HashMap<String, Variable>,
    functions: HashMap<String, ScriptFunction>,
    function_order: Vec<String>,
    candidates: Vec<CandidateRecord>,
    candidate_bytes: usize,
    output_work_bytes: usize,
    emitted_values: HashSet<String>,
    emission_attempts: usize,
    completion_invoked: bool,
    fish_group: u64,
    fish_item: u64,
    fish_force_files: bool,
    probes: Vec<ProbeRequest>,
    completion_requests: Vec<CompletionRequest>,
    filesystem_requests: Vec<FilesystemRequest>,
    snapshot_providers: Vec<String>,
    denied_probe_count: usize,
    truncated: bool,
    path_completion: PathCompletion,
    steps: usize,
    call_depth: usize,
    active_functions: Vec<String>,
    scopes: Vec<HashMap<String, Option<Variable>>>,
    loop_iterations: usize,
    last_status: i32,
    initializing: bool,
    stdin: Vec<String>,
    stdin_cursor: usize,
    capture_stderr: bool,
    suppress_word_splitting: bool,
    probe_results: &'a HashMap<ProbeKey, ProbeResult>,
    completion_results: &'a HashMap<String, Vec<String>>,
    deferred_completion_words: HashMap<String, DeferredCompletion>,
    effective_commands: Vec<String>,
    runtime_bash_registrations: Vec<(String, ScriptEntry, AppendPolicy)>,
    active_tags: Vec<String>,
    tags_iterated: bool,
    tag_context_initialized: bool,
    tag_label_iterations: HashSet<String>,
    limit_error: Option<&'static str>,
}

impl<'a> Machine<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        module: &'a ScriptModule,
        command: &'a str,
        context: &'a EvaluationContext<'a>,
        source: SourceKind,
        trust: TrustStatus,
        mode: EvaluationMode,
        candidate_limit: usize,
        candidate_bytes: usize,
        output_work_bytes: usize,
        probe_results: &'a HashMap<ProbeKey, ProbeResult>,
        completion_results: &'a HashMap<String, Vec<String>>,
        effective_commands: &[String],
    ) -> Self {
        let mut variables = context
            .environment
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    Variable {
                        values: vec![value.clone()],
                        exported: true,
                        readonly: false,
                        array: false,
                        associative: false,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        if let Some(shell_variable_values) = context.shell_variable_values {
            for (name, values) in shell_variable_values.iter().take(MAX_VALUES) {
                if values.len() <= MAX_VALUES
                    && values.iter().map(String::len).sum::<usize>() <= MAX_VALUE_BYTES
                {
                    let exported = variables
                        .get(name)
                        .is_some_and(|variable| variable.exported);
                    variables.insert(
                        name.clone(),
                        Variable {
                            values: values.clone(),
                            exported,
                            readonly: false,
                            array: values.len() > 1,
                            associative: false,
                        },
                    );
                }
            }
        }
        if let Some(shell_variables) = context.shell_variables {
            for name in shell_variables.iter().take(MAX_VALUES) {
                variables.entry(name.clone()).or_default();
            }
        }
        for name in ["EUID", "UID"] {
            variables.insert(
                name.into(),
                Variable {
                    values: vec![context.effective_user_id.to_string()],
                    exported: false,
                    readonly: true,
                    array: false,
                    associative: false,
                },
            );
        }
        initialize_context_variables(module.dialect, context, &mut variables);
        let mut function_order = module
            .functions
            .iter()
            .map(|function| function.name.clone())
            .collect::<Vec<_>>();
        function_order.dedup();
        let mut functions = module
            .functions
            .iter()
            .map(|function| (function.name.clone(), function.clone()))
            .collect::<HashMap<_, _>>();
        collect_statement_functions(&module.statements, &mut functions);
        let mut additional_functions = functions
            .keys()
            .filter(|name| !function_order.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        additional_functions.sort_unstable();
        function_order.extend(additional_functions);
        let mut deferred_completion_words = HashMap::new();
        collect_deferred_completion_words(&module.statements, &mut deferred_completion_words);
        for function in &module.functions {
            for argument in &function.arguments {
                collect_deferred_completion_word(argument, &mut deferred_completion_words);
            }
            collect_deferred_completion_words(&function.body, &mut deferred_completion_words);
        }
        Self {
            module,
            command,
            context,
            source,
            trust,
            mode,
            candidate_limit,
            variables,
            functions,
            function_order,
            candidates: Vec::new(),
            candidate_bytes,
            output_work_bytes,
            emitted_values: HashSet::new(),
            emission_attempts: 0,
            completion_invoked: false,
            fish_group: 0,
            fish_item: 0,
            fish_force_files: false,
            probes: Vec::new(),
            completion_requests: Vec::new(),
            filesystem_requests: Vec::new(),
            snapshot_providers: Vec::new(),
            denied_probe_count: 0,
            truncated: false,
            path_completion: if module.dialect == ScriptDialect::Fish {
                match command {
                    "cd" => PathCompletion::Directories,
                    "." | "source" => PathCompletion::Files,
                    _ => PathCompletion::Inherit,
                }
            } else {
                PathCompletion::Inherit
            },
            steps: 0,
            call_depth: 0,
            active_functions: Vec::new(),
            scopes: Vec::new(),
            loop_iterations: 0,
            last_status: 0,
            initializing: false,
            stdin: Vec::new(),
            stdin_cursor: 0,
            capture_stderr: false,
            suppress_word_splitting: false,
            probe_results,
            completion_results,
            deferred_completion_words,
            effective_commands: effective_commands.to_vec(),
            runtime_bash_registrations: Vec::new(),
            active_tags: Vec::new(),
            tags_iterated: false,
            tag_context_initialized: false,
            tag_label_iterations: HashSet::new(),
            limit_error: None,
        }
    }

    fn run(&mut self) -> Result<(), VmError> {
        match self.module.dialect {
            ScriptDialect::Fish => {
                // Fish completion files are declarative programs: top-level
                // `set`, control flow, and `complete` calls form the entrypoint.
                if let Some(service) = self
                    .module
                    .registrations
                    .iter()
                    .find(|registration| {
                        registration_matches(
                            ScriptDialect::Fish,
                            &registration.command,
                            self.command,
                        )
                    })
                    .and_then(|registration| registration.service.clone())
                {
                    self.set_values("service", vec![service], false);
                }
                self.completion_invoked = true;
                self.exec_statements(&self.module.statements)?;
            }
            ScriptDialect::Zsh => {
                let entries = self.matching_entries();
                if !entries.is_empty()
                    && entries
                        .iter()
                        .all(|(entry, _)| matches!(entry, ScriptEntry::Function { .. }))
                {
                    self.initializing = true;
                    let initialized = self.exec_zsh_top_level_declarations(&self.module.statements);
                    self.initializing = false;
                    initialized?;
                }
                for (entry, service) in entries {
                    self.completion_invoked = true;
                    if let Some(service) = service {
                        self.set_values("service", vec![service], false);
                    }
                    match entry {
                        ScriptEntry::Function { name } => {
                            self.call_function(&name, &[])?;
                        }
                        ScriptEntry::Module | ScriptEntry::FishComplete { .. } => {
                            self.exec_statements(&self.module.statements)?;
                        }
                    }
                }
            }
            ScriptDialect::Bash => {
                let source_positionals = self.save_positional();
                self.set_positional(&[self.command.to_owned()]);
                self.initializing = true;
                self.exec_top_level_declarations(&self.module.statements)?;
                self.initializing = false;
                self.restore_positional(source_positionals);
                if self
                    .runtime_bash_registrations
                    .iter()
                    .any(|(registered, _, append)| {
                        *append == AppendPolicy::NoSpace
                            && self.effective_commands.iter().any(|effective| {
                                registration_matches(ScriptDialect::Bash, registered, effective)
                            })
                    })
                {
                    self.set_values("__bashlume_nospace", vec!["1".into()], false);
                }
                let entries = self.matching_entries();
                for (entry, service) in entries {
                    self.completion_invoked = true;
                    if let Some(service) = service {
                        self.set_values("service", vec![service], false);
                    }
                    match entry {
                        ScriptEntry::Function { name } => {
                            self.call_function(&name, self.context.words)?;
                            self.emit_bash_compreply();
                        }
                        ScriptEntry::Module | ScriptEntry::FishComplete { .. } => {
                            self.exec_statements(&self.module.statements)?;
                            self.emit_bash_compreply();
                        }
                    }
                }
            }
        }
        self.check_machine_memory()?;
        Ok(())
    }

    fn matching_entries(&self) -> Vec<(ScriptEntry, Option<String>)> {
        let runtime = self
            .runtime_bash_registrations
            .iter()
            .filter(|(command, _, _)| {
                self.effective_commands
                    .iter()
                    .any(|effective| registration_matches(ScriptDialect::Bash, command, effective))
            })
            .map(|(_, entry, _)| (entry.clone(), None))
            .collect::<Vec<_>>();
        if self.module.dialect == ScriptDialect::Bash || !runtime.is_empty() {
            return runtime;
        }
        let direct_match = self.module.registrations.iter().any(|registration| {
            registration_matches(self.module.dialect, &registration.command, self.command)
        });
        let mut seen = HashSet::new();
        self.module
            .registrations
            .iter()
            .filter(|registration| {
                if direct_match {
                    registration_matches(self.module.dialect, &registration.command, self.command)
                } else {
                    self.effective_commands.iter().any(|effective| {
                        registration_matches(self.module.dialect, &registration.command, effective)
                    })
                }
            })
            .filter_map(|registration| {
                let key = format!("{:?}:{:?}", registration.entry, registration.service);
                seen.insert(key)
                    .then_some((registration.entry.clone(), registration.service.clone()))
            })
            .collect()
    }

    fn exec_zsh_top_level_declarations(
        &mut self,
        statements: &[ScriptStatement],
    ) -> Result<CommandResult, VmError> {
        let entry_functions = self
            .module
            .registrations
            .iter()
            .filter_map(|registration| match &registration.entry {
                ScriptEntry::Function { name } => Some(name.as_str()),
                ScriptEntry::Module | ScriptEntry::FishComplete { .. } => None,
            })
            .collect::<HashSet<_>>();
        let mut result = CommandResult::success();
        for statement in statements {
            if matches!(statement, ScriptStatement::Function { .. }) {
                continue;
            }
            let invokes_entry = match statement {
                ScriptStatement::Command { command } => command
                    .words
                    .first()
                    .and_then(ScriptWord::as_plain_literal)
                    .is_some_and(|name| entry_functions.contains(name)),
                _ => false,
            };
            if invokes_entry {
                continue;
            }
            result = self.exec_statement(statement)?;
            self.record_status(result.status);
            if result.control != Control::None {
                break;
            }
        }
        Ok(result)
    }

    fn exec_top_level_declarations(
        &mut self,
        statements: &[ScriptStatement],
    ) -> Result<CommandResult, VmError> {
        let mut result = CommandResult::success();
        for statement in statements {
            if !matches!(statement, ScriptStatement::Function { .. }) {
                result = self.exec_statement(statement)?;
                self.record_status(result.status);
                if result.control != Control::None {
                    break;
                }
            }
        }
        Ok(result)
    }

    fn step(&mut self) -> Result<(), VmError> {
        if self.steps % 16 == 0 {
            self.check_machine_memory()?;
        }
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_STEPS {
            return Err(VmError::Limit("shell script steps"));
        }
        Ok(())
    }

    fn check_machine_memory(&self) -> Result<(), VmError> {
        if let Some(error) = self.limit_error {
            return Err(VmError::Limit(error));
        }
        if self.variables.len() > MAX_MACHINE_VARIABLES {
            return Err(VmError::Limit("shell variables"));
        }
        let bytes = self
            .variables
            .iter()
            .fold(0_usize, |total, (name, variable)| {
                total
                    .saturating_add(name.len())
                    .saturating_add(variable.values.iter().map(String::len).sum::<usize>())
            });
        if bytes > MAX_MACHINE_VALUE_BYTES {
            return Err(VmError::Limit("shell variable bytes"));
        }
        let tag_items = self
            .active_tags
            .len()
            .saturating_add(self.tag_label_iterations.len());
        let tag_bytes = self
            .active_tags
            .iter()
            .chain(self.tag_label_iterations.iter())
            .map(String::len)
            .fold(0_usize, usize::saturating_add);
        if tag_items > MAX_ZSH_TAG_STATE_ITEMS || tag_bytes > MAX_ZSH_TAG_STATE_BYTES {
            return Err(VmError::Limit("Zsh completion tag state"));
        }
        Ok(())
    }

    fn charge_output_work(&mut self, values: &[String]) -> Result<(), VmError> {
        let bytes = values
            .iter()
            .map(String::len)
            .fold(0_usize, usize::saturating_add);
        self.output_work_bytes = self.output_work_bytes.saturating_add(bytes);
        if self.output_work_bytes > MAX_COMMAND_OUTPUT_WORK_BYTES {
            return Err(VmError::Limit("shell command output work"));
        }
        Ok(())
    }

    fn mark_snapshot_provider(&mut self, provider: &str) {
        if !self
            .snapshot_providers
            .iter()
            .any(|existing| existing == provider)
        {
            self.snapshot_providers.push(provider.to_owned());
        }
    }

    fn exec_statements(
        &mut self,
        statements: &[ScriptStatement],
    ) -> Result<CommandResult, VmError> {
        let mut result = CommandResult::success();
        let mut output = Vec::new();
        let mut output_bytes = 0_usize;
        for statement in statements {
            result = self.exec_statement(statement)?;
            append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
            self.record_status(result.status);
            if result.control != Control::None {
                break;
            }
        }
        result.output = output;
        Ok(result)
    }

    fn resolve_status_argument(&mut self, value: Option<&str>) -> i32 {
        let Some(value) = value else {
            return self.last_status;
        };
        if let Ok(status) = value.parse::<i32>() {
            return status;
        }
        if let Some(status) = self
            .variable_values(value)
            .first()
            .and_then(|value| value.parse::<i32>().ok())
        {
            return status;
        }
        self.eval_arithmetic(value).clamp(0, i32::MAX as i64) as i32
    }

    fn record_status(&mut self, status: i32) {
        self.last_status = status;
        if self.module.dialect == ScriptDialect::Fish {
            self.set_values("status", vec![status.to_string()], false);
        }
    }

    fn redirected_input(
        &mut self,
        redirections: &[ScriptRedirection],
    ) -> Result<Option<Vec<String>>, VmError> {
        let mut input = None;
        for redirection in redirections {
            if redirection
                .descriptor
                .is_some_and(|descriptor| descriptor != 0)
            {
                continue;
            }
            match redirection.operator.as_str() {
                "<<<" => {
                    let value = self
                        .expand_word_preserving_fields(&redirection.target)?
                        .join(" ");
                    input = Some(value.split('\n').map(str::to_owned).collect());
                }
                "<<" | "<<-" => {
                    let value = self
                        .expand_word_preserving_fields(&redirection.target)?
                        .join(" ");
                    input = Some(if value.is_empty() {
                        Vec::new()
                    } else {
                        value.split('\n').map(str::to_owned).collect()
                    });
                }
                "<" => {
                    let path = self
                        .expand_word_preserving_fields(&redirection.target)?
                        .first()
                        .cloned()
                        .unwrap_or_default();
                    input = Some(
                        self.filesystem_values(FilesystemRequestKind::Read, &path, None)
                            .unwrap_or_default(),
                    );
                }
                _ => {}
            }
        }
        Ok(input)
    }

    fn exec_statement(&mut self, statement: &ScriptStatement) -> Result<CommandResult, VmError> {
        self.step()?;
        match statement {
            ScriptStatement::Command { command } => {
                let input = self.stdin.clone();
                self.exec_command(command, &input)
            }
            ScriptStatement::Pipeline { commands, negated } => {
                let mut input = Vec::new();
                let mut result = CommandResult::success();
                let mut statuses = Vec::new();
                for command in commands {
                    let saved = std::mem::replace(&mut self.stdin, input);
                    let saved_cursor = std::mem::replace(&mut self.stdin_cursor, 0);
                    result = self.exec_statement(command)?;
                    input = result.output.clone();
                    self.stdin = saved;
                    self.stdin_cursor = saved_cursor;
                    statuses.push(result.status.to_string());
                    if result.control != Control::None {
                        break;
                    }
                }
                if self.module.dialect == ScriptDialect::Fish {
                    self.set_values("pipestatus", statuses, false);
                }
                if *negated {
                    result.status = i32::from(result.status == 0);
                }
                Ok(result)
            }
            ScriptStatement::AndOr { first, rest } => {
                let mut result = self.exec_statement(first)?;
                let mut output = Vec::new();
                let mut output_bytes = 0_usize;
                append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                self.record_status(result.status);
                for arm in rest {
                    let execute = match arm.operator {
                        ScriptBooleanOperator::And => result.status == 0,
                        ScriptBooleanOperator::Or => result.status != 0,
                    };
                    if execute && result.control == Control::None {
                        result = self.exec_statement(&arm.statement)?;
                        append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                        self.record_status(result.status);
                    }
                }
                result.output = output;
                Ok(result)
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                let mut output = Vec::new();
                let mut output_bytes = 0_usize;
                for branch in branches {
                    let mut condition = self.exec_statements(&branch.condition)?;
                    append_bounded_output(&mut output, &mut output_bytes, &mut condition.output)?;
                    if condition.status == 0 {
                        let mut result = self.exec_statements(&branch.body)?;
                        append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                        result.output = output;
                        return Ok(result);
                    }
                }
                let mut result = self.exec_statements(otherwise)?;
                append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                result.output = output;
                Ok(result)
            }
            ScriptStatement::While {
                condition,
                body,
                until,
            } => {
                let mut result = CommandResult::success();
                let mut output = Vec::new();
                let mut output_bytes = 0_usize;
                loop {
                    self.loop_step()?;
                    let stdin_cursor_before = self.stdin_cursor;
                    let mut condition_result = self.exec_statements(condition)?;
                    append_bounded_output(
                        &mut output,
                        &mut output_bytes,
                        &mut condition_result.output,
                    )?;
                    if (condition_result.status == 0) == *until {
                        break;
                    }
                    let variables_before = self.variable_fingerprint();
                    result = self.exec_statements(body)?;
                    append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                    if result.control == Control::None
                        && self.variable_fingerprint() == variables_before
                        && self.stdin_cursor == stdin_cursor_before
                    {
                        break;
                    }
                    match result.control {
                        Control::Break => {
                            result.control = Control::None;
                            break;
                        }
                        Control::Continue => result.control = Control::None,
                        Control::Return(_) | Control::Exit(_) => break,
                        Control::None => {}
                    }
                }
                result.output = output;
                Ok(result)
            }
            ScriptStatement::For {
                variables,
                words,
                body,
            } => self.exec_for(variables, words, body),
            ScriptStatement::Case { word, arms } => {
                let value = self
                    .expand_word_preserving_fields(word)?
                    .first()
                    .cloned()
                    .unwrap_or_default();
                let mut result = CommandResult::success();
                let mut output = Vec::new();
                let mut output_bytes = 0_usize;
                let mut execute_next = false;
                for arm in arms {
                    let arm_matches = execute_next
                        || arm.patterns.iter().any(|pattern| {
                            let patterns = if self.module.dialect == ScriptDialect::Fish {
                                self.expand_word_preserving_fields(pattern)
                            } else {
                                self.expand_case_pattern(pattern)
                            };
                            patterns.is_ok_and(|patterns| {
                                patterns.iter().any(|pattern| {
                                    shell_pattern_dialect(self.module.dialect, pattern, &value)
                                })
                            })
                        });
                    if arm_matches {
                        result = self.exec_statements(&arm.body)?;
                        append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
                        if result.control != Control::None {
                            break;
                        }
                        if arm.fallthrough {
                            execute_next = true;
                        } else if arm.continue_matching {
                            execute_next = false;
                        } else {
                            break;
                        }
                    }
                }
                result.output = output;
                Ok(result)
            }
            ScriptStatement::Redirected {
                statement,
                redirections,
            } => {
                let redirected_input = self.redirected_input(redirections)?;
                let saved_input =
                    redirected_input.map(|input| std::mem::replace(&mut self.stdin, input));
                let saved_cursor = saved_input
                    .as_ref()
                    .map(|_| std::mem::replace(&mut self.stdin_cursor, 0));
                let saved_capture_stderr = self.capture_stderr;
                self.capture_stderr =
                    redirections
                        .iter()
                        .fold(self.capture_stderr, |capture, redirection| {
                            if redirection.descriptor == Some(2)
                                && redirection.operator == ">&"
                                && redirection.target.as_plain_literal() == Some("1")
                            {
                                true
                            } else if redirection.descriptor == Some(2)
                                && matches!(
                                    redirection.operator.as_str(),
                                    ">" | ">>" | ">!" | ">>!" | ">|"
                                )
                                || matches!(redirection.operator.as_str(), "&>" | "&>>")
                            {
                                false
                            } else {
                                capture
                            }
                        });
                let execution = self.exec_statement(statement);
                self.capture_stderr = saved_capture_stderr;
                if let Some(saved) = saved_input {
                    self.stdin = saved;
                    self.stdin_cursor = saved_cursor.unwrap_or(0);
                }
                let mut result = execution?;
                if redirections.iter().any(|redirection| {
                    redirection
                        .descriptor
                        .is_none_or(|descriptor| descriptor == 1)
                        && matches!(
                            redirection.operator.as_str(),
                            ">" | ">>" | ">!" | ">>!" | ">|" | "&>" | "&>>"
                        )
                }) {
                    result.output.clear();
                }
                Ok(result)
            }
            ScriptStatement::Function { function } => {
                if !self.functions.contains_key(&function.name) {
                    self.function_order.push(function.name.clone());
                }
                self.functions
                    .insert(function.name.clone(), function.clone());
                Ok(CommandResult::success())
            }
            ScriptStatement::Noop => Ok(CommandResult::success()),
            ScriptStatement::Group { body, subshell } => {
                if *subshell {
                    let variables = self.variables.clone();
                    let result = self.exec_statements(body);
                    self.variables = variables;
                    result
                } else {
                    self.exec_statements(body)
                }
            }
            ScriptStatement::Return { status } => {
                let expanded = status
                    .as_ref()
                    .and_then(|word| self.expand_word(word).ok())
                    .and_then(|values| values.first().cloned());
                let status = self.resolve_status_argument(expanded.as_deref());
                Ok(CommandResult {
                    status,
                    output: Vec::new(),
                    control: Control::Return(status),
                })
            }
            ScriptStatement::Break => Ok(CommandResult {
                status: 0,
                output: Vec::new(),
                control: Control::Break,
            }),
            ScriptStatement::Continue => Ok(CommandResult {
                status: 0,
                output: Vec::new(),
                control: Control::Continue,
            }),
        }
    }

    fn exec_for(
        &mut self,
        variables: &[String],
        words: &[ScriptWord],
        body: &[ScriptStatement],
    ) -> Result<CommandResult, VmError> {
        if variables.is_empty() {
            return self.exec_arithmetic_for(words, body);
        }
        let mut values = Vec::new();
        if words.is_empty() {
            values = self.variable_values("@");
        } else {
            for word in words {
                values.extend(self.expand_command_word(word)?);
                self.check_values(&values)?;
            }
        }
        let mut result = CommandResult::success();
        let mut output = Vec::new();
        let mut output_bytes = 0_usize;
        for chunk in values.chunks(variables.len()) {
            self.loop_step()?;
            for (variable, value) in variables.iter().zip(chunk) {
                self.set_values(variable, vec![value.clone()], false);
            }
            result = self.exec_statements(body)?;
            append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
            match result.control {
                Control::Break => {
                    result.control = Control::None;
                    break;
                }
                Control::Continue => result.control = Control::None,
                Control::Return(_) | Control::Exit(_) => break,
                Control::None => {}
            }
        }
        result.output = output;
        Ok(result)
    }

    fn exec_arithmetic_for(
        &mut self,
        words: &[ScriptWord],
        body: &[ScriptStatement],
    ) -> Result<CommandResult, VmError> {
        let expression = words
            .first()
            .and_then(|word| match word.parts.first() {
                Some(ScriptWordPart::Arithmetic { expression, .. }) => Some(expression.as_str()),
                _ => None,
            })
            .unwrap_or("");
        let sections = split_top_level(expression, ';');
        if let Some(initializer) = sections.first() {
            self.eval_arithmetic(initializer);
        }
        let mut result = CommandResult::success();
        let mut output = Vec::new();
        let mut output_bytes = 0_usize;
        loop {
            self.loop_step()?;
            if sections
                .get(1)
                .is_some_and(|condition| self.eval_arithmetic(condition) == 0)
            {
                break;
            }
            result = self.exec_statements(body)?;
            append_bounded_output(&mut output, &mut output_bytes, &mut result.output)?;
            match result.control {
                Control::Break => {
                    result.control = Control::None;
                    break;
                }
                Control::Continue => result.control = Control::None,
                Control::Return(_) | Control::Exit(_) => break,
                Control::None => {}
            }
            if let Some(increment) = sections.get(2) {
                self.eval_arithmetic(increment);
            }
        }
        result.output = output;
        Ok(result)
    }

    fn variable_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut variables = self.variables.iter().collect::<Vec<_>>();
        variables.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (name, variable) in variables {
            name.hash(&mut hasher);
            variable.values.hash(&mut hasher);
            variable.exported.hash(&mut hasher);
            variable.readonly.hash(&mut hasher);
            variable.array.hash(&mut hasher);
        }
        hasher.finish()
    }

    fn loop_step(&mut self) -> Result<(), VmError> {
        self.loop_iterations = self.loop_iterations.saturating_add(1);
        if self.loop_iterations > MAX_LOOP_ITERATIONS {
            return Err(VmError::Limit("shell loop iterations"));
        }
        self.step()
    }

    fn exec_command(
        &mut self,
        command: &ScriptCommand,
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let command_name = command.words.first().and_then(ScriptWord::as_plain_literal);
        if command_name == Some("and") && self.last_status != 0
            || command_name == Some("or") && self.last_status == 0
        {
            return Ok(CommandResult::status(self.last_status));
        }
        let declaration = command
            .words
            .first()
            .and_then(ScriptWord::as_plain_literal)
            .filter(|name| {
                matches!(
                    *name,
                    "local" | "typeset" | "declare" | "integer" | "readonly" | "export"
                )
            });
        let global_declaration = command.words.iter().skip(1).any(|word| {
            word.as_plain_literal()
                .is_some_and(|argument| argument.starts_with('-') && argument[1..].contains('g'))
        });
        let temporary_assignments = declaration.is_none() && !command.words.is_empty();
        let saved_assignments = temporary_assignments.then(|| {
            command
                .assignments
                .iter()
                .map(|assignment| {
                    (
                        assignment.name.clone(),
                        self.variables.get(&assignment.name).cloned(),
                    )
                })
                .collect::<Vec<_>>()
        });
        if !global_declaration
            && declaration.is_some_and(|name| !matches!(name, "readonly" | "export"))
        {
            for assignment in &command.assignments {
                self.mark_local(&assignment.name);
            }
        }
        let declaration_options = command
            .words
            .iter()
            .skip(1)
            .filter_map(ScriptWord::as_plain_literal)
            .filter(|argument| argument.starts_with('-'))
            .collect::<Vec<_>>();
        let declaration_associative = declaration_options
            .iter()
            .any(|argument| argument[1..].contains('A'));
        let declaration_array = declaration_associative
            || declaration_options
                .iter()
                .any(|argument| argument[1..].contains('a'));
        for assignment in &command.assignments {
            let variable = self.variables.entry(assignment.name.clone()).or_default();
            variable.associative |= declaration_associative;
            variable.array |= declaration_array;
            self.apply_assignment(assignment)?;
        }
        if let Some(declaration) = declaration {
            for assignment in &command.assignments {
                if let Some(variable) = self.variables.get_mut(&assignment.name) {
                    variable.exported |= declaration == "export";
                    variable.readonly |= declaration == "readonly";
                }
            }
        }
        if command_name == Some("eval") {
            if let Some(ScriptWordPart::DeferredScript {
                source,
                statements,
                words,
            }) = command.words.get(1).and_then(|word| word.parts.first())
            {
                if source.starts_with("eval-function:") {
                    return self.define_deferred_eval_function(source, statements, words);
                }
            }
        }
        if self.module.dialect == ScriptDialect::Fish
            && command.words.first().and_then(ScriptWord::as_plain_literal) == Some("complete")
        {
            let result = self.complete_command(command);
            if let Some(saved) = saved_assignments {
                self.restore_assignments(saved);
            }
            return result;
        }
        let fish_set_substitution = self.module.dialect == ScriptDialect::Fish
            && command.words.first().and_then(ScriptWord::as_plain_literal) == Some("set")
            && command
                .words
                .iter()
                .skip(1)
                .any(word_contains_command_substitution);
        let mut arguments = Vec::new();
        let compound_expression = matches!(
            command.words.first().and_then(ScriptWord::as_plain_literal),
            Some("[[" | "((")
        );
        for word in &command.words {
            let expanded = if compound_expression {
                self.expand_word_preserving_fields(word)?
            } else {
                self.expand_command_word(word)?
            };
            if compound_expression && expanded.len() > 1 {
                arguments.push(expanded.join(" "));
            } else {
                arguments.extend(expanded);
            }
            self.check_values(&arguments)?;
        }
        let expansion_status = self.last_status;
        if arguments.is_empty() {
            if let Some(saved) = saved_assignments {
                self.restore_assignments(saved);
            }
            return Ok(CommandResult::success());
        }
        let name = arguments.remove(0);
        let redirected_input = self.redirected_input(&command.redirections)?;
        let saved_input =
            redirected_input.map(|redirected| std::mem::replace(&mut self.stdin, redirected));
        let saved_cursor = saved_input
            .as_ref()
            .map(|_| std::mem::replace(&mut self.stdin_cursor, 0));
        let invocation_input = saved_input
            .as_ref()
            .map_or_else(|| input.to_vec(), |_| self.stdin.clone());
        let saved_capture_stderr = self.capture_stderr;
        self.capture_stderr =
            command
                .redirections
                .iter()
                .fold(self.capture_stderr, |capture, redirection| {
                    if redirection.descriptor == Some(2)
                        && redirection.operator == ">&"
                        && redirection.target.as_plain_literal() == Some("1")
                    {
                        true
                    } else if redirection.descriptor == Some(2)
                        && matches!(
                            redirection.operator.as_str(),
                            ">" | ">>" | ">!" | ">>!" | ">|"
                        )
                        || matches!(redirection.operator.as_str(), "&>" | "&>>")
                    {
                        false
                    } else {
                        capture
                    }
                });
        let invoked = self.invoke(&name, &arguments, &invocation_input);
        self.capture_stderr = saved_capture_stderr;
        if let Some(saved) = saved_input {
            self.stdin = saved;
            self.stdin_cursor = saved_cursor.unwrap_or(0);
        }
        if let Some(saved) = saved_assignments {
            self.restore_assignments(saved);
        }
        let mut result = invoked?;
        self.charge_output_work(&result.output)?;
        if fish_set_substitution {
            result.status = expansion_status;
        }
        if command.redirections.iter().any(|redirection| {
            redirection
                .descriptor
                .is_none_or(|descriptor| descriptor == 1)
                && matches!(
                    redirection.operator.as_str(),
                    ">" | ">>" | ">!" | ">>!" | ">|" | "&>" | "&>>"
                )
        }) {
            result.output.clear();
        }
        Ok(result)
    }

    fn invoke(
        &mut self,
        name: &str,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        self.step()?;
        if self.initializing
            && self.module.dialect == ScriptDialect::Zsh
            && matches!(
                name,
                "_arguments"
                    | "_alternative"
                    | "_describe"
                    | "_values"
                    | "_regex_arguments"
                    | "_wanted"
                    | "_requested"
                    | "_all_labels"
                    | "_tags"
                    | "_next_label"
                    | "_files"
                    | "_path_files"
                    | "_directories"
                    | "_users"
                    | "_groups"
                    | "_hosts"
                    | "_user_at_host"
                    | "_combination"
                    | "_parameters"
                    | "_functions"
                    | "_command_names"
                    | "_commands"
                    | "_exec_commands"
                    | "_path_commands"
                    | "_jobs"
                    | "_processes"
                    | "_pids"
                    | "_ttys"
                    | "_file_systems"
                    | "_mounts"
                    | "compadd"
            )
        {
            return Ok(CommandResult::status(1));
        }
        match name {
            "_comp_command_offset" if self.module.dialect == ScriptDialect::Bash => {
                return self.bash_command_offset_builtin(arguments);
            }
            "_comp_xfunc" if self.module.dialect == ScriptDialect::Bash => {
                let Some(namespace) = arguments.first() else {
                    return Ok(CommandResult::status(2));
                };
                let Some(requested) = arguments.get(1) else {
                    return Ok(CommandResult::status(2));
                };
                let function = if requested.starts_with('_') {
                    requested.clone()
                } else {
                    let namespace = namespace
                        .chars()
                        .map(|character| {
                            if character == '_' || character.is_ascii_alphanumeric() {
                                character
                            } else {
                                '_'
                            }
                        })
                        .collect::<String>();
                    format!("_comp_xfunc_{namespace}_{requested}")
                };
                return if self.functions.contains_key(&function) {
                    self.invoke(&function, arguments.get(2..).unwrap_or_default(), &[])
                } else {
                    Ok(CommandResult::status(127))
                };
            }
            "_comp_compgen_help"
                if self.module.dialect == ScriptDialect::Bash
                    && arguments.first().map(String::as_str) == Some("-c")
                    && arguments.get(1).map(String::as_str) == Some("help") =>
            {
                return Ok(self.bash_builtin_help_completion(arguments));
            }
            "_comp_compgen_filedir"
                if self.module.dialect == ScriptDialect::Bash
                    && !arguments.iter().any(|argument| argument == "-d") =>
            {
                return self.bash_filedir_builtin(arguments);
            }
            "_comp_compgen_pids" | "_comp_compgen_pgids"
                if self.module.dialect == ScriptDialect::Bash =>
            {
                return Ok(self.bash_process_completion(false));
            }
            "_comp_compgen_pnames" if self.module.dialect == ScriptDialect::Bash => {
                return Ok(self.bash_process_completion(true));
            }
            "_pids" if self.module.dialect == ScriptDialect::Bash => {
                self.mark_snapshot_provider("process");
                return Ok(CommandResult::output(
                    self.context.process_ids.unwrap_or_default().to_vec(),
                ));
            }
            "_pnames" if self.module.dialect == ScriptDialect::Bash => {
                self.mark_snapshot_provider("process");
                return Ok(CommandResult::output(self.process_names()));
            }
            "_available_interfaces" | "_configured_interfaces"
                if self.module.dialect == ScriptDialect::Bash =>
            {
                self.mark_snapshot_provider("network");
                return Ok(CommandResult::output(
                    self.context.network_interfaces.unwrap_or_default().to_vec(),
                ));
            }
            "__fish_complete_pids" if self.module.dialect == ScriptDialect::Fish => {
                self.mark_snapshot_provider("process");
                return Ok(CommandResult::output(self.fish_process_values()));
            }
            "__fish_complete_proc" if self.module.dialect == ScriptDialect::Fish => {
                self.mark_snapshot_provider("process");
                return Ok(CommandResult::output(self.process_names()));
            }
            "__fish_print_interfaces" if self.module.dialect == ScriptDialect::Fish => {
                self.mark_snapshot_provider("network");
                return Ok(CommandResult::output(
                    self.context.network_interfaces.unwrap_or_default().to_vec(),
                ));
            }
            "_net_interfaces" if self.module.dialect == ScriptDialect::Zsh => {
                return Ok(self.zsh_network_interfaces_builtin());
            }
            "_default" if self.module.dialect == ScriptDialect::Zsh => {
                return Ok(CommandResult::status(1));
            }
            "_arguments" => return self.arguments_builtin(arguments),
            "_alternative" => return self.alternative_builtin(arguments),
            "_call_function" => return self.call_function_builtin(arguments),
            "_call_program" => return self.call_program_builtin(arguments),
            "_describe" => return self.describe_builtin(arguments),
            "_description" => return self.description_builtin(arguments),
            "_values" => return self.values_builtin(arguments),
            "_file_modes" => return Ok(self.file_modes_builtin()),
            "_urls" => return Ok(self.urls_builtin()),
            "_regex_arguments" => return self.regex_arguments_builtin(arguments),
            "_wanted" | "_requested" | "_all_labels" => {
                return self.completion_api_action_builtin(name, arguments);
            }
            "_tags" | "_next_label" => {
                return Ok(self.completion_iterator_builtin(name, arguments));
            }
            "_users" | "_groups" | "_hosts" | "_user_at_host" | "_combination" => {
                return Ok(self.zsh_snapshot_provider_builtin(name, arguments));
            }
            "_parameters" | "_functions" | "_command_names" | "_commands" | "_exec_commands"
            | "_path_commands" | "_jobs" | "_processes" | "_pids" | "_ttys" | "_file_systems"
            | "_mounts" => {
                return Ok(self.zsh_shell_snapshot_builtin(name, arguments));
            }
            "_files" | "_path_files" => {
                self.path_completion = self.path_completion.merge(PathCompletion::Files);
                return Ok(CommandResult::status(1));
            }
            "_directories" => {
                self.path_completion = self.path_completion.merge(PathCompletion::Directories);
                return Ok(CommandResult::status(1));
            }
            _ => {}
        }
        if let Some(function) = self.functions.get(name).cloned() {
            return self.call(&function, arguments);
        }
        let source_function = self
            .module
            .source_path
            .rsplit('/')
            .next()
            .and_then(|source| source.split(';').next())
            == Some(name);
        if self.module.dialect == ScriptDialect::Zsh
            && source_function
            && !self.active_functions.iter().any(|active| active == name)
        {
            let function = ScriptFunction {
                name: name.to_owned(),
                arguments: Vec::new(),
                body: self.module.statements.clone(),
            };
            let helper_arguments = if arguments.is_empty() {
                vec!["__bashlume_completion_action".into()]
            } else {
                arguments.to_vec()
            };
            return self.call(&function, &helper_arguments);
        }
        if emulated_external_command(name)
            && self
                .context
                .available_commands
                .is_some_and(|commands| !commands.contains(name))
        {
            return Ok(CommandResult::status(127));
        }
        match name {
            ":" | "true" => Ok(CommandResult::success()),
            "false" => Ok(CommandResult::status(1)),
            "return" | "exit" => {
                let status = self.resolve_status_argument(arguments.first().map(String::as_str));
                Ok(CommandResult {
                    status,
                    output: Vec::new(),
                    control: if name == "exit" {
                        Control::Exit(status)
                    } else {
                        Control::Return(status)
                    },
                })
            }
            "break" => Ok(CommandResult {
                status: 0,
                output: Vec::new(),
                control: Control::Break,
            }),
            "continue" => Ok(CommandResult {
                status: 0,
                output: Vec::new(),
                control: Control::Continue,
            }),
            "declare" if arguments.iter().any(|argument| argument == "-F") => {
                let exists = arguments
                    .iter()
                    .filter(|argument| !argument.starts_with('-'))
                    .all(|function| self.functions.contains_key(function));
                Ok(CommandResult::status(i32::from(!exists)))
            }
            "local" | "typeset" | "declare" | "integer" | "readonly" | "export" => {
                self.declaration_builtin(name, arguments);
                Ok(CommandResult::success())
            }
            "set" => self.set_builtin(arguments),
            "help" if self.module.dialect == ScriptDialect::Bash => {
                Ok(bash_help_builtin(arguments))
            }
            "pwd" => Ok(CommandResult::output(vec![
                self.context
                    .working_directory
                    .to_string_lossy()
                    .into_owned(),
            ])),
            "argparse" => self.argparse_builtin(arguments),
            "getopts" => self.getopts_builtin(arguments),
            "shift" => self.shift_builtin(arguments),
            "echo" => Ok(CommandResult::output(echo_values(arguments))),
            "printf" => self.printf_builtin(arguments),
            "read" => self.read_builtin(arguments, input),
            "mapfile" | "readarray" => self.mapfile_builtin(arguments, input),
            "eval" => self.eval_builtin(arguments),
            "unset" => {
                for argument in arguments
                    .iter()
                    .filter(|argument| !argument.starts_with('-'))
                {
                    self.unset_reference(argument);
                }
                Ok(CommandResult::success())
            }
            "test" | "[" | "[[" => Ok(CommandResult::status(i32::from(!self.test(arguments)))),
            "((" => Ok(CommandResult::status(i32::from(
                self.eval_arithmetic(&arguments.join(" ")) == 0,
            ))),
            "command" if availability_query(arguments) => {
                Ok(self.command_query(arguments, AvailabilityKind::Command))
            }
            "type" | "whence" | "which" => {
                Ok(self.command_query(arguments, AvailabilityKind::Command))
            }
            "functions" if availability_query(arguments) => {
                Ok(self.command_query(arguments, AvailabilityKind::Function))
            }
            "functions" if self.module.dialect == ScriptDialect::Fish => {
                let mut functions = self.context.shell_functions.map_or_else(
                    || self.functions.keys().cloned().collect::<Vec<_>>(),
                    <[String]>::to_vec,
                );
                if !arguments.iter().any(|argument| {
                    argument == "--all"
                        || argument
                            .strip_prefix('-')
                            .is_some_and(|flags| flags.contains('a'))
                }) {
                    functions.retain(|function| !function.starts_with('_'));
                }
                functions.sort_unstable();
                functions.dedup();
                Ok(CommandResult::output(functions))
            }
            "getent" if arguments.first().map(String::as_str) == Some("passwd") => {
                self.mark_snapshot_provider("user");
                let records = self.context.passwd_records.map_or_else(
                    || {
                        self.context
                            .users
                            .unwrap_or_default()
                            .iter()
                            .map(|user| format!("{user}:x:0:0:{user}::"))
                            .collect()
                    },
                    <[String]>::to_vec,
                );
                Ok(CommandResult::output(records))
            }
            "getent" if arguments.first().map(String::as_str) == Some("group") => {
                self.mark_snapshot_provider("group");
                let records = self.context.group_records.map_or_else(
                    || {
                        self.context
                            .groups
                            .unwrap_or_default()
                            .iter()
                            .map(|group| format!("{group}:x:0:"))
                            .collect()
                    },
                    <[String]>::to_vec,
                );
                Ok(CommandResult::output(records))
            }
            "builtin"
                if arguments
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "-n" | "--names")) =>
            {
                Ok(CommandResult::output(
                    FISH_BUILTIN_NAMES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                ))
            }
            "builtin" if availability_query(arguments) => {
                Ok(self.command_query(arguments, AvailabilityKind::Builtin))
            }
            "command" | "noglob" | "exec" => {
                let arguments = arguments
                    .iter()
                    .skip_while(|argument| argument.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>();
                let Some((command, rest)) = arguments.split_first() else {
                    return Ok(CommandResult::success());
                };
                if self.module.dialect == ScriptDialect::Fish
                    || self.functions.contains_key(command)
                {
                    self.external(command, rest)
                } else {
                    self.invoke(command, rest, input)
                }
            }
            "builtin" => {
                let arguments = arguments
                    .iter()
                    .skip_while(|argument| argument.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>();
                let Some((command, rest)) = arguments.split_first() else {
                    return Ok(CommandResult::success());
                };
                let shadowed = self.functions.remove(command);
                let result = self.invoke(command, rest, input);
                if let Some(function) = shadowed {
                    self.functions.insert(command.clone(), function);
                }
                result
            }
            "not" | "!" => {
                let Some((command, rest)) = arguments.split_first() else {
                    return Ok(CommandResult::status(1));
                };
                let mut result = self.invoke(command, rest, input)?;
                result.status = i32::from(result.status == 0);
                Ok(result)
            }
            "and" => {
                if self.last_status == 0 {
                    self.invoke_argv(arguments, input)
                } else {
                    Ok(CommandResult::status(self.last_status))
                }
            }
            "or" => {
                if self.last_status != 0 {
                    self.invoke_argv(arguments, input)
                } else {
                    Ok(CommandResult::status(0))
                }
            }
            "contains" => self.contains_builtin(arguments),
            "count" => Ok(CommandResult {
                status: i32::from(arguments.is_empty()),
                output: vec![arguments.len().to_string()],
                control: Control::None,
            }),
            "string" => self.string_builtin(arguments, input),
            "math" => Ok(CommandResult::output(vec![
                self.eval_arithmetic(&arguments.join(" ")).to_string(),
            ])),
            "seq" => Ok(CommandResult::output(sequence_values(arguments))),
            "commandline" => self.commandline_builtin(arguments),
            "bind" => self.bind_builtin(arguments),
            "set_color"
                if arguments
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "-c" | "--print-colors")) =>
            {
                Ok(CommandResult::output(
                    FISH_COLOR_NAMES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                ))
            }
            "set_color" => Ok(CommandResult::success()),
            "trap" | "kill"
                if arguments
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "-l" | "--list-signals")) =>
            {
                Ok(CommandResult::output(self.signal_values()))
            }
            "path" => self.path_builtin(arguments, input),
            "complete" => self.complete_builtin(arguments),
            "compgen" => self.compgen_builtin(arguments),
            "shopt" => self.shopt_builtin(arguments),
            "compopt" => self.compopt_builtin(arguments),
            "compadd" => self.compadd_builtin(arguments),
            "compset" => self.compset_builtin(arguments),
            "comparguments" => self.comparguments_builtin(arguments),
            "zstyle" => self.zstyle_builtin(arguments),
            "print" => self.print_builtin(arguments),
            "_message" => Ok(CommandResult::success()),
            "basename" => {
                let multiple = arguments
                    .iter()
                    .any(|argument| argument == "-a" || argument == "--multiple");
                let operands = arguments
                    .iter()
                    .filter(|argument| !argument.starts_with('-'))
                    .collect::<Vec<_>>();
                let names = if multiple {
                    operands.as_slice()
                } else {
                    operands.get(..1).unwrap_or_default()
                };
                let suffix = (!multiple)
                    .then(|| operands.get(1))
                    .flatten()
                    .map(|value| value.as_str());
                Ok(CommandResult::output(
                    names
                        .iter()
                        .map(|value| {
                            let name = value
                                .rsplit_once('/')
                                .map_or(value.as_str(), |(_, tail)| tail);
                            suffix
                                .and_then(|suffix| name.strip_suffix(suffix))
                                .unwrap_or(name)
                                .to_owned()
                        })
                        .collect(),
                ))
            }
            "dirname" => {
                let operands = arguments
                    .iter()
                    .filter(|argument| !argument.starts_with('-'))
                    .collect::<Vec<_>>();
                Ok(CommandResult::output(
                    operands
                        .iter()
                        .map(|value| {
                            value
                                .rsplit_once('/')
                                .map_or(".", |(head, _)| if head.is_empty() { "/" } else { head })
                                .to_owned()
                        })
                        .collect(),
                ))
            }
            "sort" => {
                let mut values = if input.is_empty() {
                    arguments.to_vec()
                } else {
                    input.to_vec()
                };
                values.sort();
                if arguments.iter().any(|argument| argument == "-u") {
                    values.dedup();
                }
                Ok(CommandResult::output(values))
            }
            "uniq" => {
                let mut values = input.to_vec();
                values.dedup();
                Ok(CommandResult::output(values))
            }
            "head" | "tail" => self.head_tail_builtin(name, arguments, input),
            "cut" => self.cut_builtin(arguments, input),
            "tr" => self.tr_builtin(arguments, input),
            "grep" => self.grep_builtin(arguments, input),
            "awk" => self.awk_builtin(arguments, input),
            "sed" => sed_builtin(arguments, input),
            "cat" => self.cat_builtin(arguments, input),
            _ => self.external(name, arguments),
        }
    }

    fn bash_process_completion(&mut self, names: bool) -> CommandResult {
        self.mark_snapshot_provider("process");
        let values = if names {
            self.process_names()
        } else {
            self.context.process_ids.unwrap_or_default().to_vec()
        }
        .into_iter()
        .filter(|value| value.starts_with(self.context.current_word.trim_start_matches('%')))
        .collect::<Vec<_>>();
        let status = i32::from(values.is_empty());
        self.set_values("COMPREPLY", values, false);
        if let Some(variable) = self.variables.get_mut("COMPREPLY") {
            variable.array = true;
        }
        CommandResult::status(status)
    }

    fn bash_filedir_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let query = self.context.current_word;
        let pattern = if query.is_empty() {
            "*".to_owned()
        } else {
            format!("{query}*")
        };
        let Some(mut values) = self.filesystem_values(FilesystemRequestKind::Glob, &pattern, None)
        else {
            return Ok(CommandResult::success());
        };
        if let Some(extension) = arguments
            .iter()
            .find(|argument| !argument.starts_with('-') && !argument.is_empty())
        {
            let suffix = format!(".{extension}");
            values.retain(|value| value.ends_with(&suffix));
        }
        values.retain(|value| value.starts_with(query));
        if values.is_empty() {
            self.set_values("COMPREPLY", Vec::new(), false);
            if let Some(variable) = self.variables.get_mut("COMPREPLY") {
                variable.array = true;
            }
            return Ok(CommandResult::status(1));
        }
        self.check_values(&values)?;
        self.set_values("COMPREPLY", values, false);
        if let Some(variable) = self.variables.get_mut("COMPREPLY") {
            variable.array = true;
        }
        self.path_completion = self.path_completion.merge(PathCompletion::Files);
        Ok(CommandResult::success())
    }

    fn bash_builtin_help_completion(&mut self, arguments: &[String]) -> CommandResult {
        let Some(topic) = arguments.get(2) else {
            return CommandResult::status(1);
        };
        let Some(options) = bash_builtin_options(topic) else {
            return CommandResult::status(1);
        };
        let options = options
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if options.is_empty() {
            return CommandResult::status(1);
        }
        let values = options
            .into_iter()
            .filter(|option| option.starts_with(self.context.current_word))
            .collect::<Vec<_>>();
        self.set_values("COMPREPLY", values, false);
        if let Some(variable) = self.variables.get_mut("COMPREPLY") {
            variable.array = true;
        }
        CommandResult::success()
    }

    fn bash_command_offset_builtin(
        &mut self,
        arguments: &[String],
    ) -> Result<CommandResult, VmError> {
        let offset = arguments
            .first()
            .and_then(|argument| self.resolve_index(argument, "COMP_WORDS"))
            .unwrap_or(self.context.word_index);
        if self.context.word_index <= offset {
            self.set_values("COMPREPLY", self.command_names(), false);
            if let Some(variable) = self.variables.get_mut("COMPREPLY") {
                variable.array = true;
            }
            self.path_completion = self.path_completion.merge(PathCompletion::Files);
            return Ok(CommandResult::success());
        }
        let line = self
            .context
            .words
            .get(offset..)
            .unwrap_or_default()
            .join(" ");
        if let Some(values) = self.completion_results.get(&line) {
            let mut output = Vec::with_capacity(values.len());
            for value in values {
                if let Some(path_completion) = nested_completion_path(value) {
                    self.path_completion = self.path_completion.merge(path_completion);
                } else {
                    output.push(value.clone());
                }
            }
            self.check_values(&output)?;
            self.set_values("COMPREPLY", output, false);
            if let Some(variable) = self.variables.get_mut("COMPREPLY") {
                variable.array = true;
            }
            return Ok(CommandResult::success());
        }
        let request = CompletionRequest { line };
        if !self.completion_requests.contains(&request) {
            if self.completion_requests.len() >= MAX_COMPLETION_REQUESTS {
                return Err(VmError::Limit("nested completion requests"));
            }
            self.completion_requests.push(request);
        }
        Ok(CommandResult::success())
    }

    fn command_query(&self, arguments: &[String], kind: AvailabilityKind) -> CommandResult {
        let quiet = arguments
            .iter()
            .take_while(|value| value.starts_with('-'))
            .any(|argument| {
                argument == "--query"
                    || argument
                        .strip_prefix('-')
                        .is_some_and(|flags| flags.contains('q'))
            });
        let targets = arguments
            .iter()
            .skip_while(|argument| argument.starts_with('-'))
            .filter(|argument| argument.as_str() != "--")
            .collect::<Vec<_>>();
        let available = !targets.is_empty()
            && targets.iter().all(|target| match kind {
                AvailabilityKind::Command => {
                    self.functions.contains_key(target.as_str())
                        || self.context.command_available(target).unwrap_or(false)
                }
                AvailabilityKind::Function => self.functions.contains_key(target.as_str()),
                AvailabilityKind::Builtin => SHELL_BUILTINS.contains(&target.as_str()),
            });
        if !available {
            return CommandResult::status(1);
        }
        if quiet {
            CommandResult::success()
        } else {
            CommandResult::output(targets.into_iter().cloned().collect())
        }
    }

    fn invoke_argv(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let Some((name, rest)) = arguments.split_first() else {
            return Ok(CommandResult::success());
        };
        self.invoke(name, rest, input)
    }

    fn call_function(
        &mut self,
        name: &str,
        arguments: &[String],
    ) -> Result<CommandResult, VmError> {
        let Some(function) = self.functions.get(name).cloned() else {
            return Ok(CommandResult::status(127));
        };
        self.call(&function, arguments)
    }

    fn call(
        &mut self,
        function: &ScriptFunction,
        arguments: &[String],
    ) -> Result<CommandResult, VmError> {
        self.call_depth += 1;
        if self.call_depth > MAX_CALL_DEPTH {
            self.call_depth = self.call_depth.saturating_sub(1);
            return Err(VmError::Limit("shell call depth"));
        }
        self.active_functions.push(function.name.clone());
        self.scopes.push(HashMap::new());
        let saved_tags = (
            self.active_tags.clone(),
            self.tags_iterated,
            self.tag_context_initialized,
            self.tag_label_iterations.clone(),
        );
        let saved = save_positional(&self.variables);
        self.set_positional(arguments);
        if self.module.dialect == ScriptDialect::Zsh {
            self.mark_local("OPTIND");
            self.mark_local("__bashlume_getopts_character");
            self.set_values("OPTIND", vec!["1".into()], false);
            self.set_values("__bashlume_getopts_character", vec!["1".into()], false);
        }
        if self.module.dialect == ScriptDialect::Fish {
            let argument_names = fish_function_argument_names(&function.arguments);
            for (name, value) in argument_names.iter().zip(arguments) {
                self.set_values(name, vec![value.clone()], false);
            }
        }
        let execution = self.exec_statements(&function.body);
        restore_positional(&mut self.variables, saved);
        if let Some(scope) = self.scopes.pop() {
            for (name, original) in scope {
                if let Some(variable) = original {
                    self.variables.insert(name, variable);
                } else {
                    self.variables.remove(&name);
                }
            }
        }
        self.call_depth = self.call_depth.saturating_sub(1);
        self.active_functions.pop();
        (
            self.active_tags,
            self.tags_iterated,
            self.tag_context_initialized,
            self.tag_label_iterations,
        ) = saved_tags;
        let mut result = execution?;
        if let Control::Return(status) = result.control {
            result.status = status;
            result.control = Control::None;
        }
        Ok(result)
    }

    fn restore_assignments(&mut self, saved: Vec<(String, Option<Variable>)>) {
        for (name, variable) in saved {
            if let Some(variable) = variable {
                self.variables.insert(name, variable);
            } else {
                self.variables.remove(&name);
            }
        }
    }

    fn apply_assignment(&mut self, assignment: &ScriptAssignment) -> Result<(), VmError> {
        let array_assignment = assignment.index.is_some()
            || assignment
                .value
                .parts
                .iter()
                .any(|part| matches!(part, ScriptWordPart::Array { .. }));
        let mut values = if array_assignment {
            self.expand_command_word(&assignment.value)?
        } else {
            self.expand_word_preserving_fields(&assignment.value)?
        };
        if !array_assignment && values.len() > 1 {
            values = vec![values.join(" ")];
        }
        if let Some(index) = &assignment.index {
            let index = self
                .expand_word(index)?
                .first()
                .cloned()
                .unwrap_or_default();
            let associative = self
                .variables
                .get(&assignment.name)
                .is_some_and(|variable| variable.associative);
            if associative {
                let variable = self.variables.entry(assignment.name.clone()).or_default();
                if !variable.readonly {
                    let addition = values.join(" ");
                    if let Some(position) = variable
                        .values
                        .chunks_exact(2)
                        .position(|pair| pair[0] == index)
                    {
                        if assignment.append {
                            variable.values[position * 2 + 1].push_str(&addition);
                        } else {
                            variable.values[position * 2 + 1] = addition;
                        }
                    } else {
                        variable.values.push(index);
                        variable.values.push(addition);
                    }
                }
            } else {
                let index = self
                    .resolve_index(&index, assignment.name.as_str())
                    .unwrap_or(0);
                let compound_value = assignment
                    .value
                    .parts
                    .iter()
                    .any(|part| matches!(part, ScriptWordPart::Array { .. }));
                let variable = self.variables.entry(assignment.name.clone()).or_default();
                if !variable.readonly {
                    if variable.values.len() <= index {
                        variable.values.resize(index + 1, String::new());
                    }
                    if assignment.append
                        && self.module.dialect == ScriptDialect::Zsh
                        && compound_value
                    {
                        let insertion = (index + 1).min(variable.values.len());
                        variable.values.splice(insertion..insertion, values);
                    } else if assignment.append {
                        variable.values[index].push_str(&values.join(""));
                    } else {
                        variable.values[index] = values.join(" ");
                    }
                }
            }
        } else if assignment.append {
            let variable = self.variables.entry(assignment.name.clone()).or_default();
            variable.array |= array_assignment;
            if !variable.readonly {
                if variable.array {
                    variable.values.extend(values);
                } else {
                    let addition = values.join("");
                    if let Some(value) = variable.values.first_mut() {
                        value.push_str(&addition);
                    } else {
                        variable.values.push(addition);
                    }
                }
            }
        } else {
            if self
                .variables
                .get(&assignment.name)
                .is_some_and(|variable| variable.associative)
                && values.iter().any(|value| {
                    value
                        .strip_prefix('[')
                        .and_then(|value| value.split_once("]="))
                        .is_some()
                })
            {
                values = values
                    .into_iter()
                    .flat_map(|value| {
                        if let Some((key, item)) = value
                            .strip_prefix('[')
                            .and_then(|value| value.split_once("]="))
                        {
                            vec![key.to_owned(), item.to_owned()]
                        } else {
                            vec![value]
                        }
                    })
                    .collect();
            }
            self.set_values(&assignment.name, values, false);
            if array_assignment {
                if let Some(variable) = self.variables.get_mut(&assignment.name) {
                    variable.array = true;
                }
            }
        }
        Ok(())
    }

    fn expand_word(&mut self, word: &ScriptWord) -> Result<Vec<String>, VmError> {
        let mut values = vec![String::new()];
        let mut part_index = 0;
        while part_index < word.parts.len() {
            let part = &word.parts[part_index];
            let mut consumed_parts = 1;
            let mut additions = match part {
                ScriptWordPart::Literal { value, quoted } => {
                    if *quoted || self.suppress_word_splitting {
                        vec![value.clone()]
                    } else {
                        expand_braces(value)
                    }
                }
                ScriptWordPart::Parameter { expression, quoted } => {
                    let mut output = self.expand_parameter(expression, *quoted);
                    if let Some(ScriptWordPart::Literal {
                        value: slice,
                        quoted: false,
                    }) = word.parts.get(part_index + 1)
                    {
                        if let Some(expression) = slice
                            .strip_prefix('[')
                            .and_then(|slice| slice.strip_suffix(']'))
                        {
                            output =
                                select_parameter_indices(&output, expression, self.module.dialect);
                            consumed_parts = 2;
                        }
                    }
                    output
                }
                ScriptWordPart::CommandSubstitution { statements, quoted } => {
                    let result = self.exec_statements(statements)?;
                    let mut output = if *quoted {
                        vec![result.output.join("\n")]
                    } else if self.module.dialect == ScriptDialect::Bash
                        && !self.suppress_word_splitting
                    {
                        let separators = self
                            .variable_values("IFS")
                            .first()
                            .cloned()
                            .unwrap_or_else(|| " \t\n".into());
                        result
                            .output
                            .iter()
                            .flat_map(|value| split_shell_fields(value, &separators))
                            .collect()
                    } else {
                        result.output
                    };
                    if let Some(ScriptWordPart::Literal {
                        value: slice,
                        quoted: false,
                    }) = word.parts.get(part_index + 1)
                    {
                        if let Some(expression) = slice
                            .strip_prefix('[')
                            .and_then(|slice| slice.strip_suffix(']'))
                        {
                            output =
                                select_parameter_indices(&output, expression, self.module.dialect);
                            consumed_parts = 2;
                        }
                    }
                    output
                }
                ScriptWordPart::Arithmetic { expression, .. } => {
                    vec![self.eval_arithmetic(expression).to_string()]
                }
                ScriptWordPart::BraceExpansion { alternatives, .. } => {
                    let mut output = Vec::new();
                    for alternative in alternatives {
                        output.extend(self.expand_word(alternative)?);
                    }
                    output
                }
                ScriptWordPart::Array { elements } => {
                    let mut output = Vec::new();
                    for element in elements {
                        output.extend(self.expand_word(element)?);
                    }
                    output
                }
                ScriptWordPart::DeferredScript { source, .. } => vec![source.clone()],
            };
            if additions.is_empty() {
                let zsh_rc_expand = self.module.dialect == ScriptDialect::Zsh
                    && matches!(
                        part,
                        ScriptWordPart::Parameter { expression, .. }
                            if zsh_parameter_uses_rc_expansion(expression)
                    );
                if zsh_rc_expand
                    || word.parts.len() == 1
                    || part_index == 0 && consumed_parts == word.parts.len()
                {
                    return Ok(Vec::new());
                }
                additions.push(String::new());
            }
            let mut combined = Vec::new();
            for prefix in &values {
                for addition in &additions {
                    let mut value = prefix.clone();
                    value.push_str(addition);
                    if value.len() > MAX_VALUE_BYTES {
                        return Err(VmError::Limit("expanded shell value"));
                    }
                    combined.push(value);
                    if combined.len() > MAX_VALUES {
                        return Err(VmError::Limit("expanded shell values"));
                    }
                }
            }
            values = combined;
            part_index += consumed_parts;
        }
        Ok(values)
    }

    fn expand_case_pattern(&mut self, word: &ScriptWord) -> Result<Vec<String>, VmError> {
        let mut values = vec![String::new()];
        for part in &word.parts {
            let quoted = matches!(
                part,
                ScriptWordPart::Literal { quoted: true, .. }
                    | ScriptWordPart::Parameter { quoted: true, .. }
                    | ScriptWordPart::CommandSubstitution { quoted: true, .. }
                    | ScriptWordPart::Arithmetic { quoted: true, .. }
                    | ScriptWordPart::BraceExpansion { quoted: true, .. }
            );
            let part_word = ScriptWord {
                parts: vec![part.clone()],
                raw: None,
            };
            let mut additions = self.expand_word_preserving_fields(&part_word)?;
            if additions.is_empty() {
                additions.push(String::new());
            }
            if quoted {
                additions = additions
                    .into_iter()
                    .map(|value| escape_shell_pattern_literal(&value))
                    .collect();
            }
            let mut combined = Vec::new();
            for value in &values {
                for addition in &additions {
                    if combined.len() >= MAX_VALUES {
                        break;
                    }
                    combined.push(format!("{value}{addition}"));
                }
            }
            values = combined;
        }
        Ok(values)
    }

    fn expand_word_preserving_fields(&mut self, word: &ScriptWord) -> Result<Vec<String>, VmError> {
        let saved = self.suppress_word_splitting;
        self.suppress_word_splitting = true;
        let result = self.expand_word(word);
        self.suppress_word_splitting = saved;
        result
    }

    fn expand_command_word(&mut self, word: &ScriptWord) -> Result<Vec<String>, VmError> {
        if let [ScriptWordPart::Array { elements }] = word.parts.as_slice() {
            let mut output = Vec::new();
            for element in elements {
                output.extend(self.expand_command_word(element)?);
            }
            return Ok(output);
        }
        if let [ScriptWordPart::BraceExpansion { alternatives, .. }] = word.parts.as_slice() {
            let mut output = Vec::new();
            for alternative in alternatives {
                output.extend(self.expand_command_word(alternative)?);
            }
            return Ok(output);
        }
        let values = self.expand_word(word)?;
        if !word_allows_pathname_expansion(word, self.module.dialect) {
            return Ok(values);
        }
        let mut output = Vec::new();
        for value in values {
            let zsh_completion_specification = self.module.dialect == ScriptDialect::Zsh
                && zsh_spec_description(&value).is_some()
                && !zsh_spec_options(&value).is_empty()
                && !word_has_unquoted_path_glob(word, self.module.dialect);
            if zsh_completion_specification || !has_shell_glob(self.module.dialect, &value) {
                output.push(value);
                continue;
            }
            let Some(matches) = self.filesystem_values(FilesystemRequestKind::Glob, &value, None)
            else {
                continue;
            };
            if matches.is_empty() && self.module.dialect == ScriptDialect::Bash {
                output.push(value);
            } else {
                output.extend(matches);
            }
        }
        Ok(output)
    }

    fn expand_parameter(&mut self, expression: &str, quoted: bool) -> Vec<String> {
        let mut expression = expression.trim();
        let force_word_split =
            self.module.dialect == ScriptDialect::Zsh && expression.starts_with('=');
        let mut split_lines = false;
        let mut preserve_array = false;
        let mut unique = false;
        let mut match_filter = false;
        let mut associative_keys = false;
        let mut associative_values = false;
        let mut zsh_indirect = false;
        let mut evaluate_expansion = false;
        let mut sort_ascending = false;
        let mut sort_descending = false;
        let mut quote_level = 0_usize;
        let mut unquote_expansion = false;
        let mut join = None;
        let mut split_separator = None;
        while expression.starts_with('(') {
            let Some(close) = expression.find(')') else {
                break;
            };
            let flags = &expression[1..close];
            split_lines |= flags.contains('f');
            preserve_array |= flags.contains('@');
            unique |= flags.contains('u');
            match_filter |= flags.contains('M');
            associative_keys |= flags.contains('k');
            associative_values |= flags.contains('v');
            zsh_indirect |= flags.contains('P');
            evaluate_expansion |= flags.contains('e');
            sort_ascending |= flags.contains('o');
            sort_descending |= flags.contains('O');
            quote_level = quote_level.max(flags.chars().filter(|flag| *flag == 'q').count());
            unquote_expansion |= flags.contains('Q');
            if let Some(separator) = zsh_parameter_flag_argument(flags, 'j') {
                join = Some(separator);
            }
            if let Some(separator) = zsh_parameter_flag_argument(flags, 's') {
                split_separator = Some(separator);
            }
            expression = &expression[close + 1..];
        }
        expression = expression.trim_start_matches(['^', '=', '~']);
        if self.module.dialect == ScriptDialect::Zsh {
            if expression == "compstate[nmatches]" {
                return vec![self.candidates.len().to_string()];
            }
            if matches!(
                expression,
                "compstate[quote]" | "compstate[quoting]" | "compstate[insert]"
            ) {
                return vec![String::new()];
            }
            if let Some(reference) = expression.strip_prefix('+') {
                return vec![i32::from(self.zsh_parameter_exists(reference)).to_string()];
            }
        }
        let indirect = expression.starts_with('!');
        if indirect {
            expression = &expression[1..];
        }
        let length = expression.starts_with('#') && expression.len() > 1;
        if length {
            expression = &expression[1..];
        }
        if self.module.dialect == ScriptDialect::Zsh && expression.starts_with("${") {
            if let Some(close) = matching_ascii(&expression[1..], '{', '}') {
                let end = close + 1;
                let mut values = self.expand_parameter(&expression[2..end], quoted);
                if zsh_indirect {
                    values = values
                        .iter()
                        .flat_map(|target| self.variable_values(target))
                        .collect();
                }
                if split_lines {
                    values = values
                        .iter()
                        .flat_map(|value| value.lines().map(str::to_owned).collect::<Vec<_>>())
                        .collect();
                }
                if let Some(separator) = &split_separator {
                    values = values
                        .iter()
                        .flat_map(|value| {
                            if separator.is_empty() {
                                value.chars().map(String::from).collect::<Vec<_>>()
                            } else {
                                value
                                    .split(separator)
                                    .filter(|value| !value.is_empty())
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>()
                            }
                        })
                        .collect();
                }
                if unique {
                    let mut seen = HashSet::new();
                    values.retain(|value| seen.insert(value.clone()));
                }
                if let Some(separator) = &join {
                    values = vec![values.join(separator)];
                }
                let temporary = "__bashlume_nested_parameter";
                let saved = self.variables.insert(
                    temporary.into(),
                    Variable {
                        values,
                        exported: false,
                        readonly: false,
                        array: true,
                        associative: false,
                    },
                );
                let mut flags = String::new();
                if match_filter {
                    flags.push('M');
                }
                if evaluate_expansion {
                    flags.push('e');
                }
                let flag_prefix = if flags.is_empty() {
                    String::new()
                } else {
                    format!("({flags})")
                };
                let outer = format!(
                    "{flag_prefix}{}{temporary}{}",
                    if length { "#" } else { "" },
                    &expression[end + 1..]
                );
                let values = self.expand_parameter(
                    &outer,
                    quoted && !preserve_array && !split_lines && split_separator.is_none(),
                );
                if let Some(saved) = saved {
                    self.variables.insert(temporary.into(), saved);
                } else {
                    self.variables.remove(temporary);
                }
                return values;
            }
        }
        let name_end = if expression
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'@' | b'*' | b'#' | b'?' | b'$' | b'!' | b'-'))
        {
            1
        } else {
            expression
                .char_indices()
                .take_while(|(_, character)| *character == '_' || character.is_ascii_alphanumeric())
                .map(|(index, character)| index + character.len_utf8())
                .last()
                .unwrap_or(0)
        };
        if name_end == 0 {
            return vec![String::new()];
        }
        let name = &expression[..name_end];
        let mut rest = &expression[name_end..];
        let associative = self
            .variables
            .get(name)
            .is_some_and(|variable| variable.associative);
        let scalar = self
            .variables
            .get(name)
            .is_some_and(|variable| !variable.array);
        let associative_entries = if associative {
            self.variable_values(name)
        } else {
            Vec::new()
        };
        let mut values = if associative {
            let entries = associative_entries.chunks_exact(2).collect::<Vec<_>>();
            zsh_associative_scan_indices(&entries)
                .into_iter()
                .flat_map(|index| {
                    if associative_keys && associative_values {
                        vec![entries[index][0].clone(), entries[index][1].clone()]
                    } else if associative_keys {
                        vec![entries[index][0].clone()]
                    } else {
                        vec![entries[index][1].clone()]
                    }
                })
                .collect()
        } else if associative_keys && name == "functions" {
            let mut seen = HashSet::new();
            let mut names = Vec::new();
            for name in self
                .module
                .zsh_function_names
                .iter()
                .chain(self.context.shell_functions.unwrap_or_default().iter())
                .chain(self.function_order.iter())
            {
                if seen.insert(name.clone()) {
                    names.push(name.clone());
                }
            }
            let owned_entries = names
                .into_iter()
                .map(|name| vec![name, String::new()])
                .collect::<Vec<_>>();
            let entries = owned_entries.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let indices = if self.module.zsh_function_snapshot
                || !self.module.zsh_function_names.is_empty()
            {
                zsh_hash_scan_indices(
                    &entries,
                    7,
                    self.module.zsh_function_table_size.max(7) as usize,
                )
            } else if self.module.zsh_function_table_size == 0 {
                zsh_associative_scan_indices(&entries)
            } else {
                zsh_function_scan_indices(&entries, self.module.zsh_function_table_size as usize)
            };
            indices
                .into_iter()
                .map(|index| entries[index][0].clone())
                .collect()
        } else if associative_keys && name == "parameters" {
            let mut entries = self
                .variables
                .keys()
                .cloned()
                .map(|name| vec![name, String::new()])
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left[0].cmp(&right[0]));
            let borrowed = entries.iter().map(Vec::as_slice).collect::<Vec<_>>();
            zsh_associative_scan_indices(&borrowed)
                .into_iter()
                .map(|index| borrowed[index][0].clone())
                .collect()
        } else {
            self.variable_values(name)
        };
        if indirect
            && !matches!(
                rest.strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']')),
                Some("@" | "*")
            )
        {
            let reference = values.first().cloned().unwrap_or_default();
            let (target, index) = split_variable_reference(&reference);
            values = self.variable_values(target);
            if let Some(index) = index {
                values = values.get(index as usize).cloned().into_iter().collect();
            }
        }
        let mut all_indices = false;
        let mut had_subscript = false;
        if rest.starts_with('[') {
            had_subscript = true;
            if let Some(close) = matching_ascii(rest, '[', ']') {
                let index_expression = &rest[1..close];
                all_indices = matches!(index_expression, "@" | "*");
                if associative
                    && (index_expression.starts_with("(r)") || index_expression.starts_with("(R)"))
                {
                    let all_matches = index_expression.starts_with("(R)");
                    let pattern = self.expand_pattern_inline(&index_expression[3..]);
                    let entries = associative_entries.chunks_exact(2).collect::<Vec<_>>();
                    values = zsh_associative_scan_indices(&entries)
                        .into_iter()
                        .filter(|index| {
                            shell_pattern_dialect(ScriptDialect::Zsh, &pattern, &entries[*index][1])
                        })
                        .flat_map(|index| {
                            if associative_keys && associative_values {
                                vec![entries[index][0].clone(), entries[index][1].clone()]
                            } else if associative_keys {
                                vec![entries[index][0].clone()]
                            } else {
                                vec![entries[index][1].clone()]
                            }
                        })
                        .collect();
                    if !all_matches {
                        values.truncate(1);
                    }
                } else if associative && !all_indices {
                    let key = self.expand_inline(index_expression);
                    values = associative_entries
                        .chunks_exact(2)
                        .find(|pair| pair[0] == key)
                        .map(|pair| vec![pair[1].clone()])
                        .unwrap_or_default();
                } else if self.module.dialect == ScriptDialect::Zsh
                    && (index_expression.starts_with("(r)") || index_expression.starts_with("(R)"))
                {
                    let all_matches = index_expression.starts_with("(R)");
                    let pattern = &index_expression[3..];
                    values
                        .retain(|value| shell_pattern_dialect(ScriptDialect::Zsh, pattern, value));
                    if !all_matches {
                        values.truncate(1);
                    }
                } else if self.module.dialect == ScriptDialect::Zsh
                    && (index_expression.starts_with("(i)")
                        || index_expression.starts_with("(I)")
                        || index_expression.starts_with("(ib."))
                {
                    let flags_end = index_expression.find(')').unwrap_or(2);
                    let flags = &index_expression[1..flags_end];
                    let pattern = &index_expression[flags_end + 1..];
                    let start = flags
                        .strip_prefix("ib.")
                        .and_then(|value| value.strip_suffix('.'))
                        .and_then(|name| self.variable_values(name).first().cloned())
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(1)
                        .saturating_sub(1);
                    let pattern_matches =
                        |value: &str| shell_pattern_dialect(ScriptDialect::Zsh, pattern, value);
                    let reverse = flags.starts_with('I');
                    let position = if reverse {
                        values.iter().rposition(|value| pattern_matches(value))
                    } else {
                        values
                            .iter()
                            .enumerate()
                            .skip(start)
                            .find(|(_, value)| pattern_matches(value))
                            .map(|(index, _)| index)
                    }
                    .map_or_else(
                        || if reverse { 0 } else { values.len() + 1 },
                        |index| index + 1,
                    );
                    values = vec![position.to_string()];
                } else if indirect && all_indices {
                    values = (0..values.len()).map(|index| index.to_string()).collect();
                } else {
                    let resolved_index;
                    let index_expression = if all_indices
                        || index_expression.parse::<isize>().is_ok()
                        || index_expression.contains([',', '.'])
                    {
                        index_expression
                    } else {
                        resolved_index = self.eval_arithmetic(index_expression).to_string();
                        &resolved_index
                    };
                    if self.module.dialect == ScriptDialect::Zsh && scalar && values.len() == 1 {
                        values = values[0].chars().map(String::from).collect();
                    }
                    values =
                        select_parameter_indices(&values, index_expression, self.module.dialect);
                }
                rest = &rest[close + 1..];
            }
        }
        if zsh_indirect {
            values = values
                .iter()
                .flat_map(|target| self.variable_values(target))
                .collect();
        }
        if self.module.dialect == ScriptDialect::Bash
            && !had_subscript
            && !matches!(name, "@" | "*")
            && self
                .variables
                .get(name)
                .is_some_and(|variable| variable.array)
        {
            values.truncate(1);
        }
        if self.module.dialect == ScriptDialect::Zsh && zsh_simple_modifiers(rest) {
            values = values
                .into_iter()
                .map(|value| apply_zsh_simple_modifiers(value, rest))
                .collect();
            rest = "";
        }
        if self.module.dialect == ScriptDialect::Zsh && rest.starts_with(":#") {
            let pattern = self.expand_pattern_inline(&rest[2..]);
            values.retain(|value| {
                shell_pattern_dialect(ScriptDialect::Zsh, &pattern, value) == match_filter
            });
        } else if rest.starts_with(':')
            && !rest.starts_with(":-")
            && !rest.starts_with(":+")
            && !rest.starts_with(":=")
        {
            let slice = &rest[1..];
            let mut sections = slice.splitn(2, ':');
            let offset = sections
                .next()
                .map(|value| self.eval_arithmetic(value))
                .unwrap_or(0);
            let length = sections
                .next()
                .map(|value| self.eval_arithmetic(value).max(0) as usize);
            let array_slice = matches!(name, "@" | "*")
                || all_indices
                || self
                    .variables
                    .get(name)
                    .is_some_and(|variable| variable.array && had_subscript);
            if array_slice {
                let start = if self.module.dialect == ScriptDialect::Bash {
                    if matches!(name, "@" | "*") {
                        offset.saturating_sub(1).max(0) as usize
                    } else {
                        offset.max(0) as usize
                    }
                } else {
                    offset.max(1).saturating_sub(1) as usize
                };
                values = values
                    .into_iter()
                    .skip(start)
                    .take(length.unwrap_or(usize::MAX))
                    .collect();
            } else {
                values = values
                    .into_iter()
                    .map(|value| shell_substring(&value, offset, length))
                    .collect();
            }
        } else if let Some(default) = rest.strip_prefix(":=").or_else(|| rest.strip_prefix('=')) {
            if values.is_empty() || values.iter().all(String::is_empty) {
                values = self.expand_inline_values(default);
                self.set_values(name, values.clone(), false);
            }
        } else if let Some(default) = rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-')) {
            if values.is_empty() || values.iter().all(String::is_empty) {
                values = self.expand_inline_values(default);
            }
        } else if let Some(alternate) = rest.strip_prefix(":+").or_else(|| rest.strip_prefix('+')) {
            values = if values.is_empty() {
                Vec::new()
            } else {
                self.expand_inline_values(alternate)
            };
        } else if rest.starts_with("##") || rest.starts_with('#') {
            let longest = rest.starts_with("##");
            let pattern = self.expand_pattern_inline(rest.trim_start_matches('#'));
            values = values
                .into_iter()
                .map(|value| {
                    let remainder = remove_prefix_pattern(&value, &pattern, longest);
                    if match_filter {
                        value[..value.len().saturating_sub(remainder.len())].to_owned()
                    } else {
                        remainder
                    }
                })
                .collect();
        } else if rest.starts_with("%%") || rest.starts_with('%') {
            let longest = rest.starts_with("%%");
            let pattern = self.expand_pattern_inline(rest.trim_start_matches('%'));
            values = values
                .into_iter()
                .map(|value| {
                    let remainder = remove_suffix_pattern(&value, &pattern, longest);
                    if match_filter {
                        value[remainder.len()..].to_owned()
                    } else {
                        remainder
                    }
                })
                .collect();
        } else if let Some(replacement) = rest.strip_prefix("//") {
            let (pattern, replacement) = replacement.split_once('/').unwrap_or((replacement, ""));
            let mut replaced = Vec::with_capacity(values.len());
            for value in values {
                replaced.push(self.replace_parameter_pattern(&value, pattern, replacement, true));
            }
            values = replaced;
        } else if let Some(replacement) = rest.strip_prefix('/') {
            let (pattern, replacement) = replacement.split_once('/').unwrap_or((replacement, ""));
            let mut replaced = Vec::with_capacity(values.len());
            for value in values {
                replaced.push(self.replace_parameter_pattern(&value, pattern, replacement, false));
            }
            values = replaced;
        }
        if evaluate_expansion {
            values = values
                .iter()
                .map(|value| self.expand_inline(value))
                .collect();
        }
        if length {
            let array_length = all_indices
                || self.module.dialect == ScriptDialect::Zsh
                    && self
                        .variables
                        .get(name)
                        .is_some_and(|variable| variable.array);
            values = vec![if array_length {
                values.len().to_string()
            } else {
                values.first().map_or(0, String::len).to_string()
            }];
        } else if (quoted
            || self.suppress_word_splitting && self.module.dialect != ScriptDialect::Fish)
            && values.is_empty()
            && !preserve_array
            && !all_indices
            && !matches!(name, "@" | "*")
        {
            values.push(String::new());
        }
        let explicit_field_split = split_lines || split_separator.is_some() || force_word_split;
        if force_word_split {
            let separators = self
                .variable_values("IFS")
                .first()
                .cloned()
                .unwrap_or_else(|| " \t\n".into());
            values = values
                .iter()
                .flat_map(|value| split_shell_fields(value, &separators))
                .collect();
        }
        if split_lines {
            values = values
                .iter()
                .flat_map(|value| value.lines().map(str::to_owned).collect::<Vec<_>>())
                .collect();
        }
        if let Some(separator) = split_separator {
            values = values
                .iter()
                .flat_map(|value| {
                    if separator.is_empty() {
                        value.chars().map(String::from).collect::<Vec<_>>()
                    } else {
                        value
                            .split(&separator)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    }
                })
                .collect();
        }
        if unique {
            let mut seen = HashSet::new();
            values.retain(|value| seen.insert(value.clone()));
        }
        if sort_ascending || sort_descending {
            values.sort();
            if sort_descending {
                values.reverse();
            }
        }
        if unquote_expansion {
            values = values
                .into_iter()
                .map(|value| unescape_shell_literal(&value))
                .collect();
        }
        if quote_level > 0 {
            for _ in 0..quote_level {
                values = values
                    .into_iter()
                    .map(|value| zsh_quote_value(&value))
                    .collect();
            }
        }
        if let Some(separator) = join {
            values = vec![values.join(&separator)];
        }
        if quoted
            && matches!(
                self.module.dialect,
                ScriptDialect::Fish | ScriptDialect::Zsh
            )
            && values.len() > 1
            && !preserve_array
            && !all_indices
            && name != "@"
            && !explicit_field_split
        {
            values = vec![values.join(" ")];
        }
        if !quoted
            && !self.suppress_word_splitting
            && self.module.dialect == ScriptDialect::Bash
            && values.len() == 1
        {
            let split = split_shell_words(&values[0]);
            if split.len() > 1 {
                values = split;
            }
        }
        values
    }

    fn replace_parameter_pattern(
        &mut self,
        value: &str,
        pattern: &str,
        replacement: &str,
        replace_all: bool,
    ) -> String {
        if !regex_input_is_bounded(value)
            || pattern.len() > MAX_VALUE_BYTES
            || replacement.len() > MAX_VALUE_BYTES
        {
            return value.to_owned();
        }
        let captures_match = pattern.starts_with("(#m)");
        let pattern = pattern.strip_prefix("(#m)").unwrap_or(pattern);
        let pattern = self.expand_pattern_inline(pattern);
        let pattern = pattern.as_str();
        if pattern.starts_with('[') && pattern.ends_with(']') {
            let mut output = String::with_capacity(value.len());
            let mut replaced = false;
            for character in value.chars() {
                if (!replaced || replace_all) && shell_pattern(pattern, &character.to_string()) {
                    if captures_match {
                        self.set_values("MATCH", vec![character.to_string()], false);
                    }
                    output.push_str(&self.expand_inline(replacement));
                    replaced = true;
                } else {
                    output.push(character);
                }
            }
            return output;
        }
        let replacement = self.expand_inline(replacement);
        let (prefix_anchored, suffix_anchored, pattern) =
            if let Some(pattern) = pattern.strip_prefix('#') {
                (true, false, pattern)
            } else if let Some(pattern) = pattern.strip_prefix('%') {
                (false, true, pattern)
            } else {
                (false, false, pattern)
            };
        if let Some(expression) = shell_pattern_regex(pattern) {
            let expression = format!(
                "(?s){}(?:{}){}",
                if prefix_anchored { "^" } else { "" },
                expression,
                if suffix_anchored { "$" } else { "" }
            );
            if let Some(expression) = bounded_regex(&expression, false) {
                if captures_match {
                    if let Some(matched) = expression.find(value) {
                        self.set_values("MATCH", vec![matched.as_str().to_owned()], false);
                    }
                }
                return if replace_all {
                    expression
                        .replace_all(value, regex::NoExpand(replacement.as_str()))
                        .into_owned()
                } else {
                    expression
                        .replace(value, regex::NoExpand(replacement.as_str()))
                        .into_owned()
                };
            }
        }
        let pattern = unescape_shell_literal(pattern);
        if replace_all {
            value.replace(&pattern, &replacement)
        } else {
            value.replacen(&pattern, &replacement, 1)
        }
    }

    fn expand_inline_values(&mut self, value: &str) -> Vec<String> {
        let trimmed = value.trim();
        let wrapped_quote = trimmed.len() >= 2
            && matches!(trimmed.as_bytes()[0], b'\'' | b'"')
            && trimmed.as_bytes()[0] == *trimmed.as_bytes().last().unwrap_or(&0);
        let unquoted = if wrapped_quote {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };
        if let Some(expression) = unquoted
            .strip_prefix("${")
            .and_then(|value| value.strip_suffix('}'))
        {
            return self.expand_parameter(expression, wrapped_quote);
        }
        if let Some(expression) = unquoted.strip_prefix('$') {
            let end = inline_parameter_end(expression.as_bytes(), 0);
            if end > 0 && (end == expression.len() || matches!(&expression[end..], "[@]" | "[*]")) {
                return self.expand_parameter(expression, wrapped_quote);
            }
        }
        vec![self.expand_inline(value)]
    }

    fn expand_pattern_inline(&mut self, value: &str) -> String {
        let bytes = value.as_bytes();
        let mut output = String::new();
        let mut index = 0;
        let mut quote = None;
        while index < bytes.len() {
            let byte = bytes[index];
            if matches!(byte, b'\'' | b'"') {
                if quote == Some(byte) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(byte);
                } else {
                    push_escaped_pattern_character(&mut output, byte as char);
                }
                index += 1;
                continue;
            }
            if byte == b'\\' && index + 1 < bytes.len() {
                let character = value[index + 1..].chars().next().unwrap_or('\\');
                push_escaped_pattern_character(&mut output, character);
                index += 1 + character.len_utf8();
                continue;
            }
            if byte == b'$' && quote != Some(b'\'') {
                if bytes.get(index + 1) == Some(&b'{') {
                    if let Some(close) = matching_ascii(&value[index + 1..], '{', '}') {
                        let end = index + 1 + close;
                        let expanded = self
                            .expand_parameter(&value[index + 2..end], true)
                            .join(" ");
                        if quote.is_some() {
                            for character in expanded.chars() {
                                push_escaped_pattern_character(&mut output, character);
                            }
                        } else {
                            output.push_str(&expanded);
                        }
                        index = end + 1;
                        continue;
                    }
                }
                let start = index
                    + 1
                    + usize::from(
                        self.module.dialect == ScriptDialect::Zsh
                            && bytes.get(index + 1) == Some(&b'~'),
                    );
                let end = inline_parameter_end(bytes, start);
                if end > start {
                    let expanded = self.variable_values(&value[start..end]).join(" ");
                    if quote.is_some() {
                        for character in expanded.chars() {
                            push_escaped_pattern_character(&mut output, character);
                        }
                    } else {
                        output.push_str(&expanded);
                    }
                    index = end;
                    continue;
                }
            }
            let character = value[index..].chars().next().unwrap_or(byte as char);
            if quote.is_some() {
                push_escaped_pattern_character(&mut output, character);
            } else {
                output.push(character);
            }
            index += character.len_utf8();
        }
        output
    }

    fn expand_inline(&mut self, value: &str) -> String {
        let bytes = value.as_bytes();
        let mut output = String::new();
        let mut index = 0;
        let mut quote = None;
        while index < bytes.len() {
            let byte = bytes[index];
            if matches!(byte, b'\'' | b'"') {
                if quote == Some(byte) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(byte);
                } else {
                    output.push(byte as char);
                }
                index += 1;
                continue;
            }
            if byte == b'\\' && index + 1 < bytes.len() {
                output.push(bytes[index + 1] as char);
                index += 2;
                continue;
            }
            if byte == b'$' && quote != Some(b'\'') {
                if bytes.get(index + 1) == Some(&b'{') {
                    if let Some(close) = matching_ascii(&value[index + 1..], '{', '}') {
                        let end = index + 1 + close;
                        let expression = &value[index + 2..end];
                        output.push_str(&self.expand_parameter(expression, true).join(" "));
                        index = end + 1;
                        continue;
                    }
                }
                let start = index + 1;
                let end = inline_parameter_end(bytes, start);
                if end > start {
                    output.push_str(&self.variable_values(&value[start..end]).join(" "));
                    index = end;
                    continue;
                }
            }
            output.push(byte as char);
            index += 1;
        }
        output
    }

    fn zsh_parameter_exists(&mut self, reference: &str) -> bool {
        let (name, subscript) = split_variable_subscript(reference);
        let subscript = subscript.map(|value| self.expand_inline(value));
        match (name, subscript.as_deref()) {
            ("commands", Some(command)) => self
                .context
                .command_available(command)
                .unwrap_or_else(|| self.effective_commands.iter().any(|value| value == command)),
            ("builtins", Some(command)) => SHELL_BUILTINS.contains(&command),
            ("functions", Some(function)) => self.functions.contains_key(function),
            ("parameters", Some(parameter)) => self.variables.contains_key(parameter),
            (_, Some(index)) => self.variables.get(name).is_some_and(|variable| {
                if variable.associative {
                    variable.values.chunks_exact(2).any(|pair| pair[0] == index)
                } else if variable.array {
                    parse_index(index, variable.values.len(), ScriptDialect::Zsh)
                        .is_some_and(|index| index < variable.values.len())
                } else {
                    !variable.values.is_empty()
                }
            }),
            (_, None) => self.variables.contains_key(name),
        }
    }

    fn zsh_parameter_length(&self, reference: &str) -> usize {
        let (name, subscript) = split_variable_subscript(reference);
        let Some(variable) = self.variables.get(name) else {
            return 0;
        };
        if subscript.is_some() {
            return usize::from(!variable.values.is_empty());
        }
        if variable.array {
            variable.values.len()
        } else {
            variable.values.first().map_or(0, String::len)
        }
    }

    fn variable_values(&self, name: &str) -> Vec<String> {
        match name {
            "?" => vec![self.last_status.to_string()],
            // Script IR evaluation is replayable and must not expose the host
            // process identifier. A fixed shell-local identity is sufficient
            // for completion code that only uses `$$` to form temporary names.
            "$" => vec!["1".into()],
            "#" => vec![
                self.variables
                    .get("@")
                    .map_or(0, |variable| variable.values.len())
                    .to_string(),
            ],
            _ => self
                .variables
                .get(name)
                .map_or_else(Vec::new, |variable| variable.values.clone()),
        }
    }

    fn set_values(&mut self, name: &str, values: Vec<String>, exported: bool) {
        if name.len() > MAX_VALUE_BYTES
            || values.len() > MAX_VALUES
            || values.iter().map(String::len).sum::<usize>() > MAX_VALUE_BYTES
        {
            self.limit_error = Some("shell values");
            return;
        }
        let variable = self.variables.entry(name.to_owned()).or_default();
        if !variable.readonly {
            variable.values = values;
            variable.exported |= exported;
        }
    }

    fn save_positional(&self) -> Vec<(String, Variable)> {
        self.variables
            .iter()
            .filter(|(name, _)| {
                matches!(name.as_str(), "@" | "*" | "argv")
                    || (name.as_str() != "0" && name.bytes().all(|byte| byte.is_ascii_digit()))
            })
            .map(|(name, variable)| (name.clone(), variable.clone()))
            .collect()
    }

    fn restore_positional(&mut self, saved: Vec<(String, Variable)>) {
        self.variables.retain(|name, _| {
            !matches!(name.as_str(), "@" | "*" | "argv")
                && (name == "0" || !name.bytes().all(|byte| byte.is_ascii_digit()))
        });
        self.variables.extend(saved);
    }

    fn set_positional(&mut self, arguments: &[String]) {
        self.variables
            .retain(|name, _| name == "0" || !name.bytes().all(|byte| byte.is_ascii_digit()));
        self.set_values("@", arguments.to_vec(), false);
        self.set_values("*", arguments.to_vec(), false);
        self.set_values("argv", arguments.to_vec(), false);
        for (index, value) in arguments.iter().enumerate() {
            self.set_values(&(index + 1).to_string(), vec![value.clone()], false);
        }
    }

    fn resolve_index(&self, expression: &str, name: &str) -> Option<usize> {
        if expression == "-1" {
            return self
                .variables
                .get(name)
                .and_then(|variable| variable.values.len().checked_sub(1));
        }
        let index = expression.parse::<isize>().ok()?;
        if self.module.dialect == ScriptDialect::Bash {
            usize::try_from(index).ok()
        } else {
            usize::try_from(index.saturating_sub(1)).ok()
        }
    }

    fn check_values(&self, values: &[String]) -> Result<(), VmError> {
        if values.len() > MAX_VALUES
            || values.iter().map(String::len).sum::<usize>() > MAX_VALUE_BYTES
        {
            return Err(VmError::Limit("shell values"));
        }
        Ok(())
    }

    fn unset_reference(&mut self, reference: &str) {
        if let Some(open) = reference.find('[') {
            if let Some(expression) = reference
                .strip_suffix(']')
                .and_then(|reference| reference.get(open + 1..))
            {
                let name = &reference[..open];
                if self
                    .variables
                    .get(name)
                    .is_some_and(|variable| variable.associative)
                {
                    let key = self.expand_inline(expression);
                    if let Some(variable) = self.variables.get_mut(name) {
                        variable.values = variable
                            .values
                            .chunks_exact(2)
                            .filter(|pair| pair[0] != key)
                            .flatten()
                            .cloned()
                            .collect();
                    }
                    return;
                }
                if let Some(index) = self.resolve_index(expression, name) {
                    if let Some(variable) = self.variables.get_mut(name) {
                        if index < variable.values.len() {
                            variable.values.remove(index);
                        }
                    }
                    return;
                }
            }
        }
        self.unset_variable(reference);
    }

    fn unset_variable(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if let Some(original) = scope.remove(name) {
                if let Some(variable) = original {
                    self.variables.insert(name.to_owned(), variable);
                } else {
                    self.variables.remove(name);
                }
                return;
            }
        }
        self.variables.remove(name);
    }

    fn mark_local(&mut self, name: &str) {
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        if !scope.contains_key(name) {
            scope.insert(name.to_owned(), self.variables.remove(name));
        }
    }

    fn declaration_builtin(&mut self, name: &str, arguments: &[String]) {
        let readonly = name == "readonly";
        let exported = name == "export" || arguments.iter().any(|argument| argument == "-x");
        let local = !matches!(name, "readonly" | "export")
            && !arguments
                .iter()
                .any(|argument| argument.starts_with('-') && argument[1..].contains('g'));
        let associative = arguments
            .iter()
            .any(|argument| argument.starts_with('-') && argument[1..].contains('A'));
        let array = associative
            || arguments
                .iter()
                .any(|argument| argument.starts_with('-') && argument[1..].contains('a'));
        for argument in arguments {
            if argument.starts_with('-') {
                continue;
            }
            let variable_name = argument
                .split_once('=')
                .map_or(argument.as_str(), |pair| pair.0);
            if local {
                self.mark_local(variable_name);
            }
            if let Some((variable, value)) = argument.split_once('=') {
                self.set_values(variable, vec![value.to_owned()], exported);
                if let Some(variable) = self.variables.get_mut(variable) {
                    variable.array |= array;
                    variable.associative |= associative;
                    variable.readonly |= readonly;
                }
            } else {
                let variable = self.variables.entry(argument.clone()).or_default();
                variable.exported |= exported;
                variable.readonly |= readonly;
                variable.array |= array;
                variable.associative |= associative;
            }
        }
    }

    fn getopts_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let Some(option_spec) = arguments.first() else {
            return Ok(CommandResult::status(2));
        };
        let Some(variable_name) = arguments.get(1) else {
            return Ok(CommandResult::status(2));
        };
        let option_arguments = if arguments.len() > 2 {
            arguments[2..].to_vec()
        } else {
            self.variable_values("@")
        };
        let mut option_index = self
            .variable_values("OPTIND")
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let mut character_index = self
            .variable_values("__bashlume_getopts_character")
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let Some(argument) = option_arguments.get(option_index.saturating_sub(1)) else {
            self.set_values(variable_name, vec!["?".into()], false);
            return Ok(CommandResult::status(1));
        };
        if argument == "--" {
            option_index += 1;
            self.set_values("OPTIND", vec![option_index.to_string()], false);
            self.set_values("__bashlume_getopts_character", vec!["1".into()], false);
            return Ok(CommandResult::status(1));
        }
        if !argument.starts_with('-') || argument == "-" {
            return Ok(CommandResult::status(1));
        }
        let option_bytes = argument.as_bytes();
        if character_index >= option_bytes.len() {
            option_index += 1;
            character_index = 1;
        }
        let Some(argument) = option_arguments.get(option_index.saturating_sub(1)) else {
            return Ok(CommandResult::status(1));
        };
        let option = argument
            .as_bytes()
            .get(character_index)
            .copied()
            .map(char::from)
            .unwrap_or('?');
        character_index += 1;
        let spec = option_spec.trim_start_matches(':');
        if let Some(position) = spec.find(option) {
            self.set_values(variable_name, vec![option.to_string()], false);
            let takes_value = spec.as_bytes().get(position + 1) == Some(&b':');
            if takes_value {
                let tail = argument.get(character_index..).unwrap_or("");
                let value = if tail.is_empty() {
                    option_index += 1;
                    option_arguments
                        .get(option_index.saturating_sub(1))
                        .cloned()
                        .unwrap_or_default()
                } else {
                    tail.to_owned()
                };
                self.set_values("OPTARG", vec![value], false);
                option_index += 1;
                character_index = 1;
            } else {
                self.set_values("OPTARG", vec![String::new()], false);
            }
        } else {
            self.set_values(variable_name, vec!["?".into()], false);
            self.set_values("OPTARG", vec![option.to_string()], false);
        }
        if character_index >= argument.len() {
            option_index += 1;
            character_index = 1;
        }
        self.set_values("OPTIND", vec![option_index.to_string()], false);
        self.set_values(
            "__bashlume_getopts_character",
            vec![character_index.to_string()],
            false,
        );
        Ok(CommandResult::success())
    }

    fn shopt_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut enabled = self.variable_values("__bashlume_shopt");
        let query = arguments.iter().any(|argument| argument == "-q");
        let set = arguments.iter().any(|argument| argument == "-s");
        let unset = arguments.iter().any(|argument| argument == "-u");
        let names = arguments
            .iter()
            .filter(|argument| !argument.starts_with('-'))
            .cloned()
            .collect::<Vec<_>>();
        if set {
            for name in &names {
                if !enabled.contains(name) {
                    enabled.push(name.clone());
                }
            }
        }
        if unset {
            enabled.retain(|name| !names.contains(name));
        }
        self.set_values("__bashlume_shopt", enabled.clone(), false);
        if query {
            return Ok(CommandResult::status(i32::from(
                !names.iter().all(|name| enabled.contains(name)),
            )));
        }
        Ok(CommandResult::success())
    }

    fn set_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if self.module.dialect == ScriptDialect::Bash
            && arguments
                .first()
                .is_some_and(|argument| argument == "--usage")
        {
            return Ok(CommandResult {
                status: 2,
                output: bash_builtin_help("set").into_iter().collect(),
                control: Control::None,
            });
        }
        if self.module.dialect == ScriptDialect::Fish {
            let mut index = 0;
            while index < arguments.len() && arguments[index].starts_with('-') {
                if arguments[index] == "--" {
                    index += 1;
                    break;
                }
                index += 1;
            }
            let options = &arguments[..index];
            let has_option = |short: char, long: &str| {
                options.iter().any(|value| {
                    value == long
                        || value
                            .strip_prefix('-')
                            .filter(|value| !value.starts_with('-'))
                            .is_some_and(|value| value.contains(short))
                })
            };
            let query = has_option('q', "--query");
            let names = has_option('n', "--names");
            let erase = has_option('e', "--erase");
            let append = has_option('a', "--append");
            let exported = has_option('x', "--export");
            let local = has_option('l', "--local");
            if names {
                let mut names = self
                    .variables
                    .iter()
                    .filter(|(name, variable)| {
                        !matches!(name.as_str(), "@" | "*" | "argv")
                            && !name.bytes().all(|byte| byte.is_ascii_digit())
                            && (!exported || variable.exported)
                    })
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>();
                names.sort_unstable();
                names.dedup();
                return Ok(CommandResult::output(names));
            }
            if let Some(name) = arguments.get(index) {
                if local {
                    self.mark_local(name);
                }
                if query {
                    let exists = arguments[index..]
                        .iter()
                        .all(|name| self.variable_reference_exists(name));
                    return Ok(CommandResult::status(i32::from(!exists)));
                }
                if erase {
                    for reference in &arguments[index..] {
                        self.erase_variable_reference(reference);
                    }
                } else if append {
                    let variable = self.variables.entry(name.clone()).or_default();
                    variable.values.extend_from_slice(&arguments[index + 1..]);
                } else {
                    self.set_values(name, arguments[index + 1..].to_vec(), exported);
                }
            } else if !query && !erase && !append {
                let mut values = self
                    .variables
                    .iter()
                    .filter(|(name, _)| {
                        !matches!(name.as_str(), "@" | "*" | "argv")
                            && !name.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .map(|(name, variable)| {
                        if variable.values.is_empty() {
                            name.clone()
                        } else {
                            format!("{} {}", name, variable.values.join(" "))
                        }
                    })
                    .collect::<Vec<_>>();
                values.sort();
                return Ok(CommandResult::output(values));
            }
        } else if self.module.dialect == ScriptDialect::Zsh
            && arguments.first().is_some_and(|argument| argument == "-A")
        {
            if let Some(name) = arguments.get(1) {
                self.set_values(name, arguments[2..].to_vec(), false);
            }
        } else if let Some(position) = arguments.iter().position(|value| value == "--") {
            self.set_positional(&arguments[position + 1..]);
        }
        Ok(CommandResult::success())
    }

    fn variable_reference_exists(&self, reference: &str) -> bool {
        let (name, subscript) = split_variable_subscript(reference);
        self.variables.get(name).is_some_and(|variable| {
            subscript.is_none_or(|subscript| {
                !selected_parameter_indices(subscript, variable.values.len(), ScriptDialect::Fish)
                    .is_empty()
            })
        })
    }

    fn erase_variable_reference(&mut self, reference: &str) {
        let (name, subscript) = split_variable_subscript(reference);
        if let Some(subscript) = subscript {
            if let Some(variable) = self.variables.get_mut(name) {
                let mut indices = selected_parameter_indices(
                    subscript,
                    variable.values.len(),
                    ScriptDialect::Fish,
                );
                indices.sort_unstable();
                indices.dedup();
                for index in indices.into_iter().rev() {
                    if index < variable.values.len() {
                        variable.values.remove(index);
                    }
                }
            }
        } else {
            self.variables.remove(name);
        }
    }

    fn argparse_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let Some(separator) = arguments.iter().position(|argument| argument == "--") else {
            return Ok(CommandResult::status(2));
        };
        let specs = arguments[..separator]
            .iter()
            .filter(|argument| !argument.starts_with('-'))
            .cloned()
            .collect::<Vec<_>>();
        let mut remaining = Vec::new();
        let mut index = separator + 1;
        while index < arguments.len() {
            let argument = &arguments[index];
            if argument == "--" {
                remaining.extend_from_slice(&arguments[index + 1..]);
                break;
            }
            if let Some(option) = argument.strip_prefix("--") {
                let (name, inline) = option
                    .split_once('=')
                    .map_or((option, None), |(name, value)| {
                        (name, Some(value.to_owned()))
                    });
                if let Some(spec) = specs
                    .iter()
                    .find(|spec| spec.split(['/', '-', '=']).any(|part| part == name))
                {
                    let flag = spec
                        .split(['/', '-', '='])
                        .find(|part| part.len() > 1)
                        .unwrap_or(name)
                        .replace('-', "_");
                    let takes_value = spec.contains('=') || spec.contains('+');
                    let value = if takes_value {
                        inline.or_else(|| {
                            index += 1;
                            arguments.get(index).cloned()
                        })
                    } else {
                        Some("1".into())
                    };
                    self.set_values(&format!("_flag_{flag}"), value.into_iter().collect(), false);
                } else {
                    return Ok(CommandResult::status(2));
                }
            } else if argument.starts_with('-') && argument.len() > 1 {
                for short in argument[1..].chars() {
                    if let Some(spec) = specs.iter().find(|spec| spec.starts_with(short)) {
                        let flag = spec
                            .split(['/', '-', '='])
                            .find(|part| part.len() > 1)
                            .unwrap_or_else(|| &spec[..1])
                            .replace('-', "_");
                        self.set_values(&format!("_flag_{flag}"), vec!["1".into()], false);
                    }
                }
            } else {
                remaining.push(argument.clone());
            }
            index += 1;
        }
        self.set_values("argv", remaining, false);
        Ok(CommandResult::success())
    }

    fn shift_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if self.module.dialect == ScriptDialect::Zsh {
            if let Some(name) = arguments.first().filter(|name| {
                name.bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                    && !name.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                let count = arguments
                    .get(1)
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(1);
                let values = self.variable_values(name);
                self.set_values(
                    name,
                    values.get(count..).unwrap_or_default().to_vec(),
                    false,
                );
                return Ok(CommandResult::success());
            }
        }
        let count = arguments
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let values = self.variable_values("@");
        self.set_positional(values.get(count..).unwrap_or_default());
        Ok(CommandResult::success())
    }

    fn define_deferred_eval_function(
        &mut self,
        source: &str,
        statements: &[ScriptStatement],
        captures: &[ScriptWord],
    ) -> Result<CommandResult, VmError> {
        let Some(prefix) = source.strip_prefix("eval-function:") else {
            return Ok(CommandResult::status(2));
        };
        for (index, capture) in captures.iter().enumerate() {
            let mut values = self.expand_word_preserving_fields(capture)?;
            let name = format!("{prefix}{index}");
            if self.module.dialect == ScriptDialect::Zsh
                && statements_use_unquoted_parameter(statements, &name)
            {
                values = values
                    .iter()
                    .flat_map(|value| split_shell_words(value))
                    .collect();
            }
            self.set_values(&name, values.clone(), false);
            if values.len() > 1 {
                if let Some(variable) = self.variables.get_mut(&name) {
                    variable.array = true;
                }
            }
        }
        let Some(ScriptStatement::Function { function }) = statements.first() else {
            return Ok(CommandResult::status(2));
        };
        let mut function = function.clone();
        if let Some(index) = function
            .name
            .strip_prefix(prefix)
            .and_then(|index| index.parse::<usize>().ok())
        {
            function.name = self
                .variable_values(&format!("{prefix}{index}"))
                .first()
                .cloned()
                .unwrap_or_default();
        }
        if function.name.is_empty() {
            return Ok(CommandResult::status(2));
        }
        if !self.functions.contains_key(&function.name) {
            self.function_order.push(function.name.clone());
        }
        self.functions.insert(function.name.clone(), function);
        Ok(CommandResult::success())
    }

    fn eval_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let expression = arguments
            .iter()
            .skip_while(|argument| argument.as_str() == "--")
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(arithmetic) = expression
            .trim()
            .strip_prefix("((")
            .and_then(|value| value.strip_suffix("))"))
        {
            let value = self.eval_arithmetic(arithmetic);
            return Ok(CommandResult::status(i32::from(value == 0)));
        }
        let Some(open) = expression.find('(') else {
            for field in split_shell_words(&expression) {
                let Some((target, value)) = field.split_once('=') else {
                    continue;
                };
                if !target.is_empty()
                    && target
                        .bytes()
                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                {
                    let expanded = self.expand_inline(value);
                    self.set_values(target, vec![expanded], false);
                }
            }
            return Ok(CommandResult::success());
        };
        if !expression.ends_with(')') {
            return Ok(CommandResult::status(2));
        }
        let target = expression[..open]
            .trim()
            .trim_end_matches('=')
            .trim_end_matches('+')
            .to_owned();
        if target.is_empty()
            || !target
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        {
            return Ok(CommandResult::status(2));
        }
        let append = expression[..open].trim_end().ends_with("+=");
        let body = &expression[open + 1..expression.len() - 1];
        let separators = self
            .variable_values("IFS")
            .first()
            .cloned()
            .unwrap_or_else(|| " \t\n".into());
        let mut values = Vec::new();
        for value in split_shell_fields(body, &separators) {
            let value = value.trim_matches(|character| matches!(character, '\'' | '"'));
            if let Some(parameter) = value
                .strip_prefix("${")
                .and_then(|value| value.strip_suffix('}'))
            {
                values.extend(
                    self.expand_parameter(parameter, true)
                        .into_iter()
                        .map(|value| (value, false)),
                );
            } else if let Some(parameter) = value.strip_prefix('$') {
                for value in self.variable_values(parameter) {
                    values.extend(
                        value
                            .split(|character| separators.contains(character))
                            .filter(|field| !field.is_empty())
                            .map(|value| (value.to_owned(), false)),
                    );
                }
            } else if !value.is_empty() {
                values.push((value.to_owned(), true));
            }
        }
        let nullglob = self
            .variable_values("__bashlume_shopt")
            .iter()
            .any(|option| option == "nullglob");
        let mut expanded_values = Vec::new();
        for (value, brace_expansion) in values {
            let values = if brace_expansion {
                expand_braces(&value)
            } else {
                vec![value]
            };
            for value in values {
                if has_shell_glob(ScriptDialect::Bash, &value) {
                    if let Some(matches) =
                        self.filesystem_values(FilesystemRequestKind::Glob, &value, None)
                    {
                        if matches.is_empty() && !nullglob {
                            expanded_values.push(value);
                        } else {
                            expanded_values.extend(matches);
                        }
                    }
                } else {
                    expanded_values.push(value);
                }
            }
        }
        let variable = self.variables.entry(target).or_default();
        variable.array = true;
        if append {
            variable.values.extend(expanded_values);
        } else {
            variable.values = expanded_values;
        }
        Ok(CommandResult::success())
    }

    fn printf_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if arguments.first().map(String::as_str) == Some("-v") && arguments.len() >= 3 {
            let variable = &arguments[1];
            let values = format_values(&arguments[2..]);
            self.set_variable_reference(variable, values.join("\n"));
            return Ok(CommandResult::success());
        }
        Ok(CommandResult::output(format_values(arguments)))
    }

    fn set_variable_reference(&mut self, reference: &str, value: String) {
        if let Some(open) = reference.find('[') {
            if reference.ends_with(']') {
                let name = &reference[..open];
                let expression = &reference[open + 1..reference.len() - 1];
                let index = usize::try_from(self.eval_arithmetic(expression)).unwrap_or(0);
                let variable = self.variables.entry(name.to_owned()).or_default();
                if variable.values.len() <= index {
                    variable.values.resize(index + 1, String::new());
                }
                variable.values[index] = value;
                return;
            }
        }
        self.set_values(reference, vec![value], false);
    }

    fn read_builtin(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let array_mode = arguments.iter().any(|argument| {
            argument
                .strip_prefix('-')
                .is_some_and(|options| options.contains('a'))
        });
        let zero_mode = arguments.iter().any(|argument| {
            argument == "--zero"
                || argument
                    .strip_prefix('-')
                    .filter(|options| !options.starts_with('-'))
                    .is_some_and(|options| options.contains('z'))
        });
        let mut names = Vec::new();
        let mut delimiter = None;
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--" => {
                    names.extend_from_slice(&arguments[index + 1..]);
                    break;
                }
                "-d" | "--delimiter" if index + 1 < arguments.len() => {
                    delimiter = Some(decode_echo_escapes(&arguments[index + 1]));
                    index += 2;
                }
                "-a" if self.module.dialect == ScriptDialect::Bash
                    && index + 1 < arguments.len() =>
                {
                    names.push(arguments[index + 1].clone());
                    index += 2;
                }
                "-n" | "-N" | "-p" | "-P" | "-t" | "-u" | "--nchars" | "--shell" | "--command"
                | "--prompt-str"
                    if index + 1 < arguments.len() =>
                {
                    index += 2;
                }
                argument if argument.starts_with('-') => index += 1,
                _ => {
                    names.push(arguments[index].clone());
                    index += 1;
                }
            }
        }
        if zero_mode && names.is_empty() {
            self.stdin_cursor = input.len();
            return Ok(CommandResult::output(input.to_vec()));
        }
        let joined;
        let value = if zero_mode && self.stdin_cursor < input.len() {
            joined = input[self.stdin_cursor..].join("\n");
            self.stdin_cursor = input.len();
            Some(&joined)
        } else {
            let value = input.get(self.stdin_cursor);
            if value.is_some() {
                self.stdin_cursor = self.stdin_cursor.saturating_add(1);
            }
            value
        };
        let fields = if array_mode && zero_mode && delimiter.as_deref() == Some("\n") {
            input.to_vec()
        } else {
            value.map_or_else(Vec::new, |value| {
                if let Some(delimiter) = &delimiter {
                    return value.split(delimiter).map(str::to_owned).collect();
                }
                let separators = self.variable_values("IFS");
                match separators.first() {
                    Some(separator) if separator.is_empty() => vec![value.clone()],
                    Some(separator) => value
                        .split(|character| separator.contains(character))
                        .filter(|field| !field.is_empty())
                        .map(str::to_owned)
                        .collect(),
                    None => split_shell_words(value),
                }
            })
        };
        if array_mode {
            if let Some(name) = names.first() {
                self.set_values(name, fields, false);
                if let Some(variable) = self.variables.get_mut(name) {
                    variable.array = true;
                }
            }
        } else {
            for (index, name) in names.iter().enumerate() {
                let value = if index + 1 == names.len() {
                    fields.get(index..).unwrap_or_default().join(" ")
                } else {
                    fields.get(index).cloned().unwrap_or_default()
                };
                self.set_values(name, vec![value], false);
            }
        }
        Ok(CommandResult::status(i32::from(value.is_none())))
    }

    fn mapfile_builtin(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let name = arguments
            .iter()
            .rev()
            .find(|argument| !argument.starts_with('-'))
            .map_or("MAPFILE", String::as_str);
        self.set_values(name, input.to_vec(), false);
        Ok(CommandResult::success())
    }

    fn test(&mut self, arguments: &[String]) -> bool {
        let mut arguments = arguments.to_vec();
        if arguments
            .last()
            .is_some_and(|value| matches!(value.as_str(), "]]" | "]"))
        {
            arguments.pop();
        }
        arguments.retain(|value| value != ";");
        let zsh_completion_condition = arguments
            .first()
            .map(String::as_str)
            .filter(|value| matches!(*value, "-prefix" | "-suffix"))
            .map(|value| (false, value))
            .or_else(|| {
                (arguments.first().map(String::as_str) == Some("!"))
                    .then(|| arguments.get(1).map(String::as_str))
                    .flatten()
                    .filter(|value| matches!(*value, "-prefix" | "-suffix"))
                    .map(|value| (true, value))
            });
        if self.module.dialect == ScriptDialect::Zsh {
            if let Some((negated, operator)) = zsh_completion_condition {
                let pattern = arguments.last().map_or("", String::as_str);
                let value = if operator == "-suffix" {
                    self.variable_values("SUFFIX")
                        .first()
                        .cloned()
                        .unwrap_or_default()
                } else {
                    self.variable_values("PREFIX")
                        .first()
                        .cloned()
                        .unwrap_or_default()
                };
                let mut boundaries = value
                    .char_indices()
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                boundaries.push(value.len());
                let matched = if operator == "-suffix" {
                    boundaries.into_iter().any(|index| {
                        shell_pattern_dialect(ScriptDialect::Zsh, pattern, &value[index..])
                    })
                } else {
                    boundaries.into_iter().any(|index| {
                        shell_pattern_dialect(ScriptDialect::Zsh, pattern, &value[..index])
                    })
                };
                return matched != negated;
            }
        }
        if let [operator, path] = arguments.as_slice() {
            if matches!(
                operator.as_str(),
                "-e" | "-f"
                    | "-d"
                    | "-r"
                    | "-w"
                    | "-x"
                    | "-b"
                    | "-c"
                    | "-p"
                    | "-S"
                    | "-L"
                    | "-h"
                    | "-s"
                    | "-u"
                    | "-g"
                    | "-k"
                    | "-O"
                    | "-G"
            ) {
                return self
                    .filesystem_values(FilesystemRequestKind::Test, path, Some(operator))
                    .is_some_and(|values| values.iter().any(|value| value == "true"));
            }
        }
        if let [value, operator, pattern] = arguments.as_slice() {
            if operator == "=~" {
                if !regex_input_is_bounded(value) {
                    return false;
                }
                let pattern = pattern.trim_matches(|character| matches!(character, '\'' | '"'));
                let pattern = normalize_bash_ere(pattern);
                let case_insensitive = self
                    .variable_values("__bashlume_shopt")
                    .iter()
                    .any(|option| option == "nocasematch");
                if let Some(expression) = bounded_regex(&pattern, case_insensitive) {
                    if let Some(captures) = expression.captures(value) {
                        self.set_values(
                            "BASH_REMATCH",
                            captures
                                .iter()
                                .map(|capture| {
                                    capture.map_or_else(String::new, |value| value.as_str().into())
                                })
                                .collect(),
                            true,
                        );
                        if let Some(variable) = self.variables.get_mut("BASH_REMATCH") {
                            variable.array = true;
                        }
                        return true;
                    }
                }
                self.set_values("BASH_REMATCH", Vec::new(), true);
                if let Some(variable) = self.variables.get_mut("BASH_REMATCH") {
                    variable.array = true;
                }
                return false;
            }
        }
        eval_test_expression(&arguments, &self.variables, self.module.dialect)
    }

    fn filesystem_values(
        &mut self,
        kind: FilesystemRequestKind,
        path: &str,
        operator: Option<&str>,
    ) -> Option<Vec<String>> {
        if path.len() > 4096 || path.contains('\0') {
            return Some(Vec::new());
        }
        let request_id = format!(
            "filesystem:{}:{}:{}:{}",
            match self.module.dialect {
                ScriptDialect::Bash => "bash",
                ScriptDialect::Zsh => "zsh",
                ScriptDialect::Fish => "fish",
            },
            match kind {
                FilesystemRequestKind::Test => "test",
                FilesystemRequestKind::Glob => "glob",
                FilesystemRequestKind::Read => "read",
            },
            operator.unwrap_or(""),
            path
        );
        if let Some(values) = self.completion_results.get(&request_id) {
            return Some(values.clone());
        }
        let request = FilesystemRequest {
            request_id,
            kind,
            dialect: self.module.dialect,
            path: path.to_owned(),
            operator: operator.map(str::to_owned),
        };
        if self.filesystem_requests.len() < MAX_FILESYSTEM_REQUESTS
            && !self.filesystem_requests.contains(&request)
        {
            self.filesystem_requests.push(request);
        }
        None
    }

    fn eval_arithmetic(&mut self, expression: &str) -> i64 {
        let expression = self
            .expand_arithmetic_expression(expression)
            .replace("< =", "<=")
            .replace("> =", ">=")
            .replace("= =", "==")
            .replace("! =", "!=")
            .replace("+ +", "++")
            .replace("- -", "--")
            .replace("+ =", "+=")
            .replace("- =", "-=")
            .replace("* =", "*=")
            .replace("/ =", "/=")
            .replace("& &", "&&")
            .replace("| |", "||");
        let mut result = 0;
        for section in split_top_level(&expression, ',') {
            result = Arithmetic::new(section, &mut self.variables).evaluate();
        }
        result
    }

    fn expand_arithmetic_expression(&mut self, expression: &str) -> String {
        let expression = self.resolve_zsh_arithmetic_subscripts(expression);
        let bytes = expression.as_bytes();
        let mut output = String::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'{') {
                if let Some(close) = matching_ascii(&expression[index + 1..], '{', '}') {
                    let end = index + 1 + close;
                    let parameter = &expression[index + 2..end];
                    output.push_str(
                        self.expand_parameter(parameter, true)
                            .first()
                            .map_or("0", String::as_str),
                    );
                    index = end + 1;
                    continue;
                }
            } else if bytes[index] == b'$'
                && self.module.dialect == ScriptDialect::Zsh
                && bytes
                    .get(index + 1)
                    .is_some_and(|byte| matches!(byte, b'+' | b'#'))
                && bytes
                    .get(index + 2)
                    .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
            {
                let operator = bytes[index + 1];
                let name_start = index + 2;
                let mut end = name_start;
                while end < bytes.len()
                    && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric())
                {
                    end += 1;
                }
                if bytes.get(end) == Some(&b'[') {
                    if let Some(close) = matching_ascii(&expression[end..], '[', ']') {
                        end += close + 1;
                    }
                }
                let reference = &expression[name_start..end];
                let value = if operator == b'+' {
                    i64::from(self.zsh_parameter_exists(reference))
                } else {
                    self.zsh_parameter_length(reference) as i64
                };
                output.push_str(&value.to_string());
                index = end;
                continue;
            } else if bytes[index] == b'$' && index + 1 < bytes.len() {
                let start = index + 1;
                let mut end = start;
                if matches!(bytes[start], b'#' | b'?' | b'$' | b'@' | b'*') {
                    end += 1;
                } else {
                    while end < bytes.len()
                        && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric())
                    {
                        end += 1;
                    }
                }
                if end > start {
                    output.push_str(
                        self.variable_values(&expression[start..end])
                            .first()
                            .map_or("0", String::as_str),
                    );
                    index = end;
                    continue;
                }
            }
            output.push(bytes[index] as char);
            index += 1;
        }
        output
    }

    fn resolve_zsh_arithmetic_subscripts(&self, expression: &str) -> String {
        if self.module.dialect != ScriptDialect::Zsh {
            return expression.to_owned();
        }
        let mut output = expression.to_owned();
        let mut search_from = 0_usize;
        while let Some(relative_open) = output[search_from..].find("[(") {
            let open = search_from + relative_open;
            let name_start = output[..open]
                .char_indices()
                .rev()
                .take_while(|(_, character)| *character == '_' || character.is_ascii_alphanumeric())
                .map(|(index, _)| index)
                .last()
                .unwrap_or(open);
            if name_start == open {
                search_from = open + 2;
                continue;
            }
            let Some(relative_flags_end) = output[open + 2..].find(')') else {
                break;
            };
            let flags_end = open + 2 + relative_flags_end;
            let Some(relative_close) = output[flags_end + 1..].find(']') else {
                break;
            };
            let close = flags_end + 1 + relative_close;
            let flags = &output[open + 2..flags_end];
            let pattern = &output[flags_end + 1..close];
            if !flags.starts_with('i') && !flags.starts_with('I') {
                search_from = close + 1;
                continue;
            }
            let variable_name = &output[name_start..open];
            let values = self.variable_values(variable_name);
            let start = flags
                .strip_prefix("ib.")
                .and_then(|value| value.strip_suffix('.'))
                .and_then(|name| self.variable_values(name).first().cloned())
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1)
                .saturating_sub(1);
            let matches = |value: &str| shell_pattern_dialect(ScriptDialect::Zsh, pattern, value);
            let reverse = flags.starts_with('I');
            let position = if reverse {
                values.iter().rposition(|value| matches(value))
            } else {
                values
                    .iter()
                    .enumerate()
                    .skip(start)
                    .find(|(_, value)| matches(value))
                    .map(|(index, _)| index)
            }
            .map_or_else(
                || if reverse { 0 } else { values.len() + 1 },
                |index| index + 1,
            );
            output.replace_range(name_start..=close, &position.to_string());
            search_from = name_start + position.to_string().len();
        }
        output
    }

    fn contains_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut values = arguments;
        let mut print_index = false;
        while let Some(option) = values.first() {
            if option == "-i" || option == "--index" {
                print_index = true;
                values = &values[1..];
            } else if option == "--" {
                values = &values[1..];
                break;
            } else if option.starts_with('-') {
                values = &values[1..];
            } else {
                break;
            }
        }
        let Some((needle, haystack)) = values.split_first() else {
            return Ok(CommandResult::status(1));
        };
        if let Some(index) = haystack.iter().position(|value| value == needle) {
            if print_index {
                Ok(CommandResult::output(vec![(index + 1).to_string()]))
            } else {
                Ok(CommandResult::success())
            }
        } else {
            Ok(CommandResult::status(1))
        }
    }

    fn cat_builtin(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let operands = arguments
            .iter()
            .filter(|argument| !argument.starts_with('-'))
            .collect::<Vec<_>>();
        if operands.is_empty() || operands.iter().any(|operand| operand.as_str() == "-") {
            return Ok(CommandResult::output(input.to_vec()));
        }
        let mut output = Vec::new();
        for path in operands {
            let Some(mut values) = self.filesystem_values(FilesystemRequestKind::Read, path, None)
            else {
                return Ok(CommandResult::status(125));
            };
            output.append(&mut values);
        }
        Ok(CommandResult::output(output))
    }

    fn awk_builtin(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let mut separator = None;
        let mut program = None;
        let mut program_index = None;
        let mut index = 0;
        while index < arguments.len() {
            if arguments[index] == "-F" {
                separator = arguments
                    .get(index + 1)
                    .map(|value| decode_echo_escapes(value));
                index += 2;
            } else if let Some(value) = arguments[index].strip_prefix("-F") {
                separator = Some(decode_echo_escapes(value));
                index += 1;
            } else if arguments[index].starts_with('-') {
                index += 1;
            } else {
                program = Some(arguments[index].as_str());
                program_index = Some(index);
                break;
            }
        }
        let Some(program) = program else {
            return Ok(CommandResult::status(2));
        };
        let mut source = input.to_vec();
        if source.is_empty() {
            for path in arguments
                .get(program_index.unwrap_or(arguments.len()) + 1..)
                .unwrap_or_default()
                .iter()
                .filter(|argument| !argument.starts_with('-') && !argument.contains('='))
            {
                let Some(mut values) =
                    self.filesystem_values(FilesystemRequestKind::Read, path, None)
                else {
                    return Ok(CommandResult::status(125));
                };
                source.append(&mut values);
            }
        }
        if let Some(output) = run_simple_awk(program, separator.as_deref(), &source) {
            return Ok(CommandResult::output(output));
        }
        let body = program
            .trim()
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .unwrap_or(program)
            .trim();
        let mut output = Vec::new();
        for line in &source {
            let fields = if let Some(separator) = &separator {
                line.split(separator).map(str::to_owned).collect::<Vec<_>>()
            } else {
                line.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            if let Some(expression) = body.strip_prefix("printf") {
                let Some((format, operands)) = split_awk_printf(expression.trim()) else {
                    continue;
                };
                let mut values = vec![format];
                for token in split_shell_words(operands.trim_start_matches([',', ' '])).iter() {
                    let token = token.trim_end_matches(',');
                    if let Some(field) = token
                        .strip_prefix('$')
                        .and_then(|value| value.parse::<usize>().ok())
                    {
                        values.push(
                            field
                                .checked_sub(1)
                                .and_then(|index| fields.get(index))
                                .cloned()
                                .unwrap_or_default(),
                        );
                    } else {
                        values.push(token.to_owned());
                    }
                }
                output.extend(format_values(&values));
            } else if let Some(expression) = body.strip_prefix("print") {
                let values = split_shell_words(expression.trim())
                    .into_iter()
                    .map(|token| {
                        token
                            .strip_prefix('$')
                            .and_then(|value| value.parse::<usize>().ok())
                            .and_then(|field| field.checked_sub(1))
                            .and_then(|index| fields.get(index).cloned())
                            .unwrap_or(token)
                    })
                    .collect::<Vec<_>>();
                output.push(values.join(" "));
            } else {
                output.push(line.clone());
            }
        }
        Ok(CommandResult::output(output))
    }

    fn string_builtin(
        &mut self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let Some((operation, rest)) = arguments.split_first() else {
            return Ok(CommandResult::status(2));
        };
        let values = if rest.iter().any(|value| !value.starts_with('-')) {
            rest.iter()
                .filter(|value| !value.starts_with('-'))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            input.to_vec()
        };
        match operation.as_str() {
            "split" | "split0" => {
                let mut fields = None;
                let mut positionals = Vec::new();
                let mut index = 0;
                while index < rest.len() {
                    match rest[index].as_str() {
                        "-f" | "--fields" if index + 1 < rest.len() => {
                            fields = Some(rest[index + 1].clone());
                            index += 2;
                        }
                        "--" => {
                            positionals.extend_from_slice(&rest[index + 1..]);
                            break;
                        }
                        value if value.starts_with('-') => index += 1,
                        _ => {
                            positionals.extend_from_slice(&rest[index..]);
                            break;
                        }
                    }
                }
                let separator = positionals
                    .first()
                    .map_or_else(|| "\0".to_owned(), |value| decode_echo_escapes(value));
                let source_start = if positionals.get(1).is_some_and(|value| value == "--") {
                    2
                } else {
                    1
                };
                let source = if positionals.len() > source_start {
                    &positionals[source_start..]
                } else {
                    input
                };
                let mut output = Vec::new();
                for value in source {
                    let split = value.split(&separator).collect::<Vec<_>>();
                    if let Some(fields) = &fields {
                        for index in fields.split(',').flat_map(|field| {
                            selected_parameter_indices(field, split.len(), ScriptDialect::Fish)
                        }) {
                            if let Some(value) = split.get(index) {
                                output.push((*value).to_owned());
                            }
                        }
                    } else {
                        output.extend(split.into_iter().map(str::to_owned));
                    }
                }
                Ok(CommandResult::output(output))
            }
            "join" | "join0" => {
                let separator = rest
                    .iter()
                    .find(|value| !value.starts_with('-'))
                    .map_or_else(|| "\0".to_owned(), |value| decode_echo_escapes(value));
                let source = if values.len() > 1 {
                    &values[1..]
                } else {
                    input
                };
                Ok(CommandResult::output(vec![source.join(&separator)]))
            }
            "lower" => Ok(CommandResult::output(
                values.iter().map(|value| value.to_lowercase()).collect(),
            )),
            "upper" => Ok(CommandResult::output(
                values.iter().map(|value| value.to_uppercase()).collect(),
            )),
            "length" => Ok(CommandResult::output(
                values.iter().map(|value| value.len().to_string()).collect(),
            )),
            "trim" => Ok(CommandResult::output(
                values.iter().map(|value| value.trim().to_owned()).collect(),
            )),
            "escape" | "collect" => Ok(CommandResult::output(values)),
            "match" => {
                let regex = fish_option_present(rest, 'r', "--regex");
                let invert = fish_option_present(rest, 'v', "--invert");
                let all = fish_option_present(rest, 'a', "--all");
                let groups_only = fish_option_present(rest, 'g', "--groups-only");
                let entire = fish_option_present(rest, 'e', "--entire");
                let quiet = fish_option_present(rest, 'q', "--quiet");
                let pattern_index = rest.iter().position(|value| !value.starts_with('-'));
                let Some(pattern_index) = pattern_index else {
                    return Ok(CommandResult::status(2));
                };
                let pattern = &rest[pattern_index];
                let sources = if rest
                    .get(pattern_index + 1..)
                    .is_some_and(|values| !values.is_empty())
                {
                    &rest[pattern_index + 1..]
                } else {
                    input
                };
                let mut selected = false;
                let mut output = Vec::new();
                if regex {
                    let Some(expression) = bounded_regex(pattern, false) else {
                        return Ok(CommandResult::status(2));
                    };
                    for value in sources {
                        if !regex_input_is_bounded(value) {
                            continue;
                        }
                        let captures = if all {
                            expression.captures_iter(value).collect::<Vec<_>>()
                        } else {
                            expression.captures(value).into_iter().collect::<Vec<_>>()
                        };
                        let matched = !captures.is_empty();
                        if invert {
                            if !matched {
                                selected = true;
                                output.push(value.clone());
                            }
                            continue;
                        }
                        if matched {
                            selected = true;
                        }
                        if quiet {
                            continue;
                        }
                        if entire && matched {
                            output.push(value.clone());
                            continue;
                        }
                        for captures in captures {
                            let start = usize::from(groups_only);
                            output.extend(captures.iter().skip(start).filter_map(|capture| {
                                capture.map(|value| value.as_str().to_owned())
                            }));
                        }
                    }
                } else {
                    for value in sources {
                        let matched = shell_pattern(pattern, value);
                        if matched != invert {
                            selected = true;
                            if !quiet {
                                output.push(value.clone());
                            }
                        }
                    }
                }
                Ok(CommandResult {
                    status: i32::from(!selected),
                    output,
                    control: Control::None,
                })
            }
            "replace" => {
                let literals = rest
                    .iter()
                    .filter(|value| !value.starts_with('-'))
                    .collect::<Vec<_>>();
                if literals.len() < 2 {
                    return Ok(CommandResult::status(2));
                }
                let sources = if literals.len() > 2 {
                    literals[2..]
                        .iter()
                        .map(|value| (*value).clone())
                        .collect::<Vec<_>>()
                } else {
                    input.to_vec()
                };
                let regex = fish_option_present(rest, 'r', "--regex");
                let all = fish_option_present(rest, 'a', "--all");
                let filter = fish_option_present(rest, 'f', "--filter");
                let replacement = decode_echo_escapes(literals[1]);
                let expression = regex
                    .then(|| {
                        bounded_fish_regex(
                            literals[0],
                            fish_option_present(rest, 'i', "--ignore-case"),
                        )
                    })
                    .flatten();
                let mut matched_any = false;
                let mut output = Vec::new();
                for value in sources {
                    let matched = expression.as_ref().map_or_else(
                        || value.contains(literals[0].as_str()),
                        |expression| expression.is_match(&value),
                    );
                    let replaced = if let Some(expression) = &expression {
                        expression.replace(&value, replacement.as_str(), all)
                    } else if all {
                        value.replace(literals[0].as_str(), replacement.as_str())
                    } else {
                        value.replacen(literals[0].as_str(), replacement.as_str(), 1)
                    };
                    matched_any |= matched;
                    if !filter || matched {
                        output.push(replaced);
                    }
                }
                Ok(CommandResult {
                    status: i32::from(!matched_any),
                    output,
                    control: Control::None,
                })
            }
            "sub" => {
                let start = rest
                    .iter()
                    .position(|value| value == "-s" || value == "--start")
                    .and_then(|index| rest.get(index + 1))
                    .and_then(|value| value.parse::<isize>().ok())
                    .unwrap_or(1);
                Ok(CommandResult::output(
                    values
                        .iter()
                        .map(|value| substring(value, start, None))
                        .collect(),
                ))
            }
            _ => Ok(CommandResult::output(values)),
        }
    }

    fn bind_builtin(&self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-K" | "--key-names"))
        {
            return Ok(CommandResult::output(
                FISH_NAMED_KEYS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            ));
        }
        if arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-L" | "--list-modes"))
        {
            return Ok(CommandResult::output(vec![
                "default".into(),
                "insert".into(),
                "visual".into(),
            ]));
        }
        Ok(CommandResult::success())
    }

    fn commandline_builtin(&self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut flags = String::new();
        for argument in arguments {
            if let Some(short) = argument
                .strip_prefix('-')
                .filter(|value| !value.starts_with('-'))
            {
                flags.push_str(short);
            }
        }
        if flags.contains('t')
            || arguments
                .iter()
                .any(|argument| argument == "--current-token")
        {
            return Ok(CommandResult::output(vec![
                self.context.current_word.to_owned(),
            ]));
        }
        let before_current = self.context.word_index.min(self.context.words.len());
        if flags.contains('o') {
            return Ok(CommandResult::output(
                self.context.words[..before_current].to_vec(),
            ));
        }
        if flags.contains('x') {
            let end = if flags.contains('c') {
                before_current
            } else {
                (before_current + 1).min(self.context.words.len())
            };
            return Ok(CommandResult::output(self.context.words[..end].to_vec()));
        }
        Ok(CommandResult::output(vec![self.context.words.join(" ")]))
    }

    fn path_builtin(
        &self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let Some((operation, rest)) = arguments.split_first() else {
            return Ok(CommandResult::status(2));
        };
        let values = if rest.is_empty() { input } else { rest };
        let output = match operation.as_str() {
            "basename" => values
                .iter()
                .map(|value| value.rsplit('/').next().unwrap_or(value).to_owned())
                .collect(),
            "dirname" => values
                .iter()
                .map(|value| {
                    value
                        .rsplit_once('/')
                        .map_or(".", |(head, _)| head)
                        .to_owned()
                })
                .collect(),
            "filter" => values
                .iter()
                .filter(|value| !value.starts_with('-'))
                .filter(|value| !fish_completion_has_glob(value))
                .cloned()
                .collect(),
            "change-extension" => {
                let extension = values.first().map_or("", String::as_str);
                values[1..]
                    .iter()
                    .map(|value| {
                        let stem = value
                            .rsplit_once('.')
                            .map_or(value.as_str(), |(stem, _)| stem);
                        format!("{stem}{extension}")
                    })
                    .collect()
            }
            "sort" => {
                let mut output = if rest.iter().any(|value| !value.starts_with('-')) {
                    rest.iter()
                        .filter(|value| !value.starts_with('-'))
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    input.to_vec()
                };
                output.sort_by(|left, right| fish_file_cmp(left, right));
                if rest
                    .iter()
                    .any(|value| value == "-u" || value == "--unique")
                {
                    output.dedup();
                }
                output
            }
            _ => values.to_vec(),
        };
        Ok(CommandResult::output(output))
    }

    fn complete_command(&mut self, command: &ScriptCommand) -> Result<CommandResult, VmError> {
        let mut arguments = Vec::new();
        let mut index = 1;
        while index < command.words.len() {
            let option = command.words[index]
                .as_plain_literal()
                .unwrap_or("")
                .to_owned();
            arguments.extend(self.expand_word(&command.words[index])?);
            if index + 1 < command.words.len()
                && matches!(option.as_str(), "-n" | "--condition" | "-a" | "--arguments")
            {
                if let [
                    ScriptWordPart::DeferredScript {
                        source,
                        statements,
                        words,
                    },
                ] = command.words[index + 1].parts.as_slice()
                {
                    if matches!(option.as_str(), "-n" | "--condition") {
                        let result = self.exec_statements(statements)?;
                        if result.status != 0 {
                            return Ok(CommandResult::status(1));
                        }
                        arguments.push(":".into());
                    } else {
                        let mut output = Vec::new();
                        for word in words {
                            output.extend(self.expand_command_word(word)?);
                        }
                        if output.is_empty() {
                            arguments.push(String::new());
                        } else {
                            arguments.push(output.join("\0"));
                        }
                    }
                    let _ = source;
                } else {
                    arguments.extend(self.expand_command_word(&command.words[index + 1])?);
                }
                index += 2;
            } else {
                index += 1;
            }
        }
        self.complete_builtin_normalized(&arguments, true)
    }

    fn complete_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        self.complete_builtin_normalized(arguments, false)
    }

    fn capture_bash_registration(&mut self, arguments: &[String]) {
        let mut entry = Some(ScriptEntry::Module);
        let mut remove = false;
        let mut append = AppendPolicy::Space;
        let mut commands = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "-F" if index + 1 < arguments.len() => {
                    entry = Some(ScriptEntry::Function {
                        name: arguments[index + 1].clone(),
                    });
                    index += 2;
                }
                "-C" if index + 1 < arguments.len() => {
                    entry = Some(ScriptEntry::Module);
                    index += 2;
                }
                "-r" => {
                    remove = true;
                    index += 1;
                }
                "-o" if index + 1 < arguments.len() => {
                    if arguments[index + 1] == "nospace" {
                        append = AppendPolicy::NoSpace;
                    }
                    index += 2;
                }
                "-A" | "-G" | "-P" | "-S" | "-W" | "-X" if index + 1 < arguments.len() => {
                    index += 2;
                }
                "--" => {
                    commands.extend_from_slice(&arguments[index + 1..]);
                    break;
                }
                value if value.starts_with('-') => index += 1,
                value => {
                    commands.push(value.to_owned());
                    index += 1;
                }
            }
        }
        if remove && commands.is_empty() {
            self.runtime_bash_registrations.clear();
            return;
        }
        for command in commands {
            self.runtime_bash_registrations
                .retain(|(registered, _, _)| registered != &command);
            if !remove {
                if let Some(entry) = &entry {
                    if self.runtime_bash_registrations.len() < MAX_VALUES {
                        self.runtime_bash_registrations
                            .push((command, entry.clone(), append));
                    }
                }
            }
        }
    }

    fn bash_complete_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut actions = Vec::new();
        let mut wordlist = None;
        let mut prefix = String::new();
        let mut suffix = String::new();
        let mut commands = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "-u" => {
                    actions.push("user");
                    index += 1;
                }
                "-g" => {
                    actions.push("group");
                    index += 1;
                }
                "-d" => {
                    actions.push("directory");
                    index += 1;
                }
                "-f" => {
                    actions.push("file");
                    index += 1;
                }
                "-A" if index + 1 < arguments.len() => {
                    actions.push(arguments[index + 1].as_str());
                    index += 2;
                }
                "-W" if index + 1 < arguments.len() => {
                    wordlist = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "-P" if index + 1 < arguments.len() => {
                    prefix = arguments[index + 1].clone();
                    index += 2;
                }
                "-S" if index + 1 < arguments.len() => {
                    suffix = arguments[index + 1].clone();
                    index += 2;
                }
                "-F" | "-C" | "-X" | "-o" if index + 1 < arguments.len() => index += 2,
                "--" => {
                    commands.extend_from_slice(&arguments[index + 1..]);
                    break;
                }
                value if value.starts_with('-') => index += 1,
                value => {
                    commands.push(value.to_owned());
                    index += 1;
                }
            }
        }
        if !commands.iter().any(|command| {
            self.effective_commands
                .iter()
                .any(|effective| effective == command)
        }) {
            return Ok(CommandResult::success());
        }
        if actions.contains(&"directory") {
            self.path_completion = self.path_completion.merge(PathCompletion::Directories);
        }
        if actions.contains(&"file") {
            self.path_completion = self.path_completion.merge(PathCompletion::Files);
        }
        if actions.contains(&"user") {
            for value in self.context.users.unwrap_or_default().to_vec() {
                self.emit(
                    format!("{prefix}{value}{suffix}"),
                    None,
                    RuleCandidateKind::User,
                    AppendPolicy::Space,
                );
            }
        }
        if actions.contains(&"group") {
            for value in self.context.groups.unwrap_or_default().to_vec() {
                self.emit(
                    format!("{prefix}{value}{suffix}"),
                    None,
                    RuleCandidateKind::Value,
                    AppendPolicy::Space,
                );
            }
        }
        if let Some(wordlist) = wordlist {
            let expanded = self.expand_inline(&wordlist);
            for value in split_shell_words(&expanded) {
                self.emit(
                    format!("{prefix}{value}{suffix}"),
                    None,
                    if value.starts_with('-') {
                        RuleCandidateKind::Option
                    } else {
                        RuleCandidateKind::Value
                    },
                    AppendPolicy::Space,
                );
            }
        }
        Ok(CommandResult::success())
    }

    fn complete_builtin_normalized(
        &mut self,
        arguments: &[String],
        already_normalized: bool,
    ) -> Result<CommandResult, VmError> {
        if self.initializing {
            if self.module.dialect == ScriptDialect::Bash {
                self.capture_bash_registration(arguments);
            }
            return Ok(CommandResult::success());
        }
        if self.module.dialect == ScriptDialect::Bash {
            return self.bash_complete_builtin(arguments);
        }
        if let Some(line) = fish_complete_request_line(arguments, self.context.words) {
            if let Some(values) = self.completion_results.get(&line) {
                let mut output = Vec::with_capacity(values.len());
                for value in values {
                    if let Some(path_completion) = nested_completion_path(value) {
                        self.path_completion = self.path_completion.merge(path_completion);
                    } else {
                        output.push(value.clone());
                    }
                }
                self.check_values(&output)?;
                return Ok(CommandResult::output(output));
            }
            let request = CompletionRequest { line };
            if !self.completion_requests.contains(&request) {
                if self.completion_requests.len() >= MAX_COMPLETION_REQUESTS {
                    return Err(VmError::Limit("nested completion requests"));
                }
                self.completion_requests.push(request);
            }
            return Ok(CommandResult::success());
        }
        let normalized_arguments;
        let arguments = if already_normalized {
            arguments
        } else {
            normalized_arguments = normalize_fish_complete_arguments(arguments);
            normalized_arguments.as_slice()
        };
        let mut commands = Vec::new();
        let mut short = Vec::new();
        let mut long = Vec::new();
        let mut old = Vec::new();
        let mut values = Vec::new();
        let mut has_argument_expression = false;
        let mut description = None;
        let mut conditions = Vec::new();
        let mut no_files = false;
        let mut force_files = false;
        let mut erase = false;
        let mut requires_parameter = false;
        let mut exclusive = false;
        let mut keep_order = false;
        let mut index = 0;
        if arguments
            .first()
            .is_some_and(|argument| !argument.starts_with('-'))
        {
            commands.push(arguments[0].clone());
            index = 1;
        }
        while index < arguments.len() {
            let argument = &arguments[index];
            let next = |index: usize| arguments.get(index + 1).cloned();
            match argument.as_str() {
                "-c" | "--command" | "-p" | "--path" => {
                    if let Some(value) = next(index) {
                        commands.push(value);
                    }
                    index += 2;
                }
                "-s" | "--short-option" => {
                    if let Some(value) =
                        next(index).filter(|value| value.chars().count() == 1 && value != "-")
                    {
                        short.push(value);
                    }
                    index += 2;
                }
                "-l" | "--long-option" => {
                    if let Some(value) = next(index) {
                        long.push(value);
                    }
                    index += 2;
                }
                "-o" | "--old-option" => {
                    if let Some(value) = next(index) {
                        old.push(value);
                    }
                    index += 2;
                }
                "-a" | "--arguments" => {
                    has_argument_expression = true;
                    if let Some(value) = next(index) {
                        if value.contains('\0') {
                            values.extend(value.split('\0').map(str::to_owned));
                        } else if value.contains('\t') {
                            values.extend(value.lines().map(str::to_owned));
                        } else {
                            values.extend(split_fish_completion_words(&value));
                        }
                    }
                    index += 2;
                }
                "-d" | "--description" => {
                    description = next(index)
                        .map(|value| value.split(['\r', '\n']).next().unwrap_or("").to_owned());
                    index += 2;
                }
                "-n" | "--condition" => {
                    if let Some(value) = next(index) {
                        conditions.push(value);
                    }
                    index += 2;
                }
                "-f" | "--no-files" => {
                    no_files = true;
                    index += 1;
                }
                "-F" | "--force-files" => {
                    force_files = true;
                    index += 1;
                }
                "-e" | "--erase" => {
                    erase = true;
                    index += 1;
                }
                "-r" | "--require-parameter" => {
                    requires_parameter = true;
                    index += 1;
                }
                "-x" | "--exclusive" => {
                    requires_parameter = true;
                    exclusive = true;
                    index += 1;
                }
                "-k" | "--keep-order" => {
                    keep_order = true;
                    index += 1;
                }
                _ if argument.starts_with("--command=") || argument.starts_with("--path=") => {
                    commands.push(
                        argument
                            .split_once('=')
                            .map_or("", |(_, value)| value)
                            .to_owned(),
                    );
                    index += 1;
                }
                _ if commands.is_empty() && !argument.starts_with('-') => {
                    commands.push(argument.clone());
                    index += 1;
                }
                _ => index += 1,
            }
        }
        if !commands.iter().any(|command| {
            self.effective_commands
                .iter()
                .any(|effective| registration_matches(ScriptDialect::Fish, command, effective))
        }) {
            return Ok(CommandResult::success());
        }
        if !conditions
            .iter()
            .all(|condition| self.evaluate_fish_condition(condition))
        {
            return Ok(CommandResult::status(1));
        }
        if erase {
            let values = short
                .iter()
                .map(|value| format!("-{value}"))
                .chain(long.iter().map(|value| format!("--{value}")))
                .chain(old.iter().map(|value| format!("-{value}")))
                .collect::<HashSet<_>>();
            if values.is_empty() {
                self.candidates.clear();
                self.emitted_values.clear();
            } else {
                self.candidates
                    .retain(|candidate| !values.contains(&candidate.emitted.candidate.value));
                for value in values {
                    self.emitted_values.remove(&value);
                }
            }
            return Ok(CommandResult::success());
        }
        values = self.expand_deferred_completion_values(values)?;
        self.fish_group = self.fish_group.wrapping_add(1);
        self.fish_item = 0;
        let previous = self
            .context
            .word_index
            .checked_sub(1)
            .and_then(|index| self.context.words.get(index))
            .map(String::as_str)
            .unwrap_or("");
        let has_options = !short.is_empty() || !long.is_empty() || !old.is_empty();
        let previous_is_option = short.iter().any(|option| previous == format!("-{option}"))
            || long.iter().any(|option| previous == format!("--{option}"))
            || old.iter().any(|option| previous == format!("-{option}"));
        let attached_long_prefix = long.iter().find_map(|option| {
            let prefix = format!("--{option}=");
            self.context
                .current_word
                .starts_with(&prefix)
                .then_some(prefix)
        });
        let option_parameter_applies =
            requires_parameter && previous_is_option || attached_long_prefix.is_some();
        let exclusive_applies = !has_options || option_parameter_applies;
        if no_files && exclusive_applies {
            if !self.fish_force_files {
                self.path_completion = PathCompletion::Suppress;
            }
        } else if exclusive && exclusive_applies
            || attached_long_prefix.is_some() && has_argument_expression
        {
            self.path_completion = self.path_completion.merge(PathCompletion::Suppress);
        } else if force_files && exclusive_applies {
            self.fish_force_files = true;
            self.path_completion = self.path_completion.merge(PathCompletion::Files);
        }
        let option_append = AppendPolicy::Space;
        if self.context.current_word.starts_with('-') {
            for value in short {
                let insertion = format!("-{value}");
                let append = if insertion.ends_with('=') {
                    AppendPolicy::NoSpace
                } else {
                    option_append
                };
                self.emit_with_order(
                    insertion,
                    description.clone(),
                    RuleCandidateKind::Option,
                    append,
                    false,
                );
            }
            for value in long {
                let value_prefix = format!("--{value}=");
                if attached_long_prefix.as_deref() != Some(value_prefix.as_str()) {
                    let insertion = format!("--{value}");
                    let append = if insertion.ends_with('=') {
                        AppendPolicy::NoSpace
                    } else {
                        option_append
                    };
                    self.emit_with_order(
                        insertion,
                        description.clone(),
                        RuleCandidateKind::Option,
                        append,
                        false,
                    );
                    if has_argument_expression && !requires_parameter && !value.ends_with('=') {
                        self.emit_with_order(
                            value_prefix,
                            description.clone(),
                            RuleCandidateKind::Option,
                            AppendPolicy::NoSpace,
                            false,
                        );
                    }
                }
            }
            for value in old {
                let insertion = format!("-{value}");
                let append = if insertion.ends_with('=') {
                    AppendPolicy::NoSpace
                } else {
                    option_append
                };
                self.emit_with_order(
                    insertion,
                    description.clone(),
                    RuleCandidateKind::Option,
                    append,
                    false,
                );
            }
        }
        if !has_options || option_parameter_applies {
            for value in values {
                let (value, item_description) = value
                    .split_once('\t')
                    .map_or((value.as_str(), None), |(value, description)| {
                        (value, Some(description.to_owned()))
                    });
                if fish_completion_has_glob(value) {
                    continue;
                }
                let insertion = attached_long_prefix
                    .as_ref()
                    .map_or_else(|| value.to_owned(), |prefix| format!("{prefix}{value}"));
                let kind = if insertion.starts_with('-') {
                    RuleCandidateKind::Option
                } else {
                    RuleCandidateKind::Value
                };
                let append = if insertion.ends_with('=') {
                    AppendPolicy::NoSpace
                } else {
                    AppendPolicy::Space
                };
                self.emit_with_order(
                    insertion,
                    item_description.or_else(|| description.clone()),
                    kind,
                    append,
                    keep_order,
                );
            }
        }
        Ok(CommandResult::success())
    }

    fn expand_deferred_completion_values(
        &mut self,
        mut values: Vec<String>,
    ) -> Result<Vec<String>, VmError> {
        for _ in 0..4 {
            let mut expanded = Vec::new();
            let mut changed = false;
            for value in values {
                let Some(deferred) = self.deferred_completion_words.get(&value).cloned() else {
                    expanded.push(value);
                    continue;
                };
                changed = true;
                for word in &deferred.words {
                    expanded.extend(self.expand_word(word)?);
                    self.check_values(&expanded)?;
                }
            }
            values = expanded;
            if !changed {
                break;
            }
        }
        Ok(values)
    }

    fn evaluate_fish_condition(&mut self, condition: &str) -> bool {
        let words = split_shell_words(condition);
        let Some((name, arguments)) = words.split_first() else {
            return true;
        };
        self.invoke(name, arguments, &[])
            .is_ok_and(|result| result.status == 0)
    }

    fn compgen_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut values = Vec::new();
        let mut prefix = String::new();
        let mut suffix = String::new();
        let mut action = None;
        let mut output_variable = None;
        let mut exclusion = None;
        let mut query = None;
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "-W" if index + 1 < arguments.len() => {
                    let wordlist = &arguments[index + 1];
                    if let Some(name) = wordlist.strip_prefix('$').filter(|name| {
                        !name.is_empty()
                            && name
                                .bytes()
                                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                    }) {
                        let separators = self
                            .variable_values("IFS")
                            .first()
                            .cloned()
                            .unwrap_or_else(|| " \t\n".into());
                        for value in self.variable_values(name) {
                            values.extend(
                                value
                                    .split(|character| separators.contains(character))
                                    .filter(|field| !field.is_empty())
                                    .map(str::to_owned),
                            );
                        }
                    } else {
                        for word in split_shell_words(wordlist) {
                            values.extend(self.expand_inline_values(&word));
                        }
                    }
                    index += 2;
                }
                "-P" if index + 1 < arguments.len() => {
                    prefix = arguments[index + 1].clone();
                    index += 2;
                }
                "-S" if index + 1 < arguments.len() => {
                    suffix = arguments[index + 1].clone();
                    index += 2;
                }
                "-A" if index + 1 < arguments.len() => {
                    action = Some(arguments[index + 1].as_str());
                    index += 2;
                }
                "-V" if index + 1 < arguments.len() => {
                    output_variable = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "-X" if index + 1 < arguments.len() => {
                    exclusion = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "--" if index + 2 == arguments.len() => {
                    query = Some(arguments[index + 1].clone());
                    break;
                }
                "--" => index += 1,
                "-a" | "-b" | "-c" | "-d" | "-e" | "-f" | "-g" | "-j" | "-k" | "-s" | "-u"
                | "-v" => {
                    action = Some(arguments[index].as_str());
                    index += 1;
                }
                _ => index += 1,
            }
        }
        if !values.is_empty() {
            values = values
                .into_iter()
                .flat_map(|value| expand_braces(&value))
                .collect();
        }
        if values.is_empty() {
            match action {
                Some("directory" | "-d") => {
                    self.path_completion = self.path_completion.merge(PathCompletion::Directories)
                }
                Some("file" | "-f") => {
                    self.path_completion = self.path_completion.merge(PathCompletion::Files)
                }
                Some("variable" | "-v") => {
                    self.mark_snapshot_provider("variable");
                    let mut seen = HashSet::new();
                    if let Some(names) = self.context.shell_variables {
                        for name in names {
                            if seen.insert(name.clone()) {
                                values.push(name.clone());
                            }
                        }
                    }
                    let mut locals = self
                        .variables
                        .keys()
                        .filter(|name| bash_compgen_variable_name(name))
                        .cloned()
                        .collect::<Vec<_>>();
                    locals.sort_unstable();
                    for name in locals {
                        if seen.insert(name.clone()) {
                            values.push(name);
                        }
                    }
                }
                Some("export" | "-e") => {
                    self.mark_snapshot_provider("variable");
                    let mut names = self.context.environment.keys().cloned().collect::<Vec<_>>();
                    names.sort_unstable();
                    values.extend(names);
                }
                Some("command" | "-c") => {
                    self.mark_snapshot_provider("command");
                    values.extend(self.command_names());
                }
                Some("function") => {
                    self.mark_snapshot_provider("function");
                    values.extend(
                        self.context
                            .shell_functions
                            .unwrap_or_default()
                            .iter()
                            .cloned(),
                    );
                }
                Some("alias" | "-a") => self.mark_snapshot_provider("command"),
                Some("user" | "-u") => {
                    self.mark_snapshot_provider("user");
                    values.extend(self.context.users.unwrap_or_default().iter().cloned())
                }
                Some("group" | "-g") => {
                    self.mark_snapshot_provider("group");
                    values.extend(self.context.groups.unwrap_or_default().iter().cloned())
                }
                Some("builtin" | "-b") => {
                    values.extend(SHELL_BUILTINS.iter().map(|value| (*value).to_owned()))
                }
                Some("keyword" | "-k") => {
                    values.extend(SHELL_KEYWORDS.iter().map(|value| (*value).to_owned()))
                }
                Some("helptopic") => values.extend(SHELL_HELP_TOPICS.lines().map(str::to_owned)),
                Some("binding") => values.extend(READLINE_BINDING_NAMES.lines().map(str::to_owned)),
                Some("signal") => values.extend(self.signal_values()),
                _ => {}
            }
        }
        let query = query.as_deref().unwrap_or(self.context.current_word);
        values.retain(|value| value.starts_with(query));
        if let Some(exclusion) = exclusion {
            if let Some(pattern) = exclusion.strip_prefix('!') {
                values.retain(|value| shell_pattern(pattern, value));
            } else {
                values.retain(|value| !shell_pattern(&exclusion, value));
            }
        }
        let values = values
            .into_iter()
            .map(|value| format!("{prefix}{value}{suffix}"))
            .collect::<Vec<_>>();
        if let Some(variable) = output_variable {
            let status = i32::from(values.is_empty());
            self.set_values(&variable, values, false);
            if let Some(variable) = self.variables.get_mut(&variable) {
                variable.array = true;
            }
            Ok(CommandResult::status(status))
        } else {
            Ok(CommandResult::output(values))
        }
    }

    fn compopt_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if arguments.windows(2).any(|pair| pair == ["-o", "nospace"]) {
            self.set_values("__bashlume_nospace", vec!["1".into()], false);
        }
        if arguments.windows(2).any(|pair| pair == ["-o", "filenames"]) {
            self.path_completion = self.path_completion.merge(PathCompletion::Files);
        }
        if arguments.windows(2).any(|pair| pair == ["+o", "default"])
            || arguments
                .windows(2)
                .any(|pair| pair == ["+o", "bashdefault"])
        {
            self.path_completion = self.path_completion.merge(PathCompletion::Suppress);
        }
        Ok(CommandResult::success())
    }

    fn arguments_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let initial_emissions = self.emission_attempts;
        let specifications = zsh_argument_specifications(arguments);
        let active_words = self.variable_values("words");
        self.set_values(
            "line",
            active_words.get(1..).unwrap_or_default().to_vec(),
            false,
        );
        let current_index = self
            .variable_values("CURRENT")
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(self.context.word_index + 1)
            .saturating_sub(1);
        if current_index == 0 && active_words.first().is_some_and(String::is_empty) {
            return Ok(CommandResult::status(1));
        }
        let prior_positionals = active_words
            .iter()
            .take(current_index)
            .skip(1)
            .filter(|word| !word.starts_with('-'))
            .count();
        let prior_option_terminator = active_words
            .iter()
            .take(current_index)
            .skip(1)
            .any(|word| word == "--");
        let initial_options = prior_positionals == 0 && !prior_option_terminator;
        let option_prefix = self.context.current_word.starts_with('-');
        let mut defer_option_emission = false;
        if initial_options && option_prefix {
            for specification in &specifications {
                if zsh_option_specification(specification) {
                    if let Some((description, action)) = zsh_option_action(specification) {
                        if self.previous_word_uses_zsh_spec(specification) {
                            return self.execute_zsh_argument_action(&action, &description, false);
                        }
                    }
                }
            }
            let argument_pattern_blocks = self.context.current_word.starts_with("--")
                && arguments
                    .windows(2)
                    .filter(|pair| pair[0] == "-A")
                    .map(|pair| pair[1].as_str())
                    .chain(arguments.iter().filter_map(|argument| {
                        argument
                            .strip_prefix("-A")
                            .filter(|pattern| !pattern.is_empty())
                    }))
                    .any(|pattern| {
                        shell_pattern_dialect(
                            ScriptDialect::Zsh,
                            pattern,
                            self.context.current_word,
                        )
                    });
            if argument_pattern_blocks {
                self.emit_zsh_argument_options(&specifications);
                if self.emission_attempts != initial_emissions {
                    return Ok(CommandResult::success());
                }
            }
            defer_option_emission = true;
        }

        let positional_index = prior_positionals + 1;
        let mut sequential_index = 0_usize;
        let mut fallbacks = Vec::new();
        for specification in &specifications {
            let mut value = specification.as_str();
            loop {
                let before = value.len();
                value = value.strip_prefix('!').unwrap_or(value);
                while value.starts_with(['*', '+']) && matches!(value.get(1..2), Some("-" | "{")) {
                    value = &value[1..];
                }
                if value.starts_with('(') {
                    if let Some(close) = matching_ascii(value, '(', ')') {
                        value = &value[close + 1..];
                    }
                }
                if value.len() == before {
                    break;
                }
            }
            if value.is_empty() || value == "+" {
                continue;
            }
            if zsh_option_specification(value) {
                if let Some((description, action)) = zsh_option_action(value) {
                    if self.previous_word_uses_zsh_spec(value) {
                        return self.execute_zsh_argument_action(&action, &description, false);
                    }
                }
                continue;
            }
            let fields = split_zsh_colons(value);
            let Some(selector) = fields.first().map(String::as_str) else {
                continue;
            };
            let modified_positional = fields.get(1).is_some_and(String::is_empty);
            let (description, action) = if modified_positional {
                (fields.get(2), fields.get(3..).map(|parts| parts.join(":")))
            } else {
                (fields.get(1), fields.get(2..).map(|parts| parts.join(":")))
            };
            let action = action.map(|action| action.to_owned());
            let description = description.cloned().unwrap_or_default();
            if selector.starts_with('*') {
                if let Some(action) = action.filter(|action| !action.is_empty()) {
                    fallbacks.push((
                        description,
                        action,
                        fields.get(1).is_some_and(String::is_empty),
                    ));
                    continue;
                }
                if defer_option_emission {
                    self.emit_zsh_argument_options(&specifications);
                }
                return Ok(CommandResult::status(i32::from(
                    self.emission_attempts == initial_emissions,
                )));
            }
            let selected = if selector.is_empty() {
                sequential_index += 1;
                sequential_index == positional_index
            } else {
                selector
                    .trim_start_matches('+')
                    .parse::<usize>()
                    .is_ok_and(|position| position == positional_index)
            };
            if selected {
                if let Some(action) = action.filter(|action| !action.is_empty()) {
                    if modified_positional {
                        fallbacks.push((description, action, false));
                        continue;
                    }
                    let mut result = self.execute_zsh_argument_action(
                        &action,
                        &description,
                        positional_index == 1,
                    )?;
                    if defer_option_emission {
                        self.emit_zsh_argument_options(&specifications);
                    }
                    if self.emission_attempts > initial_emissions {
                        result.status = 0;
                    }
                    return Ok(result);
                }
                if !modified_positional {
                    if defer_option_emission {
                        self.emit_zsh_argument_options(&specifications);
                    }
                    return Ok(CommandResult::status(i32::from(
                        self.emission_attempts == initial_emissions,
                    )));
                }
            }
        }
        if !fallbacks.is_empty() {
            let mut result = CommandResult::status(1);
            let mut shifted = false;
            for (description, action, shift_words) in fallbacks {
                if shift_words && !shifted {
                    let shifted_words = active_words.get(1..).unwrap_or_default().to_vec();
                    self.set_values("words", shifted_words.clone(), false);
                    self.set_values("line", shifted_words, false);
                    self.set_values("CURRENT", vec![current_index.to_string()], false);
                    shifted = true;
                }
                result =
                    self.execute_zsh_argument_action(&action, &description, positional_index == 1)?;
            }
            if defer_option_emission {
                self.emit_zsh_argument_options(&specifications);
            }
            if self.emission_attempts > initial_emissions {
                result.status = 0;
            }
            return Ok(result);
        }
        if initial_options {
            self.emit_zsh_argument_options(&specifications);
            return Ok(CommandResult::status(i32::from(
                self.emission_attempts == initial_emissions,
            )));
        }
        Ok(CommandResult::status(1))
    }

    fn previous_word_uses_zsh_spec(&self, specification: &str) -> bool {
        let words = self.variable_values("words");
        let current = self
            .variable_values("CURRENT")
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(self.context.word_index + 1);
        let previous = current
            .checked_sub(2)
            .and_then(|index| words.get(index))
            .map_or("", String::as_str);
        if previous.is_empty() {
            return false;
        }
        zsh_spec_options(specification).iter().any(|option| {
            let option = option.trim_end_matches(['+', '-']);
            !option.is_empty()
                && (previous == option
                    || option.ends_with('=') && previous.starts_with(option)
                    || specification.contains(':')
                        && !option.ends_with('=')
                        && previous.starts_with(option)
                        && previous.len() > option.len())
        })
    }

    fn execute_zsh_argument_action(
        &mut self,
        action: &str,
        description: &str,
        subcommand: bool,
    ) -> Result<CommandResult, VmError> {
        let mut result = self.execute_zsh_action(action, description, subcommand)?;
        if self.candidates.is_empty()
            && split_shell_words(action)
                .first()
                .is_some_and(|name| matches!(name.as_str(), "_files" | "_directories"))
        {
            result.status = 1;
        }
        Ok(result)
    }

    fn execute_zsh_action(
        &mut self,
        action: &str,
        description: &str,
        subcommand: bool,
    ) -> Result<CommandResult, VmError> {
        let action = action.trim();
        if let Some(state) = action.strip_prefix("->") {
            let state = state.trim();
            self.set_values("state", vec![state.to_owned()], false);
            self.set_values("state_descr", vec![description.to_owned()], false);
            self.set_values("context", vec![description.to_owned()], false);
            return Ok(CommandResult::status(1));
        }
        if let Some(deferred) = self
            .deferred_completion_words
            .iter()
            .filter(|(source, deferred)| {
                !deferred.statements.is_empty() && deferred_source_matches(source, action)
            })
            .min_by(|(left, _), (right, _)| {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            })
            .map(|(_, deferred)| deferred.clone())
        {
            return self.exec_statements(&deferred.statements);
        }
        if action.starts_with('(') && action.ends_with(')') {
            let mut body = &action[1..action.len() - 1];
            if body.starts_with('(') && body.ends_with(')') {
                body = &body[1..body.len() - 1];
            }
            let deferred_words = self
                .deferred_completion_words
                .iter()
                .filter(|(source, deferred)| {
                    !deferred.words.is_empty() && deferred_source_matches(source, action)
                })
                .min_by(|(left, _), (right, _)| {
                    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                })
                .map(|(_, deferred)| deferred.words.clone());
            let mut values = Vec::new();
            if let Some(words) = deferred_words {
                for word in &words {
                    for expanded in self.expand_command_word(word)? {
                        let (value, description) = zsh_described_value(&expanded);
                        values.extend(
                            expand_braces(&value)
                                .into_iter()
                                .map(|value| (value, description.clone())),
                        );
                    }
                }
            } else {
                for word in split_shell_words(body) {
                    for expanded in self.expand_inline_values(&word) {
                        let (value, description) = zsh_described_value(&expanded);
                        values.extend(
                            expand_braces(&value)
                                .into_iter()
                                .map(|value| (value, description.clone())),
                        );
                    }
                }
            }
            values.retain(|(value, _)| self.zsh_candidate_matches(value));
            values
                .sort_by_key(|(_, description)| description.as_ref().is_none_or(String::is_empty));
            let emitted = !values.is_empty();
            for (value, item_description) in values {
                self.emit(
                    value,
                    item_description,
                    if subcommand {
                        RuleCandidateKind::Subcommand
                    } else {
                        RuleCandidateKind::Value
                    },
                    AppendPolicy::Space,
                );
            }
            return Ok(CommandResult::status(i32::from(!emitted)));
        }
        let action_words = split_shell_words(action);
        let Some((name, rest)) = action_words.split_first() else {
            return Ok(CommandResult::status(1));
        };
        let rest = rest
            .iter()
            .flat_map(|argument| self.expand_inline_values(argument))
            .flat_map(|argument| expand_braces(&argument))
            .collect::<Vec<_>>();
        match name.as_str() {
            "_files" => {
                self.path_completion = self.path_completion.merge(PathCompletion::Files);
                Ok(CommandResult::status(1))
            }
            "_directories" => {
                self.path_completion = self.path_completion.merge(PathCompletion::Directories);
                Ok(CommandResult::status(1))
            }
            "_message" => Ok(CommandResult::success()),
            _ => self.invoke(name, &rest, &[]),
        }
    }

    fn signal_values(&mut self) -> Vec<String> {
        self.mark_snapshot_provider("signal");
        self.context.signals.map_or_else(
            || {
                LINUX_SIGNAL_NAMES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect()
            },
            <[String]>::to_vec,
        )
    }

    fn command_names(&self) -> Vec<String> {
        if let Some(commands) = self.context.shell_commands {
            return commands.to_vec();
        }
        let mut commands = self
            .context
            .available_commands
            .map(|commands| commands.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        commands.sort_unstable();
        commands
    }

    fn process_names(&self) -> Vec<String> {
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        for name in self.context.process_names.unwrap_or_default() {
            if !name.is_empty() && seen.insert(name.clone()) {
                values.push(name.clone());
            }
        }
        values
    }

    fn fish_process_values(&self) -> Vec<String> {
        let names = self.context.process_names.unwrap_or_default();
        self.context
            .process_ids
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(index, pid)| {
                names
                    .get(index)
                    .filter(|name| !name.is_empty())
                    .map_or_else(|| pid.clone(), |name| format!("{pid}\t{name}"))
            })
            .collect()
    }

    fn zsh_network_interfaces_builtin(&mut self) -> CommandResult {
        self.mark_snapshot_provider("network");
        let initial_emissions = self.emission_attempts;
        for interface in self.context.network_interfaces.unwrap_or_default() {
            if self.zsh_candidate_matches(interface) {
                self.emit(
                    interface.clone(),
                    None,
                    RuleCandidateKind::Value,
                    AppendPolicy::Space,
                );
            }
        }
        CommandResult::status(i32::from(self.emission_attempts == initial_emissions))
    }

    fn zsh_shell_snapshot_builtin(&mut self, name: &str, _arguments: &[String]) -> CommandResult {
        let provider = match name {
            "_parameters" => "variable",
            "_functions" => "function",
            "_command_names" | "_commands" | "_exec_commands" | "_path_commands" => "command",
            "_processes" | "_pids" => "process",
            "_jobs" => "job",
            "_ttys" | "_file_systems" | "_mounts" => "filesystem",
            _ => "shell",
        };
        self.mark_snapshot_provider(provider);
        let initial_emissions = self.emission_attempts;
        let (values, kind) = match name {
            "_parameters" => (
                self.context.shell_variables.unwrap_or_default().to_vec(),
                RuleCandidateKind::Variable,
            ),
            "_functions" => (
                self.context.shell_functions.unwrap_or_default().to_vec(),
                RuleCandidateKind::Subcommand,
            ),
            "_command_names" | "_commands" | "_exec_commands" | "_path_commands" => {
                (self.command_names(), RuleCandidateKind::Command)
            }
            "_processes" => (self.process_names(), RuleCandidateKind::Value),
            "_pids" => (
                self.context.process_ids.unwrap_or_default().to_vec(),
                RuleCandidateKind::Value,
            ),
            "_jobs" | "_ttys" | "_file_systems" | "_mounts" => {
                (Vec::new(), RuleCandidateKind::Value)
            }
            _ => (Vec::new(), RuleCandidateKind::Value),
        };
        for value in values {
            if self.zsh_candidate_matches(&value) {
                self.emit(value, None, kind, AppendPolicy::Space);
            }
        }
        CommandResult::status(i32::from(self.emission_attempts == initial_emissions))
    }

    fn urls_builtin(&mut self) -> CommandResult {
        let mut emitted = 0usize;
        for value in ["file:", "ftp://", "gopher://", "http://", "https://"] {
            if !self.zsh_candidate_matches(value) {
                continue;
            }
            emitted = emitted.saturating_add(1);
            self.emit(
                value.into(),
                None,
                RuleCandidateKind::Subcommand,
                AppendPolicy::NoSpace,
            );
        }
        CommandResult::status(i32::from(emitted == 0))
    }

    fn file_modes_builtin(&mut self) -> CommandResult {
        let current_prefix = self.context.current_word.to_owned();
        let segment = current_prefix
            .rsplit_once(',')
            .map_or(current_prefix.as_str(), |(_, segment)| segment);
        let operator = segment.find(['+', '-', '=']);
        let choices: &[(&str, Option<&str>)] = if operator.is_some() {
            &[
                ("r", Some("read")),
                ("w", Some("write")),
                ("x", Some("execute")),
                ("X", Some("execute only if directory or already executable")),
                ("s", Some("set user or group ID")),
                ("t", Some("sticky")),
                ("u", Some("owner permissions")),
                ("g", Some("group permissions")),
                ("o", Some("other permissions")),
            ]
        } else {
            &[
                ("a", Some("all")),
                ("u", Some("owner")),
                ("g", Some("group")),
                ("o", Some("others")),
                ("+", None),
                ("-", None),
                ("=", None),
            ]
        };
        let base = operator.map_or(segment, |index| &segment[..=index]);
        let existing = operator.map_or(segment, |index| &segment[index + 1..]);
        let mut emitted = 0usize;
        for (choice, description) in choices {
            if existing.contains(choice) {
                continue;
            }
            let value = format!("{base}{choice}");
            if !segment.is_empty() && !value.starts_with(segment) {
                continue;
            }
            let kind = if value == "-" {
                RuleCandidateKind::Option
            } else {
                RuleCandidateKind::Subcommand
            };
            emitted = emitted.saturating_add(1);
            self.emit(
                value,
                description.map(|description| description.to_owned()),
                kind,
                AppendPolicy::NoSpace,
            );
        }
        CommandResult::status(i32::from(emitted == 0))
    }

    fn zsh_snapshot_provider_builtin(&mut self, name: &str, arguments: &[String]) -> CommandResult {
        match name {
            "_users" => self.mark_snapshot_provider("user"),
            "_groups" => self.mark_snapshot_provider("group"),
            "_hosts" => self.mark_snapshot_provider("host"),
            "_user_at_host" | "_combination" => {
                self.mark_snapshot_provider("user");
                self.mark_snapshot_provider("host");
            }
            _ => self.mark_snapshot_provider("shell"),
        }
        let initial_emissions = self.emission_attempts;
        let mut prefix = String::new();
        let mut suffix = String::new();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "-P" if index + 1 < arguments.len() => {
                    prefix = arguments[index + 1].clone();
                    index += 2;
                }
                "-S" if index + 1 < arguments.len() => {
                    suffix = arguments[index + 1].clone();
                    index += 2;
                }
                argument if argument.starts_with("-P") && argument.len() > 2 => {
                    prefix = argument[2..].to_owned();
                    index += 1;
                }
                argument if argument.starts_with("-S") && argument.len() > 2 => {
                    suffix = argument[2..].to_owned();
                    index += 1;
                }
                argument if argument.starts_with('-') => {
                    let flags = argument.trim_start_matches('-');
                    let value_flag = flags
                        .char_indices()
                        .find(|(_, flag)| *flag == 'P' || *flag == 'S');
                    if let Some((position, flag)) = value_flag {
                        let attached = &flags[position + flag.len_utf8()..];
                        let value = if attached.is_empty() && index + 1 < arguments.len() {
                            index += 1;
                            arguments[index].clone()
                        } else {
                            attached.to_owned()
                        };
                        if flag == 'P' {
                            prefix = value;
                        } else {
                            suffix = value;
                        }
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
        let mut kind = RuleCandidateKind::Value;
        let mut values = Vec::new();
        if name == "_users" {
            values.extend(self.context.users.unwrap_or_default().iter().cloned());
            kind = RuleCandidateKind::User;
        } else if name == "_groups" {
            values.extend(self.context.groups.unwrap_or_default().iter().cloned());
        } else if name == "_user_at_host" {
            let completion_prefix = self.variable_values("PREFIX").join("");
            if let Some((user, _)) = completion_prefix.split_once('@') {
                prefix = format!("{user}@{prefix}");
                values.extend(self.context.hosts.unwrap_or_default().iter().cloned());
                kind = RuleCandidateKind::Host;
            } else {
                values.extend(self.context.users.unwrap_or_default().iter().cloned());
                if suffix.is_empty() {
                    suffix.push('@');
                }
                kind = RuleCandidateKind::User;
            }
        } else if name != "_combination" {
            values.extend(self.context.hosts.unwrap_or_default().iter().cloned());
            kind = RuleCandidateKind::Host;
        }
        if name == "_hosts" {
            // `_hosts` consumes its presentation prefix internally; native
            // completion reports the host (plus suffix), not compadd's `-P`.
            prefix.clear();
        }
        if self.context.word_index == 1 {
            kind = RuleCandidateKind::Subcommand;
        }
        let append = AppendPolicy::Space;
        for value in values {
            let value = format!("{prefix}{value}{suffix}");
            if self.zsh_candidate_matches(&value) {
                self.emit(value, None, kind, append);
            }
        }
        CommandResult::status(i32::from(self.emission_attempts == initial_emissions))
    }

    fn completion_iterator_builtin(&mut self, name: &str, arguments: &[String]) -> CommandResult {
        if name == "_tags" {
            if !arguments.is_empty() {
                let mut tags = Vec::new();
                let mut seen = HashSet::new();
                let mut tag_bytes = 0_usize;
                let mut index = 0_usize;
                while index < arguments.len() {
                    match arguments[index].as_str() {
                        "--" if index == 0 => index += 1,
                        "--" => {
                            index += 1;
                            while index < arguments.len() {
                                if !push_zsh_tag(
                                    &mut tags,
                                    &mut seen,
                                    &mut tag_bytes,
                                    &arguments[index],
                                ) {
                                    self.limit_error = Some("Zsh completion tag state");
                                    return CommandResult::status(1);
                                }
                                index += 1;
                            }
                        }
                        "-C" if index + 1 < arguments.len() => index += 2,
                        option if option.starts_with("-C") => index += 1,
                        option if option.starts_with('-') => index += 1,
                        _ => {
                            if !push_zsh_tag(
                                &mut tags,
                                &mut seen,
                                &mut tag_bytes,
                                &arguments[index],
                            ) {
                                self.limit_error = Some("Zsh completion tag state");
                                return CommandResult::status(1);
                            }
                            index += 1;
                        }
                    }
                }
                self.active_tags = tags;
                self.tags_iterated = false;
                self.tag_context_initialized = true;
                self.tag_label_iterations.clear();
                return CommandResult::status(i32::from(self.active_tags.is_empty()));
            }
            if self.active_tags.is_empty() || self.tags_iterated {
                self.active_tags.clear();
                self.tags_iterated = false;
                self.tag_label_iterations.clear();
                return CommandResult::status(1);
            }
            self.tags_iterated = true;
            self.tag_label_iterations.clear();
            return CommandResult::success();
        }

        let (index, presentation) = zsh_completion_group_options(arguments);
        let Some(tag) = arguments.get(index) else {
            return CommandResult::status(1);
        };
        if !self.completion_tag_requested(tag) {
            return CommandResult::status(1);
        }
        let key = format!("{}:{tag}", self.call_depth);
        let tag_state_bytes = self
            .active_tags
            .iter()
            .chain(self.tag_label_iterations.iter())
            .map(String::len)
            .fold(0_usize, usize::saturating_add);
        if !self.tag_label_iterations.contains(&key)
            && (self
                .active_tags
                .len()
                .saturating_add(self.tag_label_iterations.len())
                >= MAX_ZSH_TAG_STATE_ITEMS
                || tag_state_bytes.saturating_add(key.len()) > MAX_ZSH_TAG_STATE_BYTES)
        {
            self.limit_error = Some("Zsh completion tag state");
            return CommandResult::status(1);
        }
        if !self.tag_label_iterations.insert(key.clone()) {
            self.tag_label_iterations.remove(&key);
            return CommandResult::status(1);
        }
        if let Some(variable) = arguments.get(index + 1) {
            let description = arguments.get(index + 2).map_or("", String::as_str);
            let trailing = arguments.get(index + 3..).unwrap_or_default();
            let values = zsh_label_presentation(&presentation, description, trailing, true);
            self.set_values(variable, values, true);
        }
        CommandResult::success()
    }

    fn completion_tag_requested(&self, tag: &str) -> bool {
        !self.tag_context_initialized || self.active_tags.iter().any(|active| active == tag)
    }

    fn completion_api_action_builtin(
        &mut self,
        name: &str,
        arguments: &[String],
    ) -> Result<CommandResult, VmError> {
        let (index, presentation) = zsh_completion_group_options(arguments);
        let Some(tag) = arguments.get(index) else {
            return Ok(CommandResult::status(1));
        };
        if matches!(name, "_wanted" | "_requested" | "_all_labels")
            && !self.completion_tag_requested(tag)
        {
            return Ok(CommandResult::status(1));
        }
        if name == "_wanted" && tag.len() > MAX_ZSH_TAG_STATE_BYTES {
            self.limit_error = Some("Zsh completion tag state");
            return Ok(CommandResult::status(1));
        }
        let saved_tags = (name == "_wanted").then(|| {
            (
                self.active_tags.clone(),
                self.tags_iterated,
                self.tag_context_initialized,
                self.tag_label_iterations.clone(),
            )
        });
        if name == "_wanted" {
            self.active_tags = vec![tag.clone()];
            self.tags_iterated = true;
            self.tag_context_initialized = true;
            self.tag_label_iterations.clear();
        }

        let result = if let Some(variable) = arguments.get(index + 1) {
            let description = arguments.get(index + 2).map_or("", String::as_str);
            let action_index = index.saturating_add(3);
            if let Some(action) = arguments.get(action_index) {
                let action_arguments = zsh_label_presentation(
                    &presentation,
                    description,
                    &arguments[action_index + 1..],
                    false,
                );
                self.invoke(action, &action_arguments, &[])
            } else {
                self.set_values(
                    variable,
                    zsh_label_presentation(&presentation, description, &[], false),
                    true,
                );
                Ok(CommandResult::success())
            }
        } else {
            Ok(CommandResult::success())
        };
        if let Some((active_tags, tags_iterated, initialized, label_iterations)) = saved_tags {
            self.active_tags = active_tags;
            self.tags_iterated = tags_iterated;
            self.tag_context_initialized = initialized;
            self.tag_label_iterations = label_iterations;
        }
        result
    }

    fn call_function_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let Some(function_index) = arguments
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, value)| !value.starts_with('-'))
            .map(|(index, _)| index)
        else {
            return Ok(CommandResult::status(1));
        };
        let status_variable = arguments.first().cloned().unwrap_or_default();
        let requested = &arguments[function_index];
        let mut function = requested.clone();
        if !self.functions.contains_key(&function) {
            if let Some((prefix, _)) = requested.rsplit_once('-') {
                if let Some(service) = self
                    .variable_values("words")
                    .first()
                    .filter(|service| !service.is_empty())
                {
                    let candidate = format!("{prefix}-{service}");
                    if self.functions.contains_key(&candidate) {
                        function = candidate;
                    }
                }
            }
        }
        let result = self.call_function(&function, &arguments[function_index + 1..])?;
        if !status_variable.is_empty() {
            self.set_values(&status_variable, vec![result.status.to_string()], false);
        }
        Ok(result)
    }

    fn call_program_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let expanded = arguments
            .iter()
            .flat_map(|argument| split_shell_words(argument))
            .collect::<Vec<_>>();
        let mut tag_seen = false;
        let Some(command_index) = expanded.iter().position(|value| {
            if !tag_seen {
                if value.starts_with('-') {
                    return false;
                }
                tag_seen = true;
                return false;
            }
            !value.starts_with('-') && !matches!(value.as_str(), "command" | "noglob")
        }) else {
            return Ok(CommandResult::status(1));
        };
        self.external(&expanded[command_index], &expanded[command_index + 1..])
    }

    fn alternative_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let initial_emissions = self.emission_attempts;
        for alternative in arguments {
            if alternative.starts_with('-') {
                continue;
            }
            let fields = split_zsh_colons(alternative);
            let action = fields
                .get(2..)
                .map_or_else(|| alternative.clone(), |parts| parts.join(":"));
            let description = fields.get(1).map_or("", String::as_str);
            self.execute_zsh_action(&action, description, self.context.word_index == 1)?;
        }
        Ok(CommandResult::status(i32::from(
            self.emission_attempts == initial_emissions,
        )))
    }

    fn description_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if let Some(variable) = arguments
            .iter()
            .find(|argument| self.variables.contains_key(argument.as_str()))
        {
            self.set_values(variable, Vec::new(), true);
        }
        Ok(CommandResult::success())
    }

    fn describe_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let kind = if arguments.iter().any(|argument| argument == "-o") {
            RuleCandidateKind::Option
        } else {
            RuleCandidateKind::Subcommand
        };
        let mut values = Vec::new();
        for group in arguments.split(|argument| argument == "--") {
            let mut arrays = Vec::new();
            let mut inline_items = Vec::new();
            let mut suffix = None;
            let mut exclusions = Vec::new();
            let mut explicit_suffix = false;
            let mut index = 0;
            while index < group.len() {
                let argument = &group[index];
                if let Some(value) = argument.strip_prefix("-S=") {
                    suffix = Some(format!("={value}"));
                    explicit_suffix = true;
                    index += 1;
                } else if argument == "-S" {
                    suffix = Some(group.get(index + 1).cloned().unwrap_or_default());
                    explicit_suffix = true;
                    index += 2;
                } else if argument == "-F" && index + 1 < group.len() {
                    exclusions.extend(self.variable_values(&group[index + 1]));
                    index += 2;
                } else if argument.starts_with('-') {
                    index += if zsh_describe_option_takes_value(argument) {
                        2
                    } else {
                        1
                    };
                } else {
                    if self.variables.contains_key(argument) {
                        arrays.push(argument.clone());
                    } else if argument.starts_with('(') && argument.ends_with(')') {
                        let body = &argument[1..argument.len() - 1];
                        inline_items.extend(split_zsh_scalar_words(body));
                    }
                    index += 1;
                }
            }
            let append = if explicit_suffix
                && suffix
                    .as_ref()
                    .is_none_or(|suffix| suffix.is_empty() || suffix.chars().any(char::is_control))
            {
                AppendPolicy::NoSpace
            } else {
                AppendPolicy::Space
            };
            for item in inline_items {
                let (mut value, description) =
                    if let Some((value, description)) = item.split_once(':') {
                        (value.to_owned(), Some(unescape_shell_literal(description)))
                    } else {
                        (item, None)
                    };
                if value.is_empty()
                    || exclusions.iter().any(|exclusion| {
                        shell_pattern_dialect(ScriptDialect::Zsh, exclusion, &value)
                    })
                {
                    continue;
                }
                if let Some(suffix) = &suffix {
                    if !suffix.chars().any(char::is_control) {
                        value.push_str(suffix);
                    }
                }
                values.push((value, description, append));
            }
            for array in arrays {
                for item in self.variable_values(&array) {
                    let (mut value, description) = zsh_described_value(&item);
                    if value.is_empty()
                        || exclusions.iter().any(|exclusion| {
                            shell_pattern_dialect(ScriptDialect::Zsh, exclusion, &value)
                        })
                    {
                        continue;
                    }
                    if let Some(suffix) = &suffix {
                        if !suffix.chars().any(char::is_control) {
                            value.push_str(suffix);
                        }
                    }
                    values.push((value, description, append));
                }
            }
        }
        values.retain(|(value, _, _)| self.zsh_candidate_matches(value));
        values.sort_by_key(|(_, description, _)| description.as_ref().is_none_or(String::is_empty));
        let emitted = !values.is_empty();
        for (value, description, append) in values {
            self.emit(
                value.clone(),
                description,
                if value.starts_with('-') {
                    RuleCandidateKind::Option
                } else {
                    kind
                },
                append,
            );
        }
        Ok(CommandResult::status(i32::from(!emitted)))
    }

    fn values_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut separator = None;
        let mut explicit_suffix = None;
        let mut index = 0;
        while index < arguments.len() && arguments[index].starts_with('-') {
            if arguments[index] == "-s" {
                separator = Some(arguments.get(index + 1).cloned().unwrap_or_default());
                index += 2;
            } else if arguments[index] == "-S" {
                explicit_suffix = Some(arguments.get(index + 1).cloned().unwrap_or_default());
                index += 2;
            } else {
                index += if matches!(
                    arguments[index].as_str(),
                    "-S" | "-O" | "-M" | "-J" | "-V" | "-F" | "-X"
                ) {
                    2
                } else {
                    1
                };
            }
        }
        // The first operand names the value set; subsequent operands are the
        // ordered value specifications, including plain values without a
        // description delimiter.
        index = (index + 1).min(arguments.len());
        let mut values = Vec::new();
        for argument in &arguments[index..] {
            let mut repeated_value = argument.starts_with('*');
            let mut specification = argument.strip_prefix('*').unwrap_or(argument);
            if specification.starts_with('(') {
                if let Some(close) = matching_ascii(specification, '(', ')') {
                    specification = &specification[close + 1..];
                }
            }
            repeated_value |= specification.starts_with('*');
            specification = specification.strip_prefix('*').unwrap_or(specification);
            let fields = split_zsh_colons(specification);
            let has_value_argument = fields.len() > 1;
            let (mut value, mut description) = zsh_described_value(specification);
            if !specification.contains('[') {
                description = None;
            }
            if value.is_empty() {
                continue;
            }
            if repeated_value && description.is_some() {
                if let Some(existing) = self
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.emitted.candidate.value == value)
                {
                    if existing.emitted.candidate.description.is_none() {
                        existing.emitted.candidate.description = description.clone();
                    }
                }
            }
            let append = if has_value_argument && explicit_suffix.is_none() {
                // `-s` separates repeated values; an individual value that
                // takes an argument still uses `_values`' native `=` joiner.
                value.push('=');
                AppendPolicy::NoSpace
            } else if has_value_argument {
                let suffix = explicit_suffix.as_deref().unwrap_or_default();
                value.push_str(suffix);
                if suffix.chars().all(char::is_whitespace) {
                    AppendPolicy::Space
                } else {
                    AppendPolicy::NoSpace
                }
            } else if let Some(separator) = &separator {
                value.push_str(separator);
                if separator.is_empty() || separator == "=" {
                    AppendPolicy::NoSpace
                } else {
                    AppendPolicy::Space
                }
            } else {
                AppendPolicy::Space
            };
            values.push((value, description, append, has_value_argument));
        }
        values.sort_by_key(|(_, _, _, has_value_argument)| *has_value_argument);
        values.retain(|(value, _, _, _)| self.zsh_candidate_matches(value));
        let emitted = !values.is_empty();
        for (value, description, append, has_value_argument) in values {
            if !has_value_argument {
                if let Some(existing) = self
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.emitted.candidate.value == value)
                {
                    existing.emitted.candidate.append = append;
                }
            }
            let kind = if value.starts_with('-') {
                RuleCandidateKind::Option
            } else if self.context.word_index == 1 {
                RuleCandidateKind::Subcommand
            } else {
                RuleCandidateKind::Value
            };
            self.emit(value, description, kind, append);
        }
        Ok(CommandResult::status(i32::from(!emitted)))
    }

    fn regex_arguments_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if let Some(target) = arguments
            .first()
            .filter(|target| target.starts_with('_'))
            .filter(|target| !self.active_functions.contains(*target))
        {
            let words = std::iter::once(ScriptWord::literal("_regex_arguments"))
                .chain(arguments.iter().cloned().map(ScriptWord::quoted_literal))
                .collect();
            self.function_order.push(target.clone());
            self.functions.insert(
                target.clone(),
                ScriptFunction {
                    name: target.clone(),
                    arguments: Vec::new(),
                    body: vec![ScriptStatement::Command {
                        command: ScriptCommand {
                            assignments: Vec::new(),
                            words,
                            redirections: Vec::new(),
                        },
                    }],
                },
            );
            return Ok(CommandResult::success());
        }
        let initial_emissions = self.emission_attempts;
        if self.context.current_word.is_empty() {
            let first_actions = zsh_regex_first_actions(&arguments[1..]);
            for first_action in first_actions {
                if self.context.current_word.is_empty()
                    && zsh_parenthesized_action_all_options(&first_action.action)
                {
                    continue;
                }
                for setup in first_action.setups {
                    if let Some(deferred) = self
                        .deferred_completion_words
                        .get(&setup)
                        .filter(|deferred| !deferred.statements.is_empty())
                        .cloned()
                    {
                        self.exec_statements(&deferred.statements)?;
                    }
                }
                self.execute_zsh_action(
                    &first_action.action,
                    &first_action.description,
                    self.context.word_index == 1,
                )?;
            }
            if self.emission_attempts > initial_emissions {
                return Ok(CommandResult::success());
            }
        }
        let mut deferred_executed = false;
        let mut direct_fallback = None;
        let mut helper_fallback = None;
        let mut empty_fallback = None;
        for (index, argument) in arguments.iter().enumerate().skip(1) {
            let fields = split_zsh_colons(argument);
            if fields.len() >= 4 {
                let description = fields.get(2).cloned().unwrap_or_default();
                let action = fields[3..].join(":");
                if action.starts_with('{')
                    && self.context.current_word.starts_with('-')
                    && arguments
                        .get(index - 1)
                        .is_some_and(|pattern| matches!(pattern.as_str(), "/[]/" | "//"))
                {
                    let mut deferred = self
                        .deferred_completion_words
                        .iter()
                        .filter_map(|(source, deferred)| {
                            (!deferred.statements.is_empty())
                                .then(|| {
                                    action
                                        .find(source)
                                        .map(|position| (position, deferred.clone()))
                                })
                                .flatten()
                        })
                        .collect::<Vec<_>>();
                    deferred.sort_by_key(|(position, _)| *position);
                    if !deferred.is_empty() {
                        for (_, deferred) in deferred {
                            self.exec_statements(&deferred.statements)?;
                        }
                        deferred_executed = true;
                        continue;
                    }
                }
                if action.starts_with('(') {
                    if self.context.word_index == 1
                        && self.context.current_word.is_empty()
                        && !arguments
                            .get(index - 1)
                            .is_some_and(|pattern| matches!(pattern.as_str(), "/[]/" | "//"))
                    {
                        continue;
                    }
                    if !self.context.current_word.is_empty() {
                        let direct_values = split_shell_words(
                            action
                                .strip_prefix('(')
                                .and_then(|value| value.strip_suffix(')'))
                                .unwrap_or(&action),
                        );
                        if !direct_values
                            .iter()
                            .any(|value| value.starts_with(self.context.current_word))
                        {
                            continue;
                        }
                    }
                }
                if action.starts_with('(') {
                    if self.context.current_word.is_empty() {
                        empty_fallback = Some((description, action));
                        continue;
                    }
                    let matching_values = split_shell_words(
                        action
                            .strip_prefix('(')
                            .and_then(|value| value.strip_suffix(')'))
                            .unwrap_or(&action),
                    )
                    .iter()
                    .filter(|value| value.starts_with(self.context.current_word))
                    .count();
                    if direct_fallback
                        .as_ref()
                        .is_none_or(|(count, _, _)| matching_values > *count)
                    {
                        direct_fallback = Some((matching_values, description, action));
                    }
                    continue;
                }
                if action.starts_with('_') || action.trim_start().starts_with("compadd ") {
                    if self.context.current_word.is_empty() {
                        if arguments
                            .get(index - 1)
                            .is_some_and(|pattern| matches!(pattern.as_str(), "/[]/" | "//"))
                        {
                            empty_fallback = Some((description, action));
                        }
                        continue;
                    }
                    helper_fallback.get_or_insert((description, action));
                }
            }
            if let Some(state) = argument.split("->").nth(1) {
                let state = state.trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                });
                if !state.is_empty() {
                    self.set_values("state", vec![state.to_owned()], false);
                    return Ok(CommandResult::status(1));
                }
            }
        }
        if deferred_executed && self.emission_attempts > initial_emissions {
            return Ok(CommandResult::success());
        }
        if let Some((description, action)) = empty_fallback {
            return self.execute_zsh_action(&action, &description, self.context.word_index == 1);
        }
        if let Some((_, description, action)) = direct_fallback {
            return self.execute_zsh_action(&action, &description, self.context.word_index == 1);
        }
        if let Some((description, action)) = helper_fallback {
            return self.execute_zsh_action(&action, &description, self.context.word_index == 1);
        }
        Ok(CommandResult::status(1))
    }

    fn emit_zsh_argument_options(&mut self, specifications: &[String]) {
        let mut common = Vec::new();
        let mut sets = Vec::<(String, Vec<&String>)>::new();
        let mut active_set = None;
        let mut index = 0;
        while index < specifications.len() {
            if matches!(specifications[index].as_str(), "-" | "+")
                && index + 1 < specifications.len()
            {
                let name = specifications[index + 1]
                    .trim_matches(['(', ')'])
                    .to_owned();
                sets.push((name, Vec::new()));
                active_set = Some(sets.len() - 1);
                index += 2;
                continue;
            }
            if let Some(active_set) = active_set {
                sets[active_set].1.push(&specifications[index]);
            } else {
                common.push(&specifications[index]);
            }
            index += 1;
        }

        let current_position = self
            .variable_values("CURRENT")
            .first()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(self.context.word_index + 1)
            .saturating_sub(1);
        let option_is_present = |option: &str| {
            self.variable_values("words")
                .iter()
                .take(current_position)
                .skip(1)
                .any(|word| zsh_word_contains_option(word, option))
        };
        let mut ordered = Vec::new();
        if sets.is_empty() {
            ordered.extend(
                common
                    .into_iter()
                    .map(|specification| (specification, None)),
            );
        } else {
            let mut inactive_sets = 0usize;
            for (set_name, set) in sets.iter().rev() {
                let active = set
                    .iter()
                    .flat_map(|specification| zsh_spec_options(specification))
                    .any(|option| option_is_present(&option));
                if !active {
                    inactive_sets += 1;
                    ordered.extend(
                        common
                            .iter()
                            .copied()
                            .map(|specification| (specification, Some(set_name.as_str())))
                            .chain(
                                set.iter()
                                    .copied()
                                    .map(|specification| (specification, Some(set_name.as_str()))),
                            ),
                    );
                }
            }
            if inactive_sets == 0 {
                ordered.extend(
                    common
                        .into_iter()
                        .map(|specification| (specification, None)),
                );
            }
        }
        let categorize_arguments = true;

        let mut records = Vec::<(String, Option<String>)>::new();
        let mut record_categories = Vec::new();
        let mut record_no_space = Vec::new();
        let mut record_repeated = Vec::new();
        let mut seen_records = HashSet::new();
        for (specification, set_name) in ordered {
            let exclusions = zsh_spec_exclusions(specification);
            let excluded_by_set = set_name.is_some_and(|set_name| {
                sets.iter()
                    .find(|(name, _)| name == set_name)
                    .is_some_and(|(_, set)| {
                        set.iter()
                            .flat_map(|specification| zsh_spec_options(specification))
                            .any(|option| exclusions.iter().any(|excluded| excluded == &option))
                    })
            });
            let specification_options = zsh_spec_options(specification);
            let has_set_exclusion = exclusions
                .iter()
                .any(|exclusion| !exclusion.starts_with(['-', '+']));
            let excludes_own_option = has_set_exclusion
                && specification_options.iter().any(|option| {
                    let option = option
                        .trim_start_matches('*')
                        .trim_end_matches(['+', '-', '=']);
                    exclusions
                        .iter()
                        .any(|exclusion| exclusion.trim_end_matches('=') == option)
                });
            if excluded_by_set
                || excludes_own_option
                || exclusions.iter().any(|option| option_is_present(option))
            {
                continue;
            }
            let description = zsh_spec_description(specification);
            let has_action = split_zsh_colons(specification).len() > 1;
            let option_head = &specification[..specification
                .find(['[', ':'])
                .unwrap_or(specification.len())];
            let literal_trailing_hyphen = option_head.ends_with("\\-");
            for raw_option in specification_options {
                let option_without_mode = if matches!(raw_option.as_str(), "+" | "--") {
                    raw_option.as_str()
                } else if raw_option.ends_with('+')
                    || raw_option.ends_with('-') && !literal_trailing_hyphen
                {
                    &raw_option[..raw_option.len() - 1]
                } else {
                    &raw_option
                };
                let description = description.clone();
                let category = if !categorize_arguments {
                    0
                } else if option_without_mode.ends_with('=')
                    && (has_action || description.is_some())
                {
                    2
                } else if raw_option != "--"
                    && raw_option.ends_with('-')
                    && !literal_trailing_hyphen
                {
                    1
                } else {
                    0
                };
                let option = option_without_mode.to_owned();
                if (option.starts_with('-') || option.starts_with('+'))
                    && option != "--"
                    && !raw_option.ends_with('*')
                    && !option.is_empty()
                    && seen_records.insert((option.clone(), description.clone()))
                {
                    records.push((option, description));
                    record_categories.push(category);
                    record_no_space.push(
                        raw_option != "--" && raw_option.ends_with('-') && !literal_trailing_hyphen,
                    );
                    record_repeated.push(raw_option.ends_with('+'));
                }
            }
        }

        let matching_indices = records
            .iter()
            .enumerate()
            .filter(|(_, (option, _))| {
                self.context.current_word.is_empty()
                    || option.starts_with(self.context.current_word)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let mut order = Vec::new();
        for category in 0..=if categorize_arguments { 2 } else { 0 } {
            for described in [true, false] {
                for repeated in [false, true] {
                    order.extend(matching_indices.iter().copied().filter(|index| {
                        record_categories[*index] == category
                            && records[*index]
                                .1
                                .as_ref()
                                .is_some_and(|value| !value.is_empty())
                                == described
                            && record_repeated[*index] == repeated
                    }));
                }
            }
        }
        for index in order {
            let (option, description) = &records[index];
            self.emit(
                option.clone(),
                description.clone(),
                if option.starts_with('-') {
                    RuleCandidateKind::Option
                } else {
                    RuleCandidateKind::Subcommand
                },
                if option.ends_with('=') || record_no_space[index] {
                    AppendPolicy::NoSpace
                } else {
                    AppendPolicy::Space
                },
            );
        }
    }

    fn zsh_candidate_matches(&self, value: &str) -> bool {
        let prefix = self
            .variable_values("PREFIX")
            .first()
            .cloned()
            .unwrap_or_else(|| self.context.current_word.to_owned());
        prefix.is_empty() || value.starts_with(&prefix)
    }

    fn compadd_array_values(&self, name: &str, keys: bool) -> Vec<String> {
        let Some(variable) = self.variables.get(name) else {
            return Vec::new();
        };
        if !keys {
            return variable.values.clone();
        }
        if variable.associative {
            let entries = variable.values.chunks_exact(2).collect::<Vec<_>>();
            return zsh_associative_scan_indices(&entries)
                .into_iter()
                .map(|index| entries[index][0].clone())
                .collect();
        }
        variable.values.clone()
    }

    fn compadd_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut description = None;
        let mut description_values = Vec::new();
        let mut suffix = AppendPolicy::Space;
        let mut literal_prefix = String::new();
        let mut literal_suffix = String::new();
        let mut values = Vec::new();
        let mut output_variable = None;
        let mut array_mode = None;
        let mut index = 0;
        let mut after_separator = false;
        while index < arguments.len() {
            let argument = &arguments[index];
            if after_separator {
                if let Some(keys) = array_mode {
                    values.extend(
                        self.compadd_array_values(argument, keys)
                            .into_iter()
                            .map(|value| (value, false)),
                    );
                } else {
                    values.push((argument.clone(), true));
                }
                index += 1;
                continue;
            }
            match argument.as_str() {
                "--" | "-" => {
                    after_separator = true;
                    index += 1;
                }
                "-a" | "-k" => {
                    array_mode = Some(argument == "-k");
                    index += 1;
                }
                "-d" if index + 1 < arguments.len() => {
                    let variable = &arguments[index + 1];
                    description_values = self.variable_values(variable);
                    if description_values.is_empty() && !variable.is_empty() {
                        description = Some(variable.clone());
                    }
                    index += 2;
                }
                "-O" if index + 1 < arguments.len() => {
                    output_variable = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "-X" | "-x" if index + 1 < arguments.len() => {
                    description = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "-P" if index + 1 < arguments.len() => {
                    literal_prefix = arguments[index + 1].clone();
                    index += 2;
                }
                "-S" if index + 1 < arguments.len() => {
                    literal_suffix = arguments[index + 1].clone();
                    suffix = if literal_suffix.is_empty() || literal_suffix.ends_with('=') {
                        AppendPolicy::NoSpace
                    } else {
                        AppendPolicy::Space
                    };
                    index += 2;
                }
                value if value.starts_with('-') => {
                    let flags = value.trim_start_matches('-');
                    if let Some(position) = flags.find('P') {
                        let attached = &flags[position + 1..];
                        if !attached.is_empty() {
                            literal_prefix = attached.to_owned();
                            index += 1;
                            continue;
                        }
                    }
                    if let Some(position) = flags.find('S') {
                        let attached = &flags[position + 1..];
                        if !attached.is_empty() {
                            literal_suffix = attached.to_owned();
                            suffix = if literal_suffix.ends_with('=') {
                                AppendPolicy::NoSpace
                            } else {
                                AppendPolicy::Space
                            };
                            index += 1;
                            continue;
                        }
                    }
                    if let Some(option) = zsh_compadd_option_taking_next(value) {
                        if option == 'S' {
                            literal_suffix = arguments.get(index + 1).cloned().unwrap_or_default();
                            suffix = if literal_suffix.is_empty() || literal_suffix.ends_with('=') {
                                AppendPolicy::NoSpace
                            } else {
                                AppendPolicy::Space
                            };
                        } else if option == 'P' {
                            literal_prefix = arguments.get(index + 1).cloned().unwrap_or_default();
                        }
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                _ => {
                    if let Some(keys) = array_mode {
                        values.extend(
                            self.compadd_array_values(argument, keys)
                                .into_iter()
                                .map(|value| (value, false)),
                        );
                    } else {
                        values.push((argument.clone(), true));
                    }
                    index += 1;
                }
            }
        }
        if literal_prefix.starts_with(['\'', '"']) {
            literal_suffix = zsh_quote_value(&literal_suffix);
        }
        literal_prefix.clear();
        if let Some(variable) = output_variable {
            let output = values.iter().map(|(value, _)| value.clone()).collect();
            self.set_values(&variable, output, true);
            return Ok(CommandResult::status(i32::from(values.is_empty())));
        }
        let matching = values
            .into_iter()
            .enumerate()
            .filter(|(_, (value, explicit))| *explicit || !value.is_empty())
            .map(|(index, (raw, _))| {
                let value = format!("{literal_prefix}{raw}{literal_suffix}");
                (index, raw, value)
            })
            .filter(|(_, _, value)| self.zsh_candidate_matches(value))
            .collect::<Vec<_>>();
        let emitted = !matching.is_empty();
        for (index, raw, value) in matching {
            let kind = if value.starts_with('-') {
                RuleCandidateKind::Option
            } else if self.context.word_index == 1 {
                RuleCandidateKind::Subcommand
            } else {
                RuleCandidateKind::Value
            };
            self.emit(
                value,
                description_values
                    .get(index)
                    .and_then(|display| zsh_compadd_display_description(display, &raw))
                    .or_else(|| description.clone()),
                kind,
                suffix,
            );
        }
        Ok(CommandResult::status(i32::from(!emitted)))
    }

    fn comparguments_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if !arguments.iter().any(|argument| argument == "-i") {
            return Ok(CommandResult::status(1));
        }
        let mut after_separator = false;
        for specification in arguments {
            if specification == "--" {
                after_separator = true;
                continue;
            }
            if !after_separator && specification.starts_with('-') && specification.len() <= 3 {
                continue;
            }
            let mut value = specification.as_str();
            while value.starts_with('*') || value.starts_with('+') {
                value = &value[1..];
            }
            if value.starts_with('(') {
                if let Some(close) = matching_ascii(value, '(', ')') {
                    value = &value[close + 1..];
                }
            }
            let description = value
                .find('[')
                .and_then(|open| value[open + 1..].find(']').map(|close| (open, close)))
                .map(|(open, close)| value[open + 1..open + 1 + close].to_owned());
            let option_end = value.find(['[', ':']).unwrap_or(value.len());
            let option_expression = &value[..option_end];
            let options = if option_expression.starts_with('{') && option_expression.ends_with('}')
            {
                option_expression[1..option_expression.len() - 1]
                    .split(',')
                    .collect::<Vec<_>>()
            } else {
                vec![option_expression]
            };
            for option in options {
                let option = option.trim_end_matches('-');
                if option.starts_with('-') && option.len() > 1 {
                    self.emit(
                        option.to_owned(),
                        description.clone(),
                        RuleCandidateKind::Option,
                        if option.ends_with('=') {
                            AppendPolicy::NoSpace
                        } else {
                            AppendPolicy::Space
                        },
                    );
                }
            }
        }
        Ok(CommandResult::status(1))
    }

    fn compset_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut status = 1;
        if let Some(position) = arguments.iter().position(|argument| argument == "-n") {
            if let Some(start) = arguments
                .get(position + 1)
                .and_then(|value| value.parse::<usize>().ok())
            {
                let drop = start.saturating_sub(1);
                let current = self
                    .variable_values("CURRENT")
                    .first()
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(1);
                let words = self.variable_values("words");
                if current > drop && drop <= words.len() {
                    let words = words.into_iter().skip(drop).collect::<Vec<_>>();
                    self.set_values("words", words.clone(), false);
                    self.set_values("line", words, false);
                    self.set_values("CURRENT", vec![(current - drop).to_string()], false);
                    status = 0;
                }
            }
        }
        if let Some(position) = arguments.iter().position(|argument| argument == "-N") {
            if let Some(pattern) = arguments.get(position + 1) {
                let prefix = self.variable_values("PREFIX").join("");
                if shell_pattern_dialect(ScriptDialect::Zsh, pattern, &prefix) {
                    status = 0;
                }
            }
        }
        if let Some(position) = arguments.iter().position(|argument| argument == "-P") {
            let mut pattern_index = position + 1;
            if arguments
                .get(pattern_index)
                .is_some_and(|value| value.parse::<usize>().is_ok())
            {
                pattern_index += 1;
            }
            if let Some(pattern) = arguments.get(pattern_index) {
                let prefix = self.variable_values("PREFIX").join("");
                let mut boundaries = prefix
                    .char_indices()
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                boundaries.push(prefix.len());
                if let Some(end) = boundaries
                    .into_iter()
                    .rev()
                    .find(|end| shell_pattern_dialect(ScriptDialect::Zsh, pattern, &prefix[..*end]))
                {
                    let consumed = &prefix[..end];
                    let iprefix =
                        format!("{}{}", self.variable_values("IPREFIX").join(""), consumed);
                    self.set_values("IPREFIX", vec![iprefix], false);
                    self.set_values("PREFIX", vec![prefix[end..].to_owned()], false);
                    status = 0;
                }
            }
        }
        if let Some(position) = arguments.iter().position(|argument| argument == "-S") {
            if let Some(pattern) = arguments.get(position + 1) {
                let suffix = self.variable_values("SUFFIX").join("");
                if shell_pattern_dialect(ScriptDialect::Zsh, pattern, &suffix) {
                    status = 0;
                }
            }
        }
        Ok(CommandResult::status(status))
    }

    fn zstyle_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        if arguments
            .iter()
            .any(|argument| argument == "-t" || argument == "-T")
        {
            let enabled_by_default = arguments
                .last()
                .is_some_and(|style| style == "prefix-needed");
            return Ok(CommandResult::status(i32::from(!enabled_by_default)));
        }
        if let Some(position) = arguments.iter().position(|argument| argument == "-s") {
            if let Some(variable) = arguments.get(position + 3) {
                self.set_values(variable, Vec::new(), false);
            }
            return Ok(CommandResult::status(1));
        }
        Ok(CommandResult::success())
    }

    fn print_builtin(&mut self, arguments: &[String]) -> Result<CommandResult, VmError> {
        let mut variable = None;
        let mut format = None;
        let mut values = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "-v" if index + 1 < arguments.len() => {
                    variable = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "-f" if index + 1 < arguments.len() => {
                    format = Some(arguments[index + 1].clone());
                    index += 2;
                }
                "--" | "-" => {
                    values.extend_from_slice(&arguments[index + 1..]);
                    break;
                }
                argument if argument.starts_with('-') => index += 1,
                _ => {
                    values.push(arguments[index].clone());
                    index += 1;
                }
            }
        }
        let target_is_array = variable
            .as_ref()
            .and_then(|variable| self.variables.get(variable))
            .is_some_and(|variable| variable.array);
        let output = if let Some(format) = format {
            if target_is_array {
                let arity = printf_format_arity(&format).max(1);
                values
                    .chunks(arity)
                    .flat_map(|values| {
                        format_values(
                            &std::iter::once(format.clone())
                                .chain(values.iter().cloned())
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect()
            } else {
                format_values(&std::iter::once(format).chain(values).collect::<Vec<_>>())
            }
        } else {
            values
        };
        if let Some(variable) = variable {
            if target_is_array {
                self.set_values(&variable, output, false);
            } else {
                self.set_values(&variable, vec![output.join("\n")], false);
            }
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::output(output))
        }
    }

    fn head_tail_builtin(
        &self,
        name: &str,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let count = arguments
            .windows(2)
            .find(|pair| pair[0] == "-n")
            .and_then(|pair| pair[1].trim_start_matches('+').parse::<usize>().ok())
            .unwrap_or(10);
        let output = if name == "head" {
            input.iter().take(count).cloned().collect()
        } else if arguments.iter().any(|argument| argument.starts_with('+')) {
            input
                .iter()
                .skip(count.saturating_sub(1))
                .cloned()
                .collect()
        } else {
            input
                .iter()
                .skip(input.len().saturating_sub(count))
                .cloned()
                .collect()
        };
        Ok(CommandResult::output(output))
    }

    fn cut_builtin(
        &self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let delimiter = arguments
            .windows(2)
            .find(|pair| pair[0] == "-d")
            .and_then(|pair| pair[1].chars().next())
            .unwrap_or('\t');
        let field = arguments
            .windows(2)
            .find(|pair| pair[0] == "-f")
            .and_then(|pair| pair[1].parse::<usize>().ok())
            .unwrap_or(1);
        Ok(CommandResult::output(
            input
                .iter()
                .map(|value| {
                    value
                        .split(delimiter)
                        .nth(field.saturating_sub(1))
                        .unwrap_or("")
                        .to_owned()
                })
                .collect(),
        ))
    }

    fn tr_builtin(&self, arguments: &[String], input: &[String]) -> Result<CommandResult, VmError> {
        let delete = arguments.iter().any(|argument| {
            argument == "--delete"
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| flags.contains('d'))
        });
        let squeeze = arguments.iter().any(|argument| {
            argument == "--squeeze-repeats"
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| flags.contains('s'))
        });
        let sets = arguments
            .iter()
            .filter(|argument| !argument.starts_with('-'))
            .map(|argument| tr_character_set(argument))
            .collect::<Vec<_>>();
        let Some(from) = sets.first() else {
            return Ok(CommandResult::status(1));
        };
        if !delete && sets.len() < 2 {
            return Ok(CommandResult::status(1));
        }
        let to = sets.get(1).cloned().unwrap_or_default();
        let mut output = Vec::new();
        for value in input {
            let mut translated = String::new();
            let mut previous = None;
            for character in value.chars() {
                let mapped = from
                    .iter()
                    .position(|candidate| *candidate == character)
                    .and_then(|index| {
                        if delete {
                            None
                        } else {
                            to.get(index).or_else(|| to.last()).copied()
                        }
                    });
                if delete && from.contains(&character) {
                    continue;
                }
                let mapped = mapped.unwrap_or(character);
                if squeeze && previous == Some(mapped) && to.contains(&mapped) {
                    continue;
                }
                translated.push(mapped);
                previous = Some(mapped);
            }
            output.extend(translated.split('\n').map(str::to_owned));
        }
        Ok(CommandResult::output(output))
    }

    fn grep_builtin(
        &self,
        arguments: &[String],
        input: &[String],
    ) -> Result<CommandResult, VmError> {
        let invert = arguments.iter().any(|argument| argument == "-v");
        let quiet = arguments.iter().any(|argument| argument == "-q");
        let pattern = arguments
            .iter()
            .rev()
            .find(|argument| !argument.starts_with('-'))
            .map_or("", String::as_str);
        let mut output = input
            .iter()
            .filter(|value| simple_regex_match(pattern, value) != invert)
            .cloned()
            .collect::<Vec<_>>();
        let status = i32::from(output.is_empty());
        if quiet {
            output.clear();
        }
        Ok(CommandResult {
            status,
            output,
            control: Control::None,
        })
    }

    fn external(&mut self, name: &str, arguments: &[String]) -> Result<CommandResult, VmError> {
        let name = name.rsplit('/').next().unwrap_or(name);
        if name.starts_with('_') {
            return Ok(CommandResult::status(127));
        }
        if self.mode != EvaluationMode::ExplicitTab {
            return Ok(CommandResult::status(127));
        }
        if !self
            .module
            .probe_capabilities
            .iter()
            .any(|capability| capability == name)
        {
            self.denied_probe_count = self.denied_probe_count.saturating_add(1);
            return Ok(CommandResult::status(126));
        }
        if !self.trust.permits_dynamic_probes() {
            self.denied_probe_count = self.denied_probe_count.saturating_add(1);
            return Ok(CommandResult::status(126));
        }
        if forbidden_executable(name) || self.probes.len() >= MAX_PROBE_REQUESTS {
            return Ok(CommandResult::status(126));
        }
        let mut environment = self
            .variables
            .iter()
            .filter(|(_, variable)| variable.exported)
            .filter_map(|(name, variable)| {
                variable
                    .values
                    .first()
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect::<Vec<_>>();
        environment.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        environment.truncate(256);
        let key = ProbeKey {
            executable: name.to_owned(),
            arguments: arguments.to_vec(),
            environment,
            working_directory: self
                .context
                .working_directory
                .to_string_lossy()
                .into_owned(),
            parser: if arguments
                .iter()
                .any(|argument| matches!(argument.as_str(), "-0" | "-z" | "--null"))
            {
                ProbeParser::Nul
            } else {
                ProbeParser::Lines
            },
            include_stderr: self.capture_stderr,
        };
        if let Some(outcome) = self.probe_results.get(&key) {
            self.check_values(&outcome.values)?;
            self.truncated |= outcome.truncated;
            return Ok(CommandResult {
                status: outcome.status,
                output: outcome.values.clone(),
                control: Control::None,
            });
        }
        let probe_id = format!(
            "script:{}:{:016x}",
            self.module.source_path,
            stable_probe_hash(&key)
        );
        if self.probes.iter().any(|probe| probe.probe_id == probe_id) {
            return Ok(CommandResult::status(125));
        }
        let request = ProbeRequest {
            key,
            probe_id,
            candidate_kind: RuleCandidateKind::Value,
            append: AppendPolicy::Space,
            timeout_ms: 2000,
            output_limit: 1024 * 1024,
            cache_ttl_ms: 1000,
            description: None,
            source: self.source,
            dynamic_authorized: true,
        };
        self.probes.push(request);
        Ok(CommandResult::status(125))
    }

    fn emit_bash_compreply(&mut self) {
        let append = if self.variable_values("__bashlume_nospace").is_empty() {
            AppendPolicy::Space
        } else {
            AppendPolicy::NoSpace
        };
        for value in self.variable_values("COMPREPLY") {
            let kind = if value.starts_with('-') {
                RuleCandidateKind::Option
            } else {
                RuleCandidateKind::Value
            };
            self.emit(value, None, kind, append);
        }
    }

    fn emit(
        &mut self,
        value: String,
        description: Option<String>,
        kind: RuleCandidateKind,
        append: AppendPolicy,
    ) {
        self.emit_with_order(value, description, kind, append, true);
    }

    fn emit_with_order(
        &mut self,
        value: String,
        description: Option<String>,
        kind: RuleCandidateKind,
        append: AppendPolicy,
        preserve_order: bool,
    ) {
        if self.initializing
            || value.is_empty()
            || value.chars().any(char::is_control)
            || kind == RuleCandidateKind::Option && value.contains(['[', ']'])
        {
            return;
        }
        if value.len() > MAX_EMITTED_CANDIDATE_BYTES {
            self.limit_error = Some("candidate bytes");
            return;
        }
        self.emission_attempts = self.emission_attempts.saturating_add(1);
        let description = description.and_then(|description| {
            let description = description
                .chars()
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect::<String>();
            (!description.is_empty()).then_some(description)
        });
        if description
            .as_ref()
            .is_some_and(|description| description.len() > MAX_EMITTED_CANDIDATE_BYTES)
        {
            self.limit_error = Some("candidate description bytes");
            return;
        }
        let emission_bytes = value
            .len()
            .saturating_mul(2)
            .saturating_add(description.as_ref().map_or(0, String::len));
        if self.candidate_bytes.saturating_add(emission_bytes) > MAX_TOTAL_CANDIDATE_BYTES {
            self.limit_error = Some("candidate bytes");
            return;
        }
        self.candidate_bytes = self.candidate_bytes.saturating_add(emission_bytes);
        let fish_item = self.fish_item;
        self.fish_item = self.fish_item.wrapping_add(1);
        let deduplicate = self.module.dialect != ScriptDialect::Bash;
        if deduplicate && !self.emitted_values.insert(value.clone()) {
            if let Some(existing) = self
                .candidates
                .iter_mut()
                .find(|candidate| candidate.emitted.candidate.value == value)
            {
                if self.module.dialect == ScriptDialect::Fish {
                    existing.emitted.candidate.description = description;
                    existing.emitted.candidate.kind = kind;
                    existing.emitted.candidate.append = append;
                    existing.emitted.candidate.preserve_order = preserve_order;
                    existing.fish_group = self.fish_group;
                    existing.fish_item = fish_item;
                } else if self.module.dialect == ScriptDialect::Zsh
                    && existing.emitted.candidate.description.is_none()
                    && description.is_some()
                {
                    existing.emitted.candidate.description = description;
                }
            }
            return;
        }
        if self.candidates.len() >= self.candidate_limit {
            if deduplicate {
                self.emitted_values.remove(&value);
            }
            self.truncated = true;
            return;
        }
        self.candidates.push(CandidateRecord {
            emitted: EmittedCandidate {
                candidate: CandidateTemplate {
                    display: value.clone(),
                    value,
                    description,
                    kind,
                    append,
                    preserve_order,
                },
                source: self.source,
            },
            fish_group: self.fish_group,
            fish_item,
        });
    }
}

fn initialize_context_variables(
    dialect: ScriptDialect,
    context: &EvaluationContext<'_>,
    variables: &mut HashMap<String, Variable>,
) {
    let mut insert = |name: &str, values: Vec<String>| {
        variables.insert(
            name.into(),
            Variable {
                values,
                exported: false,
                readonly: false,
                array: matches!(
                    name,
                    "@" | "*"
                        | "argv"
                        | "COMP_WORDS"
                        | "COMPREPLY"
                        | "BASH_VERSINFO"
                        | "words"
                        | "line"
                        | "opt_args"
                ),
                associative: false,
            },
        );
    };
    insert(
        "0",
        vec![context.words.first().cloned().unwrap_or_default()],
    );
    insert("@", context.words.to_vec());
    insert("*", context.words.to_vec());
    insert("argv", context.words.get(1..).unwrap_or_default().to_vec());
    for (index, value) in context.words.iter().enumerate().skip(1) {
        insert(&index.to_string(), vec![value.clone()]);
    }
    match dialect {
        ScriptDialect::Bash => {
            insert("COMP_WORDS", context.words.to_vec());
            insert("COMP_CWORD", vec![context.word_index.to_string()]);
            let line = context.words.join(" ");
            insert("COMP_POINT", vec![line.len().to_string()]);
            insert("COMP_LINE", vec![line]);
            insert("COMPREPLY", Vec::new());
            insert("BASH_VERSINFO", vec!["5".into(), "3".into()]);
            insert("COMP_WORDBREAKS", vec![" \\t\\n\"'><=;|&(:".into()]);
            insert("__bashlume_shopt", vec!["extglob".into()]);
        }
        ScriptDialect::Zsh => {
            insert("@", Vec::new());
            insert("*", Vec::new());
            insert("argv", Vec::new());
            insert("OSTYPE", vec!["linux-gnu".into()]);
            insert("HOSTTYPE", vec![String::new()]);
            insert("MACHTYPE", vec![std::env::consts::ARCH.into()]);
            insert("VENDOR", vec!["pc".into()]);
            insert("ZSH_VERSION", vec!["5.9.2".into()]);
            insert("words", context.words.to_vec());
            insert("CURRENT", vec![(context.word_index + 1).to_string()]);
            insert("PREFIX", vec![context.current_word.to_owned()]);
            insert("IPREFIX", vec![String::new()]);
            insert("SUFFIX", vec![String::new()]);
            insert(
                "service",
                vec![context.words.first().cloned().unwrap_or_default()],
            );
            insert("state", Vec::new());
            insert("ret", vec!["1".into()]);
            insert("line", context.words.to_vec());
            insert("opt_args", Vec::new());
        }
        ScriptDialect::Fish => {}
    }
}

fn statements_use_unquoted_parameter(statements: &[ScriptStatement], name: &str) -> bool {
    fn word_uses(word: &ScriptWord, name: &str) -> bool {
        word.parts.iter().any(|part| match part {
            ScriptWordPart::Parameter {
                expression,
                quoted: false,
            } => expression
                .strip_prefix(name)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['[', ':', '/', '%', '#'])),
            ScriptWordPart::CommandSubstitution { statements, .. } => {
                statements_use_unquoted_parameter(statements, name)
            }
            ScriptWordPart::DeferredScript {
                statements, words, ..
            } => {
                statements_use_unquoted_parameter(statements, name)
                    || words.iter().any(|word| word_uses(word, name))
            }
            ScriptWordPart::Array { elements }
            | ScriptWordPart::BraceExpansion {
                alternatives: elements,
                ..
            } => elements.iter().any(|word| word_uses(word, name)),
            _ => false,
        })
    }
    fn command_uses(command: &ScriptCommand, name: &str) -> bool {
        command.words.iter().any(|word| word_uses(word, name))
            || command.assignments.iter().any(|assignment| {
                assignment
                    .index
                    .as_ref()
                    .is_some_and(|word| word_uses(word, name))
                    || word_uses(&assignment.value, name)
            })
            || command
                .redirections
                .iter()
                .any(|redirection| word_uses(&redirection.target, name))
    }
    statements.iter().any(|statement| match statement {
        ScriptStatement::Command { command } => command_uses(command, name),
        ScriptStatement::AndOr { first, rest } => {
            statements_use_unquoted_parameter(std::slice::from_ref(first.as_ref()), name)
                || rest.iter().any(|arm| {
                    statements_use_unquoted_parameter(
                        std::slice::from_ref(arm.statement.as_ref()),
                        name,
                    )
                })
        }
        ScriptStatement::Pipeline { commands, .. } => {
            statements_use_unquoted_parameter(commands, name)
        }
        ScriptStatement::If {
            branches,
            otherwise,
        } => {
            branches.iter().any(|branch| {
                statements_use_unquoted_parameter(&branch.condition, name)
                    || statements_use_unquoted_parameter(&branch.body, name)
            }) || statements_use_unquoted_parameter(otherwise, name)
        }
        ScriptStatement::While {
            condition, body, ..
        } => {
            statements_use_unquoted_parameter(condition, name)
                || statements_use_unquoted_parameter(body, name)
        }
        ScriptStatement::For { words, body, .. } => {
            words.iter().any(|word| word_uses(word, name))
                || statements_use_unquoted_parameter(body, name)
        }
        ScriptStatement::Case { word, arms } => {
            word_uses(word, name)
                || arms.iter().any(|arm| {
                    arm.patterns.iter().any(|word| word_uses(word, name))
                        || statements_use_unquoted_parameter(&arm.body, name)
                })
        }
        ScriptStatement::Function { function } => {
            function.arguments.iter().any(|word| word_uses(word, name))
                || statements_use_unquoted_parameter(&function.body, name)
        }
        ScriptStatement::Group { body, .. } => statements_use_unquoted_parameter(body, name),
        ScriptStatement::Return { status } => {
            status.as_ref().is_some_and(|word| word_uses(word, name))
        }
        ScriptStatement::Redirected {
            statement,
            redirections,
        } => {
            statements_use_unquoted_parameter(std::slice::from_ref(statement.as_ref()), name)
                || redirections
                    .iter()
                    .any(|redirection| word_uses(&redirection.target, name))
        }
        ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => false,
    })
}

fn collect_statement_functions(
    statements: &[ScriptStatement],
    functions: &mut HashMap<String, ScriptFunction>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Function { function } => {
                functions.insert(function.name.clone(), function.clone());
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_statement_functions(&branch.body, functions);
                }
                collect_statement_functions(otherwise, functions);
            }
            ScriptStatement::While { body, .. }
            | ScriptStatement::For { body, .. }
            | ScriptStatement::Group { body, .. } => collect_statement_functions(body, functions),
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_statement_functions(&arm.body, functions);
                }
            }
            ScriptStatement::Redirected { statement, .. } => {
                collect_statement_functions(std::slice::from_ref(statement), functions);
            }
            _ => {}
        }
    }
}

fn collect_deferred_completion_words(
    statements: &[ScriptStatement],
    deferred: &mut HashMap<String, DeferredCompletion>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                for assignment in &command.assignments {
                    if let Some(index) = &assignment.index {
                        collect_deferred_completion_word(index, deferred);
                    }
                    collect_deferred_completion_word(&assignment.value, deferred);
                }
                for word in &command.words {
                    collect_deferred_completion_word(word, deferred);
                }
                for redirection in &command.redirections {
                    collect_deferred_completion_word(&redirection.target, deferred);
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_deferred_completion_words(commands, deferred);
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_deferred_completion_words(std::slice::from_ref(first), deferred);
                for arm in rest {
                    collect_deferred_completion_words(
                        std::slice::from_ref(&arm.statement),
                        deferred,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_deferred_completion_words(&branch.condition, deferred);
                    collect_deferred_completion_words(&branch.body, deferred);
                }
                collect_deferred_completion_words(otherwise, deferred);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_deferred_completion_words(condition, deferred);
                collect_deferred_completion_words(body, deferred);
            }
            ScriptStatement::For { words, body, .. } => {
                for word in words {
                    collect_deferred_completion_word(word, deferred);
                }
                collect_deferred_completion_words(body, deferred);
            }
            ScriptStatement::Case { word, arms } => {
                collect_deferred_completion_word(word, deferred);
                for arm in arms {
                    for pattern in &arm.patterns {
                        collect_deferred_completion_word(pattern, deferred);
                    }
                    collect_deferred_completion_words(&arm.body, deferred);
                }
            }
            ScriptStatement::Function { function } => {
                for argument in &function.arguments {
                    collect_deferred_completion_word(argument, deferred);
                }
                collect_deferred_completion_words(&function.body, deferred);
            }
            ScriptStatement::Group { body, .. } => {
                collect_deferred_completion_words(body, deferred);
            }
            ScriptStatement::Return { status } => {
                if let Some(status) = status {
                    collect_deferred_completion_word(status, deferred);
                }
            }
            ScriptStatement::Redirected {
                statement,
                redirections,
            } => {
                collect_deferred_completion_words(std::slice::from_ref(statement), deferred);
                for redirection in redirections {
                    collect_deferred_completion_word(&redirection.target, deferred);
                }
            }
            ScriptStatement::Break | ScriptStatement::Continue | ScriptStatement::Noop => {}
        }
    }
}

fn collect_deferred_completion_word(
    word: &ScriptWord,
    deferred: &mut HashMap<String, DeferredCompletion>,
) {
    for part in &word.parts {
        match part {
            ScriptWordPart::DeferredScript {
                source,
                statements,
                words,
            } => {
                if !words.is_empty() || !statements.is_empty() {
                    deferred.insert(
                        source.clone(),
                        DeferredCompletion {
                            statements: statements.clone(),
                            words: words.clone(),
                        },
                    );
                }
                collect_deferred_completion_words(statements, deferred);
                for word in words {
                    collect_deferred_completion_word(word, deferred);
                }
            }
            ScriptWordPart::CommandSubstitution { statements, .. } => {
                collect_deferred_completion_words(statements, deferred);
            }
            ScriptWordPart::BraceExpansion { alternatives, .. } => {
                for alternative in alternatives {
                    collect_deferred_completion_word(alternative, deferred);
                }
            }
            ScriptWordPart::Array { elements } => {
                for element in elements {
                    collect_deferred_completion_word(element, deferred);
                }
            }
            _ => {}
        }
    }
}

fn fish_function_argument_names(arguments: &[ScriptWord]) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments[index].as_plain_literal().unwrap_or("");
        if matches!(value, "-a" | "--argument-names") {
            index += 1;
            while index < arguments.len() {
                let value = arguments[index].as_plain_literal().unwrap_or("");
                if value.starts_with('-') {
                    break;
                }
                names.push(value.to_owned());
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    names
}

fn save_positional(variables: &HashMap<String, Variable>) -> HashMap<String, Variable> {
    variables
        .iter()
        .filter(|(name, _)| {
            matches!(name.as_str(), "@" | "*" | "argv")
                || name.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn restore_positional(variables: &mut HashMap<String, Variable>, saved: HashMap<String, Variable>) {
    variables.retain(|name, _| {
        !matches!(name.as_str(), "@" | "*" | "argv")
            && !name.bytes().all(|byte| byte.is_ascii_digit())
    });
    variables.extend(saved);
}

fn split_variable_subscript(reference: &str) -> (&str, Option<&str>) {
    if let Some(open) = reference.find('[') {
        if reference.ends_with(']') {
            return (
                &reference[..open],
                Some(&reference[open + 1..reference.len() - 1]),
            );
        }
    }
    (reference, None)
}

fn split_variable_reference(reference: &str) -> (&str, Option<isize>) {
    let (name, subscript) = split_variable_subscript(reference);
    (name, subscript.and_then(|index| index.parse().ok()))
}

fn select_parameter_indices(
    values: &[String],
    expression: &str,
    dialect: ScriptDialect,
) -> Vec<String> {
    if matches!(expression, "@" | "*") {
        return values.to_vec();
    }
    selected_parameter_indices(expression, values.len(), dialect)
        .into_iter()
        .filter_map(|index| values.get(index).cloned())
        .collect()
}

fn selected_parameter_indices(
    expression: &str,
    length: usize,
    dialect: ScriptDialect,
) -> Vec<usize> {
    if length == 0 {
        return Vec::new();
    }
    let range = expression
        .split_once("..")
        .or_else(|| expression.split_once(','));
    if let Some((start, end)) = range {
        let start = if start.is_empty() {
            0
        } else {
            let Some(start) = parse_index(start, length, dialect).filter(|index| *index < length)
            else {
                return Vec::new();
            };
            start
        };
        let end = if end.is_empty() {
            length - 1
        } else {
            let Some(end) = parse_index(end, length, dialect).filter(|index| *index < length)
            else {
                return Vec::new();
            };
            end
        };
        if start <= end {
            (start..=end.min(length - 1)).collect()
        } else {
            (end..=start.min(length - 1)).rev().collect()
        }
    } else {
        parse_index(expression, length, dialect)
            .filter(|index| *index < length)
            .into_iter()
            .collect()
    }
}

fn parse_index(expression: &str, length: usize, dialect: ScriptDialect) -> Option<usize> {
    let value = expression.trim().parse::<isize>().ok()?;
    if value < 0 {
        return usize::try_from(length as isize + value).ok();
    }
    let value = usize::try_from(value).ok()?;
    if dialect == ScriptDialect::Bash {
        Some(value)
    } else {
        value.checked_sub(1)
    }
}

fn echo_values(arguments: &[String]) -> Vec<String> {
    let mut index = 0;
    let mut escapes = false;
    while index < arguments.len() {
        let Some(flags) = arguments[index].strip_prefix('-').filter(|flags| {
            !flags.is_empty() && flags.chars().all(|flag| matches!(flag, 'e' | 'E' | 'n'))
        }) else {
            break;
        };
        for flag in flags.chars() {
            if flag == 'e' {
                escapes = true;
            } else if flag == 'E' {
                escapes = false;
            }
        }
        index += 1;
    }
    let value = arguments[index..].join(" ");
    let value = if escapes {
        decode_echo_escapes(&value)
    } else {
        value
    };
    value.lines().map(str::to_owned).collect()
}

fn run_simple_awk(program: &str, separator: Option<&str>, input: &[String]) -> Option<Vec<String>> {
    let rules = awk_rules(program);
    if rules.is_empty() {
        return None;
    }
    let mut output = Vec::new();
    for (line_index, line) in input.iter().enumerate() {
        let fields = if let Some(separator) = separator {
            line.split(separator).map(str::to_owned).collect::<Vec<_>>()
        } else {
            line.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        for (condition, action) in &rules {
            if awk_condition(condition, line, &fields, line_index + 1) {
                execute_simple_awk_action(action, line, &fields, line_index + 1, &mut output);
            }
        }
    }
    Some(output)
}

fn awk_rules(program: &str) -> Vec<(&str, &str)> {
    let mut rules = Vec::new();
    let mut cursor = 0;
    let bytes = program.as_bytes();
    while cursor < bytes.len() {
        let Some(relative_open) = program[cursor..].find('{') else {
            break;
        };
        let open = cursor + relative_open;
        let mut index = open + 1;
        let mut depth = 1_usize;
        let mut quote = None;
        let mut escaped = false;
        while index < bytes.len() && depth > 0 {
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
            } else if byte == b'{' {
                depth += 1;
            } else if byte == b'}' {
                depth -= 1;
            }
            index += 1;
        }
        if depth != 0 {
            break;
        }
        let condition = program[cursor..open].trim().trim_start_matches(';').trim();
        let action = &program[open + 1..index - 1];
        if !condition.starts_with("function ") && !matches!(condition, "BEGIN" | "END") {
            rules.push((condition, action));
        }
        cursor = index;
    }
    rules
}

fn awk_condition(condition: &str, line: &str, fields: &[String], line_number: usize) -> bool {
    awk_condition_at_depth(condition, line, fields, line_number, 0)
}

fn awk_condition_at_depth(
    condition: &str,
    line: &str,
    fields: &[String],
    line_number: usize,
    depth: usize,
) -> bool {
    if depth >= MAX_PATTERN_RECURSION {
        return false;
    }
    let condition = condition
        .trim()
        .trim_matches(|character| matches!(character, '(' | ')'));
    if condition.is_empty() || condition == "1" {
        return true;
    }
    if let Some(index) = find_awk_boolean(condition, "||") {
        return awk_condition_at_depth(&condition[..index], line, fields, line_number, depth + 1)
            || awk_condition_at_depth(
                &condition[index + 2..],
                line,
                fields,
                line_number,
                depth + 1,
            );
    }
    if let Some(index) = find_awk_boolean(condition, "&&") {
        return awk_condition_at_depth(&condition[..index], line, fields, line_number, depth + 1)
            && awk_condition_at_depth(
                &condition[index + 2..],
                line,
                fields,
                line_number,
                depth + 1,
            );
    }
    let (negated, condition) = condition
        .strip_prefix('!')
        .map_or((false, condition), |value| (true, value.trim_start()));
    if let Some(pattern) = condition
        .strip_prefix('/')
        .and_then(|value| value.rsplit_once('/').map(|(pattern, _)| pattern))
    {
        let matched = regex_input_is_bounded(line)
            && bounded_regex(pattern, false).is_some_and(|regex| regex.is_match(line));
        return matched != negated;
    }
    for operator in ["!~", "~", "!=", "==", ">=", "<=", ">", "<"] {
        if let Some((left, right)) = condition.split_once(operator) {
            let left = awk_scalar(left.trim(), line, fields, line_number);
            let right = right.trim();
            let result = match operator {
                "~" | "!~" => {
                    let pattern = right
                        .strip_prefix('/')
                        .and_then(|value| value.rsplit_once('/').map(|(pattern, _)| pattern))
                        .unwrap_or(right);
                    let matched = regex_input_is_bounded(&left)
                        && bounded_regex(pattern, false).is_some_and(|regex| regex.is_match(&left));
                    if operator == "!~" { !matched } else { matched }
                }
                "==" | "!=" => {
                    let right = awk_scalar(right, line, fields, line_number);
                    if operator == "!=" {
                        left != right
                    } else {
                        left == right
                    }
                }
                _ => {
                    let left = left.parse::<i64>().unwrap_or(0);
                    let right = awk_scalar(right, line, fields, line_number)
                        .parse::<i64>()
                        .unwrap_or(0);
                    match operator {
                        ">=" => left >= right,
                        "<=" => left <= right,
                        ">" => left > right,
                        _ => left < right,
                    }
                }
            };
            return result != negated;
        }
    }
    awk_scalar(condition, line, fields, line_number).is_empty() == negated
}

fn find_awk_boolean(condition: &str, operator: &str) -> Option<usize> {
    let bytes = condition.as_bytes();
    let mut quote = None;
    let mut regex = false;
    let mut escaped = false;
    let mut index = 0;
    while index + operator.len() <= bytes.len() {
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
        } else if byte == b'/' {
            regex = !regex;
        } else if !regex && condition[index..].starts_with(operator) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn awk_scalar(token: &str, line: &str, fields: &[String], line_number: usize) -> String {
    let token = token.trim();
    if token == "$0" {
        return line.to_owned();
    }
    if token == "$NF" {
        return fields.last().cloned().unwrap_or_default();
    }
    if token == "NR" {
        return line_number.to_string();
    }
    if token == "NF" {
        return fields.len().to_string();
    }
    if let Some(index) = token
        .strip_prefix('$')
        .and_then(|value| value.parse::<usize>().ok())
    {
        return index
            .checked_sub(1)
            .and_then(|index| fields.get(index))
            .cloned()
            .unwrap_or_default();
    }
    token
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            token
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .map_or_else(|| token.to_owned(), decode_echo_escapes)
}

fn execute_simple_awk_action(
    action: &str,
    line: &str,
    fields: &[String],
    line_number: usize,
    output: &mut Vec<String>,
) {
    for statement in split_sed_commands(action) {
        let mut statement = statement.trim();
        if let Some(rest) = statement.strip_prefix("if") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('(') {
                if let Some(close) = rest.find(')') {
                    if !awk_condition(&rest[..close], line, fields, line_number) {
                        continue;
                    }
                    statement = rest[close + 1..].trim();
                }
            }
        }
        if let Some(expression) = statement
            .strip_prefix("printf")
            .filter(|expression| expression.starts_with(char::is_whitespace))
        {
            let Some((format, operands)) = split_awk_printf(expression.trim()) else {
                continue;
            };
            let mut values = vec![format];
            values.extend(
                operands
                    .trim_start_matches([',', ' '])
                    .split(',')
                    .map(|token| awk_scalar(token, line, fields, line_number)),
            );
            output.extend(format_values(&values));
            continue;
        }
        let Some(expression) = statement.strip_prefix("print").filter(|expression| {
            expression.is_empty() || expression.starts_with(char::is_whitespace)
        }) else {
            continue;
        };
        let expression = expression.trim();
        if expression.is_empty() {
            output.push(line.to_owned());
            continue;
        }
        let values = expression
            .split(',')
            .map(|token| awk_scalar(token, line, fields, line_number))
            .collect::<Vec<_>>();
        output.push(values.join(" "));
    }
}

fn bash_builtin_options(topic: &str) -> Option<&'static str> {
    BASH_BUILTIN_OPTIONS.lines().find_map(|line| {
        let (name, options) = line.split_once('\t')?;
        (name == topic).then_some(options)
    })
}

fn bash_builtin_help(topic: &str) -> Option<String> {
    let options = bash_builtin_options(topic)?;
    let options = options.split_ascii_whitespace().collect::<Vec<_>>();
    if options.is_empty() {
        return Some(format!("{topic}: {topic}"));
    }
    let synopsis = options
        .iter()
        .map(|option| format!("[{option}]"))
        .collect::<Vec<_>>()
        .join(" ");
    let details = options
        .iter()
        .map(|option| format!("  {option}"))
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!("{topic}: {topic} {synopsis}\n{details}"))
}

fn bash_help_builtin(arguments: &[String]) -> CommandResult {
    let topics = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    if topics.is_empty() {
        return CommandResult::output(SHELL_HELP_TOPICS.lines().map(str::to_owned).collect());
    }
    let mut output = Vec::new();
    for topic in topics {
        let Some(help) = bash_builtin_help(topic) else {
            return CommandResult::status(1);
        };
        output.push(help);
    }
    CommandResult::output(output)
}

fn sed_builtin(arguments: &[String], input: &[String]) -> Result<CommandResult, VmError> {
    let mut quiet = false;
    let mut extended = false;
    let mut scripts = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            index += 1;
            if scripts.is_empty() && index < arguments.len() {
                scripts.push(arguments[index].clone());
            }
            break;
        }
        if let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            let mut consumed_script = false;
            for (flag_index, flag) in flags.char_indices() {
                match flag {
                    'n' => quiet = true,
                    'E' | 'r' => extended = true,
                    'e' => {
                        let attached = &flags[flag_index + flag.len_utf8()..];
                        if attached.is_empty() {
                            if let Some(script) = arguments.get(index + 1) {
                                scripts.push(script.clone());
                                index += 1;
                            }
                        } else {
                            scripts.push(attached.to_owned());
                        }
                        consumed_script = true;
                        break;
                    }
                    _ => {}
                }
            }
            index += 1;
            if consumed_script {
                continue;
            }
            continue;
        }
        if scripts.is_empty() {
            scripts.push(argument.clone());
        }
        index += 1;
    }
    if scripts.is_empty() {
        return Ok(CommandResult::status(2));
    }
    let commands = scripts
        .iter()
        .flat_map(|script| split_sed_commands(script))
        .collect::<Vec<_>>();
    let mut output = Vec::new();
    let mut range_states = vec![false; commands.len()];
    for (line_index, original) in input.iter().enumerate() {
        let line_number = line_index + 1;
        let mut line = original.clone();
        let mut deleted = false;
        let mut explicit = Vec::new();
        for (command_index, command) in commands.iter().enumerate() {
            let (applies, action) = sed_address(
                command.trim(),
                line_number,
                input.len(),
                &line,
                extended,
                &mut range_states[command_index],
            );
            if !applies || action.is_empty() {
                continue;
            }
            if action == "d" {
                deleted = true;
                break;
            }
            if action == "p" {
                explicit.extend(line.split('\n').map(str::to_owned));
                continue;
            }
            if let Some((pattern, replacement, flags)) = parse_sed_substitution(action) {
                let pattern = if extended {
                    pattern
                } else {
                    sed_bre_to_rust(&pattern)
                };
                let Some(expression) =
                    bounded_regex(&pattern, flags.contains('I') || flags.contains('i'))
                else {
                    return Ok(CommandResult::status(2));
                };
                let matched = regex_input_is_bounded(&line) && expression.is_match(&line);
                if matched {
                    let replacement = sed_replacement(&replacement);
                    line = if flags.contains('g') {
                        expression
                            .replace_all(&line, replacement.as_str())
                            .into_owned()
                    } else {
                        expression.replace(&line, replacement.as_str()).into_owned()
                    };
                    if flags.contains('p') {
                        explicit.extend(line.split('\n').map(str::to_owned));
                    }
                }
            }
        }
        output.extend(explicit);
        if !quiet && !deleted {
            output.extend(line.split('\n').map(str::to_owned));
        }
    }
    Ok(CommandResult::output(output))
}

fn split_sed_commands(script: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    let mut braces = 0_usize;
    for (index, character) in script.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            ';' if braces == 0 => {
                commands.push(&script[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    commands.push(&script[start..]);
    commands
}

#[derive(Clone)]
enum SedAddress {
    Line(usize),
    Last,
    Pattern(String),
}

fn parse_sed_address(input: &str) -> Option<(SedAddress, &str)> {
    if let Some(rest) = input.strip_prefix('$') {
        return Some((SedAddress::Last, rest));
    }
    let digits = input.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 {
        return Some((
            SedAddress::Line(input[..digits].parse().ok()?),
            &input[digits..],
        ));
    }
    let rest = input.strip_prefix('/')?;
    let (pattern, rest) = take_sed_delimited(rest, '/')?;
    Some((SedAddress::Pattern(pattern), rest))
}

fn sed_address_matches(
    address: &SedAddress,
    line_number: usize,
    line_count: usize,
    line: &str,
    extended: bool,
) -> bool {
    match address {
        SedAddress::Line(expected) => line_number == *expected,
        SedAddress::Last => line_number == line_count,
        SedAddress::Pattern(pattern) => {
            let pattern = if extended {
                pattern.clone()
            } else {
                sed_bre_to_rust(pattern)
            };
            regex_input_is_bounded(line)
                && bounded_regex(&pattern, false).is_some_and(|regex| regex.is_match(line))
        }
    }
}

fn sed_address<'a>(
    command: &'a str,
    line_number: usize,
    line_count: usize,
    line: &str,
    extended: bool,
    range_active: &mut bool,
) -> (bool, &'a str) {
    let command = command.trim();
    let Some((first, rest)) = parse_sed_address(command) else {
        return (true, command);
    };
    if let Some(rest) = rest.strip_prefix(',') {
        let Some((last, rest)) = parse_sed_address(rest) else {
            return (false, rest);
        };
        let was_active = *range_active;
        let mut applies =
            was_active || sed_address_matches(&first, line_number, line_count, line, extended);
        if applies {
            if was_active && sed_address_matches(&last, line_number, line_count, line, extended) {
                *range_active = false;
            } else if !was_active {
                *range_active = true;
                if !matches!(last, SedAddress::Pattern(_))
                    && sed_address_matches(&last, line_number, line_count, line, extended)
                {
                    *range_active = false;
                }
            }
        }
        if let Some(action) = rest.strip_prefix('!') {
            applies = !applies;
            return (applies, action);
        }
        return (applies, rest);
    }
    let mut applies = sed_address_matches(&first, line_number, line_count, line, extended);
    if let Some(action) = rest.strip_prefix('!') {
        applies = !applies;
        (applies, action)
    } else {
        (applies, rest)
    }
}

fn parse_sed_substitution(command: &str) -> Option<(String, String, String)> {
    let rest = command.strip_prefix('s')?;
    let delimiter = rest.chars().next()?;
    let rest = &rest[delimiter.len_utf8()..];
    let (pattern, rest) = take_sed_delimited(rest, delimiter)?;
    let (replacement, flags) =
        take_sed_delimited(rest, delimiter).unwrap_or_else(|| (rest.to_owned(), ""));
    Some((pattern, replacement, flags.to_owned()))
}

fn take_sed_delimited(input: &str, delimiter: char) -> Option<(String, &str)> {
    let mut output = String::new();
    let mut characters = input.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if character == delimiter {
            return Some((output, &input[index + character.len_utf8()..]));
        }
        if character == '\\' {
            if let Some((_, next)) = characters.peek().copied() {
                if next == delimiter {
                    characters.next();
                    output.push(delimiter);
                    continue;
                }
            }
        }
        output.push(character);
    }
    None
}

fn sed_bre_to_rust(pattern: &str) -> String {
    let mut output = String::with_capacity(pattern.len());
    let mut characters = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(character) = characters.next() {
        if character == '[' {
            in_class = true;
            output.push(character);
            continue;
        }
        if character == ']' && in_class {
            in_class = false;
            output.push(character);
            continue;
        }
        if character == '\\' {
            let Some(next) = characters.next() else {
                output.push('\\');
                break;
            };
            if !in_class && matches!(next, '(' | ')' | '{' | '}' | '+' | '?' | '|') {
                output.push(next);
            } else {
                output.push('\\');
                output.push(next);
            }
            continue;
        }
        if !in_class && matches!(character, '(' | ')' | '{' | '}' | '+' | '?' | '|') {
            output.push('\\');
        }
        output.push(character);
    }
    output
}

fn sed_replacement(replacement: &str) -> String {
    let mut output = String::with_capacity(replacement.len());
    let mut characters = replacement.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next() {
                Some(digit) if digit.is_ascii_digit() => {
                    output.push_str("${");
                    output.push(digit);
                    output.push('}');
                }
                Some('n') => output.push('\n'),
                Some('t') => output.push('\t'),
                Some(next) => output.push(next),
                None => output.push('\\'),
            }
        } else if character == '&' {
            output.push_str("${0}");
        } else if character == '$' {
            output.push_str("$$");
        } else {
            output.push(character);
        }
    }
    output
}

fn tr_character_set(value: &str) -> Vec<char> {
    let decoded = decode_echo_escapes(value);
    let characters = decoded.chars().collect::<Vec<_>>();
    let mut output = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        if index + 2 < characters.len()
            && characters[index + 1] == '-'
            && characters[index] <= characters[index + 2]
        {
            let start = characters[index] as u32;
            let end = characters[index + 2] as u32;
            output.extend((start..=end).filter_map(char::from_u32));
            index += 3;
        } else {
            output.push(characters[index]);
            index += 1;
        }
    }
    output
}

fn decode_echo_escapes(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            output.push('\\');
            break;
        };
        match escaped {
            'a' => output.push('\u{7}'),
            'b' => output.push('\u{8}'),
            'c' => break,
            'e' | 'E' => output.push('\u{1b}'),
            'f' => output.push('\u{c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{b}'),
            '\\' => output.push('\\'),
            'x' => {
                let mut digits = String::new();
                while digits.len() < 2
                    && characters
                        .peek()
                        .is_some_and(|character| character.is_ascii_hexdigit())
                {
                    digits.push(characters.next().unwrap_or_default());
                }
                if let Ok(byte) = u8::from_str_radix(&digits, 16) {
                    output.push(byte as char);
                }
            }
            other => {
                output.push('\\');
                output.push(other);
            }
        }
    }
    output
}

fn sequence_values(arguments: &[String]) -> Vec<String> {
    let mut operands = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        if matches!(
            arguments[index].as_str(),
            "-f" | "--format" | "-s" | "--separator"
        ) {
            index += 2;
        } else if arguments[index].starts_with('-') && arguments[index].parse::<i64>().is_err() {
            index += 1;
        } else {
            operands.push(arguments[index].parse::<i64>().unwrap_or(0));
            index += 1;
        }
    }
    let (start, step, end) = match operands.as_slice() {
        [end] => (1, 1, *end),
        [start, end] => (*start, 1, *end),
        [start, step, end, ..] => (*start, *step, *end),
        _ => return Vec::new(),
    };
    if step == 0 || start < end && step < 0 || start > end && step > 0 {
        return Vec::new();
    }
    let mut output = Vec::new();
    let mut value = start;
    while output.len() < MAX_VALUES && if step > 0 { value <= end } else { value >= end } {
        output.push(value.to_string());
        let Some(next) = value.checked_add(step) else {
            break;
        };
        value = next;
    }
    output
}

fn split_top_level(value: &str, delimiter: char) -> Vec<&str> {
    let mut output = Vec::new();
    let mut depth = 0_i32;
    let mut escaped = false;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ if character == delimiter && depth == 0 => {
                output.push(&value[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    output.push(&value[start..]);
    output
}

fn fish_complete_request_line(arguments: &[String], context_words: &[String]) -> Option<String> {
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "-C" || argument == "--do-complete" {
            return Some(
                arguments
                    .get(index + 1)
                    .cloned()
                    .unwrap_or_else(|| context_words.join(" ")),
            );
        }
        if let Some(line) = argument.strip_prefix("-C").filter(|line| !line.is_empty()) {
            return Some(line.to_owned());
        }
        if let Some(line) = argument.strip_prefix("--do-complete=") {
            return Some(line.to_owned());
        }
    }
    None
}

fn normalize_fish_complete_arguments(arguments: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if !argument.starts_with('-') || argument == "-" {
            normalized.push(argument.clone());
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            normalized.push(argument.clone());
            let takes_next = !argument.contains('=')
                && matches!(
                    argument.as_str(),
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
                if let Some(value) = arguments.get(index + 1) {
                    normalized.push(value.clone());
                }
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if argument.len() == 2 {
            normalized.push(argument.clone());
            let takes_next = argument.chars().nth(1).is_some_and(|character| {
                matches!(
                    character,
                    'c' | 'p' | 's' | 'l' | 'o' | 'a' | 'd' | 'n' | 'w'
                )
            });
            if takes_next {
                if let Some(value) = arguments.get(index + 1) {
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
            normalized.push(format!("-{character}"));
            if matches!(
                character,
                'c' | 'p' | 's' | 'l' | 'o' | 'a' | 'd' | 'n' | 'w'
            ) {
                let value_start = byte_index + character.len_utf8();
                if value_start < body.len() {
                    normalized.push(body[value_start..].to_owned());
                } else if let Some(value) = arguments.get(index + 1) {
                    normalized.push(value.clone());
                    consumed_next = true;
                }
                break;
            }
            if character == 'C' {
                let value_start = byte_index + character.len_utf8();
                if value_start < body.len() {
                    normalized.push(body[value_start..].to_owned());
                }
                break;
            }
        }
        index += 1 + usize::from(consumed_next);
    }
    normalized
}

fn word_contains_command_substitution(word: &ScriptWord) -> bool {
    word.parts.iter().any(|part| match part {
        ScriptWordPart::CommandSubstitution { .. } => true,
        ScriptWordPart::BraceExpansion { alternatives, .. } => {
            alternatives.iter().any(word_contains_command_substitution)
        }
        ScriptWordPart::Array { elements } => {
            elements.iter().any(word_contains_command_substitution)
        }
        ScriptWordPart::DeferredScript { words, .. } => {
            words.iter().any(word_contains_command_substitution)
        }
        _ => false,
    })
}

fn word_allows_pathname_expansion(word: &ScriptWord, dialect: ScriptDialect) -> bool {
    word.parts
        .iter()
        .enumerate()
        .any(|(index, part)| match part {
            ScriptWordPart::Literal { value, quoted } => {
                if *quoted || !has_shell_glob(dialect, value) {
                    return false;
                }
                let parameter_slice = index > 0
                    && value.starts_with('[')
                    && value.ends_with(']')
                    && matches!(
                        &word.parts[index - 1],
                        ScriptWordPart::Parameter { .. }
                            | ScriptWordPart::CommandSubstitution { .. }
                    );
                !parameter_slice
            }
            ScriptWordPart::BraceExpansion {
                alternatives,
                quoted,
            } => {
                !quoted
                    && alternatives
                        .iter()
                        .any(|word| word_allows_pathname_expansion(word, dialect))
            }
            ScriptWordPart::Array { elements } => elements
                .iter()
                .any(|word| word_allows_pathname_expansion(word, dialect)),
            ScriptWordPart::Parameter { .. }
            | ScriptWordPart::CommandSubstitution { .. }
            | ScriptWordPart::Arithmetic { .. }
            | ScriptWordPart::DeferredScript { .. } => false,
        })
}

fn has_shell_glob(dialect: ScriptDialect, value: &str) -> bool {
    let characters = value.char_indices().collect::<Vec<_>>();
    let mut escaped = false;
    for (position, (_, character)) in characters.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '*' || dialect != ScriptDialect::Fish && character == '?' {
            return true;
        } else if dialect != ScriptDialect::Fish && character == '[' {
            let mut class_escaped = false;
            if characters[position + 1..].iter().any(|(_, candidate)| {
                if class_escaped {
                    class_escaped = false;
                    return false;
                }
                if *candidate == '\\' {
                    class_escaped = true;
                    return false;
                }
                *candidate == ']'
            }) {
                return true;
            }
        }
    }
    false
}

fn fish_completion_has_glob(value: &str) -> bool {
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '*' {
            return true;
        }
    }
    false
}

fn fish_file_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left_chars.len() && right_index < right_chars.len() {
        let left_character = left_chars[left_index];
        let right_character = right_chars[right_index];
        if left_character.is_ascii_digit() && right_character.is_ascii_digit() {
            let left_end = left_index
                + left_chars[left_index..]
                    .iter()
                    .take_while(|character| character.is_ascii_digit())
                    .count();
            let right_end = right_index
                + right_chars[right_index..]
                    .iter()
                    .take_while(|character| character.is_ascii_digit())
                    .count();
            let left_digits = &left_chars[left_index..left_end];
            let right_digits = &right_chars[right_index..right_end];
            let left_significant = left_digits
                .iter()
                .position(|character| *character != '0')
                .unwrap_or(left_digits.len());
            let right_significant = right_digits
                .iter()
                .position(|character| *character != '0')
                .unwrap_or(right_digits.len());
            let ordering = left_digits[left_significant..]
                .len()
                .cmp(&right_digits[right_significant..].len())
                .then_with(|| {
                    left_digits[left_significant..].cmp(&right_digits[right_significant..])
                });
            if ordering != Ordering::Equal {
                return ordering;
            }
            left_index = left_end;
            right_index = right_end;
            continue;
        }
        if left_character == right_character {
            left_index += 1;
            right_index += 1;
            continue;
        }
        let transform = |character: char| match character {
            '-' => '[',
            '/' => '\0',
            other => other.to_uppercase().next().unwrap_or(other),
        };
        let ordering = transform(left_character).cmp(&transform(right_character));
        if ordering != Ordering::Equal {
            return ordering;
        }
        left_index += 1;
        right_index += 1;
    }
    left_chars
        .len()
        .cmp(&right_chars.len())
        .then_with(|| left.cmp(right))
}

fn zsh_quote_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '_' || character == '-' || character == '.' || character.is_alphanumeric() {
            output.push(character);
        } else {
            output.push('\\');
            output.push(character);
        }
    }
    output
}

fn unescape_shell_literal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            if let Some(next) = characters.next() {
                output.push(next);
            }
        } else {
            output.push(character);
        }
    }
    output
}

fn word_has_unquoted_path_glob(word: &ScriptWord, dialect: ScriptDialect) -> bool {
    word.parts.iter().any(|part| match part {
        ScriptWordPart::Literal { value, quoted } => {
            !quoted && value.contains('/') && has_shell_glob(dialect, value)
        }
        ScriptWordPart::BraceExpansion {
            alternatives,
            quoted,
        } => {
            !quoted
                && alternatives
                    .iter()
                    .any(|word| word_has_unquoted_path_glob(word, dialect))
        }
        ScriptWordPart::Array { elements } => elements
            .iter()
            .any(|word| word_has_unquoted_path_glob(word, dialect)),
        ScriptWordPart::Parameter { .. }
        | ScriptWordPart::CommandSubstitution { .. }
        | ScriptWordPart::Arithmetic { .. }
        | ScriptWordPart::DeferredScript { .. } => false,
    })
}

fn split_fish_completion_words(value: &str) -> Vec<String> {
    const DESCRIPTION_SEPARATOR: char = '\u{1f}';
    let encoded = value.replace("\\t", &DESCRIPTION_SEPARATOR.to_string());
    split_shell_words(&encoded)
        .into_iter()
        .flat_map(|word| expand_braces(&word))
        .map(|word| word.replace(DESCRIPTION_SEPARATOR, "\t"))
        .collect()
}

fn split_shell_fields(value: &str, separators: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            started = true;
        } else if character == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                current.push(character);
            }
            started = true;
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
            started = true;
        } else if separators.contains(character) {
            if started {
                words.push(std::mem::take(&mut current));
                started = false;
            }
        } else {
            current.push(character);
            started = true;
        }
    }
    if started {
        words.push(current);
    }
    words
}

fn split_zsh_scalar_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn split_shell_words(value: &str) -> Vec<String> {
    split_shell_fields(value, " \t\n")
}

fn zsh_argument_specifications(arguments: &[String]) -> Vec<String> {
    let mut specifications = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if matches!(argument, "-A" | "-M" | "-O") {
            index = (index + 2).min(arguments.len());
        } else if argument.starts_with("-A")
            || argument.starts_with("-M")
            || argument.starts_with("-O")
            || matches!(
                argument,
                "-0" | "-C" | "-R" | "-S" | "-W" | "-n" | "-s" | "-w"
            )
        {
            index += 1;
        } else if argument == ":" {
            specifications.extend_from_slice(&arguments[index + 1..]);
            break;
        } else if argument == "--" {
            index += 1;
        } else {
            specifications.extend(
                arguments[index..]
                    .iter()
                    .filter(|specification| specification.as_str() != "--")
                    .cloned(),
            );
            break;
        }
    }
    specifications
}

fn split_zsh_colons(value: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = String::new();
    let mut depth = 0_i32;
    let mut escaped = false;
    let mut quote = None;
    for character in value.chars() {
        if escaped {
            if character != ':' {
                current.push('\\');
            }
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            current.push(character);
            if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' if depth == 0 => {
                quote = Some(character);
                current.push(character);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(character);
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(character);
            }
            ':' if depth == 0 => {
                output.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }
    if escaped {
        current.push('\\');
    }
    output.push(current);
    output
}

fn zsh_spec_exclusions(specification: &str) -> Vec<String> {
    let specification = specification.trim_start_matches(['!', '*']);
    if !specification.starts_with('(') {
        return Vec::new();
    }
    let Some(close) = matching_ascii(specification, '(', ')') else {
        return Vec::new();
    };
    specification[1..close]
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn zsh_word_contains_option(word: &str, option: &str) -> bool {
    let option = option.trim_start_matches('*').trim_end_matches(['+', '-']);
    if option.len() <= 1 {
        return false;
    }
    if option.starts_with("--") || option.starts_with("++") {
        return word == option
            || word
                .strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='));
    }
    let Some(prefix) = option.chars().next() else {
        return false;
    };
    if !matches!(prefix, '-' | '+') || word.starts_with("--") || word.starts_with("++") {
        return word == option;
    }
    let Some(flag) = option.chars().nth(1) else {
        return false;
    };
    word.starts_with(prefix) && word[1..].chars().any(|character| character == flag)
}

fn push_zsh_tag(
    tags: &mut Vec<String>,
    seen: &mut HashSet<String>,
    bytes: &mut usize,
    value: &str,
) -> bool {
    if seen.contains(value) {
        return true;
    }
    if tags.len() >= MAX_ZSH_TAG_STATE_ITEMS
        || bytes.saturating_add(value.len()) > MAX_ZSH_TAG_STATE_BYTES
    {
        return false;
    }
    let value = value.to_owned();
    *bytes = bytes.saturating_add(value.len());
    seen.insert(value.clone());
    tags.push(value);
    true
}

fn zsh_completion_group_options(arguments: &[String]) -> (usize, Vec<String>) {
    let mut index = 0_usize;
    let mut presentation = Vec::new();
    while index < arguments.len() {
        let option = arguments[index].as_str();
        if !option.starts_with('-') {
            break;
        }
        if option == "--" || option == "-" {
            index += 1;
            continue;
        }
        if option == "-C" {
            index = index.saturating_add(2).min(arguments.len());
            continue;
        }
        if option.starts_with("-C") {
            index += 1;
            continue;
        }
        if matches!(option, "-J" | "-V" | "-X" | "-x" | "-M" | "-F") {
            presentation.push(arguments[index].clone());
            if let Some(value) = arguments.get(index + 1) {
                presentation.push(value.clone());
            }
            index = index.saturating_add(2).min(arguments.len());
            continue;
        }
        if matches!(option, "-1" | "-2")
            || option.starts_with("-J")
            || option.starts_with("-V")
            || option.starts_with("-X")
            || option.starts_with("-x")
        {
            presentation.push(arguments[index].clone());
        }
        index += 1;
    }
    (index, presentation)
}

fn zsh_label_presentation(
    options: &[String],
    _description: &str,
    trailing: &[String],
    trailing_first: bool,
) -> Vec<String> {
    let mut values = Vec::with_capacity(options.len().saturating_add(trailing.len()));
    if trailing_first {
        values.extend_from_slice(trailing);
    }
    values.extend_from_slice(options);
    if !trailing_first {
        values.extend_from_slice(trailing);
    }
    values
}

fn zsh_option_specification(value: &str) -> bool {
    if value.len() <= 1 || value.starts_with('-') {
        return value.len() > 1 && value.starts_with('-');
    }
    if !value.starts_with('+') {
        return false;
    }
    !value.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
        || value
            .find('[')
            .is_some_and(|open| value.find(':').is_none_or(|colon| open < colon))
}

fn zsh_spec_options(specification: &str) -> Vec<String> {
    let mut value = specification;
    if value.starts_with("(-)--[") {
        return Vec::new();
    }
    while value.starts_with(['*', '+']) && value.get(1..2) == Some("-") {
        value = &value[1..];
    }
    if value.starts_with('(') {
        if let Some(close) = matching_ascii(value, '(', ')') {
            value = &value[close + 1..];
        }
    }
    while value.starts_with('*')
        || value.starts_with('+') && matches!(value.get(1..2), Some("-" | "{"))
    {
        value = &value[1..];
    }
    let mut escaped = false;
    let mut depth = 0_i32;
    let mut end = value.len();
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '[' | ':' if depth == 0 => {
                end = index;
                break;
            }
            _ => {}
        }
    }
    let expression = unescape_shell_literal(&value[..end]);
    if expression == "+" && !specification.contains('[') {
        return Vec::new();
    }
    let options = if expression.starts_with('{') && expression.ends_with('}') {
        expression[1..expression.len() - 1]
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        vec![expression]
    };
    options
        .into_iter()
        .flat_map(|option| {
            option.strip_prefix("-+").map_or_else(
                || vec![option.clone()],
                |suffix| vec![format!("+{suffix}"), format!("-{suffix}")],
            )
        })
        .collect()
}

fn zsh_spec_description(specification: &str) -> Option<String> {
    let open = specification.find('[')?;
    let mut escaped = false;
    let mut depth = 0_usize;
    for character in specification[..open].chars() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '(' | '{') {
            depth += 1;
        } else if matches!(character, ')' | '}') {
            depth = depth.saturating_sub(1);
        } else if character == ':' && depth == 0 {
            return None;
        }
    }
    let close = open + matching_unquoted_ascii(&specification[open..], '[', ']')?;
    let raw_description = &specification[open + 1..close];
    Some(unescape_shell_literal(raw_description))
}

fn zsh_option_action(specification: &str) -> Option<(String, String)> {
    let fields = split_zsh_colons(specification);
    if fields.len() >= 4 && matches!(fields[1].as_str(), "*" | "+") {
        return Some((fields[2].clone(), fields[3..].join(":")));
    }
    if fields.len() >= 3 {
        return Some((
            fields.get(1).cloned().unwrap_or_default(),
            fields[2..].join(":"),
        ));
    }
    if fields.len() == 2 {
        return zsh_spec_description(specification)
            .map(|description| (description, fields[1].clone()));
    }
    None
}

#[derive(Clone, Debug)]
struct ZshRegexFirstAction {
    description: String,
    action: String,
    setups: Vec<String>,
}

#[derive(Default)]
struct ZshRegexFirst {
    actions: Vec<ZshRegexFirstAction>,
    nullable: bool,
    setups: Vec<String>,
}

fn zsh_parenthesized_action_all_options(action: &str) -> bool {
    let body = action.trim().trim_start_matches('(').trim_end_matches(')');
    let values = split_shell_words(body);
    !values.is_empty()
        && values.iter().all(|value| {
            value
                .split_once(':')
                .map_or(value.as_str(), |(name, _)| name)
                .starts_with('-')
        })
}

fn zsh_regex_first_actions(arguments: &[String]) -> Vec<ZshRegexFirstAction> {
    let nul_pattern = arguments.iter().take(16).position(|argument| {
        argument.starts_with('/') && (argument.contains("\\0") || argument.contains('\0'))
    });
    let start = if nul_pattern == Some(0) {
        1
    } else if nul_pattern.is_some() && arguments.first().map(String::as_str) == Some("(") {
        let mut depth = 0usize;
        arguments
            .iter()
            .enumerate()
            .find_map(|(index, token)| {
                depth += usize::from(token == "(");
                depth = depth.saturating_sub(usize::from(token == ")"));
                (depth == 0).then_some(index + 1)
            })
            .unwrap_or(0)
    } else {
        0
    };
    let mut index = start;
    zsh_regex_first_alternatives(arguments, &mut index, false, 0).actions
}

fn zsh_regex_first_alternatives(
    arguments: &[String],
    index: &mut usize,
    stop_at_close: bool,
    depth: usize,
) -> ZshRegexFirst {
    let mut result = ZshRegexFirst::default();
    loop {
        let alternative = zsh_regex_first_sequence(arguments, index, stop_at_close, depth);
        result.actions.extend(alternative.actions);
        if !result.nullable && alternative.nullable {
            result.nullable = true;
            result.setups = alternative.setups;
        }
        if arguments.get(*index).map(String::as_str) == Some("|") {
            *index += 1;
        } else {
            break;
        }
    }
    result
}

fn zsh_regex_first_sequence(
    arguments: &[String],
    index: &mut usize,
    stop_at_close: bool,
    depth: usize,
) -> ZshRegexFirst {
    let mut result = ZshRegexFirst {
        actions: Vec::new(),
        nullable: true,
        setups: Vec::new(),
    };
    while let Some(token) = arguments.get(*index).map(String::as_str) {
        if token == "|" || stop_at_close && token == ")" {
            break;
        }
        let mut element = zsh_regex_first_element(arguments, index, depth);
        if result.nullable {
            for action in &mut element.actions {
                let mut setups = result.setups.clone();
                setups.append(&mut action.setups);
                action.setups = setups;
            }
            result.actions.extend(element.actions);
            if element.nullable {
                result.setups.extend(element.setups);
            }
        }
        result.nullable &= element.nullable;
    }
    result
}

fn zsh_regex_first_element(arguments: &[String], index: &mut usize, depth: usize) -> ZshRegexFirst {
    if depth >= MAX_PATTERN_RECURSION {
        *index = (*index).saturating_add(1).min(arguments.len());
        return ZshRegexFirst::default();
    }
    let Some(token) = arguments.get(*index).map(String::as_str) else {
        return ZshRegexFirst::default();
    };
    if token == "(" {
        *index += 1;
        let mut group = zsh_regex_first_alternatives(arguments, index, true, depth + 1);
        if arguments.get(*index).map(String::as_str) == Some(")") {
            *index += 1;
        }
        if arguments.get(*index).map(String::as_str) == Some("#") {
            *index += 1;
            group.nullable = true;
            group.setups.clear();
        }
        return group;
    }
    if token == ")" {
        *index += 1;
        return ZshRegexFirst {
            actions: Vec::new(),
            nullable: true,
            setups: Vec::new(),
        };
    }
    if token.starts_with('/') && token.ends_with('/') {
        let mut result = ZshRegexFirst {
            actions: Vec::new(),
            nullable: zsh_regex_pattern_nullable(token),
            setups: Vec::new(),
        };
        *index += 1;
        while let Some(follower) = arguments.get(*index).map(String::as_str) {
            if matches!(follower, "(" | ")" | "|")
                || follower.starts_with('/') && follower.ends_with('/')
            {
                break;
            }
            if follower == "#" {
                result.nullable = true;
                result.setups.clear();
                *index += 1;
                break;
            }
            let fields = split_zsh_colons(follower);
            if fields.len() >= 4 {
                result.actions.push(ZshRegexFirstAction {
                    description: fields.get(2).cloned().unwrap_or_default(),
                    action: fields[3..].join(":"),
                    setups: result.setups.clone(),
                });
            } else if follower.starts_with('-') {
                result.setups.push(follower.to_owned());
            }
            *index += 1;
        }
        return result;
    }
    *index += 1;
    ZshRegexFirst {
        actions: Vec::new(),
        nullable: true,
        setups: Vec::new(),
    }
}

fn zsh_regex_pattern_nullable(pattern: &str) -> bool {
    fn branch_nullable(branch: &[u8], depth: usize) -> bool {
        if depth >= MAX_PATTERN_RECURSION {
            return false;
        }
        let mut index = 0usize;
        while index < branch.len() {
            let atom_nullable;
            match branch[index] {
                b'\\' => {
                    atom_nullable = false;
                    index = (index + 2).min(branch.len());
                }
                b'[' => {
                    atom_nullable = false;
                    index += 1;
                    while index < branch.len() {
                        if branch[index] == b'\\' {
                            index = (index + 2).min(branch.len());
                        } else {
                            let close = branch[index] == b']';
                            index += 1;
                            if close {
                                break;
                            }
                        }
                    }
                }
                b'(' => {
                    let mut depth = 1usize;
                    let start = index + 1;
                    index += 1;
                    while index < branch.len() && depth > 0 {
                        if branch[index] == b'\\' {
                            index = (index + 2).min(branch.len());
                            continue;
                        }
                        depth += usize::from(branch[index] == b'(');
                        depth = depth.saturating_sub(usize::from(branch[index] == b')'));
                        index += 1;
                    }
                    let end = index.saturating_sub(1).max(start);
                    atom_nullable = regex_expression_nullable(&branch[start..end], depth + 1);
                }
                b'^' => {
                    atom_nullable = index == 0;
                    index += 1;
                }
                b'$' => {
                    atom_nullable = false;
                    index += 1;
                }
                _ => {
                    atom_nullable = false;
                    index += 1;
                }
            }
            let optional = branch.get(index) == Some(&b'#') && branch.get(index + 1) != Some(&b'#');
            if branch.get(index) == Some(&b'#') {
                index += 1 + usize::from(branch.get(index + 1) == Some(&b'#'));
            }
            if !atom_nullable && !optional {
                return false;
            }
        }
        true
    }

    fn regex_expression_nullable(expression: &[u8], recursion_depth: usize) -> bool {
        if recursion_depth >= MAX_PATTERN_RECURSION {
            return false;
        }
        let mut depth = 0usize;
        let mut class = false;
        let mut escaped = false;
        let mut start = 0usize;
        for (index, byte) in expression.iter().copied().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
            } else if class {
                class = byte != b']';
            } else if byte == b'[' {
                class = true;
            } else if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth = depth.saturating_sub(1);
            } else if byte == b'|' && depth == 0 {
                if branch_nullable(&expression[start..index], recursion_depth + 1) {
                    return true;
                }
                start = index + 1;
            }
        }
        branch_nullable(&expression[start..], recursion_depth + 1)
    }

    let body = pattern
        .strip_prefix('/')
        .and_then(|pattern| pattern.strip_suffix('/'))
        .unwrap_or(pattern);
    !body.is_empty() && regex_expression_nullable(body.as_bytes(), 0) || body.is_empty()
}

fn deferred_source_matches(source: &str, action: &str) -> bool {
    source == action
        || source
            .strip_suffix(action)
            .and_then(|prefix| prefix.chars().next_back())
            .is_some_and(|character| character == ':' || character.is_whitespace())
}

fn zsh_compadd_display_description(display: &str, value: &str) -> Option<String> {
    let remainder = display.strip_prefix(value)?.trim_start();
    let description = remainder
        .strip_prefix("--")
        .unwrap_or(remainder)
        .trim_start();
    (!description.is_empty()).then(|| description.to_owned())
}

fn zsh_described_value(item: &str) -> (String, Option<String>) {
    // `(q)`/`(@qq)` add a shell-escaping layer which native Zsh removes
    // before completion utilities inspect the `value:description` record.
    let unquoted;
    let item = if unescaped_colon(item).is_none() && item.contains("\\:") {
        unquoted = unescape_shell_literal(item);
        unquoted.as_str()
    } else {
        item
    };
    if let Some(open) = item.find('[') {
        if let Some(relative_close) = item[open + 1..].find(']') {
            return (
                unescape_shell_literal(&item[..open]),
                Some(unescape_shell_literal(
                    &item[open + 1..open + 1 + relative_close],
                )),
            );
        }
    }
    if let Some(separator) = unescaped_colon(item) {
        return (
            unescape_shell_literal(&item[..separator]),
            Some(unescape_shell_literal(&item[separator + 1..])),
        );
    }
    (unescape_shell_literal(item), None)
}

fn unescaped_colon(value: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            return Some(index);
        }
    }
    None
}

fn zsh_describe_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "-F" | "-J" | "-M" | "-O" | "-V" | "-X" | "-x" | "-r" | "-t"
    )
}

fn expand_braces(value: &str) -> Vec<String> {
    expand_braces_at_depth(value, 0)
}

fn expand_braces_at_depth(value: &str, depth: usize) -> Vec<String> {
    if depth >= MAX_PATTERN_RECURSION || value.len() > MAX_VALUE_BYTES {
        return Vec::new();
    }
    let Some(open) = value.find('{') else {
        return vec![value.to_owned()];
    };
    let Some(relative_close) = matching_ascii(&value[open..], '{', '}') else {
        return vec![value.to_owned()];
    };
    let close = open + relative_close;
    let body = &value[open + 1..close];
    let alternatives = if let Some((start, end)) = body.split_once("..") {
        match (start.parse::<i64>(), end.parse::<i64>()) {
            (Ok(start), Ok(end)) if (start - end).unsigned_abs() <= 4096 => {
                if start <= end {
                    (start..=end)
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                } else {
                    (end..=start).rev().map(|value| value.to_string()).collect()
                }
            }
            _ => split_top_level(body, ',')
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    } else {
        split_top_level(body, ',')
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    if alternatives.len() < 2 {
        return vec![value.to_owned()];
    }
    alternatives
        .into_iter()
        .flat_map(|alternative| {
            expand_braces_at_depth(
                &format!("{}{}{}", &value[..open], alternative, &value[close + 1..]),
                depth + 1,
            )
        })
        .take(MAX_VALUES)
        .collect()
}

fn eval_test_expression(
    arguments: &[String],
    variables: &HashMap<String, Variable>,
    dialect: ScriptDialect,
) -> bool {
    eval_test_expression_at_depth(arguments, variables, dialect, 0)
}

fn eval_test_expression_at_depth(
    arguments: &[String],
    variables: &HashMap<String, Variable>,
    dialect: ScriptDialect,
    depth: usize,
) -> bool {
    if depth >= MAX_PATTERN_RECURSION || arguments.is_empty() {
        return false;
    }
    if arguments.first().map(String::as_str) == Some("(")
        && arguments.last().map(String::as_str) == Some(")")
        && matching_test_parenthesis(arguments, 0) == Some(arguments.len() - 1)
    {
        return eval_test_expression_at_depth(
            &arguments[1..arguments.len() - 1],
            variables,
            dialect,
            depth + 1,
        );
    }
    if let Some(index) = top_level_test_operator(arguments, &["||", "-o"]) {
        return eval_test_expression_at_depth(&arguments[..index], variables, dialect, depth + 1)
            || eval_test_expression_at_depth(
                &arguments[index + 1..],
                variables,
                dialect,
                depth + 1,
            );
    }
    if let Some(index) = top_level_test_operator(arguments, &["&&", "-a"]) {
        return eval_test_expression_at_depth(&arguments[..index], variables, dialect, depth + 1)
            && eval_test_expression_at_depth(
                &arguments[index + 1..],
                variables,
                dialect,
                depth + 1,
            );
    }
    if arguments[0] == "!" {
        return !eval_test_expression_at_depth(&arguments[1..], variables, dialect, depth + 1);
    }
    if arguments.len() > 3
        && matches!(arguments[1].as_str(), "=" | "==" | "!=")
        && arguments[2] == "("
    {
        let pattern = arguments[2..].join("");
        let matches = shell_pattern_dialect(dialect, &pattern, &arguments[0]);
        return if arguments[1] == "!=" {
            !matches
        } else {
            matches
        };
    }
    match arguments {
        [operator, value] if operator == "-n" => !value.is_empty(),
        [operator, value] if operator == "-z" => value.is_empty(),
        [operator, value] if operator == "-v" => variables.contains_key(value),
        [operator, _] if matches!(operator.as_str(), "-e" | "-f" | "-d" | "-r" | "-w" | "-x") => {
            false
        }
        [left, operator, right] if matches!(operator.as_str(), "=" | "==") => {
            shell_pattern_dialect(dialect, right, left)
        }
        [left, operator, right] if operator == "=~" => simple_regex_match(right, left),
        [left, operator, right] if operator == "!=" => !shell_pattern_dialect(dialect, right, left),
        [left, operator, right]
            if matches!(
                operator.as_str(),
                "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge"
            ) =>
        {
            let numeric_value = |value: &str| {
                value.parse::<i64>().unwrap_or_else(|_| {
                    variables
                        .get(value)
                        .and_then(|variable| variable.values.first())
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                })
            };
            let left = numeric_value(left);
            let right = numeric_value(right);
            match operator.as_str() {
                "-eq" => left == right,
                "-ne" => left != right,
                "-lt" => left < right,
                "-le" => left <= right,
                "-gt" => left > right,
                _ => left >= right,
            }
        }
        [value] => !value.is_empty(),
        _ => false,
    }
}

fn matching_test_parenthesis(arguments: &[String], start: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, argument) in arguments.iter().enumerate().skip(start) {
        match argument.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn top_level_test_operator(arguments: &[String], operators: &[&str]) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, argument) in arguments.iter().enumerate() {
        match argument.as_str() {
            "(" => depth += 1,
            ")" => depth = depth.saturating_sub(1),
            _ if depth == 0
                && index > 0
                && index + 1 < arguments.len()
                && operators.contains(&argument.as_str()) =>
            {
                return Some(index);
            }
            _ => {}
        }
    }
    None
}

fn regex_input_is_bounded(value: &str) -> bool {
    value.len() <= MAX_VALUE_BYTES
}

fn bounded_regex(pattern: &str, case_insensitive: bool) -> Option<regex::Regex> {
    bounded_regex_with_limit(pattern, case_insensitive, 2 * 1024 * 1024)
}

fn bounded_regex_with_limit(
    pattern: &str,
    case_insensitive: bool,
    size_limit: usize,
) -> Option<regex::Regex> {
    if pattern.len() > 64 * 1024 {
        return None;
    }
    let mut builder = regex::RegexBuilder::new(pattern);
    builder
        .case_insensitive(case_insensitive)
        .size_limit(size_limit)
        .dfa_size_limit(size_limit);
    builder.build().ok()
}

struct BoundedFishRegex {
    expression: regex::Regex,
    leading_exclusion: Option<(regex::Regex, regex::Regex)>,
}

impl BoundedFishRegex {
    fn is_match(&self, value: &str) -> bool {
        regex_input_is_bounded(value) && self.allowed(value) && self.expression.is_match(value)
    }

    fn replace(&self, value: &str, replacement: &str, all: bool) -> String {
        if !regex_input_is_bounded(value)
            || replacement.len() > MAX_VALUE_BYTES
            || !self.allowed(value)
        {
            return value.to_owned();
        }
        if all {
            self.expression.replace_all(value, replacement).into_owned()
        } else {
            self.expression.replace(value, replacement).into_owned()
        }
    }

    fn allowed(&self, value: &str) -> bool {
        let Some((prefix, exclusion)) = &self.leading_exclusion else {
            return true;
        };
        prefix
            .find(value)
            .is_some_and(|matched| !exclusion.is_match(&value[matched.end()..]))
    }
}

fn bounded_fish_regex(pattern: &str, case_insensitive: bool) -> Option<BoundedFishRegex> {
    if let Some(expression) = bounded_regex(pattern, case_insensitive) {
        return Some(BoundedFishRegex {
            expression,
            leading_exclusion: None,
        });
    }
    let marker = pattern.find("(?!")?;
    let prefix = &pattern[..marker];
    if !prefix.starts_with('^') {
        return None;
    }
    let close = marker + matching_ascii(&pattern[marker..], '(', ')')?;
    let mut exclusion = &pattern[marker + 3..close];
    if exclusion.starts_with("(?:")
        && matching_ascii(exclusion, '(', ')') == exclusion.len().checked_sub(1)
    {
        exclusion = &exclusion[3..exclusion.len() - 1];
    }
    if exclusion.contains(['(', ')']) {
        return None;
    }
    let positive = format!("{}{}", prefix, &pattern[close + 1..]);
    // This compatibility form compiles three bounded automata. Capping each at
    // 512 KiB keeps their aggregate compiled and DFA budgets below 2 MiB.
    let expression = bounded_regex_with_limit(&positive, case_insensitive, 512 * 1024)?;
    let prefix = bounded_regex_with_limit(prefix, case_insensitive, 512 * 1024)?;
    let exclusion =
        bounded_regex_with_limit(&format!("^(?:{exclusion})"), case_insensitive, 512 * 1024)?;
    Some(BoundedFishRegex {
        expression,
        leading_exclusion: Some((prefix, exclusion)),
    })
}

pub(crate) fn normalize_bash_ere(pattern: &str) -> String {
    let characters = pattern.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    let mut in_class = false;
    let mut in_posix_class = false;
    while index < characters.len() {
        let character = characters[index];
        if character == '\\' && index + 1 < characters.len() {
            output.push(character);
            output.push(characters[index + 1]);
            index += 2;
            continue;
        }
        if !in_class && character == '[' {
            in_class = true;
            output.push(character);
        } else if in_class && !in_posix_class && character == '[' {
            if characters.get(index + 1) == Some(&':') {
                in_posix_class = true;
                output.push(character);
            } else {
                output.push_str("\\[");
            }
        } else if in_class
            && in_posix_class
            && character == ':'
            && characters.get(index + 1) == Some(&']')
        {
            output.push(':');
            output.push(']');
            in_posix_class = false;
            index += 2;
            continue;
        } else if in_class && !in_posix_class && character == ']' {
            in_class = false;
            output.push(character);
        } else {
            output.push(character);
        }
        index += 1;
    }
    output
}

fn escape_shell_pattern_literal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '*' | '?' | '[' | ']' | '(' | ')' | '|' | '+' | '@' | '!'
        ) {
            output.push('\\');
        }
        output.push(character);
    }
    output
}

fn shell_pattern_dialect(dialect: ScriptDialect, pattern: &str, value: &str) -> bool {
    shell_pattern_dialect_at_depth(dialect, pattern, value, 0)
}

fn shell_pattern_dialect_at_depth(
    dialect: ScriptDialect,
    pattern: &str,
    value: &str,
    depth: usize,
) -> bool {
    if depth >= MAX_PATTERN_RECURSION
        || !regex_input_is_bounded(value)
        || pattern.len() > MAX_VALUE_BYTES
    {
        return false;
    }
    if dialect == ScriptDialect::Zsh {
        let case_insensitive = pattern.contains("(#i)");
        let normalized = pattern
            .replace("(#s)", "")
            .replace("(#e)", "")
            .replace("(#i)", "");
        if let Some(open) = normalized.find("(^") {
            if let Some(relative_close) = matching_ascii(&normalized[open..], '(', ')') {
                let close = open + relative_close;
                let prefix = &normalized[..open];
                let excluded = &normalized[open + 2..close];
                let suffix = &normalized[close + 1..];
                let mut boundaries = value
                    .char_indices()
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                boundaries.push(value.len());
                if boundaries.len() <= 257 {
                    for start in boundaries.iter().copied() {
                        if !shell_pattern_dialect_at_depth(
                            ScriptDialect::Zsh,
                            prefix,
                            &value[..start],
                            depth + 1,
                        ) {
                            continue;
                        }
                        for end in boundaries.iter().copied().filter(|end| *end >= start) {
                            if shell_pattern_dialect_at_depth(
                                ScriptDialect::Zsh,
                                suffix,
                                &value[end..],
                                depth + 1,
                            ) && !shell_pattern_dialect_at_depth(
                                ScriptDialect::Zsh,
                                excluded,
                                &value[start..end],
                                depth + 1,
                            ) {
                                return true;
                            }
                        }
                    }
                    return false;
                }
            }
        }
        let exclusions = split_zsh_pattern_exclusions(&normalized);
        if exclusions.len() > 1 {
            let included = if exclusions[0].is_empty() {
                "*"
            } else {
                exclusions[0]
            };
            return shell_pattern_dialect_at_depth(ScriptDialect::Zsh, included, value, depth + 1)
                && exclusions[1..].iter().all(|excluded| {
                    !shell_pattern_dialect_at_depth(ScriptDialect::Zsh, excluded, value, depth + 1)
                });
        }
        let complement = if normalized.starts_with("(^")
            && normalized.ends_with(')')
            && matching_ascii(&normalized, '(', ')') == normalized.len().checked_sub(1)
        {
            Some(&normalized[2..normalized.len() - 1])
        } else {
            normalized.strip_prefix('^')
        };
        if let Some(complement) = complement {
            return !shell_pattern_dialect_at_depth(
                ScriptDialect::Zsh,
                complement,
                value,
                depth + 1,
            );
        }
        if case_insensitive {
            let normalized = normalized.to_lowercase();
            let value = value.to_lowercase();
            return zsh_registration_or_alternation_match(&normalized, &value);
        }
        return zsh_registration_or_alternation_match(&normalized, value);
    }
    shell_pattern(pattern, value)
}

fn zsh_registration_or_alternation_match(pattern: &str, value: &str) -> bool {
    let alternatives = split_top_level(pattern, '|');
    if alternatives.len() > 1 {
        return alternatives
            .iter()
            .any(|alternative| registration_matches(ScriptDialect::Zsh, alternative, value));
    }
    registration_matches(ScriptDialect::Zsh, pattern, value)
}

fn shell_pattern(pattern: &str, value: &str) -> bool {
    if !regex_input_is_bounded(value) || pattern.len() > MAX_VALUE_BYTES {
        return false;
    }
    let pattern = pattern.trim_matches(|character| matches!(character, '\'' | '"'));
    if let Some(expression) = shell_pattern_regex(pattern) {
        if let Some(expression) = bounded_regex(&format!("^(?:{expression})$"), false) {
            return expression.is_match(value);
        }
    }
    let alternatives = split_pattern_alternatives(pattern);
    alternatives
        .iter()
        .any(|pattern| wildcard_match(pattern.as_bytes(), value.as_bytes()))
}

fn shell_pattern_regex(pattern: &str) -> Option<String> {
    fn sequence(pattern: &str, index: &mut usize, nested: bool, depth: usize) -> Option<String> {
        if depth >= MAX_PATTERN_RECURSION {
            return None;
        }
        let bytes = pattern.as_bytes();
        let mut output = String::new();
        while *index < bytes.len() {
            if nested && bytes[*index] == b')' {
                break;
            }
            if bytes[*index] == b'|' {
                output.push('|');
                *index += 1;
                continue;
            }
            if *index + 1 < bytes.len()
                && matches!(bytes[*index], b'?' | b'*' | b'+' | b'@' | b'!')
                && bytes[*index + 1] == b'('
            {
                let operator = bytes[*index];
                if operator == b'!' {
                    return None;
                }
                *index += 2;
                let inner = sequence(pattern, index, true, depth + 1)?;
                if bytes.get(*index) != Some(&b')') {
                    return None;
                }
                *index += 1;
                output.push_str("(?:");
                output.push_str(&inner);
                output.push(')');
                match operator {
                    b'?' => output.push('?'),
                    b'*' => output.push('*'),
                    b'+' => output.push('+'),
                    b'@' => {}
                    _ => return None,
                }
                continue;
            }
            match bytes[*index] {
                b'*' => {
                    output.push_str(".*");
                    *index += 1;
                }
                b'?' => {
                    output.push('.');
                    *index += 1;
                }
                b'[' => {
                    let close = if pattern[*index..].starts_with("[[:") {
                        pattern[*index + 3..]
                            .find(":]]")
                            .map(|relative| *index + 3 + relative + 2)
                    } else {
                        pattern[*index + 1..]
                            .find(']')
                            .map(|relative| *index + 1 + relative)
                    }?;
                    let mut class = pattern[*index..=close].to_owned();
                    if class.starts_with("[!") {
                        class.replace_range(1..2, "^");
                    }
                    output.push_str(&class);
                    *index = close + 1;
                    if bytes.get(*index) == Some(&b'#') {
                        *index += 1;
                        if bytes.get(*index) == Some(&b'#') {
                            output.push('+');
                            *index += 1;
                        } else {
                            output.push('*');
                        }
                    }
                }
                b'\\' if *index + 1 < bytes.len() => {
                    let start = *index + 1;
                    let character = pattern[start..].chars().next()?;
                    output.push_str(&regex::escape(&character.to_string()));
                    *index = start + character.len_utf8();
                }
                _ => {
                    let character = pattern[*index..].chars().next()?;
                    output.push_str(&regex::escape(&character.to_string()));
                    *index += character.len_utf8();
                }
            }
        }
        Some(output)
    }

    let mut index = 0;
    let expression = sequence(pattern, &mut index, false, 0)?;
    (index == pattern.len()).then_some(expression)
}

fn split_zsh_pattern_exclusions(pattern: &str) -> Vec<&str> {
    let mut output = Vec::new();
    let mut depth = 0_i32;
    let mut escaped = false;
    let mut start = 0;
    for (index, character) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '~' if depth == 0 => {
                output.push(&pattern[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    output.push(&pattern[start..]);
    output
}

fn split_pattern_alternatives(pattern: &str) -> Vec<String> {
    let mut pattern = pattern.to_owned();
    for prefix in ["@(", "+(", "?(", "*("] {
        if pattern.starts_with(prefix) && pattern.ends_with(')') {
            pattern = pattern[prefix.len()..pattern.len() - 1].to_owned();
            break;
        }
    }
    split_top_level(&pattern, '|')
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.len().saturating_mul(value.len().max(1)) > 1_000_000 {
        return false;
    }
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let byte = pattern[index];
        let mut next = vec![false; value.len() + 1];
        match byte {
            b'*' => {
                next[0] = row[0];
                for position in 1..=value.len() {
                    next[position] = row[position] || next[position - 1];
                }
            }
            b'?' => next[1..].copy_from_slice(&row[..value.len()]),
            b'[' => {
                let close = pattern[index + 1..]
                    .iter()
                    .position(|candidate| *candidate == b']')
                    .map(|offset| index + 1 + offset);
                if let Some(close) = close {
                    let class = &pattern[index + 1..close];
                    for position in 1..=value.len() {
                        next[position] =
                            row[position - 1] && class_match(class, value[position - 1]);
                    }
                    index = close;
                } else {
                    for position in 1..=value.len() {
                        next[position] = row[position - 1] && value[position - 1] == b'[';
                    }
                }
            }
            b'\\' if index + 1 < pattern.len() => {
                index += 1;
                for position in 1..=value.len() {
                    next[position] = row[position - 1] && value[position - 1] == pattern[index];
                }
            }
            _ => {
                for position in 1..=value.len() {
                    next[position] = row[position - 1] && value[position - 1] == byte;
                }
            }
        }
        row = next;
        index += 1;
    }
    row[value.len()]
}

fn class_match(class: &[u8], value: u8) -> bool {
    let (invert, class) = if class
        .first()
        .is_some_and(|value| matches!(value, b'!' | b'^'))
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
    matched != invert
}

fn simple_regex_match(pattern: &str, value: &str) -> bool {
    if !regex_input_is_bounded(value) || pattern.len() > MAX_VALUE_BYTES {
        return false;
    }
    let mut pattern = pattern.trim_matches(|character| matches!(character, '\'' | '"'));
    if let Some(expression) = bounded_regex(&normalize_bash_ere(pattern), false) {
        return expression.is_match(value);
    }
    let anchored_start = pattern.starts_with('^');
    let anchored_end = pattern.ends_with('$');
    pattern = pattern.trim_start_matches('^').trim_end_matches('$');
    let pattern = pattern.replace(".*", "*").replace('.', "?");
    if anchored_start && anchored_end {
        wildcard_match(pattern.as_bytes(), value.as_bytes())
    } else if anchored_start {
        value
            .char_indices()
            .map(|(index, _)| &value[..index])
            .chain(std::iter::once(value))
            .any(|prefix| wildcard_match(pattern.as_bytes(), prefix.as_bytes()))
    } else {
        value.contains(pattern.trim_matches('*'))
    }
}

fn inline_parameter_end(bytes: &[u8], start: usize) -> usize {
    if bytes
        .get(start)
        .is_some_and(|byte| matches!(byte, b'@' | b'*' | b'#' | b'?' | b'!' | b'$' | b'-'))
    {
        return start + 1;
    }
    let mut end = start;
    while end < bytes.len() && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric()) {
        end += 1;
    }
    end
}

fn push_escaped_pattern_character(output: &mut String, character: char) {
    if matches!(
        character,
        '*' | '?' | '[' | ']' | '(' | ')' | '|' | '+' | '@' | '!' | '#' | '\\'
    ) {
        output.push('\\');
    }
    output.push(character);
}

fn remove_prefix_pattern(value: &str, pattern: &str, longest: bool) -> String {
    let indices = value
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(value.len()));
    let indices: Box<dyn Iterator<Item = usize>> = if longest {
        Box::new(indices.rev())
    } else {
        Box::new(indices)
    };
    for index in indices {
        if shell_pattern(pattern, &value[..index]) {
            return value[index..].to_owned();
        }
    }
    value.to_owned()
}

fn remove_suffix_pattern(value: &str, pattern: &str, longest: bool) -> String {
    let indices = value
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(value.len()));
    let indices: Box<dyn Iterator<Item = usize>> = if longest {
        Box::new(indices)
    } else {
        Box::new(indices.rev())
    };
    for index in indices {
        if shell_pattern(pattern, &value[index..]) {
            return value[..index].to_owned();
        }
    }
    value.to_owned()
}

fn matching_unquoted_ascii(value: &str, open: char, close: char) -> Option<usize> {
    let mut opened = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == open {
            opened = true;
        } else if character == close && opened {
            return Some(index);
        }
    }
    None
}

fn matching_ascii(value: &str, open: char, close: char) -> Option<usize> {
    let mut depth = 0;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == open {
            depth += 1;
        } else if character == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn split_awk_printf(expression: &str) -> Option<(String, &str)> {
    let expression = expression.trim_start();
    let first = expression.chars().next()?;
    if matches!(first, '\'' | '"') {
        let mut escaped = false;
        for (index, character) in expression.char_indices().skip(1) {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == first {
                return Some((expression[1..index].to_owned(), &expression[index + 1..]));
            }
        }
        return None;
    }
    let end = expression
        .find(char::is_whitespace)
        .unwrap_or(expression.len());
    Some((
        expression[..end].trim_end_matches(',').to_owned(),
        &expression[end..],
    ))
}

fn shell_printf_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric()
            || matches!(
                character,
                '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
            )
        {
            output.push(character);
        } else if character.is_control() {
            output.push_str("$'");
            for escaped in character.escape_default() {
                output.push(escaped);
            }
            output.push('\'');
        } else {
            output.push('\\');
            output.push(character);
        }
    }
    output
}

fn printf_format_arity(format: &str) -> usize {
    let mut arity = 0_usize;
    let mut characters = format.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '%' {
            continue;
        }
        if characters.peek() == Some(&'%') {
            characters.next();
            continue;
        }
        if characters
            .by_ref()
            .any(|character| character.is_ascii_alphabetic() || character == 'q')
        {
            arity = arity.saturating_add(1);
        }
    }
    arity
}

fn format_values(arguments: &[String]) -> Vec<String> {
    let Some((format, values)) = arguments.split_first() else {
        return Vec::new();
    };
    let mut output = String::new();
    let mut value_index = 0;
    loop {
        let before = value_index;
        let mut characters = format.chars().peekable();
        while let Some(character) = characters.next() {
            if character == '%' {
                if characters.peek() == Some(&'%') {
                    characters.next();
                    output.push('%');
                    continue;
                }
                let mut conversion = None;
                for next in characters.by_ref() {
                    if next.is_ascii_alphabetic() || next == 'q' {
                        conversion = Some(next);
                        break;
                    }
                }
                match conversion {
                    Some('s' | 'd' | 'i' | 'u') => {
                        output.push_str(values.get(value_index).map_or("", String::as_str));
                        value_index = value_index.saturating_add(1);
                    }
                    Some('q') => {
                        output.push_str(&shell_printf_quote(
                            values.get(value_index).map_or("", String::as_str),
                        ));
                        value_index = value_index.saturating_add(1);
                    }
                    Some('b') => {
                        output.push_str(&decode_echo_escapes(
                            values.get(value_index).map_or("", String::as_str),
                        ));
                        value_index = value_index.saturating_add(1);
                    }
                    Some(other) => {
                        output.push('%');
                        output.push(other);
                    }
                    None => output.push('%'),
                }
            } else if character == '\\' {
                match characters.next() {
                    Some('n') => output.push('\n'),
                    Some('t') => output.push('\t'),
                    Some('0') => output.push('\0'),
                    Some(other) => output.push(other),
                    None => output.push('\\'),
                }
            } else {
                output.push(character);
            }
        }
        if value_index == before || value_index >= values.len() {
            break;
        }
    }
    output
        .split(['\n', '\0'])
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn zsh_compadd_option_taking_next(value: &str) -> Option<char> {
    let mut options = value.strip_prefix('-')?.chars().peekable();
    while let Some(option) = options.next() {
        if matches!(
            option,
            'a' | 'A'
                | 'd'
                | 'e'
                | 'F'
                | 'J'
                | 'K'
                | 'M'
                | 'O'
                | 'P'
                | 'r'
                | 'R'
                | 'S'
                | 'V'
                | 'W'
                | 'X'
                | 'x'
        ) {
            return options.peek().is_none().then_some(option);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        Arithmetic, bounded_fish_regex, bounded_regex, expand_braces, shell_pattern_dialect,
        zsh_hash_scan_indices, zsh_regex_first_actions,
    };
    use crate::rules::script::ScriptDialect;
    use std::collections::HashMap;

    #[test]
    fn zsh_runtime_patterns_support_bare_alternation() {
        assert!(shell_pattern_dialect(
            ScriptDialect::Zsh,
            "alpha|beta|gamma",
            "beta",
        ));
        assert!(!shell_pattern_dialect(
            ScriptDialect::Zsh,
            "alpha|beta|gamma",
            "delta",
        ));
    }

    #[test]
    fn runtime_regexes_reject_oversized_patterns_and_inputs() {
        assert!(bounded_regex(&"a".repeat(64 * 1024 + 1), false).is_none());
        let expression = bounded_fish_regex(".*", false).unwrap();
        assert!(!expression.is_match(&"a".repeat(1024 * 1024 + 1)));
    }

    #[test]
    fn hostile_arithmetic_nesting_and_operator_chains_are_stack_bounded() {
        let mut variables = HashMap::new();
        let chain = format!("{}1", "1+".repeat(100_000));
        let _ = Arithmetic::new(&chain, &mut variables).evaluate();
        let nested = format!("{}1{}", "(".repeat(10_000), ")".repeat(10_000));
        let _ = Arithmetic::new(&nested, &mut variables).evaluate();
    }

    #[test]
    fn hostile_zsh_pattern_and_regex_first_nesting_are_stack_bounded() {
        let complement = format!("{}literal", "^".repeat(10_000));
        assert!(!shell_pattern_dialect(
            ScriptDialect::Zsh,
            &complement,
            "value",
        ));
        let mut arguments = vec!["(".to_owned(); 10_000];
        arguments.push("/x/".into());
        arguments.push("value:values:value:(x)".into());
        arguments.extend(std::iter::repeat_n(")".to_owned(), 10_000));
        let _ = zsh_regex_first_actions(&arguments);
    }

    #[test]
    fn zsh_function_hash_scan_replays_resize_chain_order() {
        let mut owned = vec![
            vec!["_E".to_owned(), String::new()],
            vec!["_a".to_owned(), String::new()],
        ];
        owned.extend((0..12).map(|index| vec![format!("_f{index}"), String::new()]));
        let entries = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let order = zsh_hash_scan_indices(&entries, 7, 7);
        let e = order.iter().position(|index| *index == 0).unwrap();
        let a = order.iter().position(|index| *index == 1).unwrap();
        assert!(e < a);

        let survivors = &entries[..13];
        assert_ne!(
            zsh_hash_scan_indices(survivors, 7, 7),
            zsh_hash_scan_indices(survivors, 7, 28),
            "a removed function must not shrink away native resize history"
        );
    }

    #[test]
    fn nested_zsh_brace_lists_expand_empty_and_nested_alternatives() {
        let values = expand_braces(
            "allow.{set_hostname,mount{,.devfs,.tmpfs},unprivileged_{parent_tampering,proc_debug}}",
        );
        assert_eq!(
            values,
            [
                "allow.set_hostname",
                "allow.mount",
                "allow.mount.devfs",
                "allow.mount.tmpfs",
                "allow.unprivileged_parent_tampering",
                "allow.unprivileged_proc_debug",
            ]
        );
        assert_eq!(
            expand_braces("allow.{set_hostname,sysvipc,raw_sockets,chflags,mount{,.devfs,.fdescfs,.fusefs,.nullfs,.procfs,.linprocfs,.linsysfs,.tmpfs,.zfs},vmm,quotas,read_msgbuf,socket_af,mlock,nfsd,reserved_ports,unprivileged_{parent_tampering,proc_debug},suser,extattr,adjtime,settime,routing,setaudit}").len(),
            29,
        );
    }
}

fn stable_probe_hash(key: &ProbeKey) -> u64 {
    struct StableHasher(u64);

    impl Hasher for StableHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(0x100000001b3);
            }
        }
    }

    let mut hasher = StableHasher(0xcbf29ce484222325);
    key.hash(&mut hasher);
    hasher.finish()
}

fn forbidden_executable(value: &str) -> bool {
    value.is_empty()
        || value.contains('/')
        || value.contains('\0')
        || matches!(value, "sh" | "bash" | "dash" | "zsh" | "fish")
}

fn zsh_hash_scan_indices(
    entries: &[&[String]],
    initial_size: usize,
    minimum_size: usize,
) -> Vec<usize> {
    fn hash(value: &str) -> u32 {
        value.as_bytes().iter().fold(0_u32, |hash, byte| {
            hash.wrapping_add(hash.wrapping_shl(5).wrapping_add(u32::from(*byte)))
        })
    }

    let mut buckets = vec![Vec::<usize>::new(); initial_size];
    let mut count = 0_usize;
    let resize = |buckets: &mut Vec<Vec<usize>>| {
        let new_size = buckets.len() * 4;
        let old = std::mem::replace(buckets, vec![Vec::new(); new_size]);
        for index in old.into_iter().flatten() {
            let bucket = hash(&entries[index][0]) as usize % buckets.len();
            buckets[bucket].insert(0, index);
        }
    };
    for (index, entry) in entries.iter().enumerate() {
        let bucket = hash(&entry[0]) as usize % buckets.len();
        buckets[bucket].insert(0, index);
        count += 1;
        if count >= buckets.len() * 2 {
            resize(&mut buckets);
        }
    }
    while buckets.len() < minimum_size {
        resize(&mut buckets);
    }
    buckets.into_iter().flatten().collect()
}

fn zsh_associative_scan_indices(entries: &[&[String]]) -> Vec<usize> {
    zsh_hash_scan_indices(entries, 17, 17)
}

fn zsh_function_scan_indices(entries: &[&[String]], table_size: usize) -> Vec<usize> {
    fn hash(value: &str) -> u32 {
        value.as_bytes().iter().fold(0_u32, |hash, byte| {
            hash.wrapping_add(hash.wrapping_shl(5).wrapping_add(u32::from(*byte)))
        })
    }

    let mut indices = (0..entries.len()).collect::<Vec<_>>();
    indices.sort_by(|left, right| {
        let left_bucket = hash(&entries[*left][0]) as usize % table_size;
        let right_bucket = hash(&entries[*right][0]) as usize % table_size;
        left_bucket.cmp(&right_bucket).then_with(|| right.cmp(left))
    });
    indices
}

fn zsh_parameter_uses_rc_expansion(expression: &str) -> bool {
    let mut expression = expression.trim();
    while expression.starts_with('(') {
        let Some(close) = expression.find(')') else {
            return false;
        };
        expression = &expression[close + 1..];
    }
    expression.starts_with('^')
}

fn zsh_parameter_flag_argument(flags: &str, flag: char) -> Option<String> {
    let start = flags.find(flag)? + flag.len_utf8();
    let delimiter = flags[start..].chars().next()?;
    if delimiter.is_ascii_alphanumeric() || delimiter.is_ascii_whitespace() {
        return None;
    }
    let value_start = start + delimiter.len_utf8();
    let end = flags[value_start..].find(delimiter)?;
    Some(flags[value_start..value_start + end].to_owned())
}

fn zsh_simple_modifiers(rest: &str) -> bool {
    !rest.is_empty()
        && rest.len() % 2 == 0
        && rest.as_bytes().chunks_exact(2).all(|pair| {
            pair[0] == b':' && matches!(pair[1], b'e' | b'h' | b'l' | b'q' | b'r' | b't' | b'u')
        })
}

fn apply_zsh_simple_modifiers(mut value: String, modifiers: &str) -> String {
    for pair in modifiers.as_bytes().chunks_exact(2) {
        value = match pair[1] {
            b'l' => value.to_lowercase(),
            b'u' => value.to_uppercase(),
            b't' => value.rsplit('/').next().unwrap_or(&value).to_owned(),
            b'h' => value
                .rsplit_once('/')
                .map_or_else(|| ".".into(), |(head, _)| head.to_owned()),
            b'r' => {
                let (directory, basename) = value
                    .rsplit_once('/')
                    .map_or(("", value.as_str()), |(directory, basename)| {
                        (directory, basename)
                    });
                let stem = basename.rsplit_once('.').map_or(basename, |(stem, _)| stem);
                if directory.is_empty() {
                    stem.to_owned()
                } else {
                    format!("{directory}/{stem}")
                }
            }
            b'e' => value
                .rsplit_once('.')
                .map_or_else(String::new, |(_, extension)| extension.to_owned()),
            b'q' => shell_printf_quote(&value),
            _ => value,
        };
    }
    value
}

fn shell_substring(value: &str, start: i64, length: Option<usize>) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let start = if start < 0 {
        (characters.len() as i64 + start).max(0) as usize
    } else {
        start as usize
    };
    characters
        .into_iter()
        .skip(start)
        .take(length.unwrap_or(usize::MAX))
        .collect()
}

fn substring(value: &str, start: isize, length: Option<usize>) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let start = if start < 0 {
        (characters.len() as isize + start).max(0) as usize
    } else {
        start.saturating_sub(1) as usize
    };
    characters
        .into_iter()
        .skip(start)
        .take(length.unwrap_or(usize::MAX))
        .collect()
}

struct Arithmetic<'a> {
    tokens: Vec<ArithmeticToken>,
    position: usize,
    variables: &'a mut HashMap<String, Variable>,
}

#[derive(Clone, Debug, PartialEq)]
enum ArithmeticToken {
    Number(i64),
    Name(String),
    Operator(String),
    Left,
    Right,
}

impl<'a> Arithmetic<'a> {
    fn new(expression: &str, variables: &'a mut HashMap<String, Variable>) -> Self {
        Self {
            tokens: arithmetic_tokens(expression),
            position: 0,
            variables,
        }
    }

    fn evaluate(&mut self) -> i64 {
        // Handle the assignment and increment forms used by shell loops before
        // entering the precedence parser.
        if self.tokens.len() >= 2 {
            if let ArithmeticToken::Name(name) = &self.tokens[0] {
                let name = name.clone();
                if self.tokens.get(1) == Some(&ArithmeticToken::Operator("++".into())) {
                    let value = self.value_of(&name).saturating_add(1);
                    self.assign(&name, value);
                    return value;
                }
                if self.tokens.get(1) == Some(&ArithmeticToken::Operator("--".into())) {
                    let value = self.value_of(&name).saturating_sub(1);
                    self.assign(&name, value);
                    return value;
                }
                if let Some(ArithmeticToken::Operator(operator)) = self.tokens.get(1).cloned() {
                    if matches!(operator.as_str(), "=" | "+=" | "-=" | "*=" | "/=") {
                        self.position = 2;
                        let right = self.expression(0, 0);
                        let left = self.value_of(&name);
                        let value = match operator.as_str() {
                            "+=" => left.saturating_add(right),
                            "-=" => left.saturating_sub(right),
                            "*=" => left.saturating_mul(right),
                            "/=" if right != 0 => left.checked_div(right).unwrap_or(i64::MAX),
                            _ => right,
                        };
                        self.assign(&name, value);
                        return value;
                    }
                }
            }
        }
        self.expression(0, 0)
    }

    fn expression(&mut self, minimum: u8, depth: usize) -> i64 {
        if depth >= MAX_ARITHMETIC_DEPTH {
            return 0;
        }
        let mut left = self.prefix(depth + 1);
        while let Some(ArithmeticToken::Operator(operator)) = self.tokens.get(self.position) {
            let precedence = arithmetic_precedence(operator);
            if precedence < minimum || precedence == 0 {
                break;
            }
            let operator = operator.clone();
            self.position += 1;
            let right = self.expression(precedence + 1, depth + 1);
            left = match operator.as_str() {
                "||" => i64::from(left != 0 || right != 0),
                "&&" => i64::from(left != 0 && right != 0),
                "==" => i64::from(left == right),
                "!=" => i64::from(left != right),
                "<" => i64::from(left < right),
                "<=" => i64::from(left <= right),
                ">" => i64::from(left > right),
                ">=" => i64::from(left >= right),
                "+" => left.saturating_add(right),
                "-" => left.saturating_sub(right),
                "*" => left.saturating_mul(right),
                "/" if right != 0 => left.checked_div(right).unwrap_or(i64::MAX),
                "%" if right != 0 => left.checked_rem(right).unwrap_or(0),
                "<<" => left.wrapping_shl(right as u32),
                ">>" => left.wrapping_shr(right as u32),
                "&" => left & right,
                "|" => left | right,
                "^" => left ^ right,
                _ => 0,
            };
        }
        left
    }

    fn prefix(&mut self, depth: usize) -> i64 {
        if depth >= MAX_ARITHMETIC_DEPTH {
            return 0;
        }
        let token = self.tokens.get(self.position).cloned();
        self.position += usize::from(token.is_some());
        match token {
            Some(ArithmeticToken::Number(value)) => value,
            Some(ArithmeticToken::Name(name)) => self.value_of(&name),
            Some(ArithmeticToken::Operator(operator))
                if matches!(operator.as_str(), "++" | "--") =>
            {
                if let Some(ArithmeticToken::Name(name)) = self.tokens.get(self.position).cloned() {
                    self.position += 1;
                    let value = if operator == "++" {
                        self.value_of(&name).saturating_add(1)
                    } else {
                        self.value_of(&name).saturating_sub(1)
                    };
                    self.assign(&name, value);
                    value
                } else {
                    0
                }
            }
            Some(ArithmeticToken::Operator(operator)) if operator == "!" => {
                i64::from(self.prefix(depth + 1) == 0)
            }
            Some(ArithmeticToken::Operator(operator)) if operator == "-" => {
                self.prefix(depth + 1).saturating_neg()
            }
            Some(ArithmeticToken::Operator(operator)) if operator == "+" => self.prefix(depth + 1),
            Some(ArithmeticToken::Left) => {
                let value = self.expression(0, depth + 1);
                if self.tokens.get(self.position) == Some(&ArithmeticToken::Right) {
                    self.position += 1;
                }
                value
            }
            _ => 0,
        }
    }

    fn value_of(&self, name: &str) -> i64 {
        let (name, index) = split_variable_reference(name.trim_start_matches('$'));
        self.variables
            .get(name)
            .and_then(|variable| variable.values.get(index.unwrap_or(0) as usize))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }

    fn assign(&mut self, name: &str, value: i64) {
        self.variables.insert(
            name.trim_start_matches('$').to_owned(),
            Variable {
                values: vec![value.to_string()],
                exported: false,
                readonly: false,
                array: false,
                associative: false,
            },
        );
    }
}

fn arithmetic_tokens(expression: &str) -> Vec<ArithmeticToken> {
    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() && tokens.len() < MAX_ARITHMETIC_TOKENS {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index].is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
                index += 1;
            }
            let raw = &expression[start..index];
            let value = if let Some(value) = raw.strip_prefix("0x") {
                i64::from_str_radix(value, 16).unwrap_or(0)
            } else {
                raw.parse().unwrap_or(0)
            };
            tokens.push(ArithmeticToken::Number(value));
        } else if bytes[index] == b'_' || bytes[index] == b'$' || bytes[index].is_ascii_alphabetic()
        {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
            {
                index += 1;
            }
            if bytes.get(index) == Some(&b'[') {
                while index < bytes.len() && bytes[index] != b']' {
                    index += 1;
                }
                index += usize::from(index < bytes.len());
            }
            tokens.push(ArithmeticToken::Name(expression[start..index].to_owned()));
        } else if bytes[index] == b'(' {
            tokens.push(ArithmeticToken::Left);
            index += 1;
        } else if bytes[index] == b')' {
            tokens.push(ArithmeticToken::Right);
            index += 1;
        } else {
            let operator = [
                "++", "--", "&&", "||", "==", "!=", "<=", ">=", "<<", ">>", "+=", "-=", "*=", "/=",
            ]
            .into_iter()
            .find(|operator| expression[index..].starts_with(operator))
            .map_or_else(|| expression[index..index + 1].to_owned(), str::to_owned);
            index += operator.len();
            tokens.push(ArithmeticToken::Operator(operator));
        }
    }
    tokens
}

fn arithmetic_precedence(operator: &str) -> u8 {
    match operator {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | "<=" | ">" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => 0,
    }
}

fn bash_compgen_variable_name(name: &str) -> bool {
    !matches!(name, "@" | "*" | "argv" | "_result" | "OPTARG")
        && !name.bytes().all(|byte| byte.is_ascii_digit())
        && !name.starts_with("__bashlume")
}

pub(crate) fn fish_builtin_available(name: &str) -> bool {
    FISH_BUILTIN_NAMES.contains(&name)
}

pub(crate) fn emulated_external_command(name: &str) -> bool {
    matches!(
        name,
        "awk"
            | "basename"
            | "cat"
            | "cut"
            | "dirname"
            | "grep"
            | "head"
            | "sed"
            | "seq"
            | "sort"
            | "tail"
            | "tr"
            | "uniq"
    )
}

const FISH_BUILTIN_NAMES: &[&str] = &[
    "!",
    ".",
    ":",
    "[",
    "_",
    "abbr",
    "and",
    "argparse",
    "begin",
    "bg",
    "bind",
    "block",
    "break",
    "breakpoint",
    "builtin",
    "case",
    "cd",
    "command",
    "commandline",
    "complete",
    "contains",
    "continue",
    "count",
    "disown",
    "echo",
    "else",
    "emit",
    "end",
    "eval",
    "exec",
    "exit",
    "false",
    "fg",
    "fish_indent",
    "fish_key_reader",
    "for",
    "function",
    "functions",
    "history",
    "if",
    "jobs",
    "math",
    "not",
    "or",
    "path",
    "printf",
    "pwd",
    "random",
    "read",
    "realpath",
    "return",
    "set",
    "set_color",
    "source",
    "status",
    "string",
    "switch",
    "test",
    "time",
    "true",
    "type",
    "ulimit",
    "wait",
    "while",
];

const FISH_COLOR_NAMES: &[&str] = &[
    "black",
    "blue",
    "brblack",
    "brblue",
    "brcyan",
    "brgreen",
    "brmagenta",
    "brred",
    "brwhite",
    "bryellow",
    "cyan",
    "green",
    "magenta",
    "red",
    "white",
    "yellow",
    "normal",
];

pub(super) const LINUX_SIGNAL_NAMES: &[&str] = &[
    "HUP",
    "INT",
    "QUIT",
    "ILL",
    "TRAP",
    "ABRT",
    "IOT",
    "BUS",
    "FPE",
    "KILL",
    "USR1",
    "SEGV",
    "USR2",
    "PIPE",
    "ALRM",
    "TERM",
    "STKFLT",
    "CHLD",
    "CLD",
    "CONT",
    "STOP",
    "TSTP",
    "TTIN",
    "TTOU",
    "URG",
    "XCPU",
    "XFSZ",
    "VTALRM",
    "PROF",
    "WINCH",
    "IO",
    "POLL",
    "PWR",
    "SYS",
    "RT<N>",
    "RTMIN+<N>",
    "RTMAX-<N>",
];

const FISH_NAMED_KEYS: &[&str] = &[
    "backspace",
    "comma",
    "delete",
    "down",
    "end",
    "enter",
    "escape",
    "f1",
    "f10",
    "f11",
    "f12",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "home",
    "insert",
    "left",
    "menu",
    "minus",
    "pagedown",
    "pageup",
    "printscreen",
    "right",
    "space",
    "tab",
    "up",
];

const SHELL_HELP_TOPICS: &str = include_str!("bash_help_topics.txt");
const BASH_BUILTIN_OPTIONS: &str = include_str!("bash_builtin_options.txt");
const READLINE_BINDING_NAMES: &str = include_str!("readline_binding_names.txt");

const SHELL_BUILTINS: &[&str] = &[
    "alias",
    "bg",
    "bind",
    "break",
    "builtin",
    "caller",
    "cd",
    "command",
    "compgen",
    "complete",
    "compopt",
    "continue",
    "declare",
    "dirs",
    "disown",
    "echo",
    "enable",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "fc",
    "fg",
    "getopts",
    "hash",
    "help",
    "history",
    "jobs",
    "kill",
    "let",
    "local",
    "logout",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "return",
    "set",
    "shift",
    "source",
    "suspend",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
];

const SHELL_KEYWORDS: &[&str] = &[
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
    "done", "in", "function", "time", "coproc", "!", "[[", "]]", "{", "}",
];
