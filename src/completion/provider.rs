use std::path::PathBuf;

use super::CompletionMode;
use super::context::CompletionContext;
use super::matcher::{Candidate, CandidateKind, CandidateSink};
use super::worker::{CompletionCache, EntryKind};
use crate::rules::format::SourceKind;
use crate::rules::ir::{AppendPolicy, PathCompletion, RuleCandidateKind};
use crate::rules::vm::{EvaluationContext, EvaluationMode, evaluate};
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

#[derive(Default)]
pub struct RuleProvider;

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
        let (programs, pending) = cache.rule_programs(command);
        let mut status = ProviderStatus {
            pending,
            ..ProviderStatus::default()
        };
        let Some(programs) = programs else {
            return status;
        };
        let evaluation_context = EvaluationContext {
            current_word: &context.query,
            words: &context.words,
            word_index: context.word_index,
            command_path: &context.command_path,
            environment: &shell.environment,
            working_directory: &shell.cwd,
        };
        let evaluation_mode = match mode {
            CompletionMode::Passive => EvaluationMode::Passive,
            CompletionMode::ExplicitTab => EvaluationMode::ExplicitTab,
        };
        let mut probes = Vec::new();
        for loaded in programs {
            let Ok(evaluated) = evaluate(
                &loaded.program,
                &evaluation_context,
                loaded.source,
                loaded.trust,
                evaluation_mode,
                sink.remaining_capacity_hint(),
            ) else {
                continue;
            };
            status.path_completion = status.path_completion.merge(evaluated.path_completion);
            for emitted in evaluated.candidates {
                push_rule_candidate(
                    context,
                    sink,
                    emitted.candidate.value,
                    emitted.candidate.display,
                    emitted.candidate.description,
                    emitted.candidate.kind,
                    emitted.candidate.append,
                    emitted.source,
                );
            }
            probes.extend(evaluated.probes);
        }
        for probe in probes {
            let (values, pending) = cache.probe_values(&probe);
            status.pending |= pending;
            let Some(values) = values else {
                continue;
            };
            for value in values {
                push_rule_candidate(
                    context,
                    sink,
                    value.clone(),
                    value.clone(),
                    probe.description.clone(),
                    probe.candidate_kind,
                    probe.append,
                    probe.source,
                );
            }
        }
        status
    }
}

#[allow(clippy::too_many_arguments)]
fn push_rule_candidate(
    context: &CompletionContext,
    sink: &mut CandidateSink,
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
        let candidate = candidate.with_source_mask(source_mask(source));
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
            return status;
        }
        host_query(context, cache, sink);

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
                display,
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

fn host_query(context: &CompletionContext, cache: &CompletionCache, sink: &mut CandidateSink) {
    let Some((user, prefix)) = context.query.rsplit_once('@') else {
        return;
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
