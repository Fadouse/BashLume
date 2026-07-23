use std::path::PathBuf;

use super::context::CompletionContext;
use super::matcher::{Candidate, CandidateKind, CandidateSink};
use super::worker::{CompletionCache, EntryKind};
use crate::shell::ShellSnapshot;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderStatus {
    pub pending: bool,
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
    ) -> ProviderStatus;
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
        if !context.command_position || explicit_path {
            let path_status = path_candidates(context, shell, cache, sink);
            status.pending |= path_status.pending;
        }

        status
    }
}

const KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "in",
    "esac", "select", "function", "time", "coproc", "[[", "((", "!", "{",
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
    for &name in KEYWORDS {
        push_named(query, name, CandidateKind::Keyword, shell, sink);
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
) -> ProviderStatus {
    let (typed_parent, leaf) = context.typed_parent_and_leaf();
    let Some(directory) = resolve_parent(&typed_parent, shell) else {
        return ProviderStatus::default();
    };
    let key = cache.request_directory(directory, &leaf);
    let Some((entries, _truncated, refreshing)) = cache.directory_entries(&key) else {
        return ProviderStatus { pending: true };
    };

    for entry in entries {
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
