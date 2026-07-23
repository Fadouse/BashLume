pub mod context;
pub mod matcher;
mod provider;
mod worker;

use context::CompletionContext;
use matcher::{Candidate, CandidateSink};
use provider::{CompletionProvider, GenericProvider};
use worker::CompletionCache;

use crate::shell::{self, ShellSnapshot};

#[derive(Debug)]
pub struct CompletionResult {
    pub candidates: Vec<Candidate>,
    pub pending: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct GhostSuggestion {
    pub suffix: String,
}

pub struct CompletionEngine {
    providers: Vec<Box<dyn CompletionProvider>>,
    cache: CompletionCache,
}

impl CompletionEngine {
    pub fn new(cache_limit_bytes: usize, max_candidates: usize) -> Self {
        Self {
            providers: vec![Box::<GenericProvider>::default()],
            cache: CompletionCache::new(cache_limit_bytes, max_candidates),
        }
    }

    pub fn reconfigure(&mut self, cache_limit_bytes: usize, max_candidates: usize) {
        self.cache.reconfigure(cache_limit_bytes, max_candidates);
    }

    pub fn refresh(&mut self, shell: &ShellSnapshot) {
        self.cache.poll();
        // Prime the current directory before PATH directories so ordinary
        // path completion wins the worker queue at a fresh prompt.
        self.cache.request_directory(shell.cwd.clone(), "");
        self.cache.refresh_path(&shell.path);
        self.cache.load_accounts(shell.home.clone());
    }

    pub fn complete(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        max_candidates: usize,
    ) -> CompletionResult {
        self.cache.poll();
        let mut sink = CandidateSink::new(max_candidates);
        let mut pending = false;
        let mut truncated = false;
        for provider in &mut self.providers {
            let status = provider.complete(context, shell, &mut self.cache, &mut sink);
            pending |= status.pending;
            truncated |= status.truncated;
        }
        CompletionResult {
            candidates: sink.finish(),
            pending,
            truncated,
        }
    }

    /// Computes a conservative, prefix-only suggestion for display at EOL.
    ///
    /// # Safety
    /// Accesses Readline's in-memory history on Bash's main thread.
    pub unsafe fn ghost(
        &mut self,
        context: &CompletionContext,
        shell_snapshot: &ShellSnapshot,
        max_candidates: usize,
    ) -> Option<GhostSuggestion> {
        if context.point != context.line.len() || context.line.is_empty() {
            return None;
        }

        if let Some(history_line) = unsafe { shell::history_suggestion(&context.line) } {
            let suffix = history_line[context.line.len()..].to_owned();
            if !suffix.trim().is_empty() {
                return Some(GhostSuggestion { suffix });
            }
        }

        if context.query.is_empty() {
            return None;
        }

        let result = self.complete(context, shell_snapshot, max_candidates.min(128));
        for candidate in result.candidates {
            if !candidate.is_strong_prefix() {
                continue;
            }
            let (line, _) = context.apply(&candidate);
            if line.len() > context.line.len() && line.starts_with(&context.line) {
                let suffix = line[context.line.len()..].to_owned();
                if !suffix.trim().is_empty() {
                    return Some(GhostSuggestion { suffix });
                }
            }
        }
        None
    }

    pub fn command_known(&self, name: &str) -> Option<bool> {
        self.cache.command_known(name)
    }

    pub fn cache_bytes(&self) -> usize {
        self.cache.used_bytes()
    }

    pub fn cache_entries(&self) -> usize {
        self.cache.entry_count()
    }

    pub fn provider_names(&self) -> String {
        self.providers
            .iter()
            .map(|provider| provider.name())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn stop(&mut self) {
        self.cache.stop();
    }
}

pub fn longest_common_display_prefix(candidates: &[Candidate]) -> Option<String> {
    let first = candidates.first()?.display.as_str();
    let mut end = first.len();
    for candidate in &candidates[1..] {
        end = common_prefix_boundary(&first[..end], &candidate.display);
        if end == 0 {
            break;
        }
    }
    Some(first[..end].to_owned())
}

fn common_prefix_boundary(left: &str, right: &str) -> usize {
    let mut end = 0;
    for ((left_index, left_char), right_char) in left.char_indices().zip(right.chars()) {
        if left_char != right_char {
            break;
        }
        end = left_index + left_char.len_utf8();
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use matcher::{Candidate, CandidateKind};

    #[test]
    fn common_prefix_stays_on_utf8_boundaries() {
        let candidates = ["测试一", "测试二"]
            .into_iter()
            .map(|name| {
                Candidate::new(
                    "测",
                    name.into(),
                    name.into(),
                    CandidateKind::File,
                    false,
                    0,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            longest_common_display_prefix(&candidates).as_deref(),
            Some("测试")
        );
    }
}
