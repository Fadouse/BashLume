pub mod context;
pub mod matcher;
mod provider;
mod worker;

use context::{CompletionContext, QuoteMode, existing_directory_target, quote_shell_word};
use matcher::{Candidate, CandidateKind, CandidateSink};
use provider::{CompletionProvider, GenericProvider, RuleProvider};
use worker::CompletionCache;

use crate::shell::{self, ShellSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode {
    Passive,
    ExplicitTab,
}

#[derive(Debug)]
pub struct CompletionResult {
    pub candidates: Vec<Candidate>,
    pub pending: bool,
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
            providers: vec![
                Box::<RuleProvider>::default(),
                Box::<GenericProvider>::default(),
            ],
            cache: CompletionCache::new(cache_limit_bytes, max_candidates),
        }
    }

    pub fn reconfigure(&mut self, cache_limit_bytes: usize, max_candidates: usize) {
        self.cache.reconfigure(cache_limit_bytes, max_candidates);
    }

    pub fn configure_rules(
        &mut self,
        paths: Vec<std::path::PathBuf>,
        trusted_key_paths: Vec<std::path::PathBuf>,
    ) {
        self.cache.configure_rules(paths, trusted_key_paths);
    }

    pub fn refresh(&mut self, shell: &ShellSnapshot) {
        self.cache.poll();
        // Prime the current directory before PATH directories so ordinary
        // path completion wins the worker queue at a fresh prompt.
        self.cache.refresh_directory(shell.cwd.clone());
        self.cache.refresh_path(&shell.path);
        self.cache.load_accounts(shell.home.clone());
    }

    pub fn complete(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        max_candidates: usize,
    ) -> CompletionResult {
        self.complete_with_mode(context, shell, max_candidates, CompletionMode::Passive)
    }

    pub fn complete_explicit(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        max_candidates: usize,
    ) -> CompletionResult {
        self.complete_with_mode(context, shell, max_candidates, CompletionMode::ExplicitTab)
    }

    fn complete_with_mode(
        &mut self,
        context: &CompletionContext,
        shell: &ShellSnapshot,
        max_candidates: usize,
        mode: CompletionMode,
    ) -> CompletionResult {
        self.cache.poll();
        let mut sink = CandidateSink::new(max_candidates);
        let mut pending = false;
        for provider in &mut self.providers {
            let status = provider.complete(context, shell, &mut self.cache, &mut sink, mode);
            pending |= status.pending;
        }
        CompletionResult {
            candidates: sink.finish(),
            pending,
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
            let history_is_valid = match existing_directory_target(&history_line) {
                Some(target) => self
                    .existing_directory_target(&target, shell_snapshot, max_candidates)
                    .unwrap_or(false),
                None => true,
            };
            let suffix = history_line[context.line.len()..].to_owned();
            if history_is_valid && !suffix.trim().is_empty() {
                return Some(GhostSuggestion { suffix });
            }
        }

        if context.query.is_empty() {
            return None;
        }

        let result = self.complete(context, shell_snapshot, max_candidates.min(128));
        if result.pending {
            return None;
        }
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

    fn existing_directory_target(
        &mut self,
        target: &str,
        shell_snapshot: &ShellSnapshot,
        max_candidates: usize,
    ) -> Option<bool> {
        if matches!(target, "/" | "." | ".." | "-" | "~")
            || target.starts_with(['$', '`'])
            || target.starts_with('+') && target[1..].bytes().all(|byte| byte.is_ascii_digit())
            || target.starts_with('-') && target[1..].bytes().all(|byte| byte.is_ascii_digit())
            || target.starts_with('~') && !target.starts_with("~/")
        {
            return Some(true);
        }

        let target = target.trim_end_matches('/');
        if target.is_empty() {
            return Some(true);
        }
        let quoted = quote_shell_word(target, QuoteMode::Unquoted);
        let validation_line = format!("cd {quoted}");
        let validation = CompletionContext::analyze(&validation_line, validation_line.len());
        let result = self.complete(&validation, shell_snapshot, max_candidates.min(128));
        if result.pending {
            return None;
        }
        let expected = target.trim_end_matches('/');
        Some(result.candidates.iter().any(|candidate| {
            matches!(
                candidate.kind,
                CandidateKind::Directory | CandidateKind::User
            ) && candidate.value.trim_end_matches('/') == expected
        }))
    }

    pub fn poll_background(&mut self) {
        self.cache.poll();
    }

    pub fn cancel_dynamic(&mut self) {
        self.cache.cancel_probes();
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

    pub fn rule_cache_entries(&self) -> usize {
        self.cache.rule_entry_count()
    }

    pub fn rule_pack_count(&self) -> usize {
        self.cache
            .rule_summaries()
            .iter()
            .filter(|summary| summary.compatible)
            .count()
    }

    pub fn rules_report(&self) -> String {
        let mut lines = Vec::new();
        if self.cache.rule_summaries().is_empty() {
            lines.push("no rule packs discovered (discovery may still be pending)".to_owned());
        }
        for summary in self.cache.rule_summaries() {
            if let Some(error) = &summary.error {
                lines.push(format!("{}: rejected: {error}", summary.path.display()));
                continue;
            }
            lines.push(format!(
                "{} {} source={:?} commit={} format={}.{} trust={:?} commands={} stale={} compatible={} license={}",
                summary.pack_id,
                summary.pack_version,
                summary.source,
                summary.source_commit,
                summary.format[0],
                summary.format[1],
                summary.trust,
                summary.command_count,
                summary.stale_count,
                summary.compatible,
                summary.license_expression,
            ));
        }
        for error in self.cache.rule_errors() {
            lines.push(format!("rule error: {error}"));
        }
        for error in self.cache.probe_errors() {
            lines.push(format!("probe error: {error}"));
        }
        lines.join("\n")
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

    #[test]
    fn installed_rule_packs_are_evaluated_independently_and_deduplicated() {
        use crate::rules::format::{PackBuildSpec, PackBuilder, PackManifest, SourceKind};
        use crate::rules::ir::{
            AppendPolicy, CandidateTemplate, CommandProgram, PredicateOp, RuleCandidateKind,
            StaticRule,
        };

        let root = std::env::temp_dir().join(format!("bashlume-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let make_pack = |source: SourceKind, name: &str, candidates: Vec<CandidateTemplate>| {
            let spec = PackBuildSpec {
                manifest: PackManifest {
                    pack_id: format!("org.bashlume.test.{name}"),
                    pack_version: "1.0.0".into(),
                    source_kind: source,
                    source_repository: "https://example.invalid".into(),
                    source_commit: name.repeat(8),
                    license_expression: "GPL-2.0-or-later".into(),
                    channel: "test".into(),
                    compiler_version: "test".into(),
                    generated_at: "1970-01-01T00:00:00Z".into(),
                    stale_commands: Vec::new(),
                    probe_capabilities: Vec::new(),
                },
                minimum_engine: [0, 2, 0],
                required_opcodes: 0,
                optional_features: 0,
                commands: vec![CommandProgram {
                    canonical_name: "bl-merge".into(),
                    registrations: vec!["bl-merge".into()],
                    source_path: name.into(),
                    source_commit: name.repeat(8),
                    license: "GPL-2.0-or-later".into(),
                    static_rules: vec![StaticRule {
                        when: vec![PredicateOp::True],
                        candidates,
                    }],
                    probes: Vec::new(),
                }],
            };
            let path = root.join(format!("{name}.blp"));
            std::fs::write(&path, PackBuilder::new(spec).build(None).unwrap()).unwrap();
            path
        };
        let option = |value: &str, description: Option<&str>| CandidateTemplate {
            value: value.into(),
            display: value.into(),
            description: description.map(str::to_owned),
            kind: RuleCandidateKind::Option,
            append: AppendPolicy::Space,
            preserve_order: false,
        };
        make_pack(SourceKind::Bash, "bash", vec![option("--shared", None)]);
        make_pack(
            SourceKind::Fish,
            "fish",
            vec![option("--shared", Some("Shared description"))],
        );
        make_pack(SourceKind::Zsh, "zsh", vec![option("--unique", None)]);

        let shell = ShellSnapshot {
            cwd: root.clone(),
            ..ShellSnapshot::default()
        };
        let mut engine = CompletionEngine::new(1024 * 1024, 128);
        engine.configure_rules(vec![root.clone()], Vec::new());
        let context = CompletionContext::analyze("bl-merge --", 11);
        let mut result = engine.complete_explicit(&context, &shell, 128);
        for _ in 0..100 {
            if !result.pending {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
            result = engine.complete_explicit(&context, &shell, 128);
        }
        assert!(!result.pending);
        let shared = result
            .candidates
            .iter()
            .find(|candidate| candidate.value == "--shared")
            .unwrap();
        assert_eq!(shared.description.as_deref(), Some("Shared description"));
        assert_eq!(shared.source_mask, 0b0011);
        assert!(
            result.candidates.iter().any(|candidate| {
                candidate.value == "--unique" && candidate.source_mask == 0b0100
            })
        );
        engine.stop();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deleted_navigation_target_is_rejected_after_prompt_refresh() {
        let root = std::env::temp_dir().join(format!("bashlume-navigation-{}", std::process::id()));
        let target = root.join("gone");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&target).unwrap();

        let shell = ShellSnapshot {
            cwd: root.clone(),
            path: String::new(),
            ..ShellSnapshot::default()
        };
        let mut engine = CompletionEngine::new(1024 * 1024, 128);
        engine.refresh(&shell);

        let wait_for = |engine: &mut CompletionEngine, expected: bool| {
            for _ in 0..100 {
                if engine.existing_directory_target("gone", &shell, 128) == Some(expected) {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            false
        };
        assert!(wait_for(&mut engine, true));

        std::fs::remove_dir(&target).unwrap();
        engine.refresh(&shell);
        assert_eq!(engine.existing_directory_target("gone", &shell, 128), None);
        assert!(wait_for(&mut engine, false));
        engine.stop();
        std::fs::remove_dir_all(root).unwrap();
    }
}
