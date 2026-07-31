// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use super::format::{PackFile, SourceKind, TrustStatus, TrustedKeys};
use super::ir::CommandProgram;
use super::script::{
    ScriptDialect, ScriptModule, ScriptStatement, ScriptWord, ScriptWordPart, registration_matches,
};

pub const MAX_DISCOVERED_PACKS: usize = 128;
pub const MAX_TRUSTED_KEYS: usize = 64;
const MAX_DISCOVERY_PATHS: usize = 128;
const MAX_DISCOVERY_PATH_BYTES: usize = 4096;
const MAX_DISCOVERY_PATHS_BYTES: usize = 512 * 1024;
pub const SUPPORTED_REQUIRED_OPCODES: u64 = 0;
pub const ENGINE_VERSION: [u16; 3] = [0, 2, 0];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSummary {
    pub path: PathBuf,
    pub pack_id: String,
    pub pack_version: String,
    pub source: SourceKind,
    pub source_commit: String,
    pub license_expression: String,
    pub trust: TrustStatus,
    pub format: [u16; 2],
    pub command_count: usize,
    pub stale_count: usize,
    pub compatible: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LoadedProgram {
    pub pack_id: [u8; 32],
    pub pack_name: String,
    pub pack_version: String,
    pub source: SourceKind,
    pub trust: TrustStatus,
    pub required_commands: Vec<String>,
    pub program: Arc<CommandProgram>,
}

#[derive(Default)]
pub struct RuleStore {
    packs: Vec<PackFile>,
    summaries: Vec<PackSummary>,
}

fn bounded_discovery_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut total_bytes = 0_usize;
    paths
        .iter()
        .filter_map(|path| {
            let bytes = path.as_os_str().as_bytes().len();
            if bytes > MAX_DISCOVERY_PATH_BYTES
                || total_bytes.saturating_add(bytes) > MAX_DISCOVERY_PATHS_BYTES
            {
                return None;
            }
            total_bytes = total_bytes.saturating_add(bytes);
            Some(path.clone())
        })
        .take(MAX_DISCOVERY_PATHS)
        .collect()
}

impl RuleStore {
    pub fn discover(paths: &[PathBuf], trusted_key_paths: &[PathBuf]) -> Self {
        let trusted_key_paths = bounded_discovery_paths(trusted_key_paths);
        let paths = bounded_discovery_paths(paths);
        let (trusted_keys, key_errors) = load_trusted_keys(&trusted_key_paths);
        let mut files = discover_files(&paths);
        files.sort_unstable();
        files.dedup();
        files.truncate(MAX_DISCOVERED_PACKS);

        let mut store = Self::default();
        for error in key_errors {
            store.summaries.push(PackSummary {
                path: PathBuf::new(),
                pack_id: "trusted-key".into(),
                pack_version: String::new(),
                source: SourceKind::User,
                source_commit: String::new(),
                license_expression: String::new(),
                trust: TrustStatus::Unsigned,
                format: [0, 0],
                command_count: 0,
                stale_count: 0,
                compatible: false,
                error: Some(error),
            });
        }
        for path in files {
            match PackFile::open(&path, &trusted_keys) {
                Ok(pack) => {
                    let compatible = version_at_least(ENGINE_VERSION, pack.minimum_engine())
                        && pack.required_opcodes() & !SUPPORTED_REQUIRED_OPCODES == 0;
                    store.summaries.push(summary(&pack, compatible, None));
                    if compatible {
                        store.packs.push(pack);
                    }
                }
                Err(error) => store.summaries.push(PackSummary {
                    path,
                    pack_id: String::new(),
                    pack_version: String::new(),
                    source: SourceKind::User,
                    source_commit: String::new(),
                    license_expression: String::new(),
                    trust: TrustStatus::Unsigned,
                    format: [0, 0],
                    command_count: 0,
                    stale_count: 0,
                    compatible: false,
                    error: Some(error.to_string()),
                }),
            }
        }
        store.packs.sort_by(|left, right| {
            right
                .source_kind()
                .priority()
                .cmp(&left.source_kind().priority())
                .then_with(|| left.manifest().pack_id.cmp(&right.manifest().pack_id))
        });
        store
    }

    pub fn summaries(&self) -> &[PackSummary] {
        &self.summaries
    }

    pub(crate) fn load_command_incremental(
        &self,
        command: &str,
        mut emit: impl FnMut(Vec<LoadedProgram>, Vec<String>, bool) -> bool,
    ) {
        let mut matching = self
            .packs
            .iter()
            .filter(|pack| pack.contains_command(command))
            .collect::<Vec<_>>();
        // Incremental consumers can use candidates from any source while the
        // remaining sources decode. Prefer directly evaluable user/Zsh blocks
        // for latency; consumers restore semantic source priority when merging
        // each chunk.
        matching.sort_by_key(|pack| match pack.source_kind() {
            SourceKind::User => 0_u8,
            SourceKind::Zsh => 1,
            SourceKind::Fish => 2,
            SourceKind::Bash => 3,
        });
        if matching.is_empty() {
            let _ = emit(Vec::new(), Vec::new(), true);
            return;
        }
        let last = matching.len() - 1;
        for (index, pack) in matching.into_iter().enumerate() {
            let (programs, errors) = load_pack_command(pack, command);
            if !emit(programs, errors, index == last) {
                return;
            }
        }
    }

    pub fn load_command(&self, command: &str) -> (Vec<LoadedProgram>, Vec<String>) {
        let mut programs = Vec::new();
        let mut errors = Vec::new();
        self.load_command_incremental(command, |loaded, load_errors, _| {
            programs.extend(loaded);
            errors.extend(load_errors);
            true
        });
        sort_loaded_programs(&mut programs);
        (programs, errors)
    }
}

pub(crate) fn sort_loaded_programs(programs: &mut [LoadedProgram]) {
    programs.sort_by(|left, right| {
        right
            .source
            .priority()
            .cmp(&left.source.priority())
            .then_with(|| left.pack_name.cmp(&right.pack_name))
    });
}

fn load_pack_command(pack: &PackFile, command: &str) -> (Vec<LoadedProgram>, Vec<String>) {
    let dialect = match pack.source_kind() {
        SourceKind::Bash => ScriptDialect::Bash,
        SourceKind::Zsh => ScriptDialect::Zsh,
        SourceKind::Fish => ScriptDialect::Fish,
        SourceKind::User => ScriptDialect::Bash,
    };
    let mut programs = Vec::new();
    let mut errors = Vec::new();
    match pack.load_matching_commands(command) {
        Ok(matches) => {
            for program in matches {
                if !program
                    .registrations
                    .iter()
                    .any(|name| registration_matches(dialect, name, command))
                {
                    errors.push(format!(
                        "{}: command block does not register {command}",
                        pack.path().display()
                    ));
                    continue;
                }
                let required_commands = required_commands(&program);
                programs.push(LoadedProgram {
                    pack_id: pack.pack_id(),
                    pack_name: pack.manifest().pack_id.clone(),
                    pack_version: pack.manifest().pack_version.clone(),
                    source: pack.source_kind(),
                    trust: pack.trust(),
                    required_commands,
                    program: Arc::new(program),
                });
            }
        }
        Err(error) => errors.push(format!("{}: {error}", pack.path().display())),
    }
    (programs, errors)
}

fn required_commands(program: &CommandProgram) -> Vec<String> {
    let mut commands = BTreeSet::new();
    for module in &program.scripts {
        let mut module_commands = BTreeSet::new();
        if module.dialect == ScriptDialect::Fish {
            module_commands.extend(
                module
                    .registrations
                    .iter()
                    .filter_map(|registration| registration.service.clone()),
            );
        }
        collect_required_commands(module, &mut module_commands);
        for function in &module.functions {
            module_commands.remove(&function.name);
        }
        if module.dialect == ScriptDialect::Fish {
            module_commands.retain(|name| !super::script_vm::fish_builtin_available(name));
        }
        commands.extend(module_commands);
    }
    commands.into_iter().collect()
}

fn collect_required_commands(module: &ScriptModule, commands: &mut BTreeSet<String>) {
    collect_statement_requirements(&module.statements, commands);
    for function in &module.functions {
        collect_statement_requirements(&function.body, commands);
    }
}

fn collect_statement_requirements(statements: &[ScriptStatement], commands: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                let name = command
                    .words
                    .first()
                    .and_then(ScriptWord::as_unquoted_plain_literal);
                if let Some(name) =
                    name.filter(|name| super::script_vm::emulated_external_command(name))
                {
                    commands.insert(name.to_owned());
                }
                if matches!(name, Some("command" | "type" | "whence" | "which")) {
                    for target in command
                        .words
                        .iter()
                        .skip(1)
                        .filter_map(ScriptWord::as_unquoted_plain_literal)
                        .filter(|argument| !argument.starts_with('-'))
                    {
                        commands.insert(target.to_owned());
                    }
                }
                for word in &command.words {
                    collect_word_requirements(word, commands);
                }
                for assignment in &command.assignments {
                    collect_word_requirements(&assignment.value, commands);
                    if let Some(index) = &assignment.index {
                        collect_word_requirements(index, commands);
                    }
                }
                for redirection in &command.redirections {
                    collect_word_requirements(&redirection.target, commands);
                }
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_statement_requirements(std::slice::from_ref(first), commands);
                for arm in rest {
                    collect_statement_requirements(std::slice::from_ref(&arm.statement), commands);
                }
            }
            ScriptStatement::Pipeline {
                commands: pipeline, ..
            } => collect_statement_requirements(pipeline, commands),
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_statement_requirements(&branch.condition, commands);
                    collect_statement_requirements(&branch.body, commands);
                }
                collect_statement_requirements(otherwise, commands);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_statement_requirements(condition, commands);
                collect_statement_requirements(body, commands);
            }
            ScriptStatement::For { words, body, .. } => {
                for word in words {
                    collect_word_requirements(word, commands);
                }
                collect_statement_requirements(body, commands);
            }
            ScriptStatement::Case { word, arms } => {
                collect_word_requirements(word, commands);
                for arm in arms {
                    for pattern in &arm.patterns {
                        collect_word_requirements(pattern, commands);
                    }
                    collect_statement_requirements(&arm.body, commands);
                }
            }
            ScriptStatement::Function { function } => {
                collect_statement_requirements(&function.body, commands)
            }
            ScriptStatement::Group { body, .. } => collect_statement_requirements(body, commands),
            ScriptStatement::Return {
                status: Some(status),
            } => collect_word_requirements(status, commands),
            _ => {}
        }
    }
}

fn collect_word_requirements(word: &ScriptWord, commands: &mut BTreeSet<String>) {
    for part in &word.parts {
        match part {
            ScriptWordPart::CommandSubstitution { statements, .. } => {
                collect_statement_requirements(statements, commands)
            }
            ScriptWordPart::DeferredScript {
                statements, words, ..
            } => {
                collect_statement_requirements(statements, commands);
                for word in words {
                    collect_word_requirements(word, commands);
                }
            }
            ScriptWordPart::BraceExpansion { alternatives, .. } => {
                for alternative in alternatives {
                    collect_word_requirements(alternative, commands);
                }
            }
            ScriptWordPart::Array { elements } => {
                for element in elements {
                    collect_word_requirements(element, commands);
                }
            }
            _ => {}
        }
    }
}

fn summary(pack: &PackFile, compatible: bool, error: Option<String>) -> PackSummary {
    PackSummary {
        path: pack.path().to_owned(),
        pack_id: pack.manifest().pack_id.clone(),
        pack_version: pack.manifest().pack_version.clone(),
        source: pack.source_kind(),
        source_commit: pack.manifest().source_commit.clone(),
        license_expression: pack.manifest().license_expression.clone(),
        trust: pack.trust(),
        format: pack.format(),
        command_count: pack.command_count(),
        stale_count: pack.manifest().stale_commands.len(),
        compatible,
        error,
    }
}

fn discover_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if files.len() >= MAX_DISCOVERED_PACKS {
            break;
        }
        let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if !seen.insert(normalized.clone()) {
            continue;
        }
        if normalized.is_file() {
            if is_pack(&normalized) {
                files.push(normalized);
            }
            continue;
        }
        let Ok(directory) = fs::read_dir(&normalized) else {
            continue;
        };
        let mut children = Vec::new();
        for child in directory
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && is_pack(path))
        {
            children.push(child);
            if children.len() >= MAX_DISCOVERED_PACKS * 2 {
                children.sort_unstable();
                children.truncate(MAX_DISCOVERED_PACKS);
            }
        }
        children.sort_unstable();
        children.truncate(MAX_DISCOVERED_PACKS);
        for child in children {
            if files.len() >= MAX_DISCOVERED_PACKS {
                break;
            }
            files.push(child);
        }
    }
    files
}

fn is_pack(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "blp")
}

fn load_trusted_keys(paths: &[PathBuf]) -> (TrustedKeys, Vec<String>) {
    let mut key_files = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if key_files.len() >= MAX_TRUSTED_KEYS {
            break;
        }
        let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if normalized.is_file() {
            if seen.insert(normalized.clone()) {
                key_files.push(normalized);
            }
            continue;
        }
        let Ok(directory) = fs::read_dir(&normalized) else {
            continue;
        };
        let mut children = Vec::new();
        for child in directory
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path.extension().is_some_and(|extension| {
                        extension == "pub" || extension == "hex" || extension == "key"
                    })
            })
        {
            children.push(child);
            if children.len() >= MAX_TRUSTED_KEYS * 2 {
                children.sort_unstable();
                children.truncate(MAX_TRUSTED_KEYS);
            }
        }
        children.sort_unstable();
        children.truncate(MAX_TRUSTED_KEYS);
        for child in children {
            if key_files.len() >= MAX_TRUSTED_KEYS {
                break;
            }
            let child = fs::canonicalize(&child).unwrap_or(child);
            if seen.insert(child.clone()) {
                key_files.push(child);
            }
        }
    }

    let mut keys = TrustedKeys::default();
    let mut errors = Vec::new();
    for path in key_files {
        let result = (|| {
            let mut text = Vec::new();
            fs::File::open(&path)?.take(4097).read_to_end(&mut text)?;
            if text.len() > 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "verifying key file exceeds 4096 bytes",
                ));
            }
            let text = String::from_utf8(text)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let bytes = hex::decode(text.trim()).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "verifying key must contain exactly 32 bytes",
                )
            })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
            keys.insert(key);
            Ok::<(), std::io::Error>(())
        })();
        if let Err(error) = result {
            errors.push(format!("{}: {error}", path.display()));
        }
    }
    (keys, errors)
}

fn version_at_least(actual: [u16; 3], minimum: [u16; 3]) -> bool {
    actual >= minimum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_version_tuples_compare_lexicographically() {
        assert!(version_at_least([1, 0, 0], [0, 99, 99]));
        assert!(version_at_least([0, 2, 1], [0, 2, 0]));
        assert!(!version_at_least([0, 1, 9], [0, 2, 0]));
    }

    #[test]
    fn decoded_chunks_are_restored_to_semantic_source_priority() {
        fn loaded(source: SourceKind, name: &str) -> LoadedProgram {
            LoadedProgram {
                pack_id: [source.priority(); 32],
                pack_name: name.into(),
                pack_version: "test".into(),
                source,
                trust: TrustStatus::Unsigned,
                required_commands: Vec::new(),
                program: Arc::new(CommandProgram {
                    canonical_name: "demo".into(),
                    registrations: vec!["demo".into()],
                    source_path: "demo".into(),
                    source_commit: "test".into(),
                    license: "test".into(),
                    static_rules: Vec::new(),
                    probes: Vec::new(),
                    scripts: Vec::new(),
                }),
            }
        }

        let mut programs = vec![
            loaded(SourceKind::Zsh, "zsh"),
            loaded(SourceKind::Fish, "fish"),
            loaded(SourceKind::User, "user"),
            loaded(SourceKind::Bash, "bash"),
        ];
        sort_loaded_programs(&mut programs);
        assert_eq!(
            programs
                .iter()
                .map(|program| program.source)
                .collect::<Vec<_>>(),
            [
                SourceKind::User,
                SourceKind::Bash,
                SourceKind::Fish,
                SourceKind::Zsh
            ]
        );
    }

    #[test]
    fn trusted_key_directories_load_only_key_files() {
        let directory = std::env::temp_dir().join(format!(
            "bashlume-trusted-keys-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        fs::write(
            directory.join("official.pub"),
            hex::encode(signing.verifying_key().as_bytes()),
        )
        .unwrap();
        fs::write(directory.join("README.md"), "not a key").unwrap();

        let (keys, errors) = load_trusted_keys(std::slice::from_ref(&directory));
        let _ = fs::remove_dir_all(&directory);
        assert!(errors.is_empty());
        assert!(!keys.is_empty());
    }
}
