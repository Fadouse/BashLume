// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use super::format::{MAX_MATCHING_COMMAND_BLOCKS, PackFile, SourceKind, TrustStatus, TrustedKeys};
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

pub(crate) fn pack_summaries_bytes(summaries: &[PackSummary]) -> usize {
    summaries
        .len()
        .saturating_mul(std::mem::size_of::<PackSummary>())
        .saturating_add(summaries.iter().fold(0_usize, |total, summary| {
            total
                .saturating_add(summary.path.as_os_str().as_bytes().len())
                .saturating_add(summary.pack_id.capacity())
                .saturating_add(summary.pack_version.capacity())
                .saturating_add(summary.source_commit.capacity())
                .saturating_add(summary.license_expression.capacity())
                .saturating_add(summary.error.as_ref().map_or(0, String::capacity))
        }))
}

#[derive(Clone, Debug)]
pub struct LoadedProgram {
    pub pack_id: [u8; 32],
    pub pack_name: String,
    pub pack_version: String,
    pub source: SourceKind,
    pub trust: TrustStatus,
    pub required_commands: Vec<String>,
    pub(crate) retained_bytes: usize,
    pub program: Arc<CommandProgram>,
}

#[derive(Default)]
pub struct RuleStore {
    packs: Vec<PackFile>,
    summaries: Vec<PackSummary>,
}

fn push_bounded_summary(
    store: &mut RuleStore,
    retained_bytes: &mut usize,
    byte_limit: usize,
    summary: PackSummary,
) -> bool {
    // One copy remains in the worker store and one is sent to the main cache.
    let bytes = pack_summaries_bytes(std::slice::from_ref(&summary)).saturating_mul(2);
    if retained_bytes.saturating_add(bytes) > byte_limit {
        return false;
    }
    *retained_bytes = retained_bytes.saturating_add(bytes);
    store.summaries.push(summary);
    true
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
        Self::discover_bounded(paths, trusted_key_paths, usize::MAX)
    }

    pub(crate) fn discover_bounded(
        paths: &[PathBuf],
        trusted_key_paths: &[PathBuf],
        byte_limit: usize,
    ) -> Self {
        Self::discover_bounded_while(paths, trusted_key_paths, byte_limit, || true)
    }

    pub(crate) fn discover_bounded_while(
        paths: &[PathBuf],
        trusted_key_paths: &[PathBuf],
        byte_limit: usize,
        mut should_continue: impl FnMut() -> bool,
    ) -> Self {
        let trusted_key_paths = bounded_discovery_paths(trusted_key_paths);
        let paths = bounded_discovery_paths(paths);
        let (trusted_keys, key_errors) = load_trusted_keys(&trusted_key_paths);
        let mut files = discover_files(&paths);
        files.sort_unstable();
        files.dedup();
        files.truncate(MAX_DISCOVERED_PACKS);

        let mut store = Self::default();
        let mut retained_bytes = 0_usize;
        for error in key_errors {
            if !should_continue() {
                return Self::default();
            }
            let _ = push_bounded_summary(
                &mut store,
                &mut retained_bytes,
                byte_limit,
                PackSummary {
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
                },
            );
        }
        for path in files {
            if !should_continue() {
                return Self::default();
            }
            // `open_bounded` preflights the mapping plus parsed metadata
            // against this complete remaining store budget before allocating.
            let mapping_limit = byte_limit.saturating_sub(retained_bytes);
            match PackFile::open_bounded(
                &path,
                &trusted_keys,
                u64::try_from(mapping_limit).unwrap_or(u64::MAX),
            ) {
                Ok(pack) => {
                    let compatible = version_at_least(ENGINE_VERSION, pack.minimum_engine())
                        && pack.required_opcodes() & !SUPPORTED_REQUIRED_OPCODES == 0;
                    let pack_bytes = pack.approximate_bytes();
                    // Compute from borrowed metadata before cloning a summary.
                    // If the aggregate cannot retain both copies, unmap the
                    // pack before allocating even the bounded rejection row.
                    let summary_bytes = summary_bytes(&pack, 0).saturating_mul(2);
                    let retained = compatible
                        && retained_bytes
                            .saturating_add(pack_bytes)
                            .saturating_add(summary_bytes)
                            <= byte_limit;
                    if retained {
                        let accepted_summary = summary(&pack, true, None);
                        retained_bytes = retained_bytes
                            .saturating_add(pack_bytes)
                            .saturating_add(summary_bytes);
                        store.summaries.push(accepted_summary);
                        store.packs.push(pack);
                    } else {
                        let path = pack.path().to_owned();
                        drop(pack);
                        let error = if compatible {
                            "rule pack exceeds the configured store limit"
                        } else {
                            "rule pack is incompatible with this engine"
                        };
                        let _ = push_bounded_summary(
                            &mut store,
                            &mut retained_bytes,
                            byte_limit,
                            rejected_summary(path, error),
                        );
                    }
                }
                Err(error) => {
                    let _ = push_bounded_summary(
                        &mut store,
                        &mut retained_bytes,
                        byte_limit,
                        PackSummary {
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
                        },
                    );
                }
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

    pub(crate) fn approximate_bytes(&self) -> usize {
        self.packs
            .iter()
            .map(PackFile::approximate_bytes)
            .sum::<usize>()
            .saturating_add(pack_summaries_bytes(&self.summaries))
    }

    pub(crate) fn load_command_incremental(
        &self,
        command: &str,
        decoded_byte_limit: usize,
        mut should_continue: impl FnMut() -> bool,
        mut emit: impl FnMut(Vec<LoadedProgram>, Vec<String>, bool, bool) -> Option<usize>,
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
        let mut pending = None;
        let mut matched_blocks = 0_usize;
        let mut remaining_bytes = decoded_byte_limit;
        for pack in matching {
            if !should_continue() {
                return;
            }
            // Retain IDs for at most one pack at a time; never materialize the
            // cross-pack Cartesian match list.
            let block_ids = match pack.matching_block_ids(command) {
                Ok(block_ids) => block_ids,
                Err(error) => {
                    let _ = emit(
                        Vec::new(),
                        vec![format!("{}: {error}", pack.path().display())],
                        true,
                        true,
                    );
                    return;
                }
            };
            for block_id in block_ids {
                matched_blocks = matched_blocks.saturating_add(1);
                if matched_blocks > MAX_MATCHING_COMMAND_BLOCKS {
                    let _ = emit(
                        Vec::new(),
                        vec![format!(
                            "{command}: matching rule blocks exceed the bounded limit"
                        )],
                        true,
                        true,
                    );
                    return;
                }
                if let Some((previous_pack, previous_block)) = pending.replace((pack, block_id)) {
                    if !should_continue() {
                        return;
                    }
                    let (programs, errors, limit_exceeded) =
                        load_pack_block(previous_pack, previous_block, command, remaining_bytes);
                    let Some(next_limit) = emit(programs, errors, false, limit_exceeded) else {
                        return;
                    };
                    remaining_bytes = next_limit;
                }
            }
        }
        let Some((pack, block_id)) = pending else {
            if should_continue() {
                let _ = emit(Vec::new(), Vec::new(), true, false);
            }
            return;
        };
        if !should_continue() {
            return;
        }
        let (programs, errors, limit_exceeded) =
            load_pack_block(pack, block_id, command, remaining_bytes);
        let _ = emit(programs, errors, true, limit_exceeded);
    }

    pub fn load_command(&self, command: &str) -> (Vec<LoadedProgram>, Vec<String>) {
        let mut programs = Vec::new();
        let mut errors = Vec::new();
        self.load_command_incremental(
            command,
            super::ir::MAX_COMMAND_DECODE_ALLOCATION_BYTES,
            || true,
            |loaded, load_errors, _, _| {
                programs.extend(loaded);
                errors.extend(load_errors);
                Some(super::ir::MAX_COMMAND_DECODE_ALLOCATION_BYTES)
            },
        );
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

fn load_pack_block(
    pack: &PackFile,
    block_id: u32,
    command: &str,
    decoded_byte_limit: usize,
) -> (Vec<LoadedProgram>, Vec<String>, bool) {
    let dialect = match pack.source_kind() {
        SourceKind::Bash => ScriptDialect::Bash,
        SourceKind::Zsh => ScriptDialect::Zsh,
        SourceKind::Fish => ScriptDialect::Fish,
        SourceKind::User => ScriptDialect::Bash,
    };
    let (program, decoded_allocation) =
        match pack.load_block_bounded_accounted(block_id, decoded_byte_limit) {
            Ok(program) => program,
            Err(error) => {
                let limit_exceeded = matches!(error, super::format::PackError::Limit(_));
                return (
                    Vec::new(),
                    vec![format!("{}: {error}", pack.path().display())],
                    limit_exceeded,
                );
            }
        };
    if !program
        .registrations
        .iter()
        .any(|name| registration_matches(dialect, name, command))
    {
        return (
            Vec::new(),
            vec![format!(
                "{}: command block does not register {command}",
                pack.path().display()
            )],
            false,
        );
    }
    let metadata_bytes = std::mem::size_of::<LoadedProgram>()
        .saturating_add(std::mem::size_of::<Arc<CommandProgram>>())
        .saturating_add(pack.manifest().pack_id.len())
        .saturating_add(pack.manifest().pack_version.len());
    let required_budget = decoded_byte_limit
        .saturating_sub(decoded_allocation)
        .saturating_sub(metadata_bytes);
    let required_commands = match required_commands_bounded(&program, required_budget) {
        Ok(commands) => commands,
        Err(()) => {
            return (
                Vec::new(),
                vec![format!(
                    "{}: required command metadata exceeds the configured limit",
                    pack.path().display()
                )],
                true,
            );
        }
    };
    let required_command_bytes = required_commands
        .capacity()
        .saturating_mul(std::mem::size_of::<String>())
        .saturating_add(
            required_commands
                .iter()
                .map(String::capacity)
                .sum::<usize>(),
        );
    let retained_bytes = decoded_allocation
        .saturating_add(metadata_bytes)
        .saturating_add(required_command_bytes);
    (
        vec![LoadedProgram {
            pack_id: pack.pack_id(),
            pack_name: pack.manifest().pack_id.clone(),
            pack_version: pack.manifest().pack_version.clone(),
            source: pack.source_kind(),
            trust: pack.trust(),
            required_commands,
            retained_bytes,
            program: Arc::new(program),
        }],
        Vec::new(),
        false,
    )
}

const MAX_REQUIRED_COMMANDS: usize = 65_536;
const REQUIRED_COMMAND_NODE_BYTES: usize =
    4 * std::mem::size_of::<usize>() + std::mem::size_of::<&str>();

struct RequiredCommandSet<'a> {
    values: BTreeSet<&'a str>,
    used: usize,
    limit: usize,
    exceeded: bool,
}

impl<'a> RequiredCommandSet<'a> {
    fn new(limit: usize) -> Self {
        Self {
            values: BTreeSet::new(),
            used: 0,
            limit,
            exceeded: false,
        }
    }

    fn insert(&mut self, value: &'a str) {
        if self.exceeded || self.values.contains(value) {
            return;
        }
        let bytes = REQUIRED_COMMAND_NODE_BYTES;
        if self.values.len() >= MAX_REQUIRED_COMMANDS
            || self.used.saturating_add(bytes) > self.limit
        {
            self.exceeded = true;
            return;
        }
        self.used = self.used.saturating_add(bytes);
        self.values.insert(value);
    }
}

fn required_commands_bounded(
    program: &CommandProgram,
    byte_limit: usize,
) -> Result<Vec<String>, ()> {
    let mut commands = RequiredCommandSet::new(byte_limit);
    for module in &program.scripts {
        let remaining = byte_limit.saturating_sub(commands.used);
        let mut module_commands = RequiredCommandSet::new(remaining);
        if module.dialect == ScriptDialect::Fish {
            for service in module
                .registrations
                .iter()
                .filter_map(|registration| registration.service.as_deref())
            {
                module_commands.insert(service);
            }
        }
        collect_required_commands(module, &mut module_commands);
        for function in &module.functions {
            module_commands.values.remove(function.name.as_str());
        }
        if module.dialect == ScriptDialect::Fish {
            module_commands
                .values
                .retain(|name| !super::script_vm::fish_builtin_available(name));
        }
        if module_commands.exceeded
            || commands.used.saturating_add(module_commands.used) > byte_limit
        {
            return Err(());
        }
        // Both trees coexist during this merge. Reserve the transient module
        // nodes while deciding whether another global node may be allocated.
        commands.limit = byte_limit.saturating_sub(module_commands.used);
        for command in module_commands.values {
            commands.insert(command);
        }
        commands.limit = byte_limit;
        if commands.exceeded {
            return Err(());
        }
    }
    let output_bytes = commands
        .values
        .len()
        .saturating_mul(std::mem::size_of::<String>())
        .saturating_add(
            commands
                .values
                .iter()
                .map(|value| value.len())
                .sum::<usize>(),
        );
    if commands.used.saturating_add(output_bytes) > byte_limit {
        return Err(());
    }
    Ok(commands.values.into_iter().map(str::to_owned).collect())
}

fn collect_required_commands<'a>(module: &'a ScriptModule, commands: &mut RequiredCommandSet<'a>) {
    collect_statement_requirements(&module.statements, commands);
    for function in &module.functions {
        collect_statement_requirements(&function.body, commands);
    }
}

fn collect_statement_requirements<'a>(
    statements: &'a [ScriptStatement],
    commands: &mut RequiredCommandSet<'a>,
) {
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
                    commands.insert(name);
                }
                if matches!(name, Some("command" | "type" | "whence" | "which")) {
                    for target in command
                        .words
                        .iter()
                        .skip(1)
                        .filter_map(ScriptWord::as_unquoted_plain_literal)
                        .filter(|argument| !argument.starts_with('-'))
                    {
                        commands.insert(target);
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

fn collect_word_requirements<'a>(word: &'a ScriptWord, commands: &mut RequiredCommandSet<'a>) {
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

fn summary_bytes(pack: &PackFile, error_bytes: usize) -> usize {
    std::mem::size_of::<PackSummary>()
        .saturating_add(pack.path().as_os_str().as_bytes().len())
        .saturating_add(pack.manifest().pack_id.len())
        .saturating_add(pack.manifest().pack_version.len())
        .saturating_add(pack.manifest().source_commit.len())
        .saturating_add(pack.manifest().license_expression.len())
        .saturating_add(error_bytes)
}

fn rejected_summary(path: PathBuf, error: &str) -> PackSummary {
    PackSummary {
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
        error: Some(error.to_owned()),
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
                retained_bytes: 0,
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
