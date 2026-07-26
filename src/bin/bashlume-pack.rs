// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bashlume::rules::format::{
    PackBuildSpec, PackBuilder, PackFile, PackManifest, SourceKind, TrustedKeys,
};
use bashlume::rules::ir::CommandProgram;
use bashlume::rules::script::{
    ScriptDialect, ScriptEntry, ScriptFunction, ScriptModule, ScriptStatement, ScriptWord,
    ScriptWordPart,
};
use bashlume::rules::script_parser::{MAX_SCRIPT_SOURCE_BYTES, parse_script};
use bashlume::rules::vm::{
    EvaluationContext, EvaluationMode, EvaluationResult, ProbeKey, ProbeResult,
    evaluate_with_outcomes,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("bashlume-pack: {error}");
        std::process::exit(1);
    }
}

fn read_bytes_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds the {} byte input limit", path.display(), limit),
        ));
    }
    Ok(bytes)
}

fn read_text_bounded(path: &Path, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bytes_bounded(path, limit)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return usage();
    };
    let remaining = arguments.collect::<Vec<_>>();
    match command.to_string_lossy().as_ref() {
        "build" => build(&remaining),
        "inspect" => inspect(&remaining, false),
        "verify" => inspect(&remaining, true),
        "key-id" => key_id(&remaining),
        "public-key" => public_key(&remaining),
        "evaluate" => evaluate_pack(&remaining),
        "parse-shell" => parse_shell(&remaining),
        "transpile-shell" => transpile_shell(&remaining),
        "help" | "--help" | "-h" => usage(),
        _ => usage(),
    }
}

fn usage<T>() -> Result<T, Box<dyn std::error::Error>> {
    Err(
        "usage:\n  bashlume-pack build SPEC.json OUTPUT.blp [SIGNING_KEY.hex]\n  bashlume-pack inspect PACK.blp [VERIFYING_KEY.hex ...]\n  bashlume-pack verify PACK.blp [VERIFYING_KEY.hex ...]\n  bashlume-pack key-id VERIFYING_KEY.hex\n  bashlume-pack public-key SIGNING_KEY.hex\n  bashlume-pack evaluate PACK.blp CONTEXT.json [VERIFYING_KEY.hex ...]\n  bashlume-pack parse-shell bash|zsh|fish OUTPUT.json SOURCE ...\n  bashlume-pack transpile-shell CONFIG.json OUTPUT.json COVERAGE.json SOURCE ..."
            .into(),
    )
}

fn build(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if !(2..=3).contains(&arguments.len()) {
        return usage();
    }
    let input = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let spec: PackBuildSpec =
        serde_json::from_slice(&read_bytes_bounded(input, 512 * 1024 * 1024)?)?;
    let signing_key = arguments
        .get(2)
        .map(|path| read_signing_key(Path::new(path)))
        .transpose()?;
    let bytes = PackBuilder::new(spec).build(signing_key.as_ref())?;
    atomic_write(output, &bytes)?;
    println!("wrote {} bytes to {}", bytes.len(), output.display());
    Ok(())
}

fn inspect(
    arguments: &[std::ffi::OsString],
    verify_all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.is_empty() {
        return usage();
    }
    let mut keys = TrustedKeys::default();
    for path in &arguments[1..] {
        keys.insert(read_verifying_key(Path::new(path))?);
    }
    let pack = PackFile::open(Path::new(&arguments[0]), &keys)?;
    println!("path: {}", pack.path().display());
    println!("pack: {}", pack.manifest().pack_id);
    println!("version: {}", pack.manifest().pack_version);
    println!("source: {:?}", pack.source_kind());
    println!("source commit: {}", pack.manifest().source_commit);
    println!("license: {}", pack.manifest().license_expression);
    println!("format: {}.{}", pack.format()[0], pack.format()[1]);
    println!(
        "minimum engine: {}.{}.{}",
        pack.minimum_engine()[0],
        pack.minimum_engine()[1],
        pack.minimum_engine()[2]
    );
    println!("trust: {:?}", pack.trust());
    println!("commands: {}", pack.command_count());
    println!("stale: {}", pack.manifest().stale_commands.len());
    if verify_all {
        for command in pack.command_names() {
            let program = pack
                .load_command(command)?
                .ok_or_else(|| format!("indexed command disappeared: {command}"))?;
            if !program.registrations.iter().any(|name| name == command) {
                return Err(format!("{command}: registration missing from command block").into());
            }
        }
        println!("all command blocks verified");
    }
    Ok(())
}

#[derive(Deserialize)]
struct EvaluationInput {
    command: String,
    #[serde(default)]
    current_word: String,
    words: Vec<String>,
    word_index: usize,
    #[serde(default)]
    command_path: Vec<String>,
    #[serde(default)]
    environment: HashMap<String, String>,
    #[serde(default)]
    available_commands: Option<Vec<String>>,
    #[serde(default)]
    shell_functions: Option<Vec<String>>,
    #[serde(default)]
    shell_variables: Option<Vec<String>>,
    #[serde(default)]
    shell_variable_values: Option<HashMap<String, Vec<String>>>,
    #[serde(default)]
    users: Option<Vec<String>>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    hosts: Option<Vec<String>>,
    #[serde(default)]
    process_ids: Option<Vec<String>>,
    #[serde(default)]
    process_names: Option<Vec<String>>,
    #[serde(default)]
    network_interfaces: Option<Vec<String>>,
    #[serde(default)]
    signals: Option<Vec<String>>,
    #[serde(default)]
    passwd_records: Option<Vec<String>>,
    #[serde(default)]
    group_records: Option<Vec<String>>,
    #[serde(default = "default_effective_user_id")]
    effective_user_id: u32,
    #[serde(default = "default_working_directory")]
    working_directory: PathBuf,
    #[serde(default)]
    explicit_tab: bool,
    #[serde(default)]
    probe_outcomes: HashMap<String, ProbeResult>,
    #[serde(default)]
    probe_results: HashMap<String, Vec<String>>,
    #[serde(default)]
    probe_failures: Vec<String>,
    #[serde(default)]
    completion_results: HashMap<String, Vec<String>>,
}

fn default_effective_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

fn default_working_directory() -> PathBuf {
    PathBuf::from(".")
}

fn evaluate_pack(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() < 2 {
        return usage();
    }
    let mut keys = TrustedKeys::default();
    for path in &arguments[2..] {
        keys.insert(read_verifying_key(Path::new(path))?);
    }
    let pack = PackFile::open(Path::new(&arguments[0]), &keys)?;
    let input: EvaluationInput = serde_json::from_slice(&read_bytes_bounded(
        Path::new(&arguments[1]),
        16 * 1024 * 1024,
    )?)?;
    if input.word_index >= input.words.len() {
        return Err("context word_index is outside words".into());
    }
    let programs = pack.load_matching_commands(&input.command)?;
    if programs.is_empty() {
        return Err(format!("no rule for command {}", input.command).into());
    }
    let available_commands = input.available_commands.as_ref().map(|commands| {
        commands
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>()
    });
    let context = EvaluationContext {
        current_word: &input.current_word,
        words: &input.words,
        word_index: input.word_index,
        command_path: &input.command_path,
        environment: &input.environment,
        working_directory: &input.working_directory,
        available_commands: available_commands.as_ref(),
        shell_commands: input.available_commands.as_deref(),
        shell_functions: input.shell_functions.as_deref(),
        shell_variables: input.shell_variables.as_deref(),
        shell_variable_values: input.shell_variable_values.as_ref(),
        users: input.users.as_deref(),
        groups: input.groups.as_deref(),
        hosts: input.hosts.as_deref(),
        process_ids: input.process_ids.as_deref(),
        process_names: input.process_names.as_deref(),
        network_interfaces: input.network_interfaces.as_deref(),
        signals: input.signals.as_deref(),
        passwd_records: input.passwd_records.as_deref(),
        group_records: input.group_records.as_deref(),
        effective_user_id: input.effective_user_id,
    };
    let mode = if input.explicit_tab {
        EvaluationMode::ExplicitTab
    } else {
        EvaluationMode::Passive
    };
    let mut result = EvaluationResult::default();
    for program in programs {
        let candidate_limit = 65_536_usize.saturating_sub(result.candidates.len());
        let mut replay = HashMap::<ProbeKey, ProbeResult>::new();
        let mut evaluated = evaluate_with_outcomes(
            &program,
            &context,
            pack.source_kind(),
            pack.trust(),
            mode,
            candidate_limit,
            &replay,
            &input.completion_results,
        )?;
        for _ in 0..8 {
            let mut progressed = false;
            for probe in &evaluated.probes {
                if replay.contains_key(&probe.key) {
                    continue;
                }
                let outcome = if let Some(outcome) = input.probe_outcomes.get(&probe.probe_id) {
                    Some(outcome.clone())
                } else if let Some(values) = input.probe_results.get(&probe.probe_id) {
                    Some(ProbeResult {
                        status: 0,
                        values: values.clone(),
                        truncated: false,
                    })
                } else if input.probe_failures.contains(&probe.probe_id) {
                    Some(ProbeResult {
                        status: 1,
                        values: Vec::new(),
                        truncated: false,
                    })
                } else {
                    None
                };
                if let Some(outcome) = outcome {
                    replay.insert(probe.key.clone(), outcome);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
            evaluated = evaluate_with_outcomes(
                &program,
                &context,
                pack.source_kind(),
                pack.trust(),
                mode,
                candidate_limit,
                &replay,
                &input.completion_results,
            )?;
        }
        result.candidates.extend(evaluated.candidates);
        result.truncated |= evaluated.truncated;
        result.probes.extend(evaluated.probes);
        for request in evaluated.completion_requests {
            if !result.completion_requests.contains(&request) {
                result.completion_requests.push(request);
            }
        }
        for request in evaluated.filesystem_requests {
            if !result.filesystem_requests.contains(&request) {
                result.filesystem_requests.push(request);
            }
        }
        for provider in evaluated.snapshot_providers {
            if !result.snapshot_providers.contains(&provider) {
                result.snapshot_providers.push(provider);
            }
        }
        result.denied_probe_count = result
            .denied_probe_count
            .saturating_add(evaluated.denied_probe_count);
        result.path_completion = result.path_completion.merge(evaluated.path_completion);
        if evaluated.completion_status.is_some() {
            result.completion_status = evaluated.completion_status;
        }
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_shell(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() < 3 {
        return usage();
    }
    let dialect = match arguments[0].to_string_lossy().as_ref() {
        "bash" => ScriptDialect::Bash,
        "zsh" => ScriptDialect::Zsh,
        "fish" => ScriptDialect::Fish,
        _ => return Err("parse-shell dialect must be bash, zsh, or fish".into()),
    };
    let output = Path::new(&arguments[1]);
    let mut modules = Vec::with_capacity(arguments.len() - 2);
    for source_path in &arguments[2..] {
        let source_path = Path::new(source_path);
        let source = read_text_bounded(source_path, MAX_SCRIPT_SOURCE_BYTES)?;
        modules.push(
            parse_script(dialect, source_path.to_string_lossy(), &source)
                .map_err(|error| format!("{}: {error}", source_path.display()))?,
        );
    }
    atomic_write(output, &serde_json::to_vec(&modules)?)?;
    println!("parsed {} {:?} source modules", modules.len(), dialect);
    Ok(())
}

#[derive(Deserialize)]
struct ShellTranspileConfig {
    dialect: ScriptDialect,
    source_root: PathBuf,
    default_license: String,
    #[serde(default)]
    support_roots: Vec<PathBuf>,
    #[serde(default)]
    support_files: Vec<PathBuf>,
    #[serde(default)]
    zsh_function_roots: Vec<PathBuf>,
    #[serde(default)]
    zsh_preload_files: Vec<PathBuf>,
    manifest: PackManifest,
    #[serde(default = "transpile_minimum_engine")]
    minimum_engine: [u16; 3],
    #[serde(default)]
    required_opcodes: u64,
    #[serde(default)]
    optional_features: u64,
}

const fn transpile_minimum_engine() -> [u16; 3] {
    [0, 2, 0]
}

struct ScriptGroup {
    registrations: BTreeSet<String>,
    scripts: Vec<bashlume::rules::script::ScriptModule>,
    licenses: BTreeSet<String>,
    source_paths: BTreeSet<String>,
}

impl ScriptGroup {
    fn merge(&mut self, other: Self) {
        self.registrations.extend(other.registrations);
        self.scripts.extend(other.scripts);
        self.licenses.extend(other.licenses);
        self.source_paths.extend(other.source_paths);
    }
}

const MAX_SUPPORT_LIBRARY_FILES: usize = 65_536;
const MAX_SUPPORT_LIBRARY_FUNCTIONS: usize = 262_144;
const MAX_ZSH_FUNCTION_NAME_BYTES: usize = 1024 * 1024;

fn update_preloaded_function(
    names: &mut Vec<String>,
    seen: &mut HashSet<String>,
    table_size: &mut u32,
    name: &str,
    remove: bool,
) {
    if remove {
        if seen.remove(name) {
            names.retain(|existing| existing != name);
        }
    } else if !name.is_empty() && seen.insert(name.to_owned()) {
        names.push(name.to_owned());
        while seen.len() >= *table_size as usize * 2 {
            *table_size = table_size.saturating_mul(4);
        }
    }
}

fn collect_preloaded_zsh_functions(
    statements: &[ScriptStatement],
    names: &mut Vec<String>,
    seen: &mut HashSet<String>,
    table_size: &mut u32,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                let words = command
                    .words
                    .iter()
                    .map(ScriptWord::as_unquoted_plain_literal)
                    .collect::<Vec<_>>();
                let Some(operation) = words.first().copied().flatten() else {
                    continue;
                };
                if !matches!(operation, "autoload" | "unfunction") {
                    continue;
                }
                let remove = operation == "unfunction";
                for name in words.into_iter().skip(1).flatten() {
                    if name == "--" || name.starts_with('-') {
                        continue;
                    }
                    update_preloaded_function(names, seen, table_size, name, remove);
                }
            }
            ScriptStatement::Function { function } => {
                update_preloaded_function(names, seen, table_size, &function.name, false);
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_preloaded_zsh_functions(commands, names, seen, table_size)
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_preloaded_zsh_functions(
                    std::slice::from_ref(first),
                    names,
                    seen,
                    table_size,
                );
                for arm in rest {
                    collect_preloaded_zsh_functions(
                        std::slice::from_ref(&arm.statement),
                        names,
                        seen,
                        table_size,
                    );
                }
            }
            // Conditional/iterative declarations require runtime state. The
            // preload snapshot records only declarations unconditionally
            // executed by the configured bootstrap file.
            ScriptStatement::If { .. }
            | ScriptStatement::While { .. }
            | ScriptStatement::For { .. }
            | ScriptStatement::Case { .. } => {}
            ScriptStatement::Group { body, .. } => {
                collect_preloaded_zsh_functions(body, names, seen, table_size)
            }
            ScriptStatement::Redirected { statement, .. } => collect_preloaded_zsh_functions(
                std::slice::from_ref(statement),
                names,
                seen,
                table_size,
            ),
            ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn zsh_preloaded_function_names(
    config: &ShellTranspileConfig,
) -> Result<(Vec<String>, u32), Box<dyn std::error::Error>> {
    if config.dialect != ScriptDialect::Zsh {
        return Ok((Vec::new(), 0));
    }
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut table_size = 7_u32;
    for path in &config.zsh_preload_files {
        let path = path.canonicalize()?;
        let source = read_text_bounded(&path, MAX_SCRIPT_SOURCE_BYTES)?;
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            update_preloaded_function(&mut names, &mut seen, &mut table_size, name, false);
        }
        let module = parse_script(ScriptDialect::Zsh, path.to_string_lossy(), &source)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        collect_preloaded_zsh_functions(&module.statements, &mut names, &mut seen, &mut table_size);
    }
    Ok((names, table_size))
}

struct SupportLibrary {
    dialect: ScriptDialect,
    files: HashMap<String, PathBuf>,
    functions: HashMap<String, ScriptFunction>,
    loaded_files: BTreeSet<PathBuf>,
    zsh_function_roots: Vec<PathBuf>,
    zsh_preloaded_functions: Vec<String>,
    zsh_preloaded_function_table_size: u32,
}

impl SupportLibrary {
    fn new(config: &ShellTranspileConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let (zsh_preloaded_functions, zsh_preloaded_function_table_size) =
            zsh_preloaded_function_names(config)?;
        let mut library = Self {
            dialect: config.dialect,
            files: HashMap::new(),
            functions: HashMap::new(),
            loaded_files: BTreeSet::new(),
            zsh_function_roots: config
                .zsh_function_roots
                .iter()
                .map(|root| root.canonicalize())
                .collect::<Result<Vec<_>, _>>()?,
            zsh_preloaded_functions,
            zsh_preloaded_function_table_size,
        };
        for root in &config.support_roots {
            library.index_root(&root.canonicalize()?)?;
        }
        for file in &config.support_files {
            library.load_file(&file.canonicalize()?)?;
        }
        Ok(library)
    }

    fn zsh_function_metadata(
        &self,
        source_path: &Path,
    ) -> Result<(Vec<String>, u32), Box<dyn std::error::Error>> {
        if self.dialect != ScriptDialect::Zsh {
            return Ok((Vec::new(), 0));
        }
        let mut roots = Vec::new();
        if let Some(parent) = source_path.parent() {
            roots.push(parent.canonicalize()?);
        }
        roots.extend(self.zsh_function_roots.iter().cloned());
        if self.zsh_function_roots.is_empty() {
            let mut indexed = self
                .files
                .values()
                .filter_map(|path| path.parent().map(Path::to_owned))
                .collect::<Vec<_>>();
            indexed.sort();
            indexed.dedup();
            roots.extend(indexed);
        }
        let mut seen_roots = HashSet::new();
        let mut seen_names = HashSet::new();
        let mut names = Vec::new();
        let mut name_bytes = 0_usize;
        let mut table_size = self.zsh_preloaded_function_table_size.max(7);
        for name in &self.zsh_preloaded_functions {
            if name.is_empty() || name.contains(['/', '\0']) || !seen_names.insert(name.clone()) {
                return Err("invalid preloaded Zsh function name".into());
            }
            name_bytes = name_bytes.saturating_add(name.len());
            names.push(name.clone());
        }
        if names.len() > MAX_SUPPORT_LIBRARY_FUNCTIONS || name_bytes > MAX_ZSH_FUNCTION_NAME_BYTES {
            return Err("Zsh function name snapshot limit exceeded".into());
        }
        for root in roots {
            if !seen_roots.insert(root.clone()) {
                continue;
            }
            let mut children = fs::read_dir(&root)?
                .flatten()
                .map(|entry| entry.path())
                .take(MAX_SUPPORT_LIBRARY_FILES + 1)
                .collect::<Vec<_>>();
            if children.len() > MAX_SUPPORT_LIBRARY_FILES {
                return Err("Zsh function index file limit exceeded".into());
            }
            children.sort();
            for path in children {
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !name.starts_with('_')
                    || name.ends_with('~')
                    || name.ends_with(".zwc")
                    || name.contains([';', '|', '&'])
                    || !seen_names.insert(name.to_owned())
                {
                    continue;
                }
                name_bytes = name_bytes.saturating_add(name.len());
                if names.len() >= MAX_SUPPORT_LIBRARY_FUNCTIONS
                    || name_bytes > MAX_ZSH_FUNCTION_NAME_BYTES
                {
                    return Err("Zsh function name snapshot limit exceeded".into());
                }
                names.push(name.to_owned());
                while names.len() >= table_size as usize * 2 {
                    table_size = table_size.saturating_mul(4);
                }
            }
        }
        Ok((names, table_size))
    }

    fn index_root(&mut self, root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut pending = vec![root.to_owned()];
        let mut visited = 0_usize;
        while let Some(path) = pending.pop() {
            visited = visited.saturating_add(1);
            if visited > MAX_SUPPORT_LIBRARY_FILES {
                return Err("support library file limit exceeded".into());
            }
            if path.is_dir() {
                let mut children = fs::read_dir(&path)?
                    .flatten()
                    .map(|entry| entry.path())
                    .take(MAX_SUPPORT_LIBRARY_FILES + 1)
                    .collect::<Vec<_>>();
                if children.len() > MAX_SUPPORT_LIBRARY_FILES
                    || pending.len().saturating_add(children.len()) > MAX_SUPPORT_LIBRARY_FILES
                {
                    return Err("support library file limit exceeded".into());
                }
                children.sort();
                pending.extend(children.into_iter().rev());
            } else if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
                    let stem = file_name
                        .strip_suffix(".fish")
                        .or_else(|| file_name.strip_suffix(".bash"))
                        .unwrap_or(file_name);
                    self.files.entry(stem.to_owned()).or_insert(path);
                }
            }
        }
        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if self.loaded_files.contains(path) {
            return Ok(());
        }
        if self.loaded_files.len() >= MAX_SUPPORT_LIBRARY_FILES {
            return Err("support library file limit exceeded".into());
        }
        self.loaded_files.insert(path.to_owned());
        let source = read_text_bounded(path, MAX_SCRIPT_SOURCE_BYTES)?;
        let module = parse_script(self.dialect, path.to_string_lossy(), &source)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let implicit_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| {
                value
                    .strip_suffix(".fish")
                    .or_else(|| value.strip_suffix(".bash"))
                    .unwrap_or(value)
                    .to_owned()
            });
        let has_implicit = implicit_name.as_ref().is_some_and(|name| {
            module
                .functions
                .iter()
                .any(|function| &function.name == name)
        });
        if let Some(name) = implicit_name.filter(|_| !has_implicit) {
            if self.functions.len() >= MAX_SUPPORT_LIBRARY_FUNCTIONS
                && !self.functions.contains_key(&name)
            {
                return Err("support library function limit exceeded".into());
            }
            self.functions
                .entry(name.clone())
                .or_insert(ScriptFunction {
                    name,
                    arguments: Vec::new(),
                    body: module.statements.clone(),
                });
        }
        for function in module.functions {
            if self.functions.len() >= MAX_SUPPORT_LIBRARY_FUNCTIONS
                && !self.functions.contains_key(&function.name)
            {
                return Err("support library function limit exceeded".into());
            }
            self.functions
                .entry(function.name.clone())
                .or_insert(function);
        }
        Ok(())
    }

    fn load_function(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.functions.contains_key(name) {
            return Ok(());
        }
        if let Some(path) = self.files.get(name).cloned() {
            self.load_file(&path)?;
        }
        if self.functions.contains_key(name) {
            return Ok(());
        }
        let mut generated_candidates = self
            .files
            .iter()
            .filter_map(|(stem, path)| {
                let identifier = completion_identifier(stem);
                (name.starts_with(&format!("_comp_xfunc_{identifier}_"))
                    || name.starts_with(&format!("_comp_cmd_{identifier}__compgen_")))
                .then_some((identifier.len(), stem.clone(), path.clone()))
            })
            .collect::<Vec<_>>();
        generated_candidates
            .sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        for (_, _, path) in generated_candidates {
            self.load_file(&path)?;
            if self.functions.contains_key(name) {
                break;
            }
        }
        Ok(())
    }

    fn link(
        &mut self,
        module: &mut ScriptModule,
        source_path: &Path,
    ) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
        let mut known = module
            .functions
            .iter()
            .map(|function| function.name.clone())
            .collect::<BTreeSet<_>>();
        let mut analyzed = BTreeSet::new();
        let mut pending = BTreeSet::new();
        collect_executable_calls(&module.statements, &mut pending);
        pending.extend(module.registrations.iter().filter_map(|registration| {
            if let ScriptEntry::Function { name } = &registration.entry {
                Some(name.clone())
            } else {
                None
            }
        }));
        pending.extend(dynamic_function_targets(
            module,
            &analyzed,
            self.functions.keys().chain(self.files.keys()),
        ));
        while let Some(name) = pending.pop_first() {
            if shell_vm_primitive(&name)
                || self
                    .files
                    .get(&name)
                    .is_some_and(|path| path == source_path)
            {
                continue;
            }
            if let Some(function) = module
                .functions
                .iter()
                .find(|function| function.name == name)
                .cloned()
            {
                if analyzed.insert(name) {
                    collect_executable_calls(&function.body, &mut pending);
                    pending.extend(dynamic_function_targets(
                        module,
                        &analyzed,
                        self.functions.keys().chain(self.files.keys()),
                    ));
                }
                continue;
            }
            self.load_function(&name)?;
            let Some(function) = self.functions.get(&name).cloned() else {
                continue;
            };
            if known.len() >= 16_384 {
                return Err("linked shell function limit exceeded".into());
            }
            known.insert(name.clone());
            module.functions.push(function);
            pending.insert(name);
        }
        Ok(analyzed)
    }
}

fn dynamic_function_targets<'a>(
    module: &ScriptModule,
    analyzed: &BTreeSet<String>,
    library_names: impl Iterator<Item = &'a String>,
) -> BTreeSet<String> {
    let candidate_names = library_names
        .cloned()
        .chain(
            module
                .functions
                .iter()
                .map(|function| function.name.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut prefixes = BTreeSet::new();
    let mut global_assignments = HashMap::<String, BTreeSet<String>>::new();
    let mut global_invoked = BTreeSet::new();
    collect_dynamic_function_data(
        &module.statements,
        &mut global_assignments,
        &mut global_invoked,
    );
    collect_dynamic_prefixes(&global_assignments, &global_invoked, &mut prefixes);
    let analyzed_functions = module
        .functions
        .iter()
        .filter(|function| analyzed.contains(&function.name))
        .map(|function| (function.name.clone(), function))
        .collect::<HashMap<_, _>>();
    let mut incoming = analyzed_functions
        .keys()
        .map(|name| (name.clone(), global_assignments.clone()))
        .collect::<HashMap<_, _>>();
    let nonlocal_assignments = analyzed_functions
        .iter()
        .map(|(name, function)| {
            let mut assignments = HashMap::new();
            collect_nonlocal_dynamic_assignments(&function.body, &mut assignments);
            (name.clone(), assignments)
        })
        .collect::<HashMap<_, _>>();
    for _ in 0..=analyzed_functions.len().saturating_mul(2) {
        let mut updates = Vec::new();
        for (name, function) in &analyzed_functions {
            let mut visible = incoming.get(name).cloned().unwrap_or_default();
            let mut invoked = BTreeSet::new();
            collect_dynamic_function_data(&function.body, &mut visible, &mut invoked);
            let mut calls = BTreeSet::new();
            collect_executable_calls(&function.body, &mut calls);
            calls.extend(resolved_dynamic_targets(
                &visible,
                &invoked,
                &candidate_names,
            ));
            for callee in calls
                .into_iter()
                .filter(|callee| analyzed_functions.contains_key(callee))
            {
                updates.push((callee.clone(), visible.clone()));
                if let Some(returned) = nonlocal_assignments.get(&callee) {
                    updates.push((name.clone(), returned.clone()));
                }
            }
        }
        let mut changed = false;
        for (target, values) in updates {
            changed |= merge_dynamic_assignments(incoming.entry(target).or_default(), &values);
        }
        if !changed {
            break;
        }
    }
    for (name, function) in analyzed_functions {
        let mut assignments = incoming.remove(&name).unwrap_or(global_assignments.clone());
        let mut invoked = BTreeSet::new();
        collect_dynamic_function_data(&function.body, &mut assignments, &mut invoked);
        collect_dynamic_prefixes(&assignments, &invoked, &mut prefixes);
    }
    candidate_names
        .into_iter()
        .filter(|name| {
            prefixes
                .iter()
                .any(|prefix| dynamic_target_matches(name, prefix))
        })
        .collect()
}

fn resolved_dynamic_targets(
    assignments: &HashMap<String, BTreeSet<String>>,
    invoked: &BTreeSet<String>,
    candidates: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut prefixes = BTreeSet::new();
    collect_dynamic_prefixes(assignments, invoked, &mut prefixes);
    candidates
        .iter()
        .filter(|name| {
            prefixes
                .iter()
                .any(|prefix| dynamic_target_matches(name, prefix))
        })
        .cloned()
        .collect()
}

fn dynamic_target_matches(name: &str, prefix: &str) -> bool {
    if prefix.starts_with('_') && prefix.len() >= 4 {
        name.starts_with(prefix)
    } else {
        name == prefix
    }
}

fn merge_dynamic_assignments(
    target: &mut HashMap<String, BTreeSet<String>>,
    source: &HashMap<String, BTreeSet<String>>,
) -> bool {
    let mut changed = false;
    for (name, values) in source {
        let target_values = target.entry(name.clone()).or_default();
        let before = target_values.len();
        target_values.extend(values.iter().cloned());
        changed |= target_values.len() != before;
    }
    changed
}

fn collect_dynamic_prefixes(
    assignments: &HashMap<String, BTreeSet<String>>,
    invoked: &BTreeSet<String>,
    prefixes: &mut BTreeSet<String>,
) {
    prefixes.extend(
        invoked
            .iter()
            .filter_map(|name| assignments.get(name))
            .flatten()
            .filter(|prefix| {
                !prefix.is_empty()
                    && !prefix.contains(['/', '\0'])
                    && !prefix
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
            })
            .cloned(),
    );
}

fn collect_nonlocal_dynamic_assignments(
    statements: &[ScriptStatement],
    assignments: &mut HashMap<String, BTreeSet<String>>,
) {
    let mut local_names = HashSet::new();
    collect_nonlocal_dynamic_assignment_data(statements, assignments, &mut local_names);
}

fn collect_nonlocal_dynamic_assignment_data(
    statements: &[ScriptStatement],
    assignments: &mut HashMap<String, BTreeSet<String>>,
    local_names: &mut HashSet<String>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                let declaration = command
                    .words
                    .first()
                    .and_then(ScriptWord::as_unquoted_plain_literal);
                let explicit_global = matches!(declaration, Some("declare" | "typeset"))
                    && command.words.iter().skip(1).any(|word| {
                        word.as_unquoted_plain_literal().is_some_and(|value| {
                            value.starts_with('-') && value.trim_start_matches('-').contains('g')
                        })
                    });
                let declares_local = matches!(declaration, Some("local" | "declare" | "typeset"))
                    && !explicit_global;
                let persistent_nonlocal = command.words.is_empty()
                    || explicit_global
                    || matches!(declaration, Some("export" | "readonly"));
                for assignment in &command.assignments {
                    if declares_local {
                        local_names.insert(assignment.name.clone());
                    } else if !local_names.contains(&assignment.name) && persistent_nonlocal {
                        collect_word_literal_prefixes(
                            &assignment.value,
                            assignments.entry(assignment.name.clone()).or_default(),
                        );
                    }
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_nonlocal_dynamic_assignment_data(commands, assignments, local_names)
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_nonlocal_dynamic_assignment_data(
                    std::slice::from_ref(first),
                    assignments,
                    local_names,
                );
                for arm in rest {
                    let mut branch_locals = local_names.clone();
                    collect_nonlocal_dynamic_assignment_data(
                        std::slice::from_ref(&arm.statement),
                        assignments,
                        &mut branch_locals,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    let mut branch_locals = local_names.clone();
                    collect_nonlocal_dynamic_assignment_data(
                        &branch.condition,
                        assignments,
                        &mut branch_locals,
                    );
                    collect_nonlocal_dynamic_assignment_data(
                        &branch.body,
                        assignments,
                        &mut branch_locals,
                    );
                }
                let mut branch_locals = local_names.clone();
                collect_nonlocal_dynamic_assignment_data(
                    otherwise,
                    assignments,
                    &mut branch_locals,
                );
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                let mut branch_locals = local_names.clone();
                collect_nonlocal_dynamic_assignment_data(
                    condition,
                    assignments,
                    &mut branch_locals,
                );
                collect_nonlocal_dynamic_assignment_data(body, assignments, &mut branch_locals);
            }
            ScriptStatement::For { body, .. } => {
                let mut branch_locals = local_names.clone();
                collect_nonlocal_dynamic_assignment_data(body, assignments, &mut branch_locals)
            }
            ScriptStatement::Group { body, .. } => {
                collect_nonlocal_dynamic_assignment_data(body, assignments, local_names)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    let mut branch_locals = local_names.clone();
                    collect_nonlocal_dynamic_assignment_data(
                        &arm.body,
                        assignments,
                        &mut branch_locals,
                    );
                }
            }
            ScriptStatement::Redirected { statement, .. } => {
                collect_nonlocal_dynamic_assignment_data(
                    std::slice::from_ref(statement),
                    assignments,
                    local_names,
                )
            }
            ScriptStatement::Function { .. }
            | ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn collect_dynamic_function_data(
    statements: &[ScriptStatement],
    assignments: &mut HashMap<String, BTreeSet<String>>,
    invoked: &mut BTreeSet<String>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                if let Some(word) = command.words.first() {
                    if let Some(ScriptWordPart::Parameter { expression, .. }) = word.parts.first() {
                        let name = expression
                            .trim_start_matches('(')
                            .split(['[', ']', '/', ':', '}', ')'])
                            .next()
                            .unwrap_or("");
                        if !name.is_empty() {
                            invoked.insert(name.to_owned());
                        }
                    }
                }
                for assignment in &command.assignments {
                    collect_word_literal_prefixes(
                        &assignment.value,
                        assignments.entry(assignment.name.clone()).or_default(),
                    );
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_dynamic_function_data(commands, assignments, invoked)
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_dynamic_function_data(std::slice::from_ref(first), assignments, invoked);
                for arm in rest {
                    collect_dynamic_function_data(
                        std::slice::from_ref(&arm.statement),
                        assignments,
                        invoked,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_dynamic_function_data(&branch.condition, assignments, invoked);
                    collect_dynamic_function_data(&branch.body, assignments, invoked);
                }
                collect_dynamic_function_data(otherwise, assignments, invoked);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_dynamic_function_data(condition, assignments, invoked);
                collect_dynamic_function_data(body, assignments, invoked);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_dynamic_function_data(body, assignments, invoked)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_dynamic_function_data(&arm.body, assignments, invoked);
                }
            }
            ScriptStatement::Function { .. } => {}
            ScriptStatement::Redirected { statement, .. } => {
                collect_dynamic_function_data(std::slice::from_ref(statement), assignments, invoked)
            }
            ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn collect_word_literal_prefixes(word: &ScriptWord, prefixes: &mut BTreeSet<String>) {
    match word.parts.as_slice() {
        [ScriptWordPart::Array { elements }] => {
            for element in elements {
                collect_word_literal_prefixes(element, prefixes);
            }
        }
        parts => {
            let prefix = parts
                .iter()
                .map_while(|part| match part {
                    ScriptWordPart::Literal { value, .. } => Some(value.as_str()),
                    _ => None,
                })
                .collect::<String>();
            if !prefix.is_empty() {
                prefixes.insert(prefix);
            }
        }
    }
}

fn completion_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character == '_' || character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn comp_compgen_dynamic_target(command: &bashlume::rules::script::ScriptCommand) -> Option<String> {
    let words = command
        .words
        .iter()
        .map(ScriptWord::as_unquoted_plain_literal)
        .collect::<Vec<_>>();
    let mut external_command = None;
    let mut internal_command = None;
    let mut index = 1_usize;
    while index < words.len() {
        let value = words[index]?;
        if value == "--" {
            return None;
        }
        if !value.starts_with('-') || value == "-" {
            let generator = completion_identifier(value);
            return if let Some(command) = external_command {
                Some(format!(
                    "_comp_xfunc_{}_compgen_{generator}",
                    completion_identifier(command)
                ))
            } else if let Some(command) = internal_command {
                Some(format!(
                    "_comp_cmd_{}__compgen_{generator}",
                    completion_identifier(command)
                ))
            } else {
                Some(format!("_comp_compgen_{generator}"))
            };
        }
        let flags = value.trim_start_matches('-').as_bytes();
        let mut flag_index = 0_usize;
        while flag_index < flags.len() {
            let flag = flags[flag_index] as char;
            if matches!(flag, 'x' | 'i' | 'F' | 'v' | 'c' | 'P') {
                let attached = std::str::from_utf8(&flags[flag_index + 1..]).ok()?;
                let argument = if attached.is_empty() {
                    index += 1;
                    words.get(index).copied().flatten()?
                } else {
                    attached
                };
                if flag == 'x' {
                    external_command = Some(argument);
                } else if flag == 'i' {
                    internal_command = Some(argument);
                }
                break;
            }
            flag_index += 1;
        }
        index += 1;
    }
    None
}

fn collect_executable_calls(statements: &[ScriptStatement], calls: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                if let Some(name) = command
                    .words
                    .first()
                    .and_then(|word| word.as_unquoted_plain_literal())
                {
                    calls.insert(name.to_owned());
                    if name == "_comp_compgen" {
                        if let Some(target) = comp_compgen_dynamic_target(command) {
                            calls.insert(target);
                        }
                    }
                    if name == "_comp_xfunc" {
                        let namespace = command
                            .words
                            .get(1)
                            .and_then(ScriptWord::as_unquoted_plain_literal);
                        let target = command
                            .words
                            .get(2)
                            .and_then(ScriptWord::as_unquoted_plain_literal);
                        if let (Some(namespace), Some(target)) = (namespace, target) {
                            if target.starts_with('_') {
                                calls.insert(target.to_owned());
                            } else {
                                let namespace = completion_identifier(namespace);
                                calls.insert(format!("_comp_xfunc_{namespace}_{target}"));
                            }
                        }
                    }
                    if matches!(
                        name,
                        "command" | "builtin" | "exec" | "noglob" | "not" | "!" | "and" | "or"
                    ) {
                        if let Some(target) = command
                            .words
                            .iter()
                            .skip(1)
                            .filter_map(|word| word.as_unquoted_plain_literal())
                            .find(|argument| !argument.starts_with('-'))
                        {
                            calls.insert(target.to_owned());
                        }
                    }
                }
                for assignment in &command.assignments {
                    if let Some(index) = &assignment.index {
                        collect_word_calls(index, calls);
                    }
                    collect_word_calls(&assignment.value, calls);
                }
                for word in &command.words {
                    collect_word_calls(word, calls);
                }
            }
            ScriptStatement::Pipeline { commands, .. } => collect_executable_calls(commands, calls),
            ScriptStatement::AndOr { first, rest } => {
                collect_executable_calls(std::slice::from_ref(first), calls);
                for arm in rest {
                    collect_executable_calls(std::slice::from_ref(&arm.statement), calls);
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_executable_calls(&branch.condition, calls);
                    collect_executable_calls(&branch.body, calls);
                }
                collect_executable_calls(otherwise, calls);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_executable_calls(condition, calls);
                collect_executable_calls(body, calls);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_executable_calls(body, calls)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_executable_calls(&arm.body, calls);
                }
            }
            ScriptStatement::Function { .. } => {}
            ScriptStatement::Redirected {
                statement,
                redirections,
            } => {
                collect_executable_calls(std::slice::from_ref(statement), calls);
                for redirection in redirections {
                    collect_word_calls(&redirection.target, calls);
                }
            }
            _ => {}
        }
    }
}

fn collect_word_calls(word: &ScriptWord, calls: &mut BTreeSet<String>) {
    for part in &word.parts {
        match part {
            ScriptWordPart::CommandSubstitution { statements, .. } => {
                collect_executable_calls(statements, calls);
            }
            ScriptWordPart::DeferredScript {
                statements, words, ..
            } => {
                collect_executable_calls(statements, calls);
                for word in words {
                    collect_word_calls(word, calls);
                }
            }
            ScriptWordPart::Array { elements }
            | ScriptWordPart::BraceExpansion {
                alternatives: elements,
                ..
            } => {
                for element in elements {
                    collect_word_calls(element, calls);
                }
            }
            ScriptWordPart::Literal { value, .. } => {
                collect_completion_action_calls(value, calls);
            }
            ScriptWordPart::Parameter { .. } | ScriptWordPart::Arithmetic { .. } => {}
        }
    }
}

fn collect_completion_action_calls(value: &str, calls: &mut BTreeSet<String>) {
    if !value.contains('[') {
        if let Some(token) = value.split_ascii_whitespace().next() {
            collect_completion_function_token(token, calls);
        }
    }
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
        if character != ':' {
            continue;
        }
        for token in value[index + 1..].split_ascii_whitespace() {
            collect_completion_function_token(token, calls);
        }
    }
}

fn collect_completion_function_token(token: &str, calls: &mut BTreeSet<String>) {
    let token = token.trim_matches(|character: char| {
        matches!(character, '\'' | '"' | '(' | ')' | '{' | '}' | ';' | '|')
    });
    let Some(name) = token.strip_prefix('_').map(|name| format!("_{name}")) else {
        return;
    };
    let end = name
        .char_indices()
        .take_while(|(_, character)| {
            *character == '_' || *character == '-' || character.is_ascii_alphanumeric()
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    if end > 1 {
        calls.insert(name[..end].to_owned());
    }
}

fn collect_probe_calls(
    statements: &[ScriptStatement],
    observed: bool,
    data_observed: bool,
    calls: &mut BTreeSet<String>,
    data_calls: &mut BTreeSet<String>,
    declared: &mut BTreeSet<String>,
) {
    for (statement_index, statement) in statements.iter().enumerate() {
        let followed_by_fish_boolean = statements
            .get(statement_index + 1)
            .and_then(|statement| match statement {
                ScriptStatement::Command { command } => command
                    .words
                    .first()
                    .and_then(ScriptWord::as_unquoted_plain_literal),
                _ => None,
            })
            .is_some_and(|name| matches!(name, "and" | "or"));
        let statement_observed = observed || followed_by_fish_boolean;
        match statement {
            ScriptStatement::Command { command } => {
                declared.extend(
                    command
                        .assignments
                        .iter()
                        .map(|assignment| assignment.name.clone()),
                );
                let command_name = command
                    .words
                    .first()
                    .and_then(|word| word.as_unquoted_plain_literal());
                if matches!(
                    command_name,
                    Some("local" | "typeset" | "declare" | "integer" | "set")
                ) {
                    let names = command
                        .words
                        .iter()
                        .skip(1)
                        .filter_map(|word| word.as_plain_literal())
                        .filter(|word| !word.starts_with('-'))
                        .map(|word| word.split_once('=').map_or(word, |(name, _)| name));
                    if command_name == Some("set") {
                        if let Some(name) = names.into_iter().next() {
                            declared.insert(name.to_owned());
                        }
                    } else {
                        declared.extend(names.map(str::to_owned));
                    }
                }
                if command_name == Some("_call_program") {
                    let mut tag_index = None;
                    for (index, word) in command.words.iter().enumerate().skip(1) {
                        let Some(value) = word.as_plain_literal() else {
                            continue;
                        };
                        if !value.starts_with('-') {
                            tag_index = Some(index);
                            break;
                        }
                    }
                    if let Some(command_word) =
                        tag_index.and_then(|index| command.words.get(index + 1))
                    {
                        let target = command_word.as_plain_literal().and_then(|value| {
                            value
                                .split_whitespace()
                                .find(|word| {
                                    !word.starts_with('-') && !matches!(*word, "noglob" | "command")
                                })
                                .map(str::to_owned)
                        });
                        let target = target
                            .map(|target| format!("@external:{target}"))
                            .unwrap_or_else(|| "@registration-service".into());
                        calls.insert(target.clone());
                        data_calls.insert(target);
                    }
                }
                if statement_observed {
                    let positional_dispatch = command.words.first().is_some_and(|word| {
                        word.parts.first().is_some_and(|part| {
                            if let ScriptWordPart::Parameter { expression, .. } = part {
                                let name = expression
                                    .trim_start_matches('(')
                                    .split(['[', ']', '/', ':', '}', ')'])
                                    .next()
                                    .unwrap_or("");
                                !name.is_empty()
                                    && (name.bytes().all(|byte| byte.is_ascii_digit())
                                        || matches!(name, "@" | "*" | "argv" | "words"))
                            } else {
                                false
                            }
                        })
                    });
                    if command_name.is_none() && positional_dispatch {
                        calls.insert("@registration-service".into());
                        if data_observed {
                            data_calls.insert("@registration-service".into());
                        }
                    }
                    if let Some(name) = command_name {
                        calls.insert(name.to_owned());
                        if data_observed {
                            data_calls.insert(name.to_owned());
                        }
                        if matches!(name, "command" | "builtin" | "exec" | "noglob")
                            && !command_is_availability_query(command)
                        {
                            let target_word = command.words.iter().skip(1).find(|word| {
                                word.as_unquoted_plain_literal()
                                    .is_none_or(|argument| !argument.starts_with('-'))
                            });
                            if let Some(target) =
                                target_word.and_then(ScriptWord::as_unquoted_plain_literal)
                            {
                                let target = format!("@external:{target}");
                                calls.insert(target.clone());
                                if data_observed {
                                    data_calls.insert(target);
                                }
                            } else if target_word.is_some_and(word_uses_registration_service) {
                                calls.insert("@registration-service".into());
                                if data_observed {
                                    data_calls.insert("@registration-service".into());
                                }
                            }
                        }
                    }
                }
                for assignment in &command.assignments {
                    if let Some(index) = &assignment.index {
                        collect_word_probe_calls(index, calls, data_calls, declared);
                    }
                    collect_word_probe_calls(&assignment.value, calls, data_calls, declared);
                }
                for word in &command.words {
                    collect_word_probe_calls(word, calls, data_calls, declared);
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                for (index, command) in commands.iter().enumerate() {
                    let data = data_observed || index + 1 < commands.len();
                    collect_probe_calls(
                        std::slice::from_ref(command),
                        observed || data,
                        data,
                        calls,
                        data_calls,
                        declared,
                    );
                }
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_probe_calls(
                    std::slice::from_ref(first),
                    !rest.is_empty() || observed,
                    data_observed && rest.is_empty(),
                    calls,
                    data_calls,
                    declared,
                );
                for (index, arm) in rest.iter().enumerate() {
                    let last = index + 1 == rest.len();
                    collect_probe_calls(
                        std::slice::from_ref(&arm.statement),
                        observed || !last,
                        data_observed && last,
                        calls,
                        data_calls,
                        declared,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_probe_calls(
                        &branch.condition,
                        true,
                        false,
                        calls,
                        data_calls,
                        declared,
                    );
                    collect_probe_calls(
                        &branch.body,
                        observed,
                        data_observed,
                        calls,
                        data_calls,
                        declared,
                    );
                }
                collect_probe_calls(
                    otherwise,
                    observed,
                    data_observed,
                    calls,
                    data_calls,
                    declared,
                );
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_probe_calls(condition, true, false, calls, data_calls, declared);
                collect_probe_calls(body, observed, data_observed, calls, data_calls, declared);
            }
            ScriptStatement::For { words, body, .. } => {
                for word in words {
                    collect_word_probe_calls(word, calls, data_calls, declared);
                }
                collect_probe_calls(body, observed, data_observed, calls, data_calls, declared);
            }
            ScriptStatement::Group { body, .. } => {
                collect_probe_calls(body, observed, data_observed, calls, data_calls, declared);
            }
            ScriptStatement::Case { word, arms } => {
                collect_word_probe_calls(word, calls, data_calls, declared);
                for arm in arms {
                    collect_probe_calls(
                        &arm.body,
                        observed,
                        data_observed,
                        calls,
                        data_calls,
                        declared,
                    );
                }
            }
            ScriptStatement::Redirected {
                statement,
                redirections,
            } => {
                collect_probe_calls(
                    std::slice::from_ref(statement),
                    observed,
                    data_observed,
                    calls,
                    data_calls,
                    declared,
                );
                for redirection in redirections {
                    collect_word_probe_calls(&redirection.target, calls, data_calls, declared);
                }
            }
            ScriptStatement::Function { .. }
            | ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn collect_word_probe_calls(
    word: &ScriptWord,
    calls: &mut BTreeSet<String>,
    data_calls: &mut BTreeSet<String>,
    declared: &mut BTreeSet<String>,
) {
    for part in &word.parts {
        match part {
            ScriptWordPart::CommandSubstitution { statements, .. } => {
                collect_probe_calls(statements, true, true, calls, data_calls, declared);
            }
            ScriptWordPart::DeferredScript {
                statements, words, ..
            } => {
                collect_probe_calls(statements, true, true, calls, data_calls, declared);
                for word in words {
                    collect_word_probe_calls(word, calls, data_calls, declared);
                }
            }
            ScriptWordPart::Array { elements }
            | ScriptWordPart::BraceExpansion {
                alternatives: elements,
                ..
            } => {
                for element in elements {
                    collect_word_probe_calls(element, calls, data_calls, declared);
                }
            }
            _ => {}
        }
    }
}

fn command_is_availability_query(command: &bashlume::rules::script::ScriptCommand) -> bool {
    command
        .words
        .iter()
        .skip(1)
        .filter_map(ScriptWord::as_unquoted_plain_literal)
        .take_while(|argument| argument.starts_with('-'))
        .any(|argument| {
            matches!(argument, "--query" | "--search" | "--verbose" | "--path")
                || argument.strip_prefix('-').is_some_and(|flags| {
                    flags
                        .chars()
                        .any(|flag| matches!(flag, 'q' | 's' | 'v' | 'V'))
                })
        })
}

fn word_uses_registration_service(word: &ScriptWord) -> bool {
    word.parts.iter().any(|part| {
        let ScriptWordPart::Parameter { expression, .. } = part else {
            return false;
        };
        let expression = expression.trim_matches(|character| matches!(character, '{' | '}'));
        matches!(expression, "1" | "service" | "words[1]" | "argv[1]")
    })
}

fn abstract_registration_word_values(
    word: &ScriptWord,
    registrations: &[String],
    variables: &HashMap<String, BTreeSet<String>>,
) -> Option<BTreeSet<String>> {
    let mut values = BTreeSet::from([String::new()]);
    for part in &word.parts {
        let additions = match part {
            ScriptWordPart::Literal { value, .. } => BTreeSet::from([value.clone()]),
            ScriptWordPart::Parameter { expression, .. } => {
                let expression =
                    expression.trim_matches(|character| matches!(character, '{' | '}'));
                let name_end = expression
                    .char_indices()
                    .take_while(|(_, character)| {
                        *character == '_' || character.is_ascii_alphanumeric()
                    })
                    .map(|(index, character)| index + character.len_utf8())
                    .last()
                    .unwrap_or(0);
                let name = &expression[..name_end];
                let rest = &expression[name_end..];
                let mut expanded = if matches!(name, "1" | "service" | "words" | "argv") {
                    registrations.iter().cloned().collect::<BTreeSet<_>>()
                } else {
                    variables.get(name)?.clone()
                };
                if let Some(suffix) = rest.strip_prefix("%%").or_else(|| rest.strip_prefix('%')) {
                    if !suffix.contains(['*', '?', '[']) {
                        expanded = expanded
                            .into_iter()
                            .map(|value| {
                                value
                                    .strip_suffix(suffix)
                                    .map_or(value.clone(), str::to_owned)
                            })
                            .collect();
                    }
                } else if let Some(prefix) =
                    rest.strip_prefix("##").or_else(|| rest.strip_prefix('#'))
                {
                    if !prefix.contains(['*', '?', '[']) {
                        expanded = expanded
                            .into_iter()
                            .map(|value| {
                                value
                                    .strip_prefix(prefix)
                                    .map_or(value.clone(), str::to_owned)
                            })
                            .collect();
                    }
                } else if !rest.is_empty() && !matches!(rest, "[0]" | "[1]") {
                    return None;
                }
                expanded
            }
            ScriptWordPart::Array { elements } => {
                let mut expanded = BTreeSet::new();
                for element in elements {
                    expanded.extend(abstract_registration_word_values(
                        element,
                        registrations,
                        variables,
                    )?);
                }
                expanded
            }
            ScriptWordPart::BraceExpansion { alternatives, .. } => {
                let mut expanded = BTreeSet::new();
                for alternative in alternatives {
                    expanded.extend(abstract_registration_word_values(
                        alternative,
                        registrations,
                        variables,
                    )?);
                }
                expanded
            }
            ScriptWordPart::CommandSubstitution { .. }
            | ScriptWordPart::DeferredScript { .. }
            | ScriptWordPart::Arithmetic { .. } => return None,
        };
        let mut combined = BTreeSet::new();
        for value in &values {
            for addition in &additions {
                if combined.len() >= 4096 {
                    return None;
                }
                combined.insert(format!("{value}{addition}"));
            }
        }
        values = combined;
    }
    Some(values)
}

fn collect_derived_external_capabilities(
    statements: &[ScriptStatement],
    registrations: &[String],
    variables: &mut HashMap<String, BTreeSet<String>>,
    output: &mut BTreeSet<String>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                for assignment in &command.assignments {
                    if let Some(values) = abstract_registration_word_values(
                        &assignment.value,
                        registrations,
                        variables,
                    ) {
                        variables.insert(assignment.name.clone(), values);
                    }
                }
                let command_word = if command
                    .words
                    .first()
                    .and_then(ScriptWord::as_unquoted_plain_literal)
                    .is_some_and(|name| matches!(name, "command" | "builtin" | "exec" | "noglob"))
                {
                    command.words.get(1)
                } else {
                    command.words.first()
                };
                if let Some(ScriptWordPart::Parameter { expression, .. }) =
                    command_word.and_then(|word| word.parts.first())
                {
                    let name = expression
                        .trim_matches(|character| matches!(character, '{' | '}'))
                        .split(['[', ':', '/', '%', '#'])
                        .next()
                        .unwrap_or_default();
                    if let Some(values) = variables.get(name) {
                        output.extend(values.iter().cloned());
                    }
                }
                for word in &command.words {
                    for part in &word.parts {
                        if let ScriptWordPart::CommandSubstitution { statements, .. }
                        | ScriptWordPart::DeferredScript { statements, .. } = part
                        {
                            collect_derived_external_capabilities(
                                statements,
                                registrations,
                                variables,
                                output,
                            );
                        }
                    }
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_derived_external_capabilities(commands, registrations, variables, output)
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_derived_external_capabilities(
                    std::slice::from_ref(first),
                    registrations,
                    variables,
                    output,
                );
                for arm in rest {
                    collect_derived_external_capabilities(
                        std::slice::from_ref(&arm.statement),
                        registrations,
                        variables,
                        output,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_derived_external_capabilities(
                        &branch.condition,
                        registrations,
                        variables,
                        output,
                    );
                    collect_derived_external_capabilities(
                        &branch.body,
                        registrations,
                        variables,
                        output,
                    );
                }
                collect_derived_external_capabilities(otherwise, registrations, variables, output);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_derived_external_capabilities(condition, registrations, variables, output);
                collect_derived_external_capabilities(body, registrations, variables, output);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_derived_external_capabilities(body, registrations, variables, output)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_derived_external_capabilities(
                        &arm.body,
                        registrations,
                        variables,
                        output,
                    );
                }
            }
            ScriptStatement::Redirected { statement, .. } => collect_derived_external_capabilities(
                std::slice::from_ref(statement),
                registrations,
                variables,
                output,
            ),
            ScriptStatement::Function { .. }
            | ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn collect_positional_command_call_arguments(
    statements: &[ScriptStatement],
    targets: &BTreeSet<String>,
    output: &mut BTreeSet<String>,
) {
    for statement in statements {
        match statement {
            ScriptStatement::Command { command } => {
                let target = command
                    .words
                    .first()
                    .and_then(ScriptWord::as_unquoted_plain_literal);
                if target.is_some_and(|target| targets.contains(target)) {
                    if let Some(argument) = command
                        .words
                        .iter()
                        .skip(1)
                        .find_map(ScriptWord::as_unquoted_plain_literal)
                        .filter(|argument| !argument.starts_with('-'))
                    {
                        output.insert(argument.to_owned());
                    }
                }
            }
            ScriptStatement::Pipeline { commands, .. } => {
                collect_positional_command_call_arguments(commands, targets, output)
            }
            ScriptStatement::AndOr { first, rest } => {
                collect_positional_command_call_arguments(
                    std::slice::from_ref(first),
                    targets,
                    output,
                );
                for arm in rest {
                    collect_positional_command_call_arguments(
                        std::slice::from_ref(&arm.statement),
                        targets,
                        output,
                    );
                }
            }
            ScriptStatement::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_positional_command_call_arguments(&branch.condition, targets, output);
                    collect_positional_command_call_arguments(&branch.body, targets, output);
                }
                collect_positional_command_call_arguments(otherwise, targets, output);
            }
            ScriptStatement::While {
                condition, body, ..
            } => {
                collect_positional_command_call_arguments(condition, targets, output);
                collect_positional_command_call_arguments(body, targets, output);
            }
            ScriptStatement::For { body, .. } | ScriptStatement::Group { body, .. } => {
                collect_positional_command_call_arguments(body, targets, output)
            }
            ScriptStatement::Case { arms, .. } => {
                for arm in arms {
                    collect_positional_command_call_arguments(&arm.body, targets, output);
                }
            }
            ScriptStatement::Redirected { statement, .. } => {
                collect_positional_command_call_arguments(
                    std::slice::from_ref(statement),
                    targets,
                    output,
                )
            }
            ScriptStatement::Function { .. }
            | ScriptStatement::Return { .. }
            | ScriptStatement::Break
            | ScriptStatement::Continue
            | ScriptStatement::Noop => {}
        }
    }
}

fn script_probe_capabilities(
    module: &ScriptModule,
    reachable_functions: &BTreeSet<String>,
) -> Vec<String> {
    let mut calls = BTreeSet::new();
    let mut data_calls = BTreeSet::new();
    let mut declared = BTreeSet::new();
    collect_probe_calls(
        &module.statements,
        false,
        false,
        &mut calls,
        &mut data_calls,
        &mut declared,
    );
    collect_executable_calls(&module.statements, &mut calls);
    calls.extend(reachable_functions.iter().cloned());
    for entry in module.registrations.iter().filter_map(|registration| {
        if let ScriptEntry::Function { name } = &registration.entry {
            Some(name.as_str())
        } else {
            None
        }
    }) {
        if let Some(function) = module
            .functions
            .iter()
            .find(|function| function.name == entry)
        {
            collect_probe_calls(
                &function.body,
                true,
                true,
                &mut calls,
                &mut data_calls,
                &mut declared,
            );
        }
    }
    let functions_by_name = module
        .functions
        .iter()
        .map(|function| (function.name.as_str(), function))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut linked = BTreeSet::new();
    loop {
        let pending = calls
            .iter()
            .filter(|name| functions_by_name.contains_key(name.as_str()) && !linked.contains(*name))
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            break;
        }
        for name in pending {
            linked.insert(name.clone());
            let data = data_calls.contains(&name);
            collect_probe_calls(
                &functions_by_name[name.as_str()].body,
                true,
                data,
                &mut calls,
                &mut data_calls,
                &mut declared,
            );
            collect_executable_calls(&functions_by_name[name.as_str()].body, &mut calls);
        }
    }
    let registration_executables = if calls.remove("@registration-service") {
        let mut executables = module
            .registrations
            .iter()
            .map(|registration| {
                registration
                    .service
                    .as_deref()
                    .unwrap_or(&registration.command)
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let positional_targets = module
            .functions
            .iter()
            .filter(|function| linked.contains(&function.name))
            .filter(|function| {
                let mut function_calls = BTreeSet::new();
                let mut function_data_calls = BTreeSet::new();
                let mut function_declared = BTreeSet::new();
                collect_probe_calls(
                    &function.body,
                    true,
                    true,
                    &mut function_calls,
                    &mut function_data_calls,
                    &mut function_declared,
                );
                function_calls.contains("@registration-service")
            })
            .map(|function| function.name.clone())
            .collect::<BTreeSet<_>>();
        collect_positional_command_call_arguments(
            &module.statements,
            &positional_targets,
            &mut executables,
        );
        for function in module
            .functions
            .iter()
            .filter(|function| linked.contains(&function.name))
        {
            collect_positional_command_call_arguments(
                &function.body,
                &positional_targets,
                &mut executables,
            );
        }
        executables.into_iter().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let registrations = module
        .registrations
        .iter()
        .map(|registration| {
            registration
                .service
                .as_deref()
                .unwrap_or(&registration.command)
                .to_owned()
        })
        .collect::<Vec<_>>();
    let mut derived_external = BTreeSet::new();
    collect_derived_external_capabilities(
        &module.statements,
        &registrations,
        &mut HashMap::new(),
        &mut derived_external,
    );
    for function in module
        .functions
        .iter()
        .filter(|function| linked.contains(&function.name))
    {
        collect_derived_external_capabilities(
            &function.body,
            &registrations,
            &mut HashMap::new(),
            &mut derived_external,
        );
    }
    calls.extend(derived_external);
    let forced_external = calls
        .iter()
        .filter_map(|name| name.strip_prefix("@external:").map(str::to_owned))
        .chain(registration_executables)
        .collect::<BTreeSet<_>>();
    calls.retain(|name| !name.starts_with("@external:"));
    let functions = functions_by_name.keys().copied().collect::<BTreeSet<_>>();
    calls.retain(|name| !functions.contains(name.as_str()) && !shell_vm_primitive(name));
    calls.extend(forced_external);
    calls = calls
        .into_iter()
        .map(|name| name.rsplit('/').next().unwrap_or_default().to_owned())
        .collect();
    calls.retain(|name| {
        !matches!(name.as_bytes().first(), Some(b'_' | b'.' | b'-'))
            && !matches!(name.as_str(), "sh" | "bash" | "dash" | "zsh" | "fish")
            && !name.bytes().all(|byte| byte.is_ascii_digit())
            && name.bytes().all(|byte| {
                matches!(byte, b'_' | b'-' | b'.' | b'+') || byte.is_ascii_alphanumeric()
            })
    });
    calls.into_iter().collect()
}

fn shell_vm_primitive(name: &str) -> bool {
    matches!(
        name,
        "" | ":"
            | "."
            | "!"
            | "_alternative"
            | "_arguments"
            | "_call_function"
            | "_call_program"
            | "_comp_xfunc"
            | "_default"
            | "_describe"
            | "_description"
            | "_directories"
            | "_files"
            | "_message"
            | "_path_files"
            | "_regex_arguments"
            | "_values"
            | "["
            | "[["
            | "(("
            | "alias"
            | "always"
            | "and"
            | "argparse"
            | "autoload"
            | "basename"
            | "begin"
            | "bg"
            | "bind"
            | "block"
            | "break"
            | "breakpoint"
            | "builtin"
            | "caller"
            | "case"
            | "cd"
            | "command"
            | "commandline"
            | "comparguments"
            | "compadd"
            | "compcall"
            | "compdescribe"
            | "compfiles"
            | "compgroups"
            | "compquote"
            | "comptags"
            | "comptry"
            | "compvalues"
            | "compdef"
            | "compgen"
            | "complete"
            | "compopt"
            | "compset"
            | "contains"
            | "continue"
            | "coproc"
            | "count"
            | "cut"
            | "declare"
            | "dirs"
            | "dirname"
            | "disown"
            | "echo"
            | "elif"
            | "else"
            | "emit"
            | "emulate"
            | "enable"
            | "end"
            | "eval"
            | "exec"
            | "exit"
            | "export"
            | "false"
            | "fc"
            | "fg"
            | "fi"
            | "fish_indent"
            | "fish_key_reader"
            | "for"
            | "foreach"
            | "functions"
            | "getent"
            | "getopts"
            | "grep"
            | "hash"
            | "head"
            | "help"
            | "history"
            | "if"
            | "integer"
            | "jobs"
            | "kill"
            | "let"
            | "local"
            | "logout"
            | "mapfile"
            | "math"
            | "noglob"
            | "not"
            | "or"
            | "path"
            | "popd"
            | "print"
            | "printf"
            | "pushd"
            | "pwd"
            | "random"
            | "read"
            | "readarray"
            | "readonly"
            | "realpath"
            | "repeat"
            | "return"
            | "sed"
            | "seq"
            | "select"
            | "set"
            | "set_color"
            | "setopt"
            | "shift"
            | "shopt"
            | "sort"
            | "source"
            | "status"
            | "strftime"
            | "string"
            | "suspend"
            | "switch"
            | "tail"
            | "test"
            | "then"
            | "time"
            | "times"
            | "trap"
            | "tr"
            | "true"
            | "type"
            | "typeset"
            | "ulimit"
            | "umask"
            | "unalias"
            | "unfunction"
            | "uniq"
            | "unset"
            | "unsetopt"
            | "wait"
            | "while"
            | "whence"
            | "zdelattr"
            | "zformat"
            | "zftp"
            | "zf_ln"
            | "zgetattr"
            | "zle"
            | "zlistattr"
            | "zmodload"
            | "zparseopts"
            | "zsetattr"
            | "zstat"
            | "zstyle"
    )
}

fn transpile_shell(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() < 4 {
        return usage();
    }
    let mut config: ShellTranspileConfig = serde_json::from_slice(&read_bytes_bounded(
        Path::new(&arguments[0]),
        8 * 1024 * 1024,
    )?)?;
    let expected_source = match config.dialect {
        ScriptDialect::Bash => SourceKind::Bash,
        ScriptDialect::Zsh => SourceKind::Zsh,
        ScriptDialect::Fish => SourceKind::Fish,
    };
    if config.manifest.source_kind != expected_source {
        return Err("transpile dialect does not match manifest source kind".into());
    }
    if !config.manifest.stale_commands.is_empty() {
        return Err("transpiled shell packs cannot declare stale commands".into());
    }

    let source_root = config.source_root.canonicalize()?;
    let mut support = SupportLibrary::new(&config)?;
    let mut groups = Vec::<ScriptGroup>::new();
    let mut report_files = Vec::new();
    let mut all_registrations = BTreeSet::new();
    let mut all_probe_capabilities = BTreeSet::new();
    for source_path in &arguments[3..] {
        let source_path = Path::new(source_path).canonicalize()?;
        let source = read_text_bounded(&source_path, MAX_SCRIPT_SOURCE_BYTES)?;
        let relative = source_path
            .strip_prefix(&source_root)
            .map_err(|_| format!("{} is outside source root", source_path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let mut module = parse_script(config.dialect, &relative, &source)
            .map_err(|error| format!("{}: {error}", source_path.display()))?;
        module.source_path = relative.clone();
        let (zsh_function_names, zsh_function_table_size) =
            support.zsh_function_metadata(&source_path)?;
        module.zsh_function_snapshot = config.dialect == ScriptDialect::Zsh;
        module.zsh_function_table_size = zsh_function_table_size;
        module.zsh_function_names = zsh_function_names;
        let reachable_functions = support.link(&mut module, &source_path)?;
        module.probe_capabilities = script_probe_capabilities(&module, &reachable_functions);
        module
            .validate()
            .map_err(|error| format!("{relative}: linked module validation failed: {error}"))?;
        all_probe_capabilities.extend(module.probe_capabilities.iter().cloned());
        let registrations = module
            .registrations
            .iter()
            .map(|registration| registration.command.clone())
            .collect::<BTreeSet<_>>();
        if registrations.is_empty() {
            return Err(format!("{relative}: no command registration produced").into());
        }
        let mut grouping_registrations = registrations.clone();
        grouping_registrations.extend(
            module
                .registrations
                .iter()
                .filter_map(|registration| registration.service.clone()),
        );
        all_registrations.extend(grouping_registrations.iter().cloned());
        let license = source_license(&source, &config.default_license);
        let digest = hex::encode(Sha256::digest(source.as_bytes()));
        report_files.push(serde_json::json!({
            "path": relative,
            "sha256": digest,
            "registrations": registrations,
            "license": license,
            "unsupported": [],
        }));

        let mut group = ScriptGroup {
            registrations: grouping_registrations,
            scripts: vec![module],
            licenses: BTreeSet::from([license]),
            source_paths: BTreeSet::from([relative]),
        };
        let mut index = 0;
        while index < groups.len() {
            if group
                .registrations
                .is_disjoint(&groups[index].registrations)
            {
                index += 1;
            } else {
                let other = groups.remove(index);
                group.merge(other);
                index = 0;
            }
        }
        groups.push(group);
    }

    let mut commands = groups
        .into_iter()
        .map(|mut group| {
            if config.dialect == ScriptDialect::Fish {
                let wrapper_services = group
                    .scripts
                    .iter()
                    .flat_map(|module| module.registrations.iter())
                    .filter_map(|registration| {
                        registration
                            .service
                            .as_ref()
                            .map(|service| (registration.command.clone(), service.clone()))
                    })
                    .collect::<HashMap<_, _>>();
                for module in &mut group.scripts {
                    for registration in &mut module.registrations {
                        if registration.service.is_none() {
                            registration.service =
                                wrapper_services.get(&registration.command).cloned();
                        }
                    }
                }
            }
            let registrations = group.registrations.into_iter().collect::<Vec<_>>();
            CommandProgram {
                canonical_name: registrations[0].clone(),
                registrations,
                source_path: group.source_paths.into_iter().collect::<Vec<_>>().join(";"),
                source_commit: config.manifest.source_commit.clone(),
                license: group.licenses.into_iter().collect::<Vec<_>>().join(" AND "),
                static_rules: Vec::new(),
                probes: Vec::new(),
                scripts: group.scripts,
            }
        })
        .collect::<Vec<_>>();
    commands.sort_by(|left, right| left.canonical_name.cmp(&right.canonical_name));
    for command in &commands {
        command.validate()?;
    }

    report_files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let report = serde_json::json!({
        "schema": 2,
        "source_commit": config.manifest.source_commit,
        "source_files": report_files.len(),
        "compiled_files": report_files.len(),
        "command_blocks": commands.len(),
        "registrations": all_registrations.len(),
        "unsupported_files": 0,
        "stale_registrations": 0,
        "files": report_files,
    });
    config.manifest.probe_capabilities = all_probe_capabilities.into_iter().collect();
    let spec = PackBuildSpec {
        manifest: config.manifest,
        minimum_engine: config.minimum_engine,
        required_opcodes: config.required_opcodes,
        optional_features: config.optional_features,
        commands,
    };
    atomic_write(Path::new(&arguments[1]), &serde_json::to_vec(&spec)?)?;
    atomic_write(
        Path::new(&arguments[2]),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "transpiled {} files into {} command blocks and {} registrations",
        report_files.len(),
        spec.commands.len(),
        all_registrations.len()
    );
    Ok(())
}

fn source_license(source: &str, default_license: &str) -> String {
    let header = source.lines().take(80).collect::<Vec<_>>().join("\n");
    if let Some(identifier) = header.lines().find_map(|line| {
        line.split_once("SPDX-License-Identifier:")
            .map(|(_, value)| value.trim().trim_end_matches("*/").trim().to_owned())
    }) {
        if !identifier.is_empty() {
            return identifier;
        }
    }
    let lowercase = header.to_ascii_lowercase();
    if lowercase.contains("either version 2") && lowercase.contains("later version") {
        return "GPL-2.0-or-later".into();
    }
    if lowercase.contains("released under the gplv2")
        || lowercase.contains("general public license, version 2")
        || lowercase.contains("general public license version 2")
    {
        return "GPL-2.0-only".into();
    }
    default_license.to_owned()
}

fn key_id(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 1 {
        return usage();
    }
    let key = read_verifying_key(Path::new(&arguments[0]))?;
    let mut keys = TrustedKeys::default();
    println!("{}", hex::encode(keys.insert(key)));
    Ok(())
}

fn public_key(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 1 {
        return usage();
    }
    let key = read_signing_key(Path::new(&arguments[0]))?;
    println!("{}", hex::encode(key.verifying_key().as_bytes()));
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes = read_hex_key(path, 32)?;
    Ok(SigningKey::from_bytes(&bytes.try_into().map_err(
        |_| "signing key must contain exactly 32 bytes",
    )?))
}

fn read_verifying_key(path: &Path) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = read_hex_key(path, 32)?;
    VerifyingKey::from_bytes(
        &bytes
            .try_into()
            .map_err(|_| "verifying key must contain exactly 32 bytes")?,
    )
    .map_err(Into::into)
}

fn read_hex_key(path: &Path, expected: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = read_text_bounded(path, 4096)?;
    let bytes = hex::decode(text.trim())?;
    if bytes.len() != expected {
        return Err(format!(
            "{} must contain {} hexadecimal bytes",
            path.display(),
            expected
        )
        .into());
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "pack".into(), |name| name.to_os_string());
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_completion_action_literals_are_linked_without_helper_name_lists() {
        let mut calls = BTreeSet::new();
        collect_completion_action_calls("_dynamic_helper argument", &mut calls);
        assert_eq!(
            calls.iter().cloned().collect::<Vec<_>>(),
            ["_dynamic_helper"]
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "xfunc.bash",
            "_entry() { _comp_xfunc apt-cache compgen_packages; _comp_compgen -ax python modules; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        calls.clear();
        collect_executable_calls(&module.functions[0].body, &mut calls);
        assert!(calls.contains("_comp_xfunc_apt_cache_compgen_packages"));
        assert!(calls.contains("_comp_xfunc_python_compgen_modules"));

        let module = parse_script(
            ScriptDialect::Bash,
            "generator.bash",
            "_entry() { _comp_compgen help -c help \"$1\"; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        calls.clear();
        collect_executable_calls(&module.functions[0].body, &mut calls);
        assert!(calls.contains("_comp_compgen_help"));

        let module = parse_script(
            ScriptDialect::Bash,
            "loader.bash",
            "local rustup=\"${1%cargo}rustup\"\neval \"$(\"$rustup\" completions bash cargo)\"\n",
        )
        .unwrap();
        let mut derived = BTreeSet::new();
        collect_derived_external_capabilities(
            &module.statements,
            &["cargo".to_owned()],
            &mut HashMap::new(),
            &mut derived,
        );
        assert_eq!(derived, BTreeSet::from(["rustup".to_owned()]));
    }

    #[test]
    fn unreachable_functions_do_not_expand_dynamic_targets_or_probe_capabilities() {
        let module = parse_script(
            ScriptDialect::Bash,
            "demo.bash",
            "_entry() { local target=_small; $target; }\n_dead() { local target=_large; $target; dangerous-tool; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned()]);
        let library_names = ["_small_one".to_owned(), "_large_one".to_owned()];
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, library_names.iter()),
            BTreeSet::from(["_small_one".to_owned()])
        );
        assert!(
            !script_probe_capabilities(&module, &analyzed).contains(&"dangerous-tool".to_owned())
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "global.bash",
            "target=_small\n_entry() { $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned()]);
        let library_names = ["_small_one".to_owned(), "_large_one".to_owned()];
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, library_names.iter()),
            BTreeSet::from(["_small_one".to_owned()])
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "flow.bash",
            "_setup() { target=_small; }\n_noise() { local target=_large; }\n_entry() { _setup; _noise; $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from([
            "_entry".to_owned(),
            "_noise".to_owned(),
            "_setup".to_owned(),
        ]);
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, library_names.iter()),
            BTreeSet::from(["_small_one".to_owned()]),
            "reachable global assignments cross function calls but locals do not"
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "dynamic-scope.bash",
            "_dispatch() { \"$target$1\"; }\n_entry() { local target=_small_; _dispatch one; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_dispatch".to_owned(), "_entry".to_owned()]);
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, library_names.iter()),
            BTreeSet::from(["_small_one".to_owned()]),
            "caller locals propagate through the shell's dynamic function scope"
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "persistent.bash",
            "_setup() { export target=_small; }\n_entry() { _setup; $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned(), "_setup".to_owned()]);
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, library_names.iter()),
            BTreeSet::from(["_small_one".to_owned()])
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "branches.bash",
            "_setup() { if true; then local target=_large; else target=_small; fi; }\n_entry() { _setup; $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned(), "_setup".to_owned()]);
        assert!(
            dynamic_function_targets(&module, &analyzed, library_names.iter())
                .contains("_small_one")
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "dynamic-chain.bash",
            "_dispatch() { \"$target\"one; }\n_entry() { local fn=_dispatch target=_small_; \"$fn\"; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_dispatch".to_owned(), "_entry".to_owned()]);
        let targets = dynamic_function_targets(&module, &analyzed, library_names.iter());
        assert!(targets.contains("_dispatch"));
        assert!(targets.contains("_small_one"));

        let module = parse_script(
            ScriptDialect::Bash,
            "and-or.bash",
            "_setup() { false && local target=_large; target=_small; }\n_entry() { _setup; $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned(), "_setup".to_owned()]);
        assert!(
            dynamic_function_targets(&module, &analyzed, library_names.iter())
                .contains("_small_one")
        );

        let module = parse_script(
            ScriptDialect::Bash,
            "names.bash",
            "_entry() { local short=_x hyphen=_foo-; $short; $hyphen; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let analyzed = BTreeSet::from(["_entry".to_owned()]);
        let names = ["_x".to_owned(), "_foo-bar".to_owned()];
        assert_eq!(
            dynamic_function_targets(&module, &analyzed, names.iter()),
            BTreeSet::from(["_foo-bar".to_owned(), "_x".to_owned()])
        );
    }

    #[test]
    fn zsh_preload_removal_does_not_shrink_function_table_history() {
        let mut names = Vec::new();
        let mut seen = HashSet::new();
        let mut table_size = 7_u32;
        for index in 0..14 {
            update_preloaded_function(
                &mut names,
                &mut seen,
                &mut table_size,
                &format!("_function_{index}"),
                false,
            );
        }
        update_preloaded_function(&mut names, &mut seen, &mut table_size, "_function_13", true);
        assert_eq!(names.len(), 13);
        assert_eq!(table_size, 28);
    }

    #[test]
    fn dynamically_selected_indexed_support_files_are_loaded_lazily() {
        let root =
            std::env::temp_dir().join(format!("bashlume-dynamic-support-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("_small_one"),
            "_small_one() { probe-tool --version; }\n",
        )
        .unwrap();
        let mut library = SupportLibrary {
            dialect: ScriptDialect::Bash,
            files: HashMap::new(),
            functions: HashMap::new(),
            loaded_files: BTreeSet::new(),
            zsh_function_roots: Vec::new(),
            zsh_preloaded_functions: Vec::new(),
            zsh_preloaded_function_table_size: 0,
        };
        library.index_root(&root).unwrap();
        let mut module = parse_script(
            ScriptDialect::Bash,
            "demo.bash",
            "target=_small\n_entry() { $target; }\ncomplete -F _entry demo\n",
        )
        .unwrap();
        let reachable = library.link(&mut module, &root.join("demo.bash")).unwrap();
        assert!(
            module
                .functions
                .iter()
                .any(|function| function.name == "_small_one")
        );
        assert!(script_probe_capabilities(&module, &reachable).contains(&"probe-tool".to_owned()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn option_words_are_never_inferred_as_probe_capabilities() {
        let module = parse_script(
            ScriptDialect::Zsh,
            "_demo",
            "#compdef demo\n_demo() { command --full-installer-version; }\n",
        )
        .unwrap();
        assert!(
            !script_probe_capabilities(&module, &BTreeSet::from(["_demo".to_owned()]))
                .iter()
                .any(|capability| capability.starts_with('-'))
        );
    }
}
