// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bashlume::rules::format::{PackBuildSpec, PackBuilder, PackFile, TrustedKeys};
use bashlume::rules::vm::{EvaluationContext, EvaluationMode, evaluate};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;

fn main() {
    if let Err(error) = run() {
        eprintln!("bashlume-pack: {error}");
        std::process::exit(1);
    }
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
        "help" | "--help" | "-h" => usage(),
        _ => usage(),
    }
}

fn usage<T>() -> Result<T, Box<dyn std::error::Error>> {
    Err(
        "usage:\n  bashlume-pack build SPEC.json OUTPUT.blp [SIGNING_KEY.hex]\n  bashlume-pack inspect PACK.blp [VERIFYING_KEY.hex ...]\n  bashlume-pack verify PACK.blp [VERIFYING_KEY.hex ...]\n  bashlume-pack key-id VERIFYING_KEY.hex\n  bashlume-pack public-key SIGNING_KEY.hex\n  bashlume-pack evaluate PACK.blp CONTEXT.json [VERIFYING_KEY.hex ...]"
            .into(),
    )
}

fn build(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if !(2..=3).contains(&arguments.len()) {
        return usage();
    }
    let input = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let spec: PackBuildSpec = serde_json::from_slice(&fs::read(input)?)?;
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
    #[serde(default = "default_working_directory")]
    working_directory: PathBuf,
    #[serde(default)]
    explicit_tab: bool,
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
    let input: EvaluationInput = serde_json::from_slice(&fs::read(Path::new(&arguments[1]))?)?;
    if input.word_index >= input.words.len() {
        return Err("context word_index is outside words".into());
    }
    let program = pack
        .load_command(&input.command)?
        .ok_or_else(|| format!("no rule for command {}", input.command))?;
    let context = EvaluationContext {
        current_word: &input.current_word,
        words: &input.words,
        word_index: input.word_index,
        command_path: &input.command_path,
        environment: &input.environment,
        working_directory: &input.working_directory,
    };
    let result = evaluate(
        &program,
        &context,
        pack.source_kind(),
        pack.trust(),
        if input.explicit_tab {
            EvaluationMode::ExplicitTab
        } else {
            EvaluationMode::Passive
        },
        65_536,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
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
    let text = fs::read_to_string(path)?;
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
