// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use super::format::{PackFile, SourceKind, TrustStatus, TrustedKeys};
use super::ir::CommandProgram;

pub const MAX_DISCOVERED_PACKS: usize = 128;
pub const MAX_TRUSTED_KEYS: usize = 64;
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
    pub program: CommandProgram,
}

#[derive(Default)]
pub struct RuleStore {
    packs: Vec<PackFile>,
    summaries: Vec<PackSummary>,
}

impl RuleStore {
    pub fn discover(paths: &[PathBuf], trusted_key_paths: &[PathBuf]) -> Self {
        let (trusted_keys, key_errors) = load_trusted_keys(trusted_key_paths);
        let mut files = discover_files(paths);
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

    pub fn load_command(&self, command: &str) -> (Vec<LoadedProgram>, Vec<String>) {
        let mut programs = Vec::new();
        let mut errors = Vec::new();
        for pack in &self.packs {
            if !pack.contains_command(command) {
                continue;
            }
            match pack.load_command(command) {
                Ok(Some(program)) if program.registrations.iter().any(|name| name == command) => {
                    programs.push(LoadedProgram {
                        pack_id: pack.pack_id(),
                        pack_name: pack.manifest().pack_id.clone(),
                        pack_version: pack.manifest().pack_version.clone(),
                        source: pack.source_kind(),
                        trust: pack.trust(),
                        program,
                    });
                }
                Ok(Some(_)) => errors.push(format!(
                    "{}: command block does not register {command}",
                    pack.path().display()
                )),
                Ok(None) => {}
                Err(error) => errors.push(format!("{}: {error}", pack.path().display())),
            }
        }
        (programs, errors)
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
        let mut children = directory
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && is_pack(path))
            .collect::<Vec<_>>();
        children.sort_unstable();
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
        let mut children = directory
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path.extension().is_some_and(|extension| {
                        extension == "pub" || extension == "hex" || extension == "key"
                    })
            })
            .collect::<Vec<_>>();
        children.sort_unstable();
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
            let text = fs::read_to_string(&path)?;
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
