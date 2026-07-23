// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ir::{CommandProgram, IrError, MAX_COMMAND_BLOCK_BYTES};

pub const PACK_MAGIC: &[u8; 4] = b"BLPK";
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 1;
// No older on-disk major exists yet. Keep this equal to the current major
// until format 2 is introduced with an explicit format-1 decoder.
pub const PREVIOUS_FORMAT_MAJOR: u16 = FORMAT_MAJOR;
pub const HEADER_SIZE: usize = 256;
pub const MAX_PACK_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMMAND_NAMES: usize = 262_144;
pub const MAX_BLOCKS: usize = 65_536;
pub const MAX_COMMAND_NAME_BYTES: usize = 4096;
pub const MAX_COMPRESSED_BLOCK_BYTES: usize = 32 * 1024 * 1024;

const FLAG_SIGNED: u8 = 0x01;
const ROOT_HASH_RANGE: std::ops::Range<usize> = 128..160;
const SIGNATURE_RANGE: std::ops::Range<usize> = 160..224;
const PACK_ID_RANGE: std::ops::Range<usize> = 224..256;
const KEY_ID_RANGE: std::ops::Range<usize> = 96..128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Bash,
    Zsh,
    Fish,
    User,
}

impl SourceKind {
    fn encode(self) -> u8 {
        match self {
            Self::Bash => 0,
            Self::Zsh => 1,
            Self::Fish => 2,
            Self::User => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, PackError> {
        match value {
            0 => Ok(Self::Bash),
            1 => Ok(Self::Zsh),
            2 => Ok(Self::Fish),
            3 => Ok(Self::User),
            _ => Err(PackError::Invalid("unknown source kind")),
        }
    }

    pub const fn priority(self) -> u8 {
        match self {
            Self::User => 4,
            Self::Bash => 3,
            Self::Fish => 2,
            Self::Zsh => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackManifest {
    pub pack_id: String,
    pub pack_version: String,
    pub source_kind: SourceKind,
    pub source_repository: String,
    pub source_commit: String,
    pub license_expression: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub compiler_version: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub stale_commands: Vec<String>,
    #[serde(default)]
    pub probe_capabilities: Vec<String>,
}

impl PackManifest {
    fn validate(&self) -> Result<(), PackError> {
        for (name, value) in [
            ("pack ID", self.pack_id.as_str()),
            ("pack version", self.pack_version.as_str()),
            ("source repository", self.source_repository.as_str()),
            ("source commit", self.source_commit.as_str()),
            ("license expression", self.license_expression.as_str()),
        ] {
            if value.is_empty() || value.len() > 4096 || value.contains('\0') {
                return Err(PackError::InvalidOwned(format!("invalid manifest {name}")));
            }
        }
        if self.stale_commands.len() > MAX_COMMAND_NAMES
            || self.probe_capabilities.len() > MAX_COMMAND_NAMES
        {
            return Err(PackError::Limit("manifest entries"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStatus {
    Verified { key_id: [u8; 32] },
    Unsigned,
    Untrusted { key_id: [u8; 32] },
}

impl TrustStatus {
    pub const fn permits_dynamic_probes(self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

#[derive(Clone, Debug)]
struct NameEntry {
    name: String,
    block_id: u32,
}

#[derive(Clone, Debug)]
struct BlockEntry {
    offset: u64,
    compressed_length: u32,
    uncompressed_length: u32,
    hash: [u8; 32],
}

pub struct PackFile {
    path: PathBuf,
    mapping: Mmap,
    manifest: PackManifest,
    source_kind: SourceKind,
    minimum_engine: [u16; 3],
    format: [u16; 2],
    required_opcodes: u64,
    optional_features: u64,
    names: Vec<NameEntry>,
    blocks: Vec<BlockEntry>,
    chunks_offset: u64,
    trust: TrustStatus,
    pack_id: [u8; 32],
}

impl PackFile {
    pub fn open(path: impl AsRef<Path>, trusted_keys: &TrustedKeys) -> Result<Self, PackError> {
        let path = path.as_ref().to_owned();
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        if metadata.len() < HEADER_SIZE as u64 || metadata.len() > MAX_PACK_BYTES {
            return Err(PackError::Limit("pack file size"));
        }
        // SAFETY: the mapping is read-only and retained for no longer than the
        // owning PackFile. A pack installed in an immutable store cannot be
        // concurrently truncated; malformed mutable files still fail bounds
        // checks before any indexed access.
        let mapping = unsafe { MmapOptions::new().map(&file)? };
        let header = mapping.get(..HEADER_SIZE).ok_or(PackError::Truncated)?;
        if header.get(..4) != Some(PACK_MAGIC.as_slice()) {
            return Err(PackError::Invalid("invalid pack magic"));
        }
        let format_major = read_u16(header, 4)?;
        let format_minor = read_u16(header, 6)?;
        if (format_major != FORMAT_MAJOR && format_major != PREVIOUS_FORMAT_MAJOR)
            || format_major == FORMAT_MAJOR && format_minor > FORMAT_MINOR
        {
            return Err(PackError::UnsupportedFormat {
                major: format_major,
                minor: format_minor,
            });
        }
        if read_u32(header, 8)? as usize != HEADER_SIZE {
            return Err(PackError::Invalid("invalid pack header size"));
        }
        let source_kind = SourceKind::decode(header[12])?;
        let flags = header[13];
        if flags & !FLAG_SIGNED != 0 || header[14..16] != [0, 0] {
            return Err(PackError::Invalid("unknown pack header flags"));
        }
        let minimum_engine = [
            read_u16(header, 16)?,
            read_u16(header, 18)?,
            read_u16(header, 20)?,
        ];
        if header[22..24] != [0, 0] {
            return Err(PackError::Invalid("nonzero reserved header bytes"));
        }
        let command_count = read_u32(header, 24)? as usize;
        let block_count = read_u32(header, 28)? as usize;
        if command_count > MAX_COMMAND_NAMES || block_count > MAX_BLOCKS {
            return Err(PackError::Limit("pack index entries"));
        }
        let index_offset = read_u64(header, 32)?;
        let index_length = read_u64(header, 40)?;
        let manifest_offset = read_u64(header, 48)?;
        let manifest_length = read_u64(header, 56)?;
        let chunks_offset = read_u64(header, 64)?;
        let chunks_length = read_u64(header, 72)?;
        let index_end = index_offset
            .checked_add(index_length)
            .ok_or(PackError::Invalid("index offset overflow"))?;
        let manifest_end = manifest_offset
            .checked_add(manifest_length)
            .ok_or(PackError::Invalid("manifest offset overflow"))?;
        let chunks_end = chunks_offset
            .checked_add(chunks_length)
            .ok_or(PackError::Invalid("chunks offset overflow"))?;
        if index_offset < HEADER_SIZE as u64
            || index_end > manifest_offset
            || manifest_end > chunks_offset
            || chunks_end != mapping.len() as u64
        {
            return Err(PackError::Invalid("overlapping or trailing pack sections"));
        }
        let index = section(&mapping, index_offset, index_length)?;
        let manifest_bytes = section(&mapping, manifest_offset, manifest_length)?;
        section(&mapping, chunks_offset, chunks_length)?;
        let required_opcodes = read_u64(header, 80)?;
        let optional_features = read_u64(header, 88)?;
        if index.len() > MAX_INDEX_BYTES || manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PackError::Limit("pack metadata section"));
        }
        let expected_root: [u8; 32] = header[ROOT_HASH_RANGE]
            .try_into()
            .map_err(|_| PackError::Truncated)?;
        let actual_root: [u8; 32] = Sha256::new()
            .chain_update(index)
            .chain_update(manifest_bytes)
            .finalize()
            .into();
        if expected_root != actual_root {
            return Err(PackError::Integrity("pack metadata root hash"));
        }
        let key_id: [u8; 32] = header[KEY_ID_RANGE]
            .try_into()
            .map_err(|_| PackError::Truncated)?;
        let trust = verify_signature(header, flags, key_id, trusted_keys)?;
        let pack_id: [u8; 32] = header[PACK_ID_RANGE]
            .try_into()
            .map_err(|_| PackError::Truncated)?;
        let manifest: PackManifest = serde_json::from_slice(manifest_bytes)?;
        manifest.validate()?;
        if manifest.source_kind != source_kind {
            return Err(PackError::Invalid("manifest source kind mismatch"));
        }
        let calculated_pack_id: [u8; 32] = Sha256::new()
            .chain_update(manifest.pack_id.as_bytes())
            .chain_update([0])
            .chain_update(manifest.pack_version.as_bytes())
            .chain_update([0])
            .chain_update(manifest.source_commit.as_bytes())
            .finalize()
            .into();
        if pack_id != calculated_pack_id {
            return Err(PackError::Integrity("pack identity"));
        }
        let (names, blocks) = parse_index(index, command_count, block_count, chunks_length)?;
        Ok(Self {
            path,
            mapping,
            manifest,
            source_kind,
            minimum_engine,
            format: [format_major, format_minor],
            required_opcodes,
            optional_features,
            names,
            blocks,
            chunks_offset,
            trust,
            pack_id,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }

    pub const fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    pub const fn trust(&self) -> TrustStatus {
        self.trust
    }

    pub const fn format(&self) -> [u16; 2] {
        self.format
    }

    pub const fn minimum_engine(&self) -> [u16; 3] {
        self.minimum_engine
    }

    pub const fn required_opcodes(&self) -> u64 {
        self.required_opcodes
    }

    pub const fn optional_features(&self) -> u64 {
        self.optional_features
    }

    pub const fn pack_id(&self) -> [u8; 32] {
        self.pack_id
    }

    pub fn command_count(&self) -> usize {
        self.names.len()
    }

    pub fn contains_command(&self, command: &str) -> bool {
        self.find_block(command).is_some()
    }

    pub fn command_names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|entry| entry.name.as_str())
    }

    pub fn load_command(&self, command: &str) -> Result<Option<CommandProgram>, PackError> {
        let Some(block_id) = self.find_block(command) else {
            return Ok(None);
        };
        let block = self
            .blocks
            .get(block_id as usize)
            .ok_or(PackError::Invalid("command references missing block"))?;
        let absolute = self
            .chunks_offset
            .checked_add(block.offset)
            .ok_or(PackError::Invalid("chunk offset overflow"))?;
        let compressed = section(&self.mapping, absolute, u64::from(block.compressed_length))?;
        let hash: [u8; 32] = Sha256::digest(compressed).into();
        if hash != block.hash {
            return Err(PackError::Integrity("command block hash"));
        }
        let decoded = zstd::bulk::decompress(compressed, block.uncompressed_length as usize)
            .map_err(PackError::Decompression)?;
        if decoded.len() != block.uncompressed_length as usize
            || decoded.len() > MAX_COMMAND_BLOCK_BYTES
        {
            return Err(PackError::Limit("decompressed command block"));
        }
        let program = CommandProgram::decode(&decoded).map_err(PackError::Ir)?;
        if program.probes.iter().any(|probe| {
            !self
                .manifest
                .probe_capabilities
                .iter()
                .any(|capability| capability == &probe.executable)
        }) {
            return Err(PackError::Invalid(
                "command block requests an undeclared probe capability",
            ));
        }
        Ok(Some(program))
    }

    fn find_block(&self, command: &str) -> Option<u32> {
        self.names
            .binary_search_by(|entry| entry.name.as_str().cmp(command))
            .ok()
            .map(|index| self.names[index].block_id)
    }
}

#[derive(Default)]
pub struct TrustedKeys {
    keys: HashMap<[u8; 32], VerifyingKey>,
}

impl TrustedKeys {
    pub fn insert(&mut self, key: VerifyingKey) -> [u8; 32] {
        let key_id: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        self.keys.insert(key_id, key);
        key_id
    }

    pub fn get(&self, key_id: &[u8; 32]) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PackBuildSpec {
    pub manifest: PackManifest,
    #[serde(default = "default_minimum_engine")]
    pub minimum_engine: [u16; 3],
    #[serde(default)]
    pub required_opcodes: u64,
    #[serde(default)]
    pub optional_features: u64,
    pub commands: Vec<CommandProgram>,
}

const fn default_minimum_engine() -> [u16; 3] {
    [0, 2, 0]
}

pub struct PackBuilder {
    spec: PackBuildSpec,
    compression_level: i32,
}

impl PackBuilder {
    pub fn new(spec: PackBuildSpec) -> Self {
        Self {
            spec,
            compression_level: 9,
        }
    }

    pub fn compression_level(mut self, level: i32) -> Self {
        self.compression_level = level.clamp(1, 19);
        self
    }

    pub fn build(&self, signing_key: Option<&SigningKey>) -> Result<Vec<u8>, PackError> {
        self.spec.manifest.validate()?;
        if self.spec.commands.is_empty() || self.spec.commands.len() > MAX_BLOCKS {
            return Err(PackError::Limit("pack command blocks"));
        }
        let manifest = canonical_manifest(&self.spec.manifest)?;
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err(PackError::Limit("pack manifest"));
        }

        let mut names = BTreeMap::<String, u32>::new();
        let mut chunks = Vec::new();
        let mut blocks = Vec::with_capacity(self.spec.commands.len());
        for (block_id, command) in self.spec.commands.iter().enumerate() {
            command.validate().map_err(PackError::Ir)?;
            for registration in &command.registrations {
                if names
                    .insert(registration.clone(), block_id as u32)
                    .is_some()
                {
                    return Err(PackError::InvalidOwned(format!(
                        "duplicate command registration: {registration}"
                    )));
                }
            }
            let encoded = command.encode().map_err(PackError::Ir)?;
            let compressed = zstd::bulk::compress(&encoded, self.compression_level)
                .map_err(PackError::Compression)?;
            if compressed.len() > MAX_COMPRESSED_BLOCK_BYTES {
                return Err(PackError::Limit("compressed command block"));
            }
            let offset = chunks.len() as u64;
            let hash: [u8; 32] = Sha256::digest(&compressed).into();
            blocks.push(BlockEntry {
                offset,
                compressed_length: compressed.len() as u32,
                uncompressed_length: encoded.len() as u32,
                hash,
            });
            chunks.extend_from_slice(&compressed);
        }
        if names.len() > MAX_COMMAND_NAMES {
            return Err(PackError::Limit("command names"));
        }
        let index = encode_index(&names, &blocks)?;
        if index.len() > MAX_INDEX_BYTES {
            return Err(PackError::Limit("pack index"));
        }

        let index_offset = HEADER_SIZE as u64;
        let manifest_offset = align_eight(index_offset + index.len() as u64);
        let chunks_offset = align_eight(manifest_offset + manifest.len() as u64);
        let final_length = chunks_offset
            .checked_add(chunks.len() as u64)
            .ok_or(PackError::Limit("pack size"))?;
        if final_length > MAX_PACK_BYTES {
            return Err(PackError::Limit("pack size"));
        }

        let mut output = vec![0_u8; final_length as usize];
        output[..4].copy_from_slice(PACK_MAGIC);
        write_u16(&mut output, 4, FORMAT_MAJOR)?;
        write_u16(&mut output, 6, FORMAT_MINOR)?;
        write_u32(&mut output, 8, HEADER_SIZE as u32)?;
        output[12] = self.spec.manifest.source_kind.encode();
        output[13] = u8::from(signing_key.is_some()) * FLAG_SIGNED;
        write_u16(&mut output, 16, self.spec.minimum_engine[0])?;
        write_u16(&mut output, 18, self.spec.minimum_engine[1])?;
        write_u16(&mut output, 20, self.spec.minimum_engine[2])?;
        write_u32(&mut output, 24, names.len() as u32)?;
        write_u32(&mut output, 28, blocks.len() as u32)?;
        write_u64(&mut output, 32, index_offset)?;
        write_u64(&mut output, 40, index.len() as u64)?;
        write_u64(&mut output, 48, manifest_offset)?;
        write_u64(&mut output, 56, manifest.len() as u64)?;
        write_u64(&mut output, 64, chunks_offset)?;
        write_u64(&mut output, 72, chunks.len() as u64)?;
        write_u64(&mut output, 80, self.spec.required_opcodes)?;
        write_u64(&mut output, 88, self.spec.optional_features)?;

        output[index_offset as usize..index_offset as usize + index.len()].copy_from_slice(&index);
        output[manifest_offset as usize..manifest_offset as usize + manifest.len()]
            .copy_from_slice(&manifest);
        output[chunks_offset as usize..].copy_from_slice(&chunks);

        let root: [u8; 32] = Sha256::new()
            .chain_update(&index)
            .chain_update(&manifest)
            .finalize()
            .into();
        output[ROOT_HASH_RANGE].copy_from_slice(&root);
        let pack_id: [u8; 32] = Sha256::new()
            .chain_update(self.spec.manifest.pack_id.as_bytes())
            .chain_update([0])
            .chain_update(self.spec.manifest.pack_version.as_bytes())
            .chain_update([0])
            .chain_update(self.spec.manifest.source_commit.as_bytes())
            .finalize()
            .into();
        output[PACK_ID_RANGE].copy_from_slice(&pack_id);

        if let Some(signing_key) = signing_key {
            let verifying = signing_key.verifying_key();
            let key_id: [u8; 32] = Sha256::digest(verifying.as_bytes()).into();
            output[KEY_ID_RANGE].copy_from_slice(&key_id);
            let message = signature_message(&output[..HEADER_SIZE])?;
            let signature = signing_key.sign(&message);
            output[SIGNATURE_RANGE].copy_from_slice(&signature.to_bytes());
        }
        Ok(output)
    }
}

fn canonical_manifest(manifest: &PackManifest) -> Result<Vec<u8>, PackError> {
    // Struct field order is fixed and vectors preserve converter-defined order;
    // pretty printing is deliberately avoided for deterministic artifacts.
    serde_json::to_vec(manifest).map_err(PackError::Json)
}

fn encode_index(
    names: &BTreeMap<String, u32>,
    blocks: &[BlockEntry],
) -> Result<Vec<u8>, PackError> {
    let mut output = Vec::with_capacity(
        8 + names.keys().map(|name| name.len() + 8).sum::<usize>() + blocks.len() * 52,
    );
    push_u32(&mut output, names.len() as u32);
    for (name, block_id) in names {
        if name.is_empty() || name.len() > MAX_COMMAND_NAME_BYTES || name.contains('\0') {
            return Err(PackError::Invalid("invalid indexed command name"));
        }
        push_u32(&mut output, name.len() as u32);
        output.extend_from_slice(name.as_bytes());
        push_u32(&mut output, *block_id);
    }
    push_u32(&mut output, blocks.len() as u32);
    for block in blocks {
        push_u64(&mut output, block.offset);
        push_u32(&mut output, block.compressed_length);
        push_u32(&mut output, block.uncompressed_length);
        output.extend_from_slice(&block.hash);
    }
    Ok(output)
}

fn parse_index(
    index: &[u8],
    expected_names: usize,
    expected_blocks: usize,
    chunks_length: u64,
) -> Result<(Vec<NameEntry>, Vec<BlockEntry>), PackError> {
    let mut decoder = IndexDecoder::new(index);
    let name_count = decoder.count(MAX_COMMAND_NAMES)?;
    if name_count != expected_names {
        return Err(PackError::Invalid("command count mismatch"));
    }
    let mut names = Vec::with_capacity(name_count);
    let mut previous: Option<String> = None;
    for _ in 0..name_count {
        let name = decoder.string(MAX_COMMAND_NAME_BYTES)?;
        if name.is_empty() || previous.as_ref().is_some_and(|value| value >= &name) {
            return Err(PackError::Invalid("command index is not strictly sorted"));
        }
        let block_id = decoder.u32()?;
        previous = Some(name.clone());
        names.push(NameEntry { name, block_id });
    }
    let block_count = decoder.count(MAX_BLOCKS)?;
    if block_count != expected_blocks {
        return Err(PackError::Invalid("block count mismatch"));
    }
    let mut blocks = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        let offset = decoder.u64()?;
        let compressed_length = decoder.u32()?;
        let uncompressed_length = decoder.u32()?;
        let hash: [u8; 32] = decoder
            .take(32)?
            .try_into()
            .map_err(|_| PackError::Truncated)?;
        if compressed_length as usize > MAX_COMPRESSED_BLOCK_BYTES
            || uncompressed_length as usize > MAX_COMMAND_BLOCK_BYTES
        {
            return Err(PackError::Limit("command block size"));
        }
        let end = offset
            .checked_add(u64::from(compressed_length))
            .ok_or(PackError::Invalid("command block offset overflow"))?;
        if end > chunks_length {
            return Err(PackError::Truncated);
        }
        blocks.push(BlockEntry {
            offset,
            compressed_length,
            uncompressed_length,
            hash,
        });
    }
    if names
        .iter()
        .any(|entry| entry.block_id as usize >= blocks.len())
    {
        return Err(PackError::Invalid("command references missing block"));
    }
    if !decoder.remaining().is_empty() {
        return Err(PackError::Invalid("trailing pack index bytes"));
    }
    Ok((names, blocks))
}

fn verify_signature(
    header: &[u8],
    flags: u8,
    key_id: [u8; 32],
    trusted_keys: &TrustedKeys,
) -> Result<TrustStatus, PackError> {
    if flags & FLAG_SIGNED == 0 {
        if key_id != [0; 32] || header[SIGNATURE_RANGE].iter().any(|byte| *byte != 0) {
            return Err(PackError::Invalid(
                "unsigned pack contains signature metadata",
            ));
        }
        return Ok(TrustStatus::Unsigned);
    }
    let Some(key) = trusted_keys.get(&key_id) else {
        return Ok(TrustStatus::Untrusted { key_id });
    };
    let signature = Signature::from_bytes(
        &header[SIGNATURE_RANGE]
            .try_into()
            .map_err(|_| PackError::Truncated)?,
    );
    let message = signature_message(header)?;
    key.verify(&message, &signature)
        .map_err(|_| PackError::Integrity("pack signature"))?;
    Ok(TrustStatus::Verified { key_id })
}

fn signature_message(header: &[u8]) -> Result<Vec<u8>, PackError> {
    if header.len() != HEADER_SIZE {
        return Err(PackError::Truncated);
    }
    let mut message = header.to_vec();
    message[SIGNATURE_RANGE].fill(0);
    Ok(message)
}

fn section(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], PackError> {
    let offset = usize::try_from(offset).map_err(|_| PackError::Limit("section offset"))?;
    let length = usize::try_from(length).map_err(|_| PackError::Limit("section length"))?;
    let end = offset
        .checked_add(length)
        .ok_or(PackError::Invalid("section offset overflow"))?;
    bytes.get(offset..end).ok_or(PackError::Truncated)
}

const fn align_eight(value: u64) -> u64 {
    value.saturating_add(7) & !7
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PackError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(PackError::Truncated)?
            .try_into()
            .map_err(|_| PackError::Truncated)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PackError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(PackError::Truncated)?
            .try_into()
            .map_err(|_| PackError::Truncated)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PackError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(PackError::Truncated)?
            .try_into()
            .map_err(|_| PackError::Truncated)?,
    ))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), PackError> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or(PackError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), PackError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(PackError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), PackError> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or(PackError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

struct IndexDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> IndexDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PackError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PackError::Invalid("index offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(PackError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, PackError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| PackError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, PackError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| PackError::Truncated)?,
        ))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, PackError> {
        let value = self.u32()? as usize;
        if value > maximum {
            return Err(PackError::Limit("index count"));
        }
        Ok(value)
    }

    fn string(&mut self, maximum: usize) -> Result<String, PackError> {
        let length = self.count(maximum)?;
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| PackError::Invalid("invalid index UTF-8"))
    }
}

#[derive(Debug)]
pub enum PackError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Compression(std::io::Error),
    Decompression(std::io::Error),
    Ir(IrError),
    Truncated,
    Invalid(&'static str),
    InvalidOwned(String),
    Integrity(&'static str),
    Limit(&'static str),
    UnsupportedFormat { major: u16, minor: u16 },
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "pack I/O error: {error}"),
            Self::Json(error) => write!(formatter, "pack JSON error: {error}"),
            Self::Compression(error) => write!(formatter, "pack compression error: {error}"),
            Self::Decompression(error) => write!(formatter, "pack decompression error: {error}"),
            Self::Ir(error) => write!(formatter, "pack IR error: {error}"),
            Self::Truncated => formatter.write_str("truncated rule pack"),
            Self::Invalid(message) => write!(formatter, "invalid rule pack: {message}"),
            Self::InvalidOwned(message) => write!(formatter, "invalid rule pack: {message}"),
            Self::Integrity(message) => write!(formatter, "rule-pack integrity failure: {message}"),
            Self::Limit(message) => write!(formatter, "rule-pack limit exceeded: {message}"),
            Self::UnsupportedFormat { major, minor } => {
                write!(formatter, "unsupported rule-pack format {major}.{minor}")
            }
        }
    }
}

impl std::error::Error for PackError {}

impl From<std::io::Error> for PackError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PackError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::rules::ir::{
        AppendPolicy, CandidateTemplate, PathCompletion, PredicateOp, RuleCandidateKind, StaticRule,
    };

    fn command(name: &str) -> CommandProgram {
        CommandProgram {
            canonical_name: name.into(),
            registrations: vec![name.into()],
            source_path: format!("completions/{name}"),
            source_commit: "0123456789abcdef".into(),
            license: "GPL-2.0-or-later".into(),
            static_rules: vec![StaticRule {
                when: vec![PredicateOp::True],
                path_completion: PathCompletion::Inherit,
                candidates: vec![CandidateTemplate {
                    value: "--help".into(),
                    display: "--help".into(),
                    description: Some("Display help".into()),
                    kind: RuleCandidateKind::Option,
                    append: AppendPolicy::Space,
                    preserve_order: false,
                }],
            }],
            probes: Vec::new(),
        }
    }

    fn spec() -> PackBuildSpec {
        PackBuildSpec {
            manifest: PackManifest {
                pack_id: "org.bashlume.rules.bash".into(),
                pack_version: "1.0.0".into(),
                source_kind: SourceKind::Bash,
                source_repository: "https://github.com/scop/bash-completion".into(),
                source_commit: "0123456789abcdef".into(),
                license_expression: "GPL-2.0-or-later".into(),
                channel: "stable".into(),
                compiler_version: "0.1.0".into(),
                generated_at: "1970-01-01T00:00:00Z".into(),
                stale_commands: Vec::new(),
                probe_capabilities: Vec::new(),
            },
            minimum_engine: [0, 2, 0],
            required_opcodes: 0,
            optional_features: 0,
            commands: vec![command("git"), command("cargo")],
        }
    }

    fn temporary_pack(bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bashlume-pack-{}-{}.blp",
            std::process::id(),
            Sha256::digest(bytes)[0]
        ));
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn unsigned_pack_round_trips_and_loads_lazily() {
        let bytes = PackBuilder::new(spec()).build(None).unwrap();
        let path = temporary_pack(&bytes);
        let pack = PackFile::open(&path, &TrustedKeys::default()).unwrap();
        assert_eq!(pack.trust(), TrustStatus::Unsigned);
        assert!(pack.contains_command("git"));
        assert!(!pack.contains_command("missing"));
        assert_eq!(
            pack.load_command("git").unwrap().unwrap().canonical_name,
            "git"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn signed_pack_requires_and_verifies_its_trusted_key() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let bytes = PackBuilder::new(spec()).build(Some(&signing)).unwrap();
        let path = temporary_pack(&bytes);
        let untrusted = PackFile::open(&path, &TrustedKeys::default()).unwrap();
        assert!(matches!(untrusted.trust(), TrustStatus::Untrusted { .. }));

        let mut keys = TrustedKeys::default();
        let key_id = keys.insert(signing.verifying_key());
        let trusted = PackFile::open(&path, &keys).unwrap();
        assert_eq!(trusted.trust(), TrustStatus::Verified { key_id });
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn metadata_and_command_corruption_are_detected() {
        let bytes = PackBuilder::new(spec()).build(None).unwrap();
        let mut metadata_corrupt = bytes.clone();
        metadata_corrupt[HEADER_SIZE + 5] ^= 0x01;
        let path = temporary_pack(&metadata_corrupt);
        assert!(matches!(
            PackFile::open(&path, &TrustedKeys::default()),
            Err(PackError::Integrity(_))
        ));
        fs::remove_file(path).unwrap();

        let mut command_corrupt = bytes;
        let header = &command_corrupt[..HEADER_SIZE];
        let chunks = read_u64(header, 64).unwrap() as usize;
        command_corrupt[chunks] ^= 0x01;
        let path = temporary_pack(&command_corrupt);
        let pack = PackFile::open(&path, &TrustedKeys::default()).unwrap();
        assert!(matches!(
            pack.load_command("git"),
            Err(PackError::Integrity(_))
        ));
        fs::remove_file(path).unwrap();
    }
}
