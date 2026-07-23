# BashLume Rule Pack Format 1.1

Status: implemented core container and IR baseline. This specification is GPL-2.0-or-later and is intended for independent rule-pack implementations.

## Container

All integers are unsigned little-endian. Offsets are absolute unless noted. Readers must reject integer overflow, overlap, trailing data, invalid UTF-8 in textual fields, and values above the published limits.

### Header (256 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `BLPK` |
| 4 | 2 | format major |
| 6 | 2 | format minor |
| 8 | 4 | header size, exactly 256 |
| 12 | 1 | source kind: Bash=0, Zsh=1, Fish=2, User=3 |
| 13 | 1 | flags; bit 0 means signed |
| 14 | 2 | reserved zero |
| 16 | 6 | minimum engine major/minor/patch (`u16` each) |
| 22 | 2 | reserved zero |
| 24 | 4 | indexed command-name count |
| 28 | 4 | command-block count |
| 32 | 8 | index offset |
| 40 | 8 | index length |
| 48 | 8 | manifest offset |
| 56 | 8 | manifest length |
| 64 | 8 | chunks offset |
| 72 | 8 | chunks length |
| 80 | 8 | required opcode bitmap |
| 88 | 8 | optional feature bitmap |
| 96 | 32 | SHA-256 signing-key ID, or zero for unsigned packs |
| 128 | 32 | SHA-256 of `index || manifest` |
| 160 | 64 | Ed25519 signature, or zero for unsigned packs |
| 224 | 32 | pack identity hash |

Sections are ordered `header`, `index`, `manifest`, `chunks`; padding between sections is zero-filled and sections may not overlap. The chunks section ends exactly at EOF.

The signature is Ed25519 over the complete 256-byte header with bytes 160–223 replaced by zero. The signed root authenticates the index and manifest; the index authenticates every compressed command block.

The key ID is SHA-256 of the raw 32-byte Ed25519 public key.

The pack identity is:

```text
SHA-256(pack_id || NUL || pack_version || NUL || source_commit)
```

## Index

```text
u32 name_count
repeat name_count:
    u32 UTF-8 name length
    bytes name
    u32 block_id
u32 block_count
repeat block_count:
    u64 offset relative to chunks section
    u32 compressed length
    u32 uncompressed length
    bytes[32] SHA-256 of compressed block
```

Names are nonempty, unique, and strictly byte-sorted. Multiple names may refer to the same block. Blocks are independent Zstandard frames.

## Manifest

The manifest is compact UTF-8 JSON with fixed fields:

```json
{
  "pack_id": "org.bashlume.rules.bash",
  "pack_version": "1.0.0",
  "source_kind": "bash",
  "source_repository": "https://github.com/scop/bash-completion",
  "source_commit": "...",
  "license_expression": "GPL-2.0-or-later",
  "channel": "stable",
  "compiler_version": "...",
  "generated_at": "...",
  "stale_commands": [],
  "probe_capabilities": ["git"]
}
```

Every dynamic probe executable in a command block must appear exactly in `probe_capabilities`. A signature never grants undeclared capabilities.

## Command IR block

Each decompressed block starts with:

```text
bytes[4] `BLIR`
u16 block version (2; version 1 remains readable)
u16 flags (zero)
```

Strings use `u32 byte_length` followed by UTF-8 bytes. Lists use `u32 count`. Optional strings use a one-byte 0/1 tag.

The remaining order is:

1. canonical command name
2. registration-name list
3. source path
4. source commit
5. SPDX license expression
6. static rule list
7. dynamic probe list

A block-version-2 static rule stores its predicate program, one path-completion byte, and its candidate list. Path completion is `inherit` (0), `suppress` (1), `directories` (2), or `files` (3). Block version 1 omitted this byte and decodes as `inherit`.

### Predicates

Predicates are verified postfix boolean programs. Format 1 supports:

| Opcode | Operation |
|---:|---|
| 0 | true |
| 1 | false |
| 2 | not |
| 3 | and |
| 4 | or |
| 5 | current word equals string |
| 6 | current word starts with string |
| 7 | previous word equals string |
| 8 | any word equals string |
| 9 | word is absent |
| 10 | word index equals `u32` |
| 11 | word index is at least `u32` |
| 12 | normalized command path equals string list |
| 13 | environment variable is set |
| 14 | environment variable equals a value |

A predicate must leave exactly one boolean, may contain at most 4096 instructions, and may not exceed stack depth 256.

### Candidates

A candidate stores:

- insertion value
- display value
- optional description
- semantic kind
- append policy (`space`, `no-space`, or `slash`)
- preserve-order flag

The runtime filters and ranks candidates against the current query, then merges identical insertion values from all installed packs. Source priority resolves metadata only; unique candidates remain in the union.

Matched path policies are merged independently. Explicit file completion wins over directory-only completion, which wins over suppression; suppression wins over an unspecified policy. The resulting policy controls the asynchronous generic path provider, allowing source rules to reproduce Fish `-f`/`-F`, Bash `compopt`, and Zsh file actions without synchronous I/O.

### Dynamic probes

A probe stores:

- ID and predicate
- executable and argv templates
- explicit environment overrides
- output parser
- candidate kind and append policy
- timeout, output limit, and cache TTL
- optional description

Template placeholders are limited to `{current}`, `{command}`, `{cwd}`, and `{word:N}`. The runtime never evaluates shell syntax. `sh`, `bash`, `dash`, `zsh`, and `fish` are forbidden probe executables. Probe execution requires a trusted signature and explicit capability declaration.

## Limits

Current hard limits include:

- pack: 512 MiB
- index: 32 MiB
- manifest: 8 MiB
- command block: 16 MiB uncompressed
- compressed block: 32 MiB
- command names: 262,144
- command blocks: 65,536
- individual string: 1 MiB
- command string data: 8 MiB
- parsed dynamic values: 4,096
- dynamic value: 64 KiB
- concurrent probe children: 2

These are parser security boundaries, not recommended generation targets.

## Compatibility

Format-major changes are breaking. Minor additions must remain backward compatible and be guarded by feature bits. Engine 0.2 reads container minors 1.0 and 1.1 and command-block versions 1 and 2; it writes 1.1/version 2. BashLume supports the current major and, once a second major exists, the immediately preceding major through a dedicated decoder. It must never treat an unknown major or newer minor as the current layout.
