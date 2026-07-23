# BashLume Native Completion Rule Packs — Complete Implementation Plan

Status: **Approved design; implementation required**  
Owner: **Fadouse**  
Core repository: `Fadouse/BashLume`  
Rule repositories:

- `Fadouse/BashLume-Rules-Bash`
- `Fadouse/BashLume-Rules-Zsh`
- `Fadouse/BashLume-Rules-Fish`

This document is the authoritative implementation and acceptance plan for replacing BashLume's generic-only completion with a complete, high-performance, Rust-native command-aware completion system derived from the Bash, Zsh, and Fish completion ecosystems.

A component, prototype, partial converter, or partially populated rule pack is **not** completion of this plan. The first Stable rule-pack baseline must meet the full-baseline gate defined below.

## 1. Non-negotiable product requirements

1. BashLume must not require `bash-completion`, Zsh, or Fish at runtime.
2. BashLume must not source or execute upstream completion scripts at runtime.
3. Runtime rule evaluation must be implemented by Rust code operating on validated, pure-data IR rule packs.
4. Bash, Zsh, and Fish-derived rules must live in separate repositories and publish separate artifacts.
5. Rule repositories may use their source shells in CI as conversion inputs and differential-test oracles.
6. BashLume must remain fully offline at shell startup, while typing, and when completing. Updates happen through CI, releases, Nix, or another package manager.
7. All installed compatible rule packs are evaluated independently. Their candidates are merged and deduplicated; one source must not suppress unique candidates from another source.
8. Static IR may participate in real-time ghost suggestions. External dynamic probes may start only after explicit `Tab` completion.
9. A single BashLume background supervisor thread handles filesystem I/O, lazy rule loading, cache maintenance, and nonblocking child supervision. At most two dynamic probe child processes may run concurrently.
10. The first Stable baseline must fully convert the pinned upstream baseline. `unsupported`, `TODO`, empty opcode handlers, generic fallback disguised as command support, and omitted rules are forbidden.
11. Post-baseline `stale` retention is only a continuity mechanism for newly introduced unsupported upstream changes. It cannot be used to ship the initial baseline incomplete.
12. Candidate descriptions use the already implemented bounded selected-item detail row by default, with `inline` and `off` modes retained.

## 2. Licensing and provenance

### 2.1 BashLume core

Relicense the BashLume core from MIT to:

```text
GPL-2.0-or-later
```

Required changes:

- Replace `LICENSE` with the complete GNU GPL version 2 text and an explicit “or any later version” project notice.
- Change `Cargo.toml` to `license = "GPL-2.0-or-later"`.
- Change Nix metadata to `lib.licenses.gpl2Plus`.
- Update README copyright and licensing text.
- Add SPDX headers to new rule-system source files.
- Record the relicensing in `CHANGELOG.md`.

All current commits are authored by Fadouse, so no third-party contributor approval is required for the existing core code.

### 2.2 Bash-derived rules

- Repository license: `GPL-2.0-or-later`.
- Preserve upstream copyright, source path, upstream commit, and modification notice for every generated command block.
- Include upstream `COPYING` and a generated provenance manifest.

### 2.3 Fish-derived rules

- Repository and generated pack license: `GPL-2.0-only` because Fish declares `GPL-2.0-only`.
- Never bundle the Fish-derived pack into the BashLume core artifact.
- Publish and install it as a separate optional data package.
- Preserve per-file source and copyright information.

### 2.4 Zsh-derived rules

- Preserve the default Zsh license and every per-file override.
- Generate a machine-readable per-command SPDX expression and attribution record.
- Commands derived from GPL-2.0-only files remain GPL-2.0-only within the Zsh pack.
- Never flatten mixed provenance into an inaccurate repository-wide claim.

### 2.5 Distribution boundary

The core engine and each rule pack are separately distributable artifacts. A meta-package may install them side by side, but the core binary must not embed Fish or mixed-license Zsh data.

## 3. Repository architecture

### 3.1 `BashLume`

Responsibilities:

- Define and document the `.blp` container and Completion IR.
- Validate signatures, hashes, structural limits, and opcode capabilities.
- Discover and lazily load locally installed packs.
- Evaluate static IR.
- Schedule and supervise permitted dynamic probes.
- Merge and deduplicate candidates from all installed sources.
- Render candidate descriptions.
- Publish a conformance test kit and pack-inspection tool.
- Pin compatible Stable rule-pack releases for integration CI without embedding them in the core artifact.

Planned modules:

```text
src/rules/mod.rs
src/rules/format.rs
src/rules/index.rs
src/rules/loader.rs
src/rules/verify.rs
src/rules/ir.rs
src/rules/vm.rs
src/rules/merge.rs
src/rules/probe.rs
src/rules/cache.rs
src/bin/bashlume-pack.rs
```

### 3.2 Rule repositories

Each source-specific repository contains:

```text
.github/workflows/
  ci.yml
  sync-stable.yml
  sync-edge.yml
  release.yml
src/ or compiler/
fixtures/
provenance/
rules.lock
LICENSES/
README.md
```

Each repository must:

- Fetch an explicitly pinned upstream commit.
- Verify the fetched repository identity and commit.
- Compile all source rules into Completion IR.
- Run exact normalized differential tests against the source shell.
- Verify no baseline command or registration was lost.
- Emit a deterministic `.blp` artifact.
- Emit SPDX/provenance manifests and source hashes.
- Sign release artifacts.
- Publish Stable and Edge channels separately.

## 4. Rule-pack container (`.blp`)

### 4.1 Design constraints

- Pure data only; native shared libraries and embedded executable machine code are forbidden.
- Deterministic and reproducible byte-for-byte output.
- Little-endian, explicitly sized fields; no Rust-native struct serialization.
- Bounds-checkable before allocation.
- Random access by command without decoding the whole pack.
- Current and previous format major supported by the core.
- Same-major additions must be backward compatible.

### 4.2 Header

The signed header includes:

```text
magic = "BLPK"
format_major
format_minor
header_size
pack_id
source_kind = bash | zsh | fish | user
pack_version
minimum_engine_version
required_opcode_bitmap
optional_feature_bitmap
command_count
index_offset/index_length
manifest_offset/manifest_length
chunk_table_offset/chunk_table_length
merkle_root
signing_key_id
signature
```

### 4.3 Command index

- Read-only mmap-compatible sorted index or deterministic minimal lookup table.
- Maps command names and aliases to command-block identifiers.
- Includes source priority metadata and block hash.
- Supports one source rule serving multiple command names.
- Does not require command blocks to be resident.

### 4.4 Command blocks

Each command block is independently compressed, hashed, validated, and decoded. It contains:

- command names and aliases
- source file and commit
- license expression and attribution IDs
- static strings and descriptions
- predicates and state transitions
- candidate emission instructions
- dynamic probe declarations
- option insertion metadata (`nospace`, filename semantics, ordering)
- dependency hashes for shared helper semantics

### 4.5 Integrity

- The signature covers the header, command index, manifest root, and Merkle root.
- Each command block is verified against its Merkle leaf before use.
- Unsigned or invalidly signed packs may provide static candidates only when local policy permits; dynamic probes are denied by default.
- Malformed packs are rejected without panics, unbounded allocation, or partial execution.

## 5. Completion IR

### 5.1 Core value types

- UTF-8 string
- byte-safe shell word
- boolean
- signed integer
- list
- map
- candidate
- path
- semantic command-line token
- probe request/result

### 5.2 Context model

The engine must expose a normalized Bash completion context including:

- full line and cursor position
- replacement byte range
- quote mode
- current dequoted word
- tokenized words
- current word index
- command name after assignments and wrappers
- subcommand path
- options already present
- pending option argument
- redirection context
- pipeline/compound-command boundaries
- working directory
- selected immutable environment snapshot

### 5.3 Required predicate capabilities

- command/subcommand equality and membership
- current/previous word tests
- seen/not-seen option tests
- mutually exclusive option groups
- positional argument ranges
- prefix/suffix/glob/regex/string tests
- file/path existence and type tests through the asynchronous cache
- environment and shell-variable tests through immutable snapshots
- source helper predicates normalized from Bash/Zsh/Fish
- boolean composition and bounded control flow

### 5.4 Required candidate capabilities

- static values
- options with short/long aliases
- subcommands
- files/directories with extension and type filters
- users/groups/hosts/services/signals/jobs/variables
- aliases/functions/builtins/commands
- values derived from context and environment
- values derived from cached dynamic probes
- descriptions
- source provenance
- insertion policy, quoting policy, ordering policy, and append-space policy

### 5.5 VM requirements

- No recursion without a verified finite depth bound.
- Instruction, stack, list, string, regex, and output budgets.
- Forward jumps and loops must be structurally validated and bounded.
- No direct syscalls from IR.
- No arbitrary shell execution.
- No arbitrary environment mutation.
- Every opcode has deterministic semantics and conformance tests.
- Unknown required opcodes reject the pack.

## 6. Source converters

### 6.1 Bash converter

The converter must cover the complete pinned `bash-completion` baseline, including:

- `complete` actions and options
- `compopt`
- `COMPREPLY`
- `COMP_WORDS`, `COMP_CWORD`, `COMP_LINE`, `COMP_POINT`, `COMP_TYPE`, and `COMP_KEY`
- `_comp_*` helpers used by the baseline
- shell functions, local variables, arrays, expansions, conditionals, loops, cases, and bounded helper calls
- glob, regex, parameter expansion, and word splitting semantics needed by the baseline
- command substitution converted to typed dynamic probes and Rust transforms
- `nospace`, `filenames`, `dirnames`, `plusdirs`, `default`, `bashdefault`, `nosort`, and quoting behavior
- lazy-loader registration aliases

The runtime must not contain or execute the source Bash functions.

### 6.2 Fish converter

The converter must cover the complete pinned Fish completion baseline, including:

- every `complete` declaration and command alias/wrap
- short, long, and old-style options
- required/optional arguments
- descriptions and ordering
- file-completion enable/disable semantics
- conditions (`-n`/`--condition`)
- argument producers (`-a`/`--arguments`)
- `__fish_*` helpers used by completion files
- command substitutions converted to typed probes
- Fish list/string/glob semantics needed by the baseline

### 6.3 Zsh converter

The converter must cover the complete pinned Zsh Completion baseline, including:

- `#compdef` registrations and service aliases
- `_arguments`, `_describe`, `_values`, `_alternative`, `_wanted`, `_requested`, `_tags`, and relevant helpers
- state transitions and context arrays
- option groups, exclusions, repetition, argument arity, and descriptions
- file and value actions
- dynamic command substitutions converted to typed probes
- helper functions used by all pinned command completion files
- per-file license overrides

### 6.4 No unsupported baseline

For the first Stable release of each pack:

- every source completion file must compile
- every registration must be represented
- every reachable construct must have an implementation
- no command may be substituted with generic completion
- no unsupported report may remain
- no stale command may exist

## 7. Multi-source evaluation, merge, and deduplication

### 7.1 Independent evaluation

For a command present in multiple installed packs:

1. Load each compatible command block independently.
2. Evaluate each source state machine against the same normalized Bash context.
3. Collect candidate and dynamic probe requests separately.
4. Deduplicate probes before execution.
5. Merge candidate outputs.

Source state machines are never rewritten into one mixed state machine at runtime.

### 7.2 Candidate identity

Canonical deduplication key:

```text
replacement_start
replacement_end
normalized insertion bytes
```

Candidates with the same display text but different insertion text remain distinct.

### 7.3 Metadata merge

- Candidate set is the union of all sources.
- Exact duplicate insertion appears once.
- Source provenance is a bitset/list.
- Metadata conflict priority: `user > bash > fish > zsh`.
- A missing description may be filled by any lower-priority source.
- `nospace` wins over append-space as the conservative choice.
- Actual filesystem type overrides inferred file type.
- Multi-source agreement may receive a small bounded ranking bonus.
- Source priority never removes a unique candidate.

### 7.4 Generic fallback

The existing Rust generic provider remains available for commands absent from every installed pack and for contexts explicitly requesting generic files, directories, users, hosts, variables, or commands. It must not be counted as successful command-rule conversion in baseline coverage.

## 8. Dynamic probes

### 8.1 Trigger policy

- Static IR can run during ordinary completion and ghost calculation.
- External processes may start only after explicit `Tab`.
- Typing, redisplay, syntax highlighting, and automatic ghost updates never spawn processes.

### 8.2 Probe representation

A probe declares:

- executable identity
- literal and context-derived argv elements
- allowed working-directory policy
- environment allowlist and explicit overrides
- stdin policy (closed by default)
- stdout parser/transforms
- stderr policy
- timeout
- output and candidate limits
- cache key and TTL
- source capability/provenance

Pipelines, `sed`, `awk`, `grep`, sorting, splitting, and filtering are represented as Rust transforms rather than shell commands.

### 8.3 Execution

- Use `posix_spawnp`; do not run `sh -c`, `bash -c`, or another shell.
- One supervisor thread owns nonblocking pipes and child state.
- At most two child probes run concurrently.
- Cancel obsolete generations and terminate their process groups.
- Close stdin, cap stdout, suppress or cap stderr, and sanitize inherited environment.
- Results are generation-tagged and cannot update a changed command line.
- Static/cached candidates display immediately; fresh results merge without a placeholder or flash.

### 8.4 Trust

- Official packs have independent signing keys.
- Signed capability manifests authorize only declared executable templates.
- New executable capabilities require human review in the rule repository.
- Unsigned packs are static-only unless the user explicitly grants local trust.
- Pack signatures do not bypass structural/resource validation.

## 9. Loading and caching

### 9.1 Search paths

In order:

```text
BASHLUME_RULE_PATH
${XDG_DATA_HOME:-$HOME/.local/share}/bashlume/rules
installation share/bashlume/rules
```

### 9.2 Startup behavior

- Bash's main thread performs no directory traversal or pack reads.
- The supervisor discovers packs asynchronously.
- Only headers and indexes are mmap'd.
- Command blocks decode lazily.
- Pending loading is visually silent.

### 9.3 Cache

- Decoded command blocks use a bounded LRU.
- Probe results have source-defined TTLs within global bounds.
- Rule-cache memory is accounted together with existing completion cache limits or by a separately bounded sub-budget whose total remains bounded.
- Pack updates invalidate blocks by pack ID, command hash, and source commit.

## 10. Candidate descriptions

Implemented prerequisite in BashLume 0.1.5:

- `Candidate.description`
- selected-item detail row by default
- `BASHLUME_MENU_DESCRIPTIONS=selected|inline|off`
- bounded, control-safe truncation
- description-preserving deduplication

Remaining integration:

- populate descriptions from all rule packs
- merge missing descriptions across sources
- retain provenance internally
- add PTY tests using real rule-pack descriptions

## 11. Workflow and release policy

### 11.1 Stable channel

- Track official upstream tags.
- Fetch and pin exact commits.
- Build deterministic pack.
- Run full converter, differential, license, provenance, security, and resource tests.
- Open an update PR; never push generated upstream changes directly to `main`.
- Publish only after review and all gates pass.

### 11.2 Edge channel

- Check upstream `main` every six hours.
- Build and test candidate packs.
- Publish prereleases only when the complete current snapshot passes.
- Open issues for newly unsupported constructs.
- Never promote automatically to Stable.

### 11.3 Post-baseline per-command transaction policy

After a complete initial Stable baseline exists:

- successfully converted commands may update independently
- a newly failing command retains its last-known-good compiled block
- it is marked `stale` with the failing source commit and reason
- shared helper changes update all dependents transactionally
- coverage may never silently decrease
- Stable release notes list every stale command

This mechanism is forbidden in the initial Stable baseline.

### 11.4 Core integration workflow

- Maintain a lock manifest containing pack release URLs, versions, format versions, and hashes.
- Test latest compatible Stable packs and optional Edge packs.
- Do not bundle optional packs into the core derivation.
- Nix/package-manager outputs install selected packs side by side.
- Runtime performs no update checks.

## 12. Differential and conformance testing

### 12.1 Exact normalized differential tests

For each source rule and generated context, compare the original source shell completion against the Rust IR result in an identical hermetic fixture.

Compare:

- candidate insertion text
- descriptions
- append-space/nospace
- candidate type
- ordering where source requires it
- subcommand and option state
- mutual exclusions
- dynamic probe requests and parsed results
- final Bash quoting and replacement range

Only explicitly documented target-Bash normalization may differ. Arbitrary supersets and “contains expected examples” tests are insufficient.

### 12.2 Fixtures

- deterministic filesystem tree
- deterministic Git repositories and refs
- fixed users/groups/hosts/services
- fixed environment variables
- mocked target executables for dynamic probes
- network disabled
- locale and terminal fixed

### 12.3 Generated coverage

Every command must include at least:

- root context
- empty query
- subcommand context
- option context
- option argument context
- positional argument context
- invalid/incomplete context
- quoted context
- dynamic context when applicable

Use source-derived cases, property testing, mutation testing, and generated command-line states.

### 12.4 Core security tests

- malformed/truncated pack corpus
- invalid offsets and integer overflow
- decompression bombs
- invalid UTF-8 where forbidden
- unknown opcodes
- stack/instruction/loop limits
- invalid signatures and Merkle leaves
- denied probe capabilities
- timeout/cancellation/process-group cleanup
- terminal-control injection in candidate text and descriptions

### 12.5 Performance gates

Retain existing gates and add:

- pack discovery does not block Readline
- indexed command lookup p99 target below 100 µs once index is ready
- static evaluation and three-source merge p99 target below 500 µs for representative command rules
- no unbounded allocation or candidate generation
- startup and standard-workload private memory remain within documented budgets
- first lazy load and dynamic probes are asynchronous

## 13. Packaging

Core outputs:

```text
bashlume-core
bashlume-pack-tool
```

Rule outputs:

```text
bashlume-rules-bash-stable
bashlume-rules-bash-edge
bashlume-rules-zsh-stable
bashlume-rules-zsh-edge
bashlume-rules-fish-stable
bashlume-rules-fish-edge
```

Recommended default meta-package:

```text
bashlume = bashlume-core + bash stable rules
```

Zsh and Fish packs remain explicit optional packages. Installing more than one pack enables merged candidate output automatically.

## 14. Runtime observability

Extend commands:

```text
bashlume status
bashlume rules
bashlume stats
```

`bashlume rules` must report:

- discovered packs
- signature/trust status
- format compatibility
- source version and commit
- command count
- current/stale counts
- loaded command blocks
- cache memory
- probe capabilities and denied requests
- errors without exposing sensitive environment values

Warnings are emitted once and never corrupt the input line.

## 15. Implementation sequence

Intermediate commits are allowed, but no intermediate state may be presented as completion of this plan.

### Phase A — Specification and legal boundary

- [ ] Relicense BashLume core to GPL-2.0-or-later.
- [ ] Add SPDX and provenance policy.
- [ ] Finalize binary format and IR specification.
- [ ] Add conformance fixture format and versioning policy.

### Phase B — Core pack infrastructure

- [ ] Implement bounded `.blp` parser and validator.
- [ ] Implement signatures, manifest verification, and command-block hashes.
- [ ] Implement mmap index and asynchronous discovery.
- [ ] Implement current/previous major compatibility.
- [ ] Implement pack inspection/build tool.
- [ ] Add malformed-pack fuzz/property tests.

### Phase C — IR and completion integration

- [ ] Expand normalized command-line context.
- [ ] Implement all required static VM opcodes.
- [ ] Implement lazy command block cache.
- [ ] Evaluate all installed source rules independently.
- [ ] Merge/deduplicate candidates and descriptions with provenance.
- [ ] Integrate static rule candidates into Tab and ghost paths.
- [ ] Add status/rules observability.

### Phase D — Dynamic probes

- [ ] Extend the one-thread worker into a nonblocking supervisor.
- [ ] Implement `posix_spawnp`, two-child concurrency, timeout, cancellation, and output limits.
- [ ] Implement capability manifests and trust enforcement.
- [ ] Implement probe transforms and cache.
- [ ] Merge late results into the menu without placeholders or flicker.

### Phase E — Rule repositories and converters

- [ ] Create and initialize Bash rule repository.
- [ ] Create and initialize Zsh rule repository.
- [ ] Create and initialize Fish rule repository.
- [ ] Implement source-specific parser/compiler pipelines.
- [ ] Implement source helper semantics required by every pinned baseline file.
- [ ] Generate deterministic packs and provenance manifests.
- [ ] Reach zero unsupported/stale rules for initial baselines.

### Phase F — Differential validation

- [ ] Implement Bash oracle harness and exact comparison.
- [ ] Implement Zsh oracle harness and exact comparison.
- [ ] Implement Fish oracle harness and exact comparison.
- [ ] Build hermetic dynamic fixtures and mocked programs.
- [ ] Prove complete registration/file coverage.
- [ ] Run security, resource, Bash 5.0/5.3, tmux, and terminal tests.

### Phase G — Workflows and packaging

- [ ] Add Stable/Edge synchronization workflows to each rule repository.
- [ ] Add deterministic release/signing workflows.
- [ ] Add core pack-lock update PR workflow.
- [ ] Add Nix outputs and local rule search paths.
- [ ] Verify runtime is offline and builds are pinned/reproducible.

### Phase H — Complete release gate

- [ ] All three initial pinned baselines compile with zero unsupported and zero stale commands.
- [ ] Exact normalized differential suites pass.
- [ ] Core and all pack CI/workflows pass.
- [ ] Licensing/provenance audit passes.
- [ ] Dynamic probe security tests pass.
- [ ] Performance/resource gates pass.
- [ ] Real interactive testing confirms merged Bash+Zsh+Fish candidates and descriptions.
- [ ] Documentation and migration instructions are complete.

## 16. Definition of done

This project is complete only when all of the following are true:

1. The BashLume core loads and validates separately installed pure-data packs.
2. Bash, Zsh, and Fish rule projects exist with working Stable/Edge workflows.
3. The pinned initial baseline of every project has zero unsupported and zero stale rules.
4. The core evaluates installed packs in Rust without source-shell runtime dependencies.
5. Candidates from all installed packs are merged and deduplicated correctly.
6. Dynamic probes are Tab-only, asynchronous, signed-capability controlled, bounded, cached, and cancellable.
7. Exact normalized differential tests pass against every pinned upstream rule baseline.
8. Runtime remains offline, Readline remains responsive, and failure safely falls back.
9. Licensing and per-rule provenance are complete and accurate.
10. Nix builds, Bash 5.0/5.3 PTY tests, tmux tests, resource tests, and strict performance tests pass.

Anything less is implementation progress, not completion.
