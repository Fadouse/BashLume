# BashLume

BashLume is a lightweight, in-process completion and syntax-highlighting plugin for GNU Bash. It keeps GNU Readline as the line editor and adds only the parts Readline does not provide: incremental Bash highlighting, ranked completion, interactive candidate menus, and fish-like ghost suggestions.

Copyright © 2026 **Fadouse**. Distributed under the GNU General Public License, version 2 or (at your option) any later version (`GPL-2.0-or-later`).

## Features

- Incremental Bash parsing through Tree-sitter Bash
- Errors-only highlighting by default, including an explicit `✗` marker; optional full semantic colors for commands, builtins, keywords, strings, variables, comments, operators, redirects, options, and paths
- Valid/unknown command classification after the asynchronous `PATH` cache is ready
- History-based and generic prefix ghost suggestions
- Layered candidate matching:
  1. exact match
  2. case-sensitive prefix
  3. case-insensitive prefix
  4. substring
  5. fuzzy subsequence
- Versioned, signed, pure-data `.blp` command-rule packs evaluated by a bounded Rust VM
- Multi-source Bash/Zsh/Fish candidate union with insertion-level deduplication and provenance-aware metadata
- Tab-only asynchronous dynamic probes with signed capability declarations and no shell execution
- Generic completion for:
  - executables on `PATH`
  - Bash builtins, aliases, and functions
  - files and directories
  - Bash variables
  - users and groups
  - `/etc/hosts`, bounded SSH config includes, and known hosts
  - process IDs/names, network interfaces, signals, commands, functions, and variables from bounded snapshots
  - Bash reserved words
- Context-aware shell quoting for spaces and metacharacters
- Readline-style, `LS_COLORS`-aware columnar completion menus with optional candidate descriptions
- Exact candidates remain visible beside longer prefix candidates (`who`, `whoami`)
- Bounded asynchronous filesystem scanning and Script-IR filesystem replay with silent, automatic pending-menu refresh
- Native Readline Emacs and Vi keymaps remain intact
- Safe fallback to unmodified Readline when loading fails

BashLume never sources Bash, Zsh, or Fish completion scripts at runtime. Separate rule projects use BashLume's own dialect-aware lexer/parser to compile fixed upstream source and reachable support functions into validated, pure-data Script IR inside `.blp` files; BashLume discovers local packs asynchronously and evaluates that IR in a bounded Rust VM. Source shells are permitted only in rule-project CI as differential-test oracles, never as runtime parsers or completion engines. The complete rollout is tracked in [`docs/rule-packs-plan.md`](docs/rule-packs-plan.md), and the format is documented in [`docs/rule-pack-format.md`](docs/rule-pack-format.md).

## Requirements

- x86_64 or AArch64 Linux
- GNU Bash 5.0 or newer, built with dynamic builtin loading
- GNU Readline 8.x
- An ANSI-compatible terminal (`xterm`, Kitty, tmux, screen, and common SSH terminals)

`TERM=dumb` is intentionally left untouched. The PTY suite is verified against Bash 5.0 with its bundled Readline 8.0 and Bash 5.3 with Readline 8.3.

## Build

### Nix

```bash
nix build
```

The default output is the core plus the pinned Stable Bash rule pack. It contains:

```text
result/lib/bash/libbashlume.so
result/lib/bash/bashlume-probe  # internal pre-exec sandbox helper
result/bin/bashlume-pack
result/share/bashlume/bashlume.bash
result/share/bashlume/rules/bash.blp
```

Release-bound outputs are also available independently:

```bash
nix build .#bashlume-core
nix build .#bashlume-pack-tool
nix build .#bashlume-rules-bash-stable
nix build .#bashlume-rules-fish-stable
nix build .#bashlume-rules-zsh-stable
nix build .#bashlume-with-all-rules
```

Each rule derivation fetches the release URL and SHA-256 pinned in `rules/packs.lock`, then verifies the pack with its source-specific official key before installation. Fish and Zsh remain explicit optional data packages; the core derivation embeds no upstream rule data. The loader resolves sibling `rules` and `trusted-keys` directories, so installing independent outputs into the same Nix profile also activates them without hard-coded profile paths.

### Cargo

```bash
cargo build --release
```

Then source the development loader:

```bash
source /path/to/BashLume/shell/bashlume.bash
```

## Bash startup integration

Build first, then add this near the end of `.bashrc`:

```bash
source /path/to/BashLume/result/share/bashlume/bashlume.bash
```

For a development checkout, this also works:

```bash
source /path/to/BashLume/shell/bashlume.bash
```

The loader looks for `result/lib/bash/libbashlume.so` and then `target/release/libbashlume.so`. Set `BASHLUME_LIBRARY` to override the location.

## Installing and migrating rule packs

The Bash, Fish, and Zsh packs are separate release artifacts; the core package does not embed their differently licensed data. The current Stable releases are [Bash v0.2.0](https://github.com/Fadouse/BashLume-Rules-Bash/releases/tag/v0.2.0), [Fish v0.2.0](https://github.com/Fadouse/BashLume-Rules-Fish/releases/tag/v0.2.0), and [Zsh v0.2.0](https://github.com/Fadouse/BashLume-Rules-Zsh/releases/tag/v0.2.0). For each desired source, download all files listed by its release `SHA256SUMS` (including the `.blp`, matching `verifying-key.hex`, provenance, and coverage manifests), then verify and install them locally:

```bash
sha256sum -c bash.SHA256SUMS
bashlume-pack verify bash.blp verifying-key.hex
install -Dm644 bash.blp "$HOME/.local/share/bashlume/rules/bash.blp"
install -Dm644 verifying-key.hex \
  "$HOME/.config/bashlume/trusted-keys/bash-rules.pub"
```

Repeat with distinct filenames for Fish and Zsh, then start a new Bash or run `bashlume reload`. `bashlume rules` must show each pack as `Verified`, compatible, and non-stale before its dynamic providers are enabled. Unsigned or unknown-key packs remain static-only. To roll back one source, remove only its `.blp` and reload; to use a system package, leave `BASHLUME_RULE_PATH` and `BASHLUME_TRUSTED_KEY_PATHS` unset so the packaged loader can append its own `share/bashlume` directories. Existing custom paths remain supported and are colon-separated.

Stable release tags, embedded pack versions, checksums, and provenance are bound to the same reviewed rule-repository commit. Rebuilding provenance additionally requires the pinned upstream and compiler commits recorded in `rules.lock`. The independent v0.2.0 bindings and verification record are documented in [`docs/releases/v0.2.0-rule-packs.md`](docs/releases/v0.2.0-rule-packs.md).

## Keys

| Key | Normal editing | With suggestion/menu |
|---|---|---|
| `Tab` | Complete or open ranked menu | Select next candidate |
| `Shift-Tab` | Open/cycle backward | Select previous candidate |
| `Right Arrow` at EOL | Original Readline behavior when no suggestion | Accept the complete ghost suggestion |
| `End` at EOL | Original Readline behavior when no suggestion | Accept the complete ghost suggestion |
| `Alt-Right` | Original Readline behavior when no suggestion | Accept the next shell word |
| `Enter` | Execute line | Insert selected menu candidate; press again to execute |
| `Ctrl-G` | Original Readline abort | Close candidate menu |
| `Esc` in Vi insert mode | Enter Vi command mode | Also closes menu and hides suggestions |

BashLume binds only Readline's `emacs-standard` and `vi-insertion` maps. Vi command-mode motions such as `h`, `l`, `w`, and `b` are never replaced.

## Runtime commands

```bash
bashlume status
bashlume disable
bashlume enable
bashlume reload
bashlume stats
bashlume rules         # pack trust, provenance, compatibility, and errors
enable -d bashlume    # fully unload and restore callbacks/bindings
```

## Configuration from `.bashrc`

Variables do not need to be exported. Set them **before** sourcing the loader, or run `bashlume reload` after changing them.

```bash
BASHLUME_CACHE_MIB=64
BASHLUME_MAX_CANDIDATES=4096
BASHLUME_MENU_ROWS=10

# on (default) | off
BASHLUME_GHOST=on

# selected (default) | inline | off
BASHLUME_MENU_DESCRIPTIONS=selected

# Colon-separated local pack files/directories; runtime never downloads packs.
BASHLUME_RULE_PATH="$HOME/.local/share/bashlume/rules"
# Colon-separated Ed25519 public-key files/directories authorizing dynamic probes.
BASHLUME_TRUSTED_KEY_PATHS="$HOME/.config/bashlume/trusted-keys"

# errors (default) | full | off
BASHLUME_HIGHLIGHT=errors

# off | marker (default) | inline
BASHLUME_DIAGNOSTICS=marker
BASHLUME_DIAGNOSTIC_DELAY_MS=300

BASHLUME_COLOR_COMMENT='2;38;5;244'
BASHLUME_COLOR_ERROR='4;38;5;203'
BASHLUME_COLOR_GHOST='2;38;5;244'
```

Supported color variables:

```text
BASHLUME_COLOR_NORMAL
BASHLUME_COLOR_COMMAND
BASHLUME_COLOR_BUILTIN
BASHLUME_COLOR_UNKNOWN_COMMAND
BASHLUME_COLOR_KEYWORD
BASHLUME_COLOR_STRING
BASHLUME_COLOR_VARIABLE
BASHLUME_COLOR_COMMENT
BASHLUME_COLOR_OPERATOR
BASHLUME_COLOR_REDIRECT
BASHLUME_COLOR_OPTION
BASHLUME_COLOR_NUMBER
BASHLUME_COLOR_PATH
BASHLUME_COLOR_ERROR
BASHLUME_COLOR_GHOST
BASHLUME_COLOR_MENU_SELECTED
BASHLUME_COLOR_COMPLETION_DIRECTORY
BASHLUME_COLOR_COMPLETION_EXECUTABLE
BASHLUME_COLOR_COMPLETION_FILE
```

Values are SGR parameter lists without `ESC[` or the final `m`. Invalid values are rejected to prevent terminal escape injection. Completion directory, executable, regular-file, and filename-extension colors follow `LS_COLORS`; the three completion variables above override its base type colors. `NO_COLOR` disables syntax colors.

Candidate descriptions default to a single detail row for the selected item, preserving the compact multi-column menu. `inline` places descriptions beside each candidate when space permits; `off` hides them. The description row counts toward `BASHLUME_MENU_ROWS` and is safely truncated at the terminal edge.

Packaged installations include the three official rule-pack public keys under `share/bashlume/trusted-keys`; the packaged loader adds that directory automatically. A trusted signature authorizes only the probe executables declared by that pack and never bypasses format, hash, opcode, timeout, or output-limit validation. User-provided unsigned packs remain static-only.

Set `BASHLUME_DISABLE=1` before loading for an emergency startup bypass.

## Resource policy

Release builds perform no runtime benchmarking or acceptance checks.

Development checks enforce:

- incremental syntax-highlighting p99 below 0.5 ms for an approximately 1 KiB line
- generic ranking thread-CPU p99 below 0.5 ms across 5,000 command names
- additional private memory below 3.75 MiB (3,840 KiB) in the standard smoke workload
- aggregate cache and mapped-rule hard limit of 64 MiB by default
- top 4,096 candidates retained per scan by default

Run all development checks with:

```bash
nix develop -c ./scripts/check.sh
```

## Design boundaries

- BashLume preserves Bash's native `PS2` continuation model; it does not replace Readline with a multiline editor.
- Previously submitted continuation lines are not made editable again.
- Invalid UTF-8 filesystem names are skipped rather than inserted incorrectly.
- Completion caches may briefly show stale entries; they refresh asynchronously and are bounded with LRU eviction.
- Separate bounded workers handle filesystem I/O and at most two capability-authorized probes. Neither calls Bash APIs. Probes are Tab-only and shell-free: `posix_spawnp` starts the co-installed sandbox helper, which applies limits and a process-group confinement filter before `execvp` replaces it with the declared target.

See [`docs/architecture.md`](docs/architecture.md) for the FFI, threading, and redisplay design.

## 中文简介

BashLume 是一个轻量级 Bash 原生插件。它保留 GNU Readline，只增加错误高亮、幽灵建议、模糊补全与交互候选菜单。默认仅标记明确语法错误，正确语法保持终端原色；补全列表使用类似 Readline/Bash 的彩色分栏布局并遵循 `LS_COLORS`。设置 `BASHLUME_HIGHLIGHT=full` 可启用完整语义着色。默认缓存上限为 16 MiB，文件系统扫描在单独的受限后台线程中执行；加载失败时自动回退到 Bash 原生行为。

常用配置可直接写入 `.bashrc`，无需 `export`。完整卸载命令为：

```bash
enable -d bashlume
```
