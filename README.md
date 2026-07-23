# BashLume

BashLume is a lightweight, in-process completion and syntax-highlighting plugin for GNU Bash. It keeps GNU Readline as the line editor and adds only the parts Readline does not provide: incremental Bash highlighting, ranked completion, interactive candidate menus, and fish-like ghost suggestions.

Copyright © 2026 **Fadouse**. Distributed under the MIT License.

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
- Generic completion for:
  - executables on `PATH`
  - Bash builtins, aliases, and functions
  - files and directories
  - Bash variables
  - users
  - `/etc/hosts`, SSH config, and known hosts
  - Bash reserved words
- Context-aware shell quoting for spaces and metacharacters
- Readline-style, `LS_COLORS`-aware columnar completion menus with optional candidate descriptions
- Exact candidates remain visible beside longer prefix candidates (`who`, `whoami`)
- Bounded asynchronous filesystem scanning with silent, automatic pending-menu refresh
- Native Readline Emacs and Vi keymaps remain intact
- Safe fallback to unmodified Readline when loading fails

BashLume does **not** invoke programmable completion scripts while typing. The first release contains a generic provider and a compile-time Rust provider trait for future command-specific providers.

## Requirements

- Linux
- GNU Bash 5.0 or newer, built with dynamic builtin loading
- GNU Readline 8.x
- An ANSI-compatible terminal (`xterm`, Kitty, tmux, screen, and common SSH terminals)

`TERM=dumb` is intentionally left untouched. The PTY suite is verified against Bash 5.0 with its bundled Readline 8.0 and Bash 5.3 with Readline 8.3.

## Build

### Nix

```bash
nix build
```

The result contains:

```text
result/lib/bash/libbashlume.so
result/share/bashlume/bashlume.bash
```

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
enable -d bashlume    # fully unload and restore callbacks/bindings
```

## Configuration from `.bashrc`

Variables do not need to be exported. Set them **before** sourcing the loader, or run `bashlume reload` after changing them.

```bash
BASHLUME_CACHE_MIB=16
BASHLUME_MAX_CANDIDATES=4096
BASHLUME_MENU_ROWS=10

# selected (default) | inline | off
BASHLUME_MENU_DESCRIPTIONS=selected

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

Set `BASHLUME_DISABLE=1` before loading for an emergency startup bypass.

## Resource policy

Release builds perform no runtime benchmarking or acceptance checks.

Development checks enforce:

- incremental syntax-highlighting p99 below 0.5 ms for an approximately 1 KiB line
- generic ranking p99 below 0.5 ms across 5,000 command names
- additional private memory below 3 MiB in the standard smoke workload
- cache hard limit of 16 MiB by default
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
- A background thread performs filesystem I/O only. It never calls Bash APIs.

See [`docs/architecture.md`](docs/architecture.md) for the FFI, threading, and redisplay design.

## 中文简介

BashLume 是一个轻量级 Bash 原生插件。它保留 GNU Readline，只增加错误高亮、幽灵建议、模糊补全与交互候选菜单。默认仅标记明确语法错误，正确语法保持终端原色；补全列表使用类似 Readline/Bash 的彩色分栏布局并遵循 `LS_COLORS`。设置 `BASHLUME_HIGHLIGHT=full` 可启用完整语义着色。默认缓存上限为 16 MiB，文件系统扫描在单独的受限后台线程中执行；加载失败时自动回退到 Bash 原生行为。

常用配置可直接写入 `.bashrc`，无需 `export`。完整卸载命令为：

```bash
enable -d bashlume
```
