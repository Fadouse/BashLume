# Architecture

## Goals

BashLume adds modern interactive features without replacing GNU Readline. The hot path must remain bounded, Bash must stay usable after any recoverable plugin failure, and no filesystem operation may block Readline's main input thread.

## Components

```text
Bash
 ├─ loadable builtin ABI
 ├─ Bash symbol snapshot (main thread only)
 └─ GNU Readline
     ├─ original editor and redisplay
     ├─ BashLume redisplay overlay
     └─ BashLume key widgets

Rust core
 ├─ Tree-sitter Bash incremental parser
 ├─ semantic highlighter
 ├─ generic and native rule-pack providers
 ├─ signed `.blp` index/manifest verifier
 ├─ bounded Completion IR VM and multi-source merger
 ├─ candidate matcher/ranker
 ├─ context-aware quoting
 ├─ terminal renderer
 └─ bounded cache
      └─ one I/O supervisor thread
          ├─ filesystem and lazy rule-block loading
          └─ at most two bounded dynamic probe children
```

## Readline integration

BashLume saves and wraps `rl_redisplay_function`. Each redraw follows this order:

1. Call Readline's original redisplay function.
2. Read the immutable `rl_line_buffer`, `rl_point`, prompt, and state.
3. Incrementally parse and classify the line.
4. Move to the start of Readline's input, clear the old overlay, and paint styled text, ghost text, and the optional menu.
5. Track the exact number of painted rows and return to Readline's cursor with relative cursor movement.

The renderer intentionally does not use the terminal's save/restore-cursor slot. When a menu reaches the bottom edge, the terminal scrolls; saved absolute cursor positions then become stale and cause repeated menus. Relative movement follows the scrolled input line and remains correct in Kitty, tmux, screen, and ordinary ANSI terminals.

Readline remains authoritative for cursor movement, undo, kill/yank, history search, bracketed paste, macros, terminal preparation, signals, and Emacs/Vi mode.

During Readline search, active-region display, macro definition, completion internals, or signal handling, BashLume does not paint an overlay.

While a completion menu is pending, BashLume temporarily wraps `rl_event_hook`. The pending state itself is visually silent. Each periodic callback consumes ready worker responses and compares the new candidate snapshot with the displayed one. It forces redisplay only when candidates or pending state changed, then restores the original event hook as soon as no asynchronous redraw remains. Idle prompts therefore do not acquire a periodic wakeup.

## Key bindings

Only `emacs-standard` and `vi-insertion` are modified. Every replaced function pointer is saved. A widget invokes the original function when BashLume has no enhancement to apply. Unload restores a binding only when it still points to BashLume, so a later user rebind is not overwritten.

Readline macros bound to one of BashLume's enhanced keys cannot be reconstructed through the public function-pointer API. The default Readline maps use functions for these keys.

## Bash FFI boundary

`src/ffi.rs` is the only declaration site for Bash and Readline symbols. Unsafe operations are limited to:

- copying NUL-terminated Bash strings
- iterating Bash-owned pointer arrays on the shell's main thread
- reading and replacing Readline buffer ranges
- saving/restoring callback and keymap function pointers
- writing the rendered overlay to the terminal

No Rust panic is allowed to unwind across a C callback. Entry points use `catch_unwind`; a redisplay panic disables enhancements and returns control to native Readline.

## Threading and fork behavior

Bash itself is single-threaded. The worker thread:

- reads directories, `/etc/passwd`, `/etc/hosts`, SSH host files, and local rule-pack indexes/blocks
- verifies and decompresses lazily requested command blocks
- supervises at most two signed-capability dynamic probes through nonblocking pipes
- never reads or writes Bash/Readline globals
- communicates through message channels
- has a 256 KiB requested stack

Dynamic probes are emitted only by an explicit Tab evaluation of a trusted pack. They use direct argument vectors rather than shell command strings, have bounded output and deadlines, and are cancelled when their menu context is abandoned. Ordinary typing and ghost evaluation never spawn processes.

A `pthread_atfork` child hook marks the inherited plugin inactive. A forked child therefore does not touch channels or locks inherited while the worker may have been active. A newly executed interactive Bash loads a fresh plugin instance normally.

## Completion pipeline

1. A tolerant shell lexer derives the word range, quote mode, current simple-command words, command name/path, and whether the cursor is in command position.
2. The rule provider requests only the matching command block from every installed compatible pack. Each source VM is evaluated independently against the same immutable context.
3. Candidate outputs are unioned and deduplicated by insertion value in the current replacement range. Source priority (`user > bash > fish > zsh`) resolves metadata only; missing descriptions are filled across sources, `nospace` wins conservatively, and unique candidates are retained.
4. The generic provider supplements contexts not owned by command rules.
5. The matcher assigns strict score bands: exact, prefix, case-insensitive prefix, substring, then fuzzy subsequence. Exact and case-sensitive prefix matches share one retained result set, so an exact `who` does not hide `whoami`; exact still sorts first.
6. Context and history add lower-order ranking bonuses.
7. The sink retains a bounded top set.
8. The insertion layer applies minimal Bash-safe quoting while preserving the user's quote style.
9. The menu lays candidates out in Readline-style top-to-bottom columns, colors filesystem types and extensions from `LS_COLORS`, and pages within a bounded physical row count. Optional provider descriptions appear on one bounded detail row for the selected candidate by default; inline and hidden modes are configurable.

`CompletionProvider` remains a compile-time Rust trait. External rule projects publish pure-data IR, never Rust/C dynamic libraries, so no unstable native plugin ABI is exposed.

## Filesystem cache

The main thread only sends scan requests and consumes completed responses. It never calls `read_dir`, `stat`, or external programs while handling a key. Cache age starts at the worker's scan-completion timestamp rather than the later time at which an idle main thread consumes the response.

A complete result for a short prefix is reused as a lossless superset for longer prefixes. The current directory is force-refreshed at every prompt, ordinary directory entries have a short freshness window, and ghost suggestions are suppressed while a relevant refresh is pending. `cd`/`pushd` history predictions perform an asynchronous full-target directory validation. If a directory result is truncated, a refined-prefix scan streams the entire directory and retains only the highest-ranked configured number of matches.

Cache memory is estimated from stored structures and strings. LRU eviction begins at the configured hard limit. The production default is 16 MiB.

## Syntax pipeline

Tree-sitter Bash provides incremental, error-tolerant concrete syntax trees. BashLume stores the previous line and tree, computes a byte-accurate `InputEdit`, and reparses against the old tree. Semantic classification then produces:

- Bash syntax categories
- known builtin/function/alias state
- asynchronously known `PATH` commands
- definite non-empty Tree-sitter error nodes

The renderer defaults to `errors` mode, which applies only definite error spans, adds a visible error marker, and leaves valid syntax in the terminal's normal color. `full` mode exposes every semantic category. Zero-width missing nodes at end-of-input are treated as unfinished interactive input, not immediate errors.

Input larger than 256 KiB safely falls back to unstyled rendering to bound paste-time work.

## Failure policy

The load callback rejects noninteractive or non-TTY sessions. ABI/load failures produce one warning and leave Readline untouched. Runtime control supports temporary disable and full `enable -d` unload.
