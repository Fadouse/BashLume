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

Bash itself is single-threaded. Two independently bounded workers each request a 256 KiB stack. The cache worker reads directories, bounded account/host/SSH/process/network snapshots, and local rule-pack indexes/blocks; it also seals and lazily decodes authenticated packs. A separate probe supervisor owns nonblocking pipes and at most two signed-capability children, so filesystem or pack I/O cannot delay probe admission, deadlines, or cancellation. Neither worker reads or writes Bash/Readline globals, and both communicate through bounded request channels.

Dynamic probes are emitted only by an explicit Tab evaluation of a trusted pack. They use direct argument vectors rather than shell command strings, reject relative/empty PATH components and loader/startup-hook environment variables, apply bounded output, wall-time, process, address-space, descriptor, CPU, and file-size controls, and publish timeout failure without waiting for inherited pipe EOF. Generation-based cancellation is out-of-band and remains polled until acknowledged. Ordinary typing and ghost evaluation never spawn processes.

A checked `pthread_atfork` child hook restores the pre-probe SIGCHLD mask and marks the inherited plugin inactive. A forked child therefore neither inherits BashLume's temporary signal coordination nor touches channels or locks inherited while workers may have been active. A newly executed interactive Bash loads a fresh plugin instance normally.

## Rule conversion pipeline

The Bash, Zsh, and Fish rule projects pin complete upstream source trees. At build time, `bashlume-pack transpile-shell` uses BashLume's own dialect-aware lexer/parser to produce a bounded Script IR data AST. A support-library index resolves statically reachable functions (including Zsh autoload functions), while registration walkers retain Bash `complete`, Fish `complete`, and Zsh `#compdef` service/pattern semantics. This is analysis of fixed source data, not invocation of the source shell.

The support linker follows registered entries with a reachable call graph and scope-local constant-prefix analysis; Bash `_comp_xfunc` and `_comp_compgen` targets are resolved from their data arguments rather than by linking whole helper families. For Zsh, the converter derives a bounded names-only `fpath` snapshot and native function-hash insertion/resize state from the configured bootstrap AST and ordered roots; this preserves complete `${(k)functions}` membership and scan order without retaining unreachable function bodies. Call-scoped tag and label state models `_tags`, `_next_label`, `_wanted`, `_requested`, and `_all_labels`. The pack builder validates registrations, AST structure, resources, and the equality of manifest/module probe-capability sets before encoding command blocks. At runtime only validated `.blp` structures are decoded. No upstream completion text is loaded, parsed, sourced, or passed to a shell. External values can be requested only through the signed, explicit-Tab probe path described above. Before any mapped byte is retained, a bounded pack is copied to a Linux `memfd`, sealed against writes/growth/shrinkage, and then mapped; replacing or truncating a mutable installation path therefore cannot SIGBUS the host Bash process. Script filesystem tests, globs, and regular-file input emit bounded pure-data replay requests; the worker resolves them with type and size limits, and the Script VM never opens a path itself. Compound redirections are typed Script IR nodes rather than runtime-parsed shell text.

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

The main thread only sends scan, typed filesystem-replay, snapshot, and probe requests and consumes completed responses. It never calls `read_dir`, `stat`, opens completion data files, or starts external programs while handling a key. Worker request FIFOs and every pending set are bounded; repeated directory generations are coalesced, and stop/cancellation have out-of-band atomic priority signals. Filesystem replay is generation-scoped to the current line and cursor, pins one coherent cache snapshot while an evaluation converges, and applies backpressure: an unscheduled request remains pending and is retried by menu polling rather than being replayed as a false empty result. Cache age starts at the worker's completion timestamp rather than the later time at which an idle main thread consumes the response. PATH directories, command names, shell names/variables, history, filesystem replay entries, processes, interfaces, accounts, and hosts all have explicit item and byte bounds.

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
