# Changelog

## 0.2.0 — Unreleased

- Relicense the BashLume core from MIT to GPL-2.0-or-later in preparation for separately distributed completion rule packs derived from GPL ecosystems.
- Add the bounded, versioned `.blp` container, signed manifests, independently hashed command blocks, a pure-data Completion IR, and `bashlume-pack` build/inspection tooling.
- Discover rule packs asynchronously, mmap their indexes, decode command blocks lazily, and expose pack status through `bashlume rules`.
- Evaluate static rules in a bounded Rust VM and merge candidates from every installed source with description preservation, conservative spacing, and source agreement metadata.
- Add signed, capability-declared, Tab-only dynamic probes supervised through `posix_spawnp` with concurrency, timeout, output, cache, and shell-execution limits.
- Add Completion IR block version 2 and pack format 1.1 path policies so matched rules can suppress files, request directories, or force file completion while version-1 blocks remain readable.

## 0.1.5 — 2026-07-23

- Add optional human-readable descriptions to completion candidates.
- Show the selected candidate's description on one bounded detail row by default while preserving the compact multi-column menu.
- Add `BASHLUME_MENU_DESCRIPTIONS=selected|inline|off`.
- Seed native Bash reserved-word candidates with descriptions so the new UI is immediately testable before external rule packs arrive.

## 0.1.4 — 2026-07-23

- Keep pending completion scans visually silent instead of flashing a `scanning…` row.
- Continue to reveal candidates automatically as soon as the worker completes.
- Remove the now-unused `BASHLUME_COLOR_MENU_META` setting.

## 0.1.3 — 2026-07-23

- Automatically replace `scanning…` with completed candidates without requiring another keypress.
- Install Readline's periodic event hook only while an asynchronous menu or delayed diagnostic is pending, then remove it again to avoid idle wakeups.
- Compare candidate snapshots before repainting so an unfinished scan does not cause continuous redraws.
- Measure cache freshness from worker completion time rather than delayed main-thread receipt time.
- Prevent unavailable workers and completed empty menus from remaining permanently pending or sticky.

## 0.1.2 — 2026-07-23

- Add an explicit marker for definite syntax errors while valid input remains uncolored.
- Keep exact and longer prefix candidates together, so completing `who` also lists `whoami`.
- Replace type-label rows with Readline-style colored columns that follow `LS_COLORS`.
- Return from completion overlays with relative cursor movement, preventing repeated/corrupted menus when the terminal scrolls at its bottom edge.
- Add PTY and tmux bottom-edge regressions.

## 0.1.1 — 2026-07-23

- Make errors-only highlighting the default; valid Bash input now keeps the terminal's normal color.
- Add `BASHLUME_HIGHLIGHT=errors|full|off`.
- Force-refresh current-directory completion snapshots at each prompt.
- Suppress path ghost suggestions while their directory cache is refreshing.
- Validate `cd` and `pushd` history predictions against the live filesystem cache.
- Add regression coverage for deleted directories and errors-only rendering.

## 0.1.0 — 2026-07-23

- Initial BashLume implementation.
