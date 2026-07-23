# Changelog

## 0.1.3 — 2026-07-23

- Treat statically unknown commands such as `whoim` as definite errors in the default errors-only mode.
- Keep dynamic command expressions such as `$command` unmarked because Bash resolves them only at execution time.
- Add a real-shell regression for unknown-command coloring and the error marker.

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
