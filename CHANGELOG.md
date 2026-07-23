# Changelog

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
