# Changelog

## 0.1.1 — 2026-07-23

- Make errors-only highlighting the default; valid Bash input now keeps the terminal's normal color.
- Add `BASHLUME_HIGHLIGHT=errors|full|off`.
- Force-refresh current-directory completion snapshots at each prompt.
- Suppress path ghost suggestions while their directory cache is refreshing.
- Validate `cd` and `pushd` history predictions against the live filesystem cache.
- Add regression coverage for deleted directories and errors-only rendering.

## 0.1.0 — 2026-07-23

- Initial BashLume implementation.
