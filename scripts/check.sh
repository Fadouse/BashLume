#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
cargo test --release -- --ignored --nocapture
shellcheck shell/bashlume.bash scripts/check.sh
python3 tests/pty_smoke.py target/release/libbashlume.so
python3 tests/tmux_bottom.py target/release/libbashlume.so
if [[ -n ${BASHLUME_TEST_BASH:-} ]]; then
  python3 tests/pty_smoke.py target/release/libbashlume.so --bash "$BASHLUME_TEST_BASH"
fi
python3 tests/resource_budget.py target/release/libbashlume.so
