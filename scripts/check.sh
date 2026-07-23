#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
cargo test --release -- --ignored --nocapture
shellcheck shell/bashlume.bash scripts/check.sh
rule_pack=$(mktemp --suffix=.blp)
trap 'rm -f -- "$rule_pack"' EXIT
target/release/bashlume-pack build \
  tests/fixtures/rules/demo.json "$rule_pack" \
  tests/fixtures/rules/test-signing-key.hex
rule_arguments=(
  --rule-pack "$rule_pack"
  --trusted-key tests/fixtures/rules/test-verifying-key.hex
)
python3 tests/pty_smoke.py target/release/libbashlume.so "${rule_arguments[@]}"
python3 tests/tmux_bottom.py target/release/libbashlume.so
if [[ -n ${BASHLUME_TEST_BASH:-} ]]; then
  python3 tests/pty_smoke.py target/release/libbashlume.so \
    --bash "$BASHLUME_TEST_BASH" "${rule_arguments[@]}"
fi
python3 tests/resource_budget.py target/release/libbashlume.so
