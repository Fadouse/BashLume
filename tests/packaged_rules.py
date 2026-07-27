#!/usr/bin/env python3
"""Verify that an installed loader discovers its co-installed rule packs."""

from __future__ import annotations

import argparse
import os
import pathlib
import time

from pty_smoke import Session, require


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("loader", type=pathlib.Path)
    parser.add_argument("--bash", dest="bash_binary", type=pathlib.Path, required=True)
    parser.add_argument("--external-pack", type=pathlib.Path)
    parser.add_argument(
        "--expect-source",
        action="append",
        choices=("bash", "fish", "zsh"),
        dest="expected_sources",
    )
    arguments = parser.parse_args()

    # Keep the loader's lexical path: resolving the file symlink would bypass
    # the package/profile directory whose sibling rules must be discovered.
    loader = pathlib.Path(os.path.abspath(arguments.loader))
    bash_binary = arguments.bash_binary.resolve()
    external_pack = (
        arguments.external_pack.resolve() if arguments.external_pack is not None else None
    )
    for path in (loader, bash_binary, external_pack):
        if path is not None and not path.is_file():
            parser.error(f"required test input is missing: {path}")
    expected_sources = arguments.expected_sources or ["bash", "fish", "zsh"]

    expected_share = loader.parent.resolve()
    session = Session(None, bash_binary, external_pack, None, loader=loader)
    try:
        status = session.send(b"bashlume status\n", 0.3)
        require(
            b"bashlume: enabled" in status,
            "the packaged loader did not initialize BashLume",
            session.output,
        )

        configured = session.send(
            b"printf 'RULES=<%s> KEYS=<%s>\\n' "
            b'"$BASHLUME_RULE_PATH" "$BASHLUME_TRUSTED_KEY_PATHS"\n',
            0.3,
        )
        require(
            str(expected_share / "rules").encode() in configured
            and str(expected_share / "trusted-keys").encode() in configured,
            "the packaged loader did not select its sibling data directories",
            session.output,
        )

        pack_ids = tuple(
            f"org.bashlume.rules.{source}".encode() for source in expected_sources
        )
        rules_output = bytearray()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all(
            pack_id in rules_output for pack_id in pack_ids
        ):
            rules_output.extend(session.send(b"bashlume rules\n", 0.4))
        require(
            all(pack_id in rules_output for pack_id in pack_ids)
            and rules_output.count(b"Verified") >= len(pack_ids),
            "the installed loader did not discover every expected verified pack",
            session.output,
        )

        if set(expected_sources) == {"bash", "fish", "zsh"}:
            checks = (
                (b"apt-cache --aud\t", b"--audit", None),
                (
                    b"\x07\x15apt-cache --f\t",
                    b"--full=",
                    b"Search full package name",
                ),
                (b"\x07\x15apt-cache --config-f\t", b"--config-file=", None),
            )
            for keys, candidate, description in checks:
                output = session.send(keys, 1.2)
                require(
                    candidate in output,
                    f"packaged merged menu omitted {candidate!r}",
                    session.output,
                )
                if description is not None:
                    require(
                        description in output,
                        f"packaged merged menu omitted {description!r}",
                        session.output,
                    )
    finally:
        session.close()

    print("Packaged loader rule discovery test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
