#!/usr/bin/env python3
"""Interactive merge smoke test for the three complete upstream rule packs."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import tempfile
import time

from pty_smoke import Session, require


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument("--bash", dest="bash_binary", type=pathlib.Path, required=True)
    parser.add_argument("--bash-pack", type=pathlib.Path, required=True)
    parser.add_argument("--fish-pack", type=pathlib.Path, required=True)
    parser.add_argument("--zsh-pack", type=pathlib.Path, required=True)
    parser.add_argument(
        "--trusted-key", type=pathlib.Path, action="append", required=True
    )
    arguments = parser.parse_args()

    library = arguments.library.resolve()
    bash_binary = arguments.bash_binary.resolve()
    trusted_keys = [path.resolve() for path in arguments.trusted_key]
    packs = {
        "bash": arguments.bash_pack.resolve(),
        "fish": arguments.fish_pack.resolve(),
        "zsh": arguments.zsh_pack.resolve(),
    }
    for path in (library, bash_binary, *trusted_keys, *packs.values()):
        if not path.is_file():
            parser.error(f"required test input is missing: {path}")

    with tempfile.TemporaryDirectory(prefix="bashlume-three-packs-") as temporary:
        temporary_root = pathlib.Path(temporary)
        rule_directory = temporary_root / "rules"
        key_directory = temporary_root / "keys"
        rule_directory.mkdir()
        key_directory.mkdir()
        for source, path in packs.items():
            shutil.copy2(path, rule_directory / f"{source}.blp")
        for index, path in enumerate(trusted_keys):
            shutil.copy2(path, key_directory / f"key-{index}.pub")

        session = Session(library, bash_binary, rule_directory, key_directory)
        try:
            rules_output = bytearray()
            deadline = time.monotonic() + 8
            pack_ids = (
                b"org.bashlume.rules.bash",
                b"org.bashlume.rules.fish",
                b"org.bashlume.rules.zsh",
            )
            while time.monotonic() < deadline and not all(
                pack_id in rules_output for pack_id in pack_ids
            ):
                rules_output.extend(session.send(b"bashlume rules\n", 0.5))
            require(
                all(pack_id in rules_output for pack_id in pack_ids),
                "the three source packs did not become ready",
                session.output,
            )

            # These apt-cache candidates are unique to each pinned source. The
            # Fish case also proves that source descriptions survive merging.
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
                    f"merged menu omitted {candidate!r}",
                    session.output,
                )
                if description is not None:
                    require(
                        description in output,
                        f"merged menu omitted {description!r}",
                        session.output,
                    )
        finally:
            session.close()

    print("Bash/Fish/Zsh interactive rule merge test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
