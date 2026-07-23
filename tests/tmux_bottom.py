#!/usr/bin/env python3
"""Regression test for completion overlays that reach the terminal bottom."""

from __future__ import annotations

import argparse
import os
import pathlib
import shlex
import shutil
import subprocess
import time
import uuid


def tmux(*arguments: str, capture: bool = False) -> str:
    result = subprocess.run(
        ["tmux", *arguments],
        check=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout if capture else ""


def send(session: str, text: str) -> None:
    tmux("send-keys", "-t", session, "-l", text)


def key(session: str, name: str) -> None:
    tmux("send-keys", "-t", session, name)


def pane(session: str, *, escapes: bool = False) -> str:
    arguments = ["capture-pane", "-p", "-t", session]
    if escapes:
        arguments.insert(2, "-e")
    return tmux(*arguments, capture=True)


def assert_stable(screen: str) -> None:
    lines = screen.splitlines()
    if sum("BASHLUME_BOTTOM> who" in line for line in lines) != 1:
        raise AssertionError(f"input prompt was duplicated or lost:\n{screen}")
    if sum("whoami" in line for line in lines) != 2:
        # One occurrence is the gray ghost on the input line and one is in
        # the candidate list. Repaint accumulation produces more copies.
        raise AssertionError(f"completion rows accumulated after scrolling:\n{screen}")
    if "[command]" in screen:
        raise AssertionError(f"legacy type-label menu was rendered:\n{screen}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument(
        "--bash",
        type=pathlib.Path,
        default=pathlib.Path(shutil.which("bash") or "/bin/bash"),
    )
    arguments = parser.parse_args()
    library = arguments.library.resolve()
    bash = arguments.bash.resolve()
    if shutil.which("tmux") is None:
        print("tmux bottom-edge test skipped (tmux not installed)")
        return 0
    if not library.is_file() or not bash.is_file():
        parser.error("library and Bash paths must exist")

    session = f"bashlume-bottom-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    shell = shlex.join(
        [
            "env",
            "TERM=xterm-256color",
            "PS1=BASHLUME_BOTTOM> ",
            "HISTFILE=/dev/null",
            str(bash),
            "--noprofile",
            "--norc",
            "-i",
        ]
    )
    try:
        tmux("new-session", "-d", "-x", "50", "-y", "8", "-s", session, shell)
        time.sleep(0.2)
        send(session, f"enable -f {library} bashlume")
        key(session, "Enter")
        time.sleep(0.5)
        send(session, "printf '1\\n2\\n3\\n4\\n5\\n'")
        key(session, "Enter")
        time.sleep(0.3)
        send(session, "who")
        key(session, "Tab")
        time.sleep(0.5)

        for _ in range(3):
            screen = pane(session)
            assert_stable(screen)
            colored = pane(session, escapes=True)
            if "\x1b[32m" not in colored:
                raise AssertionError(f"command candidates were not colored:\n{colored!r}")
            key(session, "Tab")
            time.sleep(0.2)
    finally:
        subprocess.run(
            ["tmux", "kill-session", "-t", session],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    print("tmux bottom-edge test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
