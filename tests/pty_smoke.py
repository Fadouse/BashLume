#!/usr/bin/env python3
"""End-to-end smoke test against a real interactive Bash PTY."""

from __future__ import annotations

import argparse
import errno
import os
import pathlib
import pty
import select
import shutil
import sys
import tempfile
import time


class Session:
    def __init__(self, library: pathlib.Path, bash: pathlib.Path) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            environment = os.environ.copy()
            environment.update(
                TERM="xterm-256color",
                PS1="BASHLUME_TEST> ",
                HISTFILE="/dev/null",
                BASH_SILENCE_DEPRECATION_WARNING="1",
            )
            os.execve(
                bash,
                [str(bash), "--noprofile", "--norc", "-i"],
                environment,
            )
        self.pid = pid
        self.fd = fd
        self.output = bytearray()
        os.set_blocking(fd, False)
        self.read_for(0.2)
        self.send(f"enable -f {library} bashlume\n".encode(), 0.5)

    def read_for(self, seconds: float) -> bytes:
        start = len(self.output)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            readable, _, _ = select.select(
                [self.fd], [], [], min(0.05, deadline - time.monotonic())
            )
            if not readable:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            self.output.extend(chunk)
        return bytes(self.output[start:])

    def send(self, data: bytes, wait: float = 0.2) -> bytes:
        os.write(self.fd, data)
        return self.read_for(wait)

    def close(self) -> None:
        try:
            self.send(b"exit\n", 0.2)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass


def require(condition: bool, message: str, output: bytes) -> None:
    if condition:
        return
    rendered = output.decode("utf-8", "backslashreplace").replace("\x1b", "<ESC>")
    raise AssertionError(f"{message}\n--- PTY transcript ---\n{rendered}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "library",
        nargs="?",
        type=pathlib.Path,
        default=pathlib.Path("target/release/libbashlume.so"),
    )
    parser.add_argument(
        "--bash",
        type=pathlib.Path,
        default=pathlib.Path(
            os.environ.get("BASHLUME_TEST_BASH", shutil.which("bash") or "/bin/bash")
        ),
    )
    arguments = parser.parse_args()
    library = arguments.library.resolve()
    bash = arguments.bash.resolve()
    if not library.is_file():
        parser.error(f"shared library not found: {library}")

    if not bash.is_file():
        parser.error(f"Bash executable not found: {bash}")

    session = Session(library, bash)
    try:
        status = session.send(b"bashlume status\n", 0.3)
        require(b"bashlume: enabled" in status, "loadable builtin did not initialize", session.output)

        valid = session.send(b"echo BASHLUME_VALID_SYNTAX", 0.2)
        require(
            b"\x1b[1;38;5;108m" not in valid,
            "valid syntax was colored in the default errors-only mode",
            session.output,
        )
        session.send(b"\x15", 0.2)

        syntax_error = session.send(b"echo )", 0.3)
        require(
            b"\x1b[4;38;5;203m" in syntax_error and "✗".encode() in syntax_error,
            "definite syntax error was not highlighted and marked",
            session.output,
        )
        session.send(b"\x15", 0.2)

        command_menu = session.send(b"who", 0.2) + session.send(b"\t", 0.5)
        if b"whoami" not in command_menu:
            command_menu += session.send(b"\t", 0.4)
        require(
            b"whoami" in command_menu,
            "exact command suppressed its longer prefix matches",
            session.output,
        )
        require(
            b";32m" in command_menu,
            "command completions did not use executable colors",
            session.output,
        )
        session.send(b"\x15", 0.2)
        session.send(b"\x07", 0.2)

        session.send(
            b"(read -e value; printf 'SUBSHELL:<%s>\\n' \"$value\")\n",
            0.2,
        )
        subshell = session.send(b"child-value\n", 0.4)
        require(
            b"SUBSHELL:<child-value>" in subshell,
            "forked child did not fall back to native Readline widgets",
            session.output,
        )

        session.send(b"BASHLUME_DIAGNOSTICS=inline bashlume reload\n", 0.3)
        diagnostic = session.send(b"echo )", 0.7)
        require(
            b"Bash syntax error" in diagnostic,
            "optional delayed inline diagnostic was not rendered",
            session.output,
        )
        session.send(b"\x15", 0.2)
        session.send(b"BASHLUME_DIAGNOSTICS=marker bashlume reload\n", 0.3)

        session.send(b"echo BASHLUME_HISTORY_ACCEPTED\n", 0.3)
        ghost = session.send(b"echo BASHLUME_HIST", 0.4)
        require(
            b"ORY_ACCEPTED" in ghost and b"\x1b[2;38;5;244m" in ghost,
            "history ghost suggestion was not rendered",
            session.output,
        )
        session.send(b"\x1b[C", 0.1)
        accepted = session.send(b"\n", 0.4)
        require(
            b"BASHLUME_HISTORY_ACCEPTED" in accepted,
            "Right Arrow did not accept the ghost suggestion",
            session.output,
        )

        with tempfile.TemporaryDirectory(prefix="bashlume-pty-") as directory:
            root = pathlib.Path(directory)
            (root / "alpha-file").write_text("alpha", encoding="utf-8")
            (root / "alpine-file").write_text("alpine", encoding="utf-8")
            (root / "My File").write_text("space", encoding="utf-8")
            (root / "gone").mkdir()
            session.send(f"cd {root}\n".encode(), 0.4)
            session.send(b"printf '<%s>\\n' al", 0.2)
            menu = session.send(b"\t", 0.5)
            if b"alpha-file" not in menu:
                menu += session.send(b"\t", 0.4)
            require(
                b"alpha-file" in menu and b"alpine-file" in menu,
                "columnar Tab menu was not displayed",
                session.output,
            )
            require(b"[file]" not in menu, "menu still used type-label rows", session.output)
            session.send(b"\x1b[C", 0.1)
            completed = session.send(b"\n", 0.4)
            require(
                b"<alpha-file>" in completed or b"<alpine-file>" in completed,
                "selected path completion was not inserted safely",
                session.output,
            )

            session.send(b"printf '<%s>\\n' My", 0.2)
            session.send(b"\t", 0.3)
            quoted = session.send(b"\n", 0.4)
            require(
                b"<My File>" in quoted,
                "path containing a space was not quoted safely",
                session.output,
            )

            late_directory = root / "late-scan"
            session.send(
                f"printf '<%s>\\n' {late_directory}/".encode(),
                0.4,
            )
            # The initial missing-directory scan may still be queued for the
            # main thread; freshness must use worker completion time, not the
            # later instant at which Tab consumes that response.
            late_directory.mkdir()
            for index in range(30_000):
                (late_directory / f"entry-{index:05d}").touch()
            time.sleep(0.3)
            first_scan = session.send(b"\t", 0.03)
            automatic_update = first_scan + session.read_for(1.5)
            require(
                b"scanning" not in automatic_update,
                "pending scan placeholder was rendered",
                session.output,
            )
            require(
                b"entry-00000" in automatic_update,
                "completed asynchronous scan did not redraw without another keypress",
                session.output,
            )
            session.send(b"\x07", 0.2)
            session.send(b"\x15", 0.2)

            session.send(b"cd gone\n", 0.3)
            session.send(b"cd ..\n", 0.3)
            session.send(b"rmdir gone\n", 0.3)
            stale = session.send(b"cd g", 0.5)
            require(
                b"\x1b[2;38;5;244mone" not in stale,
                "history suggested a directory that had been deleted",
                session.output,
            )
            session.send(b"\x15", 0.2)
            session.send(b"cd /\n", 0.3)

        session.send(b"alias zz_bashlume_alias='printf ALIAS_OK\\n'\n", 0.3)
        session.send(b"zz_bashlume_al", 0.2)
        session.send(b"\t", 0.3)
        alias_result = session.send(b"\n", 0.4)
        require(b"ALIAS_OK" in alias_result, "alias completion was not refreshed", session.output)

        session.send(b"set -o vi\n", 0.3)
        vi = session.send(b"echo BASHLUME_VI_OK\n", 0.3)
        require(b"BASHLUME_VI_OK" in vi, "Vi insertion mode was broken", session.output)

        session.send(b"set -o emacs\n", 0.3)
        session.send(b"echo BASHLUME_SEARCH_OK\n", 0.3)
        session.send(b"\x12BASHLUME_SEARCH", 0.2)
        searched = session.send(b"\n", 0.4)
        require(b"BASHLUME_SEARCH_OK" in searched, "Ctrl-R history search was broken", session.output)

        session.send(b"enable -d bashlume\n", 0.4)
        unloaded = session.send(b"printf 'BASHLUME_UNLOAD_OK\\n'\n", 0.3)
        require(b"BASHLUME_UNLOAD_OK" in unloaded, "unload did not restore Readline", session.output)
    finally:
        session.close()

    print("PTY smoke test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
