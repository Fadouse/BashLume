#!/usr/bin/env python3
"""Development-only startup and memory budget check.

This script is never invoked by the installed plugin.
"""

from __future__ import annotations

import argparse
import errno
import os
import pathlib
import pty
import re
import select
import time

PROMPT = b"BASHLUME_BUDGET> "


def read_available(fd: int, timeout: float) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], min(0.02, deadline - time.monotonic()))
        if not readable:
            continue
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            continue
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def read_until(fd: int, marker: bytes, timeout: float) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in output and time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], deadline - time.monotonic())
        if not readable:
            break
        try:
            output.extend(os.read(fd, 65536))
        except BlockingIOError:
            continue
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
    if marker not in output:
        raise RuntimeError(f"timed out waiting for {marker!r}")
    return bytes(output)


def memory(pid: int) -> dict[str, int]:
    values: dict[str, int] = {}
    with open(f"/proc/{pid}/smaps_rollup", encoding="ascii") as source:
        for line in source:
            match = re.match(r"(Rss|Pss|Private_Clean|Private_Dirty):\s+(\d+)", line)
            if match:
                values[match.group(1)] = int(match.group(2))
    values["Private"] = values.get("Private_Clean", 0) + values.get("Private_Dirty", 0)
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "library",
        nargs="?",
        type=pathlib.Path,
        default=pathlib.Path("target/release/libbashlume.so"),
    )
    arguments = parser.parse_args()
    library = arguments.library.resolve()

    pid, fd = pty.fork()
    if pid == 0:
        environment = os.environ.copy()
        environment.update(TERM="xterm-256color", PS1=PROMPT.decode(), HISTFILE="/dev/null")
        os.execvpe("bash", ["bash", "--noprofile", "--norc", "-i"], environment)
    os.set_blocking(fd, False)

    try:
        read_until(fd, PROMPT, 2.0)
        baseline = memory(pid)
        command = f"BASHLUME_CACHE_MIB=16; enable -f {library} bashlume\n".encode()
        started = time.perf_counter_ns()
        os.write(fd, command)
        read_until(fd, PROMPT, 2.0)
        startup_us = (time.perf_counter_ns() - started) / 1_000

        # Exercise Tree-sitter, the renderer, and the worker's initial caches.
        os.write(fd, b"# " + b"x" * 1000)
        read_available(fd, 1.0)
        loaded = memory(pid)
        os.write(fd, b"\x15enable -d bashlume\n")
        read_available(fd, 0.5)

        rss_delta = loaded["Rss"] - baseline["Rss"]
        private_delta = loaded["Private"] - baseline["Private"]
        print(
            f"startup={startup_us:.1f}us rss_delta={rss_delta}KiB "
            f"private_delta={private_delta}KiB"
        )

        # PTY scheduling is noisy, so startup has a 50 ms CI guard while the
        # reported engineering target remains below 10 ms on a warm machine.
        if startup_us >= 50_000:
            raise AssertionError(f"startup regression: {startup_us:.1f}us")
        if rss_delta >= 4 * 1024:
            raise AssertionError(f"RSS regression: {rss_delta}KiB")
        if private_delta >= 3 * 1024:
            raise AssertionError(f"private-memory regression: {private_delta}KiB")
    finally:
        try:
            os.write(fd, b"exit\n")
        except OSError:
            pass
        read_available(fd, 0.2)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
