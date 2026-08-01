#!/usr/bin/env python3
"""Verify the installed probe trampoline limits targets before exec."""

from __future__ import annotations

import argparse
import errno
import json
import os
import pathlib
import signal
import socket
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("helper", type=pathlib.Path)
    arguments = parser.parse_args()
    helper = arguments.helper.resolve()

    program = r'''
import ctypes
import errno
import fcntl
import json
import os
import platform
import resource
import signal
import sys

inherited_closed = False
try:
    os.fstat(int(sys.argv[1]))
except OSError:
    inherited_closed = True

escape_errno = None
try:
    os.setpgid(0, 0)
except OSError as error:
    escape_errno = error.errno

signal_errno = None
try:
    os.kill(os.getppid(), 0)
except OSError as error:
    signal_errno = error.errno

signal_owner_errno = None
try:
    fcntl.fcntl(1, fcntl.F_SETOWN, os.getppid())
except OSError as error:
    signal_owner_errno = error.errno

libc = ctypes.CDLL(None, use_errno=True)
syscalls = {
    "x86_64": (56, 435),
    "aarch64": (220, 435),
}
clone_nr, clone3_nr = syscalls[platform.machine()]
ctypes.set_errno(0)
clone_result = libc.syscall(
    clone_nr,
    0x00008000 | signal.SIGSTOP,  # CLONE_PARENT | hostile exit signal
    0,
    0,
    0,
    0,
)
if clone_result == 0:
    os._exit(0)
clone_parent_errno = ctypes.get_errno() if clone_result == -1 else None
ctypes.set_errno(0)
clone3_result = libc.syscall(clone3_nr, 0, 0)
clone3_errno = ctypes.get_errno() if clone3_result == -1 else None

child = os.fork()
if child == 0:
    os._exit(0)
_, child_status = os.waitpid(child, 0)
fork_succeeded = os.waitstatus_to_exitcode(child_status) == 0

status = {}
with open("/proc/self/status", encoding="ascii") as source:
    for line in source:
        if line.startswith(("NoNewPrivs:", "Seccomp:")):
            name, value = line.split(":", 1)
            status[name] = int(value.strip())

print(json.dumps({
    "clone3_errno": clone3_errno,
    "clone_parent_errno": clone_parent_errno,
    "escape_errno": escape_errno,
    "fork_succeeded": fork_succeeded,
    "inherited_closed": inherited_closed,
    "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
    "nproc": resource.getrlimit(resource.RLIMIT_NPROC),
    "signal_errno": signal_errno,
    "signal_owner_errno": signal_owner_errno,
    "address_space": resource.getrlimit(resource.RLIMIT_AS),
    "core": resource.getrlimit(resource.RLIMIT_CORE),
    "status": status,
}, sort_keys=True))
'''
    def ignore_sigchld() -> None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    def run_helper(inherit_ignored_sigchld: bool) -> dict[str, object]:
        inherited, inherited_peer = os.pipe()
        parent_start, child_start = socket.socketpair()
        parent_start.settimeout(5)
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                [
                    str(helper),
                    "--bashlume-probe-v1",
                    "1000",
                    "python3",
                    "-c",
                    program,
                    str(inherited),
                ],
                stdin=child_start,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                pass_fds=(inherited,),
                preexec_fn=ignore_sigchld if inherit_ignored_sigchld else None,
            )
            child_start.close()
            assert parent_start.recv(1) == b"A", "helper did not announce startup readiness"
            parent_start.sendall(b"B")
            assert parent_start.recv(1) == b"C", "helper did not acknowledge pidfd release"
            stdout, stderr = process.communicate(timeout=5)
            if process.returncode != 0:
                raise subprocess.CalledProcessError(
                    process.returncode, process.args, stdout, stderr
                )
            return json.loads(stdout)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            parent_start.close()
            child_start.close()
            os.close(inherited)
            os.close(inherited_peer)

    for inherited_sigchld in (False, True):
        result = run_helper(inherited_sigchld)
        assert result["clone_parent_errno"] == errno.EPERM, result
        assert result["clone3_errno"] == errno.ENOSYS, result
        assert result["escape_errno"] == errno.EPERM, result
        assert result["fork_succeeded"], result
        assert result["inherited_closed"], result
        assert result["signal_errno"] == 1, result
        assert result["signal_owner_errno"] == 1, result
        assert result["nofile"][0] <= 64 and result["nofile"][1] <= 64, result
        assert 0 < result["nproc"][0] <= result["nproc"][1] != -1, result
        assert result["address_space"][0] <= 256 * 1024 * 1024, result
        assert result["address_space"][1] <= 256 * 1024 * 1024, result
        assert result["core"] == [0, 0], result
        assert result["status"] == {"NoNewPrivs": 1, "Seccomp": 2}, result

    for forbidden in ("bash", "bashlume-probe"):
        parent_start, child_start = socket.socketpair()
        parent_start.settimeout(2)
        denied = subprocess.Popen(
            [str(helper), "--bashlume-probe-v1", "1000", forbidden, "--version"],
            stdin=child_start,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        child_start.close()
        try:
            startup = parent_start.recv(1)
            assert startup == b"", (forbidden, "target passed validation", startup)
            _, stderr = denied.communicate(timeout=2)
        finally:
            parent_start.close()
            child_start.close()
            if denied.poll() is None:
                denied.kill()
                denied.wait(timeout=1)
        assert denied.returncode == 126, (forbidden, denied.returncode, stderr)
        assert "forbidden shell or helper execution" in stderr, (forbidden, stderr)

    print("probe sandbox helper test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
