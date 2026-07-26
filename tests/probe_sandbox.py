#!/usr/bin/env python3
"""Verify the installed probe trampoline limits targets before exec."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("helper", type=pathlib.Path)
    arguments = parser.parse_args()
    helper = arguments.helper.resolve()

    program = r'''
import json
import os
import resource
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
    "escape_errno": escape_errno,
    "fork_succeeded": fork_succeeded,
    "inherited_closed": inherited_closed,
    "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
    "nproc": resource.getrlimit(resource.RLIMIT_NPROC),
    "address_space": resource.getrlimit(resource.RLIMIT_AS),
    "core": resource.getrlimit(resource.RLIMIT_CORE),
    "status": status,
}, sort_keys=True))
'''
    inherited, inherited_peer = os.pipe()
    try:
        completed = subprocess.run(
            [
                str(helper),
                "--bashlume-probe-v1",
                "1000",
                "python3",
                "-c",
                program,
                str(inherited),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            pass_fds=(inherited,),
        )
    finally:
        os.close(inherited)
        os.close(inherited_peer)
    result = json.loads(completed.stdout)
    assert result["escape_errno"] == 1, result
    assert result["fork_succeeded"], result
    assert result["inherited_closed"], result
    assert result["nofile"][0] <= 64 and result["nofile"][1] <= 64, result
    assert 0 < result["nproc"][0] <= result["nproc"][1] != -1, result
    assert result["address_space"][0] <= 256 * 1024 * 1024, result
    assert result["address_space"][1] <= 256 * 1024 * 1024, result
    assert result["core"] == [0, 0], result
    assert result["status"] == {"NoNewPrivs": 1, "Seccomp": 2}, result

    for forbidden in ("bash", "bashlume-probe"):
        denied = subprocess.run(
            [str(helper), "--bashlume-probe-v1", "1000", forbidden, "--version"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        assert denied.returncode == 126, (forbidden, denied.returncode, denied.stderr)

    print("probe sandbox helper test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
