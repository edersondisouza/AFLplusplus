#!/usr/bin/env python3
'''Runs every file of a corpus through one Renode instance, speaking the AFL
forkserver protocol, and prints the per-input status.

  replay_corpus.py [-e EDGE_LOG] RESC ELF INPUT...

With -e, AFL_RENODE_EDGE_LOG collects the exact (from, to) edges of the
coverage window (AFL_RENODE_COVERAGE, default kernel), so corpora found with
different coverage modes can be compared on the same metric:

  replay_corpus.py -e /tmp/a.edges renode_mode/example-syscall.resc \\
      zephyr-syscall-fuzz.elf out/default/queue/id*
  wc -l /tmp/a.edges
'''

import argparse
import ctypes
import os
import struct
import subprocess
import sys
import tempfile

FORKSRV_FD = 198
MAP_SIZE = 2 ** 16
IPC_PRIVATE, IPC_CREAT, IPC_RMID = 0, 0o1000, 0

ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
ap.add_argument("-e", "--edge-log")
ap.add_argument("resc")
ap.add_argument("elf")
ap.add_argument("inputs", nargs="+")
args = ap.parse_args()

libc = ctypes.CDLL("libc.so.6", use_errno=True)
shmid = libc.shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | 0o600)
if shmid < 0:
    sys.exit("shmget failed")

env = dict(os.environ, __AFL_SHM_ID=str(shmid))
if args.edge_log:
    env["AFL_RENODE_EDGE_LOG"] = os.path.abspath(args.edge_log)
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ctl_r, ctl_w = os.pipe()
st_r, st_w = os.pipe()
cur = tempfile.TemporaryFile()
renode = None
failures = 0
try:
    os.dup2(ctl_r, FORKSRV_FD)
    os.dup2(st_w, FORKSRV_FD + 1)
    renode = subprocess.Popen([os.path.join(root, "afl-renode-trace"), args.resc, args.elf],
                              stdin=cur, stdout=subprocess.DEVNULL, env=env,
                              pass_fds=(FORKSRV_FD, FORKSRV_FD + 1))
    for fd in (ctl_r, st_w, FORKSRV_FD, FORKSRV_FD + 1):
        os.close(fd)

    def read4():
        buf = b""
        while len(buf) < 4:
            chunk = os.read(st_r, 4 - len(buf))
            if not chunk:
                sys.exit("Renode exited")
            buf += chunk
        return struct.unpack("<i", buf)[0]

    read4()  # forkserver hello
    for path in args.inputs:
        with open(path, "rb") as f:
            payload = f.read()
        cur.seek(0)
        cur.truncate()
        cur.write(payload)
        cur.flush()
        cur.seek(0)
        os.write(ctl_w, b"\0\0\0\0")
        read4()
        status = read4()
        failures += status != 0
        print("%d %s" % (status, path), flush=True)
finally:
    os.close(ctl_w)
    if renode:
        try:
            renode.wait(timeout=30)
        except subprocess.TimeoutExpired:
            renode.kill()
    libc.shmctl(shmid, IPC_RMID, None)
sys.exit(1 if failures else 0)
