'''
AFL++ harness for zephyr-syscall-fuzz (see zephyr-syscall-fuzz/src/main.c).

The whole test case is written into the guest's afl_input buffer right after
each machine reset, before the CPU runs. Runs end only when the guest calls one
of its afl_* marker functions, or when the host-side watchdog fires.
'''

import os
import ctypes
import struct

import System

import afl_renode
from afl_renode import (INFD, read, monitor, emulationManager, sysbus_name,
                        W_EXITCODE, STATUS_SUCCESS, STATUS_ABORT)

AFL_MAGIC = 0xAF1F5C11
INPUT_MAX = 4096
LINUX_SIGALRM = 14
STATUS_HANG = W_EXITCODE(0, LINUX_SIGALRM)

# Host-side watchdog, in quanta, in case the guest never reaches a marker.
MAX_QUANTA = int(os.environ.get("AFL_RENODE_MAX_QUANTA", "3000"))

afl_renode.exit_symbols = {
    "afl_done": STATUS_SUCCESS,
    "afl_bug": STATUS_ABORT,
    "afl_hang": STATUS_HANG,
}
# Every test case starts from a freshly booted kernel.
afl_renode.always_reset = True
# On Cortex-R the reset vector lives at 0, so PC 0 is not a crash indicator.
afl_renode.endgame.pop(0, None)

data = ctypes.create_string_buffer(INPUT_MAX)
input_addr = None
started = False
quanta = 0
_orig_do_one_child = afl_renode.do_one_child


def read_input():
    payload = b""
    while len(payload) < INPUT_MAX:
        n = read(INFD, data, INPUT_MAX - len(payload))
        if n <= 0:
            break
        payload += data.raw[:n]
    return payload


def write_input(payload):
    global input_addr
    if input_addr is None:
        input_addr = min(afl_renode.symbol_addresses("afl_input"))
    blob = struct.pack("<II", AFL_MAGIC, len(payload)) + payload
    monitor.Machine[sysbus_name].WriteBytes(System.Array[System.Byte](bytearray(blob)),
                                            input_addr)


def do_one_child():
    global started, quanta
    _orig_do_one_child()
    quanta = 0
    write_input(read_input())

    # Trace from the very first block after reset, instead of waiting a quantum
    for cpu in monitor.Machine[sysbus_name].GetCPUs():
        cpu.SetHookAtBlockBegin(afl_renode.log_basic_block)
    afl_renode.reset = False

    if not started:
        started = True
        emulationManager.Instance.CurrentEmulation.StartAll()


def quantum_hook(mach):
    global quanta
    quanta += 1
    if quanta > MAX_QUANTA and afl_renode.status is None:
        afl_renode.status = STATUS_HANG


afl_renode.do_one_child = do_one_child
afl_renode.quantum_hook = quantum_hook
