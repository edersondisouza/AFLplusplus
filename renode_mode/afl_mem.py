from __future__ import print_function

import afl_renode
import ctypes
import random

from afl_renode import INFD, read, monitor, visited, STATUS_ABORT, STATUS_SUCCESS

IDLE_COUNT = 4

DATA_SIZE = 1024 * 64
data = ctypes.create_string_buffer(DATA_SIZE)

def quantum_hook(mach):
    data = ctypes.create_string_buffer(DATA_SIZE)
    WriteByte = mach["sysbus.afl"].WriteByte

    f = open("/tmp/afl_mem", "a")

    try:
        if len(visited) < IDLE_COUNT:
            n = read(INFD, data, DATA_SIZE)
            # Randomly, with a chance of 1/10, change the 8th byte read to 'G'
            #if n > 7 and random.randint(0, 9) == 0:
            #    print("Changing 8th byte to 'G'", file=f)
            #    f.flush()
            #    ndata = bytearray(data.raw[:n])
            #    ndata[7] = ord('G')
            #    data = ctypes.create_string_buffer(ndata.decode('ascii', 'ignore'))
            print("Read", n, "bytes from input", data.raw[:8], "<", file=f)
            for i, byte in enumerate(bytearray(data.raw[:n])):
                WriteByte(i, byte)
            if n == 0:
                print("No more input, stopping", afl_renode.visited, len(afl_renode.visited), file=f)
                if len(afl_renode.visited) == 1:
                    afl_renode.status = STATUS_ABORT
                else:
                    afl_renode.status = STATUS_SUCCESS
    except Exception as e:
        print("Error in quantum_hook:", e, file=f)
        afl_renode.status = STATUS_ABORT

    f.close()

afl_renode.quantum_hook = quantum_hook
