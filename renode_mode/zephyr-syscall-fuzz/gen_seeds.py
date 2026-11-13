#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Generate seed inputs for the objects, futex and thread groups into
seeds/<group>/. The poll seeds are kept as they were written for the original
k_poll harness.

The input is the raw byte stream consumed by src/main.c and src/group_*.c:
each operation is an opcode byte followed by its arguments, read in the order
the group code reads them. The workers share the stream: worker 0 executes
ops until it blocks, then worker 1 continues from where it stopped. So "wait,
then wake" pairs are written as consecutive ops.
"""

import os
import struct
import sys


def u32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


# Argument pools from main.c
NO_WAIT, TICKS1, FOREVER = b'\x00', b'\x01', b'\x02'
PTR_SCRATCH = b'\x07'                       # &scratch[0]


def ptr_scratch_at(off):
    return bytes([0, off])


def len_small(n):                           # n < 64
    return bytes([(n << 2) | 3])


def len_u32(n):
    return b'\x01' + u32(n)


THR_CUR, THR_W0, THR_W1, THR_DORMANT, THR_DEAD, THR_MAIN, THR_NULL = range(7)


def thr(t):
    return bytes([t])


def objects():
    (ALLOC, ALLOC_SIZE, RELEASE, GRANT, ACCESS_CHECK, INIT, SEM, EVENT_SET,
     EVENT_WAIT, CONDVAR_SIGNAL, CONDVAR_WAIT, MUTEX, USE, STACK_ALLOC,
     STACK_FREE, THREAD_CREATE, THREAD_JOIN, SLEEP) = range(18)
    # obj() selectors: 0-7 slots, then static objects
    ST_SEM, ST_EVENT, ST_CONDVAR, ST_MUTEX, UNGRANTED, STK, THREAD = range(8, 15)
    # otype() indices
    T_SEM, T_EVENT, T_CONDVAR, T_MUTEX, T_MSGQ, T_STACK, T_QUEUE, T_PIPE, T_THREAD = range(9)

    def op(*a):
        return b''.join(x if isinstance(x, bytes) else bytes([x]) for x in a)

    return {
        # Dynamic semaphore: worker 0 blocks on it, worker 1 gives it
        'objects-sem': op(ALLOC, 0, T_SEM) + op(INIT, 0, 0, 0, 1) +
        op(GRANT, 0, thr(THR_W1)) + op(SEM, 0, 0, FOREVER) + op(SEM, 0, 1) +
        op(RELEASE, 0),
        'objects-event': op(ALLOC, 1, T_EVENT) + op(INIT, 1, 1) +
        op(GRANT, 1, thr(THR_W1)) + op(EVENT_WAIT, 1, 0, u32(1), FOREVER) +
        op(EVENT_SET, 1, 0, u32(1)) + op(EVENT_WAIT, ST_EVENT, 2, u32(3), NO_WAIT) +
        op(EVENT_SET, ST_EVENT, 2, u32(0xff), u32(0x0f)),
        'objects-condvar': op(MUTEX, ST_MUTEX, 0, FOREVER) +
        op(CONDVAR_WAIT, ST_CONDVAR, ST_MUTEX, FOREVER) +
        op(MUTEX, ST_MUTEX, 0, FOREVER) + op(CONDVAR_SIGNAL, ST_CONDVAR, 0) +
        op(MUTEX, ST_MUTEX, 1) + op(ALLOC, 2, T_CONDVAR) + op(INIT, 2, 2) +
        op(CONDVAR_SIGNAL, 2, 1),
        # User stack + dynamic thread object -> run a child, join, free
        'objects-thread': op(STACK_ALLOC, 0, len_u32(512), 4) +
        op(ALLOC, 3, T_THREAD) +
        op(THREAD_CREATE, 3, 0, len_u32(512), 0, 0, 1, NO_WAIT) +
        op(THREAD_JOIN, 3, 0, FOREVER) + op(STACK_FREE, 0) + op(RELEASE, 3),
        'objects-data': op(ALLOC, 4, T_MSGQ) + op(INIT, 4, 4, len_small(4), u32(4)) +
        op(USE, 4, 0, PTR_SCRATCH, NO_WAIT) + op(USE, 4, 1, PTR_SCRATCH, NO_WAIT) +
        op(ALLOC, 5, T_QUEUE) + op(INIT, 5, 6) + op(USE, 5, 4, PTR_SCRATCH) +
        op(USE, 5, 5, NO_WAIT) +
        op(ALLOC, 6, T_STACK) + op(INIT, 6, 5, u32(4)) + op(USE, 6, 2, u32(42)) +
        op(USE, 6, 3, PTR_SCRATCH, NO_WAIT) +
        op(ALLOC, 7, T_PIPE) + op(INIT, 7, 7, ptr_scratch_at(32), len_small(16)) +
        op(USE, 7, 6, PTR_SCRATCH, len_small(4), NO_WAIT) +
        op(USE, 7, 7, ptr_scratch_at(16), len_small(4), NO_WAIT),
        'objects-perms': op(ACCESS_CHECK, UNGRANTED) + op(ACCESS_CHECK, ST_SEM) +
        op(GRANT, ST_SEM, thr(THR_DORMANT)) + op(RELEASE, ST_SEM) +
        op(ALLOC_SIZE, 0, T_MSGQ, len_u32(0x7fffffff)) + op(ALLOC, 1, 0xff) +
        op(RELEASE, 0),
    }


def futex():
    (WAIT, WAKE, STORE, LOCK, UNLOCK, MINIT, PUT, GET, PUT_FRONT, PEEK, PEEK_AT,
     ATTRS, PURGE, QINSERT, QGET, QPEEK, QCANCEL, SLEEP) = range(18)
    MSGQ4, MSGQ7 = 0, 1
    QUEUE = 0

    def op(*a):
        return b''.join(x if isinstance(x, bytes) else bytes([x]) for x in a)

    return {
        'futex-wake': op(WAIT, 0, 0, FOREVER) + op(WAKE, 0, 0) +
        op(WAIT, 1, 1, u32(5), FOREVER) + op(WAKE, 1, 1),
        'futex-sysmutex': op(LOCK, 0, FOREVER) + op(SLEEP, 0x05) +
        op(LOCK, 0, FOREVER) + op(UNLOCK, 0) + op(UNLOCK, 0),
        # With SYS_MUTEX_IMPL_FUTEX, sys_mutex only enters the kernel when
        # contended: worker 1 waits on the futex while worker 0 corrupts it
        'futex-corrupt': op(LOCK, 1, FOREVER) + op(SLEEP, TICKS1) +
        op(LOCK, 1, FOREVER) + op(STORE, 3, u32(0xfffffffe)) + op(UNLOCK, 1) +
        op(WAKE, 3, 1) + op(MINIT, 1) + op(LOCK, 1, NO_WAIT),
        'futex-msgq': op(PUT, MSGQ4, PTR_SCRATCH, NO_WAIT) +
        op(PUT_FRONT, MSGQ7, PTR_SCRATCH) + op(PEEK_AT, MSGQ4, PTR_SCRATCH, u32(0)) +
        op(PEEK, MSGQ7, PTR_SCRATCH) + op(ATTRS, MSGQ4, 0) + op(ATTRS, MSGQ4, 1) +
        op(PURGE, MSGQ7) + op(GET, MSGQ4, PTR_SCRATCH, NO_WAIT) +
        op(GET, MSGQ4, PTR_SCRATCH, FOREVER) + op(PUT, MSGQ4, PTR_SCRATCH, NO_WAIT),
        'futex-queue': op(QINSERT, QUEUE, 0, PTR_SCRATCH) +
        op(QINSERT, QUEUE, 1, PTR_SCRATCH) + op(QPEEK, QUEUE, 0) +
        op(QPEEK, QUEUE, 1) + op(QPEEK, QUEUE, 2) + op(QGET, QUEUE, NO_WAIT) +
        op(QGET, QUEUE, NO_WAIT) + op(QGET, QUEUE, FOREVER) + op(QCANCEL, QUEUE),
    }


def thread():
    (NAME_SET, NAME_COPY, PRIO_SET, PRIO_GET, DEADLINE, SUSPEND, RESUME, WAKEUP,
     JOIN, ABORT, TIMEOUT_GET, STACK_SPACE, STACK_THRESHOLD, CUSTOM, SLEEP,
     YIELD) = range(16)

    def op(*a):
        return b''.join(x if isinstance(x, bytes) else bytes([x]) for x in a)

    return {
        'thread-name': op(NAME_SET, THR_CUR, 1) + op(NAME_COPY, THR_W0, 0x41) +
        op(NAME_SET, THR_W1, 0, 10) + op(NAME_COPY, THR_W1, 0x41),
        # Worker 0 sleeps, worker 1 suspends/inspects/resumes/wakes it
        'thread-suspend': op(SLEEP, TICKS1) + op(SUSPEND, THR_W0) +
        op(TIMEOUT_GET, THR_W0, 0) + op(TIMEOUT_GET, THR_W0, 1) +
        op(RESUME, THR_W0) + op(WAKEUP, THR_W0),
        'thread-prio': op(PRIO_GET, THR_W1) + op(PRIO_SET, THR_CUR, 0x86) +
        op(DEADLINE, THR_CUR, 0x40) + op(DEADLINE, THR_W1, 0x41) + op(YIELD),
        'thread-lifecycle': op(WAKEUP, THR_DORMANT) + op(JOIN, THR_DORMANT, FOREVER) +
        op(JOIN, THR_DEAD, NO_WAIT) + op(ABORT, THR_W1),
        'thread-stack': op(STACK_SPACE, THR_CUR, 0) +
        op(STACK_THRESHOLD, THR_CUR, 0, u32(50)) + op(STACK_THRESHOLD, THR_CUR, 2) +
        op(CUSTOM, 1, u32(0x12345678)) + op(CUSTOM, 0),
    }


def main():
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seeds')
    groups = {'objects': objects, 'futex': futex, 'thread': thread}
    for name in sys.argv[1:] or groups:
        d = os.path.join(base, name)
        os.makedirs(d, exist_ok=True)
        for seed, data in groups[name]().items():
            with open(os.path.join(d, seed), 'wb') as f:
                f.write(data)
        print(f'{d}: {len(groups[name]())} seeds')


if __name__ == '__main__':
    main()
