/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interface between the common harness (main.c) and the per-group syscall
 * interpreters (group_*.c). See main.c for the overall design.
 */

#ifndef SYSCALL_FUZZ_HARNESS_H
#define SYSCALL_FUZZ_HARNESS_H

#include <zephyr/kernel.h>
#include <zephyr/app_memory/app_memdomain.h>

#define AFL_INPUT_MAX 4096
#define NUM_WORKERS   CONFIG_SYSCALL_FUZZ_WORKERS
#define SCRATCH_SIZE  64

/* User-accessible partition shared by all workers */
extern struct k_mem_partition fz_part;

/* Input stream and scratch buffer, in fz_part (see main.c for the order) */
struct fz_mem {
	uint32_t upos;
	uint32_t ulen;
	uint32_t op_offset;
	uint8_t cur_op;
	uint8_t selftest_op;
	uint8_t ubuf[AFL_INPUT_MAX];
	uint8_t scratch[SCRATCH_SIZE];
};
extern struct fz_mem fz_mem;
#define scratch (fz_mem.scratch)

/* User threads interpreting the input */
extern struct k_thread workers[NUM_WORKERS];

/* Kernel heap assigned to the workers (k_queue_alloc_append, ...) */
extern struct k_heap fz_heap;

/* Input stream, consumed by all workers (zero once exhausted) */
uint8_t next_u8(void);
uint32_t next_u32(void);

/*
 * Argument pools, mixing valid values, wrong types, kernel addresses the
 * caller has no access to, NULL and raw 32-bit values from the input.
 */
void *fz_ptr(void);	    /* buffer pointer for copies in/out */
size_t fz_len(void);	    /* buffer length */
k_timeout_t fz_timeout(void);
struct k_thread *fz_thread(void);

/* Entry point for extra user threads; sleeps (uintptr_t)p1 % 4 ticks */
void fz_child_entry(void *p1, void *p2, void *p3);

/* Implemented by the group */
void group_setup(void);		/* supervisor: init objects, grant access */
void group_op(uint8_t op);	/* user: run one operation */

#endif
