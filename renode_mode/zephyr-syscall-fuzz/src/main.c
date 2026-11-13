/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Syscall fuzzing harness for AFL++ + Renode.
 *
 * Renode writes the AFL test case into afl_input (a .noinit buffer) before the
 * CPU starts. The supervisor (main) copies it into a user-accessible partition
 * and starts CONFIG_SYSCALL_FUZZ_WORKERS K_USER threads that interpret it as a
 * sequence of operations, defined by the group selected at build time
 * (group_*.c). All workers consume the same stream: when one blocks in a
 * syscall, the next one carries on, so it can wake the first one up.
 *
 * The harness reports the outcome by calling one of the afl_*() marker
 * functions, which Renode watches for:
 *   afl_done() - the input was consumed (or every worker blocked or died).
 *                User oopses (a syscall rejecting its arguments) and user
 *                faults are expected and only end the offending thread.
 *   afl_bug()  - fatal error in kernel context (CPU fault, panic, assertion)
 *   afl_hang() - a worker kept running for longer than HANG_MS
 *
 * Before afl_bug() and afl_hang() the harness fills afl_crash, which the host
 * reads to describe the failure without needing any console output.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/fatal.h>
#include <zephyr/sys/zassert.h>
#if defined(CONFIG_CPU_AARCH32_CORTEX_R)
#include <cmsis_core.h>
#endif

#include "harness.h"

#define AFL_MAGIC     0xAF1F5C11U
struct afl_input {
	uint32_t magic;
	uint32_t len;
	uint8_t data[AFL_INPUT_MAX];
};

/* Written by Renode before boot; not touched by ELF loading or BSS init. */
__noinit struct afl_input afl_input;

#define AFL_CRASH_MAGIC 0xAF1FC4A5U

/* Layout is decoded by afl_syscall.py: keep both in sync. */
struct afl_crash {
	uint32_t magic;
	uint32_t reason;	/* K_ERR_*, or 0xFFFFFFFF for a hang */
	uint32_t thread;	/* k_current_get() */
	uint32_t esf_valid;
	uint32_t r0, r1, r2, r3, r12, lr, pc, xpsr;
	uint32_t dfsr, dfar, ifsr, ifar;
	uint32_t assert_file;	/* const char *, 0 if no assertion failed */
	uint32_t assert_line;
	uint32_t op_offset;	/* input offset of the user thread's current op */
	uint32_t op;		/* raw op byte */
};

__noinit struct afl_crash afl_crash;

/* Marker functions: Renode ends the run when their entry block executes. */
__noinline void afl_done(void)
{
	__asm__ volatile("" ::: "memory");
}

__noinline void afl_bug(unsigned int reason)
{
	ARG_UNUSED(reason);
	__asm__ volatile("" ::: "memory");
}

__noinline void afl_hang(void)
{
	__asm__ volatile("" ::: "memory");
}

K_HEAP_DEFINE(fz_heap, CONFIG_SYSCALL_FUZZ_HEAP_SIZE);

#define USER_STACK_SIZE 2048
K_THREAD_STACK_ARRAY_DEFINE(worker_stacks, NUM_WORKERS, USER_STACK_SIZE);
struct k_thread workers[NUM_WORKERS];

/* Extra thread targets: never started, and already exited */
K_THREAD_STACK_DEFINE(dormant_stack, 1024);
static struct k_thread dormant_thread;
K_THREAD_STACK_DEFINE(dead_stack, 1024);
static struct k_thread dead_thread;
static k_tid_t main_tid;

/* Whole run budget for the workers, and how long all may stay blocked */
#define HANG_MS    500
#define IDLE_TICKS 4

K_APPMEM_PARTITION_DEFINE(fz_part);
/* Last byte the workers can access (the partition is MPU-aligned) */
extern char z_data_smem_fz_part_part_end[];

/*
 * The workers' view of the input. It is user memory, so syscalls with fuzzed
 * pointers can overwrite it: the stream state comes first, so that copies
 * running off the end of scratch[] or ubuf[] cannot reach it, and the
 * supervisor ends the run if it changes behind the workers' back (raw
 * pointers can still hit it).
 */
K_APP_BMEM(fz_part) struct fz_mem fz_mem;
static uint32_t klen;	/* kernel copy of fz_mem.ulen */

static struct k_mem_domain fz_domain;

uint8_t next_u8(void)
{
	uint32_t pos = fz_mem.upos;

	if (pos >= fz_mem.ulen || pos >= AFL_INPUT_MAX) {
		return 0;
	}
	fz_mem.upos = pos + 1;
	return fz_mem.ubuf[pos];
}

uint32_t next_u32(void)
{
	uint32_t v = 0;

	for (int i = 0; i < 4; i++) {
		v |= (uint32_t)next_u8() << (8 * i);
	}
	return v;
}

void *fz_ptr(void)
{
	uint8_t sel = next_u8();

	switch (sel % 8) {
	case 0:
		return &scratch[next_u8() % SCRATCH_SIZE];
	case 1:
		return NULL;
	case 2:
		return &afl_crash;		/* kernel data */
	case 3:
		return (void *)(uintptr_t)next_u32();
	case 4:
		return &scratch[SCRATCH_SIZE - 1 - next_u8() % 8];	/* runs off scratch */
	case 5:
		/* partition end */
		return (void *)((uintptr_t)z_data_smem_fz_part_part_end - 1 - next_u8() % 8);
	case 6:
		return (void *)&fz_ptr;		/* code */
	default:
		return &scratch[0];
	}
}

size_t fz_len(void)
{
	uint8_t sel = next_u8();

	switch (sel % 4) {
	case 0:
		return next_u8();
	case 1:
		return next_u32();
	case 2:
		return SIZE_MAX - next_u8();
	default:
		return sel >> 2;
	}
}

k_timeout_t fz_timeout(void)
{
	uint8_t sel = next_u8();

	switch (sel % 4) {
	case 0:
		return K_NO_WAIT;
	case 1:
		return K_TICKS(1 + (sel >> 2) % 3);
	case 2:
		return K_FOREVER;
	default:
		/* Raw: huge, negative and (with TIMEOUT_64BIT) absolute timeouts */
		return (k_timeout_t){ .ticks = (k_ticks_t)(int32_t)next_u32() };
	}
}

struct k_thread *fz_thread(void)
{
	uint8_t sel = next_u8();

	switch (sel % 8) {
	case 0:
		return k_current_get();
	case 1:
	case 2:
		return &workers[(sel % 8 - 1) % NUM_WORKERS];
	case 3:
		return &dormant_thread;
	case 4:
		return &dead_thread;
	case 5:
		return main_tid;		/* no permission */
	case 6:
		return NULL;
	default:
		return (struct k_thread *)(uintptr_t)next_u32();
	}
}

void fz_child_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	k_sleep(K_TICKS((uintptr_t)p1 % 4));
}

static void dead_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
}

/* Raw op bytes (checked before the group sees them) for CONFIG_SYSCALL_FUZZ_SELFTEST */
#define OP_SELFTEST_PANIC 0xF0
#define OP_SELFTEST_FAULT 0xF1
#define OP_SELFTEST_ASSERT 0xF2

/* Worker entry. Coverage (AFL_RENODE_COVERAGE=window) starts here. */
static void user_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (fz_mem.upos < fz_mem.ulen && fz_mem.upos < AFL_INPUT_MAX) {
		fz_mem.op_offset = fz_mem.upos;
		uint8_t op = next_u8();

		fz_mem.cur_op = op;

		if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SELFTEST) &&
		    (op == OP_SELFTEST_PANIC || op == OP_SELFTEST_FAULT ||
		     op == OP_SELFTEST_ASSERT)) {
			fz_mem.selftest_op = op;
			fz_mem.upos = fz_mem.ulen;
			return;
		}

		group_op(op);
	}
}

static void record_crash(unsigned int reason, const struct arch_esf *esf)
{
	afl_crash.reason = reason;
	afl_crash.thread = (uint32_t)(uintptr_t)k_current_get();
	if (esf != NULL) {
		afl_crash.esf_valid = 1;
		afl_crash.r0 = esf->basic.r0;
		afl_crash.r1 = esf->basic.r1;
		afl_crash.r2 = esf->basic.r2;
		afl_crash.r3 = esf->basic.r3;
		afl_crash.r12 = esf->basic.r12;
		afl_crash.lr = esf->basic.lr;
		afl_crash.pc = esf->basic.pc;
		afl_crash.xpsr = esf->basic.xpsr;
	}
#if defined(CONFIG_CPU_AARCH32_CORTEX_R)
	afl_crash.dfsr = __get_DFSR();
	afl_crash.dfar = __get_DFAR();
	afl_crash.ifsr = __get_IFSR();
	afl_crash.ifar = __get_IFAR();
#endif
	afl_crash.op_offset = fz_mem.op_offset;
	afl_crash.op = fz_mem.cur_op;
	afl_crash.magic = AFL_CRASH_MAGIC;
}

/* Same as the default, but keeps the location for the crash record */
void zassert_post_action(const char *file, unsigned int line)
{
	afl_crash.assert_file = (uint32_t)(uintptr_t)file;
	afl_crash.assert_line = line;

	if (k_is_user_context()) {
		k_oops();
	}
	k_panic();
	CODE_UNREACHABLE;
}

void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf)
{
	bool user_fault = esf != NULL && (esf->basic.xpsr & MODE_MASK) == MODE_USR;

	/*
	 * A syscall rejecting its arguments oopses the calling user thread, and a
	 * fault in user mode is the user thread's own problem. Both are expected;
	 * returning lets the kernel abort the thread and the supervisor carry on.
	 */
	if ((k_current_get()->base.user_options & K_USER) != 0 &&
	    (reason == K_ERR_KERNEL_OOPS || user_fault)) {
		/* A user-context assertion is not a kernel bug either */
		afl_crash.assert_file = 0;
		return;
	}

	record_crash(reason, esf);
	afl_bug(reason);
	(void)arch_irq_lock();
	for (;;) {
	}
}

static void hang(void)
{
	record_crash(0xFFFFFFFFU, NULL);
	afl_hang();
	for (;;) {
		k_sleep(K_FOREVER);
	}
}

/*
 * Waits until the input is consumed and no worker can run any more (all are
 * dead, pending or suspended). Workers blocked forever, or deadlocked on each
 * other, are a user-level outcome, not a kernel bug: if no worker can run for
 * IDLE_TICKS consecutive ticks the run is over. A worker that is still
 * runnable after HANG_MS is a hang (e.g. a kernel livelock). The supervisor has
 * a higher priority than any user thread (users cannot raise theirs above
 * their own), so it gets to run every tick.
 */
static void supervise(void)
{
	const uint8_t blocked = _THREAD_PENDING | _THREAD_SLEEPING | _THREAD_SUSPENDED |
				_THREAD_DEAD;
	int64_t deadline = k_uptime_get() + HANG_MS;
	int idle = 0;

	uint32_t last_pos = 0;

	for (;;) {
		bool alive = false, runnable = false;

		/*
		 * A syscall wrote over the stream state (through a raw pointer):
		 * the input would be replayed or overrun, so the run is over. This
		 * is deterministic, so AFL just sees a shorter run.
		 */
		if (fz_mem.ulen != klen || fz_mem.upos < last_pos || fz_mem.upos > klen) {
			return;
		}
		last_pos = fz_mem.upos;

		for (int i = 0; i < NUM_WORKERS; i++) {
			uint8_t state = workers[i].base.thread_state;

			alive |= (state & _THREAD_DEAD) == 0;
			runnable |= (state & blocked) == 0;
		}
		if (!alive) {
			return;
		}
		if (runnable) {
			idle = 0;
			if (k_uptime_get() > deadline) {
				hang();
			}
		} else if (fz_mem.upos >= fz_mem.ulen || ++idle > IDLE_TICKS) {
			return;
		}
		k_sleep(K_TICKS(1));
	}
}

int main(void)
{
	struct k_mem_partition *parts[] = { &fz_part };

	memset(&afl_crash, 0, sizeof(afl_crash));

	if (afl_input.magic != AFL_MAGIC || afl_input.len > AFL_INPUT_MAX) {
		printk("syscall-fuzz: no valid input\n");
		afl_done();
		return 0;
	}

	memcpy(fz_mem.ubuf, afl_input.data, afl_input.len);
	fz_mem.ulen = afl_input.len;
	fz_mem.upos = 0;
	klen = afl_input.len;
	main_tid = k_current_get();

	k_mem_domain_init(&fz_domain, ARRAY_SIZE(parts), parts);

	k_thread_create(&dead_thread, dead_stack, K_THREAD_STACK_SIZEOF(dead_stack),
			dead_entry, NULL, NULL, NULL, K_PRIO_PREEMPT(1), K_USER, K_FOREVER);
	k_mem_domain_add_thread(&fz_domain, &dead_thread);
	k_thread_start(&dead_thread);
	k_thread_join(&dead_thread, K_FOREVER);

	k_thread_create(&dormant_thread, dormant_stack, K_THREAD_STACK_SIZEOF(dormant_stack),
			fz_child_entry, NULL, NULL, NULL, K_PRIO_PREEMPT(2), K_USER, K_FOREVER);
	k_mem_domain_add_thread(&fz_domain, &dormant_thread);

	for (int i = 0; i < NUM_WORKERS; i++) {
		k_thread_create(&workers[i], worker_stacks[i], USER_STACK_SIZE, user_entry,
				NULL, NULL, NULL, K_PRIO_PREEMPT(1), K_USER, K_FOREVER);
		k_mem_domain_add_thread(&fz_domain, &workers[i]);
		k_thread_heap_assign(&workers[i], &fz_heap);
	}
	for (int i = 0; i < NUM_WORKERS; i++) {
		for (int j = 0; j < NUM_WORKERS; j++) {
			k_object_access_grant(&workers[j], &workers[i]);
		}
		k_object_access_grant(&dormant_thread, &workers[i]);
		k_object_access_grant(&dead_thread, &workers[i]);
	}
	group_setup();

	for (int i = 0; i < NUM_WORKERS; i++) {
		k_thread_start(&workers[i]);
	}
	supervise();

	if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SELFTEST)) {
		if (fz_mem.selftest_op == OP_SELFTEST_PANIC) {
			k_panic();
		} else if (fz_mem.selftest_op == OP_SELFTEST_FAULT) {
			/* Kernel-mode access to unmapped memory */
			(void)*(volatile uint32_t *)0xF0000000;
		}
		__ASSERT(fz_mem.selftest_op != OP_SELFTEST_ASSERT, "selftest assertion");
	}

	afl_done();

	return 0;
}
