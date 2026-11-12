/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Syscall fuzzing harness for AFL++ + Renode, targeting k_poll().
 *
 * Renode writes the AFL test case into afl_input (a .noinit buffer) before the
 * CPU starts. A supervisor thread copies it into a user-accessible partition
 * and starts a K_USER thread that interprets it as a sequence of operations:
 * fuzzed k_poll() calls plus state-changing syscalls on the polled objects.
 *
 * The harness reports the outcome by calling one of the afl_*() marker
 * functions, which Renode watches for:
 *   afl_done() - all operations ran, or the user thread was killed by an
 *                expected oops (syscall argument validation rejected input)
 *   afl_bug()  - fatal error in kernel context (CPU fault, panic, assertion)
 *   afl_hang() - the user thread did not finish in time
 *
 * Before afl_bug() and afl_hang() the harness fills afl_crash, which the host
 * reads to describe the failure without needing any console output.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/app_memory/app_memdomain.h>
#include <zephyr/fatal.h>
#include <zephyr/sys/zassert.h>
#if defined(CONFIG_CPU_AARCH32_CORTEX_R)
#include <cmsis_core.h>
#endif

#define AFL_MAGIC     0xAF1F5C11U
#define AFL_INPUT_MAX 4096
#define MAX_EVENTS    8

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

/* Kernel objects the user thread may legitimately use */
K_SEM_DEFINE(fz_sem, 0, 3);
K_MSGQ_DEFINE(fz_msgq, 4, 4, 4);
K_QUEUE_DEFINE(fz_queue);
K_PIPE_DEFINE(fz_pipe, 16, 4);
struct k_poll_signal fz_signal = K_POLL_SIGNAL_INITIALIZER(fz_signal);
K_HEAP_DEFINE(fz_heap, 2048);

#define USER_STACK_SIZE 2048
K_THREAD_STACK_DEFINE(user_stack, USER_STACK_SIZE);
static struct k_thread user_thread;

/*
 * Pool of object pointers for k_poll events. Includes valid objects, objects
 * of the wrong type, a kernel object not granted to the thread, and NULL.
 */
static void *const objs[] = {
	&fz_sem, &fz_msgq, &fz_queue, &fz_pipe, &fz_signal,
	&user_thread, &afl_input, NULL,
};

K_APPMEM_PARTITION_DEFINE(fz_part);
K_APP_BMEM(fz_part) static uint8_t ubuf[AFL_INPUT_MAX];
K_APP_BMEM(fz_part) static uint32_t ulen;
K_APP_BMEM(fz_part) static uint32_t upos;
K_APP_BMEM(fz_part) static struct k_poll_event events[MAX_EVENTS];
K_APP_BMEM(fz_part) static uint8_t scratch[32];
K_APP_BMEM(fz_part) static uint32_t op_offset;
K_APP_BMEM(fz_part) static uint8_t cur_op;

static struct k_mem_domain fz_domain;

static uint8_t next_u8(void)
{
	return (upos < ulen) ? ubuf[upos++] : 0;
}

static uint32_t next_u32(void)
{
	uint32_t v = 0;

	for (int i = 0; i < 4; i++) {
		v |= (uint32_t)next_u8() << (8 * i);
	}
	return v;
}

enum fz_op {
	OP_POLL,
	OP_SEM_GIVE,
	OP_SEM_TAKE,
	OP_SIGNAL_RAISE,
	OP_SIGNAL_RESET,
	OP_MSGQ_PUT,
	OP_MSGQ_GET,
	OP_MSGQ_PURGE,
	OP_QUEUE_APPEND,
	OP_QUEUE_GET,
	OP_PIPE_WRITE,
	OP_PIPE_READ,
	OP_PIPE_RESET,
	OP_COUNT,
};

/* Raw op bytes (checked before the modulo) for CONFIG_SYSCALL_FUZZ_SELFTEST */
#define OP_SELFTEST_PANIC 0xF0
#define OP_SELFTEST_FAULT 0xF1
#define OP_SELFTEST_ASSERT 0xF2
K_APP_BMEM(fz_part) static uint8_t selftest_op;

/*
 * OP_POLL encoding:
 *   u8  number of events present in the payload (mod MAX_EVENTS + 1)
 *   u8  flags: bit0 raw num_events (u32 follows)
 *              bit1 replace events pointer: bit2 ? raw u32 : kernel address
 *   n * { sizeof(struct k_poll_event) raw bytes, u8 object selector }
 *   u8  timeout in ticks (mod 3; 0 is K_NO_WAIT)
 */
static void do_poll(void)
{
	uint8_t n = next_u8() % (MAX_EVENTS + 1);
	uint8_t flags = next_u8();
	struct k_poll_event *ev = events;
	int num = n;

	for (int i = 0; i < n; i++) {
		uint8_t *raw = (uint8_t *)&events[i];
		uint8_t sel;

		for (size_t j = 0; j < sizeof(events[i]); j++) {
			raw[j] = next_u8();
		}
		/* Out-of-range selectors keep the raw pointer from the payload */
		sel = next_u8();
		if (sel < ARRAY_SIZE(objs)) {
			events[i].obj = objs[sel];
		}
	}

	if (flags & BIT(0)) {
		num = (int)next_u32();
	}
	if (flags & BIT(1)) {
		ev = (flags & BIT(2)) ? (struct k_poll_event *)(uintptr_t)next_u32()
				      : (struct k_poll_event *)&afl_input;
	}

	(void)k_poll(ev, num, K_TICKS(next_u8() % 3));
}

static void user_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (upos < ulen) {
		op_offset = upos;
		uint8_t op = next_u8();

		cur_op = op;

		if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SELFTEST) &&
		    (op == OP_SELFTEST_PANIC || op == OP_SELFTEST_FAULT ||
		     op == OP_SELFTEST_ASSERT)) {
			selftest_op = op;
			return;
		}

		switch (op % OP_COUNT) {
		case OP_POLL:
			do_poll();
			break;
		case OP_SEM_GIVE:
			k_sem_give(&fz_sem);
			break;
		case OP_SEM_TAKE:
			(void)k_sem_take(&fz_sem, K_NO_WAIT);
			break;
		case OP_SIGNAL_RAISE:
			(void)k_poll_signal_raise(&fz_signal, (int)next_u32());
			break;
		case OP_SIGNAL_RESET:
			k_poll_signal_reset(&fz_signal);
			break;
		case OP_MSGQ_PUT:
			for (int i = 0; i < 4; i++) {
				scratch[i] = next_u8();
			}
			(void)k_msgq_put(&fz_msgq, scratch, K_NO_WAIT);
			break;
		case OP_MSGQ_GET:
			(void)k_msgq_get(&fz_msgq, scratch, K_NO_WAIT);
			break;
		case OP_MSGQ_PURGE:
			k_msgq_purge(&fz_msgq);
			break;
		case OP_QUEUE_APPEND:
			(void)k_queue_alloc_append(&fz_queue, &scratch[next_u8() % 16]);
			break;
		case OP_QUEUE_GET:
			(void)k_queue_get(&fz_queue, K_NO_WAIT);
			break;
		case OP_PIPE_WRITE: {
			uint8_t len = next_u8() % sizeof(scratch);

			for (int i = 0; i < len; i++) {
				scratch[i] = next_u8();
			}
			(void)k_pipe_write(&fz_pipe, scratch, len, K_NO_WAIT);
			break;
		}
		case OP_PIPE_READ:
			(void)k_pipe_read(&fz_pipe, scratch, next_u8() % sizeof(scratch), K_NO_WAIT);
			break;
		case OP_PIPE_RESET:
			k_pipe_reset(&fz_pipe);
			break;
		default:
			break;
		}
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
	afl_crash.op_offset = op_offset;
	afl_crash.op = cur_op;
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
	if (k_current_get() == &user_thread &&
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

int main(void)
{
	struct k_mem_partition *parts[] = { &fz_part };

	memset(&afl_crash, 0, sizeof(afl_crash));

	if (afl_input.magic != AFL_MAGIC || afl_input.len > AFL_INPUT_MAX) {
		printk("syscall-fuzz: no valid input\n");
		afl_done();
		return 0;
	}

	memcpy(ubuf, afl_input.data, afl_input.len);
	ulen = afl_input.len;
	upos = 0;

	k_mem_domain_init(&fz_domain, ARRAY_SIZE(parts), parts);
	k_thread_create(&user_thread, user_stack, USER_STACK_SIZE, user_entry,
			NULL, NULL, NULL, K_PRIO_PREEMPT(1), K_USER, K_FOREVER);
	k_mem_domain_add_thread(&fz_domain, &user_thread);
	k_thread_access_grant(&user_thread, &fz_sem, &fz_msgq, &fz_queue, &fz_pipe,
			      &fz_signal);
	k_thread_heap_assign(&user_thread, &fz_heap);
	k_thread_start(&user_thread);

	if (k_thread_join(&user_thread, K_MSEC(500)) != 0) {
		record_crash(0xFFFFFFFFU, NULL);
		afl_hang();
		return 0;
	}

	if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SELFTEST)) {
		if (selftest_op == OP_SELFTEST_PANIC) {
			k_panic();
		} else if (selftest_op == OP_SELFTEST_FAULT) {
			/* Kernel-mode access to unmapped memory */
			(void)*(volatile uint32_t *)0xF0000000;
		}
		__ASSERT(selftest_op != OP_SELFTEST_ASSERT, "selftest assertion");
	}

	afl_done();

	return 0;
}
