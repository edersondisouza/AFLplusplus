/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Group "thread": syscalls that read or change attributes of another thread
 * (name, priority, deadline, suspension, timeouts, stack usage). Targets come
 * from fz_thread(): the caller, the other workers, a thread that was created
 * but never started, a thread that already exited, a thread the caller has no
 * permission on, NULL and raw pointers. Workers may suspend, abort or wake
 * each other while the target is blocked in a syscall.
 */

#include "harness.h"

K_APP_BMEM(fz_part) static char name_buf[CONFIG_THREAD_MAX_NAME_LEN + 4];
K_APP_BMEM(fz_part) static size_t unused;
K_APP_BMEM(fz_part) static uint32_t result;

/* Strings for k_thread_name_set(): terminated, unterminated, unmapped, ... */
static const char *name_str(void)
{
	uint8_t sel = next_u8();

	switch (sel % 4) {
	case 0:
		/* NUL-terminated at a fuzzed position within the scratch buffer */
		scratch[next_u8() % SCRATCH_SIZE] = '\0';
		return (const char *)scratch;
	case 1:
		return "fz";
	default:
		/* scratch without terminator, partition end, kernel, NULL, raw */
		return fz_ptr();
	}
}

enum op {
	OP_NAME_SET,
	OP_NAME_COPY,
	OP_PRIORITY_SET,
	OP_PRIORITY_GET,
	OP_DEADLINE_SET,
	OP_SUSPEND,
	OP_RESUME,
	OP_WAKEUP,
	OP_JOIN,
	OP_ABORT,
	OP_TIMEOUT_GET,
	OP_STACK_SPACE,
	OP_STACK_THRESHOLD,
	OP_CUSTOM_DATA,
	OP_SLEEP,
	OP_YIELD,
	OP_COUNT,
};

void group_setup(void)
{
}

void group_op(uint8_t op)
{
	switch (op % OP_COUNT) {
	case OP_NAME_SET: {
		struct k_thread *t = fz_thread();

		result = k_thread_name_set(t, name_str());
		break;
	}
	case OP_NAME_COPY: {
		struct k_thread *t = fz_thread();
		uint8_t sel = next_u8();
		char *buf = (sel & 1) ? name_buf : fz_ptr();

		result = k_thread_name_copy(t, buf, (sel & 2) ? fz_len() : (sel >> 2) % sizeof(name_buf));
		break;
	}
	case OP_PRIORITY_SET: {
		struct k_thread *t = fz_thread();
		uint8_t sel = next_u8();
		int prio = (sel & 1) ? (int)next_u32() : (int)(sel >> 1) - 64;

		k_thread_priority_set(t, prio);
		break;
	}
	case OP_PRIORITY_GET:
		result = k_thread_priority_get(fz_thread());
		break;
	case OP_DEADLINE_SET: {
		struct k_thread *t = fz_thread();
		uint8_t sel = next_u8();
		int deadline = (sel & 2) ? (int)next_u32() : (int)(sel >> 2) - 8;

		if (sel & 1) {
			k_thread_absolute_deadline_set(t, deadline);
		} else {
			k_thread_deadline_set(t, deadline);
		}
		break;
	}
	case OP_SUSPEND:
		k_thread_suspend(fz_thread());
		break;
	case OP_RESUME:
		k_thread_resume(fz_thread());
		break;
	case OP_WAKEUP:
		/* Also starts the dormant thread (k_thread_start is not a syscall) */
		k_wakeup(fz_thread());
		break;
	case OP_JOIN: {
		struct k_thread *t = fz_thread();

		result = k_thread_join(t, fz_timeout());
		break;
	}
	case OP_ABORT:
		k_thread_abort(fz_thread());
		break;
	case OP_TIMEOUT_GET: {
		struct k_thread *t = fz_thread();

		result = (next_u8() & 1) ? k_thread_timeout_expires_ticks(t)
					 : k_thread_timeout_remaining_ticks(t);
		break;
	}
	case OP_STACK_SPACE: {
		struct k_thread *t = fz_thread();

		result = k_thread_stack_space_get(t, (next_u8() & 1) ? fz_ptr() : &unused);
		break;
	}
	case OP_STACK_THRESHOLD: {
#if defined(CONFIG_THREAD_RUNTIME_STACK_SAFETY)
		struct k_thread *t = fz_thread();
		uint8_t sel = next_u8();

		if (sel % 3 == 0) {
			result = k_thread_runtime_stack_unused_threshold_pct_set(t, next_u32());
		} else if (sel % 3 == 1) {
			result = k_thread_runtime_stack_unused_threshold_set(t, fz_len());
		} else {
			result = k_thread_runtime_stack_unused_threshold_get(t);
		}
#endif
		break;
	}
	case OP_CUSTOM_DATA:
		if (next_u8() & 1) {
			k_thread_custom_data_set((void *)(uintptr_t)next_u32());
		} else {
			result = (uintptr_t)k_thread_custom_data_get();
		}
		break;
	case OP_SLEEP:
		(void)k_sleep(fz_timeout());
		break;
	case OP_YIELD:
		k_yield();
		break;
	default:
		break;
	}
}
