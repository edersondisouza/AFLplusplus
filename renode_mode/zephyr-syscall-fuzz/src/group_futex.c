/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Group "futex": k_futex_wait/wake, sys_mutex (which, with
 * CONFIG_SYS_MUTEX_IMPL_FUTEX, is built on futexes in user memory and with
 * CONFIG_SYS_MUTEX_IMPL_K_MUTEX on z_sys_mutex_kernel_lock/unlock), and the
 * less used k_msgq/k_queue calls (peek_at, put_front, get_attrs,
 * cancel_wait, ...).
 *
 * Futex words live in user memory, so workers may also overwrite them
 * directly (OP_FUTEX_STORE), including the words behind a sys_mutex that
 * another worker holds or waits on: the kernel must not trust them.
 */

#include <zephyr/sys/mutex.h>
#include "harness.h"

K_APP_DMEM(fz_part) static struct k_futex futexes[2];
K_APP_DMEM(fz_part) static SYS_MUTEX_DEFINE(mutex0);
K_APP_DMEM(fz_part) static SYS_MUTEX_DEFINE(mutex1);

K_MSGQ_DEFINE(msgq4, 4, 4, 4);
K_MSGQ_DEFINE(msgq7, 7, 3, 1);	/* odd size: index and wrap-around arithmetic */
K_MSGQ_DEFINE(ungranted_msgq, 4, 2, 4);
K_QUEUE_DEFINE(queue);
K_QUEUE_DEFINE(ungranted_queue);
K_SEM_DEFINE(sem, 0, 1);	/* wrong type for the msgq/queue calls */

K_APP_BMEM(fz_part) static struct k_msgq_attrs attrs;
K_APP_BMEM(fz_part) static uint32_t result;

static struct k_futex *futex(void)
{
	uint8_t sel = next_u8();

	switch (sel % 8) {
	case 0:
	case 1:
		return &futexes[sel % 2];
#if defined(CONFIG_SYS_MUTEX_IMPL_FUTEX)
	case 2:
		return &mutex0.futex;
	case 3:
		return &mutex1.futex;
#endif
	case 4:
		return (struct k_futex *)&scratch[next_u8() % (SCRATCH_SIZE - 3)];
	case 5:
		return (struct k_futex *)&sem;	/* kernel memory */
	case 6:
		return NULL;
	default:
		return (struct k_futex *)(uintptr_t)next_u32();
	}
}

static struct sys_mutex *mutex(void)
{
	uint8_t sel = next_u8();

	switch (sel % 6) {
	case 0:
		return &mutex0;
	case 1:
		return &mutex1;
	case 2:
		return (struct sys_mutex *)&futexes[0];	/* user memory, not a sys_mutex */
	case 3:
		return (struct sys_mutex *)&sem;
	case 4:
		return NULL;
	default:
		return (struct sys_mutex *)(uintptr_t)next_u32();
	}
}

static struct k_msgq *msgq(void)
{
	uint8_t sel = next_u8();

	switch (sel % 6) {
	case 0:
		return &msgq4;
	case 1:
		return &msgq7;
	case 2:
		return &ungranted_msgq;
	case 3:
		return (struct k_msgq *)&sem;
	case 4:
		return NULL;
	default:
		return (struct k_msgq *)(uintptr_t)next_u32();
	}
}

static struct k_queue *queue_sel(void)
{
	uint8_t sel = next_u8();

	switch (sel % 5) {
	case 0:
		return &queue;
	case 1:
		return &ungranted_queue;
	case 2:
		return (struct k_queue *)&sem;
	case 3:
		return NULL;
	default:
		return (struct k_queue *)(uintptr_t)next_u32();
	}
}

static bool in_user_mem(const void *p)
{
	uintptr_t a = (uintptr_t)p;

	return (a >= (uintptr_t)&scratch[0] && a < (uintptr_t)&scratch[SCRATCH_SIZE]) ||
	       (a >= (uintptr_t)&futexes[0] && a < (uintptr_t)&futexes[2]) ||
	       p == (void *)&mutex0 || p == (void *)&mutex1;
}

enum op {
	OP_FUTEX_WAIT,
	OP_FUTEX_WAKE,
	OP_FUTEX_STORE,
	OP_MUTEX_LOCK,
	OP_MUTEX_UNLOCK,
	OP_MUTEX_INIT,
	OP_MSGQ_PUT,
	OP_MSGQ_GET,
	OP_MSGQ_PUT_FRONT,
	OP_MSGQ_PEEK,
	OP_MSGQ_PEEK_AT,
	OP_MSGQ_ATTRS,
	OP_MSGQ_PURGE,
	OP_QUEUE_INSERT,
	OP_QUEUE_GET,
	OP_QUEUE_PEEK,
	OP_QUEUE_CANCEL_WAIT,
	OP_SLEEP,
	OP_COUNT,
};

void group_setup(void)
{
	for (int i = 0; i < NUM_WORKERS; i++) {
		k_thread_access_grant(&workers[i], &msgq4, &msgq7, &queue, &sem);
	}
}

void group_op(uint8_t op)
{
	switch (op % OP_COUNT) {
	case OP_FUTEX_WAIT: {
		struct k_futex *f = futex();
		uint8_t sel = next_u8();
		/* Usually the current value (when readable), so the wait blocks */
		atomic_val_t expected = (sel & 1) ? (atomic_val_t)next_u32()
				      : in_user_mem(f) ? atomic_get(&f->val) : 0;

		result = k_futex_wait(f, expected, fz_timeout());
		break;
	}
	case OP_FUTEX_WAKE: {
		struct k_futex *f = futex();

		result = k_futex_wake(f, next_u8() & 1);
		break;
	}
	case OP_FUTEX_STORE: {
		uint8_t sel = next_u8() % 4;
		atomic_t *word = sel < 2 ? &futexes[sel].val
#if defined(CONFIG_SYS_MUTEX_IMPL_FUTEX)
				 : &(sel == 2 ? &mutex0 : &mutex1)->futex.val;
#else
				 : &(sel == 2 ? &mutex0 : &mutex1)->val;
#endif

		atomic_set(word, (atomic_val_t)next_u32());
		break;
	}
	case OP_MUTEX_LOCK: {
		struct sys_mutex *m = mutex();

		result = sys_mutex_lock(m, fz_timeout());
		break;
	}
	case OP_MUTEX_UNLOCK:
		result = sys_mutex_unlock(mutex());
		break;
	case OP_MUTEX_INIT:
		sys_mutex_init(mutex());
		break;
	case OP_MSGQ_PUT: {
		struct k_msgq *q = msgq();
		void *data = fz_ptr();

		result = k_msgq_put(q, data, fz_timeout());
		break;
	}
	case OP_MSGQ_GET: {
		struct k_msgq *q = msgq();
		void *data = fz_ptr();

		result = k_msgq_get(q, data, fz_timeout());
		break;
	}
	case OP_MSGQ_PUT_FRONT: {
		struct k_msgq *q = msgq();

		result = k_msgq_put_front(q, fz_ptr());
		break;
	}
	case OP_MSGQ_PEEK: {
		struct k_msgq *q = msgq();

		result = k_msgq_peek(q, fz_ptr());
		break;
	}
	case OP_MSGQ_PEEK_AT: {
		struct k_msgq *q = msgq();
		void *data = fz_ptr();

		result = k_msgq_peek_at(q, data, next_u32());
		break;
	}
	case OP_MSGQ_ATTRS: {
		struct k_msgq *q = msgq();
		uint8_t sel = next_u8();

		if (sel % 3 == 0) {
			k_msgq_get_attrs(q, (sel & 4) ? fz_ptr() : &attrs);
		} else if (sel % 3 == 1) {
			result = k_msgq_num_free_get(q);
		} else {
			result = k_msgq_num_used_get(q);
		}
		break;
	}
	case OP_MSGQ_PURGE:
		k_msgq_purge(msgq());
		break;
	case OP_QUEUE_INSERT: {
		struct k_queue *q = queue_sel();
		uint8_t sel = next_u8();
		void *data = fz_ptr();

		result = (sel & 1) ? k_queue_alloc_prepend(q, data) : k_queue_alloc_append(q, data);
		break;
	}
	case OP_QUEUE_GET: {
		struct k_queue *q = queue_sel();

		result = (uintptr_t)k_queue_get(q, fz_timeout());
		break;
	}
	case OP_QUEUE_PEEK: {
		struct k_queue *q = queue_sel();
		uint8_t sel = next_u8();

		result = sel % 3 == 0 ? (uintptr_t)k_queue_peek_head(q)
			 : sel % 3 == 1 ? (uintptr_t)k_queue_peek_tail(q) : k_queue_is_empty(q);
		break;
	}
	case OP_QUEUE_CANCEL_WAIT:
		k_queue_cancel_wait(queue_sel());
		break;
	case OP_SLEEP:
		(void)k_sleep(fz_timeout());
		break;
	default:
		break;
	}
}
