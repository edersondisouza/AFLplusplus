/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Group "poll": k_poll() with fuzzed event arrays, plus the syscalls that
 * change the state of the polled objects.
 */

#include "harness.h"

#define MAX_EVENTS 8

/* Kernel objects the workers may legitimately use */
K_SEM_DEFINE(fz_sem, 0, 3);
K_MSGQ_DEFINE(fz_msgq, 4, 4, 4);
K_QUEUE_DEFINE(fz_queue);
K_PIPE_DEFINE(fz_pipe, 16, 4);
struct k_poll_signal fz_signal = K_POLL_SIGNAL_INITIALIZER(fz_signal);
K_APP_BMEM(fz_part) static struct k_poll_event events[MAX_EVENTS];

/*
 * Pool of object pointers for k_poll events. Includes valid objects, objects
 * of the wrong type, kernel memory that is not an object, and NULL.
 */
static void *const objs[] = {
	&fz_sem, &fz_msgq, &fz_queue, &fz_pipe, &fz_signal,
	&workers[0], &fz_heap, NULL,
};

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
				      : (struct k_poll_event *)&fz_heap;
	}

	(void)k_poll(ev, num, K_TICKS(next_u8() % 3));
}

void group_setup(void)
{
	for (int i = 0; i < NUM_WORKERS; i++) {
		k_thread_access_grant(&workers[i], &fz_sem, &fz_msgq, &fz_queue, &fz_pipe,
				      &fz_signal);
	}
}

void group_op(uint8_t op)
{
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
		uint8_t len = next_u8() % 32;

		for (int i = 0; i < len; i++) {
			scratch[i] = next_u8();
		}
		(void)k_pipe_write(&fz_pipe, scratch, len, K_NO_WAIT);
		break;
	}
	case OP_PIPE_READ:
		(void)k_pipe_read(&fz_pipe, scratch, next_u8() % 32, K_NO_WAIT);
		break;
	case OP_PIPE_RESET:
		k_pipe_reset(&fz_pipe);
		break;
	default:
		break;
	}
}
