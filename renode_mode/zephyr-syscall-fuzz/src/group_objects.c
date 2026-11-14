/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Group "objects": the lifecycle of dynamic kernel objects and the calls that
 * use them. Workers allocate objects (k_object_alloc/_size), initialise them as
 * any type, grant them to other threads, release them, and use them while
 * other workers may be blocked on them. Thread stacks are allocated and freed
 * (k_thread_stack_alloc/free) and used to create short-lived user threads, so
 * stacks can be freed while their thread is still running or after it exited.
 *
 * Objects are referred to by selector (see obj()), so a slot keeps whatever a
 * syscall returned, including NULL, and ops can apply to stale pointers after
 * a release.
 */

#include "harness.h"

#define NUM_SLOTS  8
#define NUM_STACKS 4

/* Statically allocated objects, granted to the workers */
K_SEM_DEFINE(st_sem, 0, 4);
K_EVENT_DEFINE(st_event);
K_CONDVAR_DEFINE(st_condvar);
K_MUTEX_DEFINE(st_mutex);
/* Never granted */
K_SEM_DEFINE(ungranted_sem, 0, 1);

K_APP_BMEM(fz_part) static void *slot[NUM_SLOTS];
K_APP_BMEM(fz_part) static k_thread_stack_t *stk[NUM_STACKS];
/* Requested sizes of the dynamic stacks in slot[] and stk[] (SKIP_KNOWN_BUGS) */
K_APP_BMEM(fz_part) static size_t slot_stack_size[NUM_SLOTS];
K_APP_BMEM(fz_part) static size_t stk_size[NUM_STACKS];
K_APP_BMEM(fz_part) static uint32_t evset;

static const enum k_objects types[] = {
	K_OBJ_SEM, K_OBJ_EVENT, K_OBJ_CONDVAR, K_OBJ_MUTEX, K_OBJ_MSGQ,
	K_OBJ_STACK, K_OBJ_QUEUE, K_OBJ_PIPE, K_OBJ_THREAD,
	K_OBJ_THREAD_STACK_ELEMENT, K_OBJ_POLL_SIGNAL, K_OBJ_TIMER,
	K_OBJ_SYS_MUTEX, K_OBJ_ANY,
};

static enum k_objects otype(void)
{
	uint8_t sel = next_u8();

	return sel < ARRAY_SIZE(types) ? types[sel] : (enum k_objects)(sel - ARRAY_SIZE(types));
}

/*
 * Known bug: unref_check() runs z_msgq_cleanup()/z_stack_cleanup() on
 * dynamic objects that were never initialized; k_object_alloc() does not
 * zero them, so stale heap contents get k_free()d. Initialize such objects
 * right away (consumes no input) so they are always valid when released.
 */
static void *alloced(void *o, enum k_objects t)
{
	if (!IS_ENABLED(CONFIG_SYSCALL_FUZZ_SKIP_KNOWN_BUGS) || o == NULL) {
		return o;
	}
	if (t == K_OBJ_MSGQ) {
		(void)k_msgq_alloc_init(o, 4, 1);
	} else if (t == K_OBJ_STACK) {
		(void)k_stack_alloc_init(o, 1);
	}
	return o;
}

static void *obj(void)
{
	uint8_t sel = next_u8() % (NUM_SLOTS + 9);

	if (sel < NUM_SLOTS) {
		return slot[sel];
	}
	switch (sel - NUM_SLOTS) {
	case 0:
		return &st_sem;
	case 1:
		return &st_event;
	case 2:
		return &st_condvar;
	case 3:
		return &st_mutex;
	case 4:
		return &ungranted_sem;
	case 5:
		return stk[next_u8() % NUM_STACKS];
	case 6:
		return fz_thread();
	case 7:
		return NULL;
	default:
		return (void *)(uintptr_t)next_u32();
	}
}

static k_thread_stack_t *stack(void)
{
	uint8_t sel = next_u8();

	return sel < 0xF0 ? stk[sel % NUM_STACKS] : obj();
}

enum op {
	OP_ALLOC,
	OP_ALLOC_SIZE,
	OP_RELEASE,
	OP_GRANT,
	OP_ACCESS_CHECK,
	OP_INIT,
	OP_SEM,
	OP_EVENT_SET,
	OP_EVENT_WAIT,
	OP_CONDVAR_SIGNAL,
	OP_CONDVAR_WAIT,
	OP_MUTEX,
	OP_USE,
	OP_STACK_ALLOC,
	OP_STACK_FREE,
	OP_THREAD_CREATE,
	OP_THREAD_JOIN,
	OP_SLEEP,
	OP_COUNT,
};

static void do_init(void)
{
	void *o = obj();

	switch (next_u8() % 9) {
	case 0: {
		uint32_t initial = next_u8(), limit = next_u8();

		(void)k_sem_init(o, initial, limit);
		break;
	}
	case 1:
		k_event_init(o);
		break;
	case 2:
		(void)k_condvar_init(o);
		break;
	case 3:
		(void)k_mutex_init(o);
		break;
	case 4: {
		size_t msg_size = fz_len();
		uint32_t max_msgs = next_u32();

		if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SKIP_KNOWN_BUGS) && msg_size == 0) {
			break;
		}
		(void)k_msgq_alloc_init(o, msg_size, max_msgs);
		break;
	}
	case 5:
		(void)k_stack_alloc_init(o, next_u32());
		break;
	case 6:
		k_queue_init(o);
		break;
	case 7: {
		uint8_t *buf = fz_ptr();

		k_pipe_init(o, buf, fz_len());
		break;
	}
	default:
		k_poll_signal_init(o);
		break;
	}
}

/* Data path of the other object types, on whatever obj() returns */
static void do_use(void)
{
	void *o = obj();
	uint8_t kind = next_u8();

	switch (kind % 8) {
	case 0: {
		void *data = fz_ptr();

		(void)k_msgq_put(o, data, fz_timeout());
		break;
	}
	case 1: {
		void *data = fz_ptr();

		(void)k_msgq_get(o, data, fz_timeout());
		break;
	}
	case 2:
		(void)k_stack_push(o, next_u32());
		break;
	case 3: {
		stack_data_t *data = fz_ptr();

		(void)k_stack_pop(o, data, fz_timeout());
		break;
	}
	case 4:
		(void)k_queue_alloc_append(o, fz_ptr());
		break;
	case 5:
		(void)k_queue_get(o, fz_timeout());
		break;
	case 6: {
		void *data = fz_ptr();

		(void)k_pipe_write(o, data, fz_len(), fz_timeout());
		break;
	}
	default: {
		void *data = fz_ptr();

		(void)k_pipe_read(o, data, fz_len(), fz_timeout());
		break;
	}
	}
}

static void do_event_wait(void)
{
	void *o = obj();
	uint8_t kind = next_u8();
	uint32_t events = next_u32();
	bool reset = kind & BIT(2);
	k_timeout_t timeout = fz_timeout();

	switch (kind % 4) {
	case 0:
		evset = k_event_wait(o, events, reset, timeout);
		break;
	case 1:
		evset = k_event_wait_all(o, events, reset, timeout);
		break;
	case 2:
		evset = k_event_wait_safe(o, events, reset, timeout);
		break;
	default:
		evset = k_event_wait_all_safe(o, events, reset, timeout);
		break;
	}
}

static void do_event_set(void)
{
	void *o = obj();
	uint8_t kind = next_u8();
	uint32_t events = next_u32();

	switch (kind % 4) {
	case 0:
		evset = k_event_post(o, events);
		break;
	case 1:
		evset = k_event_set(o, events);
		break;
	case 2:
		evset = k_event_set_masked(o, events, next_u32());
		break;
	default:
		evset = k_event_clear(o, events);
		break;
	}
}

/*
 * Known bug: the kernel does not check that TLS + initial frame fit in the
 * user-supplied stack size and writes below the stack object.
 */
#define KNOWN_BUG_MIN_STACK 128

/*
 * Known bug: for a dynamically allocated user stack (k_thread_stack_alloc()
 * with K_USER, or k_object_alloc_size(K_OBJ_THREAD_STACK_ELEMENT)) the
 * object's size is the whole allocation, privileged stack included, so
 * k_thread_create() accepts a stack_size larger than the one requested and
 * the user stack region covers the privileged stack. Returns the size
 * requested for s if it is one of ours, else SIZE_MAX.
 */
static size_t dyn_stack_size(const void *s)
{
	for (int i = 0; i < NUM_STACKS; i++) {
		if (s != NULL && s == stk[i]) {
			return stk_size[i];
		}
	}
	for (int i = 0; i < NUM_SLOTS; i++) {
		if (s != NULL && s == slot[i]) {
			return slot_stack_size[i];
		}
	}
	return SIZE_MAX;
}

static void do_thread_create(void)
{
	struct k_thread *t = obj();
	k_thread_stack_t *s = stack();
	size_t size = fz_len();
	uint8_t prio = next_u8();
	uint32_t options = next_u8() | K_USER;
	uintptr_t ticks = next_u8();
	k_timeout_t delay = fz_timeout();

	if (IS_ENABLED(CONFIG_SYSCALL_FUZZ_SKIP_KNOWN_BUGS) &&
	    (size < KNOWN_BUG_MIN_STACK || size > dyn_stack_size(s))) {
		return;
	}
	(void)k_thread_create(t, s, size, fz_child_entry, (void *)ticks, NULL, NULL,
			      K_PRIO_PREEMPT(1 + prio % 8), options, delay);
}

void group_setup(void)
{
	for (int i = 0; i < NUM_WORKERS; i++) {
		k_thread_access_grant(&workers[i], &st_sem, &st_event, &st_condvar, &st_mutex);
	}
}

void group_op(uint8_t op)
{
	switch (op % OP_COUNT) {
	case OP_ALLOC: {
		uint8_t i = next_u8() % NUM_SLOTS;

		enum k_objects t = otype();

		slot[i] = alloced(k_object_alloc(t), t);
		slot_stack_size[i] = SIZE_MAX;
		break;
	}
	case OP_ALLOC_SIZE: {
		uint8_t i = next_u8() % NUM_SLOTS;
		enum k_objects t = otype();
		size_t size = fz_len();

		slot[i] = alloced(k_object_alloc_size(t, size), t);
		slot_stack_size[i] = t == K_OBJ_THREAD_STACK_ELEMENT ? size : SIZE_MAX;
		break;
	}
	case OP_RELEASE:
		k_object_release(obj());
		break;
	case OP_GRANT: {
		void *o = obj();

		k_object_access_grant(o, fz_thread());
		break;
	}
	case OP_ACCESS_CHECK:
		(void)k_object_access_check(obj());
		break;
	case OP_INIT:
		do_init();
		break;
	case OP_SEM: {
		void *o = obj();

		if (next_u8() & 1) {
			k_sem_give(o);
		} else {
			(void)k_sem_take(o, fz_timeout());
		}
		break;
	}
	case OP_EVENT_SET:
		do_event_set();
		break;
	case OP_EVENT_WAIT:
		do_event_wait();
		break;
	case OP_CONDVAR_SIGNAL: {
		void *o = obj();

		if (next_u8() & 1) {
			(void)k_condvar_broadcast(o);
		} else {
			(void)k_condvar_signal(o);
		}
		break;
	}
	case OP_CONDVAR_WAIT: {
		void *cv = obj();
		void *mutex = obj();

		(void)k_condvar_wait(cv, mutex, fz_timeout());
		break;
	}
	case OP_MUTEX: {
		void *o = obj();

		if (next_u8() & 1) {
			(void)k_mutex_unlock(o);
		} else {
			(void)k_mutex_lock(o, fz_timeout());
		}
		break;
	}
	case OP_USE:
		do_use();
		break;
	case OP_STACK_ALLOC: {
		uint8_t i = next_u8() % NUM_STACKS;
		size_t size = fz_len();

		stk[i] = k_thread_stack_alloc(size, next_u8() & K_USER);
		stk_size[i] = size;
		break;
	}
	case OP_STACK_FREE:
		(void)k_thread_stack_free(stack());
		break;
	case OP_THREAD_CREATE:
		do_thread_create();
		break;
	case OP_THREAD_JOIN: {
		struct k_thread *t = obj();

		if (next_u8() & 1) {
			k_thread_abort(t);
		} else {
			(void)k_thread_join(t, fz_timeout());
		}
		break;
	}
	case OP_SLEEP:
		(void)k_sleep(fz_timeout());
		break;
	default:
		break;
	}
}
