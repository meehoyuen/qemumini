#include "qemu-common.h"
#include "qemu-coroutine.h"
#include "qemu-coroutine-int.h"
#include "qemu-queue.h"
#include "main-loop.h"

static QTAILQ_HEAD(, Coroutine) unlock_bh_queue =
    QTAILQ_HEAD_INITIALIZER(unlock_bh_queue);
static QEMUBH* unlock_bh;

static void qemu_co_queue_next_bh(void *opaque)
{
    Coroutine *next;

    while ((next = QTAILQ_FIRST(&unlock_bh_queue))) {
        QTAILQ_REMOVE(&unlock_bh_queue, next, co_queue_next);
        qemu_coroutine_enter(next, NULL);
    }
}

void qemu_co_queue_init(CoQueue *queue)
{
    QTAILQ_INIT(&queue->entries);

    if (!unlock_bh) {
        unlock_bh = qemu_bh_new(qemu_co_queue_next_bh, NULL);
    }
}

void qemu_co_queue_wait(CoQueue *queue)
{
    Coroutine *self = qemu_coroutine_self();
    QTAILQ_INSERT_TAIL(&queue->entries, self, co_queue_next);
    qemu_coroutine_yield();
    assert(qemu_in_coroutine());
}

bool qemu_co_queue_next(CoQueue *queue)
{
    Coroutine *next;

    next = QTAILQ_FIRST(&queue->entries);
    if (next) {
        QTAILQ_REMOVE(&queue->entries, next, co_queue_next);
        QTAILQ_INSERT_TAIL(&unlock_bh_queue, next, co_queue_next);
        qemu_bh_schedule(unlock_bh);
    }

    return (next != NULL);
}

bool qemu_co_queue_empty(CoQueue *queue)
{
    return (QTAILQ_FIRST(&queue->entries) == NULL);
}

void qemu_co_mutex_init(CoMutex *mutex)
{
    memset(mutex, 0, sizeof(*mutex));
    qemu_co_queue_init(&mutex->queue);
}

void qemu_co_mutex_lock(CoMutex *mutex)
{
    while (mutex->locked) {
        qemu_co_queue_wait(&mutex->queue);
    }

    mutex->locked = true;
}

void qemu_co_mutex_unlock(CoMutex *mutex)
{
    assert(mutex->locked == true);
    assert(qemu_in_coroutine());

    mutex->locked = false;
    qemu_co_queue_next(&mutex->queue);
}

void qemu_co_rwlock_init(CoRwlock *lock)
{
    memset(lock, 0, sizeof(*lock));
    qemu_co_queue_init(&lock->queue);
}

void qemu_co_rwlock_rdlock(CoRwlock *lock)
{
    while (lock->writer) {
        qemu_co_queue_wait(&lock->queue);
    }
    lock->reader++;
}

void qemu_co_rwlock_unlock(CoRwlock *lock)
{
    assert(qemu_in_coroutine());
    if (lock->writer) {
        lock->writer = false;
        while (!qemu_co_queue_empty(&lock->queue)) {
            /*
             * Wakeup every body. This will include some
             * writers too.
             */
            qemu_co_queue_next(&lock->queue);
        }
    } else {
        lock->reader--;
        assert(lock->reader >= 0);
        /* Wakeup only one waiting writer */
        if (!lock->reader) {
            qemu_co_queue_next(&lock->queue);
        }
    }
}

void qemu_co_rwlock_wrlock(CoRwlock *lock)
{
    while (lock->writer || lock->reader) {
        qemu_co_queue_wait(&lock->queue);
    }
    lock->writer = true;
}
