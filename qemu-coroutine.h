/*
 * QEMU coroutine implementation
 */
#ifndef QEMU_COROUTINE_H
#define QEMU_COROUTINE_H

#include <stdbool.h>
#include "qemu-queue.h"

typedef void CoroutineEntry(void *opaque);
typedef struct Coroutine Coroutine;
Coroutine *qemu_coroutine_create(CoroutineEntry *entry);
void qemu_coroutine_enter(Coroutine *coroutine, void *opaque);
void qemu_coroutine_yield(void);
Coroutine *qemu_coroutine_self(void);
bool qemu_in_coroutine(void);

typedef struct CoQueue {
    QTAILQ_HEAD(, Coroutine) entries;
} CoQueue;
void qemu_co_queue_init(CoQueue *queue);
void qemu_co_queue_wait(CoQueue *queue);
bool qemu_co_queue_next(CoQueue *queue);
bool qemu_co_queue_empty(CoQueue *queue);

typedef struct CoMutex {
    bool locked;
    CoQueue queue;
} CoMutex;

void qemu_co_mutex_init(CoMutex *mutex);

void qemu_co_mutex_lock(CoMutex *mutex);
void qemu_co_mutex_unlock(CoMutex *mutex);

typedef struct CoRwlock {
    bool writer;
    int reader;
    CoQueue queue;
} CoRwlock;

void qemu_co_rwlock_init(CoRwlock *lock);
void qemu_co_rwlock_rdlock(CoRwlock *lock);
void qemu_co_rwlock_wrlock(CoRwlock *lock);
void qemu_co_rwlock_unlock(CoRwlock *lock);

#endif /* QEMU_COROUTINE_H */
