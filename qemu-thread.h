#ifndef __QEMU_THREAD_H
#define __QEMU_THREAD_H 1

#include <inttypes.h>
#include "pthread.h"

typedef struct QemuMutex QemuMutex;
typedef struct QemuCond QemuCond;
typedef struct QemuThread QemuThread;

struct QemuMutex {
    pthread_mutex_t lock;
};

struct QemuCond {
    pthread_cond_t cond;
};

struct QemuThread {
    pthread_t thread;
};

void qemu_mutex_init(QemuMutex *mutex);
void qemu_mutex_lock(QemuMutex *mutex);
int qemu_mutex_trylock(QemuMutex *mutex);
void qemu_mutex_unlock(QemuMutex *mutex);

void qemu_cond_init(QemuCond *cond);
void qemu_cond_signal(QemuCond *cond);
void qemu_cond_broadcast(QemuCond *cond);
void qemu_cond_wait(QemuCond *cond, QemuMutex *mutex);

void qemu_thread_create(QemuThread *thread,
                       void *(*start_routine)(void*),
                       void *arg);
void qemu_thread_get_self(QemuThread *thread);
int qemu_thread_is_self(QemuThread *thread);
void qemu_thread_exit(void *retval);

#endif
