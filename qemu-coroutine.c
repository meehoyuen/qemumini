#include "qemu-common.h"
#include "qemu-coroutine.h"
#include "qemu-coroutine-int.h"

Coroutine *qemu_coroutine_create(CoroutineEntry *entry)
{
    Coroutine *co = qemu_coroutine_new();
    co->entry = entry;
    return co;
}

static void coroutine_swap(Coroutine *from, Coroutine *to)
{
    CoroutineAction ret;

    ret = qemu_coroutine_switch(from, to, COROUTINE_YIELD);

    switch (ret) {
    case COROUTINE_YIELD:
        return;
    case COROUTINE_TERMINATE:
        qemu_coroutine_delete(to);
        return;
    default:
        abort();
    }
}

void qemu_coroutine_enter(Coroutine *co, void *opaque)
{
    Coroutine *self = qemu_coroutine_self();

    if (co->caller) {
        fprintf(stderr, "Co-routine re-entered recursively\n");
        abort();
    }

    co->caller = self;
    co->entry_arg = opaque;
    coroutine_swap(self, co);
}

void qemu_coroutine_yield(void)
{
    Coroutine *self = qemu_coroutine_self();
    Coroutine *to = self->caller;

    if (!to) {
        fprintf(stderr, "Co-routine is yielding to no one\n");
        abort();
    }

    self->caller = NULL;
    coroutine_swap(self, to);
}
