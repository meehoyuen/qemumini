/*
 * QEMU IRQ/GPIO common code.
 */
#include "qemu-common.h"
#include "irq.h"

struct IRQState {
    qemu_irq_handler handler;
    void *opaque;
    int n;
};

void qemu_set_irq(qemu_irq irq, int level)
{
    if (!irq)
        return;

    irq->handler(irq->opaque, irq->n, level);
}

qemu_irq *qemu_allocate_irqs(qemu_irq_handler handler, void *opaque, int n)
{
    qemu_irq *s;
    struct IRQState *p;
    int i;

    s = (qemu_irq *)calloc(n, sizeof(qemu_irq));
    p = (struct IRQState *)calloc(n, sizeof(struct IRQState));
    for (i = 0; i < n; i++) {
        p->handler = handler;
        p->opaque = opaque;
        p->n = i;
        s[i] = p;
        p++;
    }
    return s;
}

void qemu_free_irqs(qemu_irq *s)
{
    free(s[0]);
    free(s);
    s = NULL;
}

static void qemu_notirq(void *opaque, int line, int level)
{
    struct IRQState *irq = opaque;

    irq->handler(irq->opaque, irq->n, !level);
}

qemu_irq qemu_irq_invert(qemu_irq irq)
{
    /* The default state for IRQs is low, so raise the output now.  */
    qemu_irq_raise(irq);
    return qemu_allocate_irqs(qemu_notirq, irq, 1)[0];
}

static void qemu_splitirq(void *opaque, int line, int level)
{
    struct IRQState **irq = opaque;
    irq[0]->handler(irq[0]->opaque, irq[0]->n, level);
    irq[1]->handler(irq[1]->opaque, irq[1]->n, level);
}

qemu_irq qemu_irq_split(qemu_irq irq1, qemu_irq irq2)
{
    qemu_irq *s = calloc(2, sizeof(qemu_irq));
    s[0] = irq1;
    s[1] = irq2;
    return qemu_allocate_irqs(qemu_splitirq, s, 1)[0];
}

static void proxy_irq_handler(void *opaque, int n, int level)
{
    qemu_irq **target = opaque;

    if (*target) {
        qemu_set_irq((*target)[n], level);
    }
}

qemu_irq *qemu_irq_proxy(qemu_irq **target, int n)
{
    return qemu_allocate_irqs(proxy_irq_handler, target, n);
}
