#ifndef QEMU_NOTIFY_H
#define QEMU_NOTIFY_H

#include "qemu-queue.h"

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QTAILQ_ENTRY(Notifier) node;
};

typedef struct NotifierList
{
    QTAILQ_HEAD(, Notifier) notifiers;
} NotifierList;

#define NOTIFIER_LIST_INITIALIZER(head) \
    { QTAILQ_HEAD_INITIALIZER((head).notifiers) }

void notifier_list_init(NotifierList *list);

void notifier_list_add(NotifierList *list, Notifier *notifier);

void notifier_list_remove(NotifierList *list, Notifier *notifier);

void notifier_list_notify(NotifierList *list, void *data);

#endif
