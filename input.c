/*
 * QEMU System Emulator
 */

#include "sysemu.h"
#include "console.h"

int graphic_width = 800;
int graphic_height = 600;
int graphic_depth = 15;

static QEMUPutKBDEvent *qemu_put_kbd_event;
static void *qemu_put_kbd_event_opaque;
static QTAILQ_HEAD(, QEMUPutLEDEntry) led_handlers = QTAILQ_HEAD_INITIALIZER(led_handlers);
static QTAILQ_HEAD(, QEMUPutMouseEntry) mouse_handlers =
    QTAILQ_HEAD_INITIALIZER(mouse_handlers);
static NotifierList mouse_mode_notifiers = 
    NOTIFIER_LIST_INITIALIZER(mouse_mode_notifiers);

void qemu_add_kbd_event_handler(QEMUPutKBDEvent *func, void *opaque)
{
    qemu_put_kbd_event_opaque = opaque;
    qemu_put_kbd_event = func;
}

void qemu_remove_kbd_event_handler(void)
{
    qemu_put_kbd_event_opaque = NULL;
    qemu_put_kbd_event = NULL;
}

static void check_mode_change(void)
{
    static int current_is_absolute, current_has_absolute;
    int is_absolute;
    int has_absolute;

    is_absolute = kbd_mouse_is_absolute();
    has_absolute = kbd_mouse_has_absolute();

    if (is_absolute != current_is_absolute ||
        has_absolute != current_has_absolute) {
        notifier_list_notify(&mouse_mode_notifiers, NULL);
    }

    current_is_absolute = is_absolute;
    current_has_absolute = has_absolute;
}

QEMUPutMouseEntry *qemu_add_mouse_event_handler(QEMUPutMouseEvent *func,
                                                void *opaque, int absolute,
                                                const char *name)
{
    QEMUPutMouseEntry *s;
    static int mouse_index = 0;

    s = calloc(1, sizeof(QEMUPutMouseEntry));

    s->qemu_put_mouse_event = func;
    s->qemu_put_mouse_event_opaque = opaque;
    s->qemu_put_mouse_event_absolute = absolute;
    s->qemu_put_mouse_event_name = strdup(name);
    s->index = mouse_index++;

    QTAILQ_INSERT_TAIL(&mouse_handlers, s, node);

    check_mode_change();

    return s;
}

void qemu_activate_mouse_event_handler(QEMUPutMouseEntry *entry)
{
    QTAILQ_REMOVE(&mouse_handlers, entry, node);
    QTAILQ_INSERT_HEAD(&mouse_handlers, entry, node);

    check_mode_change();
}

void qemu_remove_mouse_event_handler(QEMUPutMouseEntry *entry)
{
    QTAILQ_REMOVE(&mouse_handlers, entry, node);

    free(entry->qemu_put_mouse_event_name);
    entry->qemu_put_mouse_event_name = NULL;
    free(entry);
    entry = NULL;

    check_mode_change();
}

QEMUPutLEDEntry *qemu_add_led_event_handler(QEMUPutLEDEvent *func,
                                            void *opaque)
{
    QEMUPutLEDEntry *s;

    s = calloc(1, sizeof(QEMUPutLEDEntry));

    s->put_led = func;
    s->opaque = opaque;
    QTAILQ_INSERT_TAIL(&led_handlers, s, next);
    return s;
}

void qemu_remove_led_event_handler(QEMUPutLEDEntry *entry)
{
    if (entry == NULL)
        return;
    QTAILQ_REMOVE(&led_handlers, entry, next);
    free(entry);
    entry = NULL;
}

void kbd_put_keycode(int keycode)
{
    if (qemu_put_kbd_event) {
        qemu_put_kbd_event(qemu_put_kbd_event_opaque, keycode);
    }
}

void kbd_put_ledstate(int ledstate)
{
    QEMUPutLEDEntry *cursor;

    QTAILQ_FOREACH(cursor, &led_handlers, next) {
        cursor->put_led(cursor->opaque, ledstate);
    }
}

void kbd_mouse_event(int dx, int dy, int dz, int buttons_state)
{
    QEMUPutMouseEntry *entry;
    QEMUPutMouseEvent *mouse_event;
    void *mouse_event_opaque;

    if (QTAILQ_EMPTY(&mouse_handlers)) {
        return;
    }

    entry = QTAILQ_FIRST(&mouse_handlers);

    mouse_event = entry->qemu_put_mouse_event;
    mouse_event_opaque = entry->qemu_put_mouse_event_opaque;

    if (mouse_event) {
        mouse_event(mouse_event_opaque, dx, dy, dz, buttons_state);
    }
}

int kbd_mouse_is_absolute(void)
{
    if (QTAILQ_EMPTY(&mouse_handlers)) {
        return 0;
    }

    return QTAILQ_FIRST(&mouse_handlers)->qemu_put_mouse_event_absolute;
}

int kbd_mouse_has_absolute(void)
{
    QEMUPutMouseEntry *entry;

    QTAILQ_FOREACH(entry, &mouse_handlers, node) {
        if (entry->qemu_put_mouse_event_absolute) {
            return 1;
        }
    }

    return 0;
}

void qemu_add_mouse_mode_change_notifier(Notifier *notify)
{
    notifier_list_add(&mouse_mode_notifiers, notify);
}

void qemu_remove_mouse_mode_change_notifier(Notifier *notify)
{
    notifier_list_remove(&mouse_mode_notifiers, notify);
}
