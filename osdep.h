#ifndef QEMU_OSDEP_H
#define QEMU_OSDEP_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/time.h>

#ifndef glue
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#endif

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

/* Convert from a base type to a parent type, with compile time checking.  */
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))

#define typeof_field(type, field) typeof(((type *)0)->field)
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define inline __attribute__ (( always_inline )) __inline__

void *qemu_memalign(size_t alignment, size_t size);
void *qemu_vmalloc(size_t size);
#endif
