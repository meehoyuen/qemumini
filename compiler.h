/* public domain */

#ifndef COMPILER_H
#define COMPILER_H

# define QEMU_GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#define QEMU_PACKED __attribute__((packed))

#if defined __GNUC__
/* Use gnu_printf when supported (qemu uses standard format strings). */
#define GCC_ATTR __attribute__((__unused__, format(gnu_printf, 1, 2)))
#define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
#else
#define GCC_ATTR /**/
#define GCC_FMT_ATTR(n, m)
#endif

#endif /* COMPILER_H */
