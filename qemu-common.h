/* Common header file that is included by all of qemu.  */
#ifndef QEMU_COMMON_H
#define QEMU_COMMON_H

#include "compiler.h"
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)

typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUFile QEMUFile;
typedef struct DeviceState DeviceState;

/* we put basic includes here to avoid repeating them in device drivers */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <assert.h>
#include <signal.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef ENOMEDIUM
#define ENOMEDIUM ENODEV
#endif
#if !defined(ENOTSUP)
#define ENOTSUP 4096
#endif
#ifndef TIME_MAX
#define TIME_MAX LONG_MAX
#endif

#include <sys/uio.h>
typedef int (*fprintf_function)(FILE *f, const char *fmt, ...)
    GCC_FMT_ATTR(2, 3);

/* icount */
extern int use_icount;
#include "cpu.h"
void qemu_get_timedate(struct tm *tm, int offset);
int qemu_timedate_diff(struct tm *tm);

/* cutils.c */
void pstrcpy(char *buf, int buf_size, const char *str);
char *pstrcat(char *buf, int buf_size, const char *s);
int strstart(const char *str, const char *val, const char **ptr);
int stristart(const char *str, const char *val, const char **ptr);
int qemu_strnlen(const char *s, int max_len);
time_t mktimegm(struct tm *tm);
int qemu_fls(int i);
int qemu_fdatasync(int fd);
int fcntl_setfl(int fd, int flag);

/*
 * strtosz() suffixes used to specify the default treatment of an
 * argument passed to strtosz() without an explicit suffix.
 * These should be defined using upper case characters in the range
 * A-Z, as strtosz() will use qemu_toupper() on the given argument
 * prior to comparison.
 */
#define STRTOSZ_DEFSUFFIX_TB	'T'
#define STRTOSZ_DEFSUFFIX_GB	'G'
#define STRTOSZ_DEFSUFFIX_MB	'M'
#define STRTOSZ_DEFSUFFIX_KB	'K'
#define STRTOSZ_DEFSUFFIX_B	'B'
int64_t strtosz(const char *nptr, char **end);
int64_t strtosz_suffix(const char *nptr, char **end, const char default_suffix);
int64_t strtosz_suffix_unit(const char *nptr, char **end,
                            const char default_suffix, int64_t unit);

/* path.c */
void init_paths(const char *prefix);
const char *path(const char *pathname);

#define qemu_isalnum(c)		isalnum((unsigned char)(c))
#define qemu_isalpha(c)		isalpha((unsigned char)(c))
#define qemu_iscntrl(c)		iscntrl((unsigned char)(c))
#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isgraph(c)		isgraph((unsigned char)(c))
#define qemu_islower(c)		islower((unsigned char)(c))
#define qemu_isprint(c)		isprint((unsigned char)(c))
#define qemu_ispunct(c)		ispunct((unsigned char)(c))
#define qemu_isspace(c)		isspace((unsigned char)(c))
#define qemu_isupper(c)		isupper((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))
#define qemu_tolower(c)		tolower((unsigned char)(c))
#define qemu_toupper(c)		toupper((unsigned char)(c))
#define qemu_isascii(c)		isascii((unsigned char)(c))
#define qemu_toascii(c)		toascii((unsigned char)(c))

void qemu_set_cloexec(int fd);
int qemu_eventfd(int pipefd[2]);
int qemu_pipe(int pipefd[2]);

/* Error handling.  */
void hw_error(const char *fmt, ...) GCC_FMT_ATTR(1, 2);

typedef int (*DMA_transfer_handler) (void *opaque, int nchan, int pos, int size);

/* A load of opaque types so that device init declarations don't have to
   pull in all the real definitions.  */
typedef struct BlockDriverState BlockDriverState;
typedef struct DriveInfo DriveInfo;
typedef struct DisplayState DisplayState;
typedef struct DisplayChangeListener DisplayChangeListener;
typedef struct DisplaySurface DisplaySurface;
typedef struct DisplayAllocator DisplayAllocator;
typedef struct PixelFormat PixelFormat;
typedef struct TextConsole TextConsole;
typedef struct CharDriverState CharDriverState;
typedef struct i2c_bus i2c_bus;
typedef struct i2c_slave i2c_slave;
typedef struct SMBusDevice SMBusDevice;
typedef struct PCIHostState PCIHostState;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct PCIExpressDevice PCIExpressDevice;
typedef struct IRQState *qemu_irq;
typedef struct I2SCodec I2SCodec;
typedef struct EventNotifier EventNotifier;

typedef uint64_t pcibus_t;

void cpu_exec_init_all(void);

/* Unblock cpu */
void qemu_cpu_kick(void *env);
void qemu_cpu_kick_self(void);
int qemu_cpu_is_self(void *env);
bool all_cpu_threads_idle(void);

/* work queue */
struct qemu_work_item {
    struct qemu_work_item *next;
    void (*func)(void *data);
    void *data;
    int done;
};

void qemu_init_vcpu(void *env);

typedef struct QEMUIOVector {
    struct iovec *iov;
    int niov;
    int nalloc;
    size_t size;
} QEMUIOVector;

void qemu_iovec_init(QEMUIOVector *qiov, int alloc_hint);
void qemu_iovec_init_external(QEMUIOVector *qiov, struct iovec *iov, int niov);
void qemu_iovec_add(QEMUIOVector *qiov, void *base, size_t len);
void qemu_iovec_copy(QEMUIOVector *dst, QEMUIOVector *src, uint64_t skip,
    size_t size);
void qemu_iovec_concat(QEMUIOVector *dst, QEMUIOVector *src, size_t size);
void qemu_iovec_destroy(QEMUIOVector *qiov);
void qemu_iovec_reset(QEMUIOVector *qiov);
void qemu_iovec_to_buffer(QEMUIOVector *qiov, void *buf);
void qemu_iovec_from_buffer(QEMUIOVector *qiov, const void *buf, size_t count);
void qemu_iovec_memset(QEMUIOVector *qiov, int c, size_t count);
void qemu_iovec_memset_skip(QEMUIOVector *qiov, int c, size_t count,
                            size_t skip);
#define QEMU_FILE_TYPE_BIOS   0
#define QEMU_FILE_TYPE_KEYMAP 1
char *qemu_find_file(int type, const char *name);

/* compute with 96 bit intermediate result: (a*b)/c */
static inline uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    union {
        uint64_t ll;
        struct {
            uint32_t low, high;
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
}

#include "module.h"

#endif
