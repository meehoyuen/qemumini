#ifndef QEMU_TIMER_H
#define QEMU_TIMER_H

#include "qemu-common.h"
#include "main-loop.h"
#include "notify.h"
#include <time.h>
#include <sys/time.h>

/* timers */
#define SCALE_MS 1000000
#define SCALE_US 1000
#define SCALE_NS 1

typedef struct QEMUClock QEMUClock;
typedef void QEMUTimerCB(void *opaque);

/* The real time clock should be used only for stuff which does not
   change the virtual machine state, as it is run even if the virtual
   machine is stopped. The real time clock has a frequency of 1000
   Hz. */
extern QEMUClock *rt_clock;

/* The virtual clock is only run during the emulation. It is stopped
   when the virtual machine is stopped. Virtual timers use a high
   precision clock, usually cpu cycles (use ticks_per_sec). */
extern QEMUClock *vm_clock;

/* The host clock should be use for device models that emulate accurate
   real time sources. It will continue to run when the virtual machine
   is suspended, and it will reflect system time changes the host may
   undergo (e.g. due to NTP). The host clock has the same precision as
   the virtual clock. */
extern QEMUClock *host_clock;

int64_t qemu_get_clock_ns(QEMUClock *clock);
int64_t qemu_clock_has_timers(QEMUClock *clock);
int64_t qemu_clock_expired(QEMUClock *clock);
int64_t qemu_clock_deadline(QEMUClock *clock);
void qemu_clock_enable(QEMUClock *clock, int enabled);
void qemu_clock_warp(QEMUClock *clock);

void qemu_register_clock_reset_notifier(QEMUClock *clock, Notifier *notifier);
void qemu_unregister_clock_reset_notifier(QEMUClock *clock,
                                          Notifier *notifier);

QEMUTimer *qemu_new_timer(QEMUClock *clock, int scale,
                          QEMUTimerCB *cb, void *opaque);
void qemu_free_timer(QEMUTimer *ts);
void qemu_del_timer(QEMUTimer *ts);
void qemu_mod_timer_ns(QEMUTimer *ts, int64_t expire_time);
void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time);
int qemu_timer_pending(QEMUTimer *ts);
int qemu_timer_expired(QEMUTimer *timer_head, int64_t current_time);
uint64_t qemu_timer_expire_time_ns(QEMUTimer *ts);

void qemu_run_all_timers(void);
int qemu_alarm_pending(void);
void configure_alarms(char const *opt);
int qemu_calculate_timeout(void);
void init_clocks(void);
int init_timer_alarm(void);

int64_t cpu_get_ticks(void);
void cpu_enable_ticks(void);
void cpu_disable_ticks(void);

static inline QEMUTimer *qemu_new_timer_ns(QEMUClock *clock, QEMUTimerCB *cb,
                                           void *opaque)
{
    return qemu_new_timer(clock, SCALE_NS, cb, opaque);
}

static inline QEMUTimer *qemu_new_timer_ms(QEMUClock *clock, QEMUTimerCB *cb,
                                           void *opaque)
{
    return qemu_new_timer(clock, SCALE_MS, cb, opaque);
}

static inline int64_t qemu_get_clock_ms(QEMUClock *clock)
{
    return qemu_get_clock_ns(clock) / SCALE_MS;
}

static inline int64_t get_ticks_per_sec(void)
{
    return 1000000000LL;
}

static inline int64_t get_clock(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

void qemu_get_timer(QEMUFile *f, QEMUTimer *ts);
void qemu_put_timer(QEMUFile *f, QEMUTimer *ts);

/* ptimer.c */
typedef struct ptimer_state ptimer_state;
typedef void (*ptimer_cb)(void *opaque);

ptimer_state *ptimer_init(QEMUBH *bh);
void ptimer_set_period(ptimer_state *s, int64_t period);
void ptimer_set_freq(ptimer_state *s, uint32_t freq);
void ptimer_set_limit(ptimer_state *s, uint64_t limit, int reload);
uint64_t ptimer_get_count(ptimer_state *s);
void ptimer_set_count(ptimer_state *s, uint64_t count);
void ptimer_run(ptimer_state *s, int oneshot);
void ptimer_stop(ptimer_state *s);
int64_t cpu_get_clock(void);

static inline int64_t cpu_get_real_ticks(void)
{
    uint32_t low,high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}
#endif
