#include "sysemu.h"
#include "dma.h"
#include "kvm.h"

#include "qemu-thread.h"
#include "cpus.h"
#include "main-loop.h"

#include "compatfd.h"

#include <sys/prctl.h>

#ifndef PR_MCE_KILL
#define PR_MCE_KILL 33
#endif

#ifndef PR_MCE_KILL_SET
#define PR_MCE_KILL_SET 1
#endif

#ifndef PR_MCE_KILL_EARLY
#define PR_MCE_KILL_EARLY 1
#endif

/***********************************************************/
/* guest cycle counter */

/* Conversion factor from emulated instructions to virtual clock ticks.  */
/* Arbitrarily pick 1MIPS as the minimum allowable speed.  */
#define MAX_ICOUNT_SHIFT 10

typedef struct TimersState {
    int64_t cpu_ticks_prev;
    int64_t cpu_ticks_offset;
    int64_t cpu_clock_offset;
    int32_t cpu_ticks_enabled;
    int64_t dummy;
} TimersState;

TimersState timers_state;

void cpu_dump_state(CPUState *env, FILE *f, fprintf_function cpu_fprintf, int flags);

/* return the host CPU cycle counter and handle stop/restart */
int64_t cpu_get_ticks(void)
{
    if (!timers_state.cpu_ticks_enabled) {
        return timers_state.cpu_ticks_offset;
    } else {
        int64_t ticks;
        ticks = cpu_get_real_ticks();
        if (timers_state.cpu_ticks_prev > ticks) {
            /* Note: non increasing ticks may happen if the host uses
               software suspend */
            timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        }
        timers_state.cpu_ticks_prev = ticks;
        return ticks + timers_state.cpu_ticks_offset;
    }
}

/* return the host CPU monotonic timer and handle stop/restart */
int64_t cpu_get_clock(void)
{
    int64_t ti;
    if (!timers_state.cpu_ticks_enabled) {
        return timers_state.cpu_clock_offset;
    } else {
        ti = get_clock();
        return ti + timers_state.cpu_clock_offset;
    }
}

/* enable cpu_get_ticks() */
void cpu_enable_ticks(void)
{
    if (!timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset -= cpu_get_real_ticks();
        timers_state.cpu_clock_offset -= get_clock();
        timers_state.cpu_ticks_enabled = 1;
    }
}

/* disable cpu_get_ticks() : the clock is stopped. You must not call
   cpu_get_ticks() after that.  */
void cpu_disable_ticks(void)
{
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset = cpu_get_ticks();
        timers_state.cpu_clock_offset = cpu_get_clock();
        timers_state.cpu_ticks_enabled = 0;
    }
}
/***********************************************************/
void hw_error(const char *fmt, ...)
{
    va_list ap;
    CPUState *env;

    va_start(ap, fmt);
    fprintf(stderr, "qemu: hardware error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        fprintf(stderr, "CPU #%d:\n", env->cpu_index);
        cpu_dump_state(env, stdout, fprintf, 0);
    }
    va_end(ap);
    abort();
}

void cpu_synchronize_all_states(void)
{
    CPUState *cpu;

    for (cpu = first_cpu; cpu; cpu = cpu->next_cpu) {
        cpu_synchronize_state(cpu);
    }
}

void cpu_synchronize_all_post_reset(void)
{
    CPUState *cpu;

    for (cpu = first_cpu; cpu; cpu = cpu->next_cpu) {
        cpu_synchronize_post_reset(cpu);
    }
}

void cpu_synchronize_all_post_init(void)
{
    CPUState *cpu;

    for (cpu = first_cpu; cpu; cpu = cpu->next_cpu) {
        cpu_synchronize_post_init(cpu);
    }
}

int cpu_is_stopped(CPUState *env)
{
    return !runstate_is_running() || env->stopped;
}

static void do_vm_stop(RunState state)
{
    if (runstate_is_running()) {
        cpu_disable_ticks();
        pause_all_vcpus();
        runstate_set(state);
        //vm_state_notify(0, state);
        qemu_aio_flush();
        bdrv_flush_all();
    }
}

static int cpu_can_run(CPUState *env)
{
    if (env->stop) {
        return 0;
    }
    if (env->stopped || !runstate_is_running()) {
        return 0;
    }
    return 1;
}

static bool cpu_thread_is_idle(CPUState *env)
{
    if (env->stop || env->queued_work_first) {
        return false;
    }
    if (env->stopped || !runstate_is_running()) {
        return true;
    }
    if (!env->halted || cpu_has_work(env) || kvm_irqchip_in_kernel()) {
        return false;
    }
    return true;
}

bool all_cpu_threads_idle(void)
{
    CPUState *env;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (!cpu_thread_is_idle(env)) {
            return false;
        }
    }
    return true;
}

static void sigbus_reraise(void)
{
    sigset_t set;
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (!sigaction(SIGBUS, &action, NULL)) {
        raise(SIGBUS);
        sigemptyset(&set);
        sigaddset(&set, SIGBUS);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
    }
    perror("Failed to re-raise SIGBUS!\n");
    abort();
}

static void sigbus_handler(int n, struct qemu_signalfd_siginfo *siginfo,
                           void *ctx)
{
    if (kvm_on_sigbus(siginfo->ssi_code,
                      (void *)(intptr_t)siginfo->ssi_addr)) {
        sigbus_reraise();
    }
}

static void qemu_init_sigbus(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = (void (*)(int, siginfo_t*, void*))sigbus_handler;
    sigaction(SIGBUS, &action, NULL);

    prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0);
}

static void qemu_kvm_eat_signals(CPUState *env)
{
    struct timespec ts = { 0, 0 };
    siginfo_t siginfo;
    sigset_t waitset;
    sigset_t chkset;
    int r;

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);
    sigaddset(&waitset, SIGBUS);

    do {
        r = sigtimedwait(&waitset, &siginfo, &ts);
        if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
            perror("sigtimedwait");
            exit(1);
        }

        switch (r) {
        case SIGBUS:
            if (kvm_on_sigbus_vcpu(env, siginfo.si_code, siginfo.si_addr)) {
                sigbus_reraise();
            }
            break;
        default:
            break;
        }

        r = sigpending(&chkset);
        if (r == -1) {
            perror("sigpending");
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI) || sigismember(&chkset, SIGBUS));
}

static void dummy_signal(int sig)
{
}

static void qemu_kvm_init_cpu_signals(CPUState *env)
{
    int r;
    sigset_t set;
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = dummy_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    sigdelset(&set, SIGBUS);
    r = kvm_set_signal_mask(env, &set);
    if (r) {
        fprintf(stderr, "kvm_set_signal_mask: %s\n", strerror(-r));
        exit(1);
    }

    sigdelset(&set, SIG_IPI);
    sigdelset(&set, SIGBUS);
    r = kvm_set_signal_mask(env, &set);
    if (r) {
        fprintf(stderr, "kvm_set_signal_mask: %s\n", strerror(-r));
        exit(1);
    }
}

QemuMutex qemu_global_mutex;
static QemuThread io_thread;
/* cpu creation */
static QemuCond qemu_cpu_cond;
/* system init */
static QemuCond qemu_pause_cond;
static QemuCond qemu_work_cond;

void qemu_init_cpu_loop(void)
{
    qemu_init_sigbus();
    qemu_cond_init(&qemu_cpu_cond);
    qemu_cond_init(&qemu_pause_cond);
    qemu_cond_init(&qemu_work_cond);
    qemu_mutex_init(&qemu_global_mutex);

    qemu_thread_get_self(&io_thread);
}

void run_on_cpu(CPUState *env, void (*func)(void *data), void *data)
{
    struct qemu_work_item wi;

    if (qemu_cpu_is_self(env)) {
        func(data);
        return;
    }

    wi.func = func;
    wi.data = data;
    if (!env->queued_work_first) {
        env->queued_work_first = &wi;
    } else {
        env->queued_work_last->next = &wi;
    }
    env->queued_work_last = &wi;
    wi.next = NULL;
    wi.done = false;

    qemu_cpu_kick(env);
    while (!wi.done) {
        CPUState *self_env = cpu_single_env;

        qemu_cond_wait(&qemu_work_cond, &qemu_global_mutex);
        cpu_single_env = self_env;
    }
}

static void flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->queued_work_first) {
        return;
    }

    while ((wi = env->queued_work_first)) {
        env->queued_work_first = wi->next;
        wi->func(wi->data);
        wi->done = true;
    }
    env->queued_work_last = NULL;
    qemu_cond_broadcast(&qemu_work_cond);
}

static void qemu_wait_io_event_common(CPUState *env)
{
    if (env->stop) {
        env->stop = 0;
        env->stopped = 1;
        qemu_cond_signal(&qemu_pause_cond);
    }
    flush_queued_work(env);
    env->thread_kicked = false;
}

static void qemu_kvm_wait_io_event(CPUState *env)
{
    while (cpu_thread_is_idle(env)) {
        qemu_cond_wait(env->halt_cond, &qemu_global_mutex);
    }

    qemu_kvm_eat_signals(env);
    qemu_wait_io_event_common(env);
}

static void *qemu_kvm_cpu_thread_fn(void *arg)
{
    CPUState *env = arg;
    char pr_name[16];
    int r;

    qemu_mutex_lock(&qemu_global_mutex);
    qemu_thread_get_self(env->thread);
    env->thread_id = getpid();

    r = kvm_init_vcpu(env);
    if (r < 0) {
        fprintf(stderr, "kvm_init_vcpu failed: %s\n", strerror(-r));
        exit(1);
    }
    snprintf(pr_name, sizeof(pr_name), "vcpu-%d", env->cpu_index);
    if(prctl(PR_SET_NAME, pr_name))
        perror("unable to change process name");

    qemu_kvm_init_cpu_signals(env);

    /* signal CPU creation */
    env->created = 1;
    qemu_cond_signal(&qemu_cpu_cond);

    while (1) {
        if (cpu_can_run(env)) {
            kvm_cpu_exec(env);
        }
        qemu_kvm_wait_io_event(env);
    }

    return NULL;
}

static void qemu_cpu_kick_thread(CPUState *env)
{
    int err;

    err = pthread_kill(env->thread->thread, SIG_IPI);
    if (err) {
        fprintf(stderr, "qemu:%s: %s", __func__, strerror(err));
        exit(1);
    }
}

void qemu_cpu_kick(void *_env)
{
    CPUState *env = _env;

    qemu_cond_broadcast(env->halt_cond);
    if (!env->thread_kicked) {
        qemu_cpu_kick_thread(env);
        env->thread_kicked = true;
    }
}

void qemu_cpu_kick_self(void)
{
    assert(cpu_single_env);

    if (!cpu_single_env->thread_kicked) {
        qemu_cpu_kick_thread(cpu_single_env);
        cpu_single_env->thread_kicked = true;
    }
}

int qemu_cpu_is_self(void *_env)
{
    CPUState *env = _env;

    return qemu_thread_is_self(env->thread);
}

void qemu_mutex_lock_iothread(void)
{
    qemu_mutex_lock(&qemu_global_mutex);
}

void qemu_mutex_unlock_iothread(void)
{
    qemu_mutex_unlock(&qemu_global_mutex);
}

static int all_vcpus_paused(void)
{
    CPUState *penv = first_cpu;

    while (penv) {
        if (!penv->stopped) {
            return 0;
        }
        penv = (CPUState *)penv->next_cpu;
    }

    return 1;
}

void pause_all_vcpus(void)
{
    CPUState *penv = first_cpu;

    qemu_clock_enable(vm_clock, false);
    while (penv) {
        penv->stop = 1;
        qemu_cpu_kick(penv);
        penv = (CPUState *)penv->next_cpu;
    }

    while (!all_vcpus_paused()) {
        qemu_cond_wait(&qemu_pause_cond, &qemu_global_mutex);
        penv = first_cpu;
        while (penv) {
            qemu_cpu_kick(penv);
            penv = (CPUState *)penv->next_cpu;
        }
    }
}

void resume_all_vcpus(void)
{
    CPUState *penv = first_cpu;

    qemu_clock_enable(vm_clock, true);
    while (penv) {
        penv->stop = 0;
        penv->stopped = 0;
        qemu_cpu_kick(penv);
        penv = (CPUState *)penv->next_cpu;
    }
}

static void qemu_kvm_start_vcpu(CPUState *env)
{
    env->thread = calloc(1, sizeof(QemuThread));
    env->halt_cond = calloc(1, sizeof(QemuCond));
    qemu_cond_init(env->halt_cond);
    qemu_thread_create(env->thread, qemu_kvm_cpu_thread_fn, env);
    while (env->created == 0) {
        qemu_cond_wait(&qemu_cpu_cond, &qemu_global_mutex);
    }
}

void qemu_init_vcpu(void *_env)
{
    CPUState *env = _env;

    env->nr_cores = smp_cores;
    env->nr_threads = smp_threads;
    env->stopped = 1;
    qemu_kvm_start_vcpu(env);
}

void cpu_stop_current(void)
{
    if (cpu_single_env) {
        cpu_single_env->stop = 0;
        cpu_single_env->stopped = 1;
        cpu_exit(cpu_single_env);
        qemu_cond_signal(&qemu_pause_cond);
    }
}

void vm_stop(RunState state)
{
    if (!qemu_thread_is_self(&io_thread)) {
        //qemu_system_vmstop_request(state);
        /*
         * FIXME: should not return to device code in case
         * vm_stop() has been requested.
         */
        cpu_stop_current();
        return;
    }
    do_vm_stop(state);
}

/* does a state transition even if the VM is already stopped,
   current state is forgotten forever */
void vm_stop_force_state(RunState state)
{
    if (runstate_is_running()) {
        vm_stop(state);
    } else {
        runstate_set(state);
    }
}

void set_numa_modes(void)
{
    CPUState *env;
    int i;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        for (i = 0; i < nb_numa_nodes; i++) {
            if (node_cpumask[i] & (1 << env->cpu_index)) {
                env->numa_node = i;
            }
        }
    }
}

