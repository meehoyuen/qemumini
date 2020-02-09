#ifndef SYSEMU_H
#define SYSEMU_H
/* Misc. things related to the system emulator.  */

#include "qemu-common.h"
#include "qemu-queue.h"
#include "qemu-timer.h"
#include "notify.h"
#include "main-loop.h"

/* vl.c */
typedef enum RunState
{
    RUN_STATE_DEBUG = 0,
    RUN_STATE_INTERNAL_ERROR,
    RUN_STATE_IO_ERROR,
    RUN_STATE_PAUSED,
    RUN_STATE_PRELAUNCH,
    RUN_STATE_RUNNING,
    RUN_STATE_SHUTDOWN,
    RUN_STATE_WATCHDOG,
    RUN_STATE_MAX
} RunState;
extern const char *RunState_lookup[];

extern const char *bios_name;

extern uint8_t qemu_uuid[];
#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

void runstate_init(void);
bool runstate_check(RunState state);
void runstate_set(RunState new_state);
int runstate_is_running(void);
typedef struct vm_change_state_entry VMChangeStateEntry;
typedef void VMChangeStateHandler(void *opaque, int running, RunState state);

VMChangeStateEntry *qemu_add_vm_change_state_handler(VMChangeStateHandler *cb,
                                                     void *opaque);
void qemu_del_vm_change_state_handler(VMChangeStateEntry *e);
void vm_state_notify(int running, RunState state);

void vm_start(void);
void vm_stop(RunState state);
void vm_stop_force_state(RunState state);

void qemu_system_reset_request(void);
void qemu_system_shutdown_request(void);
void qemu_system_powerdown_request(void);
void qemu_system_debug_request(void);
void qemu_system_vmstop_request(RunState reason);
int qemu_shutdown_requested_get(void);
int qemu_reset_requested_get(void);
int qemu_shutdown_requested(void);
int qemu_reset_requested(void);
int qemu_powerdown_requested(void);
void qemu_system_killed(int signal, pid_t pid);
void qemu_kill_report(void);
extern qemu_irq qemu_system_powerdown;
void qemu_system_reset(void);

void qemu_add_exit_notifier(Notifier *notify);
void qemu_remove_exit_notifier(Notifier *notify);

void qemu_add_machine_init_done_notifier(Notifier *notify);

void qemu_announce_self(void);

typedef enum DisplayType
{
    DT_DEFAULT,
    DT_NOGRAPHIC,
    DT_NONE,
} DisplayType;

extern int bios_size;

extern int graphic_width;
extern int graphic_height;
extern int graphic_depth;
extern uint8_t irq0override;
extern DisplayType display_type;
extern const char *keyboard_layout;
extern int rtc_td_hack;
extern int smp_cpus;
extern int max_cpus;
extern int cursor_hide;
extern int graphic_rotate;
extern int no_shutdown;
extern int semihosting_enabled;
extern int old_param;
extern int boot_menu;
extern uint8_t qemu_extra_params_fw[2];
extern QEMUClock *rtc_clock;

#define MAX_NODES 64
extern int nb_numa_nodes;
extern uint64_t node_mem[MAX_NODES];
extern uint64_t node_cpumask[MAX_NODES];

#define MAX_OPTION_ROMS 16
typedef struct QEMUOptionRom {
    const char *name;
    int32_t bootindex;
} QEMUOptionRom;
extern QEMUOptionRom option_rom[MAX_OPTION_ROMS];

#define MAX_PROM_ENVS 128
extern const char *prom_envs[MAX_PROM_ENVS];
extern unsigned int nb_prom_envs;

void register_devices(void);

void add_boot_device_path(int32_t bootindex, DeviceState *dev,
                          const char *suffix);
char *get_boot_devices_list(uint32_t *size);
#endif
