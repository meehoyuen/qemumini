#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "sysemu.h"
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/utsname.h>
#ifndef BIT
#define BIT(nr) (1<<(nr))
#endif
#include "kvm.h"
#include "cpu.h"
#include "cpus.h"
#include "apic.h"
#include "ioport.h"
#include "qemu-timer.h"
#include "main-loop.h"
#include "bswap.h"
#include "qemu-option.h"
#include "hw.h"
#include "usb.h"
#include "pc.h"
#include "net.h"
#include "smbios.h"
#include "qdev.h"
#include "loader.h"
#include "apic.h"
#include "pci.h"
#include "ide.h"
#include "sysbus.h"
#include "smbus.h"
#include "memory.h"
#include "exec-memory.h"
#include "block.h"
#include "blockdev.h"
#include "console.h"

#include "compatfd.h"

#define MAX_IDE_BUS 2
#define HOST_LONG_BITS 64

NICInfo nd_table[1];
static int io_thread_fd = -1;
static const char *data_dir;
const char *bios_name = NULL;
DisplayType display_type = DT_DEFAULT;
ram_addr_t ram_size;
static int rtc_date_offset = -1; /* -1 means no change */
QEMUClock *rtc_clock;
int smp_cpus = 2;
int max_cpus = 2;
int smp_cores = 1;
int smp_threads = 1;
int fd_bootchk = 1;
int no_shutdown = 0;
int cursor_hide = 1;
uint8_t irq0override = 1;
QEMUOptionRom option_rom[MAX_OPTION_ROMS];
int old_param = 0;
unsigned int nb_prom_envs = 0;
const char *prom_envs[MAX_PROM_ENVS];
uint8_t qemu_extra_params_fw[2];

#include "hw.h"
#include "pc.h"
#include "apic.h"
#include "fdc.h"
#include "ide.h"
#include "pci.h"
#include "fw_cfg.h"
#include "hpet.h"
#include "smbios.h"
#include "loader.h"
#include "mc146818rtc.h"
#include "sysbus.h"
#include "sysemu.h"
#include "blockdev.h"
#include "memory.h"
#include "exec-memory.h"

/* output Bochs bios info messages */
#define DEBUG_BIOS

/* debug PC/ISA interrupts */
//#define DEBUG_IRQ

#ifdef DEBUG_IRQ
#define IRQDPRINTF(fmt, ...)                                       \
    do { printf("CPUIRQ: " fmt , ## __VA_ARGS__); } while (0)
#else
#define IRQDPRINTF(fmt, ...)
#endif

#define BIOS_FILENAME "bios.bin"

#define PC_MAX_BIOS_SIZE (4 * 1024 * 1024)

/* Leave a chunk of memory at the top of RAM for the BIOS ACPI tables.  */
#define ACPI_DATA_SIZE       0x10000
#define BIOS_CFG_IOPORT 0x510
#define FW_CFG_ACPI_TABLES (FW_CFG_ARCH_LOCAL + 0)
#define FW_CFG_SMBIOS_ENTRIES (FW_CFG_ARCH_LOCAL + 1)
#define FW_CFG_IRQ0_OVERRIDE (FW_CFG_ARCH_LOCAL + 2)
#define FW_CFG_E820_TABLE (FW_CFG_ARCH_LOCAL + 3)
#define FW_CFG_HPET (FW_CFG_ARCH_LOCAL + 4)

#define MSI_ADDR_BASE 0xfee00000

#define E820_NR_ENTRIES     16

struct e820_entry {
    uint64_t address;
    uint64_t length;
    uint32_t type;
} QEMU_PACKED __attribute((__aligned__(4)));

struct e820_table {
    uint32_t count;
    struct e820_entry entry[E820_NR_ENTRIES];
} QEMU_PACKED __attribute((__aligned__(4)));

static struct e820_table e820_table;
struct hpet_fw_config hpet_cfg = {.count = UINT8_MAX};

void gsi_handler(void *opaque, int n, int level)
{
    GSIState *s = opaque;

    IRQDPRINTF("pc: %s GSI %d\n", level ? "raising" : "lowering", n);
    if (n < ISA_NUM_IRQS) {
        qemu_set_irq(s->i8259_irq[n], level);
    }
    qemu_set_irq(s->ioapic_irq[n], level);
}

static void ioport80_write(void *opaque, uint32_t addr, uint32_t data)
{
}

/* MSDOS compatibility mode FPU exception support */
static qemu_irq ferr_irq;

void pc_register_ferr_irq(qemu_irq irq)
{
    ferr_irq = irq;
}

/* XXX: add IGNNE support */
void cpu_set_ferr(CPUX86State *s)
{
    qemu_irq_raise(ferr_irq);
}

static void ioportF0_write(void *opaque, uint32_t addr, uint32_t data)
{
    qemu_irq_lower(ferr_irq);
}

/* TSC handling */
uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_ticks();
}

/* SMM support */

static cpu_set_smm_t smm_set;
static void *smm_arg;

void cpu_smm_register(cpu_set_smm_t callback, void *arg)
{
    assert(smm_set == NULL);
    assert(smm_arg == NULL);
    smm_set = callback;
    smm_arg = arg;
}

void cpu_smm_update(CPUState *env)
{
    if (smm_set && smm_arg && env == first_cpu)
        smm_set(!!(env->hflags & HF_SMM_MASK), smm_arg);
}


/* IRQ handling */
int cpu_get_pic_interrupt(CPUState *env)
{
    int intno;

    intno = apic_get_interrupt(env->apic_state);
    if (intno >= 0) {
        return intno;
    }
    /* read the irq from the PIC */
    if (!apic_accept_pic_intr(env->apic_state)) {
        return -1;
    }

    intno = pic_read_irq(isa_pic);
    return intno;
}

static void pic_irq_request(void *opaque, int irq, int level)
{
    CPUState *env = first_cpu;

    IRQDPRINTF("pic_irqs: %s irq %d\n", level? "raise" : "lower", irq);
    if (env->apic_state) {
        while (env) {
            if (apic_accept_pic_intr(env->apic_state)) {
                apic_deliver_pic_intr(env->apic_state, level);
            }
            env = env->next_cpu;
        }
    } else {
        if (level)
            cpu_interrupt(env, CPU_INTERRUPT_HARD);
        else
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
    }
}

/* PC cmos mappings */

#define REG_EQUIPMENT_BYTE          0x14

static int cmos_get_fd_drive_type(FDriveType fd0)
{
    int val;

    switch (fd0) {
    case FDRIVE_DRV_144:
        /* 1.44 Mb 3"5 drive */
        val = 4;
        break;
    case FDRIVE_DRV_288:
        /* 2.88 Mb 3"5 drive */
        val = 5;
        break;
    case FDRIVE_DRV_120:
        /* 1.2 Mb 5"5 drive */
        val = 2;
        break;
    case FDRIVE_DRV_NONE:
    default:
        val = 0;
        break;
    }
    return val;
}

static void cmos_init_hd(int type_ofs, int info_ofs, BlockDriverState *hd,
                         ISADevice *s)
{
    int cylinders, heads, sectors;
    bdrv_get_geometry_hint(hd, &cylinders, &heads, &sectors);
    rtc_set_memory(s, type_ofs, 47);
    rtc_set_memory(s, info_ofs, cylinders);
    rtc_set_memory(s, info_ofs + 1, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 2, heads);
    rtc_set_memory(s, info_ofs + 3, 0xff);
    rtc_set_memory(s, info_ofs + 4, 0xff);
    rtc_set_memory(s, info_ofs + 5, 0xc0 | ((heads > 8) << 3));
    rtc_set_memory(s, info_ofs + 6, cylinders);
    rtc_set_memory(s, info_ofs + 7, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 8, sectors);
}

/* convert boot_device letter to something recognizable by the bios */
static int boot_device2nibble(char boot_device)
{
    switch(boot_device) {
    case 'a':
    case 'b':
        return 0x01; /* floppy boot */
    case 'c':
        return 0x02; /* hard drive boot */
    case 'd':
        return 0x03; /* CD-ROM boot */
    case 'n':
        return 0x04; /* Network boot */
    }
    return 0;
}

static int set_boot_dev(ISADevice *s, const char *boot_device, int fd_bootchk)
{
#define PC_MAX_BOOT_DEVICES 3
    int nbds, bds[3] = { 0, };
    int i;

    nbds = strlen(boot_device);
    if (nbds > PC_MAX_BOOT_DEVICES) {
        printf("Too many boot devices for PC");
        return(1);
    }
    for (i = 0; i < nbds; i++) {
        bds[i] = boot_device2nibble(boot_device[i]);
        if (bds[i] == 0) {
            printf("Invalid boot device for PC: '%c'",
                         boot_device[i]);
            return(1);
        }
    }
    rtc_set_memory(s, 0x3d, (bds[1] << 4) | bds[0]);
    rtc_set_memory(s, 0x38, (bds[2] << 4) | (fd_bootchk ? 0x0 : 0x1));
    return(0);
}

static int pc_boot_set(void *opaque, const char *boot_device)
{
    return set_boot_dev(opaque, boot_device, 0);
}

typedef struct pc_cmos_init_late_arg {
    ISADevice *rtc_state;
    BusState *idebus0, *idebus1;
} pc_cmos_init_late_arg;

static void pc_cmos_init_late(void *opaque)
{
    pc_cmos_init_late_arg *arg = opaque;
    ISADevice *s = arg->rtc_state;
    int val;
    BlockDriverState *hd_table[4];
    int i;

    ide_get_bs(hd_table, arg->idebus0);
    ide_get_bs(hd_table + 2, arg->idebus1);

    rtc_set_memory(s, 0x12, (hd_table[0] ? 0xf0 : 0) | (hd_table[1] ? 0x0f : 0));
    if (hd_table[0])
        cmos_init_hd(0x19, 0x1b, hd_table[0], s);
    if (hd_table[1])
        cmos_init_hd(0x1a, 0x24, hd_table[1], s);

    val = 0;
    for (i = 0; i < 4; i++) {
        if (hd_table[i]) {
            int cylinders, heads, sectors, translation;
            /* NOTE: bdrv_get_geometry_hint() returns the physical
                geometry.  It is always such that: 1 <= sects <= 63, 1
                <= heads <= 16, 1 <= cylinders <= 16383. The BIOS
                geometry can be different if a translation is done. */
            translation = bdrv_get_translation_hint(hd_table[i]);
            if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                bdrv_get_geometry_hint(hd_table[i], &cylinders, &heads, &sectors);
                if (cylinders <= 1024 && heads <= 16 && sectors <= 63) {
                    /* No translation. */
                    translation = 0;
                } else {
                    /* LBA translation. */
                    translation = 1;
                }
            } else {
                translation--;
            }
            val |= translation << (i * 2);
        }
    }
    rtc_set_memory(s, 0x39, val);

    qemu_unregister_reset(pc_cmos_init_late, opaque);
}

void pc_cmos_init(ram_addr_t ram_size, ram_addr_t above_4g_mem_size,
                  const char *boot_device,
                  ISADevice *floppy, BusState *idebus0, BusState *idebus1,
                  ISADevice *s)
{
    int val, nb, nb_heads, max_track, last_sect, i;
    FDriveType fd_type[2];
    BlockDriverState *fd[MAX_FD];
    static pc_cmos_init_late_arg arg;

    /* various important CMOS locations needed by PC/Bochs bios */

    /* memory size */
    val = 640; /* base memory in K */
    rtc_set_memory(s, 0x15, val);
    rtc_set_memory(s, 0x16, val >> 8);

    val = (ram_size / 1024) - 1024;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x17, val);
    rtc_set_memory(s, 0x18, val >> 8);
    rtc_set_memory(s, 0x30, val);
    rtc_set_memory(s, 0x31, val >> 8);

    if (above_4g_mem_size) {
        rtc_set_memory(s, 0x5b, (unsigned int)above_4g_mem_size >> 16);
        rtc_set_memory(s, 0x5c, (unsigned int)above_4g_mem_size >> 24);
        rtc_set_memory(s, 0x5d, (uint64_t)above_4g_mem_size >> 32);
    }

    if (ram_size > (16 * 1024 * 1024))
        val = (ram_size / 65536) - ((16 * 1024 * 1024) / 65536);
    else
        val = 0;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x34, val);
    rtc_set_memory(s, 0x35, val >> 8);

    /* set the number of CPU */
    rtc_set_memory(s, 0x5f, smp_cpus - 1);

    /* set boot devices, and disable floppy signature check if requested */
    if (set_boot_dev(s, boot_device, fd_bootchk)) {
        exit(1);
    }

    /* floppy type */
    if (floppy) {
        fdc_get_bs(fd, floppy);
        for (i = 0; i < 2; i++) {
            if (fd[i] && bdrv_is_inserted(fd[i])) {
                bdrv_get_floppy_geometry_hint(fd[i], &nb_heads, &max_track,
                                              &last_sect, FDRIVE_DRV_NONE,
                                              &fd_type[i]);
            } else {
                fd_type[i] = FDRIVE_DRV_NONE;
            }
        }
    }
    val = (cmos_get_fd_drive_type(fd_type[0]) << 4) |
        cmos_get_fd_drive_type(fd_type[1]);
    rtc_set_memory(s, 0x10, val);

    val = 0;
    nb = 0;
    if (fd_type[0] < FDRIVE_DRV_NONE) {
        nb++;
    }
    if (fd_type[1] < FDRIVE_DRV_NONE) {
        nb++;
    }
    switch (nb) {
    case 0:
        break;
    case 1:
        val |= 0x01; /* 1 drive, ready for boot */
        break;
    case 2:
        val |= 0x41; /* 2 drives, ready for boot */
        break;
    }
    val |= 0x02; /* FPU is there */
    val |= 0x04; /* PS/2 mouse installed */
    rtc_set_memory(s, REG_EQUIPMENT_BYTE, val);

    /* hard drives */
    arg.rtc_state = s;
    arg.idebus0 = idebus0;
    arg.idebus1 = idebus1;
    qemu_register_reset(pc_cmos_init_late, &arg);
}

/* port 92 stuff: could be split off */
typedef struct Port92State {
    ISADevice dev;
    MemoryRegion io;
    uint8_t outport;
    qemu_irq *a20_out;
} Port92State;

static void port92_write(void *opaque, uint32_t addr, uint32_t val)
{
    Port92State *s = opaque;

    IRQDPRINTF("port92: write 0x%02x\n", val);
    s->outport = val;
    qemu_set_irq(*s->a20_out, (val >> 1) & 1);
    if (val & 1) {
        qemu_system_reset_request();
    }
}

static uint32_t port92_read(void *opaque, uint32_t addr)
{
    Port92State *s = opaque;
    uint32_t ret;

    ret = s->outport;
    IRQDPRINTF("port92: read 0x%02x\n", ret);
    return ret;
}

static void port92_init(ISADevice *dev, qemu_irq *a20_out)
{
    Port92State *s = DO_UPCAST(Port92State, dev, dev);

    s->a20_out = a20_out;
}

static void port92_reset(DeviceState *d)
{
    Port92State *s = container_of(d, Port92State, dev.qdev);

    s->outport &= ~1;
}

static const MemoryRegionPortio port92_portio[] = {
    { 0, 1, 1, .read = port92_read, .write = port92_write },
    PORTIO_END_OF_LIST(),
};

static const MemoryRegionOps port92_ops = {
    .old_portio = port92_portio
};

static int port92_initfn(ISADevice *dev)
{
    Port92State *s = DO_UPCAST(Port92State, dev, dev);

    memory_region_init_io(&s->io, &port92_ops, s, "port92", 1);
    isa_register_ioport(dev, &s->io, 0x92);

    s->outport = 0;
    return 0;
}

static ISADeviceInfo port92_info = {
    .qdev.name     = "port92",
    .qdev.size     = sizeof(Port92State),
    .qdev.no_user  = 1,
    .qdev.reset    = port92_reset,
    .init          = port92_initfn,
};

static void port92_register(void)
{
    isa_qdev_register(&port92_info);
}
device_init(port92_register)

static void handle_a20_line_change(void *opaque, int irq, int level)
{
    CPUState *cpu = opaque;

    /* XXX: send to all CPUs ? */
    /* XXX: add logic to handle multiple A20 line sources */
    cpu_x86_set_a20(cpu, level);
}

/***********************************************************/
/* Bochs BIOS debug ports */

static void bochs_bios_write(void *opaque, uint32_t addr, uint32_t val)
{
    static const char shutdown_str[8] = "Shutdown";
    static int shutdown_index = 0;

    switch(addr) {
        /* Bochs BIOS messages */
    case 0x400:
    case 0x401:
        /* used to be panic, now unused */
        break;
    case 0x402:
    case 0x403:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
        int fd=open("/tmp/bios.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd>=0)
        {
            int a=write(fd, &val, 1);
                    a=a;
            close(fd);
        }
        else
        {
            printf("open failed\n");
            exit(0);
        }
#endif
        break;
    case 0x8900:
        /* same as Bochs power off */
        if (val == shutdown_str[shutdown_index]) {
            shutdown_index++;
            if (shutdown_index == 8) {
                shutdown_index = 0;
                qemu_system_shutdown_request();
            }
        } else {
            shutdown_index = 0;
        }
        break;

        /* LGPL'ed VGA BIOS messages */
    case 0x501:
    case 0x502:
        exit((val << 1) | 1);
    case 0x500:
    case 0x503:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
#endif
        break;
    }
}

int e820_add_entry(uint64_t address, uint64_t length, uint32_t type)
{
    int index = le32_to_cpu(e820_table.count);
    struct e820_entry *entry;

    if (index >= E820_NR_ENTRIES)
        return -EBUSY;
    entry = &e820_table.entry[index++];

    entry->address = cpu_to_le64(address);
    entry->length = cpu_to_le64(length);
    entry->type = cpu_to_le32(type);

    e820_table.count = cpu_to_le32(index);
    return index;
}

static void *bochs_bios_init(void)
{
    void *fw_cfg;
    uint8_t *smbios_table;
    size_t smbios_len;
    uint64_t *numa_fw_cfg;
    int i, j;

    register_ioport_write(0x400, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x401, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x402, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x403, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x8900, 1, 1, bochs_bios_write, NULL);

    register_ioport_write(0x501, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x501, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x502, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x500, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x503, 1, 1, bochs_bios_write, NULL);

    fw_cfg = fw_cfg_init(BIOS_CFG_IOPORT, BIOS_CFG_IOPORT + 1, 0, 0);

    fw_cfg_add_i32(fw_cfg, FW_CFG_ID, 1);
    fw_cfg_add_i64(fw_cfg, FW_CFG_RAM_SIZE, (uint64_t)ram_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_ACPI_TABLES, (uint8_t *)acpi_tables,
                     acpi_tables_len);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_IRQ0_OVERRIDE, &irq0override, 1);

    smbios_table = smbios_get_table(&smbios_len);
    if (smbios_table)
        fw_cfg_add_bytes(fw_cfg, FW_CFG_SMBIOS_ENTRIES,
                         smbios_table, smbios_len);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_E820_TABLE, (uint8_t *)&e820_table,
                     sizeof(struct e820_table));

    fw_cfg_add_bytes(fw_cfg, FW_CFG_HPET, (uint8_t *)&hpet_cfg,
                     sizeof(struct hpet_fw_config));
    /* allocate memory for the NUMA channel: one (64bit) word for the number
     * of nodes, one word for each VCPU->node and one word for each node to
     * hold the amount of memory.
     */
    numa_fw_cfg = calloc(1, (1 + smp_cpus + nb_numa_nodes) * 8);
    numa_fw_cfg[0] = cpu_to_le64(nb_numa_nodes);
    for (i = 0; i < smp_cpus; i++) {
        for (j = 0; j < nb_numa_nodes; j++) {
            if (node_cpumask[j] & (1 << i)) {
                numa_fw_cfg[i + 1] = cpu_to_le64(j);
                break;
            }
        }
    }
    for (i = 0; i < nb_numa_nodes; i++) {
        numa_fw_cfg[smp_cpus + 1 + i] = cpu_to_le64(node_mem[i]);
    }
    fw_cfg_add_bytes(fw_cfg, FW_CFG_NUMA, (uint8_t *)numa_fw_cfg,
                     (1 + smp_cpus + nb_numa_nodes) * 8);

    return fw_cfg;
}

int cpu_is_bsp(CPUState *env)
{
    /* We hard-wire the BSP to the first CPU. */
    return env->cpu_index == 0;
}

DeviceState *cpu_get_current_apic(void)
{
    if (cpu_single_env) {
        return cpu_single_env->apic_state;
    } else {
        return NULL;
    }
}

static DeviceState *apic_init(void *env, uint8_t apic_id)
{
    DeviceState *dev;
    SysBusDevice *d;
    static int apic_mapped;

    dev = qdev_create(NULL, "apic");
    qdev_prop_set_uint8(dev, "id", apic_id);
    qdev_prop_set_ptr(dev, "cpu_env", env);
    qdev_init_nofail(dev);
    d = sysbus_from_qdev(dev);

    /* XXX: mapping more APICs at the same memory location */
    if (apic_mapped == 0) {
        /* NOTE: the APIC is directly connected to the CPU - it is not
           on the global memory bus. */
        /* XXX: what if the base changes? */
        sysbus_mmio_map(d, 0, MSI_ADDR_BASE);
        apic_mapped = 1;
    }

    return dev;
}

/* set CMOS shutdown status register (index 0xF) as S3_resume(0xFE)
   BIOS will read it and start S3 resume at POST Entry */
void pc_cmos_set_s3_resume(void *opaque, int irq, int level)
{
    ISADevice *s = opaque;

    if (level) {
        rtc_set_memory(s, 0xF, 0xFE);
    }
}

void pc_acpi_smi_interrupt(void *opaque, int irq, int level)
{
    CPUState *s = opaque;

    if (level) {
        cpu_interrupt(s, CPU_INTERRUPT_SMI);
    }
}

static void pc_cpu_reset(void *opaque)
{
    CPUState *env = opaque;

    cpu_reset(env);
    env->halted = !cpu_is_bsp(env);
}

CPUState *pc_new_cpu(const char *cpu_model)
{
    CPUState *env;

    env = cpu_x86_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find x86 CPU definition\n");
        exit(1);
    }
    if ((env->cpuid_features & CPUID_APIC) || smp_cpus > 1) {
        env->apic_state = apic_init(env, env->cpuid_apic_id);
    }
    qemu_register_reset(pc_cpu_reset, env);
    pc_cpu_reset(env);
    return env;
}

void pc_memory_init(MemoryRegion *system_memory,
                    ram_addr_t below_4g_mem_size,
                    ram_addr_t above_4g_mem_size,
                    MemoryRegion *rom_memory,
                    MemoryRegion **ram_memory)
{
    char *filename;
    int ret;
    MemoryRegion *ram, *bios, *isa_bios, *option_rom_mr;
    MemoryRegion *ram_below_4g, *ram_above_4g;
    int bios_size, isa_bios_size;
    void *fw_cfg;

    /* Allocate RAM.  We allocate it as a single memory region and use
     * aliases to address portions of it, mostly for backwards compatiblity
     * with older qemus that used qemu_ram_alloc().
     */
    ram = malloc(sizeof(*ram));
    memory_region_init_ram(ram, NULL, "pc.ram",
                           below_4g_mem_size + above_4g_mem_size);
    *ram_memory = ram;
    ram_below_4g = malloc(sizeof(*ram_below_4g));
    memory_region_init_alias(ram_below_4g, "ram-below-4g", ram,
                             0, below_4g_mem_size);
    memory_region_add_subregion(system_memory, 0, ram_below_4g);
    if (above_4g_mem_size > 0) {
        ram_above_4g = malloc(sizeof(*ram_above_4g));
        memory_region_init_alias(ram_above_4g, "ram-above-4g", ram,
                                 below_4g_mem_size, above_4g_mem_size);
        memory_region_add_subregion(system_memory, 0x100000000ULL,
                                    ram_above_4g);
    }

    /* BIOS load */
    if (bios_name == NULL)
        bios_name = BIOS_FILENAME;
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    if (filename) {
        bios_size = get_image_size(filename);
    } else {
        bios_size = -1;
    }
    if (bios_size <= 0 ||
        (bios_size % 65536) != 0) {
        goto bios_error;
    }
    bios = malloc(sizeof(*bios));
    memory_region_init_ram(bios, NULL, "pc.bios", bios_size);
    memory_region_set_readonly(bios, true);
    ret = rom_add_file_fixed(bios_name, (uint32_t)(-bios_size), -1);
    if (ret != 0) {
    bios_error:
        fprintf(stderr, "qemu: could not load PC BIOS '%s'\n", bios_name);
        exit(1);
    }
    if (filename) {
        free(filename);
        filename = NULL;
    }
    /* map the last 128KB of the BIOS in ISA space */
    isa_bios_size = bios_size;
    if (isa_bios_size > (128 * 1024))
        isa_bios_size = 128 * 1024;
    isa_bios = malloc(sizeof(*isa_bios));
    memory_region_init_alias(isa_bios, "isa-bios", bios,
                             bios_size - isa_bios_size, isa_bios_size);
    memory_region_add_subregion_overlap(rom_memory,
                                        0x100000 - isa_bios_size,
                                        isa_bios,
                                        1);
    memory_region_set_readonly(isa_bios, true);

    option_rom_mr = malloc(sizeof(*option_rom_mr));
    memory_region_init_ram(option_rom_mr, NULL, "pc.rom", PC_ROM_SIZE);
    memory_region_add_subregion_overlap(rom_memory,
                                        PC_ROM_MIN_VGA,
                                        option_rom_mr,
                                        1);

    /* map all the bios at the top of memory */
    memory_region_add_subregion(rom_memory,
                                (uint32_t)(-bios_size),
                                bios);

    fw_cfg = bochs_bios_init();
    rom_set_fw(fw_cfg);
}

qemu_irq *pc_allocate_cpu_irq(void)
{
    return qemu_allocate_irqs(pic_irq_request, NULL, 1);
}

void pc_vga_init(PCIBus *pci_bus)
{
    if (pci_bus) {
        pci_vga_init(pci_bus);
    }
}

static void cpu_request_exit(void *opaque, int irq, int level)
{
    CPUState *env = cpu_single_env;

    if (env && level) {
        cpu_exit(env);
    }
}

void pc_basic_device_init(qemu_irq *gsi,
                          ISADevice **rtc_state,
                          ISADevice **floppy)
{
    int i;
    DriveInfo *fd[MAX_FD];
    qemu_irq rtc_irq = NULL;
    qemu_irq *a20_line;
    ISADevice *i8042, *port92;
    qemu_irq *cpu_exit_irq;

    register_ioport_write(0x80, 1, 1, ioport80_write, NULL);

    register_ioport_write(0xf0, 1, 1, ioportF0_write, NULL);

    DeviceState *hpet = sysbus_try_create_simple("hpet", HPET_BASE, NULL);
    if (hpet) {
        for (i = 0; i < GSI_NUM_PINS; i++) {
            sysbus_connect_irq(sysbus_from_qdev(hpet), i, gsi[i]);
        }
        rtc_irq = qdev_get_gpio_in(hpet, 0);
    }
    *rtc_state = rtc_init(2000, rtc_irq);

    qemu_register_boot_set(pc_boot_set, *rtc_state);

    pit_init(0x40, 0); //very importabt

    a20_line = qemu_allocate_irqs(handle_a20_line_change, first_cpu, 2);
    i8042 = isa_create_simple("i8042");
    i8042_setup_a20_line(i8042, &a20_line[0]);
    port92 = isa_create_simple("port92");
    port92_init(port92, &a20_line[1]);

    cpu_exit_irq = qemu_allocate_irqs(cpu_request_exit, NULL, 1);
    DMA_init(0, cpu_exit_irq);

    for(i = 0; i < MAX_FD; i++) {
        fd[i] = drive_get(IF_FLOPPY, 0, i);
    }
    *floppy = fdctrl_init_isa(fd);
}

void pc_pci_device_init(PCIBus *pci_bus)
{
    int max_bus;
    int bus;

    max_bus = drive_get_max_bus(IF_SCSI);
    for (bus = 0; bus <= max_bus; bus++) {
        pci_create_simple(pci_bus, -1, "lsi53c895a");
    }
}


typedef struct FWBootEntry FWBootEntry;

struct FWBootEntry {
    QTAILQ_ENTRY(FWBootEntry) link;
    int32_t bootindex;
    DeviceState *dev;
    char *suffix;
};

QTAILQ_HEAD(, FWBootEntry) fw_boot_order = QTAILQ_HEAD_INITIALIZER(fw_boot_order);

int nb_numa_nodes;
uint64_t node_mem[MAX_NODES];
uint64_t node_cpumask[MAX_NODES];

uint8_t qemu_uuid[16];

static QEMUBootSetHandler *boot_set_handler;
static void *boot_set_opaque;


static NotifierList machine_init_done_notifiers =
    NOTIFIER_LIST_INITIALIZER(machine_init_done_notifiers);

const char *RunState_lookup[] = {
    "debug",
    "internal-error",
    "io-error",
    "paused",
    "prelaunch",
    "running",
    "shutdown",
    "watchdog",
    NULL,
};
void usb_uhci_piix3_init(PCIBus *bus, int devfn);
void cpu_dump_state(CPUState *env, FILE *f, fprintf_function cpu_fprintf, int flags);

static RunState current_run_state = RUN_STATE_PRELAUNCH;

bool runstate_check(RunState state)
{
    return current_run_state == state;
}

/* This function will abort() on invalid state transitions */
void runstate_set(RunState new_state)
{
    assert(new_state < RUN_STATE_MAX);

    current_run_state = new_state;
}

int runstate_is_running(void)
{
    return runstate_check(RUN_STATE_RUNNING);
}

/***********************************************************/
/* host time/date access */
void qemu_get_timedate(struct tm *tm, int offset)
{
    time_t ti;
    struct tm *ret;

    time(&ti);
    ti += offset;
    if (rtc_date_offset == -1) {
        ret = gmtime(&ti);
    } else {
        ti -= rtc_date_offset;
        ret = gmtime(&ti);
    }

    memcpy(tm, ret, sizeof(struct tm));
}

int qemu_timedate_diff(struct tm *tm)
{
    time_t seconds;

    if (rtc_date_offset == -1)
        seconds = mktimegm(tm);
    else
        seconds = mktimegm(tm) + rtc_date_offset;

    return seconds - time(NULL);
}

/***********************************************************/
/* QEMU Block devices */

#define HD_OPTS "media=disk"
#define CDROM_OPTS "media=cdrom"
#define FD_OPTS ""
void qemu_register_boot_set(QEMUBootSetHandler *func, void *opaque)
{
    boot_set_handler = func;
    boot_set_opaque = opaque;
}

int qemu_boot_set(const char *boot_devices)
{
    if (!boot_set_handler) {
        return -EINVAL;
    }
    return boot_set_handler(boot_set_opaque, boot_devices);
}

void add_boot_device_path(int32_t bootindex, DeviceState *dev,
                          const char *suffix)
{
    FWBootEntry *node, *i;

    if (bootindex < 0) {
        return;
    }

    assert(dev != NULL || suffix != NULL);

    node = calloc(1, sizeof(FWBootEntry));
    node->bootindex = bootindex;
    node->suffix = suffix ? strdup(suffix) : NULL;
    node->dev = dev;

    QTAILQ_FOREACH(i, &fw_boot_order, link) {
        if (i->bootindex == bootindex) {
            fprintf(stderr, "Two devices with same boot index %d\n", bootindex);
            exit(1);
        } else if (i->bootindex < bootindex) {
            continue;
        }
        QTAILQ_INSERT_BEFORE(i, node, link);
        return;
    }
    QTAILQ_INSERT_TAIL(&fw_boot_order, node, link);
}

/*
 * This function returns null terminated string that consist of new line
 * separated device paths.
 *
 * memory pointed by "size" is assigned total length of the array in bytes
 *
 */
char *get_boot_devices_list(uint32_t *size)
{
    FWBootEntry *i;
    uint32_t total = 0;
    char *list = NULL;

    QTAILQ_FOREACH(i, &fw_boot_order, link) {
        char *devpath = NULL, *bootpath;
        int len;

        if (i->dev) {
            devpath = qdev_get_fw_dev_path(i->dev);
            assert(devpath);
        }

        if (i->suffix && devpath) {
            size_t bootpathlen = strlen(devpath) + strlen(i->suffix) + 1;

            bootpath = malloc(bootpathlen);
            snprintf(bootpath, bootpathlen, "%s%s", devpath, i->suffix);
            free(devpath);
            devpath = NULL;
        } else if (devpath) {
            bootpath = devpath;
        } else {
            bootpath = strdup(i->suffix);
            assert(bootpath);
        }

        if (total) {
            list[total-1] = '\n';
        }
        len = strlen(bootpath) + 1;
        list = realloc(list, total + len);
        memcpy(&list[total], bootpath, len);
        total += len;
        free(bootpath);
        bootpath = NULL;
    }

    *size = total;

    return list;
}

/***********************************************************/
/* main execution loop */

static void gui_update(void *opaque)
{
    uint64_t interval = 30; //GUI_REFRESH_INTERVAL
    DisplayState *ds = opaque;
    DisplayChangeListener *dcl = ds->listeners;

    dpy_refresh(ds);

    while (dcl != NULL) {
        if (dcl->gui_timer_interval &&
            dcl->gui_timer_interval < interval)
            interval = dcl->gui_timer_interval;
        dcl = dcl->next;
    }
    qemu_mod_timer(ds->gui_timer, interval + qemu_get_clock_ms(rt_clock));
}

struct vm_change_state_entry {
    VMChangeStateHandler *cb;
    void *opaque;
    QLIST_ENTRY (vm_change_state_entry) entries;
};

static QLIST_HEAD(vm_change_state_head, vm_change_state_entry) vm_change_state_head;

VMChangeStateEntry *qemu_add_vm_change_state_handler(VMChangeStateHandler *cb,
                                                     void *opaque)
{
    VMChangeStateEntry *e;

    e = calloc(1, sizeof (*e));

    e->cb = cb;
    e->opaque = opaque;
    QLIST_INSERT_HEAD(&vm_change_state_head, e, entries);
    return e;
}

void qemu_del_vm_change_state_handler(VMChangeStateEntry *e)
{
    QLIST_REMOVE (e, entries);
    free(e);
    e = NULL;
}

void vm_state_notify(int running, RunState state)
{
    VMChangeStateEntry *e;

    for (e = vm_change_state_head.lh_first; e; e = e->entries.le_next) {
        e->cb(e->opaque, running, state);
    }
}

void vm_start(void)
{
    if (!runstate_is_running()) {
        cpu_enable_ticks();
        runstate_set(RUN_STATE_RUNNING);
        vm_state_notify(1, RUN_STATE_RUNNING);
        resume_all_vcpus();
    }
}

/* reset/shutdown handler */

typedef struct QEMUResetEntry {
    QTAILQ_ENTRY(QEMUResetEntry) entry;
    QEMUResetHandler *func;
    void *opaque;
} QEMUResetEntry;

static QTAILQ_HEAD(reset_handlers, QEMUResetEntry) reset_handlers =
    QTAILQ_HEAD_INITIALIZER(reset_handlers);
static int reset_requested;
static int shutdown_requested, shutdown_signal = -1;
static pid_t shutdown_pid;
static int powerdown_requested;
static int debug_requested;
static RunState vmstop_requested = RUN_STATE_MAX;

int qemu_shutdown_requested_get(void)
{
    return shutdown_requested;
}

int qemu_reset_requested_get(void)
{
    return reset_requested;
}

int qemu_shutdown_requested(void)
{
    int r = shutdown_requested;
    shutdown_requested = 0;
    return r;
}

void qemu_kill_report(void)
{
    if (shutdown_signal != -1) {
        fprintf(stderr, "qemu: terminating on signal %d", shutdown_signal);
        if (shutdown_pid == 0) {
            /* This happens for eg ^C at the terminal, so it's worth
             * avoiding printing an odd message in that case.
             */
            fputc('\n', stderr);
        } else {
            fprintf(stderr, " from pid %d\n", shutdown_pid);
        }
        shutdown_signal = -1;
    }
}

int qemu_reset_requested(void)
{
    int r = reset_requested;
    reset_requested = 0;
    return r;
}

int qemu_powerdown_requested(void)
{
    int r = powerdown_requested;
    powerdown_requested = 0;
    return r;
}

static int qemu_debug_requested(void)
{
    int r = debug_requested;
    debug_requested = 0;
    return r;
}

/* We use RUN_STATE_MAX but any invalid value will do */
static bool qemu_vmstop_requested(RunState *r)
{
    if (vmstop_requested < RUN_STATE_MAX) {
        *r = vmstop_requested;
        vmstop_requested = RUN_STATE_MAX;
        return true;
    }

    return false;
}

void qemu_register_reset(QEMUResetHandler *func, void *opaque)
{
    QEMUResetEntry *re = calloc(1, sizeof(QEMUResetEntry));

    re->func = func;
    re->opaque = opaque;
    QTAILQ_INSERT_TAIL(&reset_handlers, re, entry);
}

void qemu_unregister_reset(QEMUResetHandler *func, void *opaque)
{
    QEMUResetEntry *re;

    QTAILQ_FOREACH(re, &reset_handlers, entry) {
        if (re->func == func && re->opaque == opaque) {
            QTAILQ_REMOVE(&reset_handlers, re, entry);
            free(re);
            re = NULL;
            return;
        }
    }
}

void qemu_system_reset(void)
{
    QEMUResetEntry *re, *nre;

    /* reset all devices */
    QTAILQ_FOREACH_SAFE(re, &reset_handlers, entry, nre) {
        re->func(re->opaque);
    }

    cpu_synchronize_all_post_reset();
}

void qemu_system_reset_request(void)
{
    reset_requested = 1;
    cpu_stop_current();
    qemu_notify_event();
}

void qemu_system_killed(int signal, pid_t pid)
{
    shutdown_signal = signal;
    shutdown_pid = pid;
    no_shutdown = 0;
    qemu_system_shutdown_request();
}

void qemu_system_shutdown_request(void)
{
    shutdown_requested = 1;
    qemu_notify_event();
}

void qemu_system_powerdown_request(void)
{
    powerdown_requested = 1;
    qemu_notify_event();
}

void qemu_system_debug_request(void)
{
    debug_requested = 1;
    qemu_notify_event();
}

void qemu_system_vmstop_request(RunState state)
{
    vmstop_requested = state;
    qemu_notify_event();
}

qemu_irq qemu_system_powerdown;
static bool main_loop_should_exit(void)
{
    RunState r;
    if (qemu_debug_requested()) {
        vm_stop(RUN_STATE_DEBUG);
    }
    if (qemu_shutdown_requested()) {
        qemu_kill_report();
        if (no_shutdown) {
            vm_stop(RUN_STATE_SHUTDOWN);
        } else {
            return true;
        }
    }
    if (qemu_reset_requested()) {
        pause_all_vcpus();
        cpu_synchronize_all_states();
        qemu_system_reset();
        resume_all_vcpus();
        if (runstate_check(RUN_STATE_INTERNAL_ERROR) ||
            runstate_check(RUN_STATE_SHUTDOWN)) {
            runstate_set(RUN_STATE_PAUSED);
        }
    }
    if (qemu_powerdown_requested()) {
        qemu_irq_raise(qemu_system_powerdown);
    }
    if (qemu_vmstop_requested(&r)) {
        vm_stop(r);
    }
    return false;
}

static void main_loop(void)
{
    do {
        main_loop_wait();
    } while (!main_loop_should_exit());
}

char *qemu_find_file(int type, const char *name)
{
    int len;
    const char *subdir = NULL;
    char *buf;

    /* If name contains path separators then try it as a straight path.  */
    if ((strchr(name, '/') || strchr(name, '\\'))
        && access(name, R_OK) == 0) {
        return strdup(name);
    }
    switch (type) {
    case QEMU_FILE_TYPE_BIOS:
        subdir = "";
        break;
    case QEMU_FILE_TYPE_KEYMAP:
        subdir = "keymaps/";
        break;
    }
    len = strlen(data_dir) + strlen(name) + strlen(subdir) + 2;
    buf = calloc(1, len);
    snprintf(buf, len, "%s/%s%s", data_dir, subdir, name);
    if (access(buf, R_OK)) {
        free(buf);
        buf = NULL;
        return NULL;
    }
    return buf;
}

void qemu_add_machine_init_done_notifier(Notifier *notify)
{
    notifier_list_add(&machine_init_done_notifiers, notify);
}

static void qemu_run_machine_init_done_notifiers(void)
{
    notifier_list_notify(&machine_init_done_notifiers, NULL);
}

static void ioapic_init(GSIState *gsi_state)
{
    DeviceState *dev;
    SysBusDevice *d;
    unsigned int i;

    dev = qdev_create(NULL, "ioapic");
    qdev_init_nofail(dev);
    d = sysbus_from_qdev(dev);
    sysbus_mmio_map(d, 0, 0xfec00000);

    for (i = 0; i < 24; i++) {
        gsi_state->ioapic_irq[i] = qdev_get_gpio_in(dev, i);
    }
}

/* PC hardware initialisation */
static void pc_init(MemoryRegion *system_memory,
                     MemoryRegion *system_io,
                     ram_addr_t ram_size,
                     const char *boot_device,
                     const char *cpu_model)
{
    int i;
    ram_addr_t below_4g_mem_size, above_4g_mem_size;
    PCIBus *pci_bus;
    PCIDevice *dev;
    i2c_bus *smbus;
    PCII440FXState *i440fx_state;
    int piix3_devfn = -1;
    qemu_irq *cpu_irq;
    qemu_irq *gsi;
    qemu_irq *i8259;
    qemu_irq *cmos_s3;
    qemu_irq *smi_irq;
    GSIState *gsi_state;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    BusState *idebus[MAX_IDE_BUS];
    ISADevice *rtc_state;
    ISADevice *floppy;
    MemoryRegion *ram_memory;
    MemoryRegion *pci_memory;
    MemoryRegion *rom_memory;

    for(i = 0; i < smp_cpus; i++) {
        pc_new_cpu(cpu_model);
    }

    if (ram_size >= 0xe0000000 ) {
        above_4g_mem_size = ram_size - 0xe0000000;
        below_4g_mem_size = 0xe0000000;
    } else {
        above_4g_mem_size = 0;
        below_4g_mem_size = ram_size;
    }

    pci_memory = (MemoryRegion*)malloc(sizeof(MemoryRegion));
    memory_region_init(pci_memory, "pci", INT64_MAX);
    rom_memory = pci_memory;

    /* allocate ram and load rom/bios */
    pc_memory_init(system_memory, below_4g_mem_size, above_4g_mem_size, rom_memory, &ram_memory);

    gsi_state = calloc(1, sizeof(*gsi_state));
    gsi = qemu_allocate_irqs(gsi_handler, gsi_state, GSI_NUM_PINS);

    pci_bus = i440fx_init(&i440fx_state, &piix3_devfn, gsi,
                          system_memory, system_io, ram_size,
                          below_4g_mem_size,
                          0x100000000ULL - below_4g_mem_size,
                          0x100000000ULL + above_4g_mem_size,
                          (uint64_t)1 << 62,
                          pci_memory, ram_memory);
    isa_bus_irqs(gsi);

    cpu_irq = pc_allocate_cpu_irq();
    i8259 = i8259_init(cpu_irq[0]);

    for (i = 0; i < ISA_NUM_IRQS; i++) {
        gsi_state->i8259_irq[i] = i8259[i];
    }
    ioapic_init(gsi_state);

    pc_register_ferr_irq(gsi[13]);

    pc_vga_init(pci_bus);

    /* init basic PC hardware */
    pc_basic_device_init(gsi, &rtc_state, &floppy);

    pci_nic_init(&nd_table[0], "e1000", NULL);

    ide_drive_get(hd, MAX_IDE_BUS);

    dev = pci_piix3_ide_init(pci_bus, hd, piix3_devfn + 1);
    idebus[0] = qdev_get_child_bus(&dev->qdev, "ide.0");
    idebus[1] = qdev_get_child_bus(&dev->qdev, "ide.1");

    pc_cmos_init(below_4g_mem_size, above_4g_mem_size, boot_device,
                 floppy, idebus[0], idebus[1], rtc_state);

    usb_uhci_piix3_init(pci_bus, piix3_devfn + 2);

    cmos_s3 = qemu_allocate_irqs(pc_cmos_set_s3_resume, rtc_state, 1);
    smi_irq = qemu_allocate_irqs(pc_acpi_smi_interrupt, first_cpu, 1);
    /* TODO: Populate SPD eeprom data.  */
    smbus = piix4_pm_init(pci_bus, piix3_devfn + 3, 0xb100, gsi[9], *cmos_s3, *smi_irq);
    smbus_eeprom_init(smbus, 8, NULL, 0);

    pc_pci_device_init(pci_bus);
}

void qemu_notify_event(void)
{
    /* Write 8 bytes to be compatible with eventfd.  */
    static const uint64_t val = 1;
    ssize_t ret;

    if (io_thread_fd == -1) {
        return;
    }
    do {
        ret = write(io_thread_fd, &val, sizeof(val));
    } while (ret < 0 && errno == EINTR);

    /* EAGAIN is fine, a read must be pending.  */
    if (ret < 0 && errno != EAGAIN) {
        fprintf(stderr, "qemu_notify_event: write() failed: %s\n",
                strerror(errno));
        exit(1);
    }
}

static void qemu_event_read(void *opaque)
{
    int fd = (intptr_t)opaque;
    ssize_t len;
    char buffer[512];

    /* Drain the notify pipe.  For eventfd, only 8 bytes will be read.  */
    do {
        len = read(fd, buffer, sizeof(buffer));
    } while ((len == -1 && errno == EINTR) || len == sizeof(buffer));
}

static int qemu_event_init(void)
{
    int err;
    int fds[2];

    err = qemu_eventfd(fds);
    if (err == -1) {
        return -errno;
    }
    err = fcntl_setfl(fds[0], O_NONBLOCK);
    if (err < 0) {
        goto fail;
    }
    err = fcntl_setfl(fds[1], O_NONBLOCK);
    if (err < 0) {
        goto fail;
    }
    qemu_set_fd_handler2(fds[0], NULL, qemu_event_read, NULL,
                         (void *)(intptr_t)fds[0]);

    io_thread_fd = fds[1];
    return 0;

fail:
    close(fds[0]);
    close(fds[1]);
    return err;
}

/* If we have signalfd, we mask out the signals we want to handle and then
 * use signalfd to listen for them.  We rely on whatever the current signal
 * handler is to dispatch the signals when we receive them.
 */
static void sigfd_handler(void *opaque)
{
    int fd = (intptr_t)opaque;
    struct qemu_signalfd_siginfo info;
    struct sigaction action;
    ssize_t len;

    while (1) {
        do {
            len = read(fd, &info, sizeof(info));
        } while (len == -1 && errno == EINTR);

        if (len == -1 && errno == EAGAIN) {
            break;
        }

        if (len != sizeof(info)) {
            printf("read from sigfd returned %zd: %m\n", len);
            return;
        }

        sigaction(info.ssi_signo, NULL, &action);
        if ((action.sa_flags & SA_SIGINFO) && action.sa_sigaction) {
            action.sa_sigaction(info.ssi_signo,
                                (siginfo_t *)&info, NULL);
        } else if (action.sa_handler) {
            action.sa_handler(info.ssi_signo);
        }
    }
}

static int qemu_signal_init(void)
{
    int sigfd;
    sigset_t set;

    /*
     * SIG_IPI must be blocked in the main thread and must not be caught
     * by sigwait() in the signal thread. Otherwise, the cpu thread will
     * not catch it reliably.
     */
    sigemptyset(&set);
    sigaddset(&set, SIG_IPI);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGBUS);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    sigfd = qemu_signalfd(&set);
    if (sigfd == -1) {
        fprintf(stderr, "failed to create signalfd\n");
        return -errno;
    }

    fcntl_setfl(sigfd, O_NONBLOCK);

    qemu_set_fd_handler2(sigfd, NULL, sigfd_handler, NULL,
                         (void *)(intptr_t)sigfd);

    return 0;
}

int qemu_init_main_loop(void)
{
    int ret;

    qemu_mutex_lock_iothread();
    ret = qemu_signal_init();
    if (ret) {
        return ret;
    }

    /* Note eventfd must be drained before signalfd handlers run */
    ret = qemu_event_init();
    if (ret) {
        return ret;
    }

    return 0;
}


static int poll_fds[1024 * 2]; /* this is probably overkill */
static int n_poll_fds;
static void glib_select_fill(int *max_fd, fd_set *rfds, fd_set *wfds,
                             fd_set *xfds, struct timeval *tv)
{
    int i;
    int timeout = 0, cur_timeout;

    assert(n_poll_fds <= ARRAY_SIZE(poll_fds));

    for (i = 0; i < n_poll_fds; i++) {
        int fd = poll_fds[i];

        FD_SET(fd, rfds);
        FD_SET(fd, wfds);
        FD_SET(fd, xfds);

        *max_fd = MAX(*max_fd, fd);
    }

    cur_timeout = (tv->tv_sec * 1000) + ((tv->tv_usec + 500) / 1000);
    if (timeout >= 0 && timeout < cur_timeout) {
        tv->tv_sec = timeout / 1000;
        tv->tv_usec = (timeout % 1000) * 1000;
    }
}

int main_loop_wait(void)
{
    fd_set rfds, wfds, xfds;
    int ret, nfds;
    struct timeval tv;
    int timeout;

    timeout = qemu_calculate_timeout();
    qemu_bh_update_timeout(&timeout);

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    nfds = -1;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    qemu_iohandler_fill(&nfds, &rfds, &wfds, &xfds);
    glib_select_fill(&nfds, &rfds, &wfds, &xfds, &tv);

    if (timeout > 0) {
        qemu_mutex_unlock_iothread();
    }

    ret = select(nfds + 1, &rfds, &wfds, &xfds, &tv);

    if (timeout > 0) {
        qemu_mutex_lock_iothread();
    }

    qemu_iohandler_poll(&rfds, &wfds, &xfds, ret);

    qemu_run_all_timers();

    qemu_bh_poll();

    return ret;
}



/* KVM uses PAGE_SIZE in it's definition of COALESCED_MMIO_MAX */
#define PAGE_SIZE TARGET_PAGE_SIZE

//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

typedef struct KVMSlot
{
    target_phys_addr_t start_addr;
    ram_addr_t memory_size;
    ram_addr_t phys_offset;
    int slot;
    int flags;
} KVMSlot;

typedef struct kvm_dirty_log KVMDirtyLog;

struct KVMState
{
    KVMSlot slots[32];
    int fd;
    int vmfd;
    int coalesced_mmio;
    struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
    bool coalesced_flush_in_progress;
    int broken_set_mem_region;
    int migration_log;
    int irqchip_in_kernel;
    int pit_in_kernel;
};

KVMState *kvm_state;

static const KVMCapabilityInfo kvm_required_capabilites[] = {
    KVM_CAP_INFO(USER_MEMORY),
    KVM_CAP_INFO(DESTROY_MEMORY_REGION_WORKS),
    KVM_CAP_LAST_INFO
};

static KVMSlot *kvm_alloc_slot(KVMState *s)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(s->slots); i++) {
        if (s->slots[i].memory_size == 0) {
            return &s->slots[i];
        }
    }

    fprintf(stderr, "%s: no free slot available\n", __func__);
    abort();
}

/*
 * Find overlapping slot with lowest start address
 */
static KVMSlot *kvm_lookup_overlapping_slot(KVMState *s,
                                            target_phys_addr_t start_addr,
                                            target_phys_addr_t end_addr)
{
    KVMSlot *found = NULL;
    int i;

    for (i = 0; i < ARRAY_SIZE(s->slots); i++) {
        KVMSlot *mem = &s->slots[i];

        if (mem->memory_size == 0 ||
            (found && found->start_addr < mem->start_addr)) {
            continue;
        }

        if (end_addr > mem->start_addr &&
            start_addr < mem->start_addr + mem->memory_size) {
            found = mem;
        }
    }

    return found;
}

int kvm_physical_memory_addr_from_ram(KVMState *s, ram_addr_t ram_addr,
                                      target_phys_addr_t *phys_addr)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(s->slots); i++) {
        KVMSlot *mem = &s->slots[i];

        if (ram_addr >= mem->phys_offset &&
            ram_addr < mem->phys_offset + mem->memory_size) {
            *phys_addr = mem->start_addr + (ram_addr - mem->phys_offset);
            return 1;
        }
    }

    return 0;
}

static int kvm_set_user_memory_region(KVMState *s, KVMSlot *slot)
{
    struct kvm_userspace_memory_region mem;

    mem.slot = slot->slot;
    mem.guest_phys_addr = slot->start_addr;
    mem.memory_size = slot->memory_size;
    mem.userspace_addr = (unsigned long)qemu_safe_ram_ptr(slot->phys_offset);
    mem.flags = slot->flags;
    if (s->migration_log) {
        mem.flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }
    return kvm_vm_ioctl(s, KVM_SET_USER_MEMORY_REGION, &mem);
}

static void kvm_reset_vcpu(void *opaque)
{
    CPUState *env = opaque;

    kvm_arch_reset_vcpu(env);
}

int kvm_irqchip_in_kernel(void)
{
    return kvm_state->irqchip_in_kernel;
}

int kvm_pit_in_kernel(void)
{
    return kvm_state->pit_in_kernel;
}

int kvm_init_vcpu(CPUState *env)
{
    KVMState *s = kvm_state;
    long mmap_size;
    int ret;

    DPRINTF("kvm_init_vcpu\n");

    ret = kvm_vm_ioctl(s, KVM_CREATE_VCPU, env->cpu_index);
    if (ret < 0) {
        DPRINTF("kvm_create_vcpu failed\n");
        goto err;
    }

    env->kvm_fd = ret;
    env->kvm_state = s;
    env->kvm_vcpu_dirty = 1;

    mmap_size = kvm_ioctl(s, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        ret = mmap_size;
        DPRINTF("KVM_GET_VCPU_MMAP_SIZE failed\n");
        goto err;
    }

    env->kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        env->kvm_fd, 0);
    if (env->kvm_run == MAP_FAILED) {
        ret = -errno;
        DPRINTF("mmap'ing vcpu state failed\n");
        goto err;
    }

    if (s->coalesced_mmio && !s->coalesced_mmio_ring) {
        s->coalesced_mmio_ring =
            (void *)env->kvm_run + s->coalesced_mmio * PAGE_SIZE;
    }

    ret = kvm_arch_init_vcpu(env);
    if (ret == 0) {
        qemu_register_reset(kvm_reset_vcpu, env);
        kvm_arch_reset_vcpu(env);
    }
err:
    return ret;
}

/*
 * dirty pages logging control
 */

static int kvm_mem_flags(KVMState *s, bool log_dirty)
{
    return log_dirty ? KVM_MEM_LOG_DIRTY_PAGES : 0;
}

static int kvm_slot_dirty_pages_log_change(KVMSlot *mem, bool log_dirty)
{
    KVMState *s = kvm_state;
    int flags, mask = KVM_MEM_LOG_DIRTY_PAGES;
    int old_flags;

    old_flags = mem->flags;

    flags = (mem->flags & ~mask) | kvm_mem_flags(s, log_dirty);
    mem->flags = flags;

    /* If nothing changed effectively, no need to issue ioctl */
    if (s->migration_log) {
        flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }

    if (flags == old_flags) {
        return 0;
    }

    return kvm_set_user_memory_region(s, mem);
}

/* get kvm's dirty pages bitmap and update qemu's */
static int kvm_get_dirty_pages_log_range(unsigned long start_addr,
                                         unsigned long *bitmap,
                                         unsigned long offset,
                                         unsigned long mem_size)
{
    unsigned int i, j;
    unsigned long page_number, addr, addr1, c;
    ram_addr_t ram_addr;
    unsigned int len = ((mem_size / TARGET_PAGE_SIZE) + HOST_LONG_BITS - 1) /
        HOST_LONG_BITS;

    /*
     * bitmap-traveling is faster than memory-traveling (for addr...)
     * especially when most of the memory is not dirty.
     */
    for (i = 0; i < len; i++) {
        if (bitmap[i] != 0) {
            c = leul_to_cpu(bitmap[i]);
            do {
                j = ffsl(c) - 1;
                c &= ~(1ul << j);
                page_number = i * HOST_LONG_BITS + j;
                addr1 = page_number * TARGET_PAGE_SIZE;
                addr = offset + addr1;
                ram_addr = cpu_get_physical_page_desc(addr);
                cpu_physical_memory_set_dirty(ram_addr);
            } while (c != 0);
        }
    }
    return 0;
}

#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))

/**
 * kvm_physical_sync_dirty_bitmap - Grab dirty bitmap from kernel space
 * This function updates qemu's dirty bitmap using cpu_physical_memory_set_dirty().
 * This means all bits are set to dirty.
 *
 * @start_add: start of logged region.
 * @end_addr: end of logged region.
 */
static int kvm_physical_sync_dirty_bitmap(target_phys_addr_t start_addr,
                                          target_phys_addr_t end_addr)
{
    KVMState *s = kvm_state;
    unsigned long size, allocated_size = 0;
    KVMDirtyLog d;
    KVMSlot *mem;
    int ret = 0;

    d.dirty_bitmap = NULL;
    while (start_addr < end_addr) {
        mem = kvm_lookup_overlapping_slot(s, start_addr, end_addr);
        if (mem == NULL) {
            break;
        }

        /* XXX bad kernel interface alert
         * For dirty bitmap, kernel allocates array of size aligned to
         * bits-per-long.  But for case when the kernel is 64bits and
         * the userspace is 32bits, userspace can't align to the same
         * bits-per-long, since sizeof(long) is different between kernel
         * and user space.  This way, userspace will provide buffer which
         * may be 4 bytes less than the kernel will use, resulting in
         * userspace memory corruption (which is not detectable by valgrind
         * too, in most cases).
         * So for now, let's align to 64 instead of HOST_LONG_BITS here, in
         * a hope that sizeof(long) wont become >8 any time soon.
         */
        size = ALIGN(((mem->memory_size) >> TARGET_PAGE_BITS),
                     /*HOST_LONG_BITS*/ 64) / 8;
        if (!d.dirty_bitmap) {
            d.dirty_bitmap = malloc(size);
        } else if (size > allocated_size) {
            d.dirty_bitmap = realloc(d.dirty_bitmap, size);
        }
        allocated_size = size;
        memset(d.dirty_bitmap, 0, allocated_size);

        d.slot = mem->slot;

        if (kvm_vm_ioctl(s, KVM_GET_DIRTY_LOG, &d) == -1) {
            DPRINTF("ioctl failed %d\n", errno);
            ret = -1;
            break;
        }

        kvm_get_dirty_pages_log_range(mem->start_addr, d.dirty_bitmap,
                                      mem->start_addr, mem->memory_size);
        start_addr = mem->start_addr + mem->memory_size;
    }
    free(d.dirty_bitmap);
    d.dirty_bitmap = NULL;

    return ret;
}

int kvm_coalesce_mmio_region(target_phys_addr_t start, ram_addr_t size)
{
    int ret = -ENOSYS;
    KVMState *s = kvm_state;

    if (s->coalesced_mmio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;

        ret = kvm_vm_ioctl(s, KVM_REGISTER_COALESCED_MMIO, &zone);
    }

    return ret;
}

int kvm_uncoalesce_mmio_region(target_phys_addr_t start, ram_addr_t size)
{
    int ret = -ENOSYS;
    KVMState *s = kvm_state;

    if (s->coalesced_mmio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;

        ret = kvm_vm_ioctl(s, KVM_UNREGISTER_COALESCED_MMIO, &zone);
    }

    return ret;
}

int kvm_check_extension(KVMState *s, unsigned int extension)
{
    int ret;

    ret = kvm_ioctl(s, KVM_CHECK_EXTENSION, extension);
    if (ret < 0) {
        ret = 0;
    }

    return ret;
}

static const KVMCapabilityInfo *
kvm_check_extension_list(KVMState *s, const KVMCapabilityInfo *list)
{
    while (list->name) {
        if (!kvm_check_extension(s, list->value)) {
            return list;
        }
        list++;
    }
    return NULL;
}

static void kvm_set_phys_mem(target_phys_addr_t start_addr, ram_addr_t size,
                             ram_addr_t phys_offset, bool log_dirty)
{
    KVMState *s = kvm_state;
    ram_addr_t flags = phys_offset & ~TARGET_PAGE_MASK;
    KVMSlot *mem, old;
    int err;

    /* kvm works in page size chunks, but the function may be called
       with sub-page size and unaligned start address. */
    size = TARGET_PAGE_ALIGN(size);
    start_addr = TARGET_PAGE_ALIGN(start_addr);

    /* KVM does not support read-only slots */
    phys_offset &= ~IO_MEM_ROM;

    while (1) {
        mem = kvm_lookup_overlapping_slot(s, start_addr, start_addr + size);
        if (!mem) {
            break;
        }

        if (flags < IO_MEM_UNASSIGNED && start_addr >= mem->start_addr &&
            (start_addr + size <= mem->start_addr + mem->memory_size) &&
            (phys_offset - start_addr == mem->phys_offset - mem->start_addr)) {
            /* The new slot fits into the existing one and comes with
             * identical parameters - update flags and done. */
            kvm_slot_dirty_pages_log_change(mem, log_dirty);
            return;
        }

        old = *mem;

        /* unregister the overlapping slot */
        mem->memory_size = 0;
        err = kvm_set_user_memory_region(s, mem);
        if (err) {
            fprintf(stderr, "%s: error unregistering overlapping slot: %s\n",
                    __func__, strerror(-err));
            abort();
        }

        /* Workaround for older KVM versions: we can't join slots, even not by
         * unregistering the previous ones and then registering the larger
         * slot. We have to maintain the existing fragmentation. Sigh.
         *
         * This workaround assumes that the new slot starts at the same
         * address as the first existing one. If not or if some overlapping
         * slot comes around later, we will fail (not seen in practice so far)
         * - and actually require a recent KVM version. */
        if (s->broken_set_mem_region &&
            old.start_addr == start_addr && old.memory_size < size &&
            flags < IO_MEM_UNASSIGNED) {
            mem = kvm_alloc_slot(s);
            mem->memory_size = old.memory_size;
            mem->start_addr = old.start_addr;
            mem->phys_offset = old.phys_offset;
            mem->flags = kvm_mem_flags(s, log_dirty);

            err = kvm_set_user_memory_region(s, mem);
            if (err) {
                fprintf(stderr, "%s: error updating slot: %s\n", __func__,
                        strerror(-err));
                abort();
            }

            start_addr += old.memory_size;
            phys_offset += old.memory_size;
            size -= old.memory_size;
            continue;
        }

        /* register prefix slot */
        if (old.start_addr < start_addr) {
            mem = kvm_alloc_slot(s);
            mem->memory_size = start_addr - old.start_addr;
            mem->start_addr = old.start_addr;
            mem->phys_offset = old.phys_offset;
            mem->flags =  kvm_mem_flags(s, log_dirty);

            err = kvm_set_user_memory_region(s, mem);
            if (err) {
                fprintf(stderr, "%s: error registering prefix slot: %s\n",
                        __func__, strerror(-err));
                abort();
            }
        }

        /* register suffix slot */
        if (old.start_addr + old.memory_size > start_addr + size) {
            ram_addr_t size_delta;

            mem = kvm_alloc_slot(s);
            mem->start_addr = start_addr + size;
            size_delta = mem->start_addr - old.start_addr;
            mem->memory_size = old.memory_size - size_delta;
            mem->phys_offset = old.phys_offset + size_delta;
            mem->flags = kvm_mem_flags(s, log_dirty);

            err = kvm_set_user_memory_region(s, mem);
            if (err) {
                fprintf(stderr, "%s: error registering suffix slot: %s\n",
                        __func__, strerror(-err));
                abort();
            }
        }
    }

    /* in case the KVM bug workaround already "consumed" the new slot */
    if (!size) {
        return;
    }
    /* KVM does not need to know about this memory */
    if (flags >= IO_MEM_UNASSIGNED) {
        return;
    }
    mem = kvm_alloc_slot(s);
    mem->memory_size = size;
    mem->start_addr = start_addr;
    mem->phys_offset = phys_offset;
    mem->flags = kvm_mem_flags(s, log_dirty);

    err = kvm_set_user_memory_region(s, mem);
    if (err) {
        fprintf(stderr, "%s: error registering slot: %s\n", __func__,
                strerror(-err));
        abort();
    }
}

static void kvm_client_set_memory(struct CPUPhysMemoryClient *client,
                                  target_phys_addr_t start_addr,
                                  ram_addr_t size, ram_addr_t phys_offset,
                                  bool log_dirty)
{
    kvm_set_phys_mem(start_addr, size, phys_offset, log_dirty);
}

static int kvm_client_sync_dirty_bitmap(struct CPUPhysMemoryClient *client,
                                        target_phys_addr_t start_addr,
                                        target_phys_addr_t end_addr)
{
    return kvm_physical_sync_dirty_bitmap(start_addr, end_addr);
}

static CPUPhysMemoryClient kvm_cpu_phys_memory_client = {
    .set_memory = kvm_client_set_memory,
    .sync_dirty_bitmap = kvm_client_sync_dirty_bitmap,
};

static void kvm_handle_interrupt(CPUState *env, int mask)
{
    env->interrupt_request |= mask;

    if (!qemu_cpu_is_self(env)) {
        qemu_cpu_kick(env);
    }
}
CPUInterruptHandler cpu_interrupt_handler = NULL;
int kvm_init(void)
{
    static const char upgrade_note[] =
        "Please upgrade to at least kernel 2.6.29 or recent kvm-kmod\n"
        "(see http://sourceforge.net/projects/kvm).\n";
    KVMState *s;
    const KVMCapabilityInfo *missing_cap;
    int ret;
    int i;

    s = calloc(1, sizeof(KVMState));

    for (i = 0; i < ARRAY_SIZE(s->slots); i++) {
        s->slots[i].slot = i;
    }
    s->vmfd = -1;
    s->fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (s->fd == -1) {
        fprintf(stderr, "Could not access KVM kernel module: %m\n");
        ret = -errno;
        goto err;
    }

    ret = kvm_ioctl(s, KVM_GET_API_VERSION, 0);
    if (ret < KVM_API_VERSION) {
        if (ret > 0) {
            ret = -EINVAL;
        }
        fprintf(stderr, "kvm version too old\n");
        goto err;
    }

    if (ret > KVM_API_VERSION) {
        ret = -EINVAL;
        fprintf(stderr, "kvm version not supported\n");
        goto err;
    }

    s->vmfd = kvm_ioctl(s, KVM_CREATE_VM, 0);
    if (s->vmfd < 0) {
        ret = s->vmfd;
        goto err;
    }

    missing_cap = kvm_check_extension_list(s, kvm_required_capabilites);
    if (!missing_cap) {
        missing_cap =
            kvm_check_extension_list(s, kvm_arch_required_capabilities);
    }
    if (missing_cap) {
        ret = -EINVAL;
        fprintf(stderr, "kvm does not support %s\n%s",
                missing_cap->name, upgrade_note);
        goto err;
    }

    s->coalesced_mmio = kvm_check_extension(s, KVM_CAP_COALESCED_MMIO);

    s->broken_set_mem_region = 1;
    ret = kvm_check_extension(s, KVM_CAP_JOIN_MEMORY_REGIONS_WORKS);
    if (ret > 0) {
        s->broken_set_mem_region = 0;
    }

    ret = kvm_arch_init(s);
    if (ret < 0) {
        goto err;
    }

    kvm_state = s;
    cpu_register_phys_memory_client(&kvm_cpu_phys_memory_client);

    cpu_interrupt_handler = kvm_handle_interrupt;

    return 0;

err:
    if (s) {
        if (s->vmfd >= 0) {
            close(s->vmfd);
        }
        if (s->fd != -1) {
            close(s->fd);
        }
    }
    free(s);
    s = NULL;

    return ret;
}

static void kvm_handle_io(uint16_t port, void *data, int direction, int size,
                          uint32_t count)
{
    int i;
    uint8_t *ptr = data;

    for (i = 0; i < count; i++) {
        if (direction == KVM_EXIT_IO_IN) {
            switch (size) {
            case 1:
                stb_p(ptr, cpu_inb(port));
                break;
            case 2:
                stw_p(ptr, cpu_inw(port));
                break;
            case 4:
                stl_p(ptr, cpu_inl(port));
                break;
            }
        } else {
            switch (size) {
            case 1:
                cpu_outb(port, ldub_p(ptr));
                break;
            case 2:
                cpu_outw(port, lduw_p(ptr));
                break;
            case 4:
                cpu_outl(port, ldl_p(ptr));
                break;
            }
        }

        ptr += size;
    }
}

void kvm_flush_coalesced_mmio_buffer(void)
{
    KVMState *s = kvm_state;

    if (s->coalesced_flush_in_progress) {
        return;
    }

    s->coalesced_flush_in_progress = true;

    if (s->coalesced_mmio_ring) {
        struct kvm_coalesced_mmio_ring *ring = s->coalesced_mmio_ring;
        while (ring->first != ring->last) {
            struct kvm_coalesced_mmio *ent;

            ent = &ring->coalesced_mmio[ring->first];

            cpu_physical_memory_write(ent->phys_addr, ent->data, ent->len);
            asm volatile("" ::: "memory");
            ring->first = (ring->first + 1) % KVM_COALESCED_MMIO_MAX;
        }
    }

    s->coalesced_flush_in_progress = false;
}

static void do_kvm_cpu_synchronize_state(void *_env)
{
    CPUState *env = _env;

    if (!env->kvm_vcpu_dirty) {
        kvm_arch_get_registers(env);
        env->kvm_vcpu_dirty = 1;
    }
}

void kvm_cpu_synchronize_state(CPUState *env)
{
    if (!env->kvm_vcpu_dirty) {
        run_on_cpu(env, do_kvm_cpu_synchronize_state, env);
    }
}

void kvm_cpu_synchronize_post_reset(CPUState *env)
{
    kvm_arch_put_registers(env, KVM_PUT_RESET_STATE);
    env->kvm_vcpu_dirty = 0;
}

void kvm_cpu_synchronize_post_init(CPUState *env)
{
    kvm_arch_put_registers(env, KVM_PUT_FULL_STATE);
    env->kvm_vcpu_dirty = 0;
}

int kvm_cpu_exec(CPUState *env)
{
    struct kvm_run *run = env->kvm_run;
    int ret, run_ret;

    DPRINTF("kvm_cpu_exec()\n");

    if (kvm_arch_process_async_events(env)) {
        env->exit_request = 0;
        return EXCP_HLT;
    }

    cpu_single_env = env;

    do {
        if (env->kvm_vcpu_dirty) {
            kvm_arch_put_registers(env, KVM_PUT_RUNTIME_STATE);
            env->kvm_vcpu_dirty = 0;
        }

        kvm_arch_pre_run(env, run);
        if (env->exit_request) {
            DPRINTF("interrupt exit requested\n");
            /*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
            qemu_cpu_kick_self();
        }
        cpu_single_env = NULL;
        qemu_mutex_unlock_iothread();

        run_ret = kvm_vcpu_ioctl(env, KVM_RUN, 0);

        qemu_mutex_lock_iothread();
        cpu_single_env = env;
        kvm_arch_post_run(env, run);

        kvm_flush_coalesced_mmio_buffer();

        if (run_ret < 0) {
            if (run_ret == -EINTR || run_ret == -EAGAIN) {
                DPRINTF("io window exit\n");
                ret = EXCP_INTERRUPT;
                break;
            }
            DPRINTF("kvm run failed %s\n", strerror(-run_ret));
            abort();
        }

        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
            //printf("handle_io %d\n", run->io.port);
            kvm_handle_io(run->io.port,
                          (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                          run->io.size,
                          run->io.count);
            ret = 0;
            break;
        case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
            cpu_physical_memory_rw(run->mmio.phys_addr,
                                   run->mmio.data,
                                   run->mmio.len,
                                   run->mmio.is_write);
            ret = 0;
            break;
        case KVM_EXIT_IRQ_WINDOW_OPEN:
            DPRINTF("irq_window_open\n");
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_SHUTDOWN:
            DPRINTF("shutdown\n");
            qemu_system_reset_request();
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_UNKNOWN:
            fprintf(stderr, "KVM: unknown exit, hardware reason %" PRIx64 "\n",
                    (uint64_t)run->hw.hardware_exit_reason);
            ret = -1;
            break;
        default:
            DPRINTF("kvm_arch_handle_exit\n");
            ret = kvm_arch_handle_exit(env, run);
            break;
        }
    } while (ret == 0);

    if (ret < 0) {
        cpu_dump_state(env, stdout, fprintf, 0);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    env->exit_request = 0;
    cpu_single_env = NULL;
    return ret;
}

int kvm_ioctl(KVMState *s, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(s->fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_vm_ioctl(KVMState *s, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(s->vmfd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_vcpu_ioctl(CPUState *env, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(env->kvm_fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_has_sync_mmu(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_SYNC_MMU);
}

void kvm_setup_guest_memory(void *start, size_t size)
{
    if (!kvm_has_sync_mmu()) {
        int ret = madvise(start, size, MADV_DONTFORK);

        if (ret) {
            perror("madvise");
            fprintf(stderr,
                    "Need MADV_DONTFORK in absence of synchronous KVM MMU\n");
            exit(1);
        }
    }
}

int kvm_set_signal_mask(CPUState *env, const sigset_t *sigset)
{
    struct kvm_signal_mask *sigmask;
    int r;

    if (!sigset) {
        return kvm_vcpu_ioctl(env, KVM_SET_SIGNAL_MASK, NULL);
    }

    sigmask = malloc(sizeof(*sigmask) + sizeof(*sigset));

    sigmask->len = 8;
    memcpy(sigmask->sigset, sigset, sizeof(*sigset));
    r = kvm_vcpu_ioctl(env, KVM_SET_SIGNAL_MASK, sigmask);
    free(sigmask);
    sigmask = NULL;

    return r;
}

int kvm_on_sigbus_vcpu(CPUState *env, int code, void *addr)
{
    return kvm_arch_on_sigbus_vcpu(env, code, addr);
}

int kvm_on_sigbus(int code, void *addr)
{
    return kvm_arch_on_sigbus(code, addr);
}

/*
 * QEMU KVM support
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */


//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MSR_KVM_WALL_CLOCK  0x11
#define MSR_KVM_SYSTEM_TIME 0x12

#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif
#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_INFO(SET_TSS_ADDR),
    KVM_CAP_INFO(EXT_CPUID),
    KVM_CAP_INFO(MP_STATE),
    KVM_CAP_LAST_INFO
};

static bool has_msr_star;
static bool has_msr_hsave_pa;
static bool has_msr_tsc_deadline;
static bool has_msr_misc_enable;
static int lm_capable_kernel;

static struct kvm_cpuid2 *try_get_cpuid(KVMState *s, int max)
{
    struct kvm_cpuid2 *cpuid;
    int r, size;

    size = sizeof(*cpuid) + max * sizeof(*cpuid->entries);
    cpuid = (struct kvm_cpuid2 *)calloc(1, size);
    cpuid->nent = max;
    r = kvm_ioctl(s, KVM_GET_SUPPORTED_CPUID, cpuid);
    if (r == 0 && cpuid->nent >= max) {
        r = -E2BIG;
    }
    if (r < 0) {
        if (r == -E2BIG) {
            free(cpuid);
            cpuid = NULL;
            return NULL;
        } else {
            fprintf(stderr, "KVM_GET_SUPPORTED_CPUID failed: %s\n",
                    strerror(-r));
            exit(1);
        }
    }
    return cpuid;
}

struct kvm_para_features {
    int cap;
    int feature;
} para_features[] = {
    { KVM_CAP_CLOCKSOURCE, KVM_FEATURE_CLOCKSOURCE },
    { KVM_CAP_NOP_IO_DELAY, KVM_FEATURE_NOP_IO_DELAY },
    { KVM_CAP_PV_MMU, KVM_FEATURE_MMU_OP },
    { -1, -1 }
};

static int get_para_features(KVMState *s)
{
    int i, features = 0;

    for (i = 0; i < ARRAY_SIZE(para_features) - 1; i++) {
        if (kvm_check_extension(s, para_features[i].cap)) {
            features |= (1 << para_features[i].feature);
        }
    }

    return features;
}


uint32_t kvm_arch_get_supported_cpuid(KVMState *s, uint32_t function,
                                      uint32_t index, int reg)
{
    struct kvm_cpuid2 *cpuid;
    int i, max;
    uint32_t ret = 0;
    uint32_t cpuid_1_edx;
    int has_kvm_features = 0;

    max = 1;
    while ((cpuid = try_get_cpuid(s, max)) == NULL) {
        max *= 2;
    }

    for (i = 0; i < cpuid->nent; ++i) {
        if (cpuid->entries[i].function == function &&
            cpuid->entries[i].index == index) {
            if (cpuid->entries[i].function == KVM_CPUID_FEATURES) {
                has_kvm_features = 1;
            }
            switch (reg) {
            case R_EAX:
                ret = cpuid->entries[i].eax;
                break;
            case R_EBX:
                ret = cpuid->entries[i].ebx;
                break;
            case R_ECX:
                ret = cpuid->entries[i].ecx;
                break;
            case R_EDX:
                ret = cpuid->entries[i].edx;
                switch (function) {
                case 1:
                    /* KVM before 2.6.30 misreports the following features */
                    ret |= CPUID_MTRR | CPUID_PAT | CPUID_MCE | CPUID_MCA;
                    break;
                case 0x80000001:
                    /* On Intel, kvm returns cpuid according to the Intel spec,
                     * so add missing bits according to the AMD spec:
                     */
                    cpuid_1_edx = kvm_arch_get_supported_cpuid(s, 1, 0, R_EDX);
                    ret |= cpuid_1_edx & 0x183f7ff;
                    break;
                }
                break;
            }
        }
    }

    free(cpuid);
    cpuid = NULL;

    /* fallback for older kernels */
    if (!has_kvm_features && (function == KVM_CPUID_FEATURES)) {
        ret = get_para_features(s);
    }

    return ret;
}

typedef struct HWPoisonPage {
    ram_addr_t ram_addr;
    QLIST_ENTRY(HWPoisonPage) list;
} HWPoisonPage;

static QLIST_HEAD(, HWPoisonPage) hwpoison_page_list =
    QLIST_HEAD_INITIALIZER(hwpoison_page_list);

static void kvm_unpoison_all(void *param)
{
    HWPoisonPage *page, *next_page;

    QLIST_FOREACH_SAFE(page, &hwpoison_page_list, list, next_page) {
        QLIST_REMOVE(page, list);
        qemu_ram_remap(page->ram_addr, TARGET_PAGE_SIZE);
        free(page);
        page = NULL;
    }
}

static void kvm_hwpoison_page_add(ram_addr_t ram_addr)
{
    HWPoisonPage *page;

    QLIST_FOREACH(page, &hwpoison_page_list, list) {
        if (page->ram_addr == ram_addr) {
            return;
        }
    }
    page = malloc(sizeof(HWPoisonPage));
    page->ram_addr = ram_addr;
    QLIST_INSERT_HEAD(&hwpoison_page_list, page, list);
}

static void kvm_mce_inject(CPUState *env, target_phys_addr_t paddr, int code)
{
    uint64_t status = MCI_STATUS_VAL | MCI_STATUS_UC | MCI_STATUS_EN |
                      MCI_STATUS_MISCV | MCI_STATUS_ADDRV | MCI_STATUS_S;
    uint64_t mcg_status = MCG_STATUS_MCIP;

    if (code == BUS_MCEERR_AR) {
        status |= MCI_STATUS_AR | 0x134;
        mcg_status |= MCG_STATUS_EIPV;
    } else {
        status |= 0xc0;
        mcg_status |= MCG_STATUS_RIPV;
    }
    cpu_x86_inject_mce(env, 9, status, mcg_status, paddr,
                       (MCM_ADDR_PHYS << 6) | 0xc,
                       cpu_x86_support_mca_broadcast(env) ?
                       MCE_INJECT_BROADCAST : 0);
}

static void hardware_memory_error(void)
{
    fprintf(stderr, "Hardware memory error!\n");
    exit(1);
}

int kvm_arch_on_sigbus_vcpu(CPUState *env, int code, void *addr)
{
    ram_addr_t ram_addr;
    target_phys_addr_t paddr = 0;

    if ((env->mcg_cap & MCG_SER_P) && addr
        && (code == BUS_MCEERR_AR || code == BUS_MCEERR_AO)) {
        if (qemu_ram_addr_from_host(addr, &ram_addr) ||
            !kvm_physical_memory_addr_from_ram(env->kvm_state, ram_addr,
                                               &paddr)) {
            fprintf(stderr, "Hardware memory error for memory used by "
                    "QEMU itself instead of guest system!\n");
            /* Hope we are lucky for AO MCE */
            if (code == BUS_MCEERR_AO) {
                return 0;
            } else {
                hardware_memory_error();
            }
        }
        kvm_hwpoison_page_add(ram_addr);
        kvm_mce_inject(env, paddr, code);
    } else {
        if (code == BUS_MCEERR_AO) {
            return 0;
        } else if (code == BUS_MCEERR_AR) {
            hardware_memory_error();
        } else {
            return 1;
        }
    }
    return 0;
}

int kvm_arch_on_sigbus(int code, void *addr)
{
    if ((first_cpu->mcg_cap & MCG_SER_P) && addr && code == BUS_MCEERR_AO) {
        ram_addr_t ram_addr;
        target_phys_addr_t paddr;

        /* Hope we are lucky for AO MCE */
        if (qemu_ram_addr_from_host(addr, &ram_addr) ||
            !kvm_physical_memory_addr_from_ram(first_cpu->kvm_state, ram_addr,
                                               &paddr)) {
            fprintf(stderr, "Hardware memory error for memory used by "
                    "QEMU itself instead of guest system!: %p\n", addr);
            return 0;
        }
        kvm_hwpoison_page_add(ram_addr);
        kvm_mce_inject(first_cpu, paddr, code);
    } else {
        if (code == BUS_MCEERR_AO) {
            return 0;
        } else if (code == BUS_MCEERR_AR) {
            hardware_memory_error();
        } else {
            return 1;
        }
    }
    return 0;
}

static void cpu_update_state(void *opaque, int running, RunState state)
{
    CPUState *env = opaque;

    if (running) {
        env->tsc_valid = false;
    }
}

int kvm_arch_init_vcpu(CPUState *env)
{
    struct {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[100];
    } QEMU_PACKED cpuid_data;
    KVMState *s = env->kvm_state;
    uint32_t limit, i, j, cpuid_i;
    uint32_t unused;
    struct kvm_cpuid_entry2 *c;
    uint32_t signature[3];
    int r;

    env->cpuid_features &= kvm_arch_get_supported_cpuid(s, 1, 0, R_EDX);

    i = env->cpuid_ext_features & CPUID_EXT_HYPERVISOR;
    env->cpuid_ext_features &= kvm_arch_get_supported_cpuid(s, 1, 0, R_ECX);
    env->cpuid_ext_features |= i;

    env->cpuid_ext2_features &= kvm_arch_get_supported_cpuid(s, 0x80000001,
                                                             0, R_EDX);
    env->cpuid_ext3_features &= kvm_arch_get_supported_cpuid(s, 0x80000001,
                                                             0, R_ECX);
    env->cpuid_svm_features  &= kvm_arch_get_supported_cpuid(s, 0x8000000A,
                                                             0, R_EDX);

    cpuid_i = 0;

    /* Paravirtualization CPUIDs */
    memcpy(signature, "KVMKVMKVM\0\0\0", 12);
    c = &cpuid_data.entries[cpuid_i++];
    memset(c, 0, sizeof(*c));
    c->function = KVM_CPUID_SIGNATURE;
    c->eax = 0;
    c->ebx = signature[0];
    c->ecx = signature[1];
    c->edx = signature[2];

    c = &cpuid_data.entries[cpuid_i++];
    memset(c, 0, sizeof(*c));
    c->function = KVM_CPUID_FEATURES;
    c->eax = env->cpuid_kvm_features &
        kvm_arch_get_supported_cpuid(s, KVM_CPUID_FEATURES, 0, R_EAX);

    cpu_x86_cpuid(env, 0, 0, &limit, &unused, &unused, &unused);

    for (i = 0; i <= limit; i++) {
        c = &cpuid_data.entries[cpuid_i++];

        switch (i) {
        case 2: {
            /* Keep reading function 2 till all the input is received */
            int times;

            c->function = i;
            c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC |
                       KVM_CPUID_FLAG_STATE_READ_NEXT;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax & 0xff;

            for (j = 1; j < times; ++j) {
                c = &cpuid_data.entries[cpuid_i++];
                c->function = i;
                c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC;
                cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        case 4:
        case 0xb:
        case 0xd:
            for (j = 0; ; j++) {
                if (i == 0xd && j == 64) {
                    break;
                }
                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (i == 4 && c->eax == 0) {
                    break;
                }
                if (i == 0xb && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0xd && c->eax == 0) {
                    continue;
                }
                c = &cpuid_data.entries[cpuid_i++];
            }
            break;
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            break;
        }
    }
    cpu_x86_cpuid(env, 0x80000000, 0, &limit, &unused, &unused, &unused);

    for (i = 0x80000000; i <= limit; i++) {
        c = &cpuid_data.entries[cpuid_i++];

        c->function = i;
        c->flags = 0;
        cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
    }

    /* Call Centaur's CPUID instructions they are supported. */
    if (env->cpuid_xlevel2 > 0) {
        env->cpuid_ext4_features &=
            kvm_arch_get_supported_cpuid(s, 0xC0000001, 0, R_EDX);
        cpu_x86_cpuid(env, 0xC0000000, 0, &limit, &unused, &unused, &unused);

        for (i = 0xC0000000; i <= limit; i++) {
            c = &cpuid_data.entries[cpuid_i++];

            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
        }
    }

    cpuid_data.cpuid.nent = cpuid_i;

    qemu_add_vm_change_state_handler(cpu_update_state, env);

    r = kvm_vcpu_ioctl(env, KVM_SET_CPUID2, &cpuid_data);
    if (r) {
        return r;
    }

    return 0;
}

void kvm_arch_reset_vcpu(CPUState *env)
{
    env->exception_injected = -1;
    env->interrupt_injected = -1;
    env->xcr0 = 1;
    if (kvm_irqchip_in_kernel()) {
        env->mp_state = cpu_is_bsp(env) ? KVM_MP_STATE_RUNNABLE :
                                          KVM_MP_STATE_UNINITIALIZED;
    } else {
        env->mp_state = KVM_MP_STATE_RUNNABLE;
    }
}

static int kvm_get_supported_msrs(KVMState *s)
{
    static int kvm_supported_msrs;
    int ret = 0;

    /* first time */
    if (kvm_supported_msrs == 0) {
        struct kvm_msr_list msr_list, *kvm_msr_list;

        kvm_supported_msrs = -1;

        /* Obtain MSR list from KVM.  These are the MSRs that we must
         * save/restore */
        msr_list.nmsrs = 0;
        ret = kvm_ioctl(s, KVM_GET_MSR_INDEX_LIST, &msr_list);
        if (ret < 0 && ret != -E2BIG) {
            return ret;
        }
        /* Old kernel modules had a bug and could write beyond the provided
           memory. Allocate at least a safe amount of 1K. */
        kvm_msr_list = calloc(1, MAX(1024, sizeof(msr_list) +
                                              msr_list.nmsrs *
                                              sizeof(msr_list.indices[0])));

        kvm_msr_list->nmsrs = msr_list.nmsrs;
        ret = kvm_ioctl(s, KVM_GET_MSR_INDEX_LIST, kvm_msr_list);
        if (ret >= 0) {
            int i;

            for (i = 0; i < kvm_msr_list->nmsrs; i++) {
                if (kvm_msr_list->indices[i] == MSR_STAR) {
                    has_msr_star = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_VM_HSAVE_PA) {
                    has_msr_hsave_pa = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_TSCDEADLINE) {
                    has_msr_tsc_deadline = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_MISC_ENABLE) {
                    has_msr_misc_enable = true;
                    continue;
                }
            }
        }

        free(kvm_msr_list);
        kvm_msr_list = NULL;
    }

    return ret;
}

int kvm_arch_init(KVMState *s)
{
    uint64_t identity_base = 0xfffbc000;
    struct utsname utsname;
    int ret;

    ret = kvm_get_supported_msrs(s);
    if (ret < 0) {
        return ret;
    }

    uname(&utsname);
    lm_capable_kernel = strcmp(utsname.machine, "x86_64") == 0;

    /* Set TSS base one page after EPT identity map. */
    ret = kvm_vm_ioctl(s, KVM_SET_TSS_ADDR, identity_base + 0x1000);
    if (ret < 0) {
        return ret;
    }

    /* Tell fw_cfg to notify the BIOS to reserve the range. */
    ret = e820_add_entry(identity_base, 0x4000, E820_RESERVED);
    if (ret < 0) {
        fprintf(stderr, "e820_add_entry() table is full\n");
        return ret;
    }
    qemu_register_reset(kvm_unpoison_all, NULL);

    return 0;
}

static void set_v8086_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = 3;
    lhs->present = 1;
    lhs->dpl = 3;
    lhs->db = 0;
    lhs->s = 1;
    lhs->l = 0;
    lhs->g = 0;
    lhs->avl = 0;
    lhs->unusable = 0;
}

static void set_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = 0;
}

static void get_seg(SegmentCache *lhs, const struct kvm_segment *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->flags = (rhs->type << DESC_TYPE_SHIFT) |
                 (rhs->present * DESC_P_MASK) |
                 (rhs->dpl << DESC_DPL_SHIFT) |
                 (rhs->db << DESC_B_SHIFT) |
                 (rhs->s * DESC_S_MASK) |
                 (rhs->l << DESC_L_SHIFT) |
                 (rhs->g * DESC_G_MASK) |
                 (rhs->avl * DESC_AVL_MASK);
}

static void kvm_getput_reg(__u64 *kvm_reg, target_ulong *qemu_reg, int set)
{
    if (set) {
        *kvm_reg = *qemu_reg;
    } else {
        *qemu_reg = *kvm_reg;
    }
}

static int kvm_getput_regs(CPUState *env, int set)
{
    struct kvm_regs regs;
    int ret = 0;

    if (!set) {
        ret = kvm_vcpu_ioctl(env, KVM_GET_REGS, &regs);
        if (ret < 0) {
            return ret;
        }
    }

    kvm_getput_reg(&regs.rax, &env->regs[R_EAX], set);
    kvm_getput_reg(&regs.rbx, &env->regs[R_EBX], set);
    kvm_getput_reg(&regs.rcx, &env->regs[R_ECX], set);
    kvm_getput_reg(&regs.rdx, &env->regs[R_EDX], set);
    kvm_getput_reg(&regs.rsi, &env->regs[R_ESI], set);
    kvm_getput_reg(&regs.rdi, &env->regs[R_EDI], set);
    kvm_getput_reg(&regs.rsp, &env->regs[R_ESP], set);
    kvm_getput_reg(&regs.rbp, &env->regs[R_EBP], set);
    kvm_getput_reg(&regs.r8, &env->regs[8], set);
    kvm_getput_reg(&regs.r9, &env->regs[9], set);
    kvm_getput_reg(&regs.r10, &env->regs[10], set);
    kvm_getput_reg(&regs.r11, &env->regs[11], set);
    kvm_getput_reg(&regs.r12, &env->regs[12], set);
    kvm_getput_reg(&regs.r13, &env->regs[13], set);
    kvm_getput_reg(&regs.r14, &env->regs[14], set);
    kvm_getput_reg(&regs.r15, &env->regs[15], set);

    kvm_getput_reg(&regs.rflags, &env->eflags, set);
    kvm_getput_reg(&regs.rip, &env->eip, set);

    if (set) {
        ret = kvm_vcpu_ioctl(env, KVM_SET_REGS, &regs);
    }

    return ret;
}

static int kvm_put_fpu(CPUState *env)
{
    struct kvm_fpu fpu;
    int i;

    memset(&fpu, 0, sizeof fpu);
    fpu.fsw = env->fpus & ~(7 << 11);
    fpu.fsw |= (env->fpstt & 7) << 11;
    fpu.fcw = env->fpuc;
    fpu.last_opcode = env->fpop;
    fpu.last_ip = env->fpip;
    fpu.last_dp = env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu.ftwx |= (!env->fptags[i]) << i;
    }
    memcpy(fpu.fpr, env->fpregs, sizeof env->fpregs);
    memcpy(fpu.xmm, env->xmm_regs, sizeof env->xmm_regs);
    fpu.mxcsr = env->mxcsr;

    return kvm_vcpu_ioctl(env, KVM_SET_FPU, &fpu);
}


static int kvm_put_sregs(CPUState *env)
{
    struct kvm_sregs sregs;

    memset(sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));
    if (env->interrupt_injected >= 0) {
        sregs.interrupt_bitmap[env->interrupt_injected / 64] |=
                (uint64_t)1 << (env->interrupt_injected % 64);
    }

    if ((env->eflags & VM_MASK)) {
        set_v8086_seg(&sregs.cs, &env->segs[R_CS]);
        set_v8086_seg(&sregs.ds, &env->segs[R_DS]);
        set_v8086_seg(&sregs.es, &env->segs[R_ES]);
        set_v8086_seg(&sregs.fs, &env->segs[R_FS]);
        set_v8086_seg(&sregs.gs, &env->segs[R_GS]);
        set_v8086_seg(&sregs.ss, &env->segs[R_SS]);
    } else {
        set_seg(&sregs.cs, &env->segs[R_CS]);
        set_seg(&sregs.ds, &env->segs[R_DS]);
        set_seg(&sregs.es, &env->segs[R_ES]);
        set_seg(&sregs.fs, &env->segs[R_FS]);
        set_seg(&sregs.gs, &env->segs[R_GS]);
        set_seg(&sregs.ss, &env->segs[R_SS]);
    }

    set_seg(&sregs.tr, &env->tr);
    set_seg(&sregs.ldt, &env->ldt);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];

    sregs.cr8 = cpu_get_apic_tpr(env->apic_state);
    sregs.apic_base = cpu_get_apic_base(env->apic_state);

    sregs.efer = env->efer;

    return kvm_vcpu_ioctl(env, KVM_SET_SREGS, &sregs);
}

static void kvm_msr_entry_set(struct kvm_msr_entry *entry,
                              uint32_t index, uint64_t value)
{
    entry->index = index;
    entry->data = value;
}

static int kvm_put_msrs(CPUState *env, int level)
{
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[100];
    } msr_data;
    struct kvm_msr_entry *msrs = msr_data.entries;
    int n = 0;

    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_CS, env->sysenter_cs);
    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    kvm_msr_entry_set(&msrs[n++], MSR_PAT, env->pat);
    if (has_msr_star) {
        kvm_msr_entry_set(&msrs[n++], MSR_STAR, env->star);
    }
    if (has_msr_hsave_pa) {
        kvm_msr_entry_set(&msrs[n++], MSR_VM_HSAVE_PA, env->vm_hsave);
    }
    if (has_msr_tsc_deadline) {
        kvm_msr_entry_set(&msrs[n++], MSR_IA32_TSCDEADLINE, env->tsc_deadline);
    }
    if (has_msr_misc_enable) {
        kvm_msr_entry_set(&msrs[n++], MSR_IA32_MISC_ENABLE,
                          env->msr_ia32_misc_enable);
    }
    if (lm_capable_kernel) {
        kvm_msr_entry_set(&msrs[n++], MSR_CSTAR, env->cstar);
        kvm_msr_entry_set(&msrs[n++], MSR_KERNELGSBASE, env->kernelgsbase);
        kvm_msr_entry_set(&msrs[n++], MSR_FMASK, env->fmask);
        kvm_msr_entry_set(&msrs[n++], MSR_LSTAR, env->lstar);
    }
    if (level == KVM_PUT_FULL_STATE) {
        /*
         * KVM is yet unable to synchronize TSC values of multiple VCPUs on
         * writeback. Until this is fixed, we only write the offset to SMP
         * guests after migration, desynchronizing the VCPUs, but avoiding
         * huge jump-backs that would occur without any writeback at all.
         */
        if (smp_cpus == 1 || env->tsc != 0) {
            kvm_msr_entry_set(&msrs[n++], MSR_IA32_TSC, env->tsc);
        }
    }
    /*
     * The following paravirtual MSRs have side effects on the guest or are
     * too heavy for normal writeback. Limit them to reset or full state
     * updates.
     */
    if (level >= KVM_PUT_RESET_STATE) {
        kvm_msr_entry_set(&msrs[n++], MSR_KVM_SYSTEM_TIME,
                          env->system_time_msr);
        kvm_msr_entry_set(&msrs[n++], MSR_KVM_WALL_CLOCK, env->wall_clock_msr);
    }
    if (env->mcg_cap) {
        int i;

        kvm_msr_entry_set(&msrs[n++], MSR_MCG_STATUS, env->mcg_status);
        kvm_msr_entry_set(&msrs[n++], MSR_MCG_CTL, env->mcg_ctl);
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
            kvm_msr_entry_set(&msrs[n++], MSR_MC0_CTL + i, env->mce_banks[i]);
        }
    }

    msr_data.info.nmsrs = n;

    return kvm_vcpu_ioctl(env, KVM_SET_MSRS, &msr_data);

}


static int kvm_get_fpu(CPUState *env)
{
    struct kvm_fpu fpu;
    int i, ret;

    ret = kvm_vcpu_ioctl(env, KVM_GET_FPU, &fpu);
    if (ret < 0) {
        return ret;
    }

    env->fpstt = (fpu.fsw >> 11) & 7;
    env->fpus = fpu.fsw;
    env->fpuc = fpu.fcw;
    env->fpop = fpu.last_opcode;
    env->fpip = fpu.last_ip;
    env->fpdp = fpu.last_dp;
    for (i = 0; i < 8; ++i) {
        env->fptags[i] = !((fpu.ftwx >> i) & 1);
    }
    memcpy(env->fpregs, fpu.fpr, sizeof env->fpregs);
    memcpy(env->xmm_regs, fpu.xmm, sizeof env->xmm_regs);
    env->mxcsr = fpu.mxcsr;

    return 0;
}

static int kvm_get_sregs(CPUState *env)
{
    struct kvm_sregs sregs;
    uint32_t hflags;
    int bit, i, ret;

    ret = kvm_vcpu_ioctl(env, KVM_GET_SREGS, &sregs);
    if (ret < 0) {
        return ret;
    }

    /* There can only be one pending IRQ set in the bitmap at a time, so try
       to find it and save its number instead (-1 for none). */
    env->interrupt_injected = -1;
    for (i = 0; i < ARRAY_SIZE(sregs.interrupt_bitmap); i++) {
        if (sregs.interrupt_bitmap[i]) {
            uint64_t val = sregs.interrupt_bitmap[i];
            bit = val? __builtin_ctzll(val):64;
            env->interrupt_injected = i * 64 + bit;
            break;
        }
    }

    get_seg(&env->segs[R_CS], &sregs.cs);
    get_seg(&env->segs[R_DS], &sregs.ds);
    get_seg(&env->segs[R_ES], &sregs.es);
    get_seg(&env->segs[R_FS], &sregs.fs);
    get_seg(&env->segs[R_GS], &sregs.gs);
    get_seg(&env->segs[R_SS], &sregs.ss);

    get_seg(&env->tr, &sregs.tr);
    get_seg(&env->ldt, &sregs.ldt);

    env->idt.limit = sregs.idt.limit;
    env->idt.base = sregs.idt.base;
    env->gdt.limit = sregs.gdt.limit;
    env->gdt.base = sregs.gdt.base;

    env->cr[0] = sregs.cr0;
    env->cr[2] = sregs.cr2;
    env->cr[3] = sregs.cr3;
    env->cr[4] = sregs.cr4;

    cpu_set_apic_base(env->apic_state, sregs.apic_base);

    env->efer = sregs.efer;
    //cpu_set_apic_tpr(env->apic_state, sregs.cr8);

#define HFLAG_COPY_MASK \
    ~( HF_CPL_MASK | HF_PE_MASK | HF_MP_MASK | HF_EM_MASK | \
       HF_TS_MASK | HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK | \
       HF_OSFXSR_MASK | HF_LMA_MASK | HF_CS32_MASK | \
       HF_SS32_MASK | HF_CS64_MASK | HF_ADDSEG_MASK)

    hflags = (env->segs[R_CS].flags >> DESC_DPL_SHIFT) & HF_CPL_MASK;
    hflags |= (env->cr[0] & CR0_PE_MASK) << (HF_PE_SHIFT - CR0_PE_SHIFT);
    hflags |= (env->cr[0] << (HF_MP_SHIFT - CR0_MP_SHIFT)) &
                (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK);
    hflags |= (env->eflags & (HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK));
    hflags |= (env->cr[4] & CR4_OSFXSR_MASK) <<
                (HF_OSFXSR_SHIFT - CR4_OSFXSR_SHIFT);

    if (env->efer & MSR_EFER_LMA) {
        hflags |= HF_LMA_MASK;
    }

    if ((hflags & HF_LMA_MASK) && (env->segs[R_CS].flags & DESC_L_MASK)) {
        hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
    } else {
        hflags |= (env->segs[R_CS].flags & DESC_B_MASK) >>
                    (DESC_B_SHIFT - HF_CS32_SHIFT);
        hflags |= (env->segs[R_SS].flags & DESC_B_MASK) >>
                    (DESC_B_SHIFT - HF_SS32_SHIFT);
        if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK) ||
            !(hflags & HF_CS32_MASK)) {
            hflags |= HF_ADDSEG_MASK;
        } else {
            hflags |= ((env->segs[R_DS].base | env->segs[R_ES].base |
                        env->segs[R_SS].base) != 0) << HF_ADDSEG_SHIFT;
        }
    }
    env->hflags = (env->hflags & HFLAG_COPY_MASK) | hflags;

    return 0;
}

static int kvm_get_msrs(CPUState *env)
{
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[100];
    } msr_data;
    struct kvm_msr_entry *msrs = msr_data.entries;
    int ret, i, n;

    n = 0;
    msrs[n++].index = MSR_IA32_SYSENTER_CS;
    msrs[n++].index = MSR_IA32_SYSENTER_ESP;
    msrs[n++].index = MSR_IA32_SYSENTER_EIP;
    msrs[n++].index = MSR_PAT;
    if (has_msr_star) {
        msrs[n++].index = MSR_STAR;
    }
    if (has_msr_hsave_pa) {
        msrs[n++].index = MSR_VM_HSAVE_PA;
    }
    if (has_msr_tsc_deadline) {
        msrs[n++].index = MSR_IA32_TSCDEADLINE;
    }
    if (has_msr_misc_enable) {
        msrs[n++].index = MSR_IA32_MISC_ENABLE;
    }

    if (!env->tsc_valid) {
        msrs[n++].index = MSR_IA32_TSC;
        env->tsc_valid = !runstate_is_running();
    }

    if (lm_capable_kernel) {
        msrs[n++].index = MSR_CSTAR;
        msrs[n++].index = MSR_KERNELGSBASE;
        msrs[n++].index = MSR_FMASK;
        msrs[n++].index = MSR_LSTAR;
    }
    msrs[n++].index = MSR_KVM_SYSTEM_TIME;
    msrs[n++].index = MSR_KVM_WALL_CLOCK;

    if (env->mcg_cap) {
        msrs[n++].index = MSR_MCG_STATUS;
        msrs[n++].index = MSR_MCG_CTL;
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
            msrs[n++].index = MSR_MC0_CTL + i;
        }
    }

    msr_data.info.nmsrs = n;
    ret = kvm_vcpu_ioctl(env, KVM_GET_MSRS, &msr_data);
    if (ret < 0) {
        return ret;
    }

    for (i = 0; i < ret; i++) {
        switch (msrs[i].index) {
        case MSR_IA32_SYSENTER_CS:
            env->sysenter_cs = msrs[i].data;
            break;
        case MSR_IA32_SYSENTER_ESP:
            env->sysenter_esp = msrs[i].data;
            break;
        case MSR_IA32_SYSENTER_EIP:
            env->sysenter_eip = msrs[i].data;
            break;
        case MSR_PAT:
            env->pat = msrs[i].data;
            break;
        case MSR_STAR:
            env->star = msrs[i].data;
            break;
        case MSR_CSTAR:
            env->cstar = msrs[i].data;
            break;
        case MSR_KERNELGSBASE:
            env->kernelgsbase = msrs[i].data;
            break;
        case MSR_FMASK:
            env->fmask = msrs[i].data;
            break;
        case MSR_LSTAR:
            env->lstar = msrs[i].data;
            break;
        case MSR_IA32_TSC:
            env->tsc = msrs[i].data;
            break;
        case MSR_IA32_TSCDEADLINE:
            env->tsc_deadline = msrs[i].data;
            break;
        case MSR_VM_HSAVE_PA:
            env->vm_hsave = msrs[i].data;
            break;
        case MSR_KVM_SYSTEM_TIME:
            env->system_time_msr = msrs[i].data;
            break;
        case MSR_KVM_WALL_CLOCK:
            env->wall_clock_msr = msrs[i].data;
            break;
        case MSR_MCG_STATUS:
            env->mcg_status = msrs[i].data;
            break;
        case MSR_MCG_CTL:
            env->mcg_ctl = msrs[i].data;
            break;
        case MSR_IA32_MISC_ENABLE:
            env->msr_ia32_misc_enable = msrs[i].data;
            break;
        default:
            if (msrs[i].index >= MSR_MC0_CTL &&
                msrs[i].index < MSR_MC0_CTL + (env->mcg_cap & 0xff) * 4) {
                env->mce_banks[msrs[i].index - MSR_MC0_CTL] = msrs[i].data;
            }
            break;
        }
    }

    return 0;
}

static int kvm_put_mp_state(CPUState *env)
{
    struct kvm_mp_state mp_state = { .mp_state = env->mp_state };

    return kvm_vcpu_ioctl(env, KVM_SET_MP_STATE, &mp_state);
}

static int kvm_get_mp_state(CPUState *env)
{
    struct kvm_mp_state mp_state;
    int ret;

    ret = kvm_vcpu_ioctl(env, KVM_GET_MP_STATE, &mp_state);
    if (ret < 0) {
        return ret;
    }
    env->mp_state = mp_state.mp_state;
    if (kvm_irqchip_in_kernel()) {
        env->halted = (mp_state.mp_state == KVM_MP_STATE_HALTED);
    }
    return 0;
}

int kvm_arch_put_registers(CPUState *env, int level)
{
    int ret;

    assert(cpu_is_stopped(env) || qemu_cpu_is_self(env));

    ret = kvm_getput_regs(env, 1);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_fpu(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_sregs(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_msrs(env, level);
    if (ret < 0) {
        return ret;
    }
    if (level >= KVM_PUT_RESET_STATE) {
        ret = kvm_put_mp_state(env);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int kvm_arch_get_registers(CPUState *env)
{
    int ret;

    assert(cpu_is_stopped(env) || qemu_cpu_is_self(env));

    ret = kvm_getput_regs(env, 0);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_get_fpu(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_get_sregs(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_get_msrs(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_get_mp_state(env);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

void kvm_arch_pre_run(CPUState *env, struct kvm_run *run)
{
    int ret;

    /* Inject NMI */
    if (env->interrupt_request & CPU_INTERRUPT_NMI) {
        env->interrupt_request &= ~CPU_INTERRUPT_NMI;
        DPRINTF("injected NMI\n");
        ret = kvm_vcpu_ioctl(env, KVM_NMI);
        if (ret < 0) {
            fprintf(stderr, "KVM: injection failed, NMI lost (%s)\n",
                    strerror(-ret));
        }
    }

    if (!kvm_irqchip_in_kernel()) {
        /* Force the VCPU out of its inner loop to process the INIT request */
        if (env->interrupt_request & CPU_INTERRUPT_INIT) {
            env->exit_request = 1;
        }

        /* Try to inject an interrupt if the guest can accept it */
        if (run->ready_for_interrupt_injection &&
            (env->interrupt_request & CPU_INTERRUPT_HARD) &&
            (env->eflags & IF_MASK)) {
            int irq;

            env->interrupt_request &= ~CPU_INTERRUPT_HARD;
            irq = cpu_get_pic_interrupt(env);
            if (irq >= 0) {
                struct kvm_interrupt intr;

                intr.irq = irq;
                DPRINTF("injected interrupt %d\n", irq);
                ret = kvm_vcpu_ioctl(env, KVM_INTERRUPT, &intr);
                if (ret < 0) {
                    fprintf(stderr,
                            "KVM: injection failed, interrupt lost (%s)\n",
                            strerror(-ret));
                }
            }
        }

        /* If we have an interrupt but the guest is not ready to receive an
         * interrupt, request an interrupt window exit.  This will
         * cause a return to userspace as soon as the guest is ready to
         * receive interrupts. */
        if ((env->interrupt_request & CPU_INTERRUPT_HARD)) {
            run->request_interrupt_window = 1;
        } else {
            run->request_interrupt_window = 0;
        }

        DPRINTF("setting tpr\n");
        run->cr8 = cpu_get_apic_tpr(env->apic_state);
    }
}

void kvm_arch_post_run(CPUState *env, struct kvm_run *run)
{
    if (run->if_flag) {
        env->eflags |= IF_MASK;
    } else {
        env->eflags &= ~IF_MASK;
    }
    cpu_set_apic_tpr(env->apic_state, run->cr8);
    cpu_set_apic_base(env->apic_state, run->apic_base);
}

int kvm_arch_process_async_events(CPUState *env)
{
    if (env->interrupt_request & CPU_INTERRUPT_MCE) {
        /* We must not raise CPU_INTERRUPT_MCE if it's not supported. */
        assert(env->mcg_cap);

        env->interrupt_request &= ~CPU_INTERRUPT_MCE;

        kvm_cpu_synchronize_state(env);

        if (env->exception_injected == EXCP08_DBLE) {
            /* this means triple fault */
            qemu_system_reset_request();
            env->exit_request = 1;
            return 0;
        }
        env->exception_injected = EXCP12_MCHK;
        env->has_error_code = 0;

        env->halted = 0;
        if (kvm_irqchip_in_kernel() && env->mp_state == KVM_MP_STATE_HALTED) {
            env->mp_state = KVM_MP_STATE_RUNNABLE;
        }
    }

    if (kvm_irqchip_in_kernel()) {
        return 0;
    }

    if (((env->interrupt_request & CPU_INTERRUPT_HARD) &&
         (env->eflags & IF_MASK)) ||
        (env->interrupt_request & CPU_INTERRUPT_NMI)) {
        env->halted = 0;
    }
    if (env->interrupt_request & CPU_INTERRUPT_INIT) {
        kvm_cpu_synchronize_state(env);
        do_cpu_init(env);
    }
    if (env->interrupt_request & CPU_INTERRUPT_SIPI) {
        kvm_cpu_synchronize_state(env);
        do_cpu_sipi(env);
    }

    return env->halted;
}

static int kvm_handle_halt(CPUState *env)
{
    if (!((env->interrupt_request & CPU_INTERRUPT_HARD) &&
          (env->eflags & IF_MASK)) &&
        !(env->interrupt_request & CPU_INTERRUPT_NMI)) {
        env->halted = 1;
        return EXCP_HLT;
    }

    return 0;
}

static bool host_supports_vmx(void)
{
    uint32_t ecx, unused;

    host_cpuid(1, 0, &unused, &unused, &ecx, &unused);
    return ecx & CPUID_EXT_VMX;
}

#define VMX_INVALID_GUEST_STATE 0x80000021

int kvm_arch_handle_exit(CPUState *env, struct kvm_run *run)
{
    uint64_t code;
    int ret = -1;

    switch (run->exit_reason) {
    case KVM_EXIT_HLT:
        DPRINTF("handle_hlt\n");
        ret = kvm_handle_halt(env);
        break;
    case KVM_EXIT_SET_TPR:
        ret = 0;
        break;
    case KVM_EXIT_FAIL_ENTRY:
        code = run->fail_entry.hardware_entry_failure_reason;
        fprintf(stderr, "KVM: entry failed, hardware error 0x%" PRIx64 "\n",
                code);
        if (host_supports_vmx() && code == VMX_INVALID_GUEST_STATE) {
            fprintf(stderr,
                    "\nIf you're runnning a guest on an Intel machine without "
                        "unrestricted mode\n"
                    "support, the failure can be most likely due to the guest "
                        "entering an invalid\n"
                    "state for Intel VT. For example, the guest maybe running "
                        "in big real mode\n"
                    "which is not supported on less recent Intel processors."
                        "\n\n");
        }
        ret = -1;
        break;
    case KVM_EXIT_EXCEPTION:
        fprintf(stderr, "KVM: exception %d exit (error code 0x%x)\n",
                run->ex.exception, run->ex.error_code);
        ret = -1;
        break;
    case KVM_EXIT_DEBUG:
        DPRINTF("kvm_exit_debug\n");
        break;
    default:
        fprintf(stderr, "KVM: unknown exit reason %d\n", run->exit_reason);
        ret = -1;
        break;
    }

    return ret;
}

bool kvm_arch_stop_on_emulation_error(CPUState *env)
{
    return !(env->cr[0] & CR0_PE_MASK) ||
           ((env->segs[R_CS].selector  & 3) != 3);
}

void os_setup_early_signal_handling(void)
{
    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
}

static void termsig_handler(int signal, siginfo_t *info, void *c)
{
    fprintf(stderr,"terminated by signal %d\n", signal);
    exit(0);
}

void os_setup_signal_handling(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_sigaction = termsig_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

/*
 * Creates an eventfd that looks like a pipe and has EFD_CLOEXEC set.
 */
int qemu_eventfd(int fds[2])
{
    int ret;

    ret = eventfd(0, 0);
    if (ret >= 0) {
        fds[0] = ret;
        qemu_set_cloexec(ret);
        if ((fds[1] = dup(ret)) == -1) {
            close(ret);
            return -1;
        }
        qemu_set_cloexec(fds[1]);
        return 0;
    }

    if (errno != ENOSYS) {
        return -1;
    }

    return qemu_pipe(fds);
}

int main(int argc, char **argv, char **envp)
{
    int i;
    char boot_devices[33] = "cd"; /* default to HD->CD-ROM */
    DisplayState *ds;
    DisplayChangeListener *dcl;

    init_clocks();
    rtc_clock = host_clock;

    QLIST_INIT (&vm_change_state_head);
    os_setup_early_signal_handling();

    for (i = 0; i < MAX_NODES; i++) {
        node_mem[i] = 0;
        node_cpumask[i] = 0;
    }

    nb_numa_nodes = 0;

    x86_cpudef_setup();

    bdrv_init(); //must be called before drive_init()

    drive_init(drive_add(IF_IDE, 0, "image", HD_OPTS));
    drive_init(drive_add(IF_IDE, 1, "iso", CDROM_OPTS));

    data_dir = "./pc-bios/";
    //data_dir = "/usr/local/share/qemu";

    ram_size = 1024 * 1024 * 1024;

    if (net_client_parse(qemu_find_opts("net"), "nic") < 0) {
        exit(1);
    }
    if (net_client_parse(qemu_find_opts("net"), "tap,ifname=tap0,script=./ifup") < 0) {
        exit(1);
    }
    net_init_clients();
    net_check_clients();

    if (kvm_init()) {
        fprintf(stderr, "kvm init failed\n");
        exit(1);
    }

    qemu_init_cpu_loop();
    if (qemu_init_main_loop()) {
        fprintf(stderr, "qemu_init_main_loop failed\n");
        exit(1);
    }

    if (init_timer_alarm() < 0) {
        fprintf(stderr, "could not initialize alarm timer\n");
        exit(1);
    }
    cpu_exec_init_all();

    module_call_init(MODULE_INIT_DEVICE);

    pc_init(get_system_memory(), get_system_io(), ram_size, boot_devices, "qemu64");

    cpu_synchronize_all_post_init();

    set_numa_modes();

    if (0 != usbdevice_create("tablet")) {
        fprintf(stderr, "usbdevice_create tablet failed\n");
        exit(1);
    }

    net_check_clients();

    /* just use the first displaystate for the moment */
    ds = get_displaystate();

    /* must be after terminal init, SDL library changes signal handlers */
    os_setup_signal_handling();

    vnc_display_init(ds);
    if (vnc_display_open(ds, "0:0") < 0)
        exit(1);

    printf("VNC server running on `%s'\n", vnc_display_local_addr(ds));

    /* display setup */
    dpy_resize(ds);
    dcl = ds->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_refresh != NULL) {
            ds->gui_timer = qemu_new_timer_ms(rt_clock, gui_update, ds);
            qemu_mod_timer(ds->gui_timer, qemu_get_clock_ms(rt_clock));
            break;
        }
        dcl = dcl->next;
    }

    qdev_machine_creation_done();

    if (rom_load_all() != 0) {
        fprintf(stderr, "rom loading failed\n");
        exit(1);
    }

    qemu_register_reset(qbus_reset_all_fn, sysbus_get_default());
    qemu_run_machine_init_done_notifiers();

    qemu_system_reset();

    vm_start();

    resume_all_vcpus();
    main_loop();
    bdrv_close_all();
    pause_all_vcpus();
    net_cleanup();

    return 0;
}

