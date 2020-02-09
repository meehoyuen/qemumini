#ifndef HW_PC_H
#define HW_PC_H

#include "qemu-common.h"
#include "memory.h"
#include "ioport.h"
#include "isa.h"
#include "fdc.h"
#include "memory.h"

#define IOAPIC_NUM_PINS 24

/* i8259.c */
typedef struct PicState PicState;
extern PicState *isa_pic;
qemu_irq *i8259_init(qemu_irq parent_irq);
int pic_read_irq(PicState *s);
int pic_get_output(PicState *s);

/* Global System Interrupts */
#define GSI_NUM_PINS IOAPIC_NUM_PINS

typedef struct GSIState {
    qemu_irq i8259_irq[ISA_NUM_IRQS];
    qemu_irq ioapic_irq[IOAPIC_NUM_PINS];
} GSIState;

void gsi_handler(void *opaque, int n, int level);

/* i8254.c */
#define PIT_FREQ 1193182
static inline ISADevice *pit_init(int base, int irq)
{
    ISADevice *dev;

    dev = isa_create("isa-pit");
    qdev_prop_set_uint32(&dev->qdev, "iobase", base);
    qdev_prop_set_uint32(&dev->qdev, "irq", irq);
    qdev_init_nofail(&dev->qdev);

    return dev;
}

void pit_set_gate(ISADevice *dev, int channel, int val);
int pit_get_gate(ISADevice *dev, int channel);
int pit_get_initial_count(ISADevice *dev, int channel);
int pit_get_mode(ISADevice *dev, int channel);
int pit_get_out(ISADevice *dev, int channel, int64_t current_time);

void hpet_pit_disable(void);
void hpet_pit_enable(void);

/* pckbd.c */
void i8042_init(qemu_irq kbd_irq, qemu_irq mouse_irq, uint32_t io_base);
void i8042_mm_init(qemu_irq kbd_irq, qemu_irq mouse_irq,
                   MemoryRegion *region, ram_addr_t size,
                   uint64_t mask);
void i8042_isa_mouse_fake_event(void *opaque);
void i8042_setup_a20_line(ISADevice *dev, qemu_irq *a20_out);

/* pc.c */
extern int fd_bootchk;

void pc_register_ferr_irq(qemu_irq irq);
void pc_cmos_set_s3_resume(void *opaque, int irq, int level);
void pc_acpi_smi_interrupt(void *opaque, int irq, int level);

void pc_memory_init(MemoryRegion *system_memory,
                    ram_addr_t below_4g_mem_size,
                    ram_addr_t above_4g_mem_size,
                    MemoryRegion *rom_memory,
                    MemoryRegion **ram_memory);
qemu_irq *pc_allocate_cpu_irq(void);
void pc_vga_init(PCIBus *pci_bus);
void pc_basic_device_init(qemu_irq *gsi,
                          ISADevice **rtc_state,
                          ISADevice **floppy);
void pc_cmos_init(ram_addr_t ram_size, ram_addr_t above_4g_mem_size,
                  const char *boot_device,
                  ISADevice *floppy, BusState *ide0, BusState *ide1,
                  ISADevice *s);
void pc_pci_device_init(PCIBus *pci_bus);

typedef void (*cpu_set_smm_t)(int smm, void *arg);
void cpu_smm_register(cpu_set_smm_t callback, void *arg);

/* acpi.c */
extern char *acpi_tables;
extern size_t acpi_tables_len;

void acpi_bios_init(void);

/* acpi_piix.c */
i2c_bus *piix4_pm_init(PCIBus *bus, int devfn, uint32_t smb_io_base,
                       qemu_irq sci_irq, qemu_irq cmos_s3, qemu_irq smi_irq);
void piix4_smbus_register_device(SMBusDevice *dev, uint8_t addr);

/* piix_pci.c */
struct PCII440FXState;
typedef struct PCII440FXState PCII440FXState;

PCIBus *i440fx_init(PCII440FXState **pi440fx_state, int *piix_devfn,
                    qemu_irq *pic,
                    MemoryRegion *address_space_mem,
                    MemoryRegion *address_space_io,
                    ram_addr_t ram_size,
                    uint64_t pci_hole_start,
                    uint64_t pci_hole_size,
                    uint64_t pci_hole64_start,
                    uint64_t pci_hole64_size,
                    MemoryRegion *pci_memory,
                    MemoryRegion *ram_memory);

int pci_vga_init(PCIBus *bus);

/* e820 types */
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3
#define E820_NVS        4
#define E820_UNUSABLE   5

int e820_add_entry(uint64_t, uint64_t, uint32_t);

#endif
