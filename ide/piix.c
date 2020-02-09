/*
 * QEMU IDE Emulation: PCI PIIX3/4 support.
 */
#include <hw.h>
#include <pc.h>
#include <pci.h>
#include <isa.h>
#include "block.h"
#include "sysemu.h"
#include "dma.h"

#include <ide/pci.h>

static uint64_t bmdma_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    BMDMAState *bm = opaque;
    uint32_t val;

    if (size != 1) {
        return ((uint64_t)1 << (size * 8)) - 1;
    }

    switch(addr & 3) {
    case 0:
        val = bm->cmd;
        break;
    case 2:
        val = bm->status;
        break;
    default:
        val = 0xff;
        break;
    }
#ifdef DEBUG_IDE
    printf("bmdma: readb 0x%02x : 0x%02x\n", addr, val);
#endif
    return val;
}

static void bmdma_write(void *opaque, target_phys_addr_t addr,
                        uint64_t val, unsigned size)
{
    BMDMAState *bm = opaque;

    if (size != 1) {
        return;
    }

#ifdef DEBUG_IDE
    printf("bmdma: writeb 0x%02x : 0x%02x\n", addr, val);
#endif
    switch(addr & 3) {
    case 0:
        return bmdma_cmd_writeb(bm, val);
    case 2:
        bm->status = (val & 0x60) | (bm->status & 1) | (bm->status & ~val & 0x06);
        break;
    }
}

static MemoryRegionOps piix_bmdma_ops = {
    .read = bmdma_read,
    .write = bmdma_write,
};

static void bmdma_setup_bar(PCIIDEState *d)
{
    int i;

    memory_region_init(&d->bmdma_bar, "piix-bmdma-container", 16);
    for(i = 0;i < 2; i++) {
        BMDMAState *bm = &d->bmdma[i];

        memory_region_init_io(&bm->extra_io, &piix_bmdma_ops, bm,
                              "piix-bmdma", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8, &bm->extra_io);
        memory_region_init_io(&bm->addr_ioport, &bmdma_addr_ioport_ops, bm,
                              "bmdma", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8 + 4, &bm->addr_ioport);
    }
}

static void piix3_reset(void *opaque)
{
    PCIIDEState *d = opaque;
    uint8_t *pci_conf = d->dev.config;
    int i;

    for (i = 0; i < 2; i++) {
        ide_bus_reset(&d->bus[i]);
    }

    /* TODO: this is the default. do not override. */
    pci_conf[PCI_COMMAND] = 0x00;
    /* TODO: this is the default. do not override. */
    pci_conf[PCI_COMMAND + 1] = 0x00;
    /* TODO: use pci_set_word */
    pci_conf[PCI_STATUS] = PCI_STATUS_FAST_BACK;
    pci_conf[PCI_STATUS + 1] = PCI_STATUS_DEVSEL_MEDIUM >> 8;
    pci_conf[0x20] = 0x01; /* BMIBA: 20-23h */
}

static void pci_piix_init_ports(PCIIDEState *d) {
    static const struct {
        int iobase;
        int iobase2;
        int isairq;
    } port_info[] = {
        {0x1f0, 0x3f6, 14},
        {0x170, 0x376, 15},
    };
    int i;

    for (i = 0; i < 2; i++) {
        ide_bus_new(&d->bus[i], &d->dev.qdev, i);
        ide_init_ioport(&d->bus[i], NULL, port_info[i].iobase,
                        port_info[i].iobase2);
        ide_init2(&d->bus[i], isa_get_irq(port_info[i].isairq));

        bmdma_init(&d->bus[i], &d->bmdma[i], d);
        d->bmdma[i].bus = &d->bus[i];
        qemu_add_vm_change_state_handler(d->bus[i].dma->ops->restart_cb,
                                         &d->bmdma[i].dma);
    }
}

static int pci_piix_ide_initfn(PCIDevice *dev)
{
    PCIIDEState *d = DO_UPCAST(PCIIDEState, dev, dev);
    uint8_t *pci_conf = d->dev.config;

    pci_conf[PCI_CLASS_PROG] = 0x80; // legacy ATA mode

    qemu_register_reset(piix3_reset, d);

    bmdma_setup_bar(d);
    pci_register_bar(&d->dev, 4, PCI_BASE_ADDRESS_SPACE_IO, &d->bmdma_bar);

    pci_piix_init_ports(d);

    return 0;
}

static int pci_piix_ide_exitfn(PCIDevice *dev)
{
    PCIIDEState *d = DO_UPCAST(PCIIDEState, dev, dev);
    unsigned i;

    for (i = 0; i < 2; ++i) {
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].extra_io);
        memory_region_destroy(&d->bmdma[i].extra_io);
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].addr_ioport);
        memory_region_destroy(&d->bmdma[i].addr_ioport);
    }
    memory_region_destroy(&d->bmdma_bar);

    return 0;
}

/* hd_table must contain 4 block drivers */
/* NOTE: for the PIIX3, the IRQs and IOports are hardcoded */
PCIDevice *pci_piix3_ide_init(PCIBus *bus, DriveInfo **hd_table, int devfn)
{
    PCIDevice *dev;

    dev = pci_create_simple(bus, devfn, "piix3-ide");
    pci_ide_create_devs(dev, hd_table);
    return dev;
}

/* hd_table must contain 4 block drivers */
/* NOTE: for the PIIX4, the IRQs and IOports are hardcoded */
PCIDevice *pci_piix4_ide_init(PCIBus *bus, DriveInfo **hd_table, int devfn)
{
    PCIDevice *dev;

    dev = pci_create_simple(bus, devfn, "piix4-ide");
    pci_ide_create_devs(dev, hd_table);
    return dev;
}

static PCIDeviceInfo piix_ide_info[] = {
    {
        .qdev.name    = "piix3-ide",
        .qdev.size    = sizeof(PCIIDEState),
        .qdev.no_user = 1,
        .no_hotplug   = 1,
        .init         = pci_piix_ide_initfn,
        .exit         = pci_piix_ide_exitfn,
        .vendor_id    = PCI_VENDOR_ID_INTEL,
        .device_id    = PCI_DEVICE_ID_INTEL_82371SB_1,
        .class_id     = PCI_CLASS_STORAGE_IDE,
    },{
        .qdev.name    = "piix4-ide",
        .qdev.size    = sizeof(PCIIDEState),
        .qdev.no_user = 1,
        .no_hotplug   = 1,
        .init         = pci_piix_ide_initfn,
        .exit         = pci_piix_ide_exitfn,
        .vendor_id    = PCI_VENDOR_ID_INTEL,
        .device_id    = PCI_DEVICE_ID_INTEL_82371AB,
        .class_id     = PCI_CLASS_STORAGE_IDE,
    },{
        /* end of list */
    }
};

static void piix_ide_register(void)
{
    pci_qdev_register_many(piix_ide_info);
}
device_init(piix_ide_register);
