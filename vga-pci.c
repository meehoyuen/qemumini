#include "hw.h"
#include "console.h"
#include "pc.h"
#include "pci.h"
#include "vga_int.h"
#include "pixel_ops.h"
#include "qemu-timer.h"
#include "loader.h"

typedef struct PCIVGAState {
    PCIDevice dev;
    VGACommonState vga;
} PCIVGAState;

static int pci_vga_initfn(PCIDevice *dev)
{
     PCIVGAState *d = DO_UPCAST(PCIVGAState, dev, dev);
     VGACommonState *s = &d->vga;

     // vga + console init
     vga_common_init(s, VGA_RAM_SIZE);
     vga_init(s, pci_address_space(dev), pci_address_space_io(dev), true);

     s->ds = graphic_console_init(s->update, s->invalidate, s->text_update, s);

     /* XXX: VGA_RAM_SIZE must be a power of two */
     pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->vram);

     return 0;
}

int pci_vga_init(PCIBus *bus)
{
    pci_create_simple(bus, -1, "VGA");
    return 0;
}

static PCIDeviceInfo vga_info = {
    .qdev.name    = "VGA",
    .qdev.size    = sizeof(PCIVGAState),
    .no_hotplug   = 1,
    .init         = pci_vga_initfn,
    .romfile      = "vgabios-stdvga.bin",

    /* dummy VGA (same as Bochs ID) */
    .vendor_id    = PCI_VENDOR_ID_QEMU,
    .device_id    = PCI_DEVICE_ID_QEMU_VGA,
    .class_id     = PCI_CLASS_DISPLAY_VGA,
};

static void vga_register(void)
{
    pci_qdev_register(&vga_info);
}
device_init(vga_register);
