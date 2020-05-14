CONFIG_PCI=y
CONFIG_IDE_CORE=y
CONFIG_IDE_QDEV=y
CONFIG_IDE_PCI=y
CONFIG_VGA_PCI=y
CONFIG_I8254=y
CONFIG_PCKBD=y
CONFIG_FDC=y
CONFIG_ACPI=y
CONFIG_APM=y
CONFIG_DMA=y
CONFIG_IDE_PIIX=y
CONFIG_HPET=y
CONFIG_I8259=y

TARGET_BASE_ARCH=i386
TARGET_ABI_DIR=x86_64

CONFIG_POSIX=y
GLIB_CFLAGS=-pthread
MAKE=make
CC=gcc
LD=ld
CFLAGS=-O2 -g -Wall -Iinclude
QEMU_CFLAGS=-m64 -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wredundant-decls -Wundef -Wwrite-strings -fno-strict-aliasing  -fstack-protector-all -Wendif-labels -Wmissing-include-dirs -Wempty-body -Wformat-security -Wformat-y2k -Winit-self -Wignored-qualifiers -Wold-style-declaration -Wold-style-definition -Wtype-limits
QEMU_INCLUDES=-I. 
LDFLAGS=-Wl,--warn-common -m64 -g

.PHONY: clean all

all: qemu

%.o: %.c
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(CFLAGS) -c -o $@ $<,"  CC    $(TARGET_DIR)$@")

LINK = $(call quiet-command,$(CC) $(QEMU_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(sort $(1)) $(LIBS),"  LINK  $(TARGET_DIR)$@")

quiet-command = $(if $(V),$1,$(if $(2),@echo $2 && $1, @$1))

cc-option = $(if $(shell $(CC) $1 $2 -S -o /dev/null -xc /dev/null \
              >/dev/null 2>&1 && echo OK), $2, $3)
VPATH_SUFFIXES = %.c
set-vpath = $(if $1,$(foreach PATTERN,$(VPATH_SUFFIXES),$(eval vpath $(PATTERN) $1)))

oslib-obj-$(CONFIG_POSIX) += oslib-posix.o qemu-thread.o
coroutine-obj-y = qemu-coroutine.o qemu-coroutine-lock.o
coroutine-obj-$(CONFIG_POSIX) += coroutine-ucontext.o
block-obj-y = cutils.o qemu-option.o module.o async.o block.o aio.o
block-obj-$(CONFIG_POSIX) += posix-aio-compat.o
block-obj-y += block/raw.o block/cloop.o block/qcow2.o block/qcow2-refcount.o block/qcow2-cluster.o block/qcow2-cache.o
block-obj-$(CONFIG_POSIX) += block/raw-posix.o

common-obj-y = blockdev.o console.o cursor.o irq.o input.o i2c.o smbus.o smbus_eeprom.o cdrom.o hid.o usb.o ps2.o qdev.o qdev-properties.o vnc.o notify.o qemu-timer.o
common-obj-$(CONFIG_POSIX) += compatfd.o

hw-obj-y  = vl.o loader.o fw_cfg.o dma-helpers.o sysbus.o isa-bus.o qdev-addr.o
hw-obj-$(CONFIG_PCI) += pci.o msi.o
hw-obj-$(CONFIG_I8254) += i8254.o
hw-obj-$(CONFIG_PCKBD) += pckbd.o
hw-obj-$(CONFIG_FDC) += fdc.o
hw-obj-$(CONFIG_ACPI) += acpi.o acpi_piix4.o
hw-obj-$(CONFIG_APM) += pm_smbus.o apm.o
hw-obj-$(CONFIG_DMA) += dma.o
hw-obj-$(CONFIG_HPET) += hpet.o
hw-obj-$(CONFIG_I8259) += i8259.o
hw-obj-$(CONFIG_IDE_CORE) += ide/core.o ide/atapi.o
hw-obj-$(CONFIG_IDE_QDEV) += ide/qdev.o
hw-obj-$(CONFIG_IDE_PCI) += ide/pci.o
hw-obj-$(CONFIG_IDE_PIIX) += ide/piix.o
hw-obj-$(CONFIG_VGA_PCI) += vga-pci.o

net-obj-y = e1000.o net.c

QEMU_CFLAGS+=$(GLIB_CFLAGS)
QEMU_CFLAGS += -I. 

libobj-y = exec.o softfloat.o helper.o cpuid.o
obj-y = cpus.o ioport.o memory.o
obj-i386-y += vga.o mc146818rtc.o apic.o ioapic.o piix_pci.o smbios.o

LIBS+=-lm -lrt -lpthread

qemu: $(coroutine-obj-y) $(oslib-obj-y) $(block-obj-y) $(hw-obj-y) $(libobj-y) $(common-obj-y) $(obj-y) $(obj-i386-y) $(tools-obj-y) $(net-obj-y)
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o block/*.o
	rm -f ide/*.o
