/*
 * QEMU Executable loader
 */
#include "hw.h"
#include "sysemu.h"
#include "loader.h"
#include "fw_cfg.h"

static int roms_loaded;

/* return the size or -1 if error */
int get_image_size(const char *filename)
{
    int fd, size;
    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;
    size = lseek(fd, 0, SEEK_END);
    close(fd);
    return size;
}

/* return the size or -1 if error */
/* deprecated, because caller does not specify buffer size! */
int load_image(const char *filename, uint8_t *addr)
{
    int fd, size;
    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;
    size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (read(fd, addr, size) != size) {
        close(fd);
        return -1;
    }
    close(fd);
    return size;
}

/*
 * Functions for reboot-persistent memory regions.
 *  - used for vga bios and option roms.
 *  - also linux kernel (-kernel / -initrd).
 */

typedef struct Rom Rom;

struct Rom {
    char *name;
    char *path;
    size_t romsize;
    uint8_t *data;
    int isrom;
    char *fw_dir;
    char *fw_file;

    target_phys_addr_t addr;
    QTAILQ_ENTRY(Rom) next;
};

static FWCfgState *fw_cfg;
static QTAILQ_HEAD(, Rom) roms = QTAILQ_HEAD_INITIALIZER(roms);

static void rom_insert(Rom *rom)
{
    Rom *item;

    if (roms_loaded) {
        hw_error ("ROM images must be loaded at startup\n");
    }

    /* list is ordered by load address */
    QTAILQ_FOREACH(item, &roms, next) {
        if (rom->addr >= item->addr)
            continue;
        QTAILQ_INSERT_BEFORE(item, rom, next);
        return;
    }
    QTAILQ_INSERT_TAIL(&roms, rom, next);
}

int rom_add_file(const char *file, const char *fw_dir,
                 target_phys_addr_t addr, int32_t bootindex)
{
    Rom *rom;
    int rc, fd = -1;
    char devpath[100];

    rom = calloc(1, sizeof(*rom));
    rom->name = strdup(file);
    rom->path = qemu_find_file(QEMU_FILE_TYPE_BIOS, rom->name);
    if (rom->path == NULL) {
        rom->path = strdup(file);
    }

    fd = open(rom->path, O_RDONLY | O_BINARY);
    if (fd == -1) {
        fprintf(stderr, "Could not open option rom '%s': %s\n",
                rom->path, strerror(errno));
        goto err;
    }

    if (fw_dir) {
        rom->fw_dir  = strdup(fw_dir);
        rom->fw_file = strdup(file);
    }
    rom->addr    = addr;
    rom->romsize = lseek(fd, 0, SEEK_END);
    rom->data    = calloc(1, rom->romsize);
    lseek(fd, 0, SEEK_SET);
    rc = read(fd, rom->data, rom->romsize);
    if (rc != rom->romsize) {
        fprintf(stderr, "rom: file %-20s: read error: rc=%d (expected %zd)\n",
                rom->name, rc, rom->romsize);
        goto err;
    }
    close(fd);
    rom_insert(rom);
    if (rom->fw_file && fw_cfg) {
        const char *basename;
        char fw_file_name[56];

        basename = strrchr(rom->fw_file, '/');
        if (basename) {
            basename++;
        } else {
            basename = rom->fw_file;
        }
        snprintf(fw_file_name, sizeof(fw_file_name), "%s/%s", rom->fw_dir,
                 basename);
        fw_cfg_add_file(fw_cfg, fw_file_name, rom->data, rom->romsize);
        snprintf(devpath, sizeof(devpath), "/rom@%s", fw_file_name);
    } else {
        snprintf(devpath, sizeof(devpath), "/rom@" TARGET_FMT_plx, addr);
    }

    add_boot_device_path(bootindex, NULL, devpath);
    return 0;

err:
    if (fd != -1)
        close(fd);
    free(rom->data);
    rom->data = NULL;
    free(rom->path);
    rom->path = NULL;
    free(rom->name);
    rom->name = NULL;
    free(rom);
    rom = NULL;
    return -1;
}

int rom_add_blob(const char *name, const void *blob, size_t len,
                 target_phys_addr_t addr)
{
    Rom *rom;

    rom = calloc(1, sizeof(*rom));
    rom->name    = strdup(name);
    rom->addr    = addr;
    rom->romsize = len;
    rom->data    = calloc(1, rom->romsize);
    memcpy(rom->data, blob, len);
    rom_insert(rom);
    return 0;
}

static void rom_reset(void *unused)
{
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (rom->data == NULL) {
            continue;
        }
        cpu_physical_memory_write_rom(rom->addr, rom->data, rom->romsize);
        if (rom->isrom) {
            /* rom needs to be written only once */
            free(rom->data);
            rom->data = NULL;
        }
    }
}

int rom_load_all(void)
{
    target_phys_addr_t addr = 0;
    int memtype;
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (addr > rom->addr) {
            fprintf(stderr, "rom: requested regions overlap "
                    "(rom %s. free=0x" TARGET_FMT_plx
                    ", addr=0x" TARGET_FMT_plx ")\n",
                    rom->name, addr, rom->addr);
            return -1;
        }
        addr  = rom->addr;
        addr += rom->romsize;
        memtype = cpu_get_physical_page_desc(rom->addr) & (3 << IO_MEM_SHIFT);
        if (memtype == IO_MEM_ROM)
            rom->isrom = 1;
    }
    qemu_register_reset(rom_reset, NULL);
    roms_loaded = 1;
    return 0;
}

void rom_set_fw(void *f)
{
    fw_cfg = f;
}
