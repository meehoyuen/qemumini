#ifndef LOADER_H
#define LOADER_H

/* loader.c */
int get_image_size(const char *filename);
int load_image(const char *filename, uint8_t *addr); /* deprecated */
int rom_add_file(const char *file, const char *fw_dir,
                 target_phys_addr_t addr, int32_t bootindex);
int rom_add_blob(const char *name, const void *blob, size_t len,
                 target_phys_addr_t addr);
int rom_load_all(void);
void rom_set_fw(void *f);
int rom_copy(uint8_t *dest, target_phys_addr_t addr, size_t size);
void *rom_ptr(target_phys_addr_t addr);

#define rom_add_file_fixed(_f, _a, _i)          \
    rom_add_file(_f, NULL, _a, _i)
#define rom_add_blob_fixed(_f, _b, _l, _a)      \
    rom_add_blob(_f, _b, _l, _a)

#define PC_ROM_MIN_VGA     0xc0000
#define PC_ROM_MAX         0xe0000
#define PC_ROM_SIZE        (PC_ROM_MAX - PC_ROM_MIN_VGA)
#endif
