/*
 * defines common to all virtual CPUs
 */
#ifndef CPU_ALL_H
#define CPU_ALL_H

#include "qemu-common.h"
#include "cpu-common.h"

#define DECLARE_TLS(type, x) extern DEFINE_TLS(type, x)
#define DEFINE_TLS(type, x)  __thread __typeof__(type) tls__##x
#define get_tls(x)           tls__##x

static inline uint16_t tswap16(uint16_t s)
{
    return s;
}

static inline uint32_t tswap32(uint32_t s)
{
    return s;
}

static inline uint64_t tswap64(uint64_t s)
{
    return s;
}

static inline void tswap16s(uint16_t *s)
{
}

static inline void tswap32s(uint32_t *s)
{
}

static inline void tswap64s(uint64_t *s)
{
}

#if TARGET_LONG_SIZE == 4
#define tswapl(s) tswap32(s)
#define tswapls(s) tswap32s((uint32_t *)(s))
#define bswaptls(s) bswap32s(s)
#else
#define tswapl(s) tswap64(s)
#define tswapls(s) tswap64s((uint64_t *)(s))
#define bswaptls(s) bswap64s(s)
#endif

/* CPU memory access without any memory or io remapping */

/*
 * the generic syntax for the memory accesses is:
 *
 * load: ld{type}{sign}{size}{endian}_{access_type}(ptr)
 *
 * store: st{type}{size}{endian}_{access_type}(ptr, val)
 *
 * type is:
 * (empty): integer access
 *   f    : float access
 *
 * sign is:
 * (empty): for floats or 32 bit size
 *   u    : unsigned
 *   s    : signed
 *
 * size is:
 *   b: 8 bits
 *   w: 16 bits
 *   l: 32 bits
 *   q: 64 bits
 *
 * endian is:
 * (empty): target cpu endianness or 8 bit access
 *   r    : reversed target cpu endianness (not implemented yet)
 *   be   : big endian (not implemented yet)
 *   le   : little endian (not implemented yet)
 *
 * access_type is:
 *   raw    : host memory access
 *   user   : user mode access using soft MMU
 *   kernel : kernel mode access using soft MMU
 */

#define lduw_p(p) lduw_le_p(p)
#define ldsw_p(p) ldsw_le_p(p)
#define ldl_p(p) ldl_le_p(p)
#define ldq_p(p) ldq_le_p(p)
#define ldfl_p(p) ldfl_le_p(p)
#define ldfq_p(p) ldfq_le_p(p)
#define stw_p(p, v) stw_le_p(p, v)
#define stl_p(p, v) stl_le_p(p, v)
#define stq_p(p, v) stq_le_p(p, v)
#define stfl_p(p, v) stfl_le_p(p, v)
#define stfq_p(p, v) stfq_le_p(p, v)

/* MMU memory access macros */

#if defined(CONFIG_USER_ONLY)
#include <assert.h>
#include "qemu-types.h"

/* On some host systems the guest address space is reserved on the host.
 * This allows the guest address space to be offset to a convenient location.
 */
#if defined(CONFIG_USE_GUEST_BASE)
extern unsigned long guest_base;
extern int have_guest_base;
extern unsigned long reserved_va;
#define GUEST_BASE guest_base
#define RESERVED_VA reserved_va
#else
#define GUEST_BASE 0ul
#define RESERVED_VA 0ul
#endif

/* All direct uses of g2h and h2g need to go away for usermode softmmu.  */
#define g2h(x) ((void *)((unsigned long)(x) + GUEST_BASE))

#define h2g_valid(x) ({ \
    unsigned long __guest = (unsigned long)(x) - GUEST_BASE; \
    __guest < (1ul << TARGET_VIRT_ADDR_SPACE_BITS); \
})

#define h2g(x) ({ \
    unsigned long __ret = (unsigned long)(x) - GUEST_BASE; \
    /* Check if given address fits target address space */ \
    assert(h2g_valid(x)); \
    (abi_ulong)__ret; \
})

#define saddr(x) g2h(x)
#define laddr(x) g2h(x)

#else /* !CONFIG_USER_ONLY */
/* NOTE: we use double casts if pointers and target_ulong have
   different sizes */
#define saddr(x) (uint8_t *)(long)(x)
#define laddr(x) (uint8_t *)(long)(x)
#endif

#define ldub_raw(p) ldub_p(laddr((p)))
#define ldsb_raw(p) ldsb_p(laddr((p)))
#define lduw_raw(p) lduw_p(laddr((p)))
#define ldsw_raw(p) ldsw_p(laddr((p)))
#define ldl_raw(p) ldl_p(laddr((p)))
#define ldq_raw(p) ldq_p(laddr((p)))
#define ldfl_raw(p) ldfl_p(laddr((p)))
#define ldfq_raw(p) ldfq_p(laddr((p)))
#define stb_raw(p, v) stb_p(saddr((p)), v)
#define stw_raw(p, v) stw_p(saddr((p)), v)
#define stl_raw(p, v) stl_p(saddr((p)), v)
#define stq_raw(p, v) stq_p(saddr((p)), v)
#define stfl_raw(p, v) stfl_p(saddr((p)), v)
#define stfq_raw(p, v) stfq_p(saddr((p)), v)

/* page related stuff */

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)
#define TARGET_PAGE_ALIGN(addr) (((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)

/* ??? These should be the larger of unsigned long and target_ulong.  */
extern unsigned long qemu_real_host_page_size;
extern unsigned long qemu_host_page_size;
extern unsigned long qemu_host_page_mask;

#define HOST_PAGE_ALIGN(addr) (((addr) + qemu_host_page_size - 1) & qemu_host_page_mask)

/* same as PROT_xxx */
#define PAGE_READ      0x0001
#define PAGE_WRITE     0x0002
#define PAGE_EXEC      0x0004
#define PAGE_BITS      (PAGE_READ | PAGE_WRITE | PAGE_EXEC)
#define PAGE_VALID     0x0008
/* original state of the write flag (used when tracking self-modifying
   code */
#define PAGE_WRITE_ORG 0x0010

CPUState *cpu_copy(CPUState *env);
CPUState *qemu_get_cpu(int cpu);

void cpu_abort(CPUState *env, const char *fmt, ...) GCC_FMT_ATTR(2, 3);
extern CPUState *first_cpu;
DECLARE_TLS(CPUState *,cpu_single_env);
#define cpu_single_env get_tls(cpu_single_env)

/* Flags for use in ENV->INTERRUPT_PENDING.

   The numbers assigned here are non-sequential in order to preserve
   binary compatibility with the vmstate dump.  Bit 0 (0x0001) was
   previously used for CPU_INTERRUPT_EXIT, and is cleared when loading
   the vmstate dump.  */

/* External hardware interrupt pending.  This is typically used for
   interrupts from devices.  */
#define CPU_INTERRUPT_HARD        0x0002

/* Exit the current TB.  This is typically used when some system-level device
   makes some change to the memory mapping.  E.g. the a20 line change.  */
#define CPU_INTERRUPT_EXITTB      0x0004

/* Halt the CPU.  */
#define CPU_INTERRUPT_HALT        0x0020

/* Debug event pending.  */
#define CPU_INTERRUPT_DEBUG       0x0080

/* Several target-specific external hardware interrupts.  Each target
   should define proper names based on these defines.  */
#define CPU_INTERRUPT_TGT_EXT_0   0x0008
#define CPU_INTERRUPT_TGT_EXT_1   0x0010
#define CPU_INTERRUPT_TGT_EXT_2   0x0040
#define CPU_INTERRUPT_TGT_EXT_3   0x0200
#define CPU_INTERRUPT_TGT_EXT_4   0x1000

/* Several target-specific internal interrupts.  These differ from the
   preceeding target-specific interrupts in that they are intended to
   originate from within the cpu itself, typically in response to some
   instruction being executed.  These, therefore, are not masked while
   single-stepping within the debugger.  */
#define CPU_INTERRUPT_TGT_INT_0   0x0100
#define CPU_INTERRUPT_TGT_INT_1   0x0400
#define CPU_INTERRUPT_TGT_INT_2   0x0800

/* First unused bit: 0x2000.  */

/* The set of all bits that should be masked when single-stepping.  */
#define CPU_INTERRUPT_SSTEP_MASK \
    (CPU_INTERRUPT_HARD          \
     | CPU_INTERRUPT_TGT_EXT_0   \
     | CPU_INTERRUPT_TGT_EXT_1   \
     | CPU_INTERRUPT_TGT_EXT_2   \
     | CPU_INTERRUPT_TGT_EXT_3   \
     | CPU_INTERRUPT_TGT_EXT_4)

#ifndef CONFIG_USER_ONLY
typedef void (*CPUInterruptHandler)(CPUState *, int);

extern CPUInterruptHandler cpu_interrupt_handler;

static inline void cpu_interrupt(CPUState *s, int mask)
{
    cpu_interrupt_handler(s, mask);
}
#else /* USER_ONLY */
void cpu_interrupt(CPUState *env, int mask);
#endif /* USER_ONLY */

void cpu_reset_interrupt(CPUState *env, int mask);

void cpu_exit(CPUState *s);

bool qemu_cpu_has_work(CPUState *env);

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

void cpu_single_step(CPUState *env, int enabled);
void cpu_reset(CPUState *s);
int cpu_is_stopped(CPUState *env);
void run_on_cpu(CPUState *env, void (*func)(void *data), void *data);

/* Return the physical page corresponding to a virtual one. Use it
   only for debugging because no protection checks are done. Return -1
   if no page found. */
target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr);

/* memory API */

extern int phys_ram_fd;
extern ram_addr_t ram_size;

/* RAM is pre-allocated and passed into qemu_ram_alloc_from_ptr */
#define RAM_PREALLOC_MASK   (1 << 0)

typedef struct RAMBlock {
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t length;
    uint32_t flags;
    char idstr[256];
    QLIST_ENTRY(RAMBlock) next;
    int fd;
} RAMBlock;

typedef struct RAMList {
    uint8_t *phys_dirty;
    QLIST_HEAD(, RAMBlock) blocks;
} RAMList;
extern RAMList ram_list;

extern int mem_prealloc;

/* physical memory access */

/* MMIO pages are identified by a combination of an IO device index and
   3 flags.  The ROMD code stores the page ram offset in iotlb entry, 
   so only a limited number of ids are avaiable.  */

#define IO_MEM_NB_ENTRIES  (1 << (TARGET_PAGE_BITS  - IO_MEM_SHIFT))

/* Flags stored in the low bits of the TLB virtual address.  These are
   defined so that fast path ram access is all zeros.  */
/* Zero if TLB entry is valid.  */
#define TLB_INVALID_MASK   (1 << 3)
/* Set if TLB entry references a clean RAM page.  The iotlb entry will
   contain the page physical address.  */
#define TLB_NOTDIRTY    (1 << 4)
/* Set if TLB entry is an IO callback.  */
#define TLB_MMIO        (1 << 5)

#define VGA_DIRTY_FLAG       0x01
#define CODE_DIRTY_FLAG      0x02
#define MIGRATION_DIRTY_FLAG 0x08

/* read dirty bit (return 0 or 1) */
static inline int cpu_physical_memory_is_dirty(ram_addr_t addr)
{
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] == 0xff;
}

static inline int cpu_physical_memory_get_dirty_flags(ram_addr_t addr)
{
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS];
}

static inline int cpu_physical_memory_get_dirty(ram_addr_t addr,
                                                int dirty_flags)
{
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] & dirty_flags;
}

static inline void cpu_physical_memory_set_dirty(ram_addr_t addr)
{
    ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] = 0xff;
}

static inline int cpu_physical_memory_set_dirty_flags(ram_addr_t addr,
                                                      int dirty_flags)
{
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] |= dirty_flags;
}

static inline void cpu_physical_memory_mask_dirty_range(ram_addr_t start,
                                                        int length,
                                                        int dirty_flags)
{
    int i, mask, len;
    uint8_t *p;

    len = length >> TARGET_PAGE_BITS;
    mask = ~dirty_flags;
    p = ram_list.phys_dirty + (start >> TARGET_PAGE_BITS);
    for (i = 0; i < len; i++) {
        p[i] &= mask;
    }
}

void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end,
                                     int dirty_flags);
int cpu_physical_memory_set_dirty_tracking(int enable);

int cpu_physical_memory_get_dirty_tracking(void);

int cpu_physical_sync_dirty_bitmap(target_phys_addr_t start_addr,
                                   target_phys_addr_t end_addr);

int cpu_physical_log_start(target_phys_addr_t start_addr,
                           ram_addr_t size);

int cpu_physical_log_stop(target_phys_addr_t start_addr,
                          ram_addr_t size);
#endif /* CPU_ALL_H */
