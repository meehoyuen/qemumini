#include <sys/types.h>
#include <sys/mman.h>
#include "qemu-common.h"
#include "cpu.h"
#include "hw.h"
#include "qdev.h"
#include "osdep.h"
#include "kvm.h"
#include "qemu-timer.h"
#include "memory.h"
#include "exec-memory.h"

//#define DEBUG_TLB
//#define DEBUG_UNASSIGNED

/* make various TB consistency checks */
//#define DEBUG_TLB_CHECK

//#define DEBUG_IOPORT
//#define DEBUG_SUBPAGE

#define SMC_BITMAP_USE_THRESHOLD 10

static TranslationBlock *tbs;
TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];
static int nb_tbs;
static uint8_t *code_gen_buffer;
static unsigned long code_gen_buffer_size;
static uint8_t *code_gen_ptr;

RAMList ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };

static MemoryRegion *system_memory;
static MemoryRegion *system_io;

CPUState *first_cpu;
/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
DEFINE_TLS(CPUState *,cpu_single_env);
/* 0 = Do not count executed instructions.
   1 = Precise instruction counting.
   2 = Adaptive rate instruction counting.  */

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    TranslationBlock *first_tb;
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned int code_write_count;
    uint8_t *code_bitmap;
} PageDesc;

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS

/* Size of the L2 (and L3, etc) page tables.  */
#define L2_BITS 10
#define L2_SIZE (1 << L2_BITS)

/* The bits remaining after N lower levels of page tables.  */
#define P_L1_BITS_REM \
    ((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)
#define V_L1_BITS_REM \
    ((L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)

/* Size of the L1 page table.  Avoid silly small sizes.  */
#if P_L1_BITS_REM < 4
#define P_L1_BITS  (P_L1_BITS_REM + L2_BITS)
#else
#define P_L1_BITS  P_L1_BITS_REM
#endif

#if V_L1_BITS_REM < 4
#define V_L1_BITS  (V_L1_BITS_REM + L2_BITS)
#else
#define V_L1_BITS  V_L1_BITS_REM
#endif

#define P_L1_SIZE  ((target_phys_addr_t)1 << P_L1_BITS)
#define V_L1_SIZE  ((target_ulong)1 << V_L1_BITS)

#define P_L1_SHIFT (TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - P_L1_BITS)
#define V_L1_SHIFT (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - V_L1_BITS)

unsigned long qemu_real_host_page_size;
unsigned long qemu_host_page_size;
unsigned long qemu_host_page_mask;

/* This is a multi-level map on the virtual address space.
   The bottom level has pointers to PageDesc.  */
static void *l1_map[V_L1_SIZE];

typedef struct PhysPageDesc {
    /* offset in host memory of the page + io_index in the low bits */
    ram_addr_t phys_offset;
    ram_addr_t region_offset;
} PhysPageDesc;

/* This is a multi-level map on the physical address space.
   The bottom level has pointers to PhysPageDesc.  */
static void *l1_phys_map[P_L1_SIZE];

static void io_mem_init(void);
static void memory_map_init(void);

/* io memory support */
CPUWriteMemoryFunc *io_mem_write[IO_MEM_NB_ENTRIES][4];
CPUReadMemoryFunc *io_mem_read[IO_MEM_NB_ENTRIES][4];
void *io_mem_opaque[IO_MEM_NB_ENTRIES];
static char io_mem_used[IO_MEM_NB_ENTRIES];
static int io_mem_watch;

TranslationBlock *tb_gen_code(CPUState *env, 
                              target_ulong pc, target_ulong cs_base, int flags, int cflags)
{
    return NULL;
}
int cpu_restore_state(struct TranslationBlock *tb,
                      CPUState *env, unsigned long searched_pc)
{
    return -1;
}

static PageDesc *page_find_alloc(tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;


# define ALLOC(P, SIZE) \
    do { P = calloc(1, SIZE); } while (0)

    /* Level 1.  Always allocated.  */
    lp = l1_map + ((index >> V_L1_SHIFT) & (V_L1_SIZE - 1));

    /* Level 2..N-1.  */
    for (i = V_L1_SHIFT / L2_BITS - 1; i > 0; i--) {
        void **p = *lp;

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            ALLOC(p, sizeof(void *) * L2_SIZE);
            *lp = p;
        }

        lp = p + ((index >> (i * L2_BITS)) & (L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        ALLOC(pd, sizeof(PageDesc) * L2_SIZE);
        *lp = pd;
    }

#undef ALLOC

    return pd + (index & (L2_SIZE - 1));
}

static inline PageDesc *page_find(tb_page_addr_t index)
{
    return page_find_alloc(index, 0);
}

static PhysPageDesc *phys_page_find_alloc(target_phys_addr_t index, int alloc)
{
    PhysPageDesc *pd;
    void **lp;
    int i;

    /* Level 1.  Always allocated.  */
    lp = l1_phys_map + ((index >> P_L1_SHIFT) & (P_L1_SIZE - 1));

    /* Level 2..N-1.  */
    for (i = P_L1_SHIFT / L2_BITS - 1; i > 0; i--) {
        void **p = *lp;
        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            *lp = p = calloc(L2_SIZE, sizeof(void *));
        }
        lp = p + ((index >> (i * L2_BITS)) & (L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        int i;

        if (!alloc) {
            return NULL;
        }

        *lp = pd = malloc(sizeof(PhysPageDesc) * L2_SIZE);

        for (i = 0; i < L2_SIZE; i++) {
            pd[i].phys_offset = IO_MEM_UNASSIGNED;
            pd[i].region_offset = (index + i) << TARGET_PAGE_BITS;
        }
    }

    return pd + (index & (L2_SIZE - 1));
}

static inline PhysPageDesc *phys_page_find(target_phys_addr_t index)
{
    return phys_page_find_alloc(index, 0);
}

static void tlb_protect_code(ram_addr_t ram_addr);
static void tlb_unprotect_code_phys(CPUState *env, ram_addr_t ram_addr,
                                    target_ulong vaddr);
#define mmap_lock() do { } while(0)
#define mmap_unlock() do { } while(0)
#define DEFAULT_CODE_GEN_BUFFER_SIZE (32 * 1024 * 1024)

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]
               __attribute__((aligned (CODE_GEN_ALIGN)));
#endif

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */

void cpu_exec_init_all(void)
{
    memory_map_init();
    io_mem_init();
}

CPUState *qemu_get_cpu(int cpu)
{
    CPUState *env = first_cpu;

    while (env) {
        if (env->cpu_index == cpu)
            break;
        env = env->next_cpu;
    }

    return env;
}

void cpu_exec_init(CPUState *env)
{
    CPUState **penv;
    int cpu_index;

    env->next_cpu = NULL;
    penv = &first_cpu;
    cpu_index = 0;
    while (*penv != NULL) {
        penv = &(*penv)->next_cpu;
        cpu_index++;
    }
    env->cpu_index = cpu_index;
    env->numa_node = 0;
    env->thread_id = getpid();
    *penv = env;
}

void tb_free(TranslationBlock *tb)
{
    /* In practice this is mostly used for single use temporary TB
       Ignore the hard cases and just back up if this TB happens to
       be the last one generated.  */
    if (nb_tbs > 0 && tb == &tbs[nb_tbs - 1]) {
        code_gen_ptr = tb->tc_ptr;
        nb_tbs--;
    }
}

static inline void invalidate_page_bitmap(PageDesc *p)
{
    if (p->code_bitmap) {
        free(p->code_bitmap);
        p->code_bitmap = NULL;
    }
    p->code_write_count = 0;
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */

static void page_flush_tb_1 (int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            pd[i].first_tb = NULL;
            invalidate_page_bitmap(pd + i);
        }
    } else {
        void **pp = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            page_flush_tb_1 (level - 1, pp + i);
        }
    }
}

static void page_flush_tb(void)
{
    int i;
    for (i = 0; i < V_L1_SIZE; i++) {
        page_flush_tb_1(V_L1_SHIFT / L2_BITS - 1, l1_map + i);
    }
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUState *env1)
{
    CPUState *env;

    if ((unsigned long)(code_gen_ptr - code_gen_buffer) > code_gen_buffer_size)
        cpu_abort(env1, "Internal error: code buffer overflow\n");

    nb_tbs = 0;

    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        memset (env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof (void *));
    }

    memset (tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof (void *));
    page_flush_tb();

    code_gen_ptr = code_gen_buffer;
}

/* invalidate one TB */
static inline void tb_remove(TranslationBlock **ptb, TranslationBlock *tb,
                             int next_offset)
{
    TranslationBlock *tb1;
    for(;;) {
        tb1 = *ptb;
        if (tb1 == tb) {
            *ptb = *(TranslationBlock **)((char *)tb1 + next_offset);
            break;
        }
        ptb = (TranslationBlock **)((char *)tb1 + next_offset);
    }
}

static inline void tb_page_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
    TranslationBlock *tb1;
    unsigned int n1;

    for(;;) {
        tb1 = *ptb;
        n1 = (long)tb1 & 3;
        tb1 = (TranslationBlock *)((long)tb1 & ~3);
        if (tb1 == tb) {
            *ptb = tb1->page_next[n1];
            break;
        }
        ptb = &tb1->page_next[n1];
    }
}

static inline void tb_jmp_remove(TranslationBlock *tb, int n)
{
    TranslationBlock *tb1, **ptb;
    unsigned int n1;

    ptb = &tb->jmp_next[n];
    tb1 = *ptb;
    if (tb1) {
        /* find tb(n) in circular list */
        for(;;) {
            tb1 = *ptb;
            n1 = (long)tb1 & 3;
            tb1 = (TranslationBlock *)((long)tb1 & ~3);
            if (n1 == n && tb1 == tb)
                break;
            if (n1 == 2) {
                ptb = &tb1->jmp_first;
            } else {
                ptb = &tb1->jmp_next[n1];
            }
        }
        /* now we can suppress tb(n) from the list */
        *ptb = tb->jmp_next[n];

        tb->jmp_next[n] = NULL;
    }
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
static inline void tb_reset_jump(TranslationBlock *tb, int n)
{
    tb_set_jmp_target(tb, n, (unsigned long)(tb->tc_ptr + tb->tb_next_offset[n]));
}

void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr)
{
    CPUState *env;
    PageDesc *p;
    unsigned int h, n1;
    tb_page_addr_t phys_pc;
    TranslationBlock *tb1, *tb2;

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_phys_hash_func(phys_pc);
    tb_remove(&tb_phys_hash[h], tb,
              offsetof(TranslationBlock, phys_hash_next));

    /* remove the TB from the page list */
    if (tb->page_addr[0] != page_addr) {
        p = page_find(tb->page_addr[0] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }
    if (tb->page_addr[1] != -1 && tb->page_addr[1] != page_addr) {
        p = page_find(tb->page_addr[1] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }

    /* remove the TB from the hash list */
    h = tb_jmp_cache_hash_func(tb->pc);
    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->tb_jmp_cache[h] == tb)
            env->tb_jmp_cache[h] = NULL;
    }

    /* suppress this TB from the two jump lists */
    tb_jmp_remove(tb, 0);
    tb_jmp_remove(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb1 = tb->jmp_first;
    for(;;) {
        n1 = (long)tb1 & 3;
        if (n1 == 2)
            break;
        tb1 = (TranslationBlock *)((long)tb1 & ~3);
        tb2 = tb1->jmp_next[n1];
        tb_reset_jump(tb1, n1);
        tb1->jmp_next[n1] = NULL;
        tb1 = tb2;
    }
    tb->jmp_first = (TranslationBlock *)((long)tb | 2); /* fail safe */
}

static inline void set_bits(uint8_t *tab, int start, int len)
{
    int end, mask, end1;

    end = start + len;
    tab += start >> 3;
    mask = 0xff << (start & 7);
    if ((start & ~7) == (end & ~7)) {
        if (start < end) {
            mask &= ~(0xff << (end & 7));
            *tab |= mask;
        }
    } else {
        *tab++ |= mask;
        start = (start + 8) & ~7;
        end1 = end & ~7;
        while (start < end1) {
            *tab++ = 0xff;
            start += 8;
        }
        if (start < end) {
            mask = ~(0xff << (end & 7));
            *tab |= mask;
        }
    }
}

static void build_page_bitmap(PageDesc *p)
{
    int n, tb_start, tb_end;
    TranslationBlock *tb;

    p->code_bitmap = calloc(1, TARGET_PAGE_SIZE / 8);

    tb = p->first_tb;
    while (tb != NULL) {
        n = (long)tb & 3;
        tb = (TranslationBlock *)((long)tb & ~3);
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->pc & ~TARGET_PAGE_MASK;
            tb_end = tb_start + tb->size;
            if (tb_end > TARGET_PAGE_SIZE)
                tb_end = TARGET_PAGE_SIZE;
        } else {
            tb_start = 0;
            tb_end = ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        set_bits(p->code_bitmap, tb_start, tb_end - tb_start);
        tb = tb->page_next[n];
    }
}

/* invalidate all TBs which intersect with the target physical page
   starting in range [start;end[. NOTE: start and end must refer to
   the same physical page. 'is_cpu_write_access' should be true if called
   from a real cpu write access: the virtual CPU will exit the current
   TB if code is modified inside this TB. */
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access)
{
    TranslationBlock *tb, *tb_next, *saved_tb;
    CPUState *env = cpu_single_env;
    tb_page_addr_t tb_start, tb_end;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    int current_tb_not_found = is_cpu_write_access;
    TranslationBlock *current_tb = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    int current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

    p = page_find(start >> TARGET_PAGE_BITS);
    if (!p)
        return;
    if (!p->code_bitmap &&
        ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD &&
        is_cpu_write_access) {
        /* build code bitmap */
        build_page_bitmap(p);
    }

    /* we remove all the TBs in the range [start, end[ */
    /* XXX: see if in some cases it could be faster to invalidate all the code */
    tb = p->first_tb;
    while (tb != NULL) {
        n = (long)tb & 3;
        tb = (TranslationBlock *)((long)tb & ~3);
        tb_next = tb->page_next[n];
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
            tb_end = tb_start + tb->size;
        } else {
            tb_start = tb->page_addr[1];
            tb_end = tb_start + ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        if (!(tb_end <= start || tb_start >= end)) {
#ifdef TARGET_HAS_PRECISE_SMC
            if (current_tb_not_found) {
                current_tb_not_found = 0;
                current_tb = NULL;
                if (env->mem_io_pc) {
                    /* now we have a real cpu fault */
                    current_tb = tb_find_pc(env->mem_io_pc);
                }
            }
            if (current_tb == tb &&
                (current_tb->cflags & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                its execution. We could be more precise by checking
                that the modification is after the current PC, but it
                would require a specialized function to partially
                restore the CPU state */

                current_tb_modified = 1;
                cpu_restore_state(current_tb, env, env->mem_io_pc);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                     &current_flags);
            }
#endif /* TARGET_HAS_PRECISE_SMC */
            /* we need to do that to handle the case where a signal
               occurs while doing tb_phys_invalidate() */
            saved_tb = NULL;
            if (env) {
                saved_tb = env->current_tb;
                env->current_tb = NULL;
            }
            tb_phys_invalidate(tb, -1);
            if (env) {
                env->current_tb = saved_tb;
                if (env->interrupt_request && env->current_tb)
                    cpu_interrupt(env, env->interrupt_request);
            }
        }
        tb = tb_next;
    }
    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        invalidate_page_bitmap(p);
        if (is_cpu_write_access) {
            tlb_unprotect_code_phys(env, start, env->mem_io_vaddr);
        }
    }
#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        /* we generate a block containing just the instruction
           modifying the memory. It will ensure that it cannot modify
           itself */
        env->current_tb = NULL;
        tb_gen_code(env, current_pc, current_cs_base, current_flags, 1);
        env->exception_index = -1;
        longjmp(env->jmp_env, 1);
    }
#endif
}

/* len must be <= 8 and start must be a multiple of len */
static inline void tb_invalidate_phys_page_fast(tb_page_addr_t start, int len)
{
    PageDesc *p;
    int offset, b;

    p = page_find(start >> TARGET_PAGE_BITS);
    if (!p)
        return;
    if (p->code_bitmap) {
        offset = start & ~TARGET_PAGE_MASK;
        b = p->code_bitmap[offset >> 3] >> (offset & 7);
        if (b & ((1 << len) - 1))
            goto do_invalidate;
    } else {
    do_invalidate:
        tb_invalidate_phys_page_range(start, start + len, 1);
    }
}

/* add the tb in the target page and protect it if necessary */
static inline void tb_alloc_page(TranslationBlock *tb,
                                 unsigned int n, tb_page_addr_t page_addr)
{
    PageDesc *p;
    bool page_already_protected;

    tb->page_addr[n] = page_addr;
    p = page_find_alloc(page_addr >> TARGET_PAGE_BITS, 1);
    tb->page_next[n] = p->first_tb;
    page_already_protected = p->first_tb != NULL;
    p->first_tb = (TranslationBlock *)((long)tb | n);
    invalidate_page_bitmap(p);

#if defined(TARGET_HAS_SMC) || 1

    /* if some code is already present, then the pages are already
       protected. So we handle the case where only the first TB is
       allocated in a physical page */
    if (!page_already_protected) {
        tlb_protect_code(page_addr);
    }
#endif /* TARGET_HAS_SMC */
}

/* add a new TB and link it to the physical page tables. phys_page2 is
   (-1) to indicate that only one page contains the TB. */
void tb_link_page(TranslationBlock *tb,
                  tb_page_addr_t phys_pc, tb_page_addr_t phys_page2)
{
    unsigned int h;
    TranslationBlock **ptb;

    /* Grab the mmap lock to stop another thread invalidating this TB
       before we are done.  */
    mmap_lock();
    /* add in the physical hash table */
    h = tb_phys_hash_func(phys_pc);
    ptb = &tb_phys_hash[h];
    tb->phys_hash_next = *ptb;
    *ptb = tb;

    /* add in the page list */
    tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1)
        tb_alloc_page(tb, 1, phys_page2);
    else
        tb->page_addr[1] = -1;

    tb->jmp_first = (TranslationBlock *)((long)tb | 2);
    tb->jmp_next[0] = NULL;
    tb->jmp_next[1] = NULL;

    /* init original jump addresses */
    if (tb->tb_next_offset[0] != 0xffff)
        tb_reset_jump(tb, 0);
    if (tb->tb_next_offset[1] != 0xffff)
        tb_reset_jump(tb, 1);

    mmap_unlock();
}

/* find the TB 'tb' such that tb[0].tc_ptr <= tc_ptr <
   tb[1].tc_ptr. Return NULL if not found */
TranslationBlock *tb_find_pc(unsigned long tc_ptr)
{
    int m_min, m_max, m;
    unsigned long v;
    TranslationBlock *tb;

    if (nb_tbs <= 0)
        return NULL;
    if (tc_ptr < (unsigned long)code_gen_buffer ||
        tc_ptr >= (unsigned long)code_gen_ptr)
        return NULL;
    /* binary search (cf Knuth) */
    m_min = 0;
    m_max = nb_tbs - 1;
    while (m_min <= m_max) {
        m = (m_min + m_max) >> 1;
        tb = &tbs[m];
        v = (unsigned long)tb->tc_ptr;
        if (v == tc_ptr)
            return tb;
        else if (tc_ptr < v) {
            m_max = m - 1;
        } else {
            m_min = m + 1;
        }
    }
    return &tbs[m_max];
}

static void tb_reset_jump_recursive(TranslationBlock *tb);

static inline void tb_reset_jump_recursive2(TranslationBlock *tb, int n)
{
    TranslationBlock *tb1, *tb_next, **ptb;
    unsigned int n1;

    tb1 = tb->jmp_next[n];
    if (tb1 != NULL) {
        /* find head of list */
        for(;;) {
            n1 = (long)tb1 & 3;
            tb1 = (TranslationBlock *)((long)tb1 & ~3);
            if (n1 == 2)
                break;
            tb1 = tb1->jmp_next[n1];
        }
        /* we are now sure now that tb jumps to tb1 */
        tb_next = tb1;

        /* remove tb from the jmp_first list */
        ptb = &tb_next->jmp_first;
        for(;;) {
            tb1 = *ptb;
            n1 = (long)tb1 & 3;
            tb1 = (TranslationBlock *)((long)tb1 & ~3);
            if (n1 == n && tb1 == tb)
                break;
            ptb = &tb1->jmp_next[n1];
        }
        *ptb = tb->jmp_next[n];
        tb->jmp_next[n] = NULL;

        /* suppress the jump to next tb in generated code */
        tb_reset_jump(tb, n);

        /* suppress jumps in the tb on which we could have jumped */
        tb_reset_jump_recursive(tb_next);
    }
}

static void tb_reset_jump_recursive(TranslationBlock *tb)
{
    tb_reset_jump_recursive2(tb, 0);
    tb_reset_jump_recursive2(tb, 1);
}

static void cpu_unlink_tb(CPUState *env)
{
    TranslationBlock *tb;

    tb = env->current_tb;
    /* if the cpu is currently executing code, we must unlink it and
       all the potentially executing TB */
    if (tb) {
        env->current_tb = NULL;
        tb_reset_jump_recursive(tb);
    }
}

void cpu_reset_interrupt(CPUState *env, int mask)
{
    env->interrupt_request &= ~mask;
}

void cpu_exit(CPUState *env)
{
    env->exit_request = 1;
    cpu_unlink_tb(env);
}

static QLIST_HEAD(memory_client_list, CPUPhysMemoryClient) memory_client_list
    = QLIST_HEAD_INITIALIZER(memory_client_list);

static void cpu_notify_set_memory(target_phys_addr_t start_addr,
                                  ram_addr_t size,
                                  ram_addr_t phys_offset,
                                  bool log_dirty)
{
    CPUPhysMemoryClient *client;
    QLIST_FOREACH(client, &memory_client_list, list) {
        client->set_memory(client, start_addr, size, phys_offset, log_dirty);
    }
}

static int cpu_notify_sync_dirty_bitmap(target_phys_addr_t start,
                                        target_phys_addr_t end)
{
    CPUPhysMemoryClient *client;
    QLIST_FOREACH(client, &memory_client_list, list) {
        int r = client->sync_dirty_bitmap(client, start, end);
        if (r < 0)
            return r;
    }
    return 0;
}

struct last_map {
    target_phys_addr_t start_addr;
    ram_addr_t size;
    ram_addr_t phys_offset;
};

/* The l1_phys_map provides the upper P_L1_BITs of the guest physical
 * address.  Each intermediate table provides the next L2_BITs of guest
 * physical address space.  The number of levels vary based on host and
 * guest configuration, making it efficient to build the final guest
 * physical address by seeding the L1 offset and shifting and adding in
 * each L2 offset as we recurse through them. */
static void phys_page_for_each_1(CPUPhysMemoryClient *client, int level,
                                 void **lp, target_phys_addr_t addr,
                                 struct last_map *map)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PhysPageDesc *pd = *lp;
        addr <<= L2_BITS + TARGET_PAGE_BITS;
        for (i = 0; i < L2_SIZE; ++i) {
            if (pd[i].phys_offset != IO_MEM_UNASSIGNED) {
                target_phys_addr_t start_addr = addr | i << TARGET_PAGE_BITS;

                if (map->size &&
                    start_addr == map->start_addr + map->size &&
                    pd[i].phys_offset == map->phys_offset + map->size) {

                    map->size += TARGET_PAGE_SIZE;
                    continue;
                } else if (map->size) {
                    client->set_memory(client, map->start_addr,
                                       map->size, map->phys_offset, false);
                }

                map->start_addr = start_addr;
                map->size = TARGET_PAGE_SIZE;
                map->phys_offset = pd[i].phys_offset;
            }
        }
    } else {
        void **pp = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            phys_page_for_each_1(client, level - 1, pp + i,
                                 (addr << L2_BITS) | i, map);
        }
    }
}

static void phys_page_for_each(CPUPhysMemoryClient *client)
{
    int i;
    struct last_map map = { };

    for (i = 0; i < P_L1_SIZE; ++i) {
        phys_page_for_each_1(client, P_L1_SHIFT / L2_BITS - 1,
                             l1_phys_map + i, i, &map);
    }
    if (map.size) {
        client->set_memory(client, map.start_addr, map.size, map.phys_offset,
                           false);
    }
}

void cpu_register_phys_memory_client(CPUPhysMemoryClient *client)
{
    QLIST_INSERT_HEAD(&memory_client_list, client, list);
    phys_page_for_each(client);
}

void cpu_unregister_phys_memory_client(CPUPhysMemoryClient *client)
{
    QLIST_REMOVE(client, list);
}

void cpu_abort(CPUState *env, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap2);
    va_end(ap);

    abort();
}

CPUState *cpu_copy(CPUState *env)
{
    CPUState *new_env = cpu_x86_init(env->cpu_model_str);
    CPUState *next_cpu = new_env->next_cpu;
    int cpu_index = new_env->cpu_index;

    memcpy(new_env, env, sizeof(CPUState));

    /* Preserve chaining and index. */
    new_env->next_cpu = next_cpu;
    new_env->cpu_index = cpu_index;

    return new_env;
}

static inline void tlb_flush_jmp_cache(CPUState *env, target_ulong addr)
{
    unsigned int i;

    /* Discard jump cache entries for any tb which might potentially
       overlap the flushed page.  */
    i = tb_jmp_cache_hash_page(addr - TARGET_PAGE_SIZE);
    memset (&env->tb_jmp_cache[i], 0, 
            TB_JMP_PAGE_SIZE * sizeof(TranslationBlock *));

    i = tb_jmp_cache_hash_page(addr);
    memset (&env->tb_jmp_cache[i], 0, 
            TB_JMP_PAGE_SIZE * sizeof(TranslationBlock *));
}

static CPUTLBEntry s_cputlb_empty_entry = {
    .addr_read  = -1,
    .addr_write = -1,
    .addr_code  = -1,
    .addend     = -1,
};

/* NOTE: if flush_global is true, also flush global entries (not
   implemented yet) */
void tlb_flush(CPUState *env, int flush_global)
{
    int i;

#if defined(DEBUG_TLB)
    printf("tlb_flush:\n");
#endif
    /* must reset current TB so that interrupts cannot modify the
       links while we are modifying them */
    env->current_tb = NULL;

    for(i = 0; i < CPU_TLB_SIZE; i++) {
        int mmu_idx;
        for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
            env->tlb_table[mmu_idx][i] = s_cputlb_empty_entry;
        }
    }

    memset (env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof (void *));

    env->tlb_flush_addr = -1;
    env->tlb_flush_mask = 0;
}

static inline void tlb_flush_entry(CPUTLBEntry *tlb_entry, target_ulong addr)
{
    if (addr == (tlb_entry->addr_read &
                 (TARGET_PAGE_MASK | TLB_INVALID_MASK)) ||
        addr == (tlb_entry->addr_write &
                 (TARGET_PAGE_MASK | TLB_INVALID_MASK)) ||
        addr == (tlb_entry->addr_code &
                 (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        *tlb_entry = s_cputlb_empty_entry;
    }
}

void tlb_flush_page(CPUState *env, target_ulong addr)
{
    int i;
    int mmu_idx;

#if defined(DEBUG_TLB)
    printf("tlb_flush_page: " TARGET_FMT_lx "\n", addr);
#endif
    /* Check if we need to flush due to large pages.  */
    if ((addr & env->tlb_flush_mask) == env->tlb_flush_addr) {
#if defined(DEBUG_TLB)
        printf("tlb_flush_page: forced full flush ("
               TARGET_FMT_lx "/" TARGET_FMT_lx ")\n",
               env->tlb_flush_addr, env->tlb_flush_mask);
#endif
        tlb_flush(env, 1);
        return;
    }
    /* must reset current TB so that interrupts cannot modify the
       links while we are modifying them */
    env->current_tb = NULL;

    addr &= TARGET_PAGE_MASK;
    i = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++)
        tlb_flush_entry(&env->tlb_table[mmu_idx][i], addr);

    tlb_flush_jmp_cache(env, addr);
}

/* update the TLBs so that writes to code in the virtual page 'addr'
   can be detected */
static void tlb_protect_code(ram_addr_t ram_addr)
{
    cpu_physical_memory_reset_dirty(ram_addr,
                                    ram_addr + TARGET_PAGE_SIZE,
                                    CODE_DIRTY_FLAG);
}

/* update the TLB so that writes in physical page 'phys_addr' are no longer
   tested for self modifying code */
static void tlb_unprotect_code_phys(CPUState *env, ram_addr_t ram_addr,
                                    target_ulong vaddr)
{
    cpu_physical_memory_set_dirty_flags(ram_addr, CODE_DIRTY_FLAG);
}

static inline void tlb_reset_dirty_range(CPUTLBEntry *tlb_entry,
                                         unsigned long start, unsigned long length)
{
    unsigned long addr;
    if ((tlb_entry->addr_write & ~TARGET_PAGE_MASK) == IO_MEM_RAM) {
        addr = (tlb_entry->addr_write & TARGET_PAGE_MASK) + tlb_entry->addend;
        if ((addr - start) < length) {
            tlb_entry->addr_write = (tlb_entry->addr_write & TARGET_PAGE_MASK) | TLB_NOTDIRTY;
        }
    }
}

/* Note: start and end must be within the same ram block.  */
void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end,
                                     int dirty_flags)
{
    CPUState *env;
    unsigned long length, start1;
    int i;

    start &= TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    length = end - start;
    if (length == 0)
        return;
    cpu_physical_memory_mask_dirty_range(start, length, dirty_flags);

    /* we modify the TLB cache so that the dirty bit will be set again
       when accessing the range */
    start1 = (unsigned long)qemu_safe_ram_ptr(start);
    /* Check that we don't span multiple blocks - this breaks the
       address comparisons below.  */
    if ((unsigned long)qemu_safe_ram_ptr(end - 1) - start1
            != (end - 1) - start) {
        abort();
    }

    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        int mmu_idx;
        for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
            for(i = 0; i < CPU_TLB_SIZE; i++)
                tlb_reset_dirty_range(&env->tlb_table[mmu_idx][i],
                                      start1, length);
        }
    }
}

int cpu_physical_sync_dirty_bitmap(target_phys_addr_t start_addr,
                                   target_phys_addr_t end_addr)
{
    int ret;

    ret = cpu_notify_sync_dirty_bitmap(start_addr, end_addr);
    return ret;
}

static inline void tlb_update_dirty(CPUTLBEntry *tlb_entry)
{
    ram_addr_t ram_addr;
    void *p;

    if ((tlb_entry->addr_write & ~TARGET_PAGE_MASK) == IO_MEM_RAM) {
        p = (void *)(unsigned long)((tlb_entry->addr_write & TARGET_PAGE_MASK)
            + tlb_entry->addend);
        ram_addr = qemu_ram_addr_from_host_nofail(p);
        if (!cpu_physical_memory_is_dirty(ram_addr)) {
            tlb_entry->addr_write |= TLB_NOTDIRTY;
        }
    }
}

static inline void tlb_set_dirty1(CPUTLBEntry *tlb_entry, target_ulong vaddr)
{
    if (tlb_entry->addr_write == (vaddr | TLB_NOTDIRTY))
        tlb_entry->addr_write = vaddr;
}

/* update the TLB corresponding to virtual page vaddr
   so that it is no longer dirty */
static inline void tlb_set_dirty(CPUState *env, target_ulong vaddr)
{
    int i;
    int mmu_idx;

    vaddr &= TARGET_PAGE_MASK;
    i = (vaddr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++)
        tlb_set_dirty1(&env->tlb_table[mmu_idx][i], vaddr);
}

/* Our TLB does not support large pages, so remember the area covered by
   large pages and trigger a full TLB flush if these are invalidated.  */
static void tlb_add_large_page(CPUState *env, target_ulong vaddr,
                               target_ulong size)
{
    target_ulong mask = ~(size - 1);

    if (env->tlb_flush_addr == (target_ulong)-1) {
        env->tlb_flush_addr = vaddr & mask;
        env->tlb_flush_mask = mask;
        return;
    }
    /* Extend the existing region to include the new page.
       This is a compromise between unnecessary flushes and the cost
       of maintaining a full variable size TLB.  */
    mask &= env->tlb_flush_mask;
    while (((env->tlb_flush_addr ^ vaddr) & mask) != 0) {
        mask <<= 1;
    }
    env->tlb_flush_addr &= mask;
    env->tlb_flush_mask = mask;
}

/* Add a new TLB entry. At most one entry for a given virtual address
   is permitted. Only a single TARGET_PAGE_SIZE region is mapped, the
   supplied size is only used by tlb_flush_page.  */
void tlb_set_page(CPUState *env, target_ulong vaddr,
                  target_phys_addr_t paddr, int prot,
                  int mmu_idx, target_ulong size)
{
    PhysPageDesc *p;
    unsigned long pd;
    unsigned int index;
    target_ulong address;
    target_ulong code_address;
    unsigned long addend;
    CPUTLBEntry *te;
    target_phys_addr_t iotlb;

    assert(size >= TARGET_PAGE_SIZE);
    if (size != TARGET_PAGE_SIZE) {
        tlb_add_large_page(env, vaddr, size);
    }
    p = phys_page_find(paddr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }
#if defined(DEBUG_TLB)
    printf("tlb_set_page: vaddr=" TARGET_FMT_lx " paddr=0x" TARGET_FMT_plx
           " prot=%x idx=%d pd=0x%08lx\n",
           vaddr, paddr, prot, mmu_idx, pd);
#endif

    address = vaddr;
    if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM && !(pd & IO_MEM_ROMD)) {
        /* IO memory case (romd handled later) */
        address |= TLB_MMIO;
    }
    addend = (unsigned long)qemu_get_ram_ptr(pd & TARGET_PAGE_MASK);
    if ((pd & ~TARGET_PAGE_MASK) <= IO_MEM_ROM) {
        /* Normal RAM.  */
        iotlb = pd & TARGET_PAGE_MASK;
        if ((pd & ~TARGET_PAGE_MASK) == IO_MEM_RAM)
            iotlb |= IO_MEM_NOTDIRTY;
        else
            iotlb |= IO_MEM_ROM;
    } else {
        /* IO handlers are currently passed a physical address.
           It would be nice to pass an offset from the base address
           of that region.  This would avoid having to special case RAM,
           and avoid full address decoding in every device.
           We can't use the high bits of pd for this because
           IO_MEM_ROMD uses these as a ram address.  */
        iotlb = (pd & ~TARGET_PAGE_MASK);
        if (p) {
            iotlb += p->region_offset;
        } else {
            iotlb += paddr;
        }
    }

    code_address = address;
    index = (vaddr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    env->iotlb[mmu_idx][index] = iotlb - vaddr;
    te = &env->tlb_table[mmu_idx][index];
    te->addend = addend - vaddr;
    if (prot & PAGE_READ) {
        te->addr_read = address;
    } else {
        te->addr_read = -1;
    }

    if (prot & PAGE_EXEC) {
        te->addr_code = code_address;
    } else {
        te->addr_code = -1;
    }
    if (prot & PAGE_WRITE) {
        if ((pd & ~TARGET_PAGE_MASK) == IO_MEM_ROM ||
            (pd & IO_MEM_ROMD)) {
            /* Write access calls the I/O callback.  */
            te->addr_write = address | TLB_MMIO;
        } else if ((pd & ~TARGET_PAGE_MASK) == IO_MEM_RAM &&
                   !cpu_physical_memory_is_dirty(pd)) {
            te->addr_write = address | TLB_NOTDIRTY;
        } else {
            te->addr_write = address;
        }
    } else {
        te->addr_write = -1;
    }
}

#define SUBPAGE_IDX(addr) ((addr) & ~TARGET_PAGE_MASK)
typedef struct subpage_t {
    target_phys_addr_t base;
    ram_addr_t sub_io_index[TARGET_PAGE_SIZE];
    ram_addr_t region_offset[TARGET_PAGE_SIZE];
} subpage_t;

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
                             ram_addr_t memory, ram_addr_t region_offset);
static subpage_t *subpage_init (target_phys_addr_t base, ram_addr_t *phys,
                                ram_addr_t orig_memory,
                                ram_addr_t region_offset);
#define CHECK_SUBPAGE(addr, start_addr, start_addr2, end_addr, end_addr2, \
                      need_subpage)                                     \
    do {                                                                \
        if (addr > start_addr)                                          \
            start_addr2 = 0;                                            \
        else {                                                          \
            start_addr2 = start_addr & ~TARGET_PAGE_MASK;               \
            if (start_addr2 > 0)                                        \
                need_subpage = 1;                                       \
        }                                                               \
                                                                        \
        if ((start_addr + orig_size) - addr >= TARGET_PAGE_SIZE)        \
            end_addr2 = TARGET_PAGE_SIZE - 1;                           \
        else {                                                          \
            end_addr2 = (start_addr + orig_size - 1) & ~TARGET_PAGE_MASK; \
            if (end_addr2 < TARGET_PAGE_SIZE - 1)                       \
                need_subpage = 1;                                       \
        }                                                               \
    } while (0)

/* register physical memory.
   For RAM, 'size' must be a multiple of the target page size.
   If (phys_offset & ~TARGET_PAGE_MASK) != 0, then it is an
   io memory page.  The address used when calling the IO function is
   the offset from the start of the region, plus region_offset.  Both
   start_addr and region_offset are rounded down to a page boundary
   before calculating this offset.  This should not be a problem unless
   the low bits of start_addr and region_offset differ.  */
void cpu_register_physical_memory_log(target_phys_addr_t start_addr,
                                         ram_addr_t size,
                                         ram_addr_t phys_offset,
                                         ram_addr_t region_offset,
                                         bool log_dirty)
{
    target_phys_addr_t addr, end_addr;
    PhysPageDesc *p;
    CPUState *env;
    ram_addr_t orig_size = size;
    subpage_t *subpage;

    assert(size);
    cpu_notify_set_memory(start_addr, size, phys_offset, log_dirty);

    if (phys_offset == IO_MEM_UNASSIGNED) {
        region_offset = start_addr;
    }
    region_offset &= TARGET_PAGE_MASK;
    size = (size + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK;
    end_addr = start_addr + (target_phys_addr_t)size;

    addr = start_addr;
    do {
        p = phys_page_find(addr >> TARGET_PAGE_BITS);
        if (p && p->phys_offset != IO_MEM_UNASSIGNED) {
            ram_addr_t orig_memory = p->phys_offset;
            target_phys_addr_t start_addr2, end_addr2;
            int need_subpage = 0;

            CHECK_SUBPAGE(addr, start_addr, start_addr2, end_addr, end_addr2,
                          need_subpage);
            if (need_subpage) {
                if (!(orig_memory & IO_MEM_SUBPAGE)) {
                    subpage = subpage_init((addr & TARGET_PAGE_MASK),
                                           &p->phys_offset, orig_memory,
                                           p->region_offset);
                } else {
                    subpage = io_mem_opaque[(orig_memory & ~TARGET_PAGE_MASK)
                                            >> IO_MEM_SHIFT];
                }
                subpage_register(subpage, start_addr2, end_addr2, phys_offset,
                                 region_offset);
                p->region_offset = 0;
            } else {
                p->phys_offset = phys_offset;
                if ((phys_offset & ~TARGET_PAGE_MASK) <= IO_MEM_ROM ||
                    (phys_offset & IO_MEM_ROMD))
                    phys_offset += TARGET_PAGE_SIZE;
            }
        } else {
            p = phys_page_find_alloc(addr >> TARGET_PAGE_BITS, 1);
            p->phys_offset = phys_offset;
            p->region_offset = region_offset;
            if ((phys_offset & ~TARGET_PAGE_MASK) <= IO_MEM_ROM ||
                (phys_offset & IO_MEM_ROMD)) {
                phys_offset += TARGET_PAGE_SIZE;
            } else {
                target_phys_addr_t start_addr2, end_addr2;
                int need_subpage = 0;

                CHECK_SUBPAGE(addr, start_addr, start_addr2, end_addr,
                              end_addr2, need_subpage);

                if (need_subpage) {
                    subpage = subpage_init((addr & TARGET_PAGE_MASK),
                                           &p->phys_offset, IO_MEM_UNASSIGNED,
                                           addr & TARGET_PAGE_MASK);
                    subpage_register(subpage, start_addr2, end_addr2,
                                     phys_offset, region_offset);
                    p->region_offset = 0;
                }
            }
        }
        region_offset += TARGET_PAGE_SIZE;
        addr += TARGET_PAGE_SIZE;
    } while (addr != end_addr);

    /* since each CPU stores ram addresses in its TLB cache, we must
       reset the modified entries */
    /* XXX: slow ! */
    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        tlb_flush(env, 1);
    }
}

/* XXX: temporary until new memory mapping API */
ram_addr_t cpu_get_physical_page_desc(target_phys_addr_t addr)
{
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p)
        return IO_MEM_UNASSIGNED;
    return p->phys_offset;
}

void qemu_register_coalesced_mmio(target_phys_addr_t addr, ram_addr_t size)
{
    kvm_coalesce_mmio_region(addr, size);
}

void qemu_unregister_coalesced_mmio(target_phys_addr_t addr, ram_addr_t size)
{
    kvm_uncoalesce_mmio_region(addr, size);
}

void qemu_flush_coalesced_mmio_buffer(void)
{
    kvm_flush_coalesced_mmio_buffer();
}

#include <sys/vfs.h>

#define HUGETLBFS_MAGIC       0x958458f6

static ram_addr_t find_ram_offset(ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    if (QLIST_EMPTY(&ram_list.blocks))
        return 0;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        ram_addr_t end, next = RAM_ADDR_MAX;

        end = block->offset + block->length;

        QLIST_FOREACH(next_block, &ram_list.blocks, next) {
            if (next_block->offset >= end) {
                next = MIN(next, next_block->offset);
            }
        }
        if (next - end >= size && next - end < mingap) {
            offset = end;
            mingap = next - end;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n",
                (uint64_t)size);
        abort();
    }

    return offset;
}

static ram_addr_t last_ram_offset(void)
{
    RAMBlock *block;
    ram_addr_t last = 0;

    QLIST_FOREACH(block, &ram_list.blocks, next)
        last = MAX(last, block->offset + block->length);

    return last;
}

ram_addr_t qemu_ram_alloc_from_ptr(DeviceState *dev, const char *name,
                                   ram_addr_t size, void *host)
{
    RAMBlock *new_block, *block;

    size = TARGET_PAGE_ALIGN(size);
    new_block = calloc(1, sizeof(*new_block));

    if (dev && dev->parent_bus && dev->parent_bus->info->get_dev_path) {
        char *id = dev->parent_bus->info->get_dev_path(dev);
        if (id) {
            snprintf(new_block->idstr, sizeof(new_block->idstr), "%s/", id);
            free(id);
            id = NULL;
        }
    }
    pstrcat(new_block->idstr, sizeof(new_block->idstr), name);

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (!strcmp(block->idstr, new_block->idstr)) {
            fprintf(stderr, "RAMBlock \"%s\" already registered, abort!\n",
                    new_block->idstr);
            abort();
        }
    }

    new_block->offset = find_ram_offset(size);
    if (host) {
        new_block->host = host;
        new_block->flags |= RAM_PREALLOC_MASK;
    } else {
        new_block->host = qemu_vmalloc(size);
        madvise(new_block->host, size, MADV_MERGEABLE);
    }
    new_block->length = size;

    QLIST_INSERT_HEAD(&ram_list.blocks, new_block, next);

    ram_list.phys_dirty = realloc(ram_list.phys_dirty,
                                       last_ram_offset() >> TARGET_PAGE_BITS);
    memset(ram_list.phys_dirty + (new_block->offset >> TARGET_PAGE_BITS),
           0xff, size >> TARGET_PAGE_BITS);

    kvm_setup_guest_memory(new_block->host, size);

    return new_block->offset;
}

ram_addr_t qemu_ram_alloc(DeviceState *dev, const char *name, ram_addr_t size)
{
    return qemu_ram_alloc_from_ptr(dev, name, size, NULL);
}

void qemu_ram_free_from_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr == block->offset) {
            QLIST_REMOVE(block, next);
            free(block);
            block = NULL;
            return;
        }
    }
}

void qemu_ram_free(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr == block->offset) {
            QLIST_REMOVE(block, next);
            if (block->flags & RAM_PREALLOC_MASK) {
                ;
            } else {
                free(block->host);
            }
            free(block);
            block = NULL;
            return;
        }
    }

}

void qemu_ram_remap(ram_addr_t addr, ram_addr_t length)
{
    RAMBlock *block;
    ram_addr_t offset;
    int flags;
    void *area, *vaddr;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        offset = addr - block->offset;
        if (offset < block->length) {
            vaddr = block->host + offset;
            if (block->flags & RAM_PREALLOC_MASK) {
                ;
            } else {
                flags = MAP_FIXED;
                munmap(vaddr, length);
                flags |= MAP_PRIVATE | MAP_ANONYMOUS;
                area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                                flags, -1, 0);
                if (area != vaddr) {
                    fprintf(stderr, "Could not remap addr: "
                            RAM_ADDR_FMT "@" RAM_ADDR_FMT "\n",
                            length, addr);
                    exit(1);
                }
                madvise(vaddr, length, MADV_MERGEABLE);
            }
            return;
        }
    }
}

/* Return a host pointer to ram allocated with qemu_ram_alloc.
   With the exception of the softmmu code in this file, this should
   only be used for local memory (e.g. video ram) that the device owns,
   and knows it isn't going to access beyond the end of the block.

   It should not be used for general purpose DMA.
   Use cpu_physical_memory_map/cpu_physical_memory_rw instead.
 */
void *qemu_get_ram_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            /* Move this entry to to start of the list.  */
            if (block != QLIST_FIRST(&ram_list.blocks)) {
                QLIST_REMOVE(block, next);
                QLIST_INSERT_HEAD(&ram_list.blocks, block, next);
            }
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

    return NULL;
}

/* Return a host pointer to ram allocated with qemu_ram_alloc.
 * Same as qemu_get_ram_ptr but avoid reordering ramblocks.
 */
void *qemu_safe_ram_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

    return NULL;
}

/* Return a host pointer to guest's ram. Similar to qemu_get_ram_ptr
 * but takes a size argument */
void *qemu_ram_ptr_length(ram_addr_t addr, ram_addr_t *size)
{
    if (*size == 0) {
        return NULL;
    }
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            if (addr - block->offset + *size > block->length)
                *size = block->length - addr + block->offset;
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();
}

void qemu_put_ram_ptr(void *addr)
{
}

int qemu_ram_addr_from_host(void *ptr, ram_addr_t *ram_addr)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->length) {
            *ram_addr = block->offset + (host - block->host);
            return 0;
        }
    }

    return -1;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
ram_addr_t qemu_ram_addr_from_host_nofail(void *ptr)
{
    ram_addr_t ram_addr;

    if (qemu_ram_addr_from_host(ptr, &ram_addr)) {
        fprintf(stderr, "Bad ram pointer %p\n", ptr);
        abort();
    }
    return ram_addr;
}

static uint32_t unassigned_mem_readb(void *opaque, target_phys_addr_t addr)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem read " TARGET_FMT_plx "\n", addr);
#endif
    return 0;
}

static uint32_t unassigned_mem_readw(void *opaque, target_phys_addr_t addr)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem read " TARGET_FMT_plx "\n", addr);
#endif
    return 0;
}

static uint32_t unassigned_mem_readl(void *opaque, target_phys_addr_t addr)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem read " TARGET_FMT_plx "\n", addr);
#endif
    return 0;
}

static void unassigned_mem_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%x\n", addr, val);
#endif
}

static void unassigned_mem_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%x\n", addr, val);
#endif
}

static void unassigned_mem_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%x\n", addr, val);
#endif
}

static CPUReadMemoryFunc * const unassigned_mem_read[3] = {
    unassigned_mem_readb,
    unassigned_mem_readw,
    unassigned_mem_readl,
};

static CPUWriteMemoryFunc * const unassigned_mem_write[3] = {
    unassigned_mem_writeb,
    unassigned_mem_writew,
    unassigned_mem_writel,
};

static void notdirty_mem_writeb(void *opaque, target_phys_addr_t ram_addr,
                                uint32_t val)
{
    int dirty_flags;
    dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    if (!(dirty_flags & CODE_DIRTY_FLAG)) {
        tb_invalidate_phys_page_fast(ram_addr, 1);
        dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    }
    stb_p(qemu_get_ram_ptr(ram_addr), val);
    dirty_flags |= (0xff & ~CODE_DIRTY_FLAG);
    cpu_physical_memory_set_dirty_flags(ram_addr, dirty_flags);
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (dirty_flags == 0xff)
        tlb_set_dirty(cpu_single_env, cpu_single_env->mem_io_vaddr);
}

static void notdirty_mem_writew(void *opaque, target_phys_addr_t ram_addr,
                                uint32_t val)
{
    int dirty_flags;
    dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    if (!(dirty_flags & CODE_DIRTY_FLAG)) {
        tb_invalidate_phys_page_fast(ram_addr, 2);
        dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    }
    stw_p(qemu_get_ram_ptr(ram_addr), val);
    dirty_flags |= (0xff & ~CODE_DIRTY_FLAG);
    cpu_physical_memory_set_dirty_flags(ram_addr, dirty_flags);
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (dirty_flags == 0xff)
        tlb_set_dirty(cpu_single_env, cpu_single_env->mem_io_vaddr);
}

static void notdirty_mem_writel(void *opaque, target_phys_addr_t ram_addr,
                                uint32_t val)
{
    int dirty_flags;
    dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    if (!(dirty_flags & CODE_DIRTY_FLAG)) {
        tb_invalidate_phys_page_fast(ram_addr, 4);
        dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    }
    stl_p(qemu_get_ram_ptr(ram_addr), val);
    dirty_flags |= (0xff & ~CODE_DIRTY_FLAG);
    cpu_physical_memory_set_dirty_flags(ram_addr, dirty_flags);
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (dirty_flags == 0xff)
        tlb_set_dirty(cpu_single_env, cpu_single_env->mem_io_vaddr);
}

static CPUReadMemoryFunc * const error_mem_read[3] = {
    NULL, /* never used */
    NULL, /* never used */
    NULL, /* never used */
};

static CPUWriteMemoryFunc * const notdirty_mem_write[3] = {
    notdirty_mem_writeb,
    notdirty_mem_writew,
    notdirty_mem_writel,
};

/* Watchpoint access routines.  Watchpoints are inserted using TLB tricks,
   so these check for a hit then pass through to the normal out-of-line
   phys routines.  */
static uint32_t watch_mem_readb(void *opaque, target_phys_addr_t addr)
{
    return ldub_phys(addr);
}

static uint32_t watch_mem_readw(void *opaque, target_phys_addr_t addr)
{
    return lduw_phys(addr);
}

static uint32_t watch_mem_readl(void *opaque, target_phys_addr_t addr)
{
    return ldl_phys(addr);
}

static void watch_mem_writeb(void *opaque, target_phys_addr_t addr,
                             uint32_t val)
{
    stb_phys(addr, val);
}

static void watch_mem_writew(void *opaque, target_phys_addr_t addr,
                             uint32_t val)
{
    stw_phys(addr, val);
}

static void watch_mem_writel(void *opaque, target_phys_addr_t addr,
                             uint32_t val)
{
    stl_phys(addr, val);
}

static CPUReadMemoryFunc * const watch_mem_read[3] = {
    watch_mem_readb,
    watch_mem_readw,
    watch_mem_readl,
};

static CPUWriteMemoryFunc * const watch_mem_write[3] = {
    watch_mem_writeb,
    watch_mem_writew,
    watch_mem_writel,
};

static inline uint32_t subpage_readlen (subpage_t *mmio,
                                        target_phys_addr_t addr,
                                        unsigned int len)
{
    unsigned int idx = SUBPAGE_IDX(addr);
#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %d addr " TARGET_FMT_plx " idx %d\n", __func__,
           mmio, len, addr, idx);
#endif

    addr += mmio->region_offset[idx];
    idx = mmio->sub_io_index[idx];
    return io_mem_read[idx][len](io_mem_opaque[idx], addr);
}

static inline void subpage_writelen (subpage_t *mmio, target_phys_addr_t addr,
                                     uint32_t value, unsigned int len)
{
    unsigned int idx = SUBPAGE_IDX(addr);
#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %d addr " TARGET_FMT_plx " idx %d value %08x\n",
           __func__, mmio, len, addr, idx, value);
#endif

    addr += mmio->region_offset[idx];
    idx = mmio->sub_io_index[idx];
    io_mem_write[idx][len](io_mem_opaque[idx], addr, value);
}

static uint32_t subpage_readb (void *opaque, target_phys_addr_t addr)
{
    return subpage_readlen(opaque, addr, 0);
}

static void subpage_writeb (void *opaque, target_phys_addr_t addr,
                            uint32_t value)
{
    subpage_writelen(opaque, addr, value, 0);
}

static uint32_t subpage_readw (void *opaque, target_phys_addr_t addr)
{
    return subpage_readlen(opaque, addr, 1);
}

static void subpage_writew (void *opaque, target_phys_addr_t addr,
                            uint32_t value)
{
    subpage_writelen(opaque, addr, value, 1);
}

static uint32_t subpage_readl (void *opaque, target_phys_addr_t addr)
{
    return subpage_readlen(opaque, addr, 2);
}

static void subpage_writel (void *opaque, target_phys_addr_t addr,
                            uint32_t value)
{
    subpage_writelen(opaque, addr, value, 2);
}

static CPUReadMemoryFunc * const subpage_read[] = {
    &subpage_readb,
    &subpage_readw,
    &subpage_readl,
};

static CPUWriteMemoryFunc * const subpage_write[] = {
    &subpage_writeb,
    &subpage_writew,
    &subpage_writel,
};

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
                             ram_addr_t memory, ram_addr_t region_offset)
{
    int idx, eidx;

    if (start >= TARGET_PAGE_SIZE || end >= TARGET_PAGE_SIZE)
        return -1;
    idx = SUBPAGE_IDX(start);
    eidx = SUBPAGE_IDX(end);
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p start %08x end %08x idx %08x eidx %08x mem %ld\n", __func__,
           mmio, start, end, idx, eidx, memory);
#endif
    if ((memory & ~TARGET_PAGE_MASK) == IO_MEM_RAM)
        memory = IO_MEM_UNASSIGNED;
    memory = (memory >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
    for (; idx <= eidx; idx++) {
        mmio->sub_io_index[idx] = memory;
        mmio->region_offset[idx] = region_offset;
    }

    return 0;
}

static subpage_t *subpage_init (target_phys_addr_t base, ram_addr_t *phys,
                                ram_addr_t orig_memory,
                                ram_addr_t region_offset)
{
    subpage_t *mmio;
    int subpage_memory;

    mmio = calloc(1, sizeof(subpage_t));

    mmio->base = base;
    subpage_memory = cpu_register_io_memory(subpage_read, subpage_write, mmio,
                                            DEVICE_NATIVE_ENDIAN);
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p base " TARGET_FMT_plx " len %08x %d\n", __func__,
           mmio, base, TARGET_PAGE_SIZE, subpage_memory);
#endif
    *phys = subpage_memory | IO_MEM_SUBPAGE;
    subpage_register(mmio, 0, TARGET_PAGE_SIZE-1, orig_memory, region_offset);

    return mmio;
}

static int get_free_io_mem_idx(void)
{
    int i;

    for (i = 0; i<IO_MEM_NB_ENTRIES; i++)
        if (!io_mem_used[i]) {
            io_mem_used[i] = 1;
            return i;
        }
    fprintf(stderr, "RAN out out io_mem_idx, max %d !\n", IO_MEM_NB_ENTRIES);
    return -1;
}

/*
 * Usually, devices operate in little endian mode. There are devices out
 * there that operate in big endian too. Each device gets byte swapped
 * mmio if plugged onto a CPU that does the other endianness.
 *
 * CPU          Device           swap?
 *
 * little       little           no
 * little       big              yes
 * big          little           yes
 * big          big              no
 */

typedef struct SwapEndianContainer {
    CPUReadMemoryFunc *read[3];
    CPUWriteMemoryFunc *write[3];
    void *opaque;
} SwapEndianContainer;

static uint32_t swapendian_mem_readb (void *opaque, target_phys_addr_t addr)
{
    uint32_t val;
    SwapEndianContainer *c = opaque;
    val = c->read[0](c->opaque, addr);
    return val;
}

static uint32_t swapendian_mem_readw(void *opaque, target_phys_addr_t addr)
{
    uint32_t val;
    SwapEndianContainer *c = opaque;
    val = bswap16(c->read[1](c->opaque, addr));
    return val;
}

static uint32_t swapendian_mem_readl(void *opaque, target_phys_addr_t addr)
{
    uint32_t val;
    SwapEndianContainer *c = opaque;
    val = bswap32(c->read[2](c->opaque, addr));
    return val;
}

static CPUReadMemoryFunc * const swapendian_readfn[3]={
    swapendian_mem_readb,
    swapendian_mem_readw,
    swapendian_mem_readl
};

static void swapendian_mem_writeb(void *opaque, target_phys_addr_t addr,
                                  uint32_t val)
{
    SwapEndianContainer *c = opaque;
    c->write[0](c->opaque, addr, val);
}

static void swapendian_mem_writew(void *opaque, target_phys_addr_t addr,
                                  uint32_t val)
{
    SwapEndianContainer *c = opaque;
    c->write[1](c->opaque, addr, bswap16(val));
}

static void swapendian_mem_writel(void *opaque, target_phys_addr_t addr,
                                  uint32_t val)
{
    SwapEndianContainer *c = opaque;
    c->write[2](c->opaque, addr, bswap32(val));
}

static CPUWriteMemoryFunc * const swapendian_writefn[3]={
    swapendian_mem_writeb,
    swapendian_mem_writew,
    swapendian_mem_writel
};

static void swapendian_del(int io_index)
{
    if (io_mem_read[io_index][0] == swapendian_readfn[0]) {
        free(io_mem_opaque[io_index]);
        io_mem_opaque[io_index] = NULL;
    }
}

/* mem_read and mem_write are arrays of functions containing the
   function to access byte (index 0), word (index 1) and dword (index
   2). Functions can be omitted with a NULL function pointer.
   If io_index is non zero, the corresponding io zone is
   modified. If it is zero, a new io zone is allocated. The return
   value can be used with cpu_register_physical_memory(). (-1) is
   returned if error. */
static int cpu_register_io_memory_fixed(int io_index,
                                        CPUReadMemoryFunc * const *mem_read,
                                        CPUWriteMemoryFunc * const *mem_write,
                                        void *opaque, enum device_endian endian)
{
    int i;

    if (io_index <= 0) {
        io_index = get_free_io_mem_idx();
        if (io_index == -1)
            return io_index;
    } else {
        io_index >>= IO_MEM_SHIFT;
        if (io_index >= IO_MEM_NB_ENTRIES)
            return -1;
    }

    for (i = 0; i < 3; ++i) {
        io_mem_read[io_index][i]
            = (mem_read[i] ? mem_read[i] : unassigned_mem_read[i]);
    }
    for (i = 0; i < 3; ++i) {
        io_mem_write[io_index][i]
            = (mem_write[i] ? mem_write[i] : unassigned_mem_write[i]);
    }
    io_mem_opaque[io_index] = opaque;

    switch (endian) {
    case DEVICE_BIG_ENDIAN:
    break;
    case DEVICE_LITTLE_ENDIAN:
        break;
    case DEVICE_NATIVE_ENDIAN:
    default:
        break;
    }

    return (io_index << IO_MEM_SHIFT);
}

int cpu_register_io_memory(CPUReadMemoryFunc * const *mem_read,
                           CPUWriteMemoryFunc * const *mem_write,
                           void *opaque, enum device_endian endian)
{
    return cpu_register_io_memory_fixed(0, mem_read, mem_write, opaque, endian);
}

void cpu_unregister_io_memory(int io_table_address)
{
    int i;
    int io_index = io_table_address >> IO_MEM_SHIFT;

    swapendian_del(io_index);

    for (i=0;i < 3; i++) {
        io_mem_read[io_index][i] = unassigned_mem_read[i];
        io_mem_write[io_index][i] = unassigned_mem_write[i];
    }
    io_mem_opaque[io_index] = NULL;
    io_mem_used[io_index] = 0;
}

static void io_mem_init(void)
{
    int i;

    cpu_register_io_memory_fixed(IO_MEM_ROM, error_mem_read,
                                 unassigned_mem_write, NULL,
                                 DEVICE_NATIVE_ENDIAN);
    cpu_register_io_memory_fixed(IO_MEM_UNASSIGNED, unassigned_mem_read,
                                 unassigned_mem_write, NULL,
                                 DEVICE_NATIVE_ENDIAN);
    cpu_register_io_memory_fixed(IO_MEM_NOTDIRTY, error_mem_read,
                                 notdirty_mem_write, NULL,
                                 DEVICE_NATIVE_ENDIAN);
    for (i=0; i<5; i++)
        io_mem_used[i] = 1;

    io_mem_watch = cpu_register_io_memory(watch_mem_read,
                                          watch_mem_write, NULL,
                                          DEVICE_NATIVE_ENDIAN);
}

static void memory_map_init(void)
{
    system_memory = malloc(sizeof(*system_memory));
    memory_region_init(system_memory, "system", INT64_MAX);
    set_system_memory_map(system_memory);

    system_io = malloc(sizeof(*system_io));
    memory_region_init(system_io, "io", 65536);
    set_system_io_map(system_io);
}

MemoryRegion *get_system_memory(void)
{
    return system_memory;
}

MemoryRegion *get_system_io(void)
{
    return system_io;
}

void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf,
                            int len, int is_write)
{
    int l, io_index;
    uint8_t *ptr;
    uint32_t val;
    target_phys_addr_t page;
    ram_addr_t pd;
    PhysPageDesc *p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        p = phys_page_find(page >> TARGET_PAGE_BITS);
        if (!p) {
            pd = IO_MEM_UNASSIGNED;
        } else {
            pd = p->phys_offset;
        }

        if (is_write) {
            if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
                target_phys_addr_t addr1 = addr;
                io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
                if (p)
                    addr1 = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
                /* XXX: could force cpu_single_env to NULL to avoid
                   potential bugs */
                if (l >= 4 && ((addr1 & 3) == 0)) {
                    /* 32 bit write access */
                    val = ldl_p(buf);
                    io_mem_write[io_index][2](io_mem_opaque[io_index], addr1, val);
                    l = 4;
                } else if (l >= 2 && ((addr1 & 1) == 0)) {
                    /* 16 bit write access */
                    val = lduw_p(buf);
                    io_mem_write[io_index][1](io_mem_opaque[io_index], addr1, val);
                    l = 2;
                } else {
                    /* 8 bit write access */
                    val = ldub_p(buf);
                    io_mem_write[io_index][0](io_mem_opaque[io_index], addr1, val);
                    l = 1;
                }
            } else {
                ram_addr_t addr1;
                addr1 = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
                /* RAM case */
                ptr = qemu_get_ram_ptr(addr1);
                memcpy(ptr, buf, l);
                if (!cpu_physical_memory_is_dirty(addr1)) {
                    /* invalidate code */
                    tb_invalidate_phys_page_range(addr1, addr1 + l, 0);
                    /* set dirty bit */
                    cpu_physical_memory_set_dirty_flags(
                        addr1, (0xff & ~CODE_DIRTY_FLAG));
                }
                qemu_put_ram_ptr(ptr);
            }
        } else {
            if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM &&
                !(pd & IO_MEM_ROMD)) {
                target_phys_addr_t addr1 = addr;
                /* I/O case */
                io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
                if (p)
                    addr1 = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
                if (l >= 4 && ((addr1 & 3) == 0)) {
                    /* 32 bit read access */
                    val = io_mem_read[io_index][2](io_mem_opaque[io_index], addr1);
                    stl_p(buf, val);
                    l = 4;
                } else if (l >= 2 && ((addr1 & 1) == 0)) {
                    /* 16 bit read access */
                    val = io_mem_read[io_index][1](io_mem_opaque[io_index], addr1);
                    stw_p(buf, val);
                    l = 2;
                } else {
                    /* 8 bit read access */
                    val = io_mem_read[io_index][0](io_mem_opaque[io_index], addr1);
                    stb_p(buf, val);
                    l = 1;
                }
            } else {
                /* RAM case */
                ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK);
                memcpy(buf, ptr + (addr & ~TARGET_PAGE_MASK), l);
                qemu_put_ram_ptr(ptr);
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

/* used for ROM loading : can write in RAM and ROM */
void cpu_physical_memory_write_rom(target_phys_addr_t addr,
                                   const uint8_t *buf, int len)
{
    int l;
    uint8_t *ptr;
    target_phys_addr_t page;
    unsigned long pd;
    PhysPageDesc *p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        p = phys_page_find(page >> TARGET_PAGE_BITS);
        if (!p) {
            pd = IO_MEM_UNASSIGNED;
        } else {
            pd = p->phys_offset;
        }

        if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM &&
            (pd & ~TARGET_PAGE_MASK) != IO_MEM_ROM &&
            !(pd & IO_MEM_ROMD)) {
            /* do nothing */
        } else {
            unsigned long addr1;
            addr1 = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
            /* ROM/RAM case */
            ptr = qemu_get_ram_ptr(addr1);
            memcpy(ptr, buf, l);
            qemu_put_ram_ptr(ptr);
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

typedef struct {
    void *buffer;
    target_phys_addr_t addr;
    target_phys_addr_t len;
} BounceBuffer;

static BounceBuffer bounce;

typedef struct MapClient {
    void *opaque;
    void (*callback)(void *opaque);
    QLIST_ENTRY(MapClient) link;
} MapClient;

static QLIST_HEAD(map_client_list, MapClient) map_client_list
    = QLIST_HEAD_INITIALIZER(map_client_list);

void *cpu_register_map_client(void *opaque, void (*callback)(void *opaque))
{
    MapClient *client = malloc(sizeof(*client));

    client->opaque = opaque;
    client->callback = callback;
    QLIST_INSERT_HEAD(&map_client_list, client, link);
    return client;
}

void cpu_unregister_map_client(void *_client)
{
    MapClient *client = (MapClient *)_client;

    QLIST_REMOVE(client, link);
    free(client);
    client = NULL;
}

static void cpu_notify_map_clients(void)
{
    MapClient *client;

    while (!QLIST_EMPTY(&map_client_list)) {
        client = QLIST_FIRST(&map_client_list);
        client->callback(client->opaque);
        cpu_unregister_map_client(client);
    }
}

/* Map a physical memory region into a host virtual address.
 * May map a subset of the requested range, given by and returned in *plen.
 * May return NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 */
void *cpu_physical_memory_map(target_phys_addr_t addr,
                              target_phys_addr_t *plen,
                              int is_write)
{
    target_phys_addr_t len = *plen;
    target_phys_addr_t todo = 0;
    int l;
    target_phys_addr_t page;
    unsigned long pd;
    PhysPageDesc *p;
    ram_addr_t raddr = RAM_ADDR_MAX;
    ram_addr_t rlen;
    void *ret;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        p = phys_page_find(page >> TARGET_PAGE_BITS);
        if (!p) {
            pd = IO_MEM_UNASSIGNED;
        } else {
            pd = p->phys_offset;
        }

        if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
            if (todo || bounce.buffer) {
                break;
            }
            bounce.buffer = qemu_memalign(TARGET_PAGE_SIZE, TARGET_PAGE_SIZE);
            bounce.addr = addr;
            bounce.len = l;
            if (!is_write) {
                cpu_physical_memory_read(addr, bounce.buffer, l);
            }

            *plen = l;
            return bounce.buffer;
        }
        if (!todo) {
            raddr = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
        }

        len -= l;
        addr += l;
        todo += l;
    }
    rlen = todo;
    ret = qemu_ram_ptr_length(raddr, &rlen);
    *plen = rlen;
    return ret;
}

/* Unmaps a memory region previously mapped by cpu_physical_memory_map().
 * Will also mark the memory as dirty if is_write == 1.  access_len gives
 * the amount of memory that was actually read or written by the caller.
 */
void cpu_physical_memory_unmap(void *buffer, target_phys_addr_t len,
                               int is_write, target_phys_addr_t access_len)
{
    if (buffer != bounce.buffer) {
        if (is_write) {
            ram_addr_t addr1 = qemu_ram_addr_from_host_nofail(buffer);
            while (access_len) {
                unsigned l;
                l = TARGET_PAGE_SIZE;
                if (l > access_len)
                    l = access_len;
                if (!cpu_physical_memory_is_dirty(addr1)) {
                    /* invalidate code */
                    tb_invalidate_phys_page_range(addr1, addr1 + l, 0);
                    /* set dirty bit */
                    cpu_physical_memory_set_dirty_flags(
                        addr1, (0xff & ~CODE_DIRTY_FLAG));
                }
                addr1 += l;
                access_len -= l;
            }
        }
        return;
    }
    if (is_write) {
        cpu_physical_memory_write(bounce.addr, bounce.buffer, access_len);
    }
    free(bounce.buffer);
    bounce.buffer = NULL;
    cpu_notify_map_clients();
}

/* warning: addr must be aligned */
static inline uint32_t ldl_phys_internal(target_phys_addr_t addr,
                                         enum device_endian endian)
{
    int io_index;
    uint8_t *ptr;
    uint32_t val;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM &&
        !(pd & IO_MEM_ROMD)) {
        /* I/O case */
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        val = io_mem_read[io_index][2](io_mem_opaque[io_index], addr);
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap32(val);
        }
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK) +
            (addr & ~TARGET_PAGE_MASK);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = ldl_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = ldl_be_p(ptr);
            break;
        default:
            val = ldl_p(ptr);
            break;
        }
    }
    return val;
}

uint32_t ldl_phys(target_phys_addr_t addr)
{
    return ldl_phys_internal(addr, DEVICE_NATIVE_ENDIAN);
}

/* warning: addr must be aligned */
static inline uint64_t ldq_phys_internal(target_phys_addr_t addr,
                                         enum device_endian endian)
{
    int io_index;
    uint8_t *ptr;
    uint64_t val;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM &&
        !(pd & IO_MEM_ROMD)) {
        /* I/O case */
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;


        val = io_mem_read[io_index][2](io_mem_opaque[io_index], addr);
        val |= (uint64_t)io_mem_read[io_index][2](io_mem_opaque[io_index], addr + 4) << 32;
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK) +
            (addr & ~TARGET_PAGE_MASK);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = ldq_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = ldq_be_p(ptr);
            break;
        default:
            val = ldq_p(ptr);
            break;
        }
    }
    return val;
}

uint64_t ldq_phys(target_phys_addr_t addr)
{
    return ldq_phys_internal(addr, DEVICE_NATIVE_ENDIAN);
}

/* XXX: optimize */
uint32_t ldub_phys(target_phys_addr_t addr)
{
    uint8_t val;
    cpu_physical_memory_read(addr, &val, 1);
    return val;
}

/* warning: addr must be aligned */
static inline uint32_t lduw_phys_internal(target_phys_addr_t addr,
                                          enum device_endian endian)
{
    int io_index;
    uint8_t *ptr;
    uint64_t val;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM &&
        !(pd & IO_MEM_ROMD)) {
        /* I/O case */
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        val = io_mem_read[io_index][1](io_mem_opaque[io_index], addr);
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap16(val);
        }
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK) +
            (addr & ~TARGET_PAGE_MASK);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = lduw_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = lduw_be_p(ptr);
            break;
        default:
            val = lduw_p(ptr);
            break;
        }
    }
    return val;
}

uint32_t lduw_phys(target_phys_addr_t addr)
{
    return lduw_phys_internal(addr, DEVICE_NATIVE_ENDIAN);
}

/* warning: addr must be aligned. The ram page is not masked as dirty
   and the code inside is not invalidated. It is useful if the dirty
   bits are used to track modified PTEs */
void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val)
{
    int io_index;
    uint8_t *ptr;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        io_mem_write[io_index][2](io_mem_opaque[io_index], addr, val);
    } else {
        unsigned long addr1 = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
        ptr = qemu_get_ram_ptr(addr1);
        stl_p(ptr, val);
    }
}

void stq_phys_notdirty(target_phys_addr_t addr, uint64_t val)
{
    int io_index;
    uint8_t *ptr;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        io_mem_write[io_index][2](io_mem_opaque[io_index], addr, val);
        io_mem_write[io_index][2](io_mem_opaque[io_index], addr + 4, val >> 32);
    } else {
        ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK) +
            (addr & ~TARGET_PAGE_MASK);
        stq_p(ptr, val);
    }
}

/* warning: addr must be aligned */
static inline void stl_phys_internal(target_phys_addr_t addr, uint32_t val,
                                     enum device_endian endian)
{
    int io_index;
    uint8_t *ptr;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap32(val);
        }
        io_mem_write[io_index][2](io_mem_opaque[io_index], addr, val);
    } else {
        unsigned long addr1;
        addr1 = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            stl_le_p(ptr, val);
            break;
        case DEVICE_BIG_ENDIAN:
            stl_be_p(ptr, val);
            break;
        default:
            stl_p(ptr, val);
            break;
        }
        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 4, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1,
                (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stl_phys(target_phys_addr_t addr, uint32_t val)
{
    stl_phys_internal(addr, val, DEVICE_NATIVE_ENDIAN);
}

void stl_le_phys(target_phys_addr_t addr, uint32_t val)
{
    stl_phys_internal(addr, val, DEVICE_LITTLE_ENDIAN);
}

/* XXX: optimize */
void stb_phys(target_phys_addr_t addr, uint32_t val)
{
    uint8_t v = val;
    cpu_physical_memory_write(addr, &v, 1);
}

/* warning: addr must be aligned */
static inline void stw_phys_internal(target_phys_addr_t addr, uint32_t val,
                                     enum device_endian endian)
{
    int io_index;
    uint8_t *ptr;
    unsigned long pd;
    PhysPageDesc *p;

    p = phys_page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        pd = IO_MEM_UNASSIGNED;
    } else {
        pd = p->phys_offset;
    }

    if ((pd & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
        io_index = (pd >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
        if (p)
            addr = (addr & ~TARGET_PAGE_MASK) + p->region_offset;
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap16(val);
        }
        io_mem_write[io_index][1](io_mem_opaque[io_index], addr, val);
    } else {
        unsigned long addr1;
        addr1 = (pd & TARGET_PAGE_MASK) + (addr & ~TARGET_PAGE_MASK);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            stw_le_p(ptr, val);
            break;
        case DEVICE_BIG_ENDIAN:
            stw_be_p(ptr, val);
            break;
        default:
            stw_p(ptr, val);
            break;
        }
        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 2, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1,
                (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stw_phys(target_phys_addr_t addr, uint32_t val)
{
    stw_phys_internal(addr, val, DEVICE_NATIVE_ENDIAN);
}
