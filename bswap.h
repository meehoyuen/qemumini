#ifndef BSWAP_H
#define BSWAP_H

#include <inttypes.h>
#include "softfloat.h"

#define bswap_16(x) \
({ \
	uint16_t __x = (x); \
	((uint16_t)( \
		(((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
		(((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#define bswap_32(x) \
({ \
	uint32_t __x = (x); \
	((uint32_t)( \
		(((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) )); \
})

#define bswap_64(x) \
({ \
	uint64_t __x = (x); \
	((uint64_t)( \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
	        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

static inline uint16_t bswap16(uint16_t x)
{
    return bswap_16(x);
}

static inline uint32_t bswap32(uint32_t x)
{
    return bswap_32(x);
}

static inline uint64_t bswap64(uint64_t x)
{
    return bswap_64(x);
}

static inline void bswap16s(uint16_t *s)
{
    *s = bswap16(*s);
}

static inline void bswap32s(uint32_t *s)
{
    *s = bswap32(*s);
}

static inline void bswap64s(uint64_t *s)
{
    *s = bswap64(*s);
}

#define le_bswap(v, size) (v)
#define be_bswap(v, size) bswap ## size(v)
#define le_bswaps(v, size)
#define be_bswaps(p, size) *p = bswap ## size(*p);

#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return endian ## _bswap(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return endian ## _bswap(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    endian ## _bswaps(p, size)\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    endian ## _bswaps(p, size)\
}\
\
static inline type endian ## size ## _to_cpup(const type *p)\
{\
    return endian ## size ## _to_cpu(*p);\
}\
\
static inline void cpu_to_ ## endian ## size ## w(type *p, type v)\
{\
     *p = cpu_to_ ## endian ## size(v);\
}

CPU_CONVERT(be, 16, uint16_t)
CPU_CONVERT(be, 32, uint32_t)
CPU_CONVERT(be, 64, uint64_t)

CPU_CONVERT(le, 16, uint16_t)
CPU_CONVERT(le, 32, uint32_t)
CPU_CONVERT(le, 64, uint64_t)

/* unaligned versions (optimized for frequent unaligned accesses)*/

static inline void cpu_to_le16wu(uint16_t *p, uint16_t v)
{
    uint8_t *p1 = (uint8_t *)p;

    p1[0] = v & 0xff;
    p1[1] = v >> 8;
}

static inline void cpu_to_le32wu(uint32_t *p, uint32_t v)
{
    uint8_t *p1 = (uint8_t *)p;

    p1[0] = v & 0xff;
    p1[1] = v >> 8;
    p1[2] = v >> 16;
    p1[3] = v >> 24;
}

static inline uint16_t le16_to_cpupu(const uint16_t *p)
{
    const uint8_t *p1 = (const uint8_t *)p;
    return p1[0] | (p1[1] << 8);
}

static inline uint32_t le32_to_cpupu(const uint32_t *p)
{
    const uint8_t *p1 = (const uint8_t *)p;
    return p1[0] | (p1[1] << 8) | (p1[2] << 16) | (p1[3] << 24);
}

static inline uint32_t be32_to_cpupu(const uint32_t *p)
{
    const uint8_t *p1 = (const uint8_t *)p;
    return p1[3] | (p1[2] << 8) | (p1[1] << 16) | (p1[0] << 24);
}

static inline void cpu_to_be16wu(uint16_t *p, uint16_t v)
{
    uint8_t *p1 = (uint8_t *)p;

    p1[0] = v >> 8;
    p1[1] = v & 0xff;
}

static inline void cpu_to_be32wu(uint32_t *p, uint32_t v)
{
    uint8_t *p1 = (uint8_t *)p;

    p1[0] = v >> 24;
    p1[1] = v >> 16;
    p1[2] = v >> 8;
    p1[3] = v & 0xff;
}

static inline void cpu_to_be64wu(uint64_t *p, uint64_t v)
{
    uint8_t *p1 = (uint8_t *)p;

    p1[0] = v >> 56;
    p1[1] = v >> 48;
    p1[2] = v >> 40;
    p1[3] = v >> 32;
    p1[4] = v >> 24;
    p1[5] = v >> 16;
    p1[6] = v >> 8;
    p1[7] = v & 0xff;
}

#define cpu_to_32wu cpu_to_le32wu
#define leul_to_cpu(v) (v)

#undef le_bswap
#undef be_bswap
#undef le_bswaps
#undef be_bswaps

/* len must be one of 1, 2, 4 */
static inline uint32_t qemu_bswap_len(uint32_t value, int len)
{
    return bswap32(value) >> (32 - 8 * len);
}

typedef union {
    float32 f;
    uint32_t l;
} CPU_FloatU;

typedef union {
    float64 d;
    struct {
        uint32_t lower;
        uint32_t upper;
    } l;
    uint64_t ll;
} CPU_DoubleU;

typedef union {
     floatx80 d;
     struct {
         uint64_t lower;
         uint16_t upper;
     } l;
} CPU_LDoubleU;

typedef union {
    float128 q;
    struct {
        uint32_t lowest;
        uint32_t lower;
        uint32_t upper;
        uint32_t upmost;
    } l;
    struct {
        uint64_t lower;
        uint64_t upper;
    } ll;
} CPU_QuadU;

/* unaligned/endian-independent pointer access */

/*
 * the generic syntax is:
 *
 * load: ld{type}{sign}{size}{endian}_p(ptr)
 *
 * store: st{type}{size}{endian}_p(ptr, val)
 *
 * Note there are small differences with the softmmu access API!
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
 * (empty): 8 bit access
 *   be   : big endian
 *   le   : little endian
 */
static inline int ldub_p(const void *ptr)
{
    return *(uint8_t *)ptr;
}

static inline int ldsb_p(const void *ptr)
{
    return *(int8_t *)ptr;
}

static inline void stb_p(void *ptr, int v)
{
    *(uint8_t *)ptr = v;
}



static inline int lduw_le_p(const void *ptr)
{
    return *(uint16_t *)ptr;
}

static inline int ldsw_le_p(const void *ptr)
{
    return *(int16_t *)ptr;
}

static inline int ldl_le_p(const void *ptr)
{
    return *(uint32_t *)ptr;
}

static inline uint64_t ldq_le_p(const void *ptr)
{
    return *(uint64_t *)ptr;
}

static inline void stw_le_p(void *ptr, int v)
{
    *(uint16_t *)ptr = v;
}

static inline void stl_le_p(void *ptr, int v)
{
    *(uint32_t *)ptr = v;
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    *(uint64_t *)ptr = v;
}

/* float access */

static inline float32 ldfl_le_p(const void *ptr)
{
    return *(float32 *)ptr;
}

static inline float64 ldfq_le_p(const void *ptr)
{
    return *(float64 *)ptr;
}

static inline void stfl_le_p(void *ptr, float32 v)
{
    *(float32 *)ptr = v;
}

static inline void stfq_le_p(void *ptr, float64 v)
{
    *(float64 *)ptr = v;
}

static inline int lduw_be_p(const void *ptr)
{
    const uint8_t *b = ptr;
    return ((b[0] << 8) | b[1]);
}

static inline int ldsw_be_p(const void *ptr)
{
    const uint8_t *b = ptr;
    return (int16_t)((b[0] << 8) | b[1]);
}

static inline int ldl_be_p(const void *ptr)
{
    int val;
    asm volatile ("movl %1, %0\n"
                  "bswap %0\n"
                  : "=r" (val)
                  : "m" (*(uint32_t *)ptr));
    return val;
}

static inline uint64_t ldq_be_p(const void *ptr)
{
    uint32_t a,b;
    a = ldl_be_p(ptr);
    b = ldl_be_p((uint8_t *)ptr + 4);
    return (((uint64_t)a<<32)|b);
}

static inline void stw_be_p(void *ptr, int v)
{
    uint8_t *d = (uint8_t *) ptr;
    d[0] = v >> 8;
    d[1] = v;
}

static inline void stl_be_p(void *ptr, int v)
{
    asm volatile ("bswap %0\n"
                  "movl %0, %1\n"
                  : "=r" (v)
                  : "m" (*(uint32_t *)ptr), "0" (v));
}

static inline void stq_be_p(void *ptr, uint64_t v)
{
    stl_be_p(ptr, v >> 32);
    stl_be_p((uint8_t *)ptr + 4, v);
}

/* float access */

static inline float32 ldfl_be_p(const void *ptr)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.i = ldl_be_p(ptr);
    return u.f;
}

static inline void stfl_be_p(void *ptr, float32 v)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.f = v;
    stl_be_p(ptr, u.i);
}

static inline float64 ldfq_be_p(const void *ptr)
{
    CPU_DoubleU u;
    u.l.upper = ldl_be_p(ptr);
    u.l.lower = ldl_be_p((uint8_t *)ptr + 4);
    return u.d;
}

static inline void stfq_be_p(void *ptr, float64 v)
{
    CPU_DoubleU u;
    u.d = v;
    stl_be_p(ptr, u.l.upper);
    stl_be_p((uint8_t *)ptr + 4, u.l.lower);
}

#endif /* BSWAP_H */
