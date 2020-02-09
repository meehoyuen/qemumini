#define __HAVE_FAST_MULU64__
static inline void mulu64(uint64_t *plow, uint64_t *phigh,
                          uint64_t a, uint64_t b)
{
    __asm__ ("mul %0\n\t"
             : "=d" (*phigh), "=a" (*plow)
             : "a" (a), "0" (b));
}
#define __HAVE_FAST_MULS64__
static inline void muls64(uint64_t *plow, uint64_t *phigh,
                          int64_t a, int64_t b)
{
    __asm__ ("imul %0\n\t"
             : "=d" (*phigh), "=a" (*plow)
             : "a" (a), "0" (b));
}

/* Binary search for leading zeros.  */
static inline int clz32(uint32_t val)
{
    if (val)
        return __builtin_clz(val);
    return 32;
}

static inline int clz64(uint64_t val)
{
    if (val)
        return __builtin_clzll(val);
    return 64;
}

static inline int ctz32(uint32_t val)
{
    if (val)
        return __builtin_ctz(val);
    return 32;
}
