#ifndef BLOCK_QCOW2_H
#define BLOCK_QCOW2_H

#include "qemu-coroutine.h"

//#define DEBUG_ALLOC
//#define DEBUG_ALLOC2
//#define DEBUG_EXT

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define QCOW_VERSION 2

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1

#define QCOW_MAX_CRYPT_CLUSTERS 32

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED     (1LL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED (1LL << 62)

#define REFCOUNT_SHIFT 1 /* refcount size is 2 bytes */

#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21

#define L2_CACHE_SIZE 16

/* Must be at least 4 to cover all cases of refcount table growth */
#define REFCOUNT_CACHE_SIZE 4

#define DEFAULT_CLUSTER_SIZE 65536

typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;
    uint32_t l1_size; /* XXX: save number of clusters instead ? */
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
} QCowHeader;

typedef struct QCowSnapshot {
    uint64_t l1_table_offset;
    uint32_t l1_size;
    char *id_str;
    char *name;
    uint32_t vm_state_size;
    uint32_t date_sec;
    uint32_t date_nsec;
    uint64_t vm_clock_nsec;
} QCowSnapshot;

struct Qcow2Cache;
typedef struct Qcow2Cache Qcow2Cache;

typedef struct BDRVQcowState {
    int cluster_bits;
    int cluster_size;
    int cluster_sectors;
    int l2_bits;
    int l2_size;
    int l1_size;
    int l1_vm_state_index;
    int csize_shift;
    int csize_mask;
    uint64_t cluster_offset_mask;
    uint64_t l1_table_offset;
    uint64_t *l1_table;

    Qcow2Cache* l2_table_cache;
    Qcow2Cache* refcount_block_cache;

    uint8_t *cluster_cache;
    uint8_t *cluster_data;
    uint64_t cluster_cache_offset;
    QLIST_HEAD(QCowClusterAlloc, QCowL2Meta) cluster_allocs;

    uint64_t *refcount_table;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_size;
    int64_t free_cluster_index;
    int64_t free_byte_offset;

    CoMutex lock;

    uint64_t snapshots_offset;
    int snapshots_size;
    int nb_snapshots;
    QCowSnapshot *snapshots;
} BDRVQcowState;

/* XXX: use std qcow open function ? */
typedef struct QCowCreateState {
    int cluster_size;
    int cluster_bits;
    uint16_t *refcount_block;
    uint64_t *refcount_table;
    int64_t l1_table_offset;
    int64_t refcount_table_offset;
    int64_t refcount_block_offset;
} QCowCreateState;

struct QCowAIOCB;

/* XXX This could be private for qcow2-cluster.c */
typedef struct QCowL2Meta
{
    uint64_t offset;
    uint64_t cluster_offset;
    int n_start;
    int nb_available;
    int nb_clusters;
    CoQueue dependent_requests;

    QLIST_ENTRY(QCowL2Meta) next_in_flight;
} QCowL2Meta;

static inline int size_to_clusters(BDRVQcowState *s, int64_t size)
{
    return (size + (s->cluster_size - 1)) >> s->cluster_bits;
}

static inline int size_to_l1(BDRVQcowState *s, int64_t size)
{
    int shift = s->cluster_bits + s->l2_bits;
    return (size + (1ULL << shift) - 1) >> shift;
}

static inline int64_t align_offset(int64_t offset, int n)
{
    offset = (offset + n - 1) & ~(n - 1);
    return offset;
}


// FIXME Need qcow2_ prefix to global functions

/* qcow2.c functions */
int qcow2_backing_read1(BlockDriverState *bs, QEMUIOVector *qiov,
                  int64_t sector_num, int nb_sectors);

/* qcow2-refcount.c functions */
int qcow2_refcount_init(BlockDriverState *bs);
void qcow2_refcount_close(BlockDriverState *bs);

int64_t qcow2_alloc_clusters(BlockDriverState *bs, int64_t size);
int64_t qcow2_alloc_bytes(BlockDriverState *bs, int size);
void qcow2_free_clusters(BlockDriverState *bs,
    int64_t offset, int64_t size);
void qcow2_free_any_clusters(BlockDriverState *bs,
    uint64_t cluster_offset, int nb_clusters);

int qcow2_update_snapshot_refcount(BlockDriverState *bs,
    int64_t l1_table_offset, int l1_size, int addend);

int qcow2_check_refcounts(BlockDriverState *bs, BdrvCheckResult *res);

/* qcow2-cluster.c functions */
int qcow2_grow_l1_table(BlockDriverState *bs, int min_size, bool exact_size);
void qcow2_l2_cache_reset(BlockDriverState *bs);

int qcow2_get_cluster_offset(BlockDriverState *bs, uint64_t offset,
    int *num, uint64_t *cluster_offset);
int qcow2_alloc_cluster_offset(BlockDriverState *bs, uint64_t offset,
    int n_start, int n_end, int *num, QCowL2Meta *m);
int qcow2_alloc_cluster_link_l2(BlockDriverState *bs, QCowL2Meta *m);
int qcow2_discard_clusters(BlockDriverState *bs, uint64_t offset,
    int nb_sectors);

/* qcow2-cache.c functions */
Qcow2Cache *qcow2_cache_create(BlockDriverState *bs, int num_tables,
    bool writethrough);
int qcow2_cache_destroy(BlockDriverState* bs, Qcow2Cache *c);
bool qcow2_cache_set_writethrough(BlockDriverState *bs, Qcow2Cache *c,
    bool enable);

void qcow2_cache_entry_mark_dirty(Qcow2Cache *c, void *table);
int qcow2_cache_flush(BlockDriverState *bs, Qcow2Cache *c);
int qcow2_cache_set_dependency(BlockDriverState *bs, Qcow2Cache *c,
    Qcow2Cache *dependency);
void qcow2_cache_depends_on_flush(Qcow2Cache *c);

int qcow2_cache_get(BlockDriverState *bs, Qcow2Cache *c, uint64_t offset,
    void **table);
int qcow2_cache_get_empty(BlockDriverState *bs, Qcow2Cache *c, uint64_t offset,
    void **table);
int qcow2_cache_put(BlockDriverState *bs, Qcow2Cache *c, void **table);

#endif
