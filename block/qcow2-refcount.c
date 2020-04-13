/*
 * Block driver for the QCOW version 2 format
 */
#include "qemu-common.h"
#include "block_int.h"
#include "block/qcow2.h"

static int64_t alloc_clusters_noref(BlockDriverState *bs, int64_t size);
static int update_refcount(BlockDriverState *bs,
                            int64_t offset, int64_t length,
                            int addend);
/*********************************************************/
/* refcount handling */
int qcow2_refcount_init(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    int ret, refcount_table_size2, i;

    refcount_table_size2 = s->refcount_table_size * sizeof(uint64_t);
    s->refcount_table = malloc(refcount_table_size2);
    if (s->refcount_table_size > 0) {
        BLKDBG_EVENT(bs->file, BLKDBG_REFTABLE_LOAD);
        ret = bdrv_pread(bs->file, s->refcount_table_offset,
                         s->refcount_table, refcount_table_size2);
        if (ret != refcount_table_size2)
            goto fail;
        for(i = 0; i < s->refcount_table_size; i++)
            be64_to_cpus(&s->refcount_table[i]);
    }
    return 0;
 fail:
    return -ENOMEM;
}

void qcow2_refcount_close(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    free(s->refcount_table);
    s->refcount_table = NULL;
}

static int load_refcount_block(BlockDriverState *bs,
                               int64_t refcount_block_offset,
                               void **refcount_block)
{
    BDRVQcowState *s = bs->opaque;
    int ret;

    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_LOAD);
    ret = qcow2_cache_get(bs, s->refcount_block_cache, refcount_block_offset,
        refcount_block);

    return ret;
}

/*
 * Returns the refcount of the cluster given by its index. Any non-negative
 * return value is the refcount of the cluster, negative values are -errno
 * and indicate an error.
 */
static int get_refcount(BlockDriverState *bs, int64_t cluster_index)
{
    BDRVQcowState *s = bs->opaque;
    int refcount_table_index, block_index;
    int64_t refcount_block_offset;
    int ret;
    uint16_t *refcount_block;
    uint16_t refcount;

    refcount_table_index = cluster_index >> (s->cluster_bits - REFCOUNT_SHIFT);
    if (refcount_table_index >= s->refcount_table_size)
        return 0;
    refcount_block_offset = s->refcount_table[refcount_table_index];
    if (!refcount_block_offset)
        return 0;

    ret = qcow2_cache_get(bs, s->refcount_block_cache, refcount_block_offset,
        (void**) &refcount_block);
    if (ret < 0) {
        return ret;
    }

    block_index = cluster_index &
        ((1 << (s->cluster_bits - REFCOUNT_SHIFT)) - 1);
    refcount = be16_to_cpu(refcount_block[block_index]);

    ret = qcow2_cache_put(bs, s->refcount_block_cache,
        (void**) &refcount_block);
    if (ret < 0) {
        return ret;
    }

    return refcount;
}

/*
 * Rounds the refcount table size up to avoid growing the table for each single
 * refcount block that is allocated.
 */
static unsigned int next_refcount_table_size(BDRVQcowState *s,
    unsigned int min_size)
{
    unsigned int min_clusters = (min_size >> (s->cluster_bits - 3)) + 1;
    unsigned int refcount_table_clusters =
        MAX(1, s->refcount_table_size >> (s->cluster_bits - 3));

    while (min_clusters > refcount_table_clusters) {
        refcount_table_clusters = (refcount_table_clusters * 3 + 1) / 2;
    }

    return refcount_table_clusters << (s->cluster_bits - 3);
}


/* Checks if two offsets are described by the same refcount block */
static int in_same_refcount_block(BDRVQcowState *s, uint64_t offset_a,
    uint64_t offset_b)
{
    uint64_t block_a = offset_a >> (2 * s->cluster_bits - REFCOUNT_SHIFT);
    uint64_t block_b = offset_b >> (2 * s->cluster_bits - REFCOUNT_SHIFT);

    return (block_a == block_b);
}

/*
 * Loads a refcount block. If it doesn't exist yet, it is allocated first
 * (including growing the refcount table if needed).
 *
 * Returns 0 on success or -errno in error case
 */
static int alloc_refcount_block(BlockDriverState *bs,
    int64_t cluster_index, uint16_t **refcount_block)
{
    BDRVQcowState *s = bs->opaque;
    unsigned int refcount_table_index;
    int ret;

    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC);

    /* Find the refcount block for the given cluster */
    refcount_table_index = cluster_index >> (s->cluster_bits - REFCOUNT_SHIFT);

    if (refcount_table_index < s->refcount_table_size) {

        uint64_t refcount_block_offset =
            s->refcount_table[refcount_table_index];

        /* If it's already there, we're done */
        if (refcount_block_offset) {
             return load_refcount_block(bs, refcount_block_offset,
                 (void**) refcount_block);
        }
    }

    /*
     * If we came here, we need to allocate something. Something is at least
     * a cluster for the new refcount block. It may also include a new refcount
     * table if the old refcount table is too small.
     *
     * Note that allocating clusters here needs some special care:
     *
     * - We can't use the normal qcow2_alloc_clusters(), it would try to
     *   increase the refcount and very likely we would end up with an endless
     *   recursion. Instead we must place the refcount blocks in a way that
     *   they can describe them themselves.
     *
     * - We need to consider that at this point we are inside update_refcounts
     *   and doing the initial refcount increase. This means that some clusters
     *   have already been allocated by the caller, but their refcount isn't
     *   accurate yet. free_cluster_index tells us where this allocation ends
     *   as long as we don't overwrite it by freeing clusters.
     *
     * - alloc_clusters_noref and qcow2_free_clusters may load a different
     *   refcount block into the cache
     */

    *refcount_block = NULL;

    /* We write to the refcount table, so we might depend on L2 tables */
    qcow2_cache_flush(bs, s->l2_table_cache);

    /* Allocate the refcount block itself and mark it as used */
    int64_t new_block = alloc_clusters_noref(bs, s->cluster_size);
    if (new_block < 0) {
        return new_block;
    }

    if (in_same_refcount_block(s, new_block, cluster_index << s->cluster_bits)) {
        /* Zero the new refcount block before updating it */
        ret = qcow2_cache_get_empty(bs, s->refcount_block_cache, new_block,
            (void**) refcount_block);
        if (ret < 0) {
            goto fail_block;
        }

        memset(*refcount_block, 0, s->cluster_size);

        /* The block describes itself, need to update the cache */
        int block_index = (new_block >> s->cluster_bits) &
            ((1 << (s->cluster_bits - REFCOUNT_SHIFT)) - 1);
        (*refcount_block)[block_index] = cpu_to_be16(1);
    } else {
        /* Described somewhere else. This can recurse at most twice before we
         * arrive at a block that describes itself. */
        ret = update_refcount(bs, new_block, s->cluster_size, 1);
        if (ret < 0) {
            goto fail_block;
        }

        bdrv_flush(bs->file);

        /* Initialize the new refcount block only after updating its refcount,
         * update_refcount uses the refcount cache itself */
        ret = qcow2_cache_get_empty(bs, s->refcount_block_cache, new_block,
            (void**) refcount_block);
        if (ret < 0) {
            goto fail_block;
        }

        memset(*refcount_block, 0, s->cluster_size);
    }

    /* Now the new refcount block needs to be written to disk */
    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC_WRITE);
    qcow2_cache_entry_mark_dirty(s->refcount_block_cache, *refcount_block);
    ret = qcow2_cache_flush(bs, s->refcount_block_cache);
    if (ret < 0) {
        goto fail_block;
    }

    /* If the refcount table is big enough, just hook the block up there */
    if (refcount_table_index < s->refcount_table_size) {
        uint64_t data64 = cpu_to_be64(new_block);
        BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC_HOOKUP);
        ret = bdrv_pwrite_sync(bs->file,
            s->refcount_table_offset + refcount_table_index * sizeof(uint64_t),
            &data64, sizeof(data64));
        if (ret < 0) {
            goto fail_block;
        }

        s->refcount_table[refcount_table_index] = new_block;
        return 0;
    }

    ret = qcow2_cache_put(bs, s->refcount_block_cache, (void**) refcount_block);
    if (ret < 0) {
        goto fail_block;
    }

    /*
     * If we come here, we need to grow the refcount table. Again, a new
     * refcount table needs some space and we can't simply allocate to avoid
     * endless recursion.
     *
     * Therefore let's grab new refcount blocks at the end of the image, which
     * will describe themselves and the new refcount table. This way we can
     * reference them only in the new table and do the switch to the new
     * refcount table at once without producing an inconsistent state in
     * between.
     */
    BLKDBG_EVENT(bs->file, BLKDBG_REFTABLE_GROW);

    /* Calculate the number of refcount blocks needed so far */
    uint64_t refcount_block_clusters = 1 << (s->cluster_bits - REFCOUNT_SHIFT);
    uint64_t blocks_used = (s->free_cluster_index +
        refcount_block_clusters - 1) / refcount_block_clusters;

    /* And now we need at least one block more for the new metadata */
    uint64_t table_size = next_refcount_table_size(s, blocks_used + 1);
    uint64_t last_table_size;
    uint64_t blocks_clusters;
    do {
        uint64_t table_clusters = size_to_clusters(s, table_size);
        blocks_clusters = 1 +
            ((table_clusters + refcount_block_clusters - 1)
            / refcount_block_clusters);
        uint64_t meta_clusters = table_clusters + blocks_clusters;

        last_table_size = table_size;
        table_size = next_refcount_table_size(s, blocks_used +
            ((meta_clusters + refcount_block_clusters - 1)
            / refcount_block_clusters));

    } while (last_table_size != table_size);

    /* Create the new refcount table and blocks */
    uint64_t meta_offset = (blocks_used * refcount_block_clusters) *
        s->cluster_size;
    uint64_t table_offset = meta_offset + blocks_clusters * s->cluster_size;
    uint16_t *new_blocks = calloc(1, blocks_clusters * s->cluster_size);
    uint64_t *new_table = calloc(1, table_size * sizeof(uint64_t));

    assert(meta_offset >= (s->free_cluster_index * s->cluster_size));

    /* Fill the new refcount table */
    memcpy(new_table, s->refcount_table,
        s->refcount_table_size * sizeof(uint64_t));
    new_table[refcount_table_index] = new_block;

    int i;
    for (i = 0; i < blocks_clusters; i++) {
        new_table[blocks_used + i] = meta_offset + (i * s->cluster_size);
    }

    /* Fill the refcount blocks */
    uint64_t table_clusters = size_to_clusters(s, table_size * sizeof(uint64_t));
    int block = 0;
    for (i = 0; i < table_clusters + blocks_clusters; i++) {
        new_blocks[block++] = cpu_to_be16(1);
    }

    /* Write refcount blocks to disk */
    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC_WRITE_BLOCKS);
    ret = bdrv_pwrite_sync(bs->file, meta_offset, new_blocks,
        blocks_clusters * s->cluster_size);
    free(new_blocks);
    new_blocks = NULL;
    if (ret < 0) {
        goto fail_table;
    }

    /* Write refcount table to disk */
    for(i = 0; i < table_size; i++) {
        cpu_to_be64s(&new_table[i]);
    }

    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC_WRITE_TABLE);
    ret = bdrv_pwrite_sync(bs->file, table_offset, new_table,
        table_size * sizeof(uint64_t));
    if (ret < 0) {
        goto fail_table;
    }

    for(i = 0; i < table_size; i++) {
        cpu_to_be64s(&new_table[i]);
    }

    /* Hook up the new refcount table in the qcow2 header */
    uint8_t data[12];
    cpu_to_be64w((uint64_t*)data, table_offset);
    cpu_to_be32w((uint32_t*)(data + 8), table_clusters);
    BLKDBG_EVENT(bs->file, BLKDBG_REFBLOCK_ALLOC_SWITCH_TABLE);
    ret = bdrv_pwrite_sync(bs->file, offsetof(QCowHeader, refcount_table_offset),
        data, sizeof(data));
    if (ret < 0) {
        goto fail_table;
    }

    /* And switch it in memory */
    uint64_t old_table_offset = s->refcount_table_offset;
    uint64_t old_table_size = s->refcount_table_size;

    free(s->refcount_table);
    s->refcount_table = new_table;
    s->refcount_table_size = table_size;
    s->refcount_table_offset = table_offset;

    /* Free old table. Remember, we must not change free_cluster_index */
    uint64_t old_free_cluster_index = s->free_cluster_index;
    qcow2_free_clusters(bs, old_table_offset, old_table_size * sizeof(uint64_t));
    s->free_cluster_index = old_free_cluster_index;

    ret = load_refcount_block(bs, new_block, (void**) refcount_block);
    if (ret < 0) {
        return ret;
    }

    return new_block;

fail_table:
    free(new_table);
    new_table = NULL;
fail_block:
    if (*refcount_block != NULL) {
        qcow2_cache_put(bs, s->refcount_block_cache, (void**) refcount_block);
    }
    return ret;
}

/* XXX: cache several refcount block clusters ? */
static int update_refcount(BlockDriverState *bs,
    int64_t offset, int64_t length, int addend)
{
    BDRVQcowState *s = bs->opaque;
    int64_t start, last, cluster_offset;
    uint16_t *refcount_block = NULL;
    int64_t old_table_index = -1;
    int ret;

    if (length < 0) {
        return -EINVAL;
    } else if (length == 0) {
        return 0;
    }

    if (addend < 0) {
        qcow2_cache_set_dependency(bs, s->refcount_block_cache,
            s->l2_table_cache);
    }

    start = offset & ~(s->cluster_size - 1);
    last = (offset + length - 1) & ~(s->cluster_size - 1);
    for(cluster_offset = start; cluster_offset <= last;
        cluster_offset += s->cluster_size)
    {
        int block_index, refcount;
        int64_t cluster_index = cluster_offset >> s->cluster_bits;
        int64_t table_index =
            cluster_index >> (s->cluster_bits - REFCOUNT_SHIFT);

        /* Load the refcount block and allocate it if needed */
        if (table_index != old_table_index) {
            if (refcount_block) {
                ret = qcow2_cache_put(bs, s->refcount_block_cache,
                    (void**) &refcount_block);
                if (ret < 0) {
                    goto fail;
                }
            }

            ret = alloc_refcount_block(bs, cluster_index, &refcount_block);
            if (ret < 0) {
                goto fail;
            }
        }
        old_table_index = table_index;

        qcow2_cache_entry_mark_dirty(s->refcount_block_cache, refcount_block);

        /* we can update the count and save it */
        block_index = cluster_index &
            ((1 << (s->cluster_bits - REFCOUNT_SHIFT)) - 1);

        refcount = be16_to_cpu(refcount_block[block_index]);
        refcount += addend;
        if (refcount < 0 || refcount > 0xffff) {
            ret = -EINVAL;
            goto fail;
        }
        if (refcount == 0 && cluster_index < s->free_cluster_index) {
            s->free_cluster_index = cluster_index;
        }
        refcount_block[block_index] = cpu_to_be16(refcount);
    }

    ret = 0;
fail:
    /* Write last changed block to disk */
    if (refcount_block) {
        int wret;
        wret = qcow2_cache_put(bs, s->refcount_block_cache,
            (void**) &refcount_block);
        if (wret < 0) {
            return ret < 0 ? ret : wret;
        }
    }

    /*
     * Try do undo any updates if an error is returned (This may succeed in
     * some cases like ENOSPC for allocating a new refcount block)
     */
    if (ret < 0) {
        int dummy;
        dummy = update_refcount(bs, offset, cluster_offset - offset, -addend);
        (void)dummy;
    }

    return ret;
}

/*
 * Increases or decreases the refcount of a given cluster by one.
 * addend must be 1 or -1.
 *
 * If the return value is non-negative, it is the new refcount of the cluster.
 * If it is negative, it is -errno and indicates an error.
 */
static int update_cluster_refcount(BlockDriverState *bs,
                                   int64_t cluster_index,
                                   int addend)
{
    BDRVQcowState *s = bs->opaque;
    int ret;

    ret = update_refcount(bs, cluster_index << s->cluster_bits, 1, addend);
    if (ret < 0) {
        return ret;
    }

    bdrv_flush(bs->file);

    return get_refcount(bs, cluster_index);
}



/*********************************************************/
/* cluster allocation functions */

/* return < 0 if error */
static int64_t alloc_clusters_noref(BlockDriverState *bs, int64_t size)
{
    BDRVQcowState *s = bs->opaque;
    int i, nb_clusters, refcount;

    nb_clusters = size_to_clusters(s, size);
retry:
    for(i = 0; i < nb_clusters; i++) {
        int64_t next_cluster_index = s->free_cluster_index++;
        refcount = get_refcount(bs, next_cluster_index);

        if (refcount < 0) {
            return refcount;
        } else if (refcount != 0) {
            goto retry;
        }
    }

    return (s->free_cluster_index - nb_clusters) << s->cluster_bits;
}

int64_t qcow2_alloc_clusters(BlockDriverState *bs, int64_t size)
{
    int64_t offset;
    int ret;

    BLKDBG_EVENT(bs->file, BLKDBG_CLUSTER_ALLOC);
    offset = alloc_clusters_noref(bs, size);
    if (offset < 0) {
        return offset;
    }

    ret = update_refcount(bs, offset, size, 1);
    if (ret < 0) {
        return ret;
    }

    return offset;
}

/* only used to allocate compressed sectors. We try to allocate
   contiguous sectors. size must be <= cluster_size */
int64_t qcow2_alloc_bytes(BlockDriverState *bs, int size)
{
    BDRVQcowState *s = bs->opaque;
    int64_t offset, cluster_offset;
    int free_in_cluster;

    BLKDBG_EVENT(bs->file, BLKDBG_CLUSTER_ALLOC_BYTES);
    assert(size > 0 && size <= s->cluster_size);
    if (s->free_byte_offset == 0) {
        s->free_byte_offset = qcow2_alloc_clusters(bs, s->cluster_size);
        if (s->free_byte_offset < 0) {
            return s->free_byte_offset;
        }
    }
 redo:
    free_in_cluster = s->cluster_size -
        (s->free_byte_offset & (s->cluster_size - 1));
    if (size <= free_in_cluster) {
        /* enough space in current cluster */
        offset = s->free_byte_offset;
        s->free_byte_offset += size;
        free_in_cluster -= size;
        if (free_in_cluster == 0)
            s->free_byte_offset = 0;
        if ((offset & (s->cluster_size - 1)) != 0)
            update_cluster_refcount(bs, offset >> s->cluster_bits, 1);
    } else {
        offset = qcow2_alloc_clusters(bs, s->cluster_size);
        if (offset < 0) {
            return offset;
        }
        cluster_offset = s->free_byte_offset & ~(s->cluster_size - 1);
        if ((cluster_offset + s->cluster_size) == offset) {
            /* we are lucky: contiguous data */
            offset = s->free_byte_offset;
            update_cluster_refcount(bs, offset >> s->cluster_bits, 1);
            s->free_byte_offset += size;
        } else {
            s->free_byte_offset = offset;
            goto redo;
        }
    }

    bdrv_flush(bs->file);
    return offset;
}

void qcow2_free_clusters(BlockDriverState *bs,
                          int64_t offset, int64_t size)
{
    int ret;

    BLKDBG_EVENT(bs->file, BLKDBG_CLUSTER_FREE);
    ret = update_refcount(bs, offset, size, -1);
    if (ret < 0) {
        fprintf(stderr, "qcow2_free_clusters failed: %s\n", strerror(-ret));
        /* TODO Remember the clusters to free them later and avoid leaking */
    }
}

/*
 * free_any_clusters
 *
 * free clusters according to its type: compressed or not
 *
 */

void qcow2_free_any_clusters(BlockDriverState *bs,
    uint64_t cluster_offset, int nb_clusters)
{
    BDRVQcowState *s = bs->opaque;

    /* free the cluster */

    if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
        int nb_csectors;
        nb_csectors = ((cluster_offset >> s->csize_shift) &
                       s->csize_mask) + 1;
        qcow2_free_clusters(bs,
            (cluster_offset & s->cluster_offset_mask) & ~511,
            nb_csectors * 512);
        return;
    }

    qcow2_free_clusters(bs, cluster_offset, nb_clusters << s->cluster_bits);

    return;
}
