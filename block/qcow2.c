#include "qemu-common.h"
#include "block_int.h"
#include "block/qcow2.h"

typedef struct {
    uint32_t magic;
    uint32_t len;
} QCowExtension;
#define  QCOW2_EXT_MAGIC_END 0
#define  QCOW2_EXT_MAGIC_BACKING_FORMAT 0xE2792ACA

static int qcow2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const QCowHeader *cow_header = (const void *)buf;

    if (buf_size >= sizeof(QCowHeader) &&
        be32_to_cpu(cow_header->magic) == QCOW_MAGIC &&
        be32_to_cpu(cow_header->version) >= QCOW_VERSION)
        return 100;
    else
        return 0;
}


/* 
 * read qcow2 extension and fill bs
 * start reading from start_offset
 * finish reading upon magic of value 0 or when end_offset reached
 * unknown magic is skipped (future extension this version knows nothing about)
 * return 0 upon success, non-0 otherwise
 */
static int qcow2_read_extensions(BlockDriverState *bs, uint64_t start_offset,
                                 uint64_t end_offset)
{
    QCowExtension ext;
    uint64_t offset;

#ifdef DEBUG_EXT
    printf("qcow2_read_extensions: start=%ld end=%ld\n", start_offset, end_offset);
#endif
    offset = start_offset;
    while (offset < end_offset) {

#ifdef DEBUG_EXT
        BDRVQcowState *s = bs->opaque;
        /* Sanity check */
        if (offset > s->cluster_size)
            printf("qcow2_read_extension: suspicious offset %lu\n", offset);

        printf("attemting to read extended header in offset %lu\n", offset);
#endif

        if (bdrv_pread(bs->file, offset, &ext, sizeof(ext)) != sizeof(ext)) {
            fprintf(stderr, "qcow2_read_extension: ERROR: "
                    "pread fail from offset %" PRIu64 "\n",
                    offset);
            return 1;
        }
        be32_to_cpus(&ext.magic);
        be32_to_cpus(&ext.len);
        offset += sizeof(ext);
#ifdef DEBUG_EXT
        printf("ext.magic = 0x%x\n", ext.magic);
#endif
        switch (ext.magic) {
        case QCOW2_EXT_MAGIC_END:
            return 0;

        case QCOW2_EXT_MAGIC_BACKING_FORMAT:
            if (ext.len >= sizeof(bs->backing_format)) {
                fprintf(stderr, "ERROR: ext_backing_format: len=%u too large"
                        " (>=%zu)\n",
                        ext.len, sizeof(bs->backing_format));
                return 2;
            }
            if (bdrv_pread(bs->file, offset , bs->backing_format,
                           ext.len) != ext.len)
                return 3;
            bs->backing_format[ext.len] = '\0';
#ifdef DEBUG_EXT
            printf("Qcow2: Got format extension %s\n", bs->backing_format);
#endif
            offset = ((offset + ext.len + 7) & ~7);
            break;

        default:
            /* unknown magic -- just skip it */
            offset = ((offset + ext.len + 7) & ~7);
            break;
        }
    }

    return 0;
}


static int qcow2_open(BlockDriverState *bs, int flags)
{
    BDRVQcowState *s = bs->opaque;
    int len, i, ret = 0;
    QCowHeader header;
    uint64_t ext_end;
    bool writethrough;

    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    if (ret < 0) {
        goto fail;
    }
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus(&header.backing_file_offset);
    be32_to_cpus(&header.backing_file_size);
    be64_to_cpus(&header.size);
    be32_to_cpus(&header.cluster_bits);
    be32_to_cpus(&header.crypt_method);
    be64_to_cpus(&header.l1_table_offset);
    be32_to_cpus(&header.l1_size);
    be64_to_cpus(&header.refcount_table_offset);
    be32_to_cpus(&header.refcount_table_clusters);
    be64_to_cpus(&header.snapshots_offset);
    be32_to_cpus(&header.nb_snapshots);

    if (header.magic != QCOW_MAGIC) {
        ret = -EINVAL;
        goto fail;
    }
    if (header.version != QCOW_VERSION) {
        char version[64];
        snprintf(version, sizeof(version), "QCOW version %d", header.version);
        fprintf(stderr,"unknown %s", version);
        ret = -ENOTSUP;
        goto fail;
    }
    if (header.cluster_bits < MIN_CLUSTER_BITS ||
        header.cluster_bits > MAX_CLUSTER_BITS) {
        ret = -EINVAL;
        goto fail;
    }
    if (header.crypt_method > QCOW_CRYPT_NONE) {
        ret = -EINVAL;
        goto fail;
    }
    s->cluster_bits = header.cluster_bits;
    s->cluster_size = 1 << s->cluster_bits;
    s->cluster_sectors = 1 << (s->cluster_bits - 9);
    s->l2_bits = s->cluster_bits - 3; /* L2 is always one cluster */
    s->l2_size = 1 << s->l2_bits;
    bs->total_sectors = header.size / 512;
    s->csize_shift = (62 - (s->cluster_bits - 8));
    s->csize_mask = (1 << (s->cluster_bits - 8)) - 1;
    s->cluster_offset_mask = (1LL << s->csize_shift) - 1;
    s->refcount_table_offset = header.refcount_table_offset;
    s->refcount_table_size =
        header.refcount_table_clusters << (s->cluster_bits - 3);

    s->snapshots_offset = header.snapshots_offset;
    s->nb_snapshots = header.nb_snapshots;

    /* read the level 1 table */
    s->l1_size = header.l1_size;
    s->l1_vm_state_index = size_to_l1(s, header.size);
    /* the L1 table must contain at least enough entries to put
       header.size bytes */
    if (s->l1_size < s->l1_vm_state_index) {
        ret = -EINVAL;
        goto fail;
    }
    s->l1_table_offset = header.l1_table_offset;
    if (s->l1_size > 0) {
        s->l1_table = calloc(1, align_offset(s->l1_size * sizeof(uint64_t), 512));
        ret = bdrv_pread(bs->file, s->l1_table_offset, s->l1_table,
                         s->l1_size * sizeof(uint64_t));
        if (ret < 0) {
            goto fail;
        }
        for(i = 0;i < s->l1_size; i++) {
            be64_to_cpus(&s->l1_table[i]);
        }
    }

    /* alloc L2 table/refcount block cache */
    writethrough = ((flags & BDRV_O_CACHE_WB) == 0);
    s->l2_table_cache = qcow2_cache_create(bs, L2_CACHE_SIZE, writethrough);
    s->refcount_block_cache = qcow2_cache_create(bs, REFCOUNT_CACHE_SIZE,
        writethrough);

    s->cluster_cache = malloc(s->cluster_size);
    /* one more sector for decompressed data alignment */
    s->cluster_data = qemu_blockalign(bs, QCOW_MAX_CRYPT_CLUSTERS * s->cluster_size
                                  + 512);
    s->cluster_cache_offset = -1;

    ret = qcow2_refcount_init(bs);
    if (ret != 0) {
        goto fail;
    }

    QLIST_INIT(&s->cluster_allocs);

    /* read qcow2 extensions */
    if (header.backing_file_offset) {
        ext_end = header.backing_file_offset;
    } else {
        ext_end = s->cluster_size;
    }
    if (qcow2_read_extensions(bs, sizeof(header), ext_end)) {
        ret = -EINVAL;
        goto fail;
    }

    /* read the backing file name */
    if (header.backing_file_offset != 0) {
        len = header.backing_file_size;
        if (len > 1023) {
            len = 1023;
        }
        ret = bdrv_pread(bs->file, header.backing_file_offset,
                         bs->backing_file, len);
        if (ret < 0) {
            goto fail;
        }
        bs->backing_file[len] = '\0';
    }

    /* Initialise locks */
    qemu_co_mutex_init(&s->lock);

    return ret;

 fail:
    qcow2_refcount_close(bs);
    free(s->l1_table);
    s->l1_table = NULL;
    if (s->l2_table_cache) {
        qcow2_cache_destroy(bs, s->l2_table_cache);
    }
    free(s->cluster_cache);
    s->cluster_cache = NULL;
    free(s->cluster_data);
    s->cluster_data = NULL;
    return ret;
}

static int qcow2_is_allocated(BlockDriverState *bs, int64_t sector_num,
                              int nb_sectors, int *pnum)
{
    uint64_t cluster_offset;
    int ret;

    *pnum = nb_sectors;
    /* FIXME We can get errors here, but the bdrv_is_allocated interface can't
     * pass them on today */
    ret = qcow2_get_cluster_offset(bs, sector_num << 9, pnum, &cluster_offset);
    if (ret < 0) {
        *pnum = 0;
    }

    return (cluster_offset != 0);
}

/* handle reading after the end of the backing file */
int qcow2_backing_read1(BlockDriverState *bs, QEMUIOVector *qiov,
                  int64_t sector_num, int nb_sectors)
{
    int n1;
    if ((sector_num + nb_sectors) <= bs->total_sectors)
        return nb_sectors;
    if (sector_num >= bs->total_sectors)
        n1 = 0;
    else
        n1 = bs->total_sectors - sector_num;

    qemu_iovec_memset_skip(qiov, 0, 512 * (nb_sectors - n1), 512 * n1);

    return n1;
}

static int qcow2_co_readv(BlockDriverState *bs, int64_t sector_num,
                          int remaining_sectors, QEMUIOVector *qiov)
{
    BDRVQcowState *s = bs->opaque;
    int index_in_cluster, n1;
    int ret;
    int cur_nr_sectors; /* number of sectors in current iteration */
    uint64_t cluster_offset = 0;
    uint64_t bytes_done = 0;
    QEMUIOVector hd_qiov;
    uint8_t *cluster_data = NULL;

    qemu_iovec_init(&hd_qiov, qiov->niov);

    qemu_co_mutex_lock(&s->lock);

    while (remaining_sectors != 0) {

        /* prepare next request */
        cur_nr_sectors = remaining_sectors;

        ret = qcow2_get_cluster_offset(bs, sector_num << 9,
            &cur_nr_sectors, &cluster_offset);
        if (ret < 0) {
            goto fail;
        }

        index_in_cluster = sector_num & (s->cluster_sectors - 1);

        qemu_iovec_reset(&hd_qiov);
        qemu_iovec_copy(&hd_qiov, qiov, bytes_done,
            cur_nr_sectors * 512);

        if (!cluster_offset) {

            if (bs->backing_hd) {
                /* read from the base image */
                n1 = qcow2_backing_read1(bs->backing_hd, &hd_qiov,
                    sector_num, cur_nr_sectors);
                if (n1 > 0) {
                    BLKDBG_EVENT(bs->file, BLKDBG_READ_BACKING_AIO);
                    qemu_co_mutex_unlock(&s->lock);
                    ret = bdrv_co_readv(bs->backing_hd, sector_num,
                                        n1, &hd_qiov);
                    qemu_co_mutex_lock(&s->lock);
                    if (ret < 0) {
                        goto fail;
                    }
                }
            } else {
                /* Note: in this case, no need to wait */
                qemu_iovec_memset(&hd_qiov, 0, 512 * cur_nr_sectors);
            }
        } else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
            printf("compress cluster not supported\n");
        } else {
            if ((cluster_offset & 511) != 0) {
                ret = -EIO;
                goto fail;
            }

            BLKDBG_EVENT(bs->file, BLKDBG_READ_AIO);
            qemu_co_mutex_unlock(&s->lock);
            ret = bdrv_co_readv(bs->file,
                                (cluster_offset >> 9) + index_in_cluster,
                                cur_nr_sectors, &hd_qiov);
            qemu_co_mutex_lock(&s->lock);
            if (ret < 0) {
                goto fail;
            }
        }

        remaining_sectors -= cur_nr_sectors;
        sector_num += cur_nr_sectors;
        bytes_done += cur_nr_sectors * 512;
    }
    ret = 0;

fail:
    qemu_co_mutex_unlock(&s->lock);

    qemu_iovec_destroy(&hd_qiov);
    free(cluster_data);

    return ret;
}

static void run_dependent_requests(BDRVQcowState *s, QCowL2Meta *m)
{
    /* Take the request off the list of running requests */
    if (m->nb_clusters != 0) {
        QLIST_REMOVE(m, next_in_flight);
    }

    /* Restart all dependent requests */
    if (!qemu_co_queue_empty(&m->dependent_requests)) {
        qemu_co_mutex_unlock(&s->lock);
        while(qemu_co_queue_next(&m->dependent_requests));
        qemu_co_mutex_lock(&s->lock);
    }
}

static int qcow2_co_writev(BlockDriverState *bs,
                           int64_t sector_num,
                           int remaining_sectors,
                           QEMUIOVector *qiov)
{
    BDRVQcowState *s = bs->opaque;
    int index_in_cluster;
    int n_end;
    int ret;
    int cur_nr_sectors; /* number of sectors in current iteration */
    uint64_t cluster_offset;
    QEMUIOVector hd_qiov;
    uint64_t bytes_done = 0;
    uint8_t *cluster_data = NULL;
    QCowL2Meta l2meta = {
        .nb_clusters = 0,
    };

    qemu_co_queue_init(&l2meta.dependent_requests);

    qemu_iovec_init(&hd_qiov, qiov->niov);

    s->cluster_cache_offset = -1; /* disable compressed cache */

    qemu_co_mutex_lock(&s->lock);

    while (remaining_sectors != 0) {

        index_in_cluster = sector_num & (s->cluster_sectors - 1);
        n_end = index_in_cluster + remaining_sectors;

        ret = qcow2_alloc_cluster_offset(bs, sector_num << 9,
            index_in_cluster, n_end, &cur_nr_sectors, &l2meta);
        if (ret < 0) {
            goto fail;
        }

        cluster_offset = l2meta.cluster_offset;
        assert((cluster_offset & 511) == 0);

        qemu_iovec_reset(&hd_qiov);
        qemu_iovec_copy(&hd_qiov, qiov, bytes_done,
            cur_nr_sectors * 512);

        BLKDBG_EVENT(bs->file, BLKDBG_WRITE_AIO);
        qemu_co_mutex_unlock(&s->lock);
        ret = bdrv_co_writev(bs->file,
                             (cluster_offset >> 9) + index_in_cluster,
                             cur_nr_sectors, &hd_qiov);
        qemu_co_mutex_lock(&s->lock);
        if (ret < 0) {
            goto fail;
        }

        ret = qcow2_alloc_cluster_link_l2(bs, &l2meta);
        if (ret < 0) {
            goto fail;
        }

        run_dependent_requests(s, &l2meta);

        remaining_sectors -= cur_nr_sectors;
        sector_num += cur_nr_sectors;
        bytes_done += cur_nr_sectors * 512;
    }
    ret = 0;

fail:
    run_dependent_requests(s, &l2meta);

    qemu_co_mutex_unlock(&s->lock);

    qemu_iovec_destroy(&hd_qiov);
    free(cluster_data);

    return ret;
}

static void qcow2_close(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    free(s->l1_table);
    s->l1_table = NULL;

    qcow2_cache_flush(bs, s->l2_table_cache);
    qcow2_cache_flush(bs, s->refcount_block_cache);

    qcow2_cache_destroy(bs, s->l2_table_cache);
    qcow2_cache_destroy(bs, s->refcount_block_cache);

    free(s->cluster_cache);
    s->cluster_cache = NULL;
    free(s->cluster_data);
    qcow2_refcount_close(bs);
}

/*
 * Updates the variable length parts of the qcow2 header, i.e. the backing file
 * name and all extensions. qcow2 was not designed to allow such changes, so if
 * we run out of space (we can only use the first cluster) this function may
 * fail.
 *
 * Returns 0 on success, -errno in error cases.
 */
static int qcow2_update_ext_header(BlockDriverState *bs,
    const char *backing_file, const char *backing_fmt)
{
    size_t backing_file_len = 0;
    size_t backing_fmt_len = 0;
    BDRVQcowState *s = bs->opaque;
    QCowExtension ext_backing_fmt = {0, 0};
    int ret;

    /* Backing file format doesn't make sense without a backing file */
    if (backing_fmt && !backing_file) {
        return -EINVAL;
    }

    /* Prepare the backing file format extension if needed */
    if (backing_fmt) {
        ext_backing_fmt.len = cpu_to_be32(strlen(backing_fmt));
        ext_backing_fmt.magic = cpu_to_be32(QCOW2_EXT_MAGIC_BACKING_FORMAT);
        backing_fmt_len = ((sizeof(ext_backing_fmt)
            + strlen(backing_fmt) + 7) & ~7);
    }

    /* Check if we can fit the new header into the first cluster */
    if (backing_file) {
        backing_file_len = strlen(backing_file);
    }

    size_t header_size = sizeof(QCowHeader) + backing_file_len
        + backing_fmt_len;

    if (header_size > s->cluster_size) {
        return -ENOSPC;
    }

    /* Rewrite backing file name and qcow2 extensions */
    size_t ext_size = header_size - sizeof(QCowHeader);
    uint8_t buf[ext_size];
    size_t offset = 0;
    size_t backing_file_offset = 0;

    if (backing_file) {
        if (backing_fmt) {
            int padding = backing_fmt_len -
                (sizeof(ext_backing_fmt) + strlen(backing_fmt));

            memcpy(buf + offset, &ext_backing_fmt, sizeof(ext_backing_fmt));
            offset += sizeof(ext_backing_fmt);

            memcpy(buf + offset, backing_fmt, strlen(backing_fmt));
            offset += strlen(backing_fmt);

            memset(buf + offset, 0, padding);
            offset += padding;
        }

        memcpy(buf + offset, backing_file, backing_file_len);
        backing_file_offset = sizeof(QCowHeader) + offset;
    }

    ret = bdrv_pwrite_sync(bs->file, sizeof(QCowHeader), buf, ext_size);
    if (ret < 0) {
        goto fail;
    }

    /* Update header fields */
    uint64_t be_backing_file_offset = cpu_to_be64(backing_file_offset);
    uint32_t be_backing_file_size = cpu_to_be32(backing_file_len);

    ret = bdrv_pwrite_sync(bs->file, offsetof(QCowHeader, backing_file_offset),
        &be_backing_file_offset, sizeof(uint64_t));
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_pwrite_sync(bs->file, offsetof(QCowHeader, backing_file_size),
        &be_backing_file_size, sizeof(uint32_t));
    if (ret < 0) {
        goto fail;
    }

    ret = 0;
fail:
    return ret;
}

static int qcow2_change_backing_file(BlockDriverState *bs,
    const char *backing_file, const char *backing_fmt)
{
    return qcow2_update_ext_header(bs, backing_file, backing_fmt);
}

static int preallocate(BlockDriverState *bs)
{
    uint64_t nb_sectors;
    uint64_t offset;
    int num;
    int ret;
    QCowL2Meta meta;

    nb_sectors = bdrv_getlength(bs) >> 9;
    offset = 0;
    qemu_co_queue_init(&meta.dependent_requests);
    meta.cluster_offset = 0;

    while (nb_sectors) {
        num = MIN(nb_sectors, INT_MAX >> 9);
        ret = qcow2_alloc_cluster_offset(bs, offset, 0, num, &num, &meta);
        if (ret < 0) {
            return ret;
        }

        ret = qcow2_alloc_cluster_link_l2(bs, &meta);
        if (ret < 0) {
            qcow2_free_any_clusters(bs, meta.cluster_offset, meta.nb_clusters);
            return ret;
        }

        /* There are no dependent requests, but we need to remove our request
         * from the list of in-flight requests */
        run_dependent_requests(bs->opaque, &meta);

        /* TODO Preallocate data if requested */

        nb_sectors -= num;
        offset += num << 9;
    }

    /*
     * It is expected that the image file is large enough to actually contain
     * all of the allocated clusters (otherwise we get failing reads after
     * EOF). Extend the image to the last allocated sector.
     */
    if (meta.cluster_offset != 0) {
        uint8_t buf[512];
        memset(buf, 0, 512);
        ret = bdrv_write(bs->file, (meta.cluster_offset >> 9) + num - 1, buf, 1);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

static int qcow2_create2(const char *filename, int64_t total_size,
                         const char *backing_file, const char *backing_format,
                         int flags, size_t cluster_size, int prealloc,
                         QEMUOptionParameter *options)
{
    /* Calulate cluster_bits */
    int cluster_bits;
    cluster_bits = ffs(cluster_size) - 1;
    if (cluster_bits < MIN_CLUSTER_BITS || cluster_bits > MAX_CLUSTER_BITS ||
        (1 << cluster_bits) != cluster_size)
    {
        printf("Cluster size must be a power of two between %d and %dk",
            1 << MIN_CLUSTER_BITS, 1 << (MAX_CLUSTER_BITS - 10));
        return -EINVAL;
    }

    /*
     * Open the image file and write a minimal qcow2 header.
     *
     * We keep things simple and start with a zero-sized image. We also
     * do without refcount blocks or a L1 table for now. We'll fix the
     * inconsistency later.
     *
     * We do need a refcount table because growing the refcount table means
     * allocating two new refcount blocks - the seconds of which would be at
     * 2 GB for 64k clusters, and we don't want to have a 2 GB initial file
     * size for any qcow2 image.
     */
    BlockDriverState* bs;
    QCowHeader header;
    uint8_t* refcount_table;
    int ret;

    ret = bdrv_create_file(filename, options);
    if (ret < 0) {
        return ret;
    }

    ret = bdrv_file_open(&bs, filename, BDRV_O_RDWR);
    if (ret < 0) {
        return ret;
    }

    /* Write the header */
    memset(&header, 0, sizeof(header));
    header.magic = cpu_to_be32(QCOW_MAGIC);
    header.version = cpu_to_be32(QCOW_VERSION);
    header.cluster_bits = cpu_to_be32(cluster_bits);
    header.size = cpu_to_be64(0);
    header.l1_table_offset = cpu_to_be64(0);
    header.l1_size = cpu_to_be32(0);
    header.refcount_table_offset = cpu_to_be64(cluster_size);
    header.refcount_table_clusters = cpu_to_be32(1);

    header.crypt_method = cpu_to_be32(QCOW_CRYPT_NONE);

    ret = bdrv_pwrite(bs, 0, &header, sizeof(header));
    if (ret < 0) {
        goto out;
    }

    /* Write an empty refcount table */
    refcount_table = calloc(1, cluster_size);
    ret = bdrv_pwrite(bs, cluster_size, refcount_table, cluster_size);
    free(refcount_table);
    refcount_table = NULL;

    if (ret < 0) {
        goto out;
    }

    bdrv_close(bs);

    /*
     * And now open the image and make it consistent first (i.e. increase the
     * refcount of the cluster that is occupied by the header and the refcount
     * table)
     */
    BlockDriver* drv = bdrv_find_format("qcow2");
    assert(drv != NULL);
    ret = bdrv_open(bs, filename,
        BDRV_O_RDWR | BDRV_O_CACHE_WB | BDRV_O_NO_FLUSH, drv);
    if (ret < 0) {
        goto out;
    }

    ret = qcow2_alloc_clusters(bs, 2 * cluster_size);
    if (ret < 0) {
        goto out;

    } else if (ret != 0) {
        printf("Huh, first cluster in empty image is already in use?");
        abort();
    }

    /* Okay, now that we have a valid image, let's give it the right size */
    ret = bdrv_truncate(bs, total_size * BDRV_SECTOR_SIZE);
    if (ret < 0) {
        goto out;
    }

    /* Want a backing file? There you go.*/
    if (backing_file) {
        ret = bdrv_change_backing_file(bs, backing_file, backing_format);
        if (ret < 0) {
            goto out;
        }
    }

    /* And if we're supposed to preallocate metadata, do that now */
    if (prealloc) {
        ret = preallocate(bs);
        if (ret < 0) {
            goto out;
        }
    }

    ret = 0;
out:
    bdrv_delete(bs);
    return ret;
}

static int qcow2_create(const char *filename, QEMUOptionParameter *options)
{
    const char *backing_file = NULL;
    const char *backing_fmt = NULL;
    uint64_t sectors = 0;
    int flags = 0;
    size_t cluster_size = DEFAULT_CLUSTER_SIZE;
    int prealloc = 0;

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            sectors = options->value.n / 512;
        } else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
            backing_file = options->value.s;
        } else if (!strcmp(options->name, BLOCK_OPT_BACKING_FMT)) {
            backing_fmt = options->value.s;
        } else if (!strcmp(options->name, BLOCK_OPT_ENCRYPT)) {
            flags |= options->value.n ? BLOCK_FLAG_ENCRYPT : 0;
        } else if (!strcmp(options->name, BLOCK_OPT_CLUSTER_SIZE)) {
            if (options->value.n) {
                cluster_size = options->value.n;
            }
        } else if (!strcmp(options->name, BLOCK_OPT_PREALLOC)) {
            if (!options->value.s || !strcmp(options->value.s, "off")) {
                prealloc = 0;
            } else if (!strcmp(options->value.s, "metadata")) {
                prealloc = 1;
            } else {
                fprintf(stderr, "Invalid preallocation mode: '%s'\n",
                    options->value.s);
                return -EINVAL;
            }
        }
        options++;
    }

    if (backing_file && prealloc) {
        fprintf(stderr, "Backing file and preallocation cannot be used at "
            "the same time\n");
        return -EINVAL;
    }

    return qcow2_create2(filename, sectors, backing_file, backing_fmt, flags,
                         cluster_size, prealloc, options);
}

static int qcow2_co_discard(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors)
{
    int ret;
    BDRVQcowState *s = bs->opaque;

    qemu_co_mutex_lock(&s->lock);
    ret = qcow2_discard_clusters(bs, sector_num << BDRV_SECTOR_BITS,
        nb_sectors);
    qemu_co_mutex_unlock(&s->lock);
    return ret;
}

static int qcow2_truncate(BlockDriverState *bs, int64_t offset)
{
    BDRVQcowState *s = bs->opaque;
    int ret, new_l1_size;

    if (offset & 511) {
        return -EINVAL;
    }

    /* shrinking is currently not supported */
    if (offset < bs->total_sectors * 512) {
        return -ENOTSUP;
    }

    new_l1_size = size_to_l1(s, offset);
    ret = qcow2_grow_l1_table(bs, new_l1_size, true);
    if (ret < 0) {
        return ret;
    }

    /* write updated header.size */
    offset = cpu_to_be64(offset);
    ret = bdrv_pwrite_sync(bs->file, offsetof(QCowHeader, size),
                           &offset, sizeof(uint64_t));
    if (ret < 0) {
        return ret;
    }

    s->l1_vm_state_index = new_l1_size;
    return 0;
}

static int qcow2_co_flush(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    int ret;

    qemu_co_mutex_lock(&s->lock);
    ret = qcow2_cache_flush(bs, s->l2_table_cache);
    if (ret < 0) {
        qemu_co_mutex_unlock(&s->lock);
        return ret;
    }

    ret = qcow2_cache_flush(bs, s->refcount_block_cache);
    if (ret < 0) {
        qemu_co_mutex_unlock(&s->lock);
        return ret;
    }
    qemu_co_mutex_unlock(&s->lock);

    return bdrv_co_flush(bs->file);
}


static QEMUOptionParameter qcow2_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_BACKING_FILE,
        .type = OPT_STRING,
        .help = "File name of a base image"
    },
    {
        .name = BLOCK_OPT_BACKING_FMT,
        .type = OPT_STRING,
        .help = "Image format of the base image"
    },
    {
        .name = BLOCK_OPT_CLUSTER_SIZE,
        .type = OPT_SIZE,
        .help = "qcow2 cluster size",
        .value = { .n = DEFAULT_CLUSTER_SIZE },
    },
    {
        .name = BLOCK_OPT_PREALLOC,
        .type = OPT_STRING,
        .help = "Preallocation mode (allowed values: off, metadata)"
    },
    { NULL }
};

static BlockDriver bdrv_qcow2 = {
    .format_name        = "qcow2",
    .instance_size      = sizeof(BDRVQcowState),
    .bdrv_probe         = qcow2_probe,
    .bdrv_open          = qcow2_open,
    .bdrv_close         = qcow2_close,
    .bdrv_create        = qcow2_create,
    .bdrv_is_allocated  = qcow2_is_allocated,

    .bdrv_co_readv      = qcow2_co_readv,
    .bdrv_co_writev     = qcow2_co_writev,
    .bdrv_co_flush      = qcow2_co_flush,

    .bdrv_co_discard        = qcow2_co_discard,
    .bdrv_truncate          = qcow2_truncate,

    .bdrv_change_backing_file   = qcow2_change_backing_file,

    .create_options = qcow2_create_options,
};

static void bdrv_qcow2_init(void)
{
    bdrv_register(&bdrv_qcow2);
}

block_init(bdrv_qcow2_init);
