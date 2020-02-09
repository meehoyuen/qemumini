#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

#define NOT_DONE 0x7fffffff /* used while emulated sync operation in progress */

static void bdrv_dev_change_media_cb(BlockDriverState *bs, bool load);
static BlockDriverAIOCB *bdrv_aio_readv_em(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
static BlockDriverAIOCB *bdrv_aio_writev_em(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
static int bdrv_co_readv_em(BlockDriverState *bs,
                                         int64_t sector_num, int nb_sectors,
                                         QEMUIOVector *iov);
static int bdrv_co_writev_em(BlockDriverState *bs,
                                         int64_t sector_num, int nb_sectors,
                                         QEMUIOVector *iov);
static int bdrv_co_do_readv(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors, QEMUIOVector *qiov);
static int bdrv_co_do_writev(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors, QEMUIOVector *qiov);
static BlockDriverAIOCB *bdrv_co_aio_rw_vector(BlockDriverState *bs,
                                               int64_t sector_num,
                                               QEMUIOVector *qiov,
                                               int nb_sectors,
                                               BlockDriverCompletionFunc *cb,
                                               void *opaque,
                                               bool is_write);
static void bdrv_co_do_rw(void *opaque);

static QTAILQ_HEAD(, BlockDriverState) bdrv_states =
    QTAILQ_HEAD_INITIALIZER(bdrv_states);

static QLIST_HEAD(, BlockDriver) bdrv_drivers =
    QLIST_HEAD_INITIALIZER(bdrv_drivers);

/* check if the path starts with "<protocol>:" */
static int path_has_protocol(const char *path)
{
    return strchr(path, ':') != NULL;
}

int path_is_absolute(const char *path)
{
    const char *p;

    p = strchr(path, ':');
    if (p)
        p++;
    else
        p = path;
    return (*p == '/');
}

/* if filename is absolute, just copy it to dest. Otherwise, build a
   path to it by considering it is relative to base_path. URL are
   supported. */
void path_combine(char *dest, int dest_size,
                  const char *base_path,
                  const char *filename)
{
    const char *p, *p1;
    int len;

    if (dest_size <= 0)
        return;
    if (path_is_absolute(filename)) {
        pstrcpy(dest, dest_size, filename);
    } else {
        p = strchr(base_path, ':');
        if (p)
            p++;
        else
            p = base_path;
        p1 = strrchr(base_path, '/');

        if (p1)
            p1++;
        else
            p1 = base_path;
        if (p1 > p)
            p = p1;
        len = p - base_path;
        if (len > dest_size - 1)
            len = dest_size - 1;
        memcpy(dest, base_path, len);
        dest[len] = '\0';
        pstrcat(dest, dest_size, filename);
    }
}

void bdrv_register(BlockDriver *bdrv)
{
    /* Block drivers without coroutine functions need emulation */
    if (!bdrv->bdrv_co_readv) {
        bdrv->bdrv_co_readv = bdrv_co_readv_em;
        bdrv->bdrv_co_writev = bdrv_co_writev_em;

        /* bdrv_co_readv_em()/brdv_co_writev_em() work in terms of aio, so if
         * the block driver lacks aio we need to emulate that too.
         */
        if (!bdrv->bdrv_aio_readv) {
            /* add AIO emulation layer */
            bdrv->bdrv_aio_readv = bdrv_aio_readv_em;
            bdrv->bdrv_aio_writev = bdrv_aio_writev_em;
        }
    }

    QLIST_INSERT_HEAD(&bdrv_drivers, bdrv, list);
}

/* create a new block device (by default it is empty) */
BlockDriverState *bdrv_new(const char *device_name)
{
    BlockDriverState *bs;

    bs = calloc(1, sizeof(BlockDriverState));
    pstrcpy(bs->device_name, sizeof(bs->device_name), device_name);
    if (device_name[0] != '\0') {
        QTAILQ_INSERT_TAIL(&bdrv_states, bs, list);
    }
    bdrv_iostatus_disable(bs);
    return bs;
}

BlockDriver *bdrv_find_format(const char *format_name)
{
    BlockDriver *drv1;
    QLIST_FOREACH(drv1, &bdrv_drivers, list) {
        if (!strcmp(drv1->format_name, format_name)) {
            return drv1;
        }
    }
    return NULL;
}

int bdrv_create(BlockDriver *drv, const char* filename,
    QEMUOptionParameter *options)
{
    if (!drv->bdrv_create)
        return -ENOTSUP;

    return drv->bdrv_create(filename, options);
}

int bdrv_create_file(const char* filename, QEMUOptionParameter *options)
{
    BlockDriver *drv;

    drv = bdrv_find_protocol(filename);
    if (drv == NULL) {
        return -ENOENT;
    }

    return bdrv_create(drv, filename, options);
}

/*
 * Detect host devices. By convention, /dev/cdrom[N] is always
 * recognized as a host CDROM.
 */
static BlockDriver *find_hdev_driver(const char *filename)
{
    int score_max = 0, score;
    BlockDriver *drv = NULL, *d;

    QLIST_FOREACH(d, &bdrv_drivers, list) {
        if (d->bdrv_probe_device) {
            score = d->bdrv_probe_device(filename);
            if (score > score_max) {
                score_max = score;
                drv = d;
            }
        }
    }

    return drv;
}

BlockDriver *bdrv_find_protocol(const char *filename)
{
    BlockDriver *drv1;
    char protocol[128];
    int len;
    const char *p;

    /* TODO Drivers without bdrv_file_open must be specified explicitly */

    /*
     * XXX(hch): we really should not let host device detection
     * override an explicit protocol specification, but moving this
     * later breaks access to device names with colons in them.
     * Thanks to the brain-dead persistent naming schemes on udev-
     * based Linux systems those actually are quite common.
     */
    drv1 = find_hdev_driver(filename);
    if (drv1) {
        return drv1;
    }

    if (!path_has_protocol(filename)) {
        return bdrv_find_format("file");
    }
    p = strchr(filename, ':');
    assert(p != NULL);
    len = p - filename;
    if (len > sizeof(protocol) - 1)
        len = sizeof(protocol) - 1;
    memcpy(protocol, filename, len);
    protocol[len] = '\0';
    QLIST_FOREACH(drv1, &bdrv_drivers, list) {
        if (drv1->protocol_name &&
            !strcmp(drv1->protocol_name, protocol)) {
            return drv1;
        }
    }
    return NULL;
}

static int find_image_format(const char *filename, BlockDriver **pdrv)
{
    int ret, score, score_max;
    BlockDriver *drv1, *drv;
    uint8_t buf[2048];
    BlockDriverState *bs;

    ret = bdrv_file_open(&bs, filename, 0);
    if (ret < 0) {
        *pdrv = NULL;
        return ret;
    }

    /* Return the raw BlockDriver * to scsi-generic devices or empty drives */
    if (bs->sg || !bdrv_is_inserted(bs)) {
        bdrv_delete(bs);
        drv = bdrv_find_format("raw");
        if (!drv) {
            ret = -ENOENT;
        }
        *pdrv = drv;
        return ret;
    }

    ret = bdrv_pread(bs, 0, buf, sizeof(buf));
    bdrv_delete(bs);
    if (ret < 0) {
        *pdrv = NULL;
        return ret;
    }

    score_max = 0;
    drv = NULL;
    QLIST_FOREACH(drv1, &bdrv_drivers, list) {
        if (drv1->bdrv_probe) {
            score = drv1->bdrv_probe(buf, ret, filename);
            if (score > score_max) {
                score_max = score;
                drv = drv1;
            }
        }
    }
    if (!drv) {
        ret = -ENOENT;
    }
    *pdrv = drv;
    return ret;
}

/**
 * Set the current 'total_sectors' value
 */
static int refresh_total_sectors(BlockDriverState *bs, int64_t hint)
{
    BlockDriver *drv = bs->drv;

    /* Do not attempt drv->bdrv_getlength() on scsi-generic devices */
    if (bs->sg)
        return 0;

    /* query actual device if possible, otherwise just trust the hint */
    if (drv->bdrv_getlength) {
        int64_t length = drv->bdrv_getlength(bs);
        if (length < 0) {
            return length;
        }
        hint = length >> BDRV_SECTOR_BITS;
    }

    bs->total_sectors = hint;
    return 0;
}

/**
 * Set open flags for a given cache mode
 *
 * Return 0 on success, -1 if the cache mode was invalid.
 */
int bdrv_parse_cache_flags(const char *mode, int *flags)
{
    *flags &= ~BDRV_O_CACHE_MASK;

    if (!strcmp(mode, "off") || !strcmp(mode, "none")) {
        *flags |= BDRV_O_NOCACHE | BDRV_O_CACHE_WB;
    } else if (!strcmp(mode, "directsync")) {
        *flags |= BDRV_O_NOCACHE;
    } else if (!strcmp(mode, "writeback")) {
        *flags |= BDRV_O_CACHE_WB;
    } else if (!strcmp(mode, "unsafe")) {
        *flags |= BDRV_O_CACHE_WB;
        *flags |= BDRV_O_NO_FLUSH;
    } else if (!strcmp(mode, "writethrough")) {
        /* this is the default */
    } else {
        return -1;
    }

    return 0;
}

/*
 * Common part for opening disk images and files
 */
static int bdrv_open_common(BlockDriverState *bs, const char *filename,
    int flags, BlockDriver *drv)
{
    int ret, open_flags;

    assert(drv != NULL);

    bs->file = NULL;
    bs->total_sectors = 0;
    bs->encrypted = 0;
    bs->valid_key = 0;
    bs->sg = 0;
    bs->open_flags = flags;
    bs->growable = 0;
    bs->buffer_alignment = 512;

    pstrcpy(bs->filename, sizeof(bs->filename), filename);
    bs->backing_file[0] = '\0';

    bs->drv = drv;
    bs->opaque = calloc(1, drv->instance_size);

    bs->enable_write_cache = !!(flags & BDRV_O_CACHE_WB);

    /*
     * Clear flags that are internal to the block layer before opening the
     * image.
     */
    open_flags = flags & ~(BDRV_O_NO_BACKING);

    /*
     * Snapshots should be writable.
     */
    if (bs->is_temporary) {
        open_flags |= BDRV_O_RDWR;
    }

    bs->keep_read_only = bs->read_only = !(open_flags & BDRV_O_RDWR);

    /* Open the image, either directly or using a protocol */
    if (drv->bdrv_file_open) {
        ret = drv->bdrv_file_open(bs, filename, open_flags);
    } else {
        ret = bdrv_file_open(&bs->file, filename, open_flags);
        if (ret >= 0) {
            ret = drv->bdrv_open(bs, open_flags);
        }
    }

    if (ret < 0) {
        goto free_and_fail;
    }

    ret = refresh_total_sectors(bs, bs->total_sectors);
    if (ret < 0) {
        goto free_and_fail;
    }

    if (bs->is_temporary) {
        unlink(filename);
    }

    return 0;

free_and_fail:
    if (bs->file) {
        bdrv_delete(bs->file);
        bs->file = NULL;
    }
    free(bs->opaque);
    bs->opaque = NULL;
    bs->drv = NULL;
    return ret;
}

/*
 * Opens a file using a protocol (file, host_device, nbd, ...)
 */
int bdrv_file_open(BlockDriverState **pbs, const char *filename, int flags)
{
    BlockDriverState *bs;
    BlockDriver *drv;
    int ret;

    drv = bdrv_find_protocol(filename);
    if (!drv) {
        return -ENOENT;
    }

    bs = bdrv_new("");
    ret = bdrv_open_common(bs, filename, flags, drv);
    if (ret < 0) {
        bdrv_delete(bs);
        return ret;
    }
    bs->growable = 1;
    *pbs = bs;
    return 0;
}

/*
 * Opens a disk image (raw, qcow2, vmdk, ...)
 */
int bdrv_open(BlockDriverState *bs, const char *filename, int flags,
              BlockDriver *drv)
{
    int ret;

    /* Find the right image format driver */
    if (!drv) {
        ret = find_image_format(filename, &drv);
    }

    if (!drv) {
        goto unlink_and_fail;
    }

    /* Open the image */
    ret = bdrv_open_common(bs, filename, flags, drv);
    if (ret < 0) {
        goto unlink_and_fail;
    }

    /* If there is a backing file, use it */
    if ((flags & BDRV_O_NO_BACKING) == 0 && bs->backing_file[0] != '\0') {
        char backing_filename[PATH_MAX];
        int back_flags;
        BlockDriver *back_drv = NULL;

        bs->backing_hd = bdrv_new("");

        if (path_has_protocol(bs->backing_file)) {
            pstrcpy(backing_filename, sizeof(backing_filename),
                    bs->backing_file);
        } else {
            path_combine(backing_filename, sizeof(backing_filename),
                         filename, bs->backing_file);
        }

        if (bs->backing_format[0] != '\0') {
            back_drv = bdrv_find_format(bs->backing_format);
        }

        /* backing files always opened read-only */
        back_flags =
            flags & ~(BDRV_O_RDWR | BDRV_O_NO_BACKING);

        ret = bdrv_open(bs->backing_hd, backing_filename, back_flags, back_drv);
        if (ret < 0) {
            bdrv_close(bs);
            return ret;
        }
        if (bs->is_temporary) {
            bs->backing_hd->keep_read_only = !(flags & BDRV_O_RDWR);
        } else {
            /* base image inherits from "parent" */
            bs->backing_hd->keep_read_only = bs->keep_read_only;
        }
    }

	bdrv_dev_change_media_cb(bs, true);

    return 0;

unlink_and_fail:
    if (bs->is_temporary) {
        unlink(filename);
    }
    return ret;
}

void bdrv_close(BlockDriverState *bs)
{
    if (bs->drv) {
        if (bs->backing_hd) {
            bdrv_delete(bs->backing_hd);
            bs->backing_hd = NULL;
        }
        bs->drv->bdrv_close(bs);
        free(bs->opaque);
        bs->opaque = NULL;
        bs->drv = NULL;

        if (bs->file != NULL) {
            bdrv_close(bs->file);
        }

        bdrv_dev_change_media_cb(bs, false);
    }
}

void bdrv_close_all(void)
{
    BlockDriverState *bs;

    QTAILQ_FOREACH(bs, &bdrv_states, list) {
        bdrv_close(bs);
    }
}

/* make a BlockDriverState anonymous by removing from bdrv_state list.
   Also, NULL terminate the device_name to prevent double remove */
void bdrv_make_anon(BlockDriverState *bs)
{
    if (bs->device_name[0] != '\0') {
        QTAILQ_REMOVE(&bdrv_states, bs, list);
    }
    bs->device_name[0] = '\0';
}

void bdrv_delete(BlockDriverState *bs)
{
    assert(!bs->dev);

    /* remove from list, if necessary */
    bdrv_make_anon(bs);

    bdrv_close(bs);
    if (bs->file != NULL) {
        bdrv_delete(bs->file);
    }

    free(bs);
    bs = NULL;
}

int bdrv_attach_dev(BlockDriverState *bs, void *dev)
/* TODO change to DeviceState *dev when all users are qdevified */
{
    if (bs->dev) {
        return -EBUSY;
    }
    bs->dev = dev;
    bdrv_iostatus_reset(bs);
    return 0;
}

/* TODO qdevified devices don't use this, remove when devices are qdevified */
void bdrv_attach_dev_nofail(BlockDriverState *bs, void *dev)
{
    if (bdrv_attach_dev(bs, dev) < 0) {
        abort();
    }
}

void bdrv_detach_dev(BlockDriverState *bs, void *dev)
/* TODO change to DeviceState *dev when all users are qdevified */
{
    assert(bs->dev == dev);
    bs->dev = NULL;
    bs->dev_ops = NULL;
    bs->dev_opaque = NULL;
    bs->buffer_alignment = 512;
}

/* TODO change to return DeviceState * when all users are qdevified */
void *bdrv_get_attached_dev(BlockDriverState *bs)
{
    return bs->dev;
}

void bdrv_set_dev_ops(BlockDriverState *bs, const BlockDevOps *ops,
                      void *opaque)
{
    bs->dev_ops = ops;
    bs->dev_opaque = opaque;
}

static void bdrv_dev_change_media_cb(BlockDriverState *bs, bool load)
{
    if (bs->dev_ops && bs->dev_ops->change_media_cb) {
        bs->dev_ops->change_media_cb(bs->dev_opaque, load);
    }
}

bool bdrv_dev_has_removable_media(BlockDriverState *bs)
{
    return !bs->dev || (bs->dev_ops && bs->dev_ops->change_media_cb);
}

bool bdrv_dev_is_tray_open(BlockDriverState *bs)
{
    if (bs->dev_ops && bs->dev_ops->is_tray_open) {
        return bs->dev_ops->is_tray_open(bs->dev_opaque);
    }
    return false;
}

static void bdrv_dev_resize_cb(BlockDriverState *bs)
{
    if (bs->dev_ops && bs->dev_ops->resize_cb) {
        bs->dev_ops->resize_cb(bs->dev_opaque);
    }
}

bool bdrv_dev_is_medium_locked(BlockDriverState *bs)
{
    if (bs->dev_ops && bs->dev_ops->is_medium_locked) {
        return bs->dev_ops->is_medium_locked(bs->dev_opaque);
    }
    return false;
}

/*
 * Run consistency checks on an image
 *
 * Returns 0 if the check could be completed (it doesn't mean that the image is
 * free of errors) or -errno when an internal error occurred. The results of the
 * check are stored in res.
 */
int bdrv_check(BlockDriverState *bs, BdrvCheckResult *res)
{
    if (bs->drv->bdrv_check == NULL) {
        return -ENOTSUP;
    }

    memset(res, 0, sizeof(*res));
    return bs->drv->bdrv_check(bs, res);
}

/*
 * Return values:
 * 0        - success
 * -EINVAL  - backing format specified, but no file
 * -ENOSPC  - can't update the backing file because no space is left in the
 *            image file header
 * -ENOTSUP - format driver doesn't support changing the backing file
 */
int bdrv_change_backing_file(BlockDriverState *bs,
    const char *backing_file, const char *backing_fmt)
{
    BlockDriver *drv = bs->drv;

    if (drv->bdrv_change_backing_file != NULL) {
        return drv->bdrv_change_backing_file(bs, backing_file, backing_fmt);
    } else {
        return -ENOTSUP;
    }
}

static int bdrv_check_byte_request(BlockDriverState *bs, int64_t offset,
                                   size_t size)
{
    int64_t len;

    if (!bdrv_is_inserted(bs))
        return -ENOMEDIUM;

    if (bs->growable)
        return 0;

    len = bdrv_getlength(bs);

    if (offset < 0)
        return -EIO;

    if ((offset > len) || (len - offset < size))
        return -EIO;

    return 0;
}

static int bdrv_check_request(BlockDriverState *bs, int64_t sector_num,
                              int nb_sectors)
{
    return bdrv_check_byte_request(bs, sector_num * BDRV_SECTOR_SIZE,
                                   nb_sectors * BDRV_SECTOR_SIZE);
}

typedef struct RwCo {
    BlockDriverState *bs;
    int64_t sector_num;
    int nb_sectors;
    QEMUIOVector *qiov;
    bool is_write;
    int ret;
} RwCo;

static void bdrv_rw_co_entry(void *opaque)
{
    RwCo *rwco = opaque;

    if (!rwco->is_write) {
        rwco->ret = bdrv_co_do_readv(rwco->bs, rwco->sector_num,
                                     rwco->nb_sectors, rwco->qiov);
    } else {
        rwco->ret = bdrv_co_do_writev(rwco->bs, rwco->sector_num,
                                      rwco->nb_sectors, rwco->qiov);
    }
}

/*
 * Process a synchronous request using coroutines
 */
static int bdrv_rw_co(BlockDriverState *bs, int64_t sector_num, uint8_t *buf,
                      int nb_sectors, bool is_write)
{
    QEMUIOVector qiov;
    struct iovec iov = {
        .iov_base = (void *)buf,
        .iov_len = nb_sectors * BDRV_SECTOR_SIZE,
    };
    Coroutine *co;
    RwCo rwco = {
        .bs = bs,
        .sector_num = sector_num,
        .nb_sectors = nb_sectors,
        .qiov = &qiov,
        .is_write = is_write,
        .ret = NOT_DONE,
    };

    qemu_iovec_init_external(&qiov, &iov, 1);

    if (qemu_in_coroutine()) {
        /* Fast-path if already in coroutine context */
        bdrv_rw_co_entry(&rwco);
    } else {
        co = qemu_coroutine_create(bdrv_rw_co_entry);
        qemu_coroutine_enter(co, &rwco);
        while (rwco.ret == NOT_DONE) {
            qemu_aio_wait();
        }
    }
    return rwco.ret;
}

/* return < 0 if error. See bdrv_write() for the return codes */
int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors)
{
    return bdrv_rw_co(bs, sector_num, buf, nb_sectors, false);
}

static void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
                             int nb_sectors, int dirty)
{
    int64_t start, end;
    unsigned long val, idx, bit;

    start = sector_num / BDRV_SECTORS_PER_DIRTY_CHUNK;
    end = (sector_num + nb_sectors - 1) / BDRV_SECTORS_PER_DIRTY_CHUNK;

    for (; start <= end; start++) {
        idx = start / (sizeof(unsigned long) * 8);
        bit = start % (sizeof(unsigned long) * 8);
        val = bs->dirty_bitmap[idx];
        if (dirty) {
            if (!(val & (1UL << bit))) {
                bs->dirty_count++;
                val |= 1UL << bit;
            }
        } else {
            if (val & (1UL << bit)) {
                bs->dirty_count--;
                val &= ~(1UL << bit);
            }
        }
        bs->dirty_bitmap[idx] = val;
    }
}

/* Return < 0 if error. Important errors are:
  -EIO         generic I/O error (may happen for all errors)
  -ENOMEDIUM   No media inserted.
  -EINVAL      Invalid sector number or nb_sectors
  -EACCES      Trying to write a read-only device
*/
int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors)
{
    return bdrv_rw_co(bs, sector_num, (uint8_t *)buf, nb_sectors, true);
}

int bdrv_pread(BlockDriverState *bs, int64_t offset,
               void *buf, int count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    int len, nb_sectors, count;
    int64_t sector_num;
    int ret;

    count = count1;
    /* first read to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = offset >> BDRV_SECTOR_BITS;
    if (len > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(buf, tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), len);
        count -= len;
        if (count == 0)
            return count1;
        sector_num++;
        buf += len;
    }

    /* read the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdrv_read(bs, sector_num, buf, nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(buf, tmp_buf, count);
    }
    return count1;
}

int bdrv_pwrite(BlockDriverState *bs, int64_t offset,
                const void *buf, int count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    int len, nb_sectors, count;
    int64_t sector_num;
    int ret;

    count = count1;
    /* first write to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = offset >> BDRV_SECTOR_BITS;
    if (len > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), buf, len);
        if ((ret = bdrv_write(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        count -= len;
        if (count == 0)
            return count1;
        sector_num++;
        buf += len;
    }

    /* write the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdrv_write(bs, sector_num, buf, nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(tmp_buf, buf, count);
        if ((ret = bdrv_write(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
    }
    return count1;
}

/*
 * Writes to the file and ensures that no writes are reordered across this
 * request (acts as a barrier)
 *
 * Returns 0 on success, -errno in error cases.
 */
int bdrv_pwrite_sync(BlockDriverState *bs, int64_t offset,
    const void *buf, int count)
{
    int ret;

    ret = bdrv_pwrite(bs, offset, buf, count);
    if (ret < 0) {
        return ret;
    }

    /* No flush needed for cache modes that use O_DSYNC */
    if ((bs->open_flags & BDRV_O_CACHE_WB) != 0) {
        bdrv_flush(bs);
    }

    return 0;
}

/*
 * Handle a read request in coroutine context
 */
static int bdrv_co_do_readv(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors, QEMUIOVector *qiov)
{
    BlockDriver *drv = bs->drv;

    if (!drv) {
        return -ENOMEDIUM;
    }
    if (bdrv_check_request(bs, sector_num, nb_sectors)) {
        return -EIO;
    }

    return drv->bdrv_co_readv(bs, sector_num, nb_sectors, qiov);
}

int bdrv_co_readv(BlockDriverState *bs, int64_t sector_num,
    int nb_sectors, QEMUIOVector *qiov)
{
    return bdrv_co_do_readv(bs, sector_num, nb_sectors, qiov);
}

/*
 * Handle a write request in coroutine context
 */
static int bdrv_co_do_writev(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors, QEMUIOVector *qiov)
{
    BlockDriver *drv = bs->drv;
    int ret;

    if (!bs->drv) {
        return -ENOMEDIUM;
    }
    if (bs->read_only) {
        return -EACCES;
    }
    if (bdrv_check_request(bs, sector_num, nb_sectors)) {
        return -EIO;
    }

    ret = drv->bdrv_co_writev(bs, sector_num, nb_sectors, qiov);

    if (bs->dirty_bitmap) {
        set_dirty_bitmap(bs, sector_num, nb_sectors, 1);
    }

    return ret;
}

int bdrv_co_writev(BlockDriverState *bs, int64_t sector_num,
    int nb_sectors, QEMUIOVector *qiov)
{
    return bdrv_co_do_writev(bs, sector_num, nb_sectors, qiov);
}

/**
 * Truncate file to 'offset' bytes (needed only for file protocols)
 */
int bdrv_truncate(BlockDriverState *bs, int64_t offset)
{
    BlockDriver *drv = bs->drv;
    int ret;
    if (!drv)
        return -ENOMEDIUM;
    if (!drv->bdrv_truncate)
        return -ENOTSUP;
    if (bs->read_only)
        return -EACCES;
    if (bdrv_in_use(bs))
        return -EBUSY;
    ret = drv->bdrv_truncate(bs, offset);
    if (ret == 0) {
        ret = refresh_total_sectors(bs, offset >> BDRV_SECTOR_BITS);
        bdrv_dev_resize_cb(bs);
    }
    return ret;
}

/**
 * Length of a allocated file in bytes. Sparse files are counted by actual
 * allocated space. Return < 0 if error or unknown.
 */
int64_t bdrv_get_allocated_file_size(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;
    if (!drv) {
        return -ENOMEDIUM;
    }
    if (drv->bdrv_get_allocated_file_size) {
        return drv->bdrv_get_allocated_file_size(bs);
    }
    if (bs->file) {
        return bdrv_get_allocated_file_size(bs->file);
    }
    return -ENOTSUP;
}

/**
 * Length of a file in bytes. Return < 0 if error or unknown.
 */
int64_t bdrv_getlength(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;
    if (!drv)
        return -ENOMEDIUM;

    if (bs->growable || bdrv_dev_has_removable_media(bs)) {
        if (drv->bdrv_getlength) {
            return drv->bdrv_getlength(bs);
        }
    }
    return bs->total_sectors * BDRV_SECTOR_SIZE;
}

/* return 0 as number of sectors if no device present or error */
void bdrv_get_geometry(BlockDriverState *bs, uint64_t *nb_sectors_ptr)
{
    int64_t length;
    length = bdrv_getlength(bs);
    if (length < 0)
        length = 0;
    else
        length = length >> BDRV_SECTOR_BITS;
    *nb_sectors_ptr = length;
}

struct partition {
        uint8_t boot_ind;           /* 0x80 - active */
        uint8_t head;               /* starting head */
        uint8_t sector;             /* starting sector */
        uint8_t cyl;                /* starting cylinder */
        uint8_t sys_ind;            /* What partition type */
        uint8_t end_head;           /* end head */
        uint8_t end_sector;         /* end sector */
        uint8_t end_cyl;            /* end cylinder */
        uint32_t start_sect;        /* starting sector counting from 0 */
        uint32_t nr_sects;          /* nr of sectors in partition */
} QEMU_PACKED;

/* try to guess the disk logical geometry from the MSDOS partition table. Return 0 if OK, -1 if could not guess */
static int guess_disk_lchs(BlockDriverState *bs,
                           int *pcylinders, int *pheads, int *psectors)
{
    uint8_t buf[BDRV_SECTOR_SIZE];
    int ret, i, heads, sectors, cylinders;
    struct partition *p;
    uint32_t nr_sects;
    uint64_t nb_sectors;

    bdrv_get_geometry(bs, &nb_sectors);

    ret = bdrv_read(bs, 0, buf, 1);
    if (ret < 0)
        return -1;
    /* test msdos magic */
    if (buf[510] != 0x55 || buf[511] != 0xaa)
        return -1;
    for(i = 0; i < 4; i++) {
        p = ((struct partition *)(buf + 0x1be)) + i;
        nr_sects = le32_to_cpu(p->nr_sects);
        if (nr_sects && p->end_head) {
            /* We make the assumption that the partition terminates on
               a cylinder boundary */
            heads = p->end_head + 1;
            sectors = p->end_sector & 63;
            if (sectors == 0)
                continue;
            cylinders = nb_sectors / (heads * sectors);
            if (cylinders < 1 || cylinders > 16383)
                continue;
            *pheads = heads;
            *psectors = sectors;
            *pcylinders = cylinders;
#if 0
            printf("guessed geometry: LCHS=%d %d %d\n",
                   cylinders, heads, sectors);
#endif
            return 0;
        }
    }
    return -1;
}

void bdrv_guess_geometry(BlockDriverState *bs, int *pcyls, int *pheads, int *psecs)
{
    int translation, lba_detected = 0;
    int cylinders, heads, secs;
    uint64_t nb_sectors;

    /* if a geometry hint is available, use it */
    bdrv_get_geometry(bs, &nb_sectors);
    bdrv_get_geometry_hint(bs, &cylinders, &heads, &secs);
    translation = bdrv_get_translation_hint(bs);
    if (cylinders != 0) {
        *pcyls = cylinders;
        *pheads = heads;
        *psecs = secs;
    } else {
        if (guess_disk_lchs(bs, &cylinders, &heads, &secs) == 0) {
            if (heads > 16) {
                /* if heads > 16, it means that a BIOS LBA
                   translation was active, so the default
                   hardware geometry is OK */
                lba_detected = 1;
                goto default_geometry;
            } else {
                *pcyls = cylinders;
                *pheads = heads;
                *psecs = secs;
                /* disable any translation to be in sync with
                   the logical geometry */
                if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_NONE);
                }
            }
        } else {
        default_geometry:
            /* if no geometry, use a standard physical disk geometry */
            cylinders = nb_sectors / (16 * 63);

            if (cylinders > 16383)
                cylinders = 16383;
            else if (cylinders < 2)
                cylinders = 2;
            *pcyls = cylinders;
            *pheads = 16;
            *psecs = 63;
            if ((lba_detected == 1) && (translation == BIOS_ATA_TRANSLATION_AUTO)) {
                if ((*pcyls * *pheads) <= 131072) {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_LARGE);
                } else {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_LBA);
                }
            }
        }
        bdrv_set_geometry_hint(bs, *pcyls, *pheads, *psecs);
    }
}

void bdrv_set_geometry_hint(BlockDriverState *bs,
                            int cyls, int heads, int secs)
{
    bs->cyls = cyls;
    bs->heads = heads;
    bs->secs = secs;
}

void bdrv_set_translation_hint(BlockDriverState *bs, int translation)
{
    bs->translation = translation;
}

void bdrv_get_geometry_hint(BlockDriverState *bs,
                            int *pcyls, int *pheads, int *psecs)
{
    *pcyls = bs->cyls;
    *pheads = bs->heads;
    *psecs = bs->secs;
}

/* Recognize floppy formats */
typedef struct FDFormat {
    FDriveType drive;
    uint8_t last_sect;
    uint8_t max_track;
    uint8_t max_head;
} FDFormat;

static const FDFormat fd_formats[] = {
    /* First entry is default format */
    /* 1.44 MB 3"1/2 floppy disks */
    { FDRIVE_DRV_144, 18, 80, 1, },
    { FDRIVE_DRV_144, 20, 80, 1, },
    { FDRIVE_DRV_144, 21, 80, 1, },
    { FDRIVE_DRV_144, 21, 82, 1, },
    { FDRIVE_DRV_144, 21, 83, 1, },
    { FDRIVE_DRV_144, 22, 80, 1, },
    { FDRIVE_DRV_144, 23, 80, 1, },
    { FDRIVE_DRV_144, 24, 80, 1, },
    /* 2.88 MB 3"1/2 floppy disks */
    { FDRIVE_DRV_288, 36, 80, 1, },
    { FDRIVE_DRV_288, 39, 80, 1, },
    { FDRIVE_DRV_288, 40, 80, 1, },
    { FDRIVE_DRV_288, 44, 80, 1, },
    { FDRIVE_DRV_288, 48, 80, 1, },
    /* 720 kB 3"1/2 floppy disks */
    { FDRIVE_DRV_144,  9, 80, 1, },
    { FDRIVE_DRV_144, 10, 80, 1, },
    { FDRIVE_DRV_144, 10, 82, 1, },
    { FDRIVE_DRV_144, 10, 83, 1, },
    { FDRIVE_DRV_144, 13, 80, 1, },
    { FDRIVE_DRV_144, 14, 80, 1, },
    /* 1.2 MB 5"1/4 floppy disks */
    { FDRIVE_DRV_120, 15, 80, 1, },
    { FDRIVE_DRV_120, 18, 80, 1, },
    { FDRIVE_DRV_120, 18, 82, 1, },
    { FDRIVE_DRV_120, 18, 83, 1, },
    { FDRIVE_DRV_120, 20, 80, 1, },
    /* 720 kB 5"1/4 floppy disks */
    { FDRIVE_DRV_120,  9, 80, 1, },
    { FDRIVE_DRV_120, 11, 80, 1, },
    /* 360 kB 5"1/4 floppy disks */
    { FDRIVE_DRV_120,  9, 40, 1, },
    { FDRIVE_DRV_120,  9, 40, 0, },
    { FDRIVE_DRV_120, 10, 41, 1, },
    { FDRIVE_DRV_120, 10, 42, 1, },
    /* 320 kB 5"1/4 floppy disks */
    { FDRIVE_DRV_120,  8, 40, 1, },
    { FDRIVE_DRV_120,  8, 40, 0, },
    /* 360 kB must match 5"1/4 better than 3"1/2... */
    { FDRIVE_DRV_144,  9, 80, 0, },
    /* end */
    { FDRIVE_DRV_NONE, -1, -1, 0, },
};

void bdrv_get_floppy_geometry_hint(BlockDriverState *bs, int *nb_heads,
                                   int *max_track, int *last_sect,
                                   FDriveType drive_in, FDriveType *drive)
{
    const FDFormat *parse;
    uint64_t nb_sectors, size;
    int i, first_match, match;

    bdrv_get_geometry_hint(bs, nb_heads, max_track, last_sect);
    if (*nb_heads != 0 && *max_track != 0 && *last_sect != 0) {
        /* User defined disk */
    } else {
        bdrv_get_geometry(bs, &nb_sectors);
        match = -1;
        first_match = -1;
        for (i = 0; ; i++) {
            parse = &fd_formats[i];
            if (parse->drive == FDRIVE_DRV_NONE) {
                break;
            }
            if (drive_in == parse->drive ||
                drive_in == FDRIVE_DRV_NONE) {
                size = (parse->max_head + 1) * parse->max_track *
                    parse->last_sect;
                if (nb_sectors == size) {
                    match = i;
                    break;
                }
                if (first_match == -1) {
                    first_match = i;
                }
            }
        }
        if (match == -1) {
            if (first_match == -1) {
                match = 1;
            } else {
                match = first_match;
            }
            parse = &fd_formats[match];
        }
        *nb_heads = parse->max_head + 1;
        *max_track = parse->max_track;
        *last_sect = parse->last_sect;
        *drive = parse->drive;
    }
}

int bdrv_get_translation_hint(BlockDriverState *bs)
{
    return bs->translation;
}

void bdrv_set_on_error(BlockDriverState *bs, BlockErrorAction on_read_error,
                       BlockErrorAction on_write_error)
{
    bs->on_read_error = on_read_error;
    bs->on_write_error = on_write_error;
}

BlockErrorAction bdrv_get_on_error(BlockDriverState *bs, int is_read)
{
    return is_read ? bs->on_read_error : bs->on_write_error;
}

int bdrv_is_read_only(BlockDriverState *bs)
{
    return bs->read_only;
}

int bdrv_is_sg(BlockDriverState *bs)
{
    return bs->sg;
}

int bdrv_enable_write_cache(BlockDriverState *bs)
{
    return bs->enable_write_cache;
}

void bdrv_get_format(BlockDriverState *bs, char *buf, int buf_size)
{
    if (!bs->drv) {
        buf[0] = '\0';
    } else {
        pstrcpy(buf, buf_size, bs->drv->format_name);
    }
}

void bdrv_iterate_format(void (*it)(void *opaque, const char *name),
                         void *opaque)
{
    BlockDriver *drv;

    QLIST_FOREACH(drv, &bdrv_drivers, list) {
        it(opaque, drv->format_name);
    }
}

BlockDriverState *bdrv_find(const char *name)
{
    BlockDriverState *bs;

    QTAILQ_FOREACH(bs, &bdrv_states, list) {
        if (!strcmp(name, bs->device_name)) {
            return bs;
        }
    }
    return NULL;
}

BlockDriverState *bdrv_next(BlockDriverState *bs)
{
    if (!bs) {
        return QTAILQ_FIRST(&bdrv_states);
    }
    return QTAILQ_NEXT(bs, list);
}

void bdrv_iterate(void (*it)(void *opaque, BlockDriverState *bs), void *opaque)
{
    BlockDriverState *bs;

    QTAILQ_FOREACH(bs, &bdrv_states, list) {
        it(opaque, bs);
    }
}

const char *bdrv_get_device_name(BlockDriverState *bs)
{
    return bs->device_name;
}

void bdrv_flush_all(void)
{
    BlockDriverState *bs;

    QTAILQ_FOREACH(bs, &bdrv_states, list) {
        if (!bdrv_is_read_only(bs) && bdrv_is_inserted(bs)) {
            bdrv_flush(bs);
        }
    }
}

int bdrv_has_zero_init(BlockDriverState *bs)
{
    assert(bs->drv);

    if (bs->drv->bdrv_has_zero_init) {
        return bs->drv->bdrv_has_zero_init(bs);
    }

    return 1;
}

/*
 * Returns true iff the specified sector is present in the disk image. Drivers
 * not implementing the functionality are assumed to not support backing files,
 * hence all their sectors are reported as allocated.
 *
 * 'pnum' is set to the number of sectors (including and immediately following
 * the specified sector) that are known to be in the same
 * allocated/unallocated state.
 *
 * 'nb_sectors' is the max value 'pnum' should be set to.
 */
int bdrv_is_allocated(BlockDriverState *bs, int64_t sector_num, int nb_sectors,
	int *pnum)
{
    int64_t n;
    if (!bs->drv->bdrv_is_allocated) {
        if (sector_num >= bs->total_sectors) {
            *pnum = 0;
            return 0;
        }
        n = bs->total_sectors - sector_num;
        *pnum = (n < nb_sectors) ? (n) : (nb_sectors);
        return 1;
    }
    return bs->drv->bdrv_is_allocated(bs, sector_num, nb_sectors, pnum);
}

void bdrv_debug_event(BlockDriverState *bs, BlkDebugEvent event)
{
    BlockDriver *drv = bs->drv;

    if (!drv || !drv->bdrv_debug_event) {
        return;
    }

    return drv->bdrv_debug_event(bs, event);

}

/**************************************************************/
/* async I/Os */
BlockDriverAIOCB *bdrv_aio_readv(BlockDriverState *bs, int64_t sector_num,
                                 QEMUIOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_co_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, false);
}

BlockDriverAIOCB *bdrv_aio_writev(BlockDriverState *bs, int64_t sector_num,
                                  QEMUIOVector *qiov, int nb_sectors,
                                  BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_co_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, true);
}

void bdrv_aio_cancel(BlockDriverAIOCB *acb)
{
    acb->pool->cancel(acb);
}


/**************************************************************/
/* async block device emulation */

typedef struct BlockDriverAIOCBSync {
    BlockDriverAIOCB common;
    QEMUBH *bh;
    int ret;
    /* vector translation state */
    QEMUIOVector *qiov;
    uint8_t *bounce;
    int is_write;
} BlockDriverAIOCBSync;

static void bdrv_aio_cancel_em(BlockDriverAIOCB *blockacb)
{
    BlockDriverAIOCBSync *acb =
        container_of(blockacb, BlockDriverAIOCBSync, common);
    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    qemu_aio_release(acb);
}

static AIOPool bdrv_em_aio_pool = {
    .aiocb_size         = sizeof(BlockDriverAIOCBSync),
    .cancel             = bdrv_aio_cancel_em,
};

static void bdrv_aio_bh_cb(void *opaque)
{
    BlockDriverAIOCBSync *acb = opaque;

    if (!acb->is_write)
        qemu_iovec_from_buffer(acb->qiov, acb->bounce, acb->qiov->size);
    free(acb->bounce);
    acb->common.cb(acb->common.opaque, acb->ret);
    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    qemu_aio_release(acb);
}

static BlockDriverAIOCB *bdrv_aio_rw_vector(BlockDriverState *bs,
                                            int64_t sector_num,
                                            QEMUIOVector *qiov,
                                            int nb_sectors,
                                            BlockDriverCompletionFunc *cb,
                                            void *opaque,
                                            int is_write)

{
    BlockDriverAIOCBSync *acb;

    acb = qemu_aio_get(&bdrv_em_aio_pool, bs, cb, opaque);
    acb->is_write = is_write;
    acb->qiov = qiov;
    acb->bounce = qemu_blockalign(bs, qiov->size);

    if (!acb->bh)
        acb->bh = qemu_bh_new(bdrv_aio_bh_cb, acb);

    if (is_write) {
        qemu_iovec_to_buffer(acb->qiov, acb->bounce);
        acb->ret = bs->drv->bdrv_write(bs, sector_num, acb->bounce, nb_sectors);
    } else {
        acb->ret = bs->drv->bdrv_read(bs, sector_num, acb->bounce, nb_sectors);
    }

    qemu_bh_schedule(acb->bh);

    return &acb->common;
}

static BlockDriverAIOCB *bdrv_aio_readv_em(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, 0);
}

static BlockDriverAIOCB *bdrv_aio_writev_em(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, 1);
}


typedef struct BlockDriverAIOCBCoroutine {
    BlockDriverAIOCB common;
    BlockRequest req;
    bool is_write;
    QEMUBH* bh;
} BlockDriverAIOCBCoroutine;

static void bdrv_aio_co_cancel_em(BlockDriverAIOCB *blockacb)
{
    qemu_aio_flush();
}

static AIOPool bdrv_em_co_aio_pool = {
    .aiocb_size         = sizeof(BlockDriverAIOCBCoroutine),
    .cancel             = bdrv_aio_co_cancel_em,
};

static void bdrv_co_em_bh(void *opaque)
{
    BlockDriverAIOCBCoroutine *acb = opaque;

    acb->common.cb(acb->common.opaque, acb->req.error);
    qemu_bh_delete(acb->bh);
    qemu_aio_release(acb);
}

/* Invoke bdrv_co_do_readv/bdrv_co_do_writev */
static void bdrv_co_do_rw(void *opaque)
{
    BlockDriverAIOCBCoroutine *acb = opaque;
    BlockDriverState *bs = acb->common.bs;

    if (!acb->is_write) {
        acb->req.error = bdrv_co_do_readv(bs, acb->req.sector,
            acb->req.nb_sectors, acb->req.qiov);
    } else {
        acb->req.error = bdrv_co_do_writev(bs, acb->req.sector,
            acb->req.nb_sectors, acb->req.qiov);
    }

    acb->bh = qemu_bh_new(bdrv_co_em_bh, acb);
    qemu_bh_schedule(acb->bh);
}

static BlockDriverAIOCB *bdrv_co_aio_rw_vector(BlockDriverState *bs,
                                               int64_t sector_num,
                                               QEMUIOVector *qiov,
                                               int nb_sectors,
                                               BlockDriverCompletionFunc *cb,
                                               void *opaque,
                                               bool is_write)
{
    Coroutine *co;
    BlockDriverAIOCBCoroutine *acb;

    acb = qemu_aio_get(&bdrv_em_co_aio_pool, bs, cb, opaque);
    acb->req.sector = sector_num;
    acb->req.nb_sectors = nb_sectors;
    acb->req.qiov = qiov;
    acb->is_write = is_write;

    co = qemu_coroutine_create(bdrv_co_do_rw);
    qemu_coroutine_enter(co, acb);

    return &acb->common;
}

static void bdrv_aio_flush_co_entry(void *opaque)
{
    BlockDriverAIOCBCoroutine *acb = opaque;
    BlockDriverState *bs = acb->common.bs;

    acb->req.error = bdrv_co_flush(bs);
    acb->bh = qemu_bh_new(bdrv_co_em_bh, acb);
    qemu_bh_schedule(acb->bh);
}

BlockDriverAIOCB *bdrv_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    Coroutine *co;
    BlockDriverAIOCBCoroutine *acb;

    acb = qemu_aio_get(&bdrv_em_co_aio_pool, bs, cb, opaque);
    co = qemu_coroutine_create(bdrv_aio_flush_co_entry);
    qemu_coroutine_enter(co, acb);

    return &acb->common;
}

static void bdrv_aio_discard_co_entry(void *opaque)
{
    BlockDriverAIOCBCoroutine *acb = opaque;
    BlockDriverState *bs = acb->common.bs;

    acb->req.error = bdrv_co_discard(bs, acb->req.sector, acb->req.nb_sectors);
    acb->bh = qemu_bh_new(bdrv_co_em_bh, acb);
    qemu_bh_schedule(acb->bh);
}

BlockDriverAIOCB *bdrv_aio_discard(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    Coroutine *co;
    BlockDriverAIOCBCoroutine *acb;

    acb = qemu_aio_get(&bdrv_em_co_aio_pool, bs, cb, opaque);
    acb->req.sector = sector_num;
    acb->req.nb_sectors = nb_sectors;
    co = qemu_coroutine_create(bdrv_aio_discard_co_entry);
    qemu_coroutine_enter(co, acb);

    return &acb->common;
}

void bdrv_init(void)
{
    module_call_init(MODULE_INIT_BLOCK);
}

void *qemu_aio_get(AIOPool *pool, BlockDriverState *bs,
                   BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriverAIOCB *acb;

    if (pool->free_aiocb) {
        acb = pool->free_aiocb;
        pool->free_aiocb = acb->next;
    } else {
        acb = calloc(1, pool->aiocb_size);
        acb->pool = pool;
    }
    acb->bs = bs;
    acb->cb = cb;
    acb->opaque = opaque;
    return acb;
}

void qemu_aio_release(void *p)
{
    BlockDriverAIOCB *acb = (BlockDriverAIOCB *)p;
    AIOPool *pool = acb->pool;
    acb->next = pool->free_aiocb;
    pool->free_aiocb = acb;
}

/**************************************************************/
/* Coroutine block device emulation */

typedef struct CoroutineIOCompletion {
    Coroutine *coroutine;
    int ret;
} CoroutineIOCompletion;

static void bdrv_co_io_em_complete(void *opaque, int ret)
{
    CoroutineIOCompletion *co = opaque;

    co->ret = ret;
    qemu_coroutine_enter(co->coroutine, NULL);
}

static int bdrv_co_io_em(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *iov,
                                      bool is_write)
{
    CoroutineIOCompletion co = {
        .coroutine = qemu_coroutine_self(),
    };
    BlockDriverAIOCB *acb;

    if (is_write) {
        acb = bs->drv->bdrv_aio_writev(bs, sector_num, iov, nb_sectors,
                                       bdrv_co_io_em_complete, &co);
    } else {
        acb = bs->drv->bdrv_aio_readv(bs, sector_num, iov, nb_sectors,
                                      bdrv_co_io_em_complete, &co);
    }

    if (!acb) {
        return -EIO;
    }

    qemu_coroutine_yield();

    return co.ret;
}

static int bdrv_co_readv_em(BlockDriverState *bs,
                                         int64_t sector_num, int nb_sectors,
                                         QEMUIOVector *iov)
{
    return bdrv_co_io_em(bs, sector_num, nb_sectors, iov, false);
}

static int bdrv_co_writev_em(BlockDriverState *bs,
                                         int64_t sector_num, int nb_sectors,
                                         QEMUIOVector *iov)
{
    return bdrv_co_io_em(bs, sector_num, nb_sectors, iov, true);
}

static void bdrv_flush_co_entry(void *opaque)
{
    RwCo *rwco = opaque;

    rwco->ret = bdrv_co_flush(rwco->bs);
}

int bdrv_co_flush(BlockDriverState *bs)
{
    if (bs->open_flags & BDRV_O_NO_FLUSH) {
        return 0;
    } else if (!bs->drv) {
        return 0;
    } else if (bs->drv->bdrv_co_flush) {
        return bs->drv->bdrv_co_flush(bs);
    } else if (bs->drv->bdrv_aio_flush) {
        BlockDriverAIOCB *acb;
        CoroutineIOCompletion co = {
            .coroutine = qemu_coroutine_self(),
        };

        acb = bs->drv->bdrv_aio_flush(bs, bdrv_co_io_em_complete, &co);
        if (acb == NULL) {
            return -EIO;
        } else {
            qemu_coroutine_yield();
            return co.ret;
        }
    } else {
        /*
         * Some block drivers always operate in either writethrough or unsafe
         * mode and don't support bdrv_flush therefore. Usually qemu doesn't
         * know how the server works (because the behaviour is hardcoded or
         * depends on server-side configuration), so we can't ensure that
         * everything is safe on disk. Returning an error doesn't work because
         * that would break guests even if the server operates in writethrough
         * mode.
         *
         * Let's hope the user knows what he's doing.
         */
        return 0;
    }
}

int bdrv_flush(BlockDriverState *bs)
{
    Coroutine *co;
    RwCo rwco = {
        .bs = bs,
        .ret = NOT_DONE,
    };

    if (qemu_in_coroutine()) {
        /* Fast-path if already in coroutine context */
        bdrv_flush_co_entry(&rwco);
    } else {
        co = qemu_coroutine_create(bdrv_flush_co_entry);
        qemu_coroutine_enter(co, &rwco);
        while (rwco.ret == NOT_DONE) {
            qemu_aio_wait();
        }
    }

    return rwco.ret;
}

static void bdrv_discard_co_entry(void *opaque)
{
    RwCo *rwco = opaque;

    rwco->ret = bdrv_co_discard(rwco->bs, rwco->sector_num, rwco->nb_sectors);
}

int bdrv_co_discard(BlockDriverState *bs, int64_t sector_num,
                                 int nb_sectors)
{
    if (!bs->drv) {
        return -ENOMEDIUM;
    } else if (bdrv_check_request(bs, sector_num, nb_sectors)) {
        return -EIO;
    } else if (bs->read_only) {
        return -EROFS;
    } else if (bs->drv->bdrv_co_discard) {
        return bs->drv->bdrv_co_discard(bs, sector_num, nb_sectors);
    } else if (bs->drv->bdrv_aio_discard) {
        BlockDriverAIOCB *acb;
        CoroutineIOCompletion co = {
            .coroutine = qemu_coroutine_self(),
        };

        acb = bs->drv->bdrv_aio_discard(bs, sector_num, nb_sectors,
                                        bdrv_co_io_em_complete, &co);
        if (acb == NULL) {
            return -EIO;
        } else {
            qemu_coroutine_yield();
            return co.ret;
        }
    } else {
        return 0;
    }
}

int bdrv_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    Coroutine *co;
    RwCo rwco = {
        .bs = bs,
        .sector_num = sector_num,
        .nb_sectors = nb_sectors,
        .ret = NOT_DONE,
    };

    if (qemu_in_coroutine()) {
        /* Fast-path if already in coroutine context */
        bdrv_discard_co_entry(&rwco);
    } else {
        co = qemu_coroutine_create(bdrv_discard_co_entry);
        qemu_coroutine_enter(co, &rwco);
        while (rwco.ret == NOT_DONE) {
            qemu_aio_wait();
        }
    }

    return rwco.ret;
}

/**************************************************************/
/* removable device support */

/**
 * Return TRUE if the media is present
 */
int bdrv_is_inserted(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return 0;
    if (!drv->bdrv_is_inserted)
        return 1;
    return drv->bdrv_is_inserted(bs);
}

/**
 * Return whether the media changed since the last call to this
 * function, or -ENOTSUP if we don't know.  Most drivers don't know.
 */
int bdrv_media_changed(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_media_changed) {
        return drv->bdrv_media_changed(bs);
    }
    return -ENOTSUP;
}

/**
 * If eject_flag is TRUE, eject the media. Otherwise, close the tray
 */
void bdrv_eject(BlockDriverState *bs, int eject_flag)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_eject) {
        drv->bdrv_eject(bs, eject_flag);
    }
}

/**
 * Lock or unlock the media (if it is locked, the user won't be able
 * to eject it manually).
 */
void bdrv_lock_medium(BlockDriverState *bs, bool locked)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_lock_medium) {
        drv->bdrv_lock_medium(bs, locked);
    }
}

/* needed for generic scsi interface */

int bdrv_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_ioctl)
        return drv->bdrv_ioctl(bs, req, buf);
    return -ENOTSUP;
}

BlockDriverAIOCB *bdrv_aio_ioctl(BlockDriverState *bs,
        unsigned long int req, void *buf,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_aio_ioctl)
        return drv->bdrv_aio_ioctl(bs, req, buf, cb, opaque);
    return NULL;
}

void bdrv_set_buffer_alignment(BlockDriverState *bs, int align)
{
    bs->buffer_alignment = align;
}

void *qemu_blockalign(BlockDriverState *bs, size_t size)
{
    return qemu_memalign((bs && bs->buffer_alignment) ? bs->buffer_alignment : 512, size);
}

void bdrv_set_dirty_tracking(BlockDriverState *bs, int enable)
{
    int64_t bitmap_size;

    bs->dirty_count = 0;
    if (enable) {
        if (!bs->dirty_bitmap) {
            bitmap_size = (bdrv_getlength(bs) >> BDRV_SECTOR_BITS) +
                    BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1;
            bitmap_size /= BDRV_SECTORS_PER_DIRTY_CHUNK * 8;

            bs->dirty_bitmap = calloc(1, bitmap_size);
        }
    } else {
        if (bs->dirty_bitmap) {
            free(bs->dirty_bitmap);
            bs->dirty_bitmap = NULL;
        }
    }
}

int bdrv_get_dirty(BlockDriverState *bs, int64_t sector)
{
    int64_t chunk = sector / (int64_t)BDRV_SECTORS_PER_DIRTY_CHUNK;

    if (bs->dirty_bitmap &&
        (sector << BDRV_SECTOR_BITS) < bdrv_getlength(bs)) {
        return !!(bs->dirty_bitmap[chunk / (sizeof(unsigned long) * 8)] &
            (1UL << (chunk % (sizeof(unsigned long) * 8))));
    } else {
        return 0;
    }
}

void bdrv_reset_dirty(BlockDriverState *bs, int64_t cur_sector,
                      int nr_sectors)
{
    set_dirty_bitmap(bs, cur_sector, nr_sectors, 0);
}

int64_t bdrv_get_dirty_count(BlockDriverState *bs)
{
    return bs->dirty_count;
}

void bdrv_set_in_use(BlockDriverState *bs, int in_use)
{
    assert(bs->in_use != in_use);
    bs->in_use = in_use;
}

int bdrv_in_use(BlockDriverState *bs)
{
    return bs->in_use;
}

void bdrv_iostatus_enable(BlockDriverState *bs)
{
    bs->iostatus_enabled = true;
    bs->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
}

/* The I/O status is only enabled if the drive explicitly
 * enables it _and_ the VM is configured to stop on errors */
bool bdrv_iostatus_is_enabled(const BlockDriverState *bs)
{
    return (bs->iostatus_enabled &&
           (bs->on_write_error == BLOCK_ERR_STOP_ENOSPC ||
            bs->on_write_error == BLOCK_ERR_STOP_ANY    ||
            bs->on_read_error == BLOCK_ERR_STOP_ANY));
}

void bdrv_iostatus_disable(BlockDriverState *bs)
{
    bs->iostatus_enabled = false;
}

void bdrv_iostatus_reset(BlockDriverState *bs)
{
    if (bdrv_iostatus_is_enabled(bs)) {
        bs->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
    }
}

void bdrv_iostatus_set_err(BlockDriverState *bs, int error)
{
    if (bdrv_iostatus_is_enabled(bs) &&
        bs->iostatus == BLOCK_DEVICE_IO_STATUS_OK) {
        assert(error >= 0);
        bs->iostatus = error == ENOSPC ? BLOCK_DEVICE_IO_STATUS_NOSPACE :
                                         BLOCK_DEVICE_IO_STATUS_FAILED;
    }
}
