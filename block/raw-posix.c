#include "qemu-common.h"
#include "qemu-timer.h"
#include "block_int.h"
#include "module.h"
#include "block/raw-posix-aio.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <linux/cdrom.h>
#include <linux/fd.h>

//#define DEBUG_FLOPPY

//#define DEBUG_BLOCK
#if defined(DEBUG_BLOCK)
#define DEBUG_BLOCK_PRINT(formatCstr, ...) do { if (qemu_log_enabled()) \
    { qemu_log(formatCstr, ## __VA_ARGS__); qemu_log_flush(); } } while (0)
#else
#define DEBUG_BLOCK_PRINT(formatCstr, ...)
#endif

/* Approximate O_DIRECT with O_DSYNC if O_DIRECT isn't available */
#ifndef O_DIRECT
#define O_DIRECT O_DSYNC
#endif

#define FTYPE_FILE   0
#define FTYPE_CD     1
#define FTYPE_FD     2

/* if the FD is not accessed during that time (in ns), we try to
   reopen it to see if the disk has been changed */
#define FD_OPEN_TIMEOUT (1000000000)

#define MAX_BLOCKSIZE	4096

typedef struct BDRVRawState {
    int fd;
    int type;
    int open_flags;

    /* linux floppy specific */
    int64_t fd_open_time;
    int64_t fd_error_time;
    int fd_got_error;
    int fd_media_changed;
    uint8_t *aligned_buf;
    unsigned aligned_buf_size;
} BDRVRawState;

static int fd_open(BlockDriverState *bs);
static int64_t raw_getlength(BlockDriverState *bs);


static int raw_open_common(BlockDriverState *bs, const char *filename,
                           int bdrv_flags, int open_flags)
{
    BDRVRawState *s = bs->opaque;
    int fd, ret;

    s->open_flags = open_flags | O_BINARY;
    s->open_flags &= ~O_ACCMODE;
    if (bdrv_flags & BDRV_O_RDWR) {
        s->open_flags |= O_RDWR;
    } else {
        s->open_flags |= O_RDONLY;
    }

    /* Use O_DSYNC for write-through caching, no flags for write-back caching,
     * and O_DIRECT for no caching. */
    if ((bdrv_flags & BDRV_O_NOCACHE))
        s->open_flags |= O_DIRECT;
    if (!(bdrv_flags & BDRV_O_CACHE_WB))
        s->open_flags |= O_DSYNC;

    s->fd = -1;
    fd = open(filename, s->open_flags | O_CLOEXEC, 0644);
    if (fd < 0) {
        ret = -errno;
        if (ret == -EROFS)
            ret = -EACCES;
        return ret;
    }
    s->fd = fd;
    s->aligned_buf = NULL;

    if ((bdrv_flags & BDRV_O_NOCACHE)) {
        /*
         * Allocate a buffer for read/modify/write cycles.  Chose the size
         * pessimistically as we don't know the block size yet.
         */
        s->aligned_buf_size = 32 * MAX_BLOCKSIZE;
        s->aligned_buf = qemu_memalign(MAX_BLOCKSIZE, s->aligned_buf_size);
        if (s->aligned_buf == NULL) {
            goto out_close;
        }
    }

    /* We're falling back to POSIX AIO in some cases so init always */
    if (paio_init() < 0) {
        goto out_free_buf;
    }

    return 0;

out_free_buf:
    free(s->aligned_buf);
out_close:
    close(fd);
    return -errno;
}

static int raw_open(BlockDriverState *bs, const char *filename, int flags)
{
    BDRVRawState *s = bs->opaque;

    s->type = FTYPE_FILE;
    return raw_open_common(bs, filename, flags, 0);
}

/*
 * Check if all memory in this vector is sector aligned.
 */
static int qiov_is_aligned(BlockDriverState *bs, QEMUIOVector *qiov)
{
    int i;

    for (i = 0; i < qiov->niov; i++) {
        if ((uintptr_t) qiov->iov[i].iov_base % bs->buffer_alignment) {
            return 0;
        }
    }

    return 1;
}

static BlockDriverAIOCB *raw_aio_submit(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque, int type)
{
    BDRVRawState *s = bs->opaque;

    if (fd_open(bs) < 0)
        return NULL;

    /*
     * If O_DIRECT is used the buffer needs to be aligned on a sector
     * boundary.  Check if this is the case or tell the low-level
     * driver that it needs to copy the buffer.
     */
    if (s->aligned_buf) {
        if (!qiov_is_aligned(bs, qiov)) {
            type |= QEMU_AIO_MISALIGNED;
        }
    }

    return paio_submit(bs, s->fd, sector_num, qiov, nb_sectors,
                       cb, opaque, type);
}

static BlockDriverAIOCB *raw_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return raw_aio_submit(bs, sector_num, qiov, nb_sectors,
                          cb, opaque, QEMU_AIO_READ);
}

static BlockDriverAIOCB *raw_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return raw_aio_submit(bs, sector_num, qiov, nb_sectors,
                          cb, opaque, QEMU_AIO_WRITE);
}

static BlockDriverAIOCB *raw_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;

    if (fd_open(bs) < 0)
        return NULL;

    return paio_submit(bs, s->fd, 0, NULL, 0, cb, opaque, QEMU_AIO_FLUSH);
}

static void raw_close(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
        if (s->aligned_buf != NULL)
            free(s->aligned_buf);
    }
}

static int raw_truncate(BlockDriverState *bs, int64_t offset)
{
    BDRVRawState *s = bs->opaque;
    struct stat st;

    if (fstat(s->fd, &st)) {
        return -errno;
    }

    if (S_ISREG(st.st_mode)) {
        if (ftruncate(s->fd, offset) < 0) {
            return -errno;
        }
    } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
       if (offset > raw_getlength(bs)) {
           return -EINVAL;
       }
    } else {
        return -ENOTSUP;
    }

    return 0;
}

static int fd_open(BlockDriverState *bs) 
{
    BDRVRawState *s = bs->opaque;
    int last_media_present;

    if (s->type != FTYPE_FD)
        return 0;
    last_media_present = (s->fd >= 0);
    if (s->fd >= 0 && 
        (get_clock() - s->fd_open_time) >= FD_OPEN_TIMEOUT) {
        close(s->fd);
        s->fd = -1;
    }    
    if (s->fd < 0) { 
        if (s->fd_got_error &&
            (get_clock() - s->fd_error_time) < FD_OPEN_TIMEOUT) {

            return -EIO;
        }    
        s->fd = open(bs->filename, s->open_flags & ~O_NONBLOCK);
        if (s->fd < 0) { 
            s->fd_error_time = get_clock();
            s->fd_got_error = 1; 
            if (last_media_present)
                s->fd_media_changed = 1; 

            return -EIO;
        }
    }    
    if (!last_media_present)
        s->fd_media_changed = 1; 
    s->fd_open_time = get_clock();
    s->fd_got_error = 0; 
    return 0;
}

static int64_t raw_getlength(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    int ret;

    ret = fd_open(bs);
    if (ret < 0) {
        return ret;
    }

    return lseek(s->fd, 0, SEEK_END);
}

static int64_t raw_get_allocated_file_size(BlockDriverState *bs)
{
    struct stat st;
    BDRVRawState *s = bs->opaque;

    if (fstat(s->fd, &st) < 0) {
        return -errno;
    }
    return (int64_t)st.st_blocks * 512;
}

static int raw_create(const char *filename, QEMUOptionParameter *options)
{
    int fd;
    int result = 0;
    int64_t total_size = 0;

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            total_size = options->value.n / BDRV_SECTOR_SIZE;
        }
        options++;
    }

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
              0644);
    if (fd < 0) {
        result = -errno;
    } else {
        if (ftruncate(fd, total_size * BDRV_SECTOR_SIZE) != 0) {
            result = -errno;
        }
        if (close(fd) != 0) {
            result = -errno;
        }
    }
    return result;
}

static QEMUOptionParameter raw_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    { NULL }
};

static BlockDriver bdrv_file = {
    .format_name = "file",
    .protocol_name = "file",
    .instance_size = sizeof(BDRVRawState),
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_file_open = raw_open,
    .bdrv_close = raw_close,
    .bdrv_create = raw_create,

    .bdrv_aio_readv = raw_aio_readv,
    .bdrv_aio_writev = raw_aio_writev,
    .bdrv_aio_flush = raw_aio_flush,

    .bdrv_truncate = raw_truncate,
    .bdrv_getlength = raw_getlength,
    .bdrv_get_allocated_file_size
                        = raw_get_allocated_file_size,

    .create_options = raw_create_options,
};

static void bdrv_file_init(void)
{
    bdrv_register(&bdrv_file);
}

block_init(bdrv_file_init);
