#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
//#include <zlib.h>

typedef struct BDRVCloopState {
    uint32_t block_size;
    uint32_t n_blocks;
    uint64_t *offsets;
    uint32_t sectors_per_block;
    uint32_t current_block;
    uint8_t *compressed_block;
    uint8_t *uncompressed_block;
    //z_stream zstream;
} BDRVCloopState;

static int cloop_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const char *magic_version_2_0 = "#!/bin/sh\n"
        "#V2.0 Format\n"
        "modprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n";
    int length = strlen(magic_version_2_0);
    if (length > buf_size) {
        length = buf_size;
    }
    if (!memcmp(magic_version_2_0, buf, length)) {
        return 2;
    }
    return 0;
}

static int cloop_open(BlockDriverState *bs, int flags)
{
    BDRVCloopState *s = bs->opaque;
    uint32_t offsets_size, max_compressed_block_size = 1, i;

    bs->read_only = 1;

    /* read header */
    if (bdrv_pread(bs->file, 128, &s->block_size, 4) < 4) {
        goto cloop_close;
    }
    s->block_size = be32_to_cpu(s->block_size);

    if (bdrv_pread(bs->file, 128 + 4, &s->n_blocks, 4) < 4) {
        goto cloop_close;
    }
    s->n_blocks = be32_to_cpu(s->n_blocks);

    /* read offsets */
    offsets_size = s->n_blocks * sizeof(uint64_t);
    s->offsets = malloc(offsets_size);
    if (bdrv_pread(bs->file, 128 + 4 + 4, s->offsets, offsets_size) <
            offsets_size) {
        goto cloop_close;
    }
    for(i=0;i<s->n_blocks;i++) {
        s->offsets[i] = be64_to_cpu(s->offsets[i]);
        if (i > 0) {
            uint32_t size = s->offsets[i] - s->offsets[i - 1];
            if (size > max_compressed_block_size) {
                max_compressed_block_size = size;
            }
        }
    }

    /* initialize zlib engine */
    s->compressed_block = malloc(max_compressed_block_size + 1);
    s->uncompressed_block = malloc(s->block_size);
    if (0/*inflateInit(&s->zstream) != Z_OK*/) {
        goto cloop_close;
    }
    s->current_block = s->n_blocks;

    s->sectors_per_block = s->block_size/512;
    bs->total_sectors = s->n_blocks * s->sectors_per_block;
    return 0;

cloop_close:
    return -1;
}

static inline int cloop_read_block(BlockDriverState *bs, int block_num)
{
    BDRVCloopState *s = bs->opaque;

    if (s->current_block != block_num) {
        int ret;
        uint32_t bytes = s->offsets[block_num + 1] - s->offsets[block_num];

        ret = bdrv_pread(bs->file, s->offsets[block_num], s->compressed_block,
                         bytes);
        if (ret != bytes) {
            return -1;
        }
#if 0
        s->zstream.next_in = s->compressed_block;
        s->zstream.avail_in = bytes;
        s->zstream.next_out = s->uncompressed_block;
        s->zstream.avail_out = s->block_size;
        ret = 0;//inflateReset(&s->zstream);
        if (ret != Z_OK) {
            return -1;
        }
        ret = 0;//inflate(&s->zstream, Z_FINISH);
        if (ret != Z_STREAM_END || s->zstream.total_out != s->block_size) {
            return -1;
        }
#endif
        s->current_block = block_num;
    }
    return 0;
}

static int cloop_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    BDRVCloopState *s = bs->opaque;
    int i;

    for (i = 0; i < nb_sectors; i++) {
        uint32_t sector_offset_in_block =
            ((sector_num + i) % s->sectors_per_block),
            block_num = (sector_num + i) / s->sectors_per_block;
        if (cloop_read_block(bs, block_num) != 0) {
            return -1;
        }
        memcpy(buf + i * 512,
            s->uncompressed_block + sector_offset_in_block * 512, 512);
    }
    return 0;
}

static void cloop_close(BlockDriverState *bs)
{
    BDRVCloopState *s = bs->opaque;
    if (s->n_blocks > 0) {
        free(s->offsets);
        s->offsets = NULL;
    }
    free(s->compressed_block);
    s->compressed_block = NULL;
    free(s->uncompressed_block);
    s->uncompressed_block = NULL;
    //inflateEnd(&s->zstream);
}

static BlockDriver bdrv_cloop = {
    .format_name    = "cloop",
    .instance_size  = sizeof(BDRVCloopState),
    .bdrv_probe     = cloop_probe,
    .bdrv_open      = cloop_open,
    .bdrv_read      = cloop_read,
    .bdrv_close     = cloop_close,
};

static void bdrv_cloop_init(void)
{
    bdrv_register(&bdrv_cloop);
}

block_init(bdrv_cloop_init);
