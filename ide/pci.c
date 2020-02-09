#include <hw.h>
#include <pc.h>
#include <pci.h>
#include <isa.h>
#include "block.h"
#include "dma.h"

#include <ide/pci.h>

#define BMDMA_PAGE_SIZE 4096

static void bmdma_start_dma(IDEDMA *dma, IDEState *s,
                            BlockDriverCompletionFunc *dma_cb)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);

    bm->unit = s->unit;
    bm->dma_cb = dma_cb;
    bm->cur_prd_last = 0;
    bm->cur_prd_addr = 0;
    bm->cur_prd_len = 0;
    bm->sector_num = ide_get_sector(s);
    bm->nsector = s->nsector;

    if (bm->status & BM_STATUS_DMAING) {
        bm->dma_cb(bmdma_active_if(bm), 0);
    }
}

/* return 0 if buffer completed */
static int bmdma_prepare_buf(IDEDMA *dma, int is_write)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    IDEState *s = bmdma_active_if(bm);
    struct {
        uint32_t addr;
        uint32_t size;
    } prd;
    int l, len;

    pci_dma_sglist_init(&s->sg, &bm->pci_dev->dev,
                        s->nsector / (BMDMA_PAGE_SIZE / 512) + 1);
    s->io_buffer_size = 0;
    for(;;) {
        if (bm->cur_prd_len == 0) {
            /* end of table (with a fail safe of one page) */
            if (bm->cur_prd_last ||
                (bm->cur_addr - bm->addr) >= BMDMA_PAGE_SIZE)
                return s->io_buffer_size != 0;
            pci_dma_read(&bm->pci_dev->dev, bm->cur_addr, (uint8_t *)&prd, 8);
            bm->cur_addr += 8;
            prd.addr = le32_to_cpu(prd.addr);
            prd.size = le32_to_cpu(prd.size);
            len = prd.size & 0xfffe;
            if (len == 0)
                len = 0x10000;
            bm->cur_prd_len = len;
            bm->cur_prd_addr = prd.addr;
            bm->cur_prd_last = (prd.size & 0x80000000);
        }
        l = bm->cur_prd_len;
        if (l > 0) {
            qemu_sglist_add(&s->sg, bm->cur_prd_addr, l);
            bm->cur_prd_addr += l;
            bm->cur_prd_len -= l;
            s->io_buffer_size += l;
        }
    }
    return 1;
}

/* return 0 if buffer completed */
static int bmdma_rw_buf(IDEDMA *dma, int is_write)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    IDEState *s = bmdma_active_if(bm);
    struct {
        uint32_t addr;
        uint32_t size;
    } prd;
    int l, len;

    for(;;) {
        l = s->io_buffer_size - s->io_buffer_index;
        if (l <= 0)
            break;
        if (bm->cur_prd_len == 0) {
            /* end of table (with a fail safe of one page) */
            if (bm->cur_prd_last ||
                (bm->cur_addr - bm->addr) >= BMDMA_PAGE_SIZE)
                return 0;
            pci_dma_read(&bm->pci_dev->dev, bm->cur_addr, (uint8_t *)&prd, 8);
            bm->cur_addr += 8;
            prd.addr = le32_to_cpu(prd.addr);
            prd.size = le32_to_cpu(prd.size);
            len = prd.size & 0xfffe;
            if (len == 0)
                len = 0x10000;
            bm->cur_prd_len = len;
            bm->cur_prd_addr = prd.addr;
            bm->cur_prd_last = (prd.size & 0x80000000);
        }
        if (l > bm->cur_prd_len)
            l = bm->cur_prd_len;
        if (l > 0) {
            if (is_write) {
                pci_dma_write(&bm->pci_dev->dev, bm->cur_prd_addr,
                              s->io_buffer + s->io_buffer_index, l);
            } else {
                pci_dma_read(&bm->pci_dev->dev, bm->cur_prd_addr,
                             s->io_buffer + s->io_buffer_index, l);
            }
            bm->cur_prd_addr += l;
            bm->cur_prd_len -= l;
            s->io_buffer_index += l;
        }
    }
    return 1;
}

static int bmdma_set_unit(IDEDMA *dma, int unit)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    bm->unit = unit;

    return 0;
}

static int bmdma_add_status(IDEDMA *dma, int status)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    bm->status |= status;

    return 0;
}

static int bmdma_set_inactive(IDEDMA *dma)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);

    bm->status &= ~BM_STATUS_DMAING;
    bm->dma_cb = NULL;
    bm->unit = -1;

    return 0;
}

static void bmdma_restart_dma(BMDMAState *bm, enum ide_dma_cmd dma_cmd)
{
    IDEState *s = bmdma_active_if(bm);

    ide_set_sector(s, bm->sector_num);
    s->io_buffer_index = 0;
    s->io_buffer_size = 0;
    s->nsector = bm->nsector;
    s->dma_cmd = dma_cmd;
    bm->cur_addr = bm->addr;
    bm->dma_cb = ide_dma_cb;
    bmdma_start_dma(&bm->dma, s, bm->dma_cb);
}

/* TODO This should be common IDE code */
static void bmdma_restart_bh(void *opaque)
{
    BMDMAState *bm = opaque;
    IDEBus *bus = bm->bus;
    int is_read;
    int error_status;

    qemu_bh_delete(bm->bh);
    bm->bh = NULL;

    if (bm->unit == (uint8_t) -1) {
        return;
    }

    is_read = !!(bus->error_status & BM_STATUS_RETRY_READ);

    /* The error status must be cleared before resubmitting the request: The
     * request may fail again, and this case can only be distinguished if the
     * called function can set a new error status. */
    error_status = bus->error_status;
    bus->error_status = 0;

    if (error_status & BM_STATUS_DMA_RETRY) {
        if (error_status & BM_STATUS_RETRY_TRIM) {
            bmdma_restart_dma(bm, IDE_DMA_TRIM);
        } else {
            bmdma_restart_dma(bm, is_read ? IDE_DMA_READ : IDE_DMA_WRITE);
        }
    } else if (error_status & BM_STATUS_PIO_RETRY) {
        if (is_read) {
            ide_sector_read(bmdma_active_if(bm));
        } else {
            ide_sector_write(bmdma_active_if(bm));
        }
    } else if (error_status & BM_STATUS_RETRY_FLUSH) {
        ide_flush_cache(bmdma_active_if(bm));
    }
}

static void bmdma_restart_cb(void *opaque, int running, RunState state)
{
    IDEDMA *dma = opaque;
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);

    if (!running)
        return;

    if (!bm->bh) {
        bm->bh = qemu_bh_new(bmdma_restart_bh, &bm->dma);
        qemu_bh_schedule(bm->bh);
    }
}

static void bmdma_cancel(BMDMAState *bm)
{
    if (bm->status & BM_STATUS_DMAING) {
        /* cancel DMA request */
        bmdma_set_inactive(&bm->dma);
    }
}

static int bmdma_reset(IDEDMA *dma)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);

#ifdef DEBUG_IDE
    printf("ide: dma_reset\n");
#endif
    bmdma_cancel(bm);
    bm->cmd = 0;
    bm->status = 0;
    bm->addr = 0;
    bm->cur_addr = 0;
    bm->cur_prd_last = 0;
    bm->cur_prd_addr = 0;
    bm->cur_prd_len = 0;
    bm->sector_num = 0;
    bm->nsector = 0;

    return 0;
}

static int bmdma_start_transfer(IDEDMA *dma)
{
    return 0;
}

static void bmdma_irq(void *opaque, int n, int level)
{
    BMDMAState *bm = opaque;

    if (!level) {
        /* pass through lower */
        qemu_set_irq(bm->irq, level);
        return;
    }

    bm->status |= BM_STATUS_INT;

    /* trigger the real irq */
    qemu_set_irq(bm->irq, level);
}

void bmdma_cmd_writeb(BMDMAState *bm, uint32_t val)
{
#ifdef DEBUG_IDE
    printf("%s: 0x%08x\n", __func__, val);
#endif

    /* Ignore writes to SSBM if it keeps the old value */
    if ((val & BM_CMD_START) != (bm->cmd & BM_CMD_START)) {
        if (!(val & BM_CMD_START)) {
            /*
             * We can't cancel Scatter Gather DMA in the middle of the
             * operation or a partial (not full) DMA transfer would reach
             * the storage so we wait for completion instead (we beahve
             * like if the DMA was completed by the time the guest trying
             * to cancel dma with bmdma_cmd_writeb with BM_CMD_START not
             * set).
             *
             * In the future we'll be able to safely cancel the I/O if the
             * whole DMA operation will be submitted to disk with a single
             * aio operation with preadv/pwritev.
             */
            if (bm->bus->dma->aiocb) {
                qemu_aio_flush();
                assert(bm->bus->dma->aiocb == NULL);
                assert((bm->status & BM_STATUS_DMAING) == 0);
            }
        } else {
            bm->cur_addr = bm->addr;
            if (!(bm->status & BM_STATUS_DMAING)) {
                bm->status |= BM_STATUS_DMAING;
                /* start dma transfer if possible */
                if (bm->dma_cb)
                    bm->dma_cb(bmdma_active_if(bm), 0);
            }
        }
    }

    bm->cmd = val & 0x09;
}

static uint64_t bmdma_addr_read(void *opaque, dma_addr_t addr,
                                unsigned width)
{
    BMDMAState *bm = opaque;
    uint32_t mask = (1ULL << (width * 8)) - 1;
    uint64_t data;

    data = (bm->addr >> (addr * 8)) & mask;
#ifdef DEBUG_IDE
    printf("%s: 0x%08x\n", __func__, (unsigned)*data);
#endif
    return data;
}

static void bmdma_addr_write(void *opaque, dma_addr_t addr,
                             uint64_t data, unsigned width)
{
    BMDMAState *bm = opaque;
    int shift = addr * 8;
    uint32_t mask = (1ULL << (width * 8)) - 1;

#ifdef DEBUG_IDE
    printf("%s: 0x%08x\n", __func__, (unsigned)data);
#endif
    bm->addr &= ~(mask << shift);
    bm->addr |= ((data & mask) << shift) & ~3;
}

MemoryRegionOps bmdma_addr_ioport_ops = {
    .read = bmdma_addr_read,
    .write = bmdma_addr_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

void pci_ide_create_devs(PCIDevice *dev, DriveInfo **hd_table)
{
    PCIIDEState *d = DO_UPCAST(PCIIDEState, dev, dev);
    static const int bus[4]  = { 0, 0, 1, 1 };
    static const int unit[4] = { 0, 1, 0, 1 };
    int i;

    for (i = 0; i < 4; i++) {
        if (hd_table[i] == NULL)
            continue;
        ide_create_drive(d->bus+bus[i], unit[i], hd_table[i]);
    }
}

static const struct IDEDMAOps bmdma_ops = {
    .start_dma = bmdma_start_dma,
    .start_transfer = bmdma_start_transfer,
    .prepare_buf = bmdma_prepare_buf,
    .rw_buf = bmdma_rw_buf,
    .set_unit = bmdma_set_unit,
    .add_status = bmdma_add_status,
    .set_inactive = bmdma_set_inactive,
    .restart_cb = bmdma_restart_cb,
    .reset = bmdma_reset,
};

void bmdma_init(IDEBus *bus, BMDMAState *bm, PCIIDEState *d)
{
    qemu_irq *irq;

    if (bus->dma == &bm->dma) {
        return;
    }

    bm->dma.ops = &bmdma_ops;
    bus->dma = &bm->dma;
    bm->irq = bus->irq;
    irq = qemu_allocate_irqs(bmdma_irq, bm, 1);
    bus->irq = *irq;
    bm->pci_dev = d;
}