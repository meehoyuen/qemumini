#include "qemu-common.h"
#include "qemu-queue.h"
#include "main-loop.h"
#include <sys/wait.h>

#include "ioport.h"
#include "memory.h"

/***********************************************************/
/* IO Port */

//#define DEBUG_UNUSED_IOPORT
//#define DEBUG_IOPORT

#ifdef DEBUG_UNUSED_IOPORT
#  define LOG_UNUSED_IOPORT(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#  define LOG_UNUSED_IOPORT(fmt, ...) do{ } while (0)
#endif


/* XXX: use a two level table to limit memory usage */

static void *ioport_opaque[MAX_IOPORTS];
static IOPortReadFunc *ioport_read_table[3][MAX_IOPORTS];
static IOPortWriteFunc *ioport_write_table[3][MAX_IOPORTS];

static IOPortReadFunc default_ioport_readb, default_ioport_readw, default_ioport_readl;
static IOPortWriteFunc default_ioport_writeb, default_ioport_writew, default_ioport_writel;

static uint32_t ioport_read(int index, uint32_t address)
{
    static IOPortReadFunc * const default_func[3] = {
        default_ioport_readb,
        default_ioport_readw,
        default_ioport_readl
    };
    IOPortReadFunc *func = ioport_read_table[index][address];
    if (!func)
        func = default_func[index];
    return func(ioport_opaque[address], address);
}

static void ioport_write(int index, uint32_t address, uint32_t data)
{
    static IOPortWriteFunc * const default_func[3] = {
        default_ioport_writeb,
        default_ioport_writew,
        default_ioport_writel
    };
    IOPortWriteFunc *func = ioport_write_table[index][address];
    if (!func)
        func = default_func[index];
    func(ioport_opaque[address], address, data);
}

static uint32_t default_ioport_readb(void *opaque, uint32_t address)
{
    LOG_UNUSED_IOPORT("unused inb: port=0x%04"PRIx32"\n", address);
    return 0xff;
}

static void default_ioport_writeb(void *opaque, uint32_t address, uint32_t data)
{
    LOG_UNUSED_IOPORT("unused outb: port=0x%04"PRIx32" data=0x%02"PRIx32"\n",
                      address, data);
}

/* default is to make two byte accesses */
static uint32_t default_ioport_readw(void *opaque, uint32_t address)
{
    uint32_t data;
    data = ioport_read(0, address);
    address = (address + 1) & IOPORTS_MASK;
    data |= ioport_read(0, address) << 8;
    return data;
}

static void default_ioport_writew(void *opaque, uint32_t address, uint32_t data)
{
    ioport_write(0, address, data & 0xff);
    address = (address + 1) & IOPORTS_MASK;
    ioport_write(0, address, (data >> 8) & 0xff);
}

static uint32_t default_ioport_readl(void *opaque, uint32_t address)
{
    LOG_UNUSED_IOPORT("unused inl: port=0x%04"PRIx32"\n", address);
    return 0xffffffff;
}

static void default_ioport_writel(void *opaque, uint32_t address, uint32_t data)
{
    LOG_UNUSED_IOPORT("unused outl: port=0x%04"PRIx32" data=0x%02"PRIx32"\n",
                      address, data);
}

static int ioport_bsize(int size, int *bsize)
{
    if (size == 1) {
        *bsize = 0;
    } else if (size == 2) {
        *bsize = 1;
    } else if (size == 4) {
        *bsize = 2;
    } else {
        return -1;
    }
    return 0;
}

/* size is the word size in byte */
int register_ioport_read(pio_addr_t start, int length, int size,
                         IOPortReadFunc *func, void *opaque)
{
    int i, bsize;

    if (ioport_bsize(size, &bsize)) {
        hw_error("register_ioport_read: invalid size");
        return -1;
    }
    for(i = start; i < start + length; ++i) {
        ioport_read_table[bsize][i] = func;
        if (ioport_opaque[i] != NULL && ioport_opaque[i] != opaque)
            hw_error("register_ioport_read: invalid opaque for address 0x%x",
                     i);
        ioport_opaque[i] = opaque;
    }
    return 0;
}

/* size is the word size in byte */
int register_ioport_write(pio_addr_t start, int length, int size,
                          IOPortWriteFunc *func, void *opaque)
{
    int i, bsize;

    if (ioport_bsize(size, &bsize)) {
        hw_error("register_ioport_write: invalid size");
        return -1;
    }
    for(i = start; i < start + length; ++i) {
        ioport_write_table[bsize][i] = func;
        if (ioport_opaque[i] != NULL && ioport_opaque[i] != opaque)
            hw_error("register_ioport_write: invalid opaque for address 0x%x",
                     i);
        ioport_opaque[i] = opaque;
    }
    return 0;
}

static uint32_t ioport_readb_thunk(void *opaque, uint32_t addr)
{
    IORange *ioport = opaque;
    uint64_t data;

    ioport->ops->read(ioport, addr - ioport->base, 1, &data);
    return data;
}

static uint32_t ioport_readw_thunk(void *opaque, uint32_t addr)
{
    IORange *ioport = opaque;
    uint64_t data;

    ioport->ops->read(ioport, addr - ioport->base, 2, &data);
    return data;
}

static uint32_t ioport_readl_thunk(void *opaque, uint32_t addr)
{
    IORange *ioport = opaque;
    uint64_t data;

    ioport->ops->read(ioport, addr - ioport->base, 4, &data);
    return data;
}

static void ioport_writeb_thunk(void *opaque, uint32_t addr, uint32_t data)
{
    IORange *ioport = opaque;

    ioport->ops->write(ioport, addr - ioport->base, 1, data);
}

static void ioport_writew_thunk(void *opaque, uint32_t addr, uint32_t data)
{
    IORange *ioport = opaque;

    ioport->ops->write(ioport, addr - ioport->base, 2, data);
}

static void ioport_writel_thunk(void *opaque, uint32_t addr, uint32_t data)
{
    IORange *ioport = opaque;

    ioport->ops->write(ioport, addr - ioport->base, 4, data);
}

void ioport_register(IORange *ioport)
{
    register_ioport_read(ioport->base, ioport->len, 1,
                         ioport_readb_thunk, ioport);
    register_ioport_read(ioport->base, ioport->len, 2,
                         ioport_readw_thunk, ioport);
    register_ioport_read(ioport->base, ioport->len, 4,
                         ioport_readl_thunk, ioport);
    register_ioport_write(ioport->base, ioport->len, 1,
                          ioport_writeb_thunk, ioport);
    register_ioport_write(ioport->base, ioport->len, 2,
                          ioport_writew_thunk, ioport);
    register_ioport_write(ioport->base, ioport->len, 4,
                          ioport_writel_thunk, ioport);
}

void isa_unassign_ioport(pio_addr_t start, int length)
{
    int i;

    for(i = start; i < start + length; i++) {
        ioport_read_table[0][i] = NULL;
        ioport_read_table[1][i] = NULL;
        ioport_read_table[2][i] = NULL;

        ioport_write_table[0][i] = NULL;
        ioport_write_table[1][i] = NULL;
        ioport_write_table[2][i] = NULL;

        ioport_opaque[i] = NULL;
    }
}

bool isa_is_ioport_assigned(pio_addr_t start)
{
    return (ioport_read_table[0][start] || ioport_write_table[0][start] ||
	    ioport_read_table[1][start] || ioport_write_table[1][start] ||
	    ioport_read_table[2][start] || ioport_write_table[2][start]);
}

/***********************************************************/

void cpu_outb(pio_addr_t addr, uint8_t val)
{
    ioport_write(0, addr, val);
}

void cpu_outw(pio_addr_t addr, uint16_t val)
{
    ioport_write(1, addr, val);
}

void cpu_outl(pio_addr_t addr, uint32_t val)
{
    ioport_write(2, addr, val);
}

uint8_t cpu_inb(pio_addr_t addr)
{
    uint8_t val;
    val = ioport_read(0, addr);
    return val;
}

uint16_t cpu_inw(pio_addr_t addr)
{
    uint16_t val;
    val = ioport_read(1, addr);
    return val;
}

uint32_t cpu_inl(pio_addr_t addr)
{
    uint32_t val;
    val = ioport_read(2, addr);
    return val;
}

void portio_list_init(PortioList *piolist,
                      const MemoryRegionPortio *callbacks,
                      void *opaque, const char *name)
{
    unsigned n = 0;

    while (callbacks[n].size) {
        ++n;
    }

    piolist->ports = callbacks;
    piolist->nr = 0;
    piolist->regions = (MemoryRegion**)malloc(sizeof(MemoryRegion *)*n);
    piolist->address_space = NULL;
    piolist->opaque = opaque;
    piolist->name = name;
}

void portio_list_destroy(PortioList *piolist)
{
    free(piolist->regions);
    piolist->regions = NULL;
}

static void portio_list_add_1(PortioList *piolist,
                              const MemoryRegionPortio *pio_init,
                              unsigned count, unsigned start,
                              unsigned off_low, unsigned off_high)
{
    MemoryRegionPortio *pio;
    MemoryRegionOps *ops;
    MemoryRegion *region;
    unsigned i;

    /* Copy the sub-list and null-terminate it.  */
    pio = (MemoryRegionPortio *)malloc(sizeof(MemoryRegionPortio)*(count + 1));
    memcpy(pio, pio_init, sizeof(MemoryRegionPortio) * count);
    memset(pio + count, 0, sizeof(MemoryRegionPortio));

    /* Adjust the offsets to all be zero-based for the region.  */
    for (i = 0; i < count; ++i) {
        pio[i].offset -= off_low;
    }

    ops = (MemoryRegionOps *)malloc(sizeof(MemoryRegionOps));
    ops->old_portio = pio;

    region = (MemoryRegion *)malloc(sizeof(MemoryRegion));
    memory_region_init_io(region, ops, piolist->opaque, piolist->name,
                          off_high - off_low);
    memory_region_set_offset(region, start + off_low);
    memory_region_add_subregion(piolist->address_space,
                                start + off_low, region);
    piolist->regions[piolist->nr++] = region;
}

void portio_list_add(PortioList *piolist,
                     MemoryRegion *address_space,
                     uint32_t start)
{
    const MemoryRegionPortio *pio, *pio_start = piolist->ports;
    unsigned int off_low, off_high, off_last, count;

    piolist->address_space = address_space;

    /* Handle the first entry specially.  */
    off_last = off_low = pio_start->offset;
    off_high = off_low + pio_start->len;
    count = 1;

    for (pio = pio_start + 1; pio->size != 0; pio++, count++) {
        /* All entries must be sorted by offset.  */
        assert(pio->offset >= off_last);
        off_last = pio->offset;

        /* If we see a hole, break the region.  */
        if (off_last > off_high) {
            portio_list_add_1(piolist, pio_start, count, start, off_low,
                              off_high);
            /* ... and start collecting anew.  */
            pio_start = pio;
            off_low = off_last;
            off_high = off_low + pio->len;
            count = 0;
        } else if (off_last + pio->len > off_high) {
            off_high = off_last + pio->len;
        }
    }

    /* There will always be an open sub-list.  */
    portio_list_add_1(piolist, pio_start, count, start, off_low, off_high);
}

void portio_list_del(PortioList *piolist)
{
    MemoryRegion *mr;
    unsigned i;

    for (i = 0; i < piolist->nr; ++i) {
        mr = piolist->regions[i];
        memory_region_del_subregion(piolist->address_space, mr);
        memory_region_destroy(mr);
        free((MemoryRegionOps *)mr->ops);
        mr->ops = NULL;
        free(mr);
        mr = NULL;
        piolist->regions[i] = NULL;
    }
}

typedef struct IOHandlerRecord {
    int fd;
    IOCanReadHandler *fd_read_poll;
    IOHandler *fd_read;
    IOHandler *fd_write;
    int deleted;
    void *opaque;
    QLIST_ENTRY(IOHandlerRecord) next;
} IOHandlerRecord;

static QLIST_HEAD(, IOHandlerRecord) io_handlers =
    QLIST_HEAD_INITIALIZER(io_handlers);


/* XXX: fd_read_poll should be suppressed, but an API change is
   necessary in the character devices to suppress fd_can_read(). */
int qemu_set_fd_handler2(int fd,
                         IOCanReadHandler *fd_read_poll,
                         IOHandler *fd_read,
                         IOHandler *fd_write,
                         void *opaque)
{
    IOHandlerRecord *ioh;

    if (!fd_read && !fd_write) {
        QLIST_FOREACH(ioh, &io_handlers, next) {
            if (ioh->fd == fd) {
                ioh->deleted = 1;
                break;
            }
        }
    } else {
        QLIST_FOREACH(ioh, &io_handlers, next) {
            if (ioh->fd == fd)
                goto found;
        }
        ioh = calloc(1, sizeof(IOHandlerRecord));
        QLIST_INSERT_HEAD(&io_handlers, ioh, next);
    found:
        ioh->fd = fd;
        ioh->fd_read_poll = fd_read_poll;
        ioh->fd_read = fd_read;
        ioh->fd_write = fd_write;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }
    return 0;
}

int qemu_set_fd_handler(int fd,
                        IOHandler *fd_read,
                        IOHandler *fd_write,
                        void *opaque)
{
    return qemu_set_fd_handler2(fd, NULL, fd_read, fd_write, opaque);
}

void qemu_iohandler_fill(int *pnfds, fd_set *readfds, fd_set *writefds, fd_set *xfds)
{
    IOHandlerRecord *ioh;

    QLIST_FOREACH(ioh, &io_handlers, next) {
        if (ioh->deleted)
            continue;
        if (ioh->fd_read &&
            (!ioh->fd_read_poll ||
             ioh->fd_read_poll(ioh->opaque) != 0)) {
            FD_SET(ioh->fd, readfds);
            if (ioh->fd > *pnfds)
                *pnfds = ioh->fd;
        }
        if (ioh->fd_write) {
            FD_SET(ioh->fd, writefds);
            if (ioh->fd > *pnfds)
                *pnfds = ioh->fd;
        }
    }
}

void qemu_iohandler_poll(fd_set *readfds, fd_set *writefds, fd_set *xfds, int ret)
{
    if (ret > 0) {
        IOHandlerRecord *pioh, *ioh;

        QLIST_FOREACH_SAFE(ioh, &io_handlers, next, pioh) {
            if (!ioh->deleted && ioh->fd_read && FD_ISSET(ioh->fd, readfds)) {
                ioh->fd_read(ioh->opaque);
            }
            if (!ioh->deleted && ioh->fd_write && FD_ISSET(ioh->fd, writefds)) {
                ioh->fd_write(ioh->opaque);
            }

            /* Do this last in case read/write handlers marked it for deletion */
            if (ioh->deleted) {
                QLIST_REMOVE(ioh, next);
                free(ioh);
                ioh = NULL;
            }
        }
    }
}

/* reaping of zombies.  right now we're not passing the status to
   anyone, but it would be possible to add a callback.  */
typedef struct ChildProcessRecord {
    int pid;
    QLIST_ENTRY(ChildProcessRecord) next;
} ChildProcessRecord;

static QLIST_HEAD(, ChildProcessRecord) child_watches =
    QLIST_HEAD_INITIALIZER(child_watches);

static QEMUBH *sigchld_bh;

static void sigchld_handler(int signal)
{
    qemu_bh_schedule(sigchld_bh);
}

static void sigchld_bh_handler(void *opaque)
{
    ChildProcessRecord *rec, *next;

    QLIST_FOREACH_SAFE(rec, &child_watches, next, next) {
        if (waitpid(rec->pid, NULL, WNOHANG) == rec->pid) {
            QLIST_REMOVE(rec, next);
            free(rec);
            rec = NULL;
        }
    }
}

static void qemu_init_child_watch(void)
{
    struct sigaction act;
    sigchld_bh = qemu_bh_new(sigchld_bh_handler, NULL);

    act.sa_handler = sigchld_handler;
    act.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &act, NULL);
}

int qemu_add_child_watch(pid_t pid)
{
    ChildProcessRecord *rec;

    if (!sigchld_bh) {
        qemu_init_child_watch();
    }

    QLIST_FOREACH(rec, &child_watches, next) {
        if (rec->pid == pid) {
            return 1;
        }
    }
    rec = calloc(1, sizeof(ChildProcessRecord));
    rec->pid = pid;
    QLIST_INSERT_HEAD(&child_watches, rec, next);
    return 0;
}
