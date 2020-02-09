/*
 * QEMU USB emulation
 */
#include "qemu-common.h"
#include "cpu-common.h"
#include "usb.h"
#include "dma.h"
#include "hw.h"
#include "qdev.h"
#include "sysemu.h"
#include "console.h"
#include "hid.h"
#include "pci.h"
#include "qemu-timer.h"

#include <inttypes.h>

struct USBDescID {
    uint16_t                  idVendor;
    uint16_t                  idProduct;
    uint16_t                  bcdDevice;
    uint8_t                   iManufacturer;
    uint8_t                   iProduct;
    uint8_t                   iSerialNumber;
};

struct USBDescDevice {
    uint16_t                  bcdUSB;
    uint8_t                   bDeviceClass;
    uint8_t                   bDeviceSubClass;
    uint8_t                   bDeviceProtocol;
    uint8_t                   bMaxPacketSize0;
    uint8_t                   bNumConfigurations;

    const USBDescConfig       *confs;
};

struct USBDescConfig {
    uint8_t                   bNumInterfaces;
    uint8_t                   bConfigurationValue;
    uint8_t                   iConfiguration;
    uint8_t                   bmAttributes;
    uint8_t                   bMaxPower;

    /* grouped interfaces */
    uint8_t                   nif_groups;
    const USBDescIfaceAssoc   *if_groups;

    /* "normal" interfaces */
    uint8_t                   nif;
    const USBDescIface        *ifs;
};

/* conceptually an Interface Association Descriptor, and releated interfaces */
struct USBDescIfaceAssoc {
    uint8_t                   bFirstInterface;
    uint8_t                   bInterfaceCount;
    uint8_t                   bFunctionClass;
    uint8_t                   bFunctionSubClass;
    uint8_t                   bFunctionProtocol;
    uint8_t                   iFunction;

    uint8_t                   nif;
    const USBDescIface        *ifs;
};

struct USBDescIface {
    uint8_t                   bInterfaceNumber;
    uint8_t                   bAlternateSetting;
    uint8_t                   bNumEndpoints;
    uint8_t                   bInterfaceClass;
    uint8_t                   bInterfaceSubClass;
    uint8_t                   bInterfaceProtocol;
    uint8_t                   iInterface;

    uint8_t                   ndesc;
    USBDescOther              *descs;
    USBDescEndpoint           *eps;
};

struct USBDescEndpoint {
    uint8_t                   bEndpointAddress;
    uint8_t                   bmAttributes;
    uint16_t                  wMaxPacketSize;
    uint8_t                   bInterval;
};

struct USBDescOther {
    uint8_t                   length;
    const uint8_t             *data;
};

typedef const char *USBDescStrings[256];

struct USBDesc {
    USBDescID                 id;
    const USBDescDevice       *full;
    const USBDescDevice       *high;
    const char* const         *str;
};

/* generate usb packages from structs */
int usb_desc_device(const USBDescID *id, const USBDescDevice *dev,
                    uint8_t *dest, size_t len);
int usb_desc_device_qualifier(const USBDescDevice *dev,
                              uint8_t *dest, size_t len);
int usb_desc_config(const USBDescConfig *conf, uint8_t *dest, size_t len);
int usb_desc_iface_group(const USBDescIfaceAssoc *iad, uint8_t *dest,
                         size_t len);
int usb_desc_iface(const USBDescIface *iface, uint8_t *dest, size_t len);
int usb_desc_endpoint(const USBDescEndpoint *ep, uint8_t *dest, size_t len);
int usb_desc_other(const USBDescOther *desc, uint8_t *dest, size_t len);

/* control message emulation helpers */
void usb_desc_init(USBDevice *dev);
void usb_desc_attach(USBDevice *dev);
void usb_desc_set_string(USBDevice *dev, uint8_t index, const char *str);
const char *usb_desc_get_string(USBDevice *dev, uint8_t index);
int usb_desc_string(USBDevice *dev, int index, uint8_t *dest, size_t len);
int usb_desc_get_descriptor(USBDevice *dev, int value, uint8_t *dest, size_t len);
int usb_desc_handle_control(USBDevice *dev, USBPacket *p,
        int request, int value, int index, int length, uint8_t *data);

//#define DEBUG
//#define DEBUG_DUMP_DATA

size_t iov_from_buf(struct iovec *iov, unsigned int iov_cnt,
                    const void *buf, size_t iov_off, size_t size)
{
    size_t iovec_off, buf_off;
    unsigned int i;

    iovec_off = 0;
    buf_off = 0;
    for (i = 0; i < iov_cnt && size; i++) {
        if (iov_off < (iovec_off + iov[i].iov_len)) {
            size_t len = MIN((iovec_off + iov[i].iov_len) - iov_off, size);

            memcpy(iov[i].iov_base + (iov_off - iovec_off), buf + buf_off, len);

            buf_off += len;
            iov_off += len;
            size -= len;
        }
        iovec_off += iov[i].iov_len;
    }
    return buf_off;
}

size_t iov_to_buf(const struct iovec *iov, const unsigned int iov_cnt,
                  void *buf, size_t iov_off, size_t size)
{
    uint8_t *ptr;
    size_t iovec_off, buf_off;
    unsigned int i;

    ptr = buf;
    iovec_off = 0;
    buf_off = 0;
    for (i = 0; i < iov_cnt && size; i++) {
        if (iov_off < (iovec_off + iov[i].iov_len)) {
            size_t len = MIN((iovec_off + iov[i].iov_len) - iov_off , size);

            memcpy(ptr + buf_off, iov[i].iov_base + (iov_off - iovec_off), len);

            buf_off += len;
            iov_off += len;
            size -= len;
        }
        iovec_off += iov[i].iov_len;
    }
    return buf_off;
}

size_t iov_clear(const struct iovec *iov, const unsigned int iov_cnt,
                 size_t iov_off, size_t size)
{
    size_t iovec_off, buf_off;
    unsigned int i;

    iovec_off = 0;
    buf_off = 0;
    for (i = 0; i < iov_cnt && size; i++) {
        if (iov_off < (iovec_off + iov[i].iov_len)) {
            size_t len = MIN((iovec_off + iov[i].iov_len) - iov_off , size);

            memset(iov[i].iov_base + (iov_off - iovec_off), 0, len);

            buf_off += len;
            iov_off += len;
            size -= len;
        }
        iovec_off += iov[i].iov_len;
    }
    return buf_off;
}

size_t iov_size(const struct iovec *iov, const unsigned int iov_cnt)
{
    size_t len;
    unsigned int i;

    len = 0;
    for (i = 0; i < iov_cnt; i++) {
        len += iov[i].iov_len;
    }
    return len;
}

void iov_hexdump(const struct iovec *iov, const unsigned int iov_cnt,
                 FILE *fp, const char *prefix, size_t limit)
{
    unsigned int i, v, b;
    uint8_t *c;

    c = iov[0].iov_base;
    for (i = 0, v = 0, b = 0; b < limit; i++, b++) {
        if (i == iov[v].iov_len) {
            i = 0; v++;
            if (v == iov_cnt) {
                break;
            }
            c = iov[v].iov_base;
        }
        if ((b % 16) == 0) {
            fprintf(fp, "%s: %04x:", prefix, b);
        }
        if ((b % 4) == 0) {
            fprintf(fp, " ");
        }
        fprintf(fp, " %02x", c[i]);
        if ((b % 16) == 15) {
            fprintf(fp, "\n");
        }
    }
    if ((b % 16) != 0) {
        fprintf(fp, "\n");
    }
}

void usb_attach(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    assert(dev->attached);
    assert(dev->state == USB_STATE_NOTATTACHED);
    port->ops->attach(port);
    usb_send_msg(dev, USB_MSG_ATTACH);
}

void usb_detach(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    assert(dev->state != USB_STATE_NOTATTACHED);
    port->ops->detach(port);
    usb_send_msg(dev, USB_MSG_DETACH);
}

void usb_reset(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    usb_detach(port);
    usb_attach(port);
    usb_send_msg(dev, USB_MSG_RESET);
}

void usb_wakeup(USBDevice *dev)
{
    if (dev->remote_wakeup && dev->port && dev->port->ops->wakeup) {
        dev->port->ops->wakeup(dev->port);
    }
}

/**********************/

/* generic USB device helpers (you are not forced to use them when
   writing your USB device driver, but they help handling the
   protocol)
*/
#define SETUP_STATE_IDLE  0
#define SETUP_STATE_SETUP 1
#define SETUP_STATE_DATA  2
#define SETUP_STATE_ACK   3

static int do_token_setup(USBDevice *s, USBPacket *p)
{
    int request, value, index;
    int ret = 0;

    if (p->iov.size != 8) {
        return USB_RET_STALL;
    }

    usb_packet_copy(p, s->setup_buf, p->iov.size);
    s->setup_len   = (s->setup_buf[7] << 8) | s->setup_buf[6];
    s->setup_index = 0;

    request = (s->setup_buf[0] << 8) | s->setup_buf[1];
    value   = (s->setup_buf[3] << 8) | s->setup_buf[2];
    index   = (s->setup_buf[5] << 8) | s->setup_buf[4];

    if (s->setup_buf[0] & USB_DIR_IN) {
        ret = s->info->handle_control(s, p, request, value, index,
                                      s->setup_len, s->data_buf);
        if (ret == USB_RET_ASYNC) {
             s->setup_state = SETUP_STATE_SETUP;
             return USB_RET_ASYNC;
        }
        if (ret < 0)
            return ret;

        if (ret < s->setup_len)
            s->setup_len = ret;
        s->setup_state = SETUP_STATE_DATA;
    } else {
        if (s->setup_len > sizeof(s->data_buf)) {
            fprintf(stderr,
                "usb_generic_handle_packet: ctrl buffer too small (%d > %zu)\n",
                s->setup_len, sizeof(s->data_buf));
            return USB_RET_STALL;
        }
        if (s->setup_len == 0)
            s->setup_state = SETUP_STATE_ACK;
        else
            s->setup_state = SETUP_STATE_DATA;
    }

    return ret;
}

static int do_token_in(USBDevice *s, USBPacket *p)
{
    int request, value, index;
    int ret = 0;

    if (p->devep != 0)
        return s->info->handle_data(s, p);

    request = (s->setup_buf[0] << 8) | s->setup_buf[1];
    value   = (s->setup_buf[3] << 8) | s->setup_buf[2];
    index   = (s->setup_buf[5] << 8) | s->setup_buf[4];
 
    switch(s->setup_state) {
    case SETUP_STATE_ACK:
        if (!(s->setup_buf[0] & USB_DIR_IN)) {
            ret = s->info->handle_control(s, p, request, value, index,
                                          s->setup_len, s->data_buf);
            if (ret == USB_RET_ASYNC) {
                return USB_RET_ASYNC;
            }
            s->setup_state = SETUP_STATE_IDLE;
            if (ret > 0)
                return 0;
            return ret;
        }

        /* return 0 byte */
        return 0;

    case SETUP_STATE_DATA:
        if (s->setup_buf[0] & USB_DIR_IN) {
            int len = s->setup_len - s->setup_index;
            if (len > p->iov.size) {
                len = p->iov.size;
            }
            usb_packet_copy(p, s->data_buf + s->setup_index, len);
            s->setup_index += len;
            if (s->setup_index >= s->setup_len)
                s->setup_state = SETUP_STATE_ACK;
            return len;
        }

        s->setup_state = SETUP_STATE_IDLE;
        return USB_RET_STALL;

    default:
        return USB_RET_STALL;
    }
}

static int do_token_out(USBDevice *s, USBPacket *p)
{
    if (p->devep != 0)
        return s->info->handle_data(s, p);

    switch(s->setup_state) {
    case SETUP_STATE_ACK:
        if (s->setup_buf[0] & USB_DIR_IN) {
            s->setup_state = SETUP_STATE_IDLE;
            /* transfer OK */
        } else {
            /* ignore additional output */
        }
        return 0;

    case SETUP_STATE_DATA:
        if (!(s->setup_buf[0] & USB_DIR_IN)) {
            int len = s->setup_len - s->setup_index;
            if (len > p->iov.size) {
                len = p->iov.size;
            }
            usb_packet_copy(p, s->data_buf + s->setup_index, len);
            s->setup_index += len;
            if (s->setup_index >= s->setup_len)
                s->setup_state = SETUP_STATE_ACK;
            return len;
        }

        s->setup_state = SETUP_STATE_IDLE;
        return USB_RET_STALL;

    default:
        return USB_RET_STALL;
    }
}

/*
 * Generic packet handler.
 * Called by the HC (host controller).
 *
 * Returns length of the transaction or one of the USB_RET_XXX codes.
 */
int usb_generic_handle_packet(USBDevice *s, USBPacket *p)
{
    switch(p->pid) {
    case USB_MSG_ATTACH:
        s->state = USB_STATE_ATTACHED;
        if (s->info->handle_attach) {
            s->info->handle_attach(s);
        }
        return 0;

    case USB_MSG_DETACH:
        s->state = USB_STATE_NOTATTACHED;
        return 0;

    case USB_MSG_RESET:
        s->remote_wakeup = 0;
        s->addr = 0;
        s->state = USB_STATE_DEFAULT;
        if (s->info->handle_reset) {
            s->info->handle_reset(s);
        }
        return 0;
    }

    /* Rest of the PIDs must match our address */
    if (s->state < USB_STATE_DEFAULT || p->devaddr != s->addr)
        return USB_RET_NODEV;

    switch (p->pid) {
    case USB_TOKEN_SETUP:
        return do_token_setup(s, p);

    case USB_TOKEN_IN:
        return do_token_in(s, p);

    case USB_TOKEN_OUT:
        return do_token_out(s, p);
 
    default:
        return USB_RET_STALL;
    }
}

/* ctrl complete function for devices which use usb_generic_handle_packet and
   may return USB_RET_ASYNC from their handle_control callback. Device code
   which does this *must* call this function instead of the normal
   usb_packet_complete to complete their async control packets. */
void usb_generic_async_ctrl_complete(USBDevice *s, USBPacket *p)
{
    if (p->result < 0) {
        s->setup_state = SETUP_STATE_IDLE;
    }

    switch (s->setup_state) {
    case SETUP_STATE_SETUP:
        if (p->result < s->setup_len) {
            s->setup_len = p->result;
        }
        s->setup_state = SETUP_STATE_DATA;
        p->result = 8;
        break;

    case SETUP_STATE_ACK:
        s->setup_state = SETUP_STATE_IDLE;
        p->result = 0;
        break;

    default:
        break;
    }
    usb_packet_complete(s, p);
}

/* XXX: fix overflow */
int set_usb_string(uint8_t *buf, const char *str)
{
    int len, i;
    uint8_t *q;

    q = buf;
    len = strlen(str);
    *q++ = 2 * len + 2;
    *q++ = 3;
    for(i = 0; i < len; i++) {
        *q++ = str[i];
        *q++ = 0;
    }
    return q - buf;
}

/* Send an internal message to a USB device.  */
void usb_send_msg(USBDevice *dev, int msg)
{
    USBPacket p;
    int ret;

    memset(&p, 0, sizeof(p));
    p.pid = msg;
    ret = usb_handle_packet(dev, &p);
    /* This _must_ be synchronous */
    assert(ret != USB_RET_ASYNC);
}

/* Hand over a packet to a device for processing.  Return value
   USB_RET_ASYNC indicates the processing isn't finished yet, the
   driver will call usb_packet_complete() when done processing it. */
int usb_handle_packet(USBDevice *dev, USBPacket *p)
{
    int ret;

    assert(p->owner == NULL);
    ret = dev->info->handle_packet(dev, p);
    if (ret == USB_RET_ASYNC) {
        if (p->owner == NULL) {
            p->owner = dev;
        } else {
            /* We'll end up here when usb_handle_packet is called
             * recursively due to a hub being in the chain.  Nothing
             * to do.  Leave p->owner pointing to the device, not the
             * hub. */;
        }
    }
    return ret;
}

/* Notify the controller that an async packet is complete.  This should only
   be called for packets previously deferred by returning USB_RET_ASYNC from
   handle_packet. */
void usb_packet_complete(USBDevice *dev, USBPacket *p)
{
    /* Note: p->owner != dev is possible in case dev is a hub */
    assert(p->owner != NULL);
    p->owner = NULL;
    dev->port->ops->complete(dev->port, p);
}

/* Cancel an active packet.  The packed must have been deferred by
   returning USB_RET_ASYNC from handle_packet, and not yet
   completed.  */
void usb_cancel_packet(USBPacket * p)
{
    assert(p->owner != NULL);
    p->owner->info->cancel_packet(p->owner, p);
    p->owner = NULL;
}


void usb_packet_init(USBPacket *p)
{
    qemu_iovec_init(&p->iov, 1);
}

void usb_packet_setup(USBPacket *p, int pid, uint8_t addr, uint8_t ep)
{
    p->pid = pid;
    p->devaddr = addr;
    p->devep = ep;
    p->result = 0;
    qemu_iovec_reset(&p->iov);
}

void usb_packet_addbuf(USBPacket *p, void *ptr, size_t len)
{
    qemu_iovec_add(&p->iov, ptr, len);
}

void usb_packet_copy(USBPacket *p, void *ptr, size_t bytes)
{
    assert(p->result >= 0);
    assert(p->result + bytes <= p->iov.size);
    switch (p->pid) {
    case USB_TOKEN_SETUP:
    case USB_TOKEN_OUT:
        iov_to_buf(p->iov.iov, p->iov.niov, ptr, p->result, bytes);
        break;
    case USB_TOKEN_IN:
        iov_from_buf(p->iov.iov, p->iov.niov, ptr, p->result, bytes);
        break;
    default:
        fprintf(stderr, "%s: invalid pid: %x\n", __func__, p->pid);
        abort();
    }
    p->result += bytes;
}

void usb_packet_skip(USBPacket *p, size_t bytes)
{
    assert(p->result >= 0);
    assert(p->result + bytes <= p->iov.size);
    if (p->pid == USB_TOKEN_IN) {
        iov_clear(p->iov.iov, p->iov.niov, p->result, bytes);
    }
    p->result += bytes;
}

void usb_packet_cleanup(USBPacket *p)
{
    qemu_iovec_destroy(&p->iov);
}

int usb_packet_map(USBPacket *p, QEMUSGList *sgl)
{
    int is_write = (p->pid == USB_TOKEN_IN);
    target_phys_addr_t len;
    void *mem;
    int i;

    for (i = 0; i < sgl->nsg; i++) {
        len = sgl->sg[i].len;
        mem = cpu_physical_memory_map(sgl->sg[i].base, &len,
                                      is_write);
        if (!mem) {
            goto err;
        }
        qemu_iovec_add(&p->iov, mem, len);
        if (len != sgl->sg[i].len) {
            goto err;
        }
    }
    return 0;

err:
    usb_packet_unmap(p);
    return -1;
}

void usb_packet_unmap(USBPacket *p)
{
    int is_write = (p->pid == USB_TOKEN_IN);
    int i;

    for (i = 0; i < p->iov.niov; i++) {
        cpu_physical_memory_unmap(p->iov.iov[i].iov_base,
                                  p->iov.iov[i].iov_len, is_write,
                                  p->iov.iov[i].iov_len);
    }
}

/*
 * USB UHCI controller emulation
 * QEMU USB emulation, libhw bits.
 */

#define UHCI_CMD_FGR      (1 << 4)
#define UHCI_CMD_EGSM     (1 << 3)
#define UHCI_CMD_GRESET   (1 << 2)
#define UHCI_CMD_HCRESET  (1 << 1)
#define UHCI_CMD_RS       (1 << 0)

#define UHCI_STS_HCHALTED (1 << 5)
#define UHCI_STS_HCPERR   (1 << 4)
#define UHCI_STS_HSERR    (1 << 3)
#define UHCI_STS_RD       (1 << 2)
#define UHCI_STS_USBERR   (1 << 1)
#define UHCI_STS_USBINT   (1 << 0)

#define TD_CTRL_SPD     (1 << 29)
#define TD_CTRL_ERROR_SHIFT  27
#define TD_CTRL_IOS     (1 << 25)
#define TD_CTRL_IOC     (1 << 24)
#define TD_CTRL_ACTIVE  (1 << 23)
#define TD_CTRL_STALL   (1 << 22)
#define TD_CTRL_BABBLE  (1 << 20)
#define TD_CTRL_NAK     (1 << 19)
#define TD_CTRL_TIMEOUT (1 << 18)

#define UHCI_PORT_SUSPEND (1 << 12)
#define UHCI_PORT_RESET (1 << 9)
#define UHCI_PORT_LSDA  (1 << 8)
#define UHCI_PORT_RD    (1 << 6)
#define UHCI_PORT_ENC   (1 << 3)
#define UHCI_PORT_EN    (1 << 2)
#define UHCI_PORT_CSC   (1 << 1)
#define UHCI_PORT_CCS   (1 << 0)

#define UHCI_PORT_READ_ONLY    (0x1bb)
#define UHCI_PORT_WRITE_CLEAR  (UHCI_PORT_CSC | UHCI_PORT_ENC)

#define FRAME_TIMER_FREQ 1000

#define FRAME_MAX_LOOPS  100

#define NB_PORTS 2

#ifdef DEBUG
#define DPRINTF printf

static const char *pid2str(int pid)
{
    switch (pid) {
    case USB_TOKEN_SETUP: return "SETUP";
    case USB_TOKEN_IN:    return "IN";
    case USB_TOKEN_OUT:   return "OUT";
    }
    return "?";
}

#else
#define DPRINTF(...)
#endif

#ifdef DEBUG_DUMP_DATA
static void dump_data(USBPacket *p, int ret)
{
    iov_hexdump(p->iov.iov, p->iov.niov, stderr, "uhci", ret);
}
#else
static void dump_data(USBPacket *p, int ret) {}
#endif

typedef struct UHCIState UHCIState;

/* 
 * Pending async transaction.
 * 'packet' must be the first field because completion
 * handler does "(UHCIAsync *) pkt" cast.
 */
typedef struct UHCIAsync {
    USBPacket packet;
    QEMUSGList sgl;
    UHCIState *uhci;
    QTAILQ_ENTRY(UHCIAsync) next;
    uint32_t  td;
    uint32_t  token;
    int8_t    valid;
    uint8_t   isoc;
    uint8_t   done;
} UHCIAsync;

typedef struct UHCIPort {
    USBPort port;
    uint16_t ctrl;
} UHCIPort;

struct UHCIState {
    PCIDevice dev;
    MemoryRegion io_bar;
    USBBus bus; /* Note unused when we're a companion controller */
    uint16_t cmd; /* cmd register */
    uint16_t status;
    uint16_t intr; /* interrupt enable register */
    uint16_t frnum; /* frame number */
    uint32_t fl_base_addr; /* frame list base address */
    uint8_t sof_timing;
    uint8_t status2; /* bit 0 and 1 are used to generate UHCI_STS_USBINT */
    int64_t expire_time;
    QEMUTimer *frame_timer;
    UHCIPort ports[NB_PORTS];

    /* Interrupts that should be raised at the end of the current frame.  */
    uint32_t pending_int_mask;

    /* Active packets */
    QTAILQ_HEAD(,UHCIAsync) async_pending;
    uint8_t num_ports_vmstate;

    /* Properties */
    char *masterbus;
    uint32_t firstport;
};

typedef struct UHCI_TD {
    uint32_t link;
    uint32_t ctrl; /* see TD_CTRL_xxx */
    uint32_t token;
    uint32_t buffer;
} UHCI_TD;

typedef struct UHCI_QH {
    uint32_t link;
    uint32_t el_link;
} UHCI_QH;

static UHCIAsync *uhci_async_alloc(UHCIState *s)
{
    UHCIAsync *async = malloc(sizeof(UHCIAsync));

    memset(&async->packet, 0, sizeof(async->packet));
    async->uhci  = s;
    async->valid = 0;
    async->td    = 0;
    async->token = 0;
    async->done  = 0;
    async->isoc  = 0;
    usb_packet_init(&async->packet);
    pci_dma_sglist_init(&async->sgl, &s->dev, 1);

    return async;
}

static void uhci_async_free(UHCIState *s, UHCIAsync *async)
{
    usb_packet_cleanup(&async->packet);
    qemu_sglist_destroy(&async->sgl);
    free(async);
    async = NULL;
}

static void uhci_async_link(UHCIState *s, UHCIAsync *async)
{
    QTAILQ_INSERT_HEAD(&s->async_pending, async, next);
}

static void uhci_async_unlink(UHCIState *s, UHCIAsync *async)
{
    QTAILQ_REMOVE(&s->async_pending, async, next);
}

static void uhci_async_cancel(UHCIState *s, UHCIAsync *async)
{
    DPRINTF("uhci: cancel td 0x%x token 0x%x done %u\n",
           async->td, async->token, async->done);

    if (!async->done)
        usb_cancel_packet(&async->packet);
    uhci_async_free(s, async);
}

/*
 * Mark all outstanding async packets as invalid.
 * This is used for canceling them when TDs are removed by the HCD.
 */
static UHCIAsync *uhci_async_validate_begin(UHCIState *s)
{
    UHCIAsync *async;

    QTAILQ_FOREACH(async, &s->async_pending, next) {
        async->valid--;
    }
    return NULL;
}

/*
 * Cancel async packets that are no longer valid
 */
static void uhci_async_validate_end(UHCIState *s)
{
    UHCIAsync *curr, *n;

    QTAILQ_FOREACH_SAFE(curr, &s->async_pending, next, n) {
        if (curr->valid > 0) {
            continue;
        }
        uhci_async_unlink(s, curr);
        uhci_async_cancel(s, curr);
    }
}

static void uhci_async_cancel_device(UHCIState *s, USBDevice *dev)
{
    UHCIAsync *curr, *n;

    QTAILQ_FOREACH_SAFE(curr, &s->async_pending, next, n) {
        if (curr->packet.owner != dev) {
            continue;
        }
        uhci_async_unlink(s, curr);
        uhci_async_cancel(s, curr);
    }
}

static void uhci_async_cancel_all(UHCIState *s)
{
    UHCIAsync *curr, *n;

    QTAILQ_FOREACH_SAFE(curr, &s->async_pending, next, n) {
        uhci_async_unlink(s, curr);
        uhci_async_cancel(s, curr);
    }
}

static UHCIAsync *uhci_async_find_td(UHCIState *s, uint32_t addr, uint32_t token)
{
    UHCIAsync *async;
    UHCIAsync *match = NULL;
    int count = 0;

    /*
     * We're looking for the best match here. ie both td addr and token.
     * Otherwise we return last good match. ie just token.
     * It's ok to match just token because it identifies the transaction
     * rather well, token includes: device addr, endpoint, size, etc.
     *
     * Also since we queue async transactions in reverse order by returning
     * last good match we restores the order.
     *
     * It's expected that we wont have a ton of outstanding transactions.
     * If we ever do we'd want to optimize this algorithm.
     */

    QTAILQ_FOREACH(async, &s->async_pending, next) {
        if (async->token == token) {
            /* Good match */
            match = async;

            if (async->td == addr) {
                /* Best match */
                break;
            }
        }
        count++;
    }

    if (count > 64)
	fprintf(stderr, "uhci: warning lots of async transactions\n");

    return match;
}

static void uhci_update_irq(UHCIState *s)
{
    int level;
    if (((s->status2 & 1) && (s->intr & (1 << 2))) ||
        ((s->status2 & 2) && (s->intr & (1 << 3))) ||
        ((s->status & UHCI_STS_USBERR) && (s->intr & (1 << 0))) ||
        ((s->status & UHCI_STS_RD) && (s->intr & (1 << 1))) ||
        (s->status & UHCI_STS_HSERR) ||
        (s->status & UHCI_STS_HCPERR)) {
        level = 1;
    } else {
        level = 0;
    }
    qemu_set_irq(s->dev.irq[3], level);
}

static void uhci_reset(void *opaque)
{
    UHCIState *s = opaque;
    uint8_t *pci_conf;
    int i;
    UHCIPort *port;

    DPRINTF("uhci: full reset\n");

    pci_conf = s->dev.config;

    pci_conf[0x6a] = 0x01; /* usb clock */
    pci_conf[0x6b] = 0x00;
    s->cmd = 0;
    s->status = 0;
    s->status2 = 0;
    s->intr = 0;
    s->fl_base_addr = 0;
    s->sof_timing = 64;

    for(i = 0; i < NB_PORTS; i++) {
        port = &s->ports[i];
        port->ctrl = 0x0080;
        if (port->port.dev && port->port.dev->attached) {
            usb_reset(&port->port);
        }
    }

    uhci_async_cancel_all(s);
}

static void uhci_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;

    addr &= 0x1f;
    switch(addr) {
    case 0x0c:
        s->sof_timing = val;
        break;
    }
}

static uint32_t uhci_ioport_readb(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x0c:
        val = s->sof_timing;
        break;
    default:
        val = 0xff;
        break;
    }
    return val;
}

static void uhci_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;

    addr &= 0x1f;
    DPRINTF("uhci: writew port=0x%04x val=0x%04x\n", addr, val);

    switch(addr) {
    case 0x00:
        if ((val & UHCI_CMD_RS) && !(s->cmd & UHCI_CMD_RS)) {
            /* start frame processing */
            s->expire_time = qemu_get_clock_ns(vm_clock) +
                (get_ticks_per_sec() / FRAME_TIMER_FREQ);
            qemu_mod_timer(s->frame_timer, qemu_get_clock_ns(vm_clock));
            s->status &= ~UHCI_STS_HCHALTED;
        } else if (!(val & UHCI_CMD_RS)) {
            s->status |= UHCI_STS_HCHALTED;
        }
        if (val & UHCI_CMD_GRESET) {
            UHCIPort *port;
            USBDevice *dev;
            int i;

            /* send reset on the USB bus */
            for(i = 0; i < NB_PORTS; i++) {
                port = &s->ports[i];
                dev = port->port.dev;
                if (dev && dev->attached) {
                    usb_send_msg(dev, USB_MSG_RESET);
                }
            }
            uhci_reset(s);
            return;
        }
        if (val & UHCI_CMD_HCRESET) {
            uhci_reset(s);
            return;
        }
        s->cmd = val;
        break;
    case 0x02:
        s->status &= ~val;
        /* XXX: the chip spec is not coherent, so we add a hidden
           register to distinguish between IOC and SPD */
        if (val & UHCI_STS_USBINT)
            s->status2 = 0;
        uhci_update_irq(s);
        break;
    case 0x04:
        s->intr = val;
        uhci_update_irq(s);
        break;
    case 0x06:
        if (s->status & UHCI_STS_HCHALTED)
            s->frnum = val & 0x7ff;
        break;
    case 0x10 ... 0x1f:
        {
            UHCIPort *port;
            USBDevice *dev;
            int n;

            n = (addr >> 1) & 7;
            if (n >= NB_PORTS)
                return;
            port = &s->ports[n];
            dev = port->port.dev;
            if (dev && dev->attached) {
                /* port reset */
                if ( (val & UHCI_PORT_RESET) &&
                     !(port->ctrl & UHCI_PORT_RESET) ) {
                    usb_send_msg(dev, USB_MSG_RESET);
                }
            }
            port->ctrl &= UHCI_PORT_READ_ONLY;
            port->ctrl |= (val & ~UHCI_PORT_READ_ONLY);
            /* some bits are reset when a '1' is written to them */
            port->ctrl &= ~(val & UHCI_PORT_WRITE_CLEAR);
        }
        break;
    }
}

static uint32_t uhci_ioport_readw(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x00:
        val = s->cmd;
        break;
    case 0x02:
        val = s->status;
        break;
    case 0x04:
        val = s->intr;
        break;
    case 0x06:
        val = s->frnum;
        break;
    case 0x10 ... 0x1f:
        {
            UHCIPort *port;
            int n;
            n = (addr >> 1) & 7;
            if (n >= NB_PORTS)
                goto read_default;
            port = &s->ports[n];
            val = port->ctrl;
        }
        break;
    default:
    read_default:
        val = 0xff7f; /* disabled port */
        break;
    }

    DPRINTF("uhci: readw port=0x%04x val=0x%04x\n", addr, val);

    return val;
}

static void uhci_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;

    addr &= 0x1f;
    DPRINTF("uhci: writel port=0x%04x val=0x%08x\n", addr, val);

    switch(addr) {
    case 0x08:
        s->fl_base_addr = val & ~0xfff;
        break;
    }
}

static uint32_t uhci_ioport_readl(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x08:
        val = s->fl_base_addr;
        break;
    default:
        val = 0xffffffff;
        break;
    }
    return val;
}

/* signal resume if controller suspended */
static void uhci_resume (void *opaque)
{
    UHCIState *s = (UHCIState *)opaque;

    if (!s)
        return;

    if (s->cmd & UHCI_CMD_EGSM) {
        s->cmd |= UHCI_CMD_FGR;
        s->status |= UHCI_STS_RD;
        uhci_update_irq(s);
    }
}

static void uhci_attach(USBPort *port1)
{
    UHCIState *s = port1->opaque;
    UHCIPort *port = &s->ports[port1->index];

    /* set connect status */
    port->ctrl |= UHCI_PORT_CCS | UHCI_PORT_CSC;

    /* update speed */
    if (port->port.dev->speed == USB_SPEED_LOW) {
        port->ctrl |= UHCI_PORT_LSDA;
    } else {
        port->ctrl &= ~UHCI_PORT_LSDA;
    }

    uhci_resume(s);
}

static void uhci_detach(USBPort *port1)
{
    UHCIState *s = port1->opaque;
    UHCIPort *port = &s->ports[port1->index];

    uhci_async_cancel_device(s, port1->dev);

    /* set connect status */
    if (port->ctrl & UHCI_PORT_CCS) {
        port->ctrl &= ~UHCI_PORT_CCS;
        port->ctrl |= UHCI_PORT_CSC;
    }
    /* disable port */
    if (port->ctrl & UHCI_PORT_EN) {
        port->ctrl &= ~UHCI_PORT_EN;
        port->ctrl |= UHCI_PORT_ENC;
    }

    uhci_resume(s);
}

static void uhci_child_detach(USBPort *port1, USBDevice *child)
{
    UHCIState *s = port1->opaque;

    uhci_async_cancel_device(s, child);
}

static void uhci_wakeup(USBPort *port1)
{
    UHCIState *s = port1->opaque;
    UHCIPort *port = &s->ports[port1->index];

    if (port->ctrl & UHCI_PORT_SUSPEND && !(port->ctrl & UHCI_PORT_RD)) {
        port->ctrl |= UHCI_PORT_RD;
        uhci_resume(s);
    }
}

static int uhci_broadcast_packet(UHCIState *s, USBPacket *p)
{
    int i, ret;

    DPRINTF("uhci: packet enter. pid %s addr 0x%02x ep %d len %zd\n",
           pid2str(p->pid), p->devaddr, p->devep, p->iov.size);
    if (p->pid == USB_TOKEN_OUT || p->pid == USB_TOKEN_SETUP)
        dump_data(p, 0);

    ret = USB_RET_NODEV;
    for (i = 0; i < NB_PORTS && ret == USB_RET_NODEV; i++) {
        UHCIPort *port = &s->ports[i];
        USBDevice *dev = port->port.dev;

        if (dev && dev->attached && (port->ctrl & UHCI_PORT_EN)) {
            ret = usb_handle_packet(dev, p);
        }
    }

    DPRINTF("uhci: packet exit. ret %d len %zd\n", ret, p->iov.size);
    if (p->pid == USB_TOKEN_IN && ret > 0)
        dump_data(p, ret);

    return ret;
}

static void uhci_async_complete(USBPort *port, USBPacket *packet);
static void uhci_process_frame(UHCIState *s);

/* return -1 if fatal error (frame must be stopped)
          0 if TD successful
          1 if TD unsuccessful or inactive
*/
static int uhci_complete_td(UHCIState *s, UHCI_TD *td, UHCIAsync *async, uint32_t *int_mask)
{
    int len = 0, max_len, err, ret;
    uint8_t pid;

    max_len = ((td->token >> 21) + 1) & 0x7ff;
    pid = td->token & 0xff;

    ret = async->packet.result;

    if (td->ctrl & TD_CTRL_IOS)
        td->ctrl &= ~TD_CTRL_ACTIVE;

    if (ret < 0)
        goto out;

    len = async->packet.result;
    td->ctrl = (td->ctrl & ~0x7ff) | ((len - 1) & 0x7ff);

    /* The NAK bit may have been set by a previous frame, so clear it
       here.  The docs are somewhat unclear, but win2k relies on this
       behavior.  */
    td->ctrl &= ~(TD_CTRL_ACTIVE | TD_CTRL_NAK);
    if (td->ctrl & TD_CTRL_IOC)
        *int_mask |= 0x01;

    if (pid == USB_TOKEN_IN) {
        if (len > max_len) {
            ret = USB_RET_BABBLE;
            goto out;
        }

        if ((td->ctrl & TD_CTRL_SPD) && len < max_len) {
            *int_mask |= 0x02;
            /* short packet: do not update QH */
            DPRINTF("uhci: short packet. td 0x%x token 0x%x\n", async->td, async->token);
            return 1;
        }
    }

    /* success */
    return 0;

out:
    switch(ret) {
    case USB_RET_STALL:
        td->ctrl |= TD_CTRL_STALL;
        td->ctrl &= ~TD_CTRL_ACTIVE;
        s->status |= UHCI_STS_USBERR;
        if (td->ctrl & TD_CTRL_IOC) {
            *int_mask |= 0x01;
        }
        uhci_update_irq(s);
        return 1;

    case USB_RET_BABBLE:
        td->ctrl |= TD_CTRL_BABBLE | TD_CTRL_STALL;
        td->ctrl &= ~TD_CTRL_ACTIVE;
        s->status |= UHCI_STS_USBERR;
        if (td->ctrl & TD_CTRL_IOC) {
            *int_mask |= 0x01;
        }
        uhci_update_irq(s);
        /* frame interrupted */
        return -1;

    case USB_RET_NAK:
        td->ctrl |= TD_CTRL_NAK;
        if (pid == USB_TOKEN_SETUP)
            break;
	return 1;

    case USB_RET_NODEV:
    default:
	break;
    }

    /* Retry the TD if error count is not zero */

    td->ctrl |= TD_CTRL_TIMEOUT;
    err = (td->ctrl >> TD_CTRL_ERROR_SHIFT) & 3;
    if (err != 0) {
        err--;
        if (err == 0) {
            td->ctrl &= ~TD_CTRL_ACTIVE;
            s->status |= UHCI_STS_USBERR;
            if (td->ctrl & TD_CTRL_IOC)
                *int_mask |= 0x01;
            uhci_update_irq(s);
        }
    }
    td->ctrl = (td->ctrl & ~(3 << TD_CTRL_ERROR_SHIFT)) |
        (err << TD_CTRL_ERROR_SHIFT);
    return 1;
}

static int uhci_handle_td(UHCIState *s, uint32_t addr, UHCI_TD *td, uint32_t *int_mask)
{
    UHCIAsync *async;
    int len = 0, max_len;
    uint8_t pid, isoc;
    uint32_t token;

    /* Is active ? */
    if (!(td->ctrl & TD_CTRL_ACTIVE))
        return 1;

    /* token field is not unique for isochronous requests,
     * so use the destination buffer 
     */
    if (td->ctrl & TD_CTRL_IOS) {
        token = td->buffer;
        isoc = 1;
    } else {
        token = td->token;
        isoc = 0;
    }

    async = uhci_async_find_td(s, addr, token);
    if (async) {
        /* Already submitted */
        async->valid = 32;

        if (!async->done)
            return 1;

        uhci_async_unlink(s, async);
        goto done;
    }

    /* Allocate new packet */
    async = uhci_async_alloc(s);
    if (!async)
        return 1;

    /* valid needs to be large enough to handle 10 frame delay
     * for initial isochronous requests
     */
    async->valid = 32;
    async->td    = addr;
    async->token = token;
    async->isoc  = isoc;

    max_len = ((td->token >> 21) + 1) & 0x7ff;
    pid = td->token & 0xff;

    usb_packet_setup(&async->packet, pid, (td->token >> 8) & 0x7f,
                     (td->token >> 15) & 0xf);
    qemu_sglist_add(&async->sgl, td->buffer, max_len);
    usb_packet_map(&async->packet, &async->sgl);

    switch(pid) {
    case USB_TOKEN_OUT:
    case USB_TOKEN_SETUP:
        len = uhci_broadcast_packet(s, &async->packet);
        if (len >= 0)
            len = max_len;
        break;

    case USB_TOKEN_IN:
        len = uhci_broadcast_packet(s, &async->packet);
        break;

    default:
        /* invalid pid : frame interrupted */
        uhci_async_free(s, async);
        s->status |= UHCI_STS_HCPERR;
        uhci_update_irq(s);
        return -1;
    }
 
    if (len == USB_RET_ASYNC) {
        uhci_async_link(s, async);
        return 2;
    }

    async->packet.result = len;

done:
    len = uhci_complete_td(s, td, async, int_mask);
    usb_packet_unmap(&async->packet);
    uhci_async_free(s, async);
    return len;
}

static void uhci_async_complete(USBPort *port, USBPacket *packet)
{
    UHCIAsync *async = container_of(packet, UHCIAsync, packet);
    UHCIState *s = async->uhci;

    DPRINTF("uhci: async complete. td 0x%x token 0x%x\n", async->td, async->token);

    if (async->isoc) {
        UHCI_TD td;
        uint32_t link = async->td;
        uint32_t int_mask = 0, val;

        pci_dma_read(&s->dev, link & ~0xf, (uint8_t *) &td, sizeof(td));
        le32_to_cpus(&td.link);
        le32_to_cpus(&td.ctrl);
        le32_to_cpus(&td.token);
        le32_to_cpus(&td.buffer);

        uhci_async_unlink(s, async);
        uhci_complete_td(s, &td, async, &int_mask);
        s->pending_int_mask |= int_mask;

        /* update the status bits of the TD */
        val = cpu_to_le32(td.ctrl);
        pci_dma_write(&s->dev, (link & ~0xf) + 4,
                      (const uint8_t *)&val, sizeof(val));
        uhci_async_free(s, async);
    } else {
        async->done = 1;
        uhci_process_frame(s);
    }
}

static int is_valid(uint32_t link)
{
    return (link & 1) == 0;
}

static int is_qh(uint32_t link)
{
    return (link & 2) != 0;
}

static int depth_first(uint32_t link)
{
    return (link & 4) != 0;
}

/* QH DB used for detecting QH loops */
#define UHCI_MAX_QUEUES 128
typedef struct {
    uint32_t addr[UHCI_MAX_QUEUES];
    int      count;
} QhDb;

static void qhdb_reset(QhDb *db)
{
    db->count = 0;
}

/* Add QH to DB. Returns 1 if already present or DB is full. */
static int qhdb_insert(QhDb *db, uint32_t addr)
{
    int i;
    for (i = 0; i < db->count; i++)
        if (db->addr[i] == addr)
            return 1;

    if (db->count >= UHCI_MAX_QUEUES)
        return 1;

    db->addr[db->count++] = addr;
    return 0;
}

static void uhci_process_frame(UHCIState *s)
{
    uint32_t frame_addr, link, old_td_ctrl, val, int_mask;
    uint32_t curr_qh;
    int cnt, ret;
    UHCI_TD td;
    UHCI_QH qh;
    QhDb qhdb;

    frame_addr = s->fl_base_addr + ((s->frnum & 0x3ff) << 2);

    DPRINTF("uhci: processing frame %d addr 0x%x\n" , s->frnum, frame_addr);

    pci_dma_read(&s->dev, frame_addr, (uint8_t *)&link, 4);
    le32_to_cpus(&link);

    int_mask = 0;
    curr_qh  = 0;

    qhdb_reset(&qhdb);

    for (cnt = FRAME_MAX_LOOPS; is_valid(link) && cnt; cnt--) {
        if (is_qh(link)) {
            /* QH */

            if (qhdb_insert(&qhdb, link)) {
                /*
                 * We're going in circles. Which is not a bug because
                 * HCD is allowed to do that as part of the BW management. 
                 * In our case though it makes no sense to spin here. Sync transations 
                 * are already done, and async completion handler will re-process 
                 * the frame when something is ready.
                 */
                DPRINTF("uhci: detected loop. qh 0x%x\n", link);
                break;
            }

            pci_dma_read(&s->dev, link & ~0xf, (uint8_t *) &qh, sizeof(qh));
            le32_to_cpus(&qh.link);
            le32_to_cpus(&qh.el_link);

            DPRINTF("uhci: QH 0x%x load. link 0x%x elink 0x%x\n",
                    link, qh.link, qh.el_link);

            if (!is_valid(qh.el_link)) {
                /* QH w/o elements */
                curr_qh = 0;
                link = qh.link;
            } else {
                /* QH with elements */
            	curr_qh = link;
            	link = qh.el_link;
            }
            continue;
        }

        /* TD */
        pci_dma_read(&s->dev, link & ~0xf, (uint8_t *) &td, sizeof(td));
        le32_to_cpus(&td.link);
        le32_to_cpus(&td.ctrl);
        le32_to_cpus(&td.token);
        le32_to_cpus(&td.buffer);

        DPRINTF("uhci: TD 0x%x load. link 0x%x ctrl 0x%x token 0x%x qh 0x%x\n", 
                link, td.link, td.ctrl, td.token, curr_qh);

        old_td_ctrl = td.ctrl;
        ret = uhci_handle_td(s, link, &td, &int_mask);
        if (old_td_ctrl != td.ctrl) {
            /* update the status bits of the TD */
            val = cpu_to_le32(td.ctrl);
            pci_dma_write(&s->dev, (link & ~0xf) + 4,
                          (const uint8_t *)&val, sizeof(val));
        }

        if (ret < 0) {
            /* interrupted frame */
            break;
        }

        if (ret == 2 || ret == 1) {
            DPRINTF("uhci: TD 0x%x %s. link 0x%x ctrl 0x%x token 0x%x qh 0x%x\n",
                    link, ret == 2 ? "pend" : "skip",
                    td.link, td.ctrl, td.token, curr_qh);

            link = curr_qh ? qh.link : td.link;
            continue;
        }

        /* completed TD */

        DPRINTF("uhci: TD 0x%x done. link 0x%x ctrl 0x%x token 0x%x qh 0x%x\n", 
                link, td.link, td.ctrl, td.token, curr_qh);

        link = td.link;

        if (curr_qh) {
	    /* update QH element link */
            qh.el_link = link;
            val = cpu_to_le32(qh.el_link);
            pci_dma_write(&s->dev, (curr_qh & ~0xf) + 4,
                          (const uint8_t *)&val, sizeof(val));

            if (!depth_first(link)) {
               /* done with this QH */

               DPRINTF("uhci: QH 0x%x done. link 0x%x elink 0x%x\n",
                       curr_qh, qh.link, qh.el_link);

               curr_qh = 0;
               link    = qh.link;
            }
        }

        /* go to the next entry */
    }

    s->pending_int_mask |= int_mask;
}

static void uhci_frame_timer(void *opaque)
{
    UHCIState *s = opaque;

    /* prepare the timer for the next frame */
    s->expire_time += (get_ticks_per_sec() / FRAME_TIMER_FREQ);

    if (!(s->cmd & UHCI_CMD_RS)) {
        /* Full stop */
        qemu_del_timer(s->frame_timer);
        /* set hchalted bit in status - UHCI11D 2.1.2 */
        s->status |= UHCI_STS_HCHALTED;

        DPRINTF("uhci: halted\n");
        return;
    }

    /* Complete the previous frame */
    if (s->pending_int_mask) {
        s->status2 |= s->pending_int_mask;
        s->status  |= UHCI_STS_USBINT;
        uhci_update_irq(s);
    }
    s->pending_int_mask = 0;

    /* Start new frame */
    s->frnum = (s->frnum + 1) & 0x7ff;

    DPRINTF("uhci: new frame #%u\n" , s->frnum);

    uhci_async_validate_begin(s);

    uhci_process_frame(s);

    uhci_async_validate_end(s);

    qemu_mod_timer(s->frame_timer, s->expire_time);
}

static const MemoryRegionPortio uhci_portio[] = {
    { 0, 32, 2, .write = uhci_ioport_writew, },
    { 0, 32, 2, .read = uhci_ioport_readw, },
    { 0, 32, 4, .write = uhci_ioport_writel, },
    { 0, 32, 4, .read = uhci_ioport_readl, },
    { 0, 32, 1, .write = uhci_ioport_writeb, },
    { 0, 32, 1, .read = uhci_ioport_readb, },
    PORTIO_END_OF_LIST()
};

static const MemoryRegionOps uhci_ioport_ops = {
    .old_portio = uhci_portio,
};

static USBPortOps uhci_port_ops = {
    .attach = uhci_attach,
    .detach = uhci_detach,
    .child_detach = uhci_child_detach,
    .wakeup = uhci_wakeup,
    .complete = uhci_async_complete,
};

static USBBusOps uhci_bus_ops = {
};

static int usb_uhci_common_initfn(PCIDevice *dev)
{
    UHCIState *s = DO_UPCAST(UHCIState, dev, dev);
    uint8_t *pci_conf = s->dev.config;
    int i;

    pci_conf[PCI_CLASS_PROG] = 0x00;
    /* TODO: reset value should be 0. */
    pci_conf[PCI_INTERRUPT_PIN] = 4; /* interrupt pin D */
    pci_conf[USB_SBRN] = USB_RELEASE_1; // release number

    if (s->masterbus) {
        USBPort *ports[NB_PORTS];
        for(i = 0; i < NB_PORTS; i++) {
            ports[i] = &s->ports[i].port;
        }
        if (usb_register_companion(s->masterbus, ports, NB_PORTS,
                s->firstport, s, &uhci_port_ops,
                USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL) != 0) {
            return -1;
        }
    } else {
        usb_bus_new(&s->bus, &uhci_bus_ops, &s->dev.qdev);
        for (i = 0; i < NB_PORTS; i++) {
            usb_register_port(&s->bus, &s->ports[i].port, s, i, &uhci_port_ops,
                              USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL);
        }
    }
    s->frame_timer = qemu_new_timer_ns(vm_clock, uhci_frame_timer, s);
    s->num_ports_vmstate = NB_PORTS;
    QTAILQ_INIT(&s->async_pending);

    qemu_register_reset(uhci_reset, s);

    memory_region_init_io(&s->io_bar, &uhci_ioport_ops, s, "uhci", 0x20);
    /* Use region 4 for consistency with real hardware.  BSD guests seem
       to rely on this.  */
    pci_register_bar(&s->dev, 4, PCI_BASE_ADDRESS_SPACE_IO, &s->io_bar);

    return 0;
}

static int usb_uhci_exit(PCIDevice *dev)
{
    UHCIState *s = DO_UPCAST(UHCIState, dev, dev);

    memory_region_destroy(&s->io_bar);
    return 0;
}

static Property uhci_properties[] = {
    DEFINE_PROP_STRING("masterbus", UHCIState, masterbus),
    DEFINE_PROP_UINT32("firstport", UHCIState, firstport, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static PCIDeviceInfo uhci_info[] = {
    {
        .qdev.name    = "piix3-usb-uhci",
        .qdev.size    = sizeof(UHCIState),
        .init         = usb_uhci_common_initfn,
        .exit         = usb_uhci_exit,
        .vendor_id    = PCI_VENDOR_ID_INTEL,
        .device_id    = PCI_DEVICE_ID_INTEL_82371SB_2,
        .revision     = 0x01,
        .class_id     = PCI_CLASS_SERIAL_USB,
        .qdev.props   = uhci_properties,
    },{
        .qdev.name    = "piix4-usb-uhci",
        .qdev.size    = sizeof(UHCIState),
        .init         = usb_uhci_common_initfn,
        .exit         = usb_uhci_exit,
        .vendor_id    = PCI_VENDOR_ID_INTEL,
        .device_id    = PCI_DEVICE_ID_INTEL_82371AB_2,
        .revision     = 0x01,
        .class_id     = PCI_CLASS_SERIAL_USB,
        .qdev.props   = uhci_properties,
    },{
        /* end of list */
    }
};

static void uhci_register(void)
{
    pci_qdev_register_many(uhci_info);
}
device_init(uhci_register);

void usb_uhci_piix3_init(PCIBus *bus, int devfn)
{
    pci_create_simple(bus, devfn, "piix3-usb-uhci");
}

void usb_uhci_piix4_init(PCIBus *bus, int devfn)
{
    pci_create_simple(bus, devfn, "piix4-usb-uhci");
}

/* ------------------------------------------------------------------ */

static uint8_t usb_lo(uint16_t val)
{
    return val & 0xff;
}

static uint8_t usb_hi(uint16_t val)
{
    return (val >> 8) & 0xff;
}

int usb_desc_device(const USBDescID *id, const USBDescDevice *dev,
                    uint8_t *dest, size_t len)
{
    uint8_t bLength = 0x12;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_DEVICE;

    dest[0x02] = usb_lo(dev->bcdUSB);
    dest[0x03] = usb_hi(dev->bcdUSB);
    dest[0x04] = dev->bDeviceClass;
    dest[0x05] = dev->bDeviceSubClass;
    dest[0x06] = dev->bDeviceProtocol;
    dest[0x07] = dev->bMaxPacketSize0;

    dest[0x08] = usb_lo(id->idVendor);
    dest[0x09] = usb_hi(id->idVendor);
    dest[0x0a] = usb_lo(id->idProduct);
    dest[0x0b] = usb_hi(id->idProduct);
    dest[0x0c] = usb_lo(id->bcdDevice);
    dest[0x0d] = usb_hi(id->bcdDevice);
    dest[0x0e] = id->iManufacturer;
    dest[0x0f] = id->iProduct;
    dest[0x10] = id->iSerialNumber;

    dest[0x11] = dev->bNumConfigurations;

    return bLength;
}

int usb_desc_device_qualifier(const USBDescDevice *dev,
                              uint8_t *dest, size_t len)
{
    uint8_t bLength = 0x0a;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_DEVICE_QUALIFIER;

    dest[0x02] = usb_lo(dev->bcdUSB);
    dest[0x03] = usb_hi(dev->bcdUSB);
    dest[0x04] = dev->bDeviceClass;
    dest[0x05] = dev->bDeviceSubClass;
    dest[0x06] = dev->bDeviceProtocol;
    dest[0x07] = dev->bMaxPacketSize0;
    dest[0x08] = dev->bNumConfigurations;
    dest[0x09] = 0; /* reserved */

    return bLength;
}

int usb_desc_config(const USBDescConfig *conf, uint8_t *dest, size_t len)
{
    uint8_t  bLength = 0x09;
    uint16_t wTotalLength = 0;
    int i, rc;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_CONFIG;
    dest[0x04] = conf->bNumInterfaces;
    dest[0x05] = conf->bConfigurationValue;
    dest[0x06] = conf->iConfiguration;
    dest[0x07] = conf->bmAttributes;
    dest[0x08] = conf->bMaxPower;
    wTotalLength += bLength;

    /* handle grouped interfaces if any*/
    for (i = 0; i < conf->nif_groups; i++) {
        rc = usb_desc_iface_group(&(conf->if_groups[i]),
                                  dest + wTotalLength,
                                  len - wTotalLength);
        if (rc < 0) {
            return rc;
        }
        wTotalLength += rc;
    }

    /* handle normal (ungrouped / no IAD) interfaces if any */
    for (i = 0; i < conf->nif; i++) {
        rc = usb_desc_iface(conf->ifs + i, dest + wTotalLength, len - wTotalLength);
        if (rc < 0) {
            return rc;
        }
        wTotalLength += rc;
    }

    dest[0x02] = usb_lo(wTotalLength);
    dest[0x03] = usb_hi(wTotalLength);
    return wTotalLength;
}

int usb_desc_iface_group(const USBDescIfaceAssoc *iad, uint8_t *dest,
                         size_t len)
{
    int pos = 0;
    int i = 0;

    /* handle interface association descriptor */
    uint8_t bLength = 0x08;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_INTERFACE_ASSOC;
    dest[0x02] = iad->bFirstInterface;
    dest[0x03] = iad->bInterfaceCount;
    dest[0x04] = iad->bFunctionClass;
    dest[0x05] = iad->bFunctionSubClass;
    dest[0x06] = iad->bFunctionProtocol;
    dest[0x07] = iad->iFunction;
    pos += bLength;

    /* handle associated interfaces in this group */
    for (i = 0; i < iad->nif; i++) {
        int rc = usb_desc_iface(&(iad->ifs[i]), dest + pos, len - pos);
        if (rc < 0) {
            return rc;
        }
        pos += rc;
    }

    return pos;
}

int usb_desc_iface(const USBDescIface *iface, uint8_t *dest, size_t len)
{
    uint8_t bLength = 0x09;
    int i, rc, pos = 0;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_INTERFACE;
    dest[0x02] = iface->bInterfaceNumber;
    dest[0x03] = iface->bAlternateSetting;
    dest[0x04] = iface->bNumEndpoints;
    dest[0x05] = iface->bInterfaceClass;
    dest[0x06] = iface->bInterfaceSubClass;
    dest[0x07] = iface->bInterfaceProtocol;
    dest[0x08] = iface->iInterface;
    pos += bLength;

    for (i = 0; i < iface->ndesc; i++) {
        rc = usb_desc_other(iface->descs + i, dest + pos, len - pos);
        if (rc < 0) {
            return rc;
        }
        pos += rc;
    }

    for (i = 0; i < iface->bNumEndpoints; i++) {
        rc = usb_desc_endpoint(iface->eps + i, dest + pos, len - pos);
        if (rc < 0) {
            return rc;
        }
        pos += rc;
    }

    return pos;
}

int usb_desc_endpoint(const USBDescEndpoint *ep, uint8_t *dest, size_t len)
{
    uint8_t bLength = 0x07;

    if (len < bLength) {
        return -1;
    }

    dest[0x00] = bLength;
    dest[0x01] = USB_DT_ENDPOINT;
    dest[0x02] = ep->bEndpointAddress;
    dest[0x03] = ep->bmAttributes;
    dest[0x04] = usb_lo(ep->wMaxPacketSize);
    dest[0x05] = usb_hi(ep->wMaxPacketSize);
    dest[0x06] = ep->bInterval;

    return bLength;
}

int usb_desc_other(const USBDescOther *desc, uint8_t *dest, size_t len)
{
    int bLength = desc->length ? desc->length : desc->data[0];

    if (len < bLength) {
        return -1;
    }

    memcpy(dest, desc->data, bLength);
    return bLength;
}

/* ------------------------------------------------------------------ */

static void usb_desc_setdefaults(USBDevice *dev)
{
    const USBDesc *desc = dev->info->usb_desc;

    assert(desc != NULL);
    switch (dev->speed) {
    case USB_SPEED_LOW:
    case USB_SPEED_FULL:
        dev->device = desc->full;
        break;
    case USB_SPEED_HIGH:
        dev->device = desc->high;
        break;
    }
    dev->config = dev->device->confs;
}

void usb_desc_init(USBDevice *dev)
{
    const USBDesc *desc = dev->info->usb_desc;

    assert(desc != NULL);
    dev->speed = USB_SPEED_FULL;
    dev->speedmask = 0;
    if (desc->full) {
        dev->speedmask |= USB_SPEED_MASK_FULL;
    }
    if (desc->high) {
        dev->speedmask |= USB_SPEED_MASK_HIGH;
    }
    usb_desc_setdefaults(dev);
}

void usb_desc_attach(USBDevice *dev)
{
    const USBDesc *desc = dev->info->usb_desc;

    assert(desc != NULL);
    if (desc->high && (dev->port->speedmask & USB_SPEED_MASK_HIGH)) {
        dev->speed = USB_SPEED_HIGH;
    } else if (desc->full && (dev->port->speedmask & USB_SPEED_MASK_FULL)) {
        dev->speed = USB_SPEED_FULL;
    } else {
        fprintf(stderr, "usb: port/device speed mismatch for \"%s\"\n",
                dev->info->product_desc);
        return;
    }
    usb_desc_setdefaults(dev);
}

void usb_desc_set_string(USBDevice *dev, uint8_t index, const char *str)
{
    USBDescString *s;

    QLIST_FOREACH(s, &dev->strings, next) {
        if (s->index == index) {
            break;
        }
    }
    if (s == NULL) {
        s = calloc(1, sizeof(*s));
        s->index = index;
        QLIST_INSERT_HEAD(&dev->strings, s, next);
    }
    free(s->str);
    s->str = strdup(str);
}

const char *usb_desc_get_string(USBDevice *dev, uint8_t index)
{
    USBDescString *s;

    QLIST_FOREACH(s, &dev->strings, next) {
        if (s->index == index) {
            return s->str;
        }
    }
    return NULL;
}

int usb_desc_string(USBDevice *dev, int index, uint8_t *dest, size_t len)
{
    uint8_t bLength, pos, i;
    const char *str;

    if (len < 4) {
        return -1;
    }

    if (index == 0) {
        /* language ids */
        dest[0] = 4;
        dest[1] = USB_DT_STRING;
        dest[2] = 0x09;
        dest[3] = 0x04;
        return 4;
    }

    str = usb_desc_get_string(dev, index);
    if (str == NULL) {
        str = dev->info->usb_desc->str[index];
        if (str == NULL) {
            return 0;
        }
    }

    bLength = strlen(str) * 2 + 2;
    dest[0] = bLength;
    dest[1] = USB_DT_STRING;
    i = 0; pos = 2;
    while (pos+1 < bLength && pos+1 < len) {
        dest[pos++] = str[i++];
        dest[pos++] = 0;
    }
    return pos;
}

int usb_desc_get_descriptor(USBDevice *dev, int value, uint8_t *dest, size_t len)
{
    const USBDesc *desc = dev->info->usb_desc;
    const USBDescDevice *other_dev;
    uint8_t buf[256];
    uint8_t type = value >> 8;
    uint8_t index = value & 0xff;
    int ret = -1;

    if (dev->speed == USB_SPEED_HIGH) {
        other_dev = dev->info->usb_desc->full;
    } else {
        other_dev = dev->info->usb_desc->high;
    }

    switch(type) {
    case USB_DT_DEVICE:
        ret = usb_desc_device(&desc->id, dev->device, buf, sizeof(buf));
        break;
    case USB_DT_CONFIG:
        if (index < dev->device->bNumConfigurations) {
            ret = usb_desc_config(dev->device->confs + index, buf, sizeof(buf));
        }
        break;
    case USB_DT_STRING:
        ret = usb_desc_string(dev, index, buf, sizeof(buf));
        break;

    case USB_DT_DEVICE_QUALIFIER:
        if (other_dev != NULL) {
            ret = usb_desc_device_qualifier(other_dev, buf, sizeof(buf));
        }
        break;
    case USB_DT_OTHER_SPEED_CONFIG:
        if (other_dev != NULL && index < other_dev->bNumConfigurations) {
            ret = usb_desc_config(other_dev->confs + index, buf, sizeof(buf));
            buf[0x01] = USB_DT_OTHER_SPEED_CONFIG;
        }
        break;

    case USB_DT_DEBUG:
        /* ignore silently */
        break;

    default:
        fprintf(stderr, "%s: %d unknown type %d (len %zd)\n", __FUNCTION__,
                dev->addr, type, len);
        break;
    }

    if (ret > 0) {
        if (ret > len) {
            ret = len;
        }
        memcpy(dest, buf, ret);
    }
    return ret;
}

int usb_desc_handle_control(USBDevice *dev, USBPacket *p,
        int request, int value, int index, int length, uint8_t *data)
{
    const USBDesc *desc = dev->info->usb_desc;
    int i, ret = -1;

    assert(desc != NULL);
    switch(request) {
    case DeviceOutRequest | USB_REQ_SET_ADDRESS:
        dev->addr = value;
        ret = 0;
        break;

    case DeviceRequest | USB_REQ_GET_DESCRIPTOR:
        ret = usb_desc_get_descriptor(dev, value, data, length);
        break;

    case DeviceRequest | USB_REQ_GET_CONFIGURATION:
        data[0] = dev->config->bConfigurationValue;
        ret = 1;
        break;
    case DeviceOutRequest | USB_REQ_SET_CONFIGURATION:
        for (i = 0; i < dev->device->bNumConfigurations; i++) {
            if (dev->device->confs[i].bConfigurationValue == value) {
                dev->config = dev->device->confs + i;
                ret = 0;
            }
        }
        break;

    case DeviceRequest | USB_REQ_GET_STATUS:
        data[0] = 0;
        if (dev->config->bmAttributes & 0x40) {
            data[0] |= 1 << USB_DEVICE_SELF_POWERED;
        }
        if (dev->remote_wakeup) {
            data[0] |= 1 << USB_DEVICE_REMOTE_WAKEUP;
        }
        data[1] = 0x00;
        ret = 2;
        break;
    case DeviceOutRequest | USB_REQ_CLEAR_FEATURE:
        if (value == USB_DEVICE_REMOTE_WAKEUP) {
            dev->remote_wakeup = 0;
            ret = 0;
        }
        break;
    case DeviceOutRequest | USB_REQ_SET_FEATURE:
        if (value == USB_DEVICE_REMOTE_WAKEUP) {
            dev->remote_wakeup = 1;
            ret = 0;
        }
        break;
    }
    return ret;
}

/*
 * QEMU USB HUB emulation
 */
//#define DEBUG

#define NUM_PORTS 8

typedef struct USBHubPort {
    USBPort port;
    uint16_t wPortStatus;
    uint16_t wPortChange;
} USBHubPort;

typedef struct USBHubState {
    USBDevice dev;
    USBHubPort ports[NUM_PORTS];
} USBHubState;

#define ClearHubFeature		(0x2000 | USB_REQ_CLEAR_FEATURE)
#define ClearPortFeature	(0x2300 | USB_REQ_CLEAR_FEATURE)
#define GetHubDescriptor	(0xa000 | USB_REQ_GET_DESCRIPTOR)
#define GetHubStatus		(0xa000 | USB_REQ_GET_STATUS)
#define GetPortStatus		(0xa300 | USB_REQ_GET_STATUS)
#define SetHubFeature		(0x2000 | USB_REQ_SET_FEATURE)
#define SetPortFeature		(0x2300 | USB_REQ_SET_FEATURE)

#define PORT_STAT_CONNECTION	0x0001
#define PORT_STAT_ENABLE	0x0002
#define PORT_STAT_SUSPEND	0x0004
#define PORT_STAT_OVERCURRENT	0x0008
#define PORT_STAT_RESET		0x0010
#define PORT_STAT_POWER		0x0100
#define PORT_STAT_LOW_SPEED	0x0200
#define PORT_STAT_HIGH_SPEED    0x0400
#define PORT_STAT_TEST          0x0800
#define PORT_STAT_INDICATOR     0x1000

#define PORT_STAT_C_CONNECTION	0x0001
#define PORT_STAT_C_ENABLE	0x0002
#define PORT_STAT_C_SUSPEND	0x0004
#define PORT_STAT_C_OVERCURRENT	0x0008
#define PORT_STAT_C_RESET	0x0010

#define PORT_CONNECTION	        0
#define PORT_ENABLE		1
#define PORT_SUSPEND		2
#define PORT_OVERCURRENT	3
#define PORT_RESET		4
#define PORT_POWER		8
#define PORT_LOWSPEED		9
#define PORT_HIGHSPEED		10
#define PORT_C_CONNECTION	16
#define PORT_C_ENABLE		17
#define PORT_C_SUSPEND		18
#define PORT_C_OVERCURRENT	19
#define PORT_C_RESET		20
#define PORT_TEST               21
#define PORT_INDICATOR          22

/* same as Linux kernel root hubs */

enum {
    STRHUB_MANUFACTURER = 1,
    STRHUB_PRODUCT,
    STRHUB_SERIALNUMBER,
};

static const USBDescStrings hubdesc_strings = {
    [STRHUB_MANUFACTURER] = "QEMU 1.0",
    [STRHUB_PRODUCT]      = "QEMU USB Hub",
    [STRHUB_SERIALNUMBER] = "314159",
};

static const USBDescIface desc_iface_hub = {
    .bInterfaceNumber              = 0,
    .bNumEndpoints                 = 1,
    .bInterfaceClass               = USB_CLASS_HUB,
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress      = USB_DIR_IN | 0x01,
            .bmAttributes          = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize        = 1 + (NUM_PORTS + 7) / 8,
            .bInterval             = 0xff,
        },
    }
};

static const USBDescDevice desc_device_hub = {
    .bcdUSB                        = 0x0110,
    .bDeviceClass                  = USB_CLASS_HUB,
    .bMaxPacketSize0               = 8,
    .bNumConfigurations            = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 1,
            .bConfigurationValue   = 1,
            .bmAttributes          = 0xe0,
            .nif = 1,
            .ifs = &desc_iface_hub,
        },
    },
};

static const USBDesc desc_hub = {
    .id = {
        .idVendor          = 0x0409,
        .idProduct         = 0x55aa,
        .bcdDevice         = 0x0101,
        .iManufacturer     = STRHUB_MANUFACTURER,
        .iProduct          = STRHUB_PRODUCT,
        .iSerialNumber     = STRHUB_SERIALNUMBER,
    },
    .full = &desc_device_hub,
    .str  = hubdesc_strings,
};

static const uint8_t qemu_hub_hub_descriptor[] =
{
	0x00,			/*  u8  bLength; patched in later */
	0x29,			/*  u8  bDescriptorType; Hub-descriptor */
	0x00,			/*  u8  bNbrPorts; (patched later) */
	0x0a,			/* u16  wHubCharacteristics; */
	0x00,			/*   (per-port OC, no power switching) */
	0x01,			/*  u8  bPwrOn2pwrGood; 2ms */
	0x00			/*  u8  bHubContrCurrent; 0 mA */

        /* DeviceRemovable and PortPwrCtrlMask patched in later */
};

static void usb_hub_attach(USBPort *port1)
{
    USBHubState *s = port1->opaque;
    USBHubPort *port = &s->ports[port1->index];

    port->wPortStatus |= PORT_STAT_CONNECTION;
    port->wPortChange |= PORT_STAT_C_CONNECTION;
    if (port->port.dev->speed == USB_SPEED_LOW) {
        port->wPortStatus |= PORT_STAT_LOW_SPEED;
    } else {
        port->wPortStatus &= ~PORT_STAT_LOW_SPEED;
    }
    usb_wakeup(&s->dev);
}

static void usb_hub_detach(USBPort *port1)
{
    USBHubState *s = port1->opaque;
    USBHubPort *port = &s->ports[port1->index];

    /* Let upstream know the device on this port is gone */
    s->dev.port->ops->child_detach(s->dev.port, port1->dev);

    port->wPortStatus &= ~PORT_STAT_CONNECTION;
    port->wPortChange |= PORT_STAT_C_CONNECTION;
    if (port->wPortStatus & PORT_STAT_ENABLE) {
        port->wPortStatus &= ~PORT_STAT_ENABLE;
        port->wPortChange |= PORT_STAT_C_ENABLE;
    }
}

static void usb_hub_child_detach(USBPort *port1, USBDevice *child)
{
    USBHubState *s = port1->opaque;

    /* Pass along upstream */
    s->dev.port->ops->child_detach(s->dev.port, child);
}

static void usb_hub_wakeup(USBPort *port1)
{
    USBHubState *s = port1->opaque;
    USBHubPort *port = &s->ports[port1->index];

    if (port->wPortStatus & PORT_STAT_SUSPEND) {
        port->wPortChange |= PORT_STAT_C_SUSPEND;
        usb_wakeup(&s->dev);
    }
}

static void usb_hub_complete(USBPort *port, USBPacket *packet)
{
    USBHubState *s = port->opaque;

    /*
     * Just pass it along upstream for now.
     *
     * If we ever implement usb 2.0 split transactions this will
     * become a little more complicated ...
     *
     * Can't use usb_packet_complete() here because packet->owner is
     * cleared already, go call the ->complete() callback directly
     * instead.
     */
    s->dev.port->ops->complete(s->dev.port, packet);
}

static void usb_hub_handle_reset(USBDevice *dev)
{
    /* XXX: do it */
}

static int usb_hub_handle_control(USBDevice *dev, USBPacket *p,
               int request, int value, int index, int length, uint8_t *data)
{
    USBHubState *s = (USBHubState *)dev;
    int ret;

    ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
    if (ret >= 0) {
        return ret;
    }

    switch(request) {
    case EndpointOutRequest | USB_REQ_CLEAR_FEATURE:
        if (value == 0 && index != 0x81) { /* clear ep halt */
            goto fail;
        }
        ret = 0;
        break;
    case DeviceRequest | USB_REQ_GET_INTERFACE:
        data[0] = 0;
        ret = 1;
        break;
    case DeviceOutRequest | USB_REQ_SET_INTERFACE:
        ret = 0;
        break;
        /* usb specific requests */
    case GetHubStatus:
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;
        ret = 4;
        break;
    case GetPortStatus:
        {
            unsigned int n = index - 1;
            USBHubPort *port;
            if (n >= NUM_PORTS) {
                goto fail;
            }
            port = &s->ports[n];
            data[0] = port->wPortStatus;
            data[1] = port->wPortStatus >> 8;
            data[2] = port->wPortChange;
            data[3] = port->wPortChange >> 8;
            ret = 4;
        }
        break;
    case SetHubFeature:
    case ClearHubFeature:
        if (value == 0 || value == 1) {
        } else {
            goto fail;
        }
        ret = 0;
        break;
    case SetPortFeature:
        {
            unsigned int n = index - 1;
            USBHubPort *port;
            USBDevice *dev;
            if (n >= NUM_PORTS) {
                goto fail;
            }
            port = &s->ports[n];
            dev = port->port.dev;
            switch(value) {
            case PORT_SUSPEND:
                port->wPortStatus |= PORT_STAT_SUSPEND;
                break;
            case PORT_RESET:
                if (dev && dev->attached) {
                    usb_send_msg(dev, USB_MSG_RESET);
                    port->wPortChange |= PORT_STAT_C_RESET;
                    /* set enable bit */
                    port->wPortStatus |= PORT_STAT_ENABLE;
                }
                break;
            case PORT_POWER:
                break;
            default:
                goto fail;
            }
            ret = 0;
        }
        break;
    case ClearPortFeature:
        {
            unsigned int n = index - 1;
            USBHubPort *port;

            if (n >= NUM_PORTS) {
                goto fail;
            }
            port = &s->ports[n];
            switch(value) {
            case PORT_ENABLE:
                port->wPortStatus &= ~PORT_STAT_ENABLE;
                break;
            case PORT_C_ENABLE:
                port->wPortChange &= ~PORT_STAT_C_ENABLE;
                break;
            case PORT_SUSPEND:
                port->wPortStatus &= ~PORT_STAT_SUSPEND;
                break;
            case PORT_C_SUSPEND:
                port->wPortChange &= ~PORT_STAT_C_SUSPEND;
                break;
            case PORT_C_CONNECTION:
                port->wPortChange &= ~PORT_STAT_C_CONNECTION;
                break;
            case PORT_C_OVERCURRENT:
                port->wPortChange &= ~PORT_STAT_C_OVERCURRENT;
                break;
            case PORT_C_RESET:
                port->wPortChange &= ~PORT_STAT_C_RESET;
                break;
            default:
                goto fail;
            }
            ret = 0;
        }
        break;
    case GetHubDescriptor:
        {
            unsigned int n, limit, var_hub_size = 0;
            memcpy(data, qemu_hub_hub_descriptor,
                   sizeof(qemu_hub_hub_descriptor));
            data[2] = NUM_PORTS;

            /* fill DeviceRemovable bits */
            limit = ((NUM_PORTS + 1 + 7) / 8) + 7;
            for (n = 7; n < limit; n++) {
                data[n] = 0x00;
                var_hub_size++;
            }

            /* fill PortPwrCtrlMask bits */
            limit = limit + ((NUM_PORTS + 7) / 8);
            for (;n < limit; n++) {
                data[n] = 0xff;
                var_hub_size++;
            }

            ret = sizeof(qemu_hub_hub_descriptor) + var_hub_size;
            data[0] = ret;
            break;
        }
    default:
    fail:
        ret = USB_RET_STALL;
        break;
    }
    return ret;
}

static int usb_hub_handle_data(USBDevice *dev, USBPacket *p)
{
    USBHubState *s = (USBHubState *)dev;
    int ret;

    switch(p->pid) {
    case USB_TOKEN_IN:
        if (p->devep == 1) {
            USBHubPort *port;
            unsigned int status;
            uint8_t buf[4];
            int i, n;
            n = (NUM_PORTS + 1 + 7) / 8;
            if (p->iov.size == 1) { /* FreeBSD workaround */
                n = 1;
            } else if (n > p->iov.size) {
                return USB_RET_BABBLE;
            }
            status = 0;
            for(i = 0; i < NUM_PORTS; i++) {
                port = &s->ports[i];
                if (port->wPortChange)
                    status |= (1 << (i + 1));
            }
            if (status != 0) {
                for(i = 0; i < n; i++) {
                    buf[i] = status >> (8 * i);
                }
                usb_packet_copy(p, buf, n);
                ret = n;
            } else {
                ret = USB_RET_NAK; /* usb11 11.13.1 */
            }
        } else {
            goto fail;
        }
        break;
    case USB_TOKEN_OUT:
    default:
    fail:
        ret = USB_RET_STALL;
        break;
    }
    return ret;
}

static int usb_hub_broadcast_packet(USBHubState *s, USBPacket *p)
{
    USBHubPort *port;
    USBDevice *dev;
    int i, ret;

    for(i = 0; i < NUM_PORTS; i++) {
        port = &s->ports[i];
        dev = port->port.dev;
        if (dev && dev->attached && (port->wPortStatus & PORT_STAT_ENABLE)) {
            ret = usb_handle_packet(dev, p);
            if (ret != USB_RET_NODEV) {
                return ret;
            }
        }
    }
    return USB_RET_NODEV;
}

static int usb_hub_handle_packet(USBDevice *dev, USBPacket *p)
{
    USBHubState *s = (USBHubState *)dev;

#if defined(DEBUG) && 0
    printf("usb_hub: pid=0x%x\n", pid);
#endif
    if (dev->state == USB_STATE_DEFAULT &&
        dev->addr != 0 &&
        p->devaddr != dev->addr &&
        (p->pid == USB_TOKEN_SETUP ||
         p->pid == USB_TOKEN_OUT ||
         p->pid == USB_TOKEN_IN)) {
        /* broadcast the packet to the devices */
        return usb_hub_broadcast_packet(s, p);
    }
    return usb_generic_handle_packet(dev, p);
}

static void usb_hub_handle_destroy(USBDevice *dev)
{
    USBHubState *s = (USBHubState *)dev;
    int i;

    for (i = 0; i < NUM_PORTS; i++) {
        usb_unregister_port(usb_bus_from_device(dev),
                            &s->ports[i].port);
    }
}

static USBPortOps usb_hub_port_ops = {
    .attach = usb_hub_attach,
    .detach = usb_hub_detach,
    .child_detach = usb_hub_child_detach,
    .wakeup = usb_hub_wakeup,
    .complete = usb_hub_complete,
};

static int usb_hub_initfn(USBDevice *dev)
{
    USBHubState *s = DO_UPCAST(USBHubState, dev, dev);
    USBHubPort *port;
    int i;

    usb_desc_init(dev);
    for (i = 0; i < NUM_PORTS; i++) {
        port = &s->ports[i];
        usb_register_port(usb_bus_from_device(dev),
                          &port->port, s, i, &usb_hub_port_ops,
                          USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL);
        usb_port_location(&port->port, dev->port, i+1);
        port->wPortStatus = PORT_STAT_POWER;
        port->wPortChange = 0;
    }
    return 0;
}

static struct USBDeviceInfo hub_info = {
    .product_desc   = "QEMU USB Hub",
    .qdev.name      = "usb-hub",
    .qdev.fw_name    = "hub",
    .qdev.size      = sizeof(USBHubState),
    .usb_desc       = &desc_hub,
    .init           = usb_hub_initfn,
    .handle_packet  = usb_hub_handle_packet,
    .handle_reset   = usb_hub_handle_reset,
    .handle_control = usb_hub_handle_control,
    .handle_data    = usb_hub_handle_data,
    .handle_destroy = usb_hub_handle_destroy,
};

static void usb_hub_register_devices(void)
{
    usb_qdev_register(&hub_info);
}
device_init(usb_hub_register_devices)

/*
 * QEMU USB HID devices
 */

/* HID interface requests */
#define GET_REPORT   0xa101
#define GET_IDLE     0xa102
#define GET_PROTOCOL 0xa103
#define SET_REPORT   0x2109
#define SET_IDLE     0x210a
#define SET_PROTOCOL 0x210b

/* HID descriptor types */
#define USB_DT_HID    0x21
#define USB_DT_REPORT 0x22
#define USB_DT_PHY    0x23

typedef struct USBHIDState {
    USBDevice dev;
    HIDState hid;
} USBHIDState;

enum {
    STR_MANUFACTURER = 1,
    STR_PRODUCT_MOUSE,
    STR_PRODUCT_TABLET,
    STR_PRODUCT_KEYBOARD,
    STR_SERIALNUMBER,
    STR_CONFIG_MOUSE,
    STR_CONFIG_TABLET,
    STR_CONFIG_KEYBOARD,
};

static const USBDescStrings desc_strings = {
    [STR_MANUFACTURER]     = "QEMU 1.0",
    [STR_PRODUCT_MOUSE]    = "QEMU USB Mouse",
    [STR_PRODUCT_TABLET]   = "QEMU USB Tablet",
    [STR_PRODUCT_KEYBOARD] = "QEMU USB Keyboard",
    [STR_SERIALNUMBER]     = "42", /* == remote wakeup works */
    [STR_CONFIG_MOUSE]     = "HID Mouse",
    [STR_CONFIG_TABLET]    = "HID Tablet",
    [STR_CONFIG_KEYBOARD]  = "HID Keyboard",
};

static const USBDescIface desc_iface_mouse = {
    .bInterfaceNumber              = 0,
    .bNumEndpoints                 = 1,
    .bInterfaceClass               = USB_CLASS_HID,
    .bInterfaceSubClass            = 0x01, /* boot */
    .bInterfaceProtocol            = 0x02,
    .ndesc                         = 1,
    .descs = (USBDescOther[]) {
        {
            /* HID descriptor */
            .data = (uint8_t[]) {
                0x09,          /*  u8  bLength */
                USB_DT_HID,    /*  u8  bDescriptorType */
                0x01, 0x00,    /*  u16 HID_class */
                0x00,          /*  u8  country_code */
                0x01,          /*  u8  num_descriptors */
                USB_DT_REPORT, /*  u8  type: Report */
                52, 0,         /*  u16 len */
            },
        },
    },
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress      = USB_DIR_IN | 0x01,
            .bmAttributes          = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize        = 4,
            .bInterval             = 0x0a,
        },
    },
};

static const USBDescIface desc_iface_tablet = {
    .bInterfaceNumber              = 0,
    .bNumEndpoints                 = 1,
    .bInterfaceClass               = USB_CLASS_HID,
    .bInterfaceProtocol            = 0x02,
    .ndesc                         = 1,
    .descs = (USBDescOther[]) {
        {
            /* HID descriptor */
            .data = (uint8_t[]) {
                0x09,          /*  u8  bLength */
                USB_DT_HID,    /*  u8  bDescriptorType */
                0x01, 0x00,    /*  u16 HID_class */
                0x00,          /*  u8  country_code */
                0x01,          /*  u8  num_descriptors */
                USB_DT_REPORT, /*  u8  type: Report */
                74, 0,         /*  u16 len */
            },
        },
    },
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress      = USB_DIR_IN | 0x01,
            .bmAttributes          = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize        = 8,
            .bInterval             = 0x0a,
        },
    },
};

static const USBDescIface desc_iface_keyboard = {
    .bInterfaceNumber              = 0,
    .bNumEndpoints                 = 1,
    .bInterfaceClass               = USB_CLASS_HID,
    .bInterfaceSubClass            = 0x01, /* boot */
    .bInterfaceProtocol            = 0x01, /* keyboard */
    .ndesc                         = 1,
    .descs = (USBDescOther[]) {
        {
            /* HID descriptor */
            .data = (uint8_t[]) {
                0x09,          /*  u8  bLength */
                USB_DT_HID,    /*  u8  bDescriptorType */
                0x11, 0x01,    /*  u16 HID_class */
                0x00,          /*  u8  country_code */
                0x01,          /*  u8  num_descriptors */
                USB_DT_REPORT, /*  u8  type: Report */
                0x3f, 0,       /*  u16 len */
            },
        },
    },
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress      = USB_DIR_IN | 0x01,
            .bmAttributes          = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize        = 8,
            .bInterval             = 0x0a,
        },
    },
};

static const USBDescDevice desc_device_mouse = {
    .bcdUSB                        = 0x0100,
    .bMaxPacketSize0               = 8,
    .bNumConfigurations            = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 1,
            .bConfigurationValue   = 1,
            .iConfiguration        = STR_CONFIG_MOUSE,
            .bmAttributes          = 0xa0,
            .bMaxPower             = 50,
            .nif = 1,
            .ifs = &desc_iface_mouse,
        },
    },
};

static const USBDescDevice desc_device_tablet = {
    .bcdUSB                        = 0x0100,
    .bMaxPacketSize0               = 8,
    .bNumConfigurations            = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 1,
            .bConfigurationValue   = 1,
            .iConfiguration        = STR_CONFIG_TABLET,
            .bmAttributes          = 0xa0,
            .bMaxPower             = 50,
            .nif = 1,
            .ifs = &desc_iface_tablet,
        },
    },
};

static const USBDescDevice desc_device_keyboard = {
    .bcdUSB                        = 0x0100,
    .bMaxPacketSize0               = 8,
    .bNumConfigurations            = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 1,
            .bConfigurationValue   = 1,
            .iConfiguration        = STR_CONFIG_KEYBOARD,
            .bmAttributes          = 0xa0,
            .bMaxPower             = 50,
            .nif = 1,
            .ifs = &desc_iface_keyboard,
        },
    },
};

static const USBDesc desc_mouse = {
    .id = {
        .idVendor          = 0x0627,
        .idProduct         = 0x0001,
        .bcdDevice         = 0,
        .iManufacturer     = STR_MANUFACTURER,
        .iProduct          = STR_PRODUCT_MOUSE,
        .iSerialNumber     = STR_SERIALNUMBER,
    },
    .full = &desc_device_mouse,
    .str  = desc_strings,
};

static const USBDesc desc_tablet = {
    .id = {
        .idVendor          = 0x0627,
        .idProduct         = 0x0001,
        .bcdDevice         = 0,
        .iManufacturer     = STR_MANUFACTURER,
        .iProduct          = STR_PRODUCT_TABLET,
        .iSerialNumber     = STR_SERIALNUMBER,
    },
    .full = &desc_device_tablet,
    .str  = desc_strings,
};

static const USBDesc desc_keyboard = {
    .id = {
        .idVendor          = 0x0627,
        .idProduct         = 0x0001,
        .bcdDevice         = 0,
        .iManufacturer     = STR_MANUFACTURER,
        .iProduct          = STR_PRODUCT_KEYBOARD,
        .iSerialNumber     = STR_SERIALNUMBER,
    },
    .full = &desc_device_keyboard,
    .str  = desc_strings,
};

static const uint8_t qemu_mouse_hid_report_descriptor[] = {
    0x05, 0x01,		/* Usage Page (Generic Desktop) */
    0x09, 0x02,		/* Usage (Mouse) */
    0xa1, 0x01,		/* Collection (Application) */
    0x09, 0x01,		/*   Usage (Pointer) */
    0xa1, 0x00,		/*   Collection (Physical) */
    0x05, 0x09,		/*     Usage Page (Button) */
    0x19, 0x01,		/*     Usage Minimum (1) */
    0x29, 0x03,		/*     Usage Maximum (3) */
    0x15, 0x00,		/*     Logical Minimum (0) */
    0x25, 0x01,		/*     Logical Maximum (1) */
    0x95, 0x03,		/*     Report Count (3) */
    0x75, 0x01,		/*     Report Size (1) */
    0x81, 0x02,		/*     Input (Data, Variable, Absolute) */
    0x95, 0x01,		/*     Report Count (1) */
    0x75, 0x05,		/*     Report Size (5) */
    0x81, 0x01,		/*     Input (Constant) */
    0x05, 0x01,		/*     Usage Page (Generic Desktop) */
    0x09, 0x30,		/*     Usage (X) */
    0x09, 0x31,		/*     Usage (Y) */
    0x09, 0x38,		/*     Usage (Wheel) */
    0x15, 0x81,		/*     Logical Minimum (-0x7f) */
    0x25, 0x7f,		/*     Logical Maximum (0x7f) */
    0x75, 0x08,		/*     Report Size (8) */
    0x95, 0x03,		/*     Report Count (3) */
    0x81, 0x06,		/*     Input (Data, Variable, Relative) */
    0xc0,		/*   End Collection */
    0xc0,		/* End Collection */
};

static const uint8_t qemu_tablet_hid_report_descriptor[] = {
    0x05, 0x01,		/* Usage Page (Generic Desktop) */
    0x09, 0x01,		/* Usage (Pointer) */
    0xa1, 0x01,		/* Collection (Application) */
    0x09, 0x01,		/*   Usage (Pointer) */
    0xa1, 0x00,		/*   Collection (Physical) */
    0x05, 0x09,		/*     Usage Page (Button) */
    0x19, 0x01,		/*     Usage Minimum (1) */
    0x29, 0x03,		/*     Usage Maximum (3) */
    0x15, 0x00,		/*     Logical Minimum (0) */
    0x25, 0x01,		/*     Logical Maximum (1) */
    0x95, 0x03,		/*     Report Count (3) */
    0x75, 0x01,		/*     Report Size (1) */
    0x81, 0x02,		/*     Input (Data, Variable, Absolute) */
    0x95, 0x01,		/*     Report Count (1) */
    0x75, 0x05,		/*     Report Size (5) */
    0x81, 0x01,		/*     Input (Constant) */
    0x05, 0x01,		/*     Usage Page (Generic Desktop) */
    0x09, 0x30,		/*     Usage (X) */
    0x09, 0x31,		/*     Usage (Y) */
    0x15, 0x00,		/*     Logical Minimum (0) */
    0x26, 0xff, 0x7f,	/*     Logical Maximum (0x7fff) */
    0x35, 0x00,		/*     Physical Minimum (0) */
    0x46, 0xff, 0x7f,	/*     Physical Maximum (0x7fff) */
    0x75, 0x10,		/*     Report Size (16) */
    0x95, 0x02,		/*     Report Count (2) */
    0x81, 0x02,		/*     Input (Data, Variable, Absolute) */
    0x05, 0x01,		/*     Usage Page (Generic Desktop) */
    0x09, 0x38,		/*     Usage (Wheel) */
    0x15, 0x81,		/*     Logical Minimum (-0x7f) */
    0x25, 0x7f,		/*     Logical Maximum (0x7f) */
    0x35, 0x00,		/*     Physical Minimum (same as logical) */
    0x45, 0x00,		/*     Physical Maximum (same as logical) */
    0x75, 0x08,		/*     Report Size (8) */
    0x95, 0x01,		/*     Report Count (1) */
    0x81, 0x06,		/*     Input (Data, Variable, Relative) */
    0xc0,		/*   End Collection */
    0xc0,		/* End Collection */
};

static const uint8_t qemu_keyboard_hid_report_descriptor[] = {
    0x05, 0x01,		/* Usage Page (Generic Desktop) */
    0x09, 0x06,		/* Usage (Keyboard) */
    0xa1, 0x01,		/* Collection (Application) */
    0x75, 0x01,		/*   Report Size (1) */
    0x95, 0x08,		/*   Report Count (8) */
    0x05, 0x07,		/*   Usage Page (Key Codes) */
    0x19, 0xe0,		/*   Usage Minimum (224) */
    0x29, 0xe7,		/*   Usage Maximum (231) */
    0x15, 0x00,		/*   Logical Minimum (0) */
    0x25, 0x01,		/*   Logical Maximum (1) */
    0x81, 0x02,		/*   Input (Data, Variable, Absolute) */
    0x95, 0x01,		/*   Report Count (1) */
    0x75, 0x08,		/*   Report Size (8) */
    0x81, 0x01,		/*   Input (Constant) */
    0x95, 0x05,		/*   Report Count (5) */
    0x75, 0x01,		/*   Report Size (1) */
    0x05, 0x08,		/*   Usage Page (LEDs) */
    0x19, 0x01,		/*   Usage Minimum (1) */
    0x29, 0x05,		/*   Usage Maximum (5) */
    0x91, 0x02,		/*   Output (Data, Variable, Absolute) */
    0x95, 0x01,		/*   Report Count (1) */
    0x75, 0x03,		/*   Report Size (3) */
    0x91, 0x01,		/*   Output (Constant) */
    0x95, 0x06,		/*   Report Count (6) */
    0x75, 0x08,		/*   Report Size (8) */
    0x15, 0x00,		/*   Logical Minimum (0) */
    0x25, 0xff,		/*   Logical Maximum (255) */
    0x05, 0x07,		/*   Usage Page (Key Codes) */
    0x19, 0x00,		/*   Usage Minimum (0) */
    0x29, 0xff,		/*   Usage Maximum (255) */
    0x81, 0x00,		/*   Input (Data, Array) */
    0xc0,		/* End Collection */
};

static void usb_hid_changed(HIDState *hs)
{
    USBHIDState *us = container_of(hs, USBHIDState, hid);

    usb_wakeup(&us->dev);
}

static void usb_hid_handle_reset(USBDevice *dev)
{
    USBHIDState *us = DO_UPCAST(USBHIDState, dev, dev);

    hid_reset(&us->hid);
}

static int usb_hid_handle_control(USBDevice *dev, USBPacket *p,
               int request, int value, int index, int length, uint8_t *data)
{
    USBHIDState *us = DO_UPCAST(USBHIDState, dev, dev);
    HIDState *hs = &us->hid;
    int ret;

    ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
    if (ret >= 0) {
        return ret;
    }

    ret = 0;
    switch (request) {
    case DeviceRequest | USB_REQ_GET_INTERFACE:
        data[0] = 0;
        ret = 1;
        break;
    case DeviceOutRequest | USB_REQ_SET_INTERFACE:
        ret = 0;
        break;
        /* hid specific requests */
    case InterfaceRequest | USB_REQ_GET_DESCRIPTOR:
        switch (value >> 8) {
        case 0x22:
            if (hs->kind == HID_MOUSE) {
		memcpy(data, qemu_mouse_hid_report_descriptor,
		       sizeof(qemu_mouse_hid_report_descriptor));
		ret = sizeof(qemu_mouse_hid_report_descriptor);
            } else if (hs->kind == HID_TABLET) {
                memcpy(data, qemu_tablet_hid_report_descriptor,
		       sizeof(qemu_tablet_hid_report_descriptor));
		ret = sizeof(qemu_tablet_hid_report_descriptor);
            } else if (hs->kind == HID_KEYBOARD) {
                memcpy(data, qemu_keyboard_hid_report_descriptor,
                       sizeof(qemu_keyboard_hid_report_descriptor));
                ret = sizeof(qemu_keyboard_hid_report_descriptor);
            }
            break;
        default:
            goto fail;
        }
        break;
    case GET_REPORT:
        if (hs->kind == HID_MOUSE || hs->kind == HID_TABLET) {
            ret = hid_pointer_poll(hs, data, length);
        } else if (hs->kind == HID_KEYBOARD) {
            ret = hid_keyboard_poll(hs, data, length);
        }
        break;
    case SET_REPORT:
        if (hs->kind == HID_KEYBOARD) {
            ret = hid_keyboard_write(hs, data, length);
        } else {
            goto fail;
        }
        break;
    case GET_PROTOCOL:
        if (hs->kind != HID_KEYBOARD && hs->kind != HID_MOUSE) {
            goto fail;
        }
        ret = 1;
        data[0] = hs->protocol;
        break;
    case SET_PROTOCOL:
        if (hs->kind != HID_KEYBOARD && hs->kind != HID_MOUSE) {
            goto fail;
        }
        ret = 0;
        hs->protocol = value;
        break;
    case GET_IDLE:
        ret = 1;
        data[0] = hs->idle;
        break;
    case SET_IDLE:
        hs->idle = (uint8_t) (value >> 8);
        hid_set_next_idle(hs, qemu_get_clock_ns(vm_clock));
        if (hs->kind == HID_MOUSE || hs->kind == HID_TABLET) {
            hid_pointer_activate(hs);
        }
        ret = 0;
        break;
    default:
    fail:
        ret = USB_RET_STALL;
        break;
    }
    return ret;
}

static int usb_hid_handle_data(USBDevice *dev, USBPacket *p)
{
    USBHIDState *us = DO_UPCAST(USBHIDState, dev, dev);
    HIDState *hs = &us->hid;
    uint8_t buf[p->iov.size];
    int ret = 0;

    switch (p->pid) {
    case USB_TOKEN_IN:
        if (p->devep == 1) {
            int64_t curtime = qemu_get_clock_ns(vm_clock);
            if (!hid_has_events(hs) &&
                (!hs->idle || hs->next_idle_clock - curtime > 0)) {
                return USB_RET_NAK;
            }
            hid_set_next_idle(hs, curtime);
            if (hs->kind == HID_MOUSE || hs->kind == HID_TABLET) {
                ret = hid_pointer_poll(hs, buf, p->iov.size);
            } else if (hs->kind == HID_KEYBOARD) {
                ret = hid_keyboard_poll(hs, buf, p->iov.size);
            }
            usb_packet_copy(p, buf, ret);
        } else {
            goto fail;
        }
        break;
    case USB_TOKEN_OUT:
    default:
    fail:
        ret = USB_RET_STALL;
        break;
    }
    return ret;
}

static void usb_hid_handle_destroy(USBDevice *dev)
{
    USBHIDState *us = DO_UPCAST(USBHIDState, dev, dev);

    hid_free(&us->hid);
}

static int usb_hid_initfn(USBDevice *dev, int kind)
{
    USBHIDState *us = DO_UPCAST(USBHIDState, dev, dev);

    usb_desc_init(dev);
    hid_init(&us->hid, kind, usb_hid_changed);
    return 0;
}

static int usb_tablet_initfn(USBDevice *dev)
{
    return usb_hid_initfn(dev, HID_TABLET);
}

static int usb_mouse_initfn(USBDevice *dev)
{
    return usb_hid_initfn(dev, HID_MOUSE);
}

static int usb_keyboard_initfn(USBDevice *dev)
{
    return usb_hid_initfn(dev, HID_KEYBOARD);
}

static struct USBDeviceInfo hid_info[] = {
    {
        .product_desc   = "QEMU USB Tablet",
        .qdev.name      = "usb-tablet",
        .usbdevice_name = "tablet",
        .qdev.size      = sizeof(USBHIDState),
        .usb_desc       = &desc_tablet,
        .init           = usb_tablet_initfn,
        .handle_packet  = usb_generic_handle_packet,
        .handle_reset   = usb_hid_handle_reset,
        .handle_control = usb_hid_handle_control,
        .handle_data    = usb_hid_handle_data,
        .handle_destroy = usb_hid_handle_destroy,
    },{
        .product_desc   = "QEMU USB Mouse",
        .qdev.name      = "usb-mouse",
        .usbdevice_name = "mouse",
        .qdev.size      = sizeof(USBHIDState),
        .usb_desc       = &desc_mouse,
        .init           = usb_mouse_initfn,
        .handle_packet  = usb_generic_handle_packet,
        .handle_reset   = usb_hid_handle_reset,
        .handle_control = usb_hid_handle_control,
        .handle_data    = usb_hid_handle_data,
        .handle_destroy = usb_hid_handle_destroy,
    },{
        .product_desc   = "QEMU USB Keyboard",
        .qdev.name      = "usb-kbd",
        .usbdevice_name = "keyboard",
        .qdev.size      = sizeof(USBHIDState),
        .usb_desc       = &desc_keyboard,
        .init           = usb_keyboard_initfn,
        .handle_packet  = usb_generic_handle_packet,
        .handle_reset   = usb_hid_handle_reset,
        .handle_control = usb_hid_handle_control,
        .handle_data    = usb_hid_handle_data,
        .handle_destroy = usb_hid_handle_destroy,
    },{
        /* end of list */
    }
};

static void usb_hid_register_devices(void)
{
    usb_qdev_register_many(hid_info);
}
device_init(usb_hid_register_devices)

static char *usb_get_dev_path(DeviceState *dev);
static char *usb_get_fw_dev_path(DeviceState *qdev);

static struct BusInfo usb_bus_info = {
    .name      = "USB",
    .size      = sizeof(USBBus),
    .get_dev_path = usb_get_dev_path,
    .get_fw_dev_path = usb_get_fw_dev_path,
    .props      = (Property[]) {
        DEFINE_PROP_STRING("port", USBDevice, port_path),
        DEFINE_PROP_END_OF_LIST()
    },
};
static int next_usb_bus = 0;
static QTAILQ_HEAD(, USBBus) busses = QTAILQ_HEAD_INITIALIZER(busses);

void usb_bus_new(USBBus *bus, USBBusOps *ops, DeviceState *host)
{
    qbus_create_inplace(&bus->qbus, &usb_bus_info, host, NULL);
    bus->ops = ops;
    bus->busnr = next_usb_bus++;
    bus->qbus.allow_hotplug = 1; /* Yes, we can */
    QTAILQ_INIT(&bus->free);
    QTAILQ_INIT(&bus->used);
    QTAILQ_INSERT_TAIL(&busses, bus, next);
}

USBBus *usb_bus_find(int busnr)
{
    USBBus *bus;

    if (-1 == busnr)
        return QTAILQ_FIRST(&busses);
    QTAILQ_FOREACH(bus, &busses, next) {
        if (bus->busnr == busnr)
            return bus;
    }
    return NULL;
}

static int usb_qdev_init(DeviceState *qdev, DeviceInfo *base)
{
    USBDevice *dev = DO_UPCAST(USBDevice, qdev, qdev);
    USBDeviceInfo *info = DO_UPCAST(USBDeviceInfo, qdev, base);
    int rc;

    pstrcpy(dev->product_desc, sizeof(dev->product_desc), info->product_desc);
    dev->info = info;
    dev->auto_attach = 1;
    QLIST_INIT(&dev->strings);
    rc = usb_claim_port(dev);
    if (rc == 0) {
        rc = dev->info->init(dev);
    }
    if (rc == 0 && dev->auto_attach) {
        rc = usb_device_attach(dev);
    }
    return rc;
}

static int usb_qdev_exit(DeviceState *qdev)
{
    USBDevice *dev = DO_UPCAST(USBDevice, qdev, qdev);

    if (dev->attached) {
        usb_device_detach(dev);
    }
    if (dev->info->handle_destroy) {
        dev->info->handle_destroy(dev);
    }
    if (dev->port) {
        usb_release_port(dev);
    }
    return 0;
}

void usb_qdev_register(USBDeviceInfo *info)
{
    info->qdev.bus_info = &usb_bus_info;
    info->qdev.init     = usb_qdev_init;
    info->qdev.unplug   = qdev_simple_unplug_cb;
    info->qdev.exit     = usb_qdev_exit;
    qdev_register(&info->qdev);
}

void usb_qdev_register_many(USBDeviceInfo *info)
{
    while (info->qdev.name) {
        usb_qdev_register(info);
        info++;
    }
}

USBDevice *usb_create(USBBus *bus, const char *name)
{
    DeviceState *dev;

    /* temporary stopgap until all usb is properly qdev-ified */
    if (!bus) {
        bus = usb_bus_find(-1);
        if (!bus)
            return NULL;
        printf("%s: no bus specified, using \"%s\" for \"%s\"\n",
                __FUNCTION__, bus->qbus.name, name);
    }

    dev = qdev_create(&bus->qbus, name);
    return DO_UPCAST(USBDevice, qdev, dev);
}

USBDevice *usb_create_simple(USBBus *bus, const char *name)
{
    USBDevice *dev = usb_create(bus, name);
    if (!dev) {
        hw_error("Failed to create USB device '%s'\n", name);
    }
    qdev_init_nofail(&dev->qdev);
    return dev;
}

static void usb_fill_port(USBPort *port, void *opaque, int index,
                          USBPortOps *ops, int speedmask)
{
    port->opaque = opaque;
    port->index = index;
    port->ops = ops;
    port->speedmask = speedmask;
    usb_port_location(port, NULL, index + 1);
}

void usb_register_port(USBBus *bus, USBPort *port, void *opaque, int index,
                       USBPortOps *ops, int speedmask)
{
    usb_fill_port(port, opaque, index, ops, speedmask);
    QTAILQ_INSERT_TAIL(&bus->free, port, next);
    bus->nfree++;
}

int usb_register_companion(const char *masterbus, USBPort *ports[],
                           uint32_t portcount, uint32_t firstport,
                           void *opaque, USBPortOps *ops, int speedmask)
{
    USBBus *bus;
    int i;

    QTAILQ_FOREACH(bus, &busses, next) {
        if (strcmp(bus->qbus.name, masterbus) == 0) {
            break;
        }
    }

    if (!bus || !bus->ops->register_companion) {
        printf("QERR_INVALID_PARAMETER_VALUE, masterbus, an USB masterbus\n");
        if (bus) {
            printf("USB bus '%s' does not allow companion controllers\n", masterbus);
        }
        return -1;
    }

    for (i = 0; i < portcount; i++) {
        usb_fill_port(ports[i], opaque, i, ops, speedmask);
    }

    return bus->ops->register_companion(bus, ports, portcount, firstport);
}

void usb_port_location(USBPort *downstream, USBPort *upstream, int portnr)
{
    if (upstream) {
        snprintf(downstream->path, sizeof(downstream->path), "%s.%d",
                 upstream->path, portnr);
    } else {
        snprintf(downstream->path, sizeof(downstream->path), "%d", portnr);
    }
}

void usb_unregister_port(USBBus *bus, USBPort *port)
{
    if (port->dev)
        qdev_free(&port->dev->qdev);
    QTAILQ_REMOVE(&bus->free, port, next);
    bus->nfree--;
}

int usb_claim_port(USBDevice *dev)
{
    USBBus *bus = usb_bus_from_device(dev);
    USBPort *port;

    assert(dev->port == NULL);

    if (dev->port_path) {
        QTAILQ_FOREACH(port, &bus->free, next) {
            if (strcmp(port->path, dev->port_path) == 0) {
                break;
            }
        }
        if (port == NULL) {
            printf("Error: usb port %s (bus %s) not found (in use?)\n",
                         dev->port_path, bus->qbus.name);
            return -1;
        }
    } else {
        if (bus->nfree == 1 && strcmp(dev->qdev.info->name, "usb-hub") != 0) {
            /* Create a new hub and chain it on */
            usb_create_simple(bus, "usb-hub");
        }
        if (bus->nfree == 0) {
            printf("Error: tried to attach usb device %s to a bus "
                         "with no free ports\n", dev->product_desc);
            return -1;
        }
        port = QTAILQ_FIRST(&bus->free);
    }
    QTAILQ_REMOVE(&bus->free, port, next);
    bus->nfree--;

    dev->port = port;
    port->dev = dev;

    QTAILQ_INSERT_TAIL(&bus->used, port, next);
    bus->nused++;
    return 0;
}

void usb_release_port(USBDevice *dev)
{
    USBBus *bus = usb_bus_from_device(dev);
    USBPort *port = dev->port;

    assert(port != NULL);

    QTAILQ_REMOVE(&bus->used, port, next);
    bus->nused--;

    dev->port = NULL;
    port->dev = NULL;

    QTAILQ_INSERT_TAIL(&bus->free, port, next);
    bus->nfree++;
}

int usb_device_attach(USBDevice *dev)
{
    USBBus *bus = usb_bus_from_device(dev);
    USBPort *port = dev->port;

    assert(port != NULL);
    assert(!dev->attached);

    if (!(port->speedmask & dev->speedmask)) {
        printf("Warning: speed mismatch trying to attach "
                     "usb device %s to bus %s\n",
                     dev->product_desc, bus->qbus.name);
        return -1;
    }

    dev->attached++;
    usb_attach(port);

    return 0;
}

int usb_device_detach(USBDevice *dev)
{
    USBPort *port = dev->port;

    assert(port != NULL);
    assert(dev->attached);

    usb_detach(port);
    dev->attached--;
    return 0;
}

int usb_device_delete_addr(int busnr, int addr)
{
    USBBus *bus;
    USBPort *port;
    USBDevice *dev;

    bus = usb_bus_find(busnr);
    if (!bus)
        return -1;

    QTAILQ_FOREACH(port, &bus->used, next) {
        if (port->dev->addr == addr)
            break;
    }
    if (!port)
        return -1;
    dev = port->dev;

    qdev_free(&dev->qdev);
    return 0;
}

static char *usb_get_dev_path(DeviceState *qdev)
{
    USBDevice *dev = DO_UPCAST(USBDevice, qdev, qdev);
    return strdup(dev->port->path);
}

static char *usb_get_fw_dev_path(DeviceState *qdev)
{
    USBDevice *dev = DO_UPCAST(USBDevice, qdev, qdev);
    char *fw_path, *in;
    ssize_t pos = 0, fw_len;
    long nr;

    fw_len = 32 + strlen(dev->port->path) * 6;
    fw_path = malloc(fw_len);
    in = dev->port->path;
    while (fw_len - pos > 0) {
        nr = strtol(in, &in, 10);
        if (in[0] == '.') {
            /* some hub between root port and device */
            pos += snprintf(fw_path + pos, fw_len - pos, "hub@%ld/", nr);
            in++;
        } else {
            /* the device itself */
            pos += snprintf(fw_path + pos, fw_len - pos, "%s@%ld",
                            qdev_fw_name(qdev), nr);
            break;
        }
    }
    return fw_path;
}

/* handle legacy -usbdevice cmd line option */
int usbdevice_create(const char *cmdline)
{
    USBBus *bus = usb_bus_find(-1 /* any */);
    DeviceInfo *info;
    USBDeviceInfo *usb;
    char driver[32];
    const char *params;
    int len;

    params = strchr(cmdline,':');
    if (params) {
        params++;
        len = params - cmdline;
        if (len > sizeof(driver))
            len = sizeof(driver);
        pstrcpy(driver, len, cmdline);
    } else {
        params = "";
        pstrcpy(driver, sizeof(driver), cmdline);
    }

    for (info = device_info_list; info != NULL; info = info->next) {
        if (info->bus_info != &usb_bus_info)
            continue;
        usb = DO_UPCAST(USBDeviceInfo, qdev, info);
        if (usb->usbdevice_name == NULL)
            continue;
        if (strcmp(usb->usbdevice_name, driver) != 0)
            continue;
        break;
    }
    if (info == NULL) {
        return -1;
    }

    if (!usb->usbdevice_init) {
        if (*params) {
            printf("usbdevice %s accepts no params", driver);
            return -1;
        }
        if (usb_create_simple(bus, usb->qdev.name)==NULL)
			return -1;
		return 0;
    }
    if (usb->usbdevice_init(params)==NULL)
		return -1;
	return 0;
}
