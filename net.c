#include "net.h"
#include "qemu-common.h"
#include <arpa/inet.h>
#include "qdev.h"
#include "qemu-queue.h"
#include <errno.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <net/if.h>
#include "sysemu.h"

#define PATH_NET_TUN "/dev/net/tun"

#define PROTO_TCP  6
#define PROTO_UDP 17

uint32_t net_checksum_add(int len, uint8_t *buf)
{
    uint32_t sum = 0;
    int i;

    for (i = 0; i < len; i++) {
	if (i & 1)
	    sum += (uint32_t)buf[i];
	else
	    sum += (uint32_t)buf[i] << 8;
    }
    return sum;
}

uint16_t net_checksum_finish(uint32_t sum)
{
    while (sum>>16)
	sum = (sum & 0xFFFF)+(sum >> 16);
    return ~sum;
}

uint16_t net_checksum_tcpudp(uint16_t length, uint16_t proto,
                             uint8_t *addrs, uint8_t *buf)
{
    uint32_t sum = 0;

    sum += net_checksum_add(length, buf);         // payload
    sum += net_checksum_add(8, addrs);            // src + dst address
    sum += proto + length;                        // protocol & length
    return net_checksum_finish(sum);
}

struct NetPacket {
    QTAILQ_ENTRY(NetPacket) entry;
    VLANClientState *sender;
    unsigned flags;
    int size;
    NetPacketSent *sent_cb;
    uint8_t data[0];
};

struct NetQueue {
    NetPacketDeliver *deliver;
    NetPacketDeliverIOV *deliver_iov;
    void *opaque;

    QTAILQ_HEAD(packets, NetPacket) packets;

    unsigned delivering : 1;
};

static QTAILQ_HEAD(, VLANState) vlans;
static QTAILQ_HEAD(, VLANClientState) non_vlan_clients;

/***********************************************************/
/* network device redirectors */
void qemu_format_nic_info_str(VLANClientState *vc, uint8_t macaddr[6])
{
    snprintf(vc->info_str, sizeof(vc->info_str),
             "model=%s,macaddr=%02x:%02x:%02x:%02x:%02x:%02x",
             vc->model,
             macaddr[0], macaddr[1], macaddr[2],
             macaddr[3], macaddr[4], macaddr[5]);
}

void qemu_macaddr_default_if_unset(MACAddr *macaddr)
{
    static int index = 0;
    static const MACAddr zero = { .a = { 0,0,0,0,0,0 } };

    if (memcmp(macaddr, &zero, sizeof(zero)) != 0)
        return;
    macaddr->a[0] = 0x52;
    macaddr->a[1] = 0x54;
    macaddr->a[2] = 0x00;
    macaddr->a[3] = 0x12;
    macaddr->a[4] = 0x34;
    macaddr->a[5] = 0x56 + index++;
}

static char *assign_name(VLANClientState *vc1, const char *model)
{
    VLANState *vlan;
    VLANClientState *vc;
    char buf[256];
    int id = 0;

    QTAILQ_FOREACH(vlan, &vlans, next) {
        QTAILQ_FOREACH(vc, &vlan->clients, next) {
            if (vc != vc1 && strcmp(vc->model, model) == 0) {
                id++;
            }
        }
    }

    QTAILQ_FOREACH(vc, &non_vlan_clients, next) {
        if (vc != vc1 && strcmp(vc->model, model) == 0) {
            id++;
        }
    }

    snprintf(buf, sizeof(buf), "%s.%d", model, id);

    return strdup(buf);
}

static ssize_t qemu_deliver_packet(VLANClientState *sender,
                                   unsigned flags,
                                   const uint8_t *data,
                                   size_t size,
                                   void *opaque);
static ssize_t qemu_deliver_packet_iov(VLANClientState *sender,
                                       unsigned flags,
                                       const struct iovec *iov,
                                       int iovcnt,
                                       void *opaque);

VLANClientState *qemu_new_net_client(NetClientInfo *info,
                                     VLANState *vlan,
                                     VLANClientState *peer,
                                     const char *model,
                                     const char *name)
{
    VLANClientState *vc;

    assert(info->size >= sizeof(VLANClientState));

    vc = calloc(1, info->size);

    vc->info = info;
    vc->model = strdup(model);
    if (name) {
        vc->name = strdup(name);
    } else {
        vc->name = assign_name(vc, model);
    }

    if (vlan) {
        assert(!peer);
        vc->vlan = vlan;
        QTAILQ_INSERT_TAIL(&vc->vlan->clients, vc, next);
    } else {
        if (peer) {
            assert(!peer->peer);
            vc->peer = peer;
            peer->peer = vc;
        }
printf("info6:%p\n", info);
        QTAILQ_INSERT_TAIL(&non_vlan_clients, vc, next);
printf("info7:%p\n", info);

        vc->send_queue = qemu_new_net_queue(qemu_deliver_packet,
                                            qemu_deliver_packet_iov,
                                            vc);
printf("info8:%p\n", info);
    }

    return vc;
}

NICState *qemu_new_nic(NetClientInfo *info,
                       NICConf *conf,
                       const char *model,
                       const char *name,
                       void *opaque)
{
    VLANClientState *nc;
    NICState *nic;

    assert(info->type == NET_CLIENT_TYPE_NIC);
    assert(info->size >= sizeof(NICState));

    nc = qemu_new_net_client(info, conf->vlan, conf->peer, model, name);

    nic = DO_UPCAST(NICState, nc, nc);
    nic->conf = conf;
    nic->opaque = opaque;

    return nic;
}

static void qemu_cleanup_vlan_client(VLANClientState *vc)
{
    if (vc->vlan) {
        QTAILQ_REMOVE(&vc->vlan->clients, vc, next);
    } else {
        QTAILQ_REMOVE(&non_vlan_clients, vc, next);
    }

    if (vc->info->cleanup) {
        vc->info->cleanup(vc);
    }
}

static void qemu_free_vlan_client(VLANClientState *vc)
{
    if (!vc->vlan) {
        if (vc->send_queue) {
            qemu_del_net_queue(vc->send_queue);
        }
        if (vc->peer) {
            vc->peer->peer = NULL;
        }
    }
    free(vc->name);
    vc->name = NULL;
    free(vc->model);
    vc->model = NULL;
    free(vc);
    vc = NULL;
}

void qemu_del_vlan_client(VLANClientState *vc)
{
    /* If there is a peer NIC, delete and cleanup client, but do not free. */
    if (!vc->vlan && vc->peer && vc->peer->info->type == NET_CLIENT_TYPE_NIC) {
        NICState *nic = DO_UPCAST(NICState, nc, vc->peer);
        if (nic->peer_deleted) {
            return;
        }
        nic->peer_deleted = true;
        /* Let NIC know peer is gone. */
        vc->peer->link_down = true;
        if (vc->peer->info->link_status_changed) {
            vc->peer->info->link_status_changed(vc->peer);
        }
        qemu_cleanup_vlan_client(vc);
        return;
    }

    /* If this is a peer NIC and peer has already been deleted, free it now. */
    if (!vc->vlan && vc->peer && vc->info->type == NET_CLIENT_TYPE_NIC) {
        NICState *nic = DO_UPCAST(NICState, nc, vc);
        if (nic->peer_deleted) {
            qemu_free_vlan_client(vc->peer);
        }
    }

    qemu_cleanup_vlan_client(vc);
    qemu_free_vlan_client(vc);
}

VLANClientState *
qemu_find_vlan_client_by_name(int vlan_id,
                              const char *client_str)
{
    VLANState *vlan;
    VLANClientState *vc;

    vlan = qemu_find_vlan(vlan_id, 0);
    if (!vlan) {
        printf("unknown VLAN %d\n", vlan_id);
        return NULL;
    }

    QTAILQ_FOREACH(vc, &vlan->clients, next) {
        if (!strcmp(vc->name, client_str)) {
            break;
        }
    }
    if (!vc) {
        printf("can't find device %s on VLAN %d\n",
                       client_str, vlan_id);
    }

    return vc;
}

void qemu_foreach_nic(qemu_nic_foreach func, void *opaque)
{
    VLANClientState *nc;
    VLANState *vlan;

    QTAILQ_FOREACH(nc, &non_vlan_clients, next) {
        if (nc->info->type == NET_CLIENT_TYPE_NIC) {
            func(DO_UPCAST(NICState, nc, nc), opaque);
        }
    }

    QTAILQ_FOREACH(vlan, &vlans, next) {
        QTAILQ_FOREACH(nc, &vlan->clients, next) {
            if (nc->info->type == NET_CLIENT_TYPE_NIC) {
                func(DO_UPCAST(NICState, nc, nc), opaque);
            }
        }
    }
}

int qemu_can_send_packet(VLANClientState *sender)
{
    VLANState *vlan = sender->vlan;
    VLANClientState *vc;

    if (sender->peer) {
        if (sender->peer->receive_disabled) {
            return 0;
        } else if (sender->peer->info->can_receive &&
                   !sender->peer->info->can_receive(sender->peer)) {
            return 0;
        } else {
            return 1;
        }
    }

    if (!sender->vlan) {
        return 1;
    }

    QTAILQ_FOREACH(vc, &vlan->clients, next) {
        if (vc == sender) {
            continue;
        }

        /* no can_receive() handler, they can always receive */
        if (vc->info->can_receive && !vc->info->can_receive(vc)) {
            return 0;
        }
    }
    return 1;
}

static ssize_t qemu_deliver_packet(VLANClientState *sender,
                                   unsigned flags,
                                   const uint8_t *data,
                                   size_t size,
                                   void *opaque)
{
    VLANClientState *vc = opaque;
    ssize_t ret;

    if (vc->link_down) {
        return size;
    }

    if (vc->receive_disabled) {
        return 0;
    }

    if (flags & QEMU_NET_PACKET_FLAG_RAW && vc->info->receive_raw) {
        ret = vc->info->receive_raw(vc, data, size);
    } else {
        ret = vc->info->receive(vc, data, size);
    }

    if (ret == 0) {
        vc->receive_disabled = 1;
    };

    return ret;
}

static ssize_t qemu_vlan_deliver_packet(VLANClientState *sender,
                                        unsigned flags,
                                        const uint8_t *buf,
                                        size_t size,
                                        void *opaque)
{
    VLANState *vlan = opaque;
    VLANClientState *vc;
    ssize_t ret = -1;

    QTAILQ_FOREACH(vc, &vlan->clients, next) {
        ssize_t len;

        if (vc == sender) {
            continue;
        }

        if (vc->link_down) {
            ret = size;
            continue;
        }

        if (vc->receive_disabled) {
            ret = 0;
            continue;
        }

        if (flags & QEMU_NET_PACKET_FLAG_RAW && vc->info->receive_raw) {
            len = vc->info->receive_raw(vc, buf, size);
        } else {
            len = vc->info->receive(vc, buf, size);
        }

        if (len == 0) {
            vc->receive_disabled = 1;
        }

        ret = (ret >= 0) ? ret : len;

    }

    return ret;
}

void qemu_purge_queued_packets(VLANClientState *vc)
{
    NetQueue *queue;

    if (!vc->peer && !vc->vlan) {
        return;
    }

    if (vc->peer) {
        queue = vc->peer->send_queue;
    } else {
        queue = vc->vlan->send_queue;
    }

    qemu_net_queue_purge(queue, vc);
}

void qemu_flush_queued_packets(VLANClientState *vc)
{
    NetQueue *queue;

    vc->receive_disabled = 0;

    if (vc->vlan) {
        queue = vc->vlan->send_queue;
    } else {
        queue = vc->send_queue;
    }

    qemu_net_queue_flush(queue);
}

static ssize_t qemu_send_packet_async_with_flags(VLANClientState *sender,
                                                 unsigned flags,
                                                 const uint8_t *buf, int size,
                                                 NetPacketSent *sent_cb)
{
    NetQueue *queue;

    if (sender->link_down || (!sender->peer && !sender->vlan)) {
        return size;
    }

    if (sender->peer) {
        queue = sender->peer->send_queue;
    } else {
        queue = sender->vlan->send_queue;
    }

    return qemu_net_queue_send(queue, sender, flags, buf, size, sent_cb);
}

ssize_t qemu_send_packet_async(VLANClientState *sender,
                               const uint8_t *buf, int size,
                               NetPacketSent *sent_cb)
{
    return qemu_send_packet_async_with_flags(sender, QEMU_NET_PACKET_FLAG_NONE,
                                             buf, size, sent_cb);
}

void qemu_send_packet(VLANClientState *vc, const uint8_t *buf, int size)
{
    qemu_send_packet_async(vc, buf, size, NULL);
}

ssize_t qemu_send_packet_raw(VLANClientState *vc, const uint8_t *buf, int size)
{
    return qemu_send_packet_async_with_flags(vc, QEMU_NET_PACKET_FLAG_RAW,
                                             buf, size, NULL);
}

static ssize_t vc_sendv_compat(VLANClientState *vc, const struct iovec *iov,
                               int iovcnt)
{
    uint8_t buffer[4096];
    size_t offset;

    offset = iov_to_buf(iov, iovcnt, buffer, 0, sizeof(buffer));

    return vc->info->receive(vc, buffer, offset);
}

static ssize_t qemu_deliver_packet_iov(VLANClientState *sender,
                                       unsigned flags,
                                       const struct iovec *iov,
                                       int iovcnt,
                                       void *opaque)
{
    VLANClientState *vc = opaque;

    if (vc->link_down) {
        return iov_size(iov, iovcnt);
    }

    if (vc->info->receive_iov) {
        return vc->info->receive_iov(vc, iov, iovcnt);
    } else {
        return vc_sendv_compat(vc, iov, iovcnt);
    }
}

static ssize_t qemu_vlan_deliver_packet_iov(VLANClientState *sender,
                                            unsigned flags,
                                            const struct iovec *iov,
                                            int iovcnt,
                                            void *opaque)
{
    VLANState *vlan = opaque;
    VLANClientState *vc;
    ssize_t ret = -1;

    QTAILQ_FOREACH(vc, &vlan->clients, next) {
        ssize_t len;

        if (vc == sender) {
            continue;
        }

        if (vc->link_down) {
            ret = iov_size(iov, iovcnt);
            continue;
        }

        assert(!(flags & QEMU_NET_PACKET_FLAG_RAW));

        if (vc->info->receive_iov) {
            len = vc->info->receive_iov(vc, iov, iovcnt);
        } else {
            len = vc_sendv_compat(vc, iov, iovcnt);
        }

        ret = (ret >= 0) ? ret : len;
    }

    return ret;
}

ssize_t qemu_sendv_packet_async(VLANClientState *sender,
                                const struct iovec *iov, int iovcnt,
                                NetPacketSent *sent_cb)
{
    NetQueue *queue;

    if (sender->link_down || (!sender->peer && !sender->vlan)) {
        return iov_size(iov, iovcnt);
    }

    if (sender->peer) {
        queue = sender->peer->send_queue;
    } else {
        queue = sender->vlan->send_queue;
    }

    return qemu_net_queue_send_iov(queue, sender,
                                   QEMU_NET_PACKET_FLAG_NONE,
                                   iov, iovcnt, sent_cb);
}

ssize_t
qemu_sendv_packet(VLANClientState *vc, const struct iovec *iov, int iovcnt)
{
    return qemu_sendv_packet_async(vc, iov, iovcnt, NULL);
}

/* find or alloc a new VLAN */
VLANState *qemu_find_vlan(int id, int allocate)
{
    VLANState *vlan;

    QTAILQ_FOREACH(vlan, &vlans, next) {
        if (vlan->id == id) {
            return vlan;
        }
    }

    if (!allocate) {
        return NULL;
    }

    vlan = calloc(1, sizeof(VLANState));
    vlan->id = id;
    QTAILQ_INIT(&vlan->clients);

    vlan->send_queue = qemu_new_net_queue(qemu_vlan_deliver_packet,
                                          qemu_vlan_deliver_packet_iov,
                                          vlan);

    QTAILQ_INSERT_TAIL(&vlans, vlan, next);

    return vlan;
}

VLANClientState *qemu_find_netdev(const char *id)
{
    VLANClientState *vc;

    QTAILQ_FOREACH(vc, &non_vlan_clients, next) {
        if (vc->info->type == NET_CLIENT_TYPE_NIC)
            continue;
        if (!strcmp(vc->name, id)) {
            return vc;
        }
    }

    return NULL;
}

int qemu_show_nic_models(const char *arg, const char *const *models)
{
    int i;

    if (!arg || strcmp(arg, "?"))
        return 0;

    fprintf(stderr, "qemu: Supported NIC models: ");
    for (i = 0 ; models[i]; i++)
        fprintf(stderr, "%s%c", models[i], models[i+1] ? ',' : '\n');
    return 1;
}

void qemu_check_nic_model(NICInfo *nd, const char *model)
{
    const char *models[2];

    models[0] = model;
    models[1] = NULL;

    if (qemu_show_nic_models(nd->model, models))
        exit(0);
    if (qemu_find_nic_model(nd, models, model) < 0)
        exit(1);
}

int qemu_find_nic_model(NICInfo *nd, const char * const *models,
                        const char *default_model)
{
    int i;

    if (!nd->model)
        nd->model = strdup(default_model);

    for (i = 0 ; models[i]; i++) {
        if (strcmp(nd->model, models[i]) == 0)
            return i;
    }

    printf("Unsupported NIC model: %s", nd->model);
    return -1;
}

static int net_init_nic(QemuOpts *opts,
                        const char *name,
                        VLANState *vlan)
{
    NICInfo *nd;
    const char *netdev;

    nd = &nd_table[0];

    memset(nd, 0, sizeof(*nd));

    if ((netdev = qemu_opt_get(opts, "netdev"))) {
        nd->netdev = qemu_find_netdev(netdev);
        if (!nd->netdev) {
            printf("netdev '%s' not found", netdev);
            return -1;
        }
    } else {
        assert(vlan);
        nd->vlan = vlan;
    }
    if (name) {
        nd->name = strdup(name);
    }
    if (qemu_opt_get(opts, "model")) {
        nd->model = strdup(qemu_opt_get(opts, "model"));
    }
    if (qemu_opt_get(opts, "addr")) {
        nd->devaddr = strdup(qemu_opt_get(opts, "addr"));
    }

    if (qemu_opt_get(opts, "macaddr") &&
        net_parse_macaddr(nd->macaddr.a, qemu_opt_get(opts, "macaddr")) < 0) {
        printf("invalid syntax for ethernet address");
        return -1;
    }
    qemu_macaddr_default_if_unset(&nd->macaddr);

    nd->nvectors = qemu_opt_get_number(opts, "vectors",
                                       DEV_NVECTORS_UNSPECIFIED);
    if (nd->nvectors != DEV_NVECTORS_UNSPECIFIED &&
        (nd->nvectors < 0 || nd->nvectors > 0x7ffffff)) {
        printf("invalid # of vectors: %d", nd->nvectors);
        return -1;
    }

    nd->used = 1;

    return 0;
}

#define NET_COMMON_PARAMS_DESC                     \
    {                                              \
        .name = "type",                            \
        .type = QEMU_OPT_STRING,                   \
        .help = "net client type (nic, tap etc.)", \
     }, {                                          \
        .name = "vlan",                            \
        .type = QEMU_OPT_NUMBER,                   \
        .help = "vlan number",                     \
     }, {                                          \
        .name = "name",                            \
        .type = QEMU_OPT_STRING,                   \
        .help = "identifier for monitor commands", \
     }

typedef int (*net_client_init_func)(QemuOpts *opts,
                                    const char *name,
                                    VLANState *vlan);

/* magic number, but compiler will warn if too small */
#define NET_MAX_DESC 20

static const struct {
    const char *type;
    net_client_init_func init;
    QemuOptDesc desc[NET_MAX_DESC];
} net_client_types[NET_CLIENT_TYPE_MAX] = {
    [NET_CLIENT_TYPE_NONE] = {
        .type = "none",
        .desc = {
            NET_COMMON_PARAMS_DESC,
            { /* end of list */ }
        },
    },
    [NET_CLIENT_TYPE_NIC] = {
        .type = "nic",
        .init = net_init_nic,
        .desc = {
            NET_COMMON_PARAMS_DESC,
            {
                .name = "netdev",
                .type = QEMU_OPT_STRING,
                .help = "id of -netdev to connect to",
            },
            {
                .name = "macaddr",
                .type = QEMU_OPT_STRING,
                .help = "MAC address",
            }, {
                .name = "model",
                .type = QEMU_OPT_STRING,
                .help = "device model (e1000)",
            }, {
                .name = "addr",
                .type = QEMU_OPT_STRING,
                .help = "PCI device address",
            }, {
                .name = "vectors",
                .type = QEMU_OPT_NUMBER,
                .help = "number of MSI-x vectors, 0 to disable MSI-X",
            },
            { /* end of list */ }
        },
    },
    [NET_CLIENT_TYPE_TAP] = {
        .type = "tap",
        .init = net_init_tap,
        .desc = {
            NET_COMMON_PARAMS_DESC,
            {
                .name = "ifname",
                .type = QEMU_OPT_STRING,
                .help = "interface name",
            },
            {
                .name = "fd",
                .type = QEMU_OPT_STRING,
                .help = "file descriptor of an already opened tap",
            }, {
                .name = "script",
                .type = QEMU_OPT_STRING,
                .help = "script to initialize the interface",
            }, {
                .name = "downscript",
                .type = QEMU_OPT_STRING,
                .help = "script to shut down the interface",
            }, {
                .name = "sndbuf",
                .type = QEMU_OPT_SIZE,
                .help = "send buffer limit"
            }, {
                .name = "vnet_hdr",
                .type = QEMU_OPT_BOOL,
                .help = "enable the IFF_VNET_HDR flag on the tap interface"
            }, {
                .name = "vhost",
                .type = QEMU_OPT_BOOL,
                .help = "enable vhost-net network accelerator",
            }, {
                .name = "vhostfd",
                .type = QEMU_OPT_STRING,
                .help = "file descriptor of an already opened vhost net device",
            }, {
                .name = "vhostforce",
                .type = QEMU_OPT_BOOL,
                .help = "force vhost on for non-MSIX virtio guests",
        },
            { /* end of list */ }
        },
    },
};

int net_client_init(QemuOpts *opts, int is_netdev)
{
    const char *name;
    const char *type;
    int i;

    type = qemu_opt_get(opts, "type");
    if (!type) {
        printf("QERR_MISSING_PARAMETER type:%s\n", type);
        return -1;
    }

    if (is_netdev) {
        if (strcmp(type, "tap") != 0) {
            printf("QERR_INVALID_PARAMETER_VALUE, type:%s, a netdev backend type\n", type);
            return -1;
        }

        if (qemu_opt_get(opts, "vlan")) {
            printf("QERR_INVALID_PARAMETER, vlan\n");
            return -1;
        }
        if (qemu_opt_get(opts, "name")) {
            printf("QERR_INVALID_PARAMETER, name\n");
            return -1;
        }
        if (!qemu_opts_id(opts)) {
            printf("QERR_MISSING_PARAMETER, id\n");
            return -1;
        }
    }

    name = qemu_opts_id(opts);
    if (!name) {
        name = qemu_opt_get(opts, "name");
    }

    for (i = 0; i < NET_CLIENT_TYPE_MAX; i++) {
        if (net_client_types[i].type != NULL &&
            !strcmp(net_client_types[i].type, type)) {
            VLANState *vlan = NULL;
            int ret;

            if (qemu_opts_validate(opts, &net_client_types[i].desc[0]) == -1) {
                return -1;
            }

            /* Do not add to a vlan if it's a -netdev or a nic with a
             * netdev= parameter. */
            if (!(is_netdev ||
                  (strcmp(type, "nic") == 0 && qemu_opt_get(opts, "netdev")))) {
                vlan = qemu_find_vlan(qemu_opt_get_number(opts, "vlan", 0), 1);
            }

            ret = 0;
            if (net_client_types[i].init) {
                ret = net_client_types[i].init(opts, name, vlan);
                if (ret < 0) {
                    /* TODO push error reporting into init() methods */
                    printf("QERR_DEVICE_INIT_FAILED, type:%s\n", type);
                    return -1;
                }
            }
            return ret;
        }
    }

    printf("QERR_INVALID_PARAMETER_VALUE, type:%s, a network client type\n", type);
    return -1;
}

static int net_host_check_device(const char *device)
{
    int i;
    const char *valid_param_list[] = {"tap"};
    for (i = 0; i < sizeof(valid_param_list) / sizeof(char *); i++) {
        if (!strncmp(valid_param_list[i], device,
                     strlen(valid_param_list[i])))
            return 1;
    }

    return 0;
}

void net_cleanup(void)
{
    VLANState *vlan;
    VLANClientState *vc, *next_vc;

    QTAILQ_FOREACH(vlan, &vlans, next) {
        QTAILQ_FOREACH_SAFE(vc, &vlan->clients, next, next_vc) {
            qemu_del_vlan_client(vc);
        }
    }

    QTAILQ_FOREACH_SAFE(vc, &non_vlan_clients, next, next_vc) {
        qemu_del_vlan_client(vc);
    }
}

void net_check_clients(void)
{
    VLANState *vlan;
    VLANClientState *vc;
    NICInfo *nd = &nd_table[0];

    QTAILQ_FOREACH(vlan, &vlans, next) {
        int has_nic = 0, has_host_dev = 0;

        QTAILQ_FOREACH(vc, &vlan->clients, next) {
            switch (vc->info->type) {
            case NET_CLIENT_TYPE_NIC:
                has_nic = 1;
                break;
            case NET_CLIENT_TYPE_TAP:
                has_host_dev = 1;
                break;
            default: ;
            }
        }
        if (has_host_dev && !has_nic)
            fprintf(stderr, "Warning: vlan %d with no nics\n", vlan->id);
        if (has_nic && !has_host_dev)
            fprintf(stderr,
                    "Warning: vlan %d is not connected to host network\n",
                    vlan->id);
    }
    QTAILQ_FOREACH(vc, &non_vlan_clients, next) {
        if (!vc->peer) {
            fprintf(stderr, "Warning: %s %s has no peer\n",
                    vc->info->type == NET_CLIENT_TYPE_NIC ? "nic" : "netdev",
                    vc->name);
        }
    }

    if (nd->used && !nd->instantiated) {
        fprintf(stderr, "requested NIC (%s, model %s) was not created\n", nd->name ? nd->name : "anonymous", nd->model ? nd->model : "unspecified");
    }
}

static int net_init_client(QemuOpts *opts, void *dummy)
{
    if (net_client_init(opts, 0) < 0)
        return -1;
    return 0;
}

static int net_init_netdev(QemuOpts *opts, void *dummy)
{
    return net_client_init(opts, 1);
}

int net_init_clients(void)
{
    QemuOptsList *net = qemu_find_opts("net");

    QTAILQ_INIT(&vlans);
    QTAILQ_INIT(&non_vlan_clients);

    if (qemu_opts_foreach(net, net_init_client, NULL, 1) == -1) {
        return -1;
    }

    return 0;
}

int net_client_parse(QemuOptsList *opts_list, const char *optarg)
{
    if (!qemu_opts_parse(opts_list, optarg, 1)) {
        return -1;
    }

    return 0;
}

NetQueue *qemu_new_net_queue(NetPacketDeliver *deliver,
                             NetPacketDeliverIOV *deliver_iov,
                             void *opaque)
{
    NetQueue *queue;

    queue = calloc(1, sizeof(NetQueue));

    queue->deliver = deliver;
    queue->deliver_iov = deliver_iov;
    queue->opaque = opaque;

    QTAILQ_INIT(&queue->packets);

    queue->delivering = 0;

    return queue;
}

void qemu_del_net_queue(NetQueue *queue)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        QTAILQ_REMOVE(&queue->packets, packet, entry);
        free(packet);
        packet = NULL;
    }

    free(queue);
    queue = NULL;
}

static ssize_t qemu_net_queue_append(NetQueue *queue,
                                     VLANClientState *sender,
                                     unsigned flags,
                                     const uint8_t *buf,
                                     size_t size,
                                     NetPacketSent *sent_cb)
{
    NetPacket *packet;

    packet = malloc(sizeof(NetPacket) + size);
    packet->sender = sender;
    packet->flags = flags;
    packet->size = size;
    packet->sent_cb = sent_cb;
    memcpy(packet->data, buf, size);

    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);

    return size;
}

static ssize_t qemu_net_queue_append_iov(NetQueue *queue,
                                         VLANClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb)
{
    NetPacket *packet;
    size_t max_len = 0;
    int i;

    for (i = 0; i < iovcnt; i++) {
        max_len += iov[i].iov_len;
    }

    packet = malloc(sizeof(NetPacket) + max_len);
    packet->sender = sender;
    packet->sent_cb = sent_cb;
    packet->flags = flags;
    packet->size = 0;

    for (i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;

        memcpy(packet->data + packet->size, iov[i].iov_base, len);
        packet->size += len;
    }

    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);

    return packet->size;
}

static ssize_t qemu_net_queue_deliver(NetQueue *queue,
                                      VLANClientState *sender,
                                      unsigned flags,
                                      const uint8_t *data,
                                      size_t size)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = queue->deliver(sender, flags, data, size, queue->opaque);
    queue->delivering = 0;

    return ret;
}

static ssize_t qemu_net_queue_deliver_iov(NetQueue *queue,
                                          VLANClientState *sender,
                                          unsigned flags,
                                          const struct iovec *iov,
                                          int iovcnt)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = queue->deliver_iov(sender, flags, iov, iovcnt, queue->opaque);
    queue->delivering = 0;

    return ret;
}

ssize_t qemu_net_queue_send(NetQueue *queue,
                            VLANClientState *sender,
                            unsigned flags,
                            const uint8_t *data,
                            size_t size,
                            NetPacketSent *sent_cb)
{
    ssize_t ret;

    if (queue->delivering) {
        return qemu_net_queue_append(queue, sender, flags, data, size, NULL);
    }

    ret = qemu_net_queue_deliver(queue, sender, flags, data, size);
    if (ret == 0) {
        qemu_net_queue_append(queue, sender, flags, data, size, sent_cb);
        return 0;
    }

    qemu_net_queue_flush(queue);

    return ret;
}

ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                VLANClientState *sender,
                                unsigned flags,
                                const struct iovec *iov,
                                int iovcnt,
                                NetPacketSent *sent_cb)
{
    ssize_t ret;

    if (queue->delivering) {
        return qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, NULL);
    }

    ret = qemu_net_queue_deliver_iov(queue, sender, flags, iov, iovcnt);
    if (ret == 0) {
        qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, sent_cb);
        return 0;
    }

    qemu_net_queue_flush(queue);

    return ret;
}

void qemu_net_queue_purge(NetQueue *queue, VLANClientState *from)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        if (packet->sender == from) {
            QTAILQ_REMOVE(&queue->packets, packet, entry);
            free(packet);
            packet = NULL;
        }
    }
}

void qemu_net_queue_flush(NetQueue *queue)
{
    while (!QTAILQ_EMPTY(&queue->packets)) {
        NetPacket *packet;
        int ret;

        packet = QTAILQ_FIRST(&queue->packets);
        QTAILQ_REMOVE(&queue->packets, packet, entry);

        ret = qemu_net_queue_deliver(queue,
                                     packet->sender,
                                     packet->flags,
                                     packet->data,
                                     packet->size);
        if (ret == 0) {
            QTAILQ_INSERT_HEAD(&queue->packets, packet, entry);
            break;
        }

        if (packet->sent_cb) {
            packet->sent_cb(packet->sender, ret);
        }

        free(packet);
        packet = NULL;
    }
}

int tap_open(char *ifname, int ifname_size, int *vnet_hdr, int vnet_hdr_required)
{
    struct ifreq ifr;
    int fd, ret;

    TFR(fd = open(PATH_NET_TUN, O_RDWR));
    if (fd < 0) {
        printf("could not open %s: %m", PATH_NET_TUN);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (*vnet_hdr) {
        unsigned int features;

        if (ioctl(fd, TUNGETFEATURES, &features) == 0 &&
            features & IFF_VNET_HDR) {
            *vnet_hdr = 1;
            ifr.ifr_flags |= IFF_VNET_HDR;
        } else {
            *vnet_hdr = 0;
        }

        if (vnet_hdr_required && !*vnet_hdr) {
            printf("vnet_hdr=1 requested, but no kernel "
                         "support for IFF_VNET_HDR available");
            close(fd);
            return -1;
        }
    }

    if (ifname[0] != '\0')
        pstrcpy(ifr.ifr_name, IFNAMSIZ, ifname);
    else
        pstrcpy(ifr.ifr_name, IFNAMSIZ, "tap%d");
    ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (ret != 0) {
        if (ifname[0] != '\0') {
            printf("could not configure %s (%s): %m", PATH_NET_TUN, ifr.ifr_name);
        } else {
            printf("could not configure %s: %m", PATH_NET_TUN);
        }
        close(fd);
        return -1;
    }
    pstrcpy(ifname, ifname_size, ifr.ifr_name);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
}

/* sndbuf implements a kind of flow control for tap.
 * Unfortunately when it's enabled, and packets are sent
 * to other guests on the same host, the receiver
 * can lock up the transmitter indefinitely.
 *
 * To avoid packet loss, sndbuf should be set to a value lower than the tx
 * queue capacity of any destination network interface.
 * Ethernet NICs generally have txqueuelen=1000, so 1Mb is
 * a good value, given a 1500 byte MTU.
 */
#define TAP_DEFAULT_SNDBUF 0

int tap_set_sndbuf(int fd, QemuOpts *opts)
{
    int sndbuf;

    sndbuf = qemu_opt_get_size(opts, "sndbuf", TAP_DEFAULT_SNDBUF);
    if (!sndbuf) {
        sndbuf = INT_MAX;
    }

    if (ioctl(fd, TUNSETSNDBUF, &sndbuf) == -1 && qemu_opt_get(opts, "sndbuf")) {
        printf("TUNSETSNDBUF ioctl failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int tap_probe_vnet_hdr(int fd)
{
    struct ifreq ifr;

    if (ioctl(fd, TUNGETIFF, &ifr) != 0) {
        printf("TUNGETIFF ioctl() failed: %s", strerror(errno));
        return 0;
    }

    return ifr.ifr_flags & IFF_VNET_HDR;
}

int tap_probe_has_ufo(int fd)
{
    unsigned offload;

    offload = TUN_F_CSUM | TUN_F_UFO;

    if (ioctl(fd, TUNSETOFFLOAD, offload) < 0)
        return 0;

    return 1;
}

/* Verify that we can assign given length */
int tap_probe_vnet_hdr_len(int fd, int len)
{
    int orig;
    if (ioctl(fd, TUNGETVNETHDRSZ, &orig) == -1) {
        return 0;
    }
    if (ioctl(fd, TUNSETVNETHDRSZ, &len) == -1) {
        return 0;
    }
    /* Restore original length: we can't handle failure. */
    if (ioctl(fd, TUNSETVNETHDRSZ, &orig) == -1) {
        fprintf(stderr, "TUNGETVNETHDRSZ ioctl() failed: %s. Exiting.\n",
                strerror(errno));
        assert(0);
        return -errno;
    }
    return 1;
}

void tap_fd_set_vnet_hdr_len(int fd, int len)
{
    if (ioctl(fd, TUNSETVNETHDRSZ, &len) == -1) {
        fprintf(stderr, "TUNSETVNETHDRSZ ioctl() failed: %s. Exiting.\n",
                strerror(errno));
        assert(0);
    }
}

void tap_fd_set_offload(int fd, int csum, int tso4,
                        int tso6, int ecn, int ufo)
{
    unsigned int offload = 0;

    /* Check if our kernel supports TUNSETOFFLOAD */
    if (ioctl(fd, TUNSETOFFLOAD, 0) != 0 && errno == EINVAL) {
        return;
    }

    if (csum) {
        offload |= TUN_F_CSUM;
        if (tso4)
            offload |= TUN_F_TSO4;
        if (tso6)
            offload |= TUN_F_TSO6;
        if ((tso4 || tso6) && ecn)
            offload |= TUN_F_TSO_ECN;
        if (ufo)
            offload |= TUN_F_UFO;
    }

    if (ioctl(fd, TUNSETOFFLOAD, offload) != 0) {
        offload &= ~TUN_F_UFO;
        if (ioctl(fd, TUNSETOFFLOAD, offload) != 0) {
            fprintf(stderr, "TUNSETOFFLOAD ioctl() failed: %s\n",
                    strerror(errno));
        }
    }
}

/* Maximum GSO packet size (64k) plus plenty of room for
 * the ethernet and virtio_net headers
 */
#define TAP_BUFSIZE (4096 + 65536)

typedef struct TAPState {
    VLANClientState nc;
    int fd;
    char down_script[1024];
    char down_script_arg[128];
    uint8_t buf[TAP_BUFSIZE];
    unsigned int read_poll : 1;
    unsigned int write_poll : 1;
    unsigned int using_vnet_hdr : 1;
    unsigned int has_ufo: 1;
    unsigned host_vnet_hdr_len;
} TAPState;

static int launch_script(const char *setup_script, const char *ifname, int fd);

static int tap_can_send(void *opaque);
static void tap_send(void *opaque);
static void tap_writable(void *opaque);

static void tap_update_fd_handler(TAPState *s)
{
    qemu_set_fd_handler2(s->fd,
                         s->read_poll  ? tap_can_send : NULL,
                         s->read_poll  ? tap_send     : NULL,
                         s->write_poll ? tap_writable : NULL,
                         s);
}

static void tap_read_poll(TAPState *s, int enable)
{
    s->read_poll = !!enable;
    tap_update_fd_handler(s);
}

static void tap_write_poll(TAPState *s, int enable)
{
    s->write_poll = !!enable;
    tap_update_fd_handler(s);
}

static void tap_writable(void *opaque)
{
    TAPState *s = opaque;

    tap_write_poll(s, 0);

    qemu_flush_queued_packets(&s->nc);
}

static ssize_t tap_write_packet(TAPState *s, const struct iovec *iov, int iovcnt)
{
    ssize_t len;

    do {
        len = writev(s->fd, iov, iovcnt);
    } while (len == -1 && errno == EINTR);

    if (len == -1 && errno == EAGAIN) {
        tap_write_poll(s, 1);
        return 0;
    }

    return len;
}

static ssize_t tap_receive_iov(VLANClientState *nc, const struct iovec *iov,
                               int iovcnt)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    const struct iovec *iovp = iov;
    struct iovec iov_copy[iovcnt + 1];
    struct virtio_net_hdr_mrg_rxbuf hdr = { };

    if (s->host_vnet_hdr_len && !s->using_vnet_hdr) {
        iov_copy[0].iov_base = &hdr;
        iov_copy[0].iov_len =  s->host_vnet_hdr_len;
        memcpy(&iov_copy[1], iov, iovcnt * sizeof(*iov));
        iovp = iov_copy;
        iovcnt++;
    }

    return tap_write_packet(s, iovp, iovcnt);
}

static ssize_t tap_receive_raw(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    struct iovec iov[2];
    int iovcnt = 0;
    struct virtio_net_hdr_mrg_rxbuf hdr = { };

    if (s->host_vnet_hdr_len) {
        iov[iovcnt].iov_base = &hdr;
        iov[iovcnt].iov_len  = s->host_vnet_hdr_len;
        iovcnt++;
    }

    iov[iovcnt].iov_base = (char *)buf;
    iov[iovcnt].iov_len  = size;
    iovcnt++;

    return tap_write_packet(s, iov, iovcnt);
}

static ssize_t tap_receive(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    struct iovec iov[1];

    if (s->host_vnet_hdr_len && !s->using_vnet_hdr) {
        return tap_receive_raw(nc, buf, size);
    }

    iov[0].iov_base = (char *)buf;
    iov[0].iov_len  = size;

    return tap_write_packet(s, iov, 1);
}

static int tap_can_send(void *opaque)
{
    TAPState *s = opaque;

    return qemu_can_send_packet(&s->nc);
}

ssize_t tap_read_packet(int tapfd, uint8_t *buf, int maxlen)
{
    return read(tapfd, buf, maxlen);
}

static void tap_send_completed(VLANClientState *nc, ssize_t len)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    tap_read_poll(s, 1);
}

static void tap_send(void *opaque)
{
    TAPState *s = opaque;
    int size;

    do {
        uint8_t *buf = s->buf;

        size = tap_read_packet(s->fd, s->buf, sizeof(s->buf));
        if (size <= 0) {
            break;
        }

        if (s->host_vnet_hdr_len && !s->using_vnet_hdr) {
            buf  += s->host_vnet_hdr_len;
            size -= s->host_vnet_hdr_len;
        }

        size = qemu_send_packet_async(&s->nc, buf, size, tap_send_completed);
        if (size == 0) {
            tap_read_poll(s, 0);
        }
    } while (size > 0 && qemu_can_send_packet(&s->nc));
}

void tap_set_vnet_hdr_len(VLANClientState *nc, int len)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);

    assert(nc->info->type == NET_CLIENT_TYPE_TAP);
    assert(len == sizeof(struct virtio_net_hdr_mrg_rxbuf) ||
           len == sizeof(struct virtio_net_hdr));

    tap_fd_set_vnet_hdr_len(s->fd, len);
    s->host_vnet_hdr_len = len;
}

void tap_using_vnet_hdr(VLANClientState *nc, int using_vnet_hdr)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);

    using_vnet_hdr = using_vnet_hdr != 0;

    assert(nc->info->type == NET_CLIENT_TYPE_TAP);
    assert(!!s->host_vnet_hdr_len == using_vnet_hdr);

    s->using_vnet_hdr = using_vnet_hdr;
}

void tap_set_offload(VLANClientState *nc, int csum, int tso4,
                     int tso6, int ecn, int ufo)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    if (s->fd < 0) {
        return;
    }

    tap_fd_set_offload(s->fd, csum, tso4, tso6, ecn, ufo);
}

static void tap_cleanup(VLANClientState *nc)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);

    qemu_purge_queued_packets(nc);

    if (s->down_script[0])
        launch_script(s->down_script, s->down_script_arg, s->fd);

    tap_read_poll(s, 0);
    tap_write_poll(s, 0);
    close(s->fd);
    s->fd = -1;
}

static void tap_poll(VLANClientState *nc, bool enable)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    tap_read_poll(s, enable);
    tap_write_poll(s, enable);
}

int tap_get_fd(VLANClientState *nc)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    assert(nc->info->type == NET_CLIENT_TYPE_TAP);
    return s->fd;
}

static NetClientInfo net_tap_info = {
    .type = NET_CLIENT_TYPE_TAP,
    .size = sizeof(TAPState),
    .receive = tap_receive,
    .receive_raw = tap_receive_raw,
    .receive_iov = tap_receive_iov,
    .poll = tap_poll,
    .cleanup = tap_cleanup,
};

static TAPState *net_tap_fd_init(VLANState *vlan,
                                 const char *model,
                                 const char *name,
                                 int fd,
                                 int vnet_hdr)
{
    VLANClientState *nc;
    TAPState *s;

    nc = qemu_new_net_client(&net_tap_info, vlan, NULL, model, name);

    s = DO_UPCAST(TAPState, nc, nc);

    s->fd = fd;
    s->host_vnet_hdr_len = vnet_hdr ? sizeof(struct virtio_net_hdr) : 0;
    s->using_vnet_hdr = 0;
    s->has_ufo = tap_probe_has_ufo(s->fd);
    tap_set_offload(&s->nc, 0, 0, 0, 0, 0);
    tap_read_poll(s, 1);
    return s;
}

static int launch_script(const char *setup_script, const char *ifname, int fd)
{
    sigset_t oldmask, mask;
    int pid, status;
    char *args[3];
    char **parg;

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    /* try to launch network script */
    pid = fork();
    if (pid == 0) {
        int open_max = sysconf(_SC_OPEN_MAX), i;

        for (i = 0; i < open_max; i++) {
            if (i != STDIN_FILENO &&
                i != STDOUT_FILENO &&
                i != STDERR_FILENO &&
                i != fd) {
                close(i);
            }
        }
        parg = args;
        *parg++ = (char *)setup_script;
        *parg++ = (char *)ifname;
        *parg = NULL;
        execv(setup_script, args);
        _exit(1);
    } else if (pid > 0) {
        while (waitpid(pid, &status, 0) != pid) {
            /* loop */
        }
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;
        }
    }
    fprintf(stderr, "%s: could not launch network script\n", setup_script);
    return -1;
}

static int net_tap_init(QemuOpts *opts, int *vnet_hdr)
{
    int fd, vnet_hdr_required;
    char ifname[128] = {0,};
    const char *setup_script;

    if (qemu_opt_get(opts, "ifname")) {
        pstrcpy(ifname, sizeof(ifname), qemu_opt_get(opts, "ifname"));
    }

    *vnet_hdr = qemu_opt_get_bool(opts, "vnet_hdr", 1);
    if (qemu_opt_get(opts, "vnet_hdr")) {
        vnet_hdr_required = *vnet_hdr;
    } else {
        vnet_hdr_required = 0;
    }

    TFR(fd = tap_open(ifname, sizeof(ifname), vnet_hdr, vnet_hdr_required));
    if (fd < 0) {
        return -1;
    }

    setup_script = qemu_opt_get(opts, "script");
    if (setup_script &&
        setup_script[0] != '\0' &&
        strcmp(setup_script, "no") != 0 &&
        launch_script(setup_script, ifname, fd)) {
        close(fd);
        return -1;
    }

    qemu_opt_set(opts, "ifname", ifname);

    return fd;
}

int net_init_tap(QemuOpts *opts, const char *name, VLANState *vlan)
{
    TAPState *s;
    int fd, vnet_hdr = 0;

    if (!qemu_opt_get(opts, "script")) {
        qemu_opt_set(opts, "script", DEFAULT_NETWORK_SCRIPT);
    }

    if (!qemu_opt_get(opts, "downscript")) {
        qemu_opt_set(opts, "downscript", DEFAULT_NETWORK_DOWN_SCRIPT);
    }

    fd = net_tap_init(opts, &vnet_hdr);
    if (fd == -1) {
        return -1;
    }

    s = net_tap_fd_init(vlan, "tap", name, fd, vnet_hdr);
    if (!s) {
        close(fd);
        return -1;
    }

    if (tap_set_sndbuf(s->fd, opts) < 0) {
        return -1;
    }

    const char *ifname, *script, *downscript;

    ifname     = qemu_opt_get(opts, "ifname");
    script     = qemu_opt_get(opts, "script");
    downscript = qemu_opt_get(opts, "downscript");

    snprintf(s->nc.info_str, sizeof(s->nc.info_str),
                 "ifname=%s,script=%s,downscript=%s",
                 ifname, script, downscript);
    if (strcmp(downscript, "no") != 0) {
        snprintf(s->down_script, sizeof(s->down_script), "%s", downscript);
        snprintf(s->down_script_arg, sizeof(s->down_script_arg), "%s", ifname);
    }

    return 0;
}

int net_parse_macaddr(uint8_t *macaddr, const char *p)
{
    int i;
    char *last_char;
    long int offset;

    errno = 0;
    offset = strtol(p, &last_char, 0);
    if (errno == 0 && *last_char == '\0' &&
        offset >= 0 && offset <= 0xFFFFFF) {
        macaddr[3] = (offset & 0xFF0000) >> 16;
        macaddr[4] = (offset & 0xFF00) >> 8;
        macaddr[5] = offset & 0xFF;
        return 0;
    }

    for (i = 0; i < 6; i++) {
        macaddr[i] = strtol(p, (char **)&p, 16);
        if (i == 5) {
            if (*p != '\0') {
                return -1;
            }
        } else {
            if (*p != ':' && *p != '-') {
                return -1;
            }
            p++;
        }
    }

    return 0;
}
