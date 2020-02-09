#ifndef QEMU_NET_H
#define QEMU_NET_H

#include "qemu-queue.h"
#include "qemu-common.h"
#include "qemu-option.h"
#include <stdint.h>
#include <linux/ioctl.h>

/* Ioctl defines */
#define TUNSETIFF       _IOW('T', 202, int)
#define TUNGETFEATURES  _IOR('T', 207, unsigned int)
#define TUNSETOFFLOAD   _IOW('T', 208, unsigned int)
#define TUNGETIFF       _IOR('T', 210, unsigned int)
#define TUNSETSNDBUF    _IOW('T', 212, int)
#define TUNGETVNETHDRSZ _IOR('T', 215, int)
#define TUNSETVNETHDRSZ _IOW('T', 216, int)

/* TUNSETIFF ifr flags */
#define IFF_TAP		0x0002
#define IFF_NO_PI	0x1000
#define IFF_VNET_HDR	0x4000

/* Features for GSO (TUNSETOFFLOAD). */
#define TUN_F_CSUM	0x01	/* You can hand me unchecksummed packets. */
#define TUN_F_TSO4	0x02	/* I can handle TSO for IPv4 packets */
#define TUN_F_TSO6	0x04	/* I can handle TSO for IPv6 packets */
#define TUN_F_TSO_ECN	0x08	/* I can handle TSO with ECN bits. */
#define TUN_F_UFO	0x10	/* I can handle UFO packets */


#define DEFAULT_NETWORK_SCRIPT      "/etc/qemu-ifup"
#define DEFAULT_NETWORK_DOWN_SCRIPT "/etc/qemu-ifdown"
#define QEMU_NET_PACKET_FLAG_NONE   0
#define QEMU_NET_PACKET_FLAG_RAW    (1<<0)

struct VLANClientState;
struct VLANState;
struct NetClientInfo;
struct NetQueue;
struct NICInfo;

typedef struct VLANClientState{
    struct NetClientInfo *info;
    int link_down;
    QTAILQ_ENTRY(VLANClientState) next;
    struct VLANState *vlan;
    struct VLANClientState *peer;
    struct NetQueue *send_queue;
    char *model;
    char *name;
    char info_str[256];
    unsigned receive_disabled : 1;
}VLANClientState;

typedef struct VLANState{
    int id;
    QTAILQ_HEAD(, VLANClientState) clients;
    QTAILQ_ENTRY(VLANState) next;
    struct NetQueue *send_queue;
}VLANState;

typedef struct{
    uint8_t a[6];
}MACAddr;

/* qdev nic properties */
typedef struct NICConf{
    MACAddr macaddr;
    VLANState *vlan;
    VLANClientState *peer;
    int32_t bootindex;
}NICConf;

#define DEFINE_NIC_PROPERTIES(_state, _conf)                            \
    DEFINE_PROP_MACADDR("mac",   _state, _conf.macaddr),                \
    DEFINE_PROP_VLAN("vlan",     _state, _conf.vlan),                   \
    DEFINE_PROP_NETDEV("netdev", _state, _conf.peer),                   \
    DEFINE_PROP_INT32("bootindex", _state, _conf.bootindex, -1)

/* VLANs support */
typedef enum{
    NET_CLIENT_TYPE_NONE,
    NET_CLIENT_TYPE_NIC,
    NET_CLIENT_TYPE_USER,
    NET_CLIENT_TYPE_TAP,
    NET_CLIENT_TYPE_SOCKET,
    NET_CLIENT_TYPE_VDE,
    NET_CLIENT_TYPE_DUMP,

    NET_CLIENT_TYPE_MAX
}net_client_type;

typedef void (NetPacketSent) (VLANClientState *sender, ssize_t ret);
typedef void (NetPoll)(VLANClientState *, bool enable);
typedef int (NetCanReceive)(VLANClientState *);
typedef ssize_t (NetReceive)(VLANClientState *, const uint8_t *, size_t);
typedef ssize_t (NetReceiveIOV)(VLANClientState *, const struct iovec *, int);
typedef void (NetCleanup) (VLANClientState *);
typedef void (LinkStatusChanged)(VLANClientState *);

typedef struct NetClientInfo{
    net_client_type type;
    size_t size;
    NetReceive *receive;
    NetReceive *receive_raw;
    NetReceiveIOV *receive_iov;
    NetCanReceive *can_receive;
    NetCleanup *cleanup;
    LinkStatusChanged *link_status_changed;
    NetPoll *poll;
}NetClientInfo;

typedef struct NICState{
    VLANClientState nc;
    NICConf *conf;
    void *opaque;
    bool peer_deleted;
}NICState;

/* NIC info */
typedef struct NICInfo{
    MACAddr macaddr;
    char *model;
    char *name;
    char *devaddr;
    VLANState *vlan;
    VLANClientState *netdev;
    int used;         /* is this slot in nd_table[] being used? */
    int instantiated; /* does this NICInfo correspond to an instantiated NIC? */
    int nvectors;
}NICInfo;

VLANState *qemu_find_vlan(int id, int allocate);
VLANClientState *qemu_find_netdev(const char *id);
VLANClientState *qemu_new_net_client(NetClientInfo *info,
                                     VLANState *vlan,
                                     VLANClientState *peer,
                                     const char *model,
                                     const char *name);
NICState *qemu_new_nic(NetClientInfo *info,
                       NICConf *conf,
                       const char *model,
                       const char *name,
                       void *opaque);
void qemu_del_vlan_client(VLANClientState *vc);
VLANClientState *qemu_find_vlan_client_by_name(int vlan_id,
                                               const char *client_str);
typedef void (*qemu_nic_foreach)(NICState *nic, void *opaque);
void qemu_foreach_nic(qemu_nic_foreach func, void *opaque);
int qemu_can_send_packet(VLANClientState *vc);
ssize_t qemu_sendv_packet(VLANClientState *vc, const struct iovec *iov,
                          int iovcnt);
ssize_t qemu_sendv_packet_async(VLANClientState *vc, const struct iovec *iov,
                                int iovcnt, NetPacketSent *sent_cb);
void qemu_send_packet(VLANClientState *vc, const uint8_t *buf, int size);
ssize_t qemu_send_packet_raw(VLANClientState *vc, const uint8_t *buf, int size);
ssize_t qemu_send_packet_async(VLANClientState *vc, const uint8_t *buf,
                               int size, NetPacketSent *sent_cb);
void qemu_purge_queued_packets(VLANClientState *vc);
void qemu_flush_queued_packets(VLANClientState *vc);
void qemu_format_nic_info_str(VLANClientState *vc, uint8_t macaddr[6]);
void qemu_macaddr_default_if_unset(MACAddr *macaddr);
int qemu_show_nic_models(const char *arg, const char *const *models);
void qemu_check_nic_model(NICInfo *nd, const char *model);
int qemu_find_nic_model(NICInfo *nd, const char * const *models,
                        const char *default_model);
extern NICInfo nd_table[1];

/* from net.c */
extern const char *legacy_tftp_prefix;
extern const char *legacy_bootp_filename;

int net_client_init(QemuOpts *opts, int is_netdev);
int net_client_parse(QemuOptsList *opts_list, const char *str);
int net_init_clients(void);
void net_check_clients(void);
void net_cleanup(void);

void qdev_set_nic_properties(DeviceState *dev, NICInfo *nd);
int net_handle_fd_param(const char *param);
int net_parse_macaddr(uint8_t *macaddr, const char *p);

int net_init_tap(QemuOpts *opts, const char *name, VLANState *vlan);

int tap_open(char *ifname, int ifname_size, int *vnet_hdr, int vnet_hdr_required);

ssize_t tap_read_packet(int tapfd, uint8_t *buf, int maxlen);

void tap_using_vnet_hdr(VLANClientState *vc, int using_vnet_hdr);
void tap_set_offload(VLANClientState *vc, int csum, int tso4, int tso6, int ecn, int ufo);
void tap_set_vnet_hdr_len(VLANClientState *vc, int len);

int tap_set_sndbuf(int fd, QemuOpts *opts);
int tap_probe_vnet_hdr(int fd);
int tap_probe_vnet_hdr_len(int fd, int len);
int tap_probe_has_ufo(int fd);
void tap_fd_set_offload(int fd, int csum, int tso4, int tso6, int ecn, int ufo);
void tap_fd_set_vnet_hdr_len(int fd, int len);
int tap_get_fd(VLANClientState *vc);

struct virtio_net_hdr
{
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};

struct virtio_net_hdr_mrg_rxbuf
{
    struct virtio_net_hdr hdr;
    uint16_t num_buffers;   /* Number of merged rx buffers */
};

uint32_t net_checksum_add(int len, uint8_t *buf);
uint16_t net_checksum_finish(uint32_t sum);
uint16_t net_checksum_tcpudp(uint16_t length, uint16_t proto,
                             uint8_t *addrs, uint8_t *buf);
typedef struct NetPacket NetPacket;
typedef struct NetQueue NetQueue;

typedef void (NetPacketSent) (VLANClientState *sender, ssize_t ret);

typedef ssize_t (NetPacketDeliver) (VLANClientState *sender,
                                    unsigned flags,
                                    const uint8_t *buf,
                                    size_t size,
                                    void *opaque);

typedef ssize_t (NetPacketDeliverIOV) (VLANClientState *sender,
                                       unsigned flags,
                                       const struct iovec *iov,
                                       int iovcnt,
                                       void *opaque);

NetQueue *qemu_new_net_queue(NetPacketDeliver *deliver,
                             NetPacketDeliverIOV *deliver_iov,
                             void *opaque);
void qemu_del_net_queue(NetQueue *queue);

ssize_t qemu_net_queue_send(NetQueue *queue,
                            VLANClientState *sender,
                            unsigned flags,
                            const uint8_t *data,
                            size_t size,
                            NetPacketSent *sent_cb);

ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                VLANClientState *sender,
                                unsigned flags,
                                const struct iovec *iov,
                                int iovcnt,
                                NetPacketSent *sent_cb);

void qemu_net_queue_purge(NetQueue *queue, VLANClientState *from);
void qemu_net_queue_flush(NetQueue *queue);

#endif /* QEMU_NET_QUEUE_H */
