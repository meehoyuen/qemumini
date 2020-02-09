/*
 *  Dynamic device configuration and creation.
 */
#include "qdev.h"
#include "sysemu.h"

static int qdev_hotplug = 0;
static bool qdev_hot_added = false;

/* This is a nasty hack to allow passing a NULL bus to qdev_create.  */
static BusState *main_system_bus;
static void main_system_bus_create(void);

DeviceInfo *device_info_list;

static BusState *qbus_find_recursive(BusState *bus, const char *name,
                                     const BusInfo *info);
static BusState *qbus_find(const char *path);

/* Register a new device type.  */
void qdev_register(DeviceInfo *info)
{
    assert(info->size >= sizeof(DeviceState));
    assert(!info->next);

    info->next = device_info_list;
    device_info_list = info;
}

static DeviceInfo *qdev_find_info(BusInfo *bus_info, const char *name)
{
    DeviceInfo *info;

    /* first check device names */
    for (info = device_info_list; info != NULL; info = info->next) {
        if (bus_info && info->bus_info != bus_info)
            continue;
        if (strcmp(info->name, name) != 0)
            continue;
        return info;
    }

    /* failing that check the aliases */
    for (info = device_info_list; info != NULL; info = info->next) {
        if (bus_info && info->bus_info != bus_info)
            continue;
        if (!info->alias)
            continue;
        if (strcmp(info->alias, name) != 0)
            continue;
        return info;
    }
    return NULL;
}

static DeviceState *qdev_create_from_info(BusState *bus, DeviceInfo *info)
{
    DeviceState *dev;

    assert(bus->info == info->bus_info);
    dev = calloc(1, info->size);
    dev->info = info;
    dev->parent_bus = bus;
    qdev_prop_set_defaults(dev, dev->info->props);
    qdev_prop_set_defaults(dev, dev->parent_bus->info->props);
    QTAILQ_INSERT_HEAD(&bus->children, dev, sibling);
    if (qdev_hotplug) {
        assert(bus->allow_hotplug);
        dev->hotplugged = 1;
        qdev_hot_added = true;
    }
    dev->instance_id_alias = -1;
    dev->state = DEV_STATE_CREATED;
    return dev;
}

/* Create a new device.  This only initializes the device state structure
   and allows properties to be set.  qdev_init should be called to
   initialize the actual device emulation.  */
DeviceState *qdev_create(BusState *bus, const char *name)
{
    DeviceState *dev;

    dev = qdev_try_create(bus, name);
    if (!dev) {
        if (bus) {
            hw_error("Unknown device '%s' for bus '%s'\n", name,
                     bus->info->name);
        } else {
            hw_error("Unknown device '%s' for default sysbus\n", name);
        }
    }

    return dev;
}

DeviceState *qdev_try_create(BusState *bus, const char *name)
{
    DeviceInfo *info;

    if (!bus) {
        bus = sysbus_get_default();
    }

    info = qdev_find_info(bus->info, name);
    if (!info) {
        return NULL;
    }

    return qdev_create_from_info(bus, info);
}

static int set_property(const char *name, const char *value, void *opaque)
{
    DeviceState *dev = opaque;

    if (strcmp(name, "driver") == 0)
        return 0;
    if (strcmp(name, "bus") == 0)
        return 0;

    if (qdev_prop_parse(dev, name, value) == -1) {
        return -1;
    }
    return 0;
}

DeviceState *qdev_device_add(QemuOpts *opts)
{
    const char *driver, *path, *id;
    DeviceInfo *info;
    DeviceState *qdev;
    BusState *bus;

    driver = qemu_opt_get(opts, "driver");
    if (!driver) {
        printf("QERR_MISSING_PARAMETER, driver\n");
        return NULL;
    }

    /* find driver */
    info = qdev_find_info(NULL, driver);
    if (!info || info->no_user) {
        printf("QERR_INVALID_PARAMETER_VALUE, driver, a driver name\n");
        printf("Try with argument '?' for a list.\n");
        return NULL;
    }

    /* find bus */
    path = qemu_opt_get(opts, "bus");
    if (path != NULL) {
        bus = qbus_find(path);
        if (!bus) {
            return NULL;
        }
        if (bus->info != info->bus_info) {
            printf("QERR_BAD_BUS_FOR_DEVICE, driver:%s, bus->info->name:%s\n", driver, bus->info->name);
            return NULL;
        }
    } else {
        bus = qbus_find_recursive(main_system_bus, NULL, info->bus_info);
        if (!bus) {
            printf("QERR_NO_BUS_FOR_DEVICE, info->name:%s, info->bus_info->name:%s\n", info->name, info->bus_info->name);
            return NULL;
        }
    }
    if (qdev_hotplug && !bus->allow_hotplug) {
        printf("QERR_BUS_NO_HOTPLUG, bus->name:%s\n", bus->name);
        return NULL;
    }

    /* create device, set properties */
    qdev = qdev_create_from_info(bus, info);
    id = qemu_opts_id(opts);
    if (id) {
        qdev->id = id;
    }
    if (qemu_opt_foreach(opts, set_property, qdev, 1) != 0) {
        qdev_free(qdev);
        return NULL;
    }
    if (qdev_init(qdev) < 0) {
        printf("QERR_DEVICE_INIT_FAILED, driver:%s\n", driver);
        return NULL;
    }
    qdev->opts = opts;
    return qdev;
}

/* Initialize a device.  Device properties should be set before calling
   this function.  IRQs and MMIO regions should be connected/mapped after
   calling this function.
   On failure, destroy the device and return negative value.
   Return 0 on success.  */
int qdev_init(DeviceState *dev)
{
    int rc;

    assert(dev->state == DEV_STATE_CREATED);
    rc = dev->info->init(dev, dev->info);
    if (rc < 0) {
        qdev_free(dev);
        return rc;
    }
    dev->state = DEV_STATE_INITIALIZED;
    if (dev->hotplugged && dev->info->reset) {
        dev->info->reset(dev);
    }
    return 0;
}

void qdev_set_legacy_instance_id(DeviceState *dev, int alias_id,
                                 int required_for_version)
{
    assert(dev->state == DEV_STATE_CREATED);
    dev->instance_id_alias = alias_id;
    dev->alias_required_for_version = required_for_version;
}

static int qdev_reset_one(DeviceState *dev, void *opaque)
{
    if (dev->info->reset) {
        dev->info->reset(dev);
    }

    return 0;
}

BusState *sysbus_get_default(void)
{
    if (!main_system_bus) {
        main_system_bus_create();
    }
    return main_system_bus;
}

static int qbus_reset_one(BusState *bus, void *opaque)
{
    if (bus->info->reset) {
        return bus->info->reset(bus);
    }
    return 0;
}

void qdev_reset_all(DeviceState *dev)
{
    qdev_walk_children(dev, qdev_reset_one, qbus_reset_one, NULL);
}

void qbus_reset_all_fn(void *opaque)
{
    BusState *bus = opaque;
    qbus_walk_children(bus, qdev_reset_one, qbus_reset_one, NULL);
}

/* can be used as ->unplug() callback for the simple cases */
int qdev_simple_unplug_cb(DeviceState *dev)
{
    /* just zap it */
    qdev_free(dev);
    return 0;
}


/* Like qdev_init(), but terminate program via printf() instead of
   returning an error value.  This is okay during machine creation.
   Don't use for hotplug, because there callers need to recover from
   failure.  Exception: if you know the device's init() callback can't
   fail, then qdev_init_nofail() can't fail either, and is therefore
   usable even then.  But relying on the device implementation that
   way is somewhat unclean, and best avoided.  */
void qdev_init_nofail(DeviceState *dev)
{
    DeviceInfo *info = dev->info;

    if (qdev_init(dev) < 0) {
        printf("Initialization of device %s failed", info->name);
        exit(1);
    }
}

/* Unlink device from bus and free the structure.  */
void qdev_free(DeviceState *dev)
{
    BusState *bus;
    Property *prop;

    if (dev->state == DEV_STATE_INITIALIZED) {
        while (dev->num_child_bus) {
            bus = QLIST_FIRST(&dev->child_bus);
            qbus_free(bus);
        }
        if (dev->info->exit)
            dev->info->exit(dev);
        if (dev->opts)
            qemu_opts_del(dev->opts);
    }
    QTAILQ_REMOVE(&dev->parent_bus->children, dev, sibling);
    for (prop = dev->info->props; prop && prop->name; prop++) {
        if (prop->info->free) {
            prop->info->free(dev, prop);
        }
    }
    free(dev);
    dev = NULL;
}

void qdev_machine_creation_done(void)
{
    /*
     * ok, initial machine setup is done, starting from now we can
     * only create hotpluggable devices
     */
    qdev_hotplug = 1;
}

BusState *qdev_get_parent_bus(DeviceState *dev)
{
    return dev->parent_bus;
}

void qdev_init_gpio_in(DeviceState *dev, qemu_irq_handler handler, int n)
{
    assert(dev->num_gpio_in == 0);
    dev->num_gpio_in = n;
    dev->gpio_in = qemu_allocate_irqs(handler, dev, n);
}

void qdev_init_gpio_out(DeviceState *dev, qemu_irq *pins, int n)
{
    assert(dev->num_gpio_out == 0);
    dev->num_gpio_out = n;
    dev->gpio_out = pins;
}

qemu_irq qdev_get_gpio_in(DeviceState *dev, int n)
{
    assert(n >= 0 && n < dev->num_gpio_in);
    return dev->gpio_in[n];
}

void qdev_connect_gpio_out(DeviceState * dev, int n, qemu_irq pin)
{
    assert(n >= 0 && n < dev->num_gpio_out);
    dev->gpio_out[n] = pin;
}

void qdev_set_nic_properties(DeviceState *dev, NICInfo *nd)
{
    qdev_prop_set_macaddr(dev, "mac", nd->macaddr.a);
    if (nd->vlan)
        qdev_prop_set_vlan(dev, "vlan", nd->vlan);
    if (nd->netdev)
        qdev_prop_set_netdev(dev, "netdev", nd->netdev);
    if (nd->nvectors != DEV_NVECTORS_UNSPECIFIED &&
        qdev_prop_exists(dev, "vectors")) {
        qdev_prop_set_uint32(dev, "vectors", nd->nvectors);
    }   
    nd->instantiated = 1;
}

BusState *qdev_get_child_bus(DeviceState *dev, const char *name)
{
    BusState *bus;

    QLIST_FOREACH(bus, &dev->child_bus, sibling) {
        if (strcmp(name, bus->name) == 0) {
            return bus;
        }
    }
    return NULL;
}

int qbus_walk_children(BusState *bus, qdev_walkerfn *devfn,
                       qbus_walkerfn *busfn, void *opaque)
{
    DeviceState *dev;
    int err;

    if (busfn) {
        err = busfn(bus, opaque);
        if (err) {
            return err;
        }
    }

    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        err = qdev_walk_children(dev, devfn, busfn, opaque);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

int qdev_walk_children(DeviceState *dev, qdev_walkerfn *devfn,
                       qbus_walkerfn *busfn, void *opaque)
{
    BusState *bus;
    int err;

    if (devfn) {
        err = devfn(dev, opaque);
        if (err) {
            return err;
        }
    }

    QLIST_FOREACH(bus, &dev->child_bus, sibling) {
        err = qbus_walk_children(bus, devfn, busfn, opaque);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

static BusState *qbus_find_recursive(BusState *bus, const char *name,
                                     const BusInfo *info)
{
    DeviceState *dev;
    BusState *child, *ret;
    int match = 1;

    if (name && (strcmp(bus->name, name) != 0)) {
        match = 0;
    }
    if (info && (bus->info != info)) {
        match = 0;
    }
    if (match) {
        return bus;
    }

    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        QLIST_FOREACH(child, &dev->child_bus, sibling) {
            ret = qbus_find_recursive(child, name, info);
            if (ret) {
                return ret;
            }
        }
    }
    return NULL;
}

DeviceState *qdev_find_recursive(BusState *bus, const char *id)
{
    DeviceState *dev, *ret;
    BusState *child;

    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        if (dev->id && strcmp(dev->id, id) == 0)
            return dev;
        QLIST_FOREACH(child, &dev->child_bus, sibling) {
            ret = qdev_find_recursive(child, id);
            if (ret) {
                return ret;
            }
        }
    }
    return NULL;
}

static void qbus_list_bus(DeviceState *dev)
{
    BusState *child;
    const char *sep = " ";

    fprintf(stderr, "child busses at \"%s\":", dev->id ? dev->id : dev->info->name);
    QLIST_FOREACH(child, &dev->child_bus, sibling) {
        fprintf(stderr, "%s\"%s\"", sep, child->name);
        sep = ", ";
    }
    fprintf(stderr, "\n");
}

static void qbus_list_dev(BusState *bus)
{
    DeviceState *dev;
    const char *sep = " ";

    fprintf(stderr, "devices at \"%s\":", bus->name);
    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        fprintf(stderr, "%s\"%s\"", sep, dev->info->name);
        if (dev->id)
            fprintf(stderr, "/\"%s\"", dev->id);
        sep = ", ";
    }
    fprintf(stderr, "\n");
}

static BusState *qbus_find_bus(DeviceState *dev, char *elem)
{
    BusState *child;

    QLIST_FOREACH(child, &dev->child_bus, sibling) {
        if (strcmp(child->name, elem) == 0) {
            return child;
        }
    }
    return NULL;
}

static DeviceState *qbus_find_dev(BusState *bus, char *elem)
{
    DeviceState *dev;

    /*
     * try to match in order:
     *   (1) instance id, if present
     *   (2) driver name
     *   (3) driver alias, if present
     */
    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        if (dev->id  &&  strcmp(dev->id, elem) == 0) {
            return dev;
        }
    }
    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        if (strcmp(dev->info->name, elem) == 0) {
            return dev;
        }
    }
    QTAILQ_FOREACH(dev, &bus->children, sibling) {
        if (dev->info->alias && strcmp(dev->info->alias, elem) == 0) {
            return dev;
        }
    }
    return NULL;
}

static BusState *qbus_find(const char *path)
{
    DeviceState *dev;
    BusState *bus;
    char elem[128];
    int pos, len;

    /* find start element */
    if (path[0] == '/') {
        bus = main_system_bus;
        pos = 0;
    } else {
        if (sscanf(path, "%127[^/]%n", elem, &len) != 1) {
            assert(!path[0]);
            elem[0] = len = 0;
        }
        bus = qbus_find_recursive(main_system_bus, elem, NULL);
        if (!bus) {
            printf("QERR_BUS_NOT_FOUND, elem:%s\n", elem);
            return NULL;
        }
        pos = len;
    }

    for (;;) {
        assert(path[pos] == '/' || !path[pos]);
        while (path[pos] == '/') {
            pos++;
        }
        if (path[pos] == '\0') {
            return bus;
        }

        /* find device */
        if (sscanf(path+pos, "%127[^/]%n", elem, &len) != 1) {
            assert(0);
            elem[0] = len = 0;
        }
        pos += len;
        dev = qbus_find_dev(bus, elem);
        if (!dev) {
            printf("QERR_DEVICE_NOT_FOUND, elem:%s\n", elem);
            qbus_list_dev(bus);
            return NULL;
        }

        assert(path[pos] == '/' || !path[pos]);
        while (path[pos] == '/') {
            pos++;
        }
        if (path[pos] == '\0') {
            /* last specified element is a device.  If it has exactly
             * one child bus accept it nevertheless */
            switch (dev->num_child_bus) {
            case 0:
                printf("QERR_DEVICE_NO_BUS, elem:%s\n", elem);
                return NULL;
            case 1:
                return QLIST_FIRST(&dev->child_bus);
            default:
                printf("QERR_DEVICE_MULTIPLE_BUSSES, elem:%s\n", elem);
                qbus_list_bus(dev);
                return NULL;
            }
        }

        /* find bus */
        if (sscanf(path+pos, "%127[^/]%n", elem, &len) != 1) {
            assert(0);
            elem[0] = len = 0;
        }
        pos += len;
        bus = qbus_find_bus(dev, elem);
        if (!bus) {
            printf("QERR_BUS_NOT_FOUND, elem:%s\n", elem);
            qbus_list_bus(dev);
            return NULL;
        }
    }
}

void qbus_create_inplace(BusState *bus, BusInfo *info,
                         DeviceState *parent, const char *name)
{
    char *buf;
    int i,len;

    bus->info = info;
    bus->parent = parent;

    if (name) {
        /* use supplied name */
        bus->name = strdup(name);
    } else if (parent && parent->id) {
        /* parent device has id -> use it for bus name */
        len = strlen(parent->id) + 16;
        buf = malloc(len);
        snprintf(buf, len, "%s.%d", parent->id, parent->num_child_bus);
        bus->name = buf;
    } else {
        /* no id -> use lowercase bus type for bus name */
        len = strlen(info->name) + 16;
        buf = malloc(len);
        len = snprintf(buf, len, "%s.%d", info->name,
                       parent ? parent->num_child_bus : 0);
        for (i = 0; i < len; i++)
            buf[i] = qemu_tolower(buf[i]);
        bus->name = buf;
    }

    QTAILQ_INIT(&bus->children);
    if (parent) {
        QLIST_INSERT_HEAD(&parent->child_bus, bus, sibling);
        parent->num_child_bus++;
    } else if (bus != main_system_bus) {
        /* TODO: once all bus devices are qdevified,
           only reset handler for main_system_bus should be registered here. */
        qemu_register_reset(qbus_reset_all_fn, bus);
    }
}

BusState *qbus_create(BusInfo *info, DeviceState *parent, const char *name)
{
    BusState *bus;

    bus = calloc(1, info->size);
    bus->qdev_allocated = 1;
    qbus_create_inplace(bus, info, parent, name);
    return bus;
}

static void main_system_bus_create(void)
{
    /* assign main_system_bus before qbus_create_inplace()
     * in order to make "if (bus != main_system_bus)" work */
    main_system_bus = calloc(1, system_bus_info.size);
    main_system_bus->qdev_allocated = 1;
    qbus_create_inplace(main_system_bus, &system_bus_info, NULL,
                        "main-system-bus");
}

void qbus_free(BusState *bus)
{
    DeviceState *dev;

    while ((dev = QTAILQ_FIRST(&bus->children)) != NULL) {
        qdev_free(dev);
    }
    if (bus->parent) {
        QLIST_REMOVE(bus, sibling);
        bus->parent->num_child_bus--;
    } else {
        assert(bus != main_system_bus); /* main_system_bus is never freed */
        qemu_unregister_reset(qbus_reset_all_fn, bus);
    }
    free((void*)bus->name);
    bus->name = NULL;
    if (bus->qdev_allocated) {
        free(bus);
        bus = NULL;
    }
}

static int qdev_get_fw_dev_path_helper(DeviceState *dev, char *p, int size)
{
    int l = 0;

    if (dev && dev->parent_bus) {
        char *d;
        l = qdev_get_fw_dev_path_helper(dev->parent_bus->parent, p, size);
        if (dev->parent_bus->info->get_fw_dev_path) {
            d = dev->parent_bus->info->get_fw_dev_path(dev);
            l += snprintf(p + l, size - l, "%s", d);
            free(d);
            d = NULL;
        } else {
            l += snprintf(p + l, size - l, "%s", dev->info->name);
        }
    }
    l += snprintf(p + l , size - l, "/");

    return l;
}

char* qdev_get_fw_dev_path(DeviceState *dev)
{
    char path[128];
    int l;

    l = qdev_get_fw_dev_path_helper(dev, path, 128);

    path[l-1] = '\0';

    return strdup(path);
}
