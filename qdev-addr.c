#include "qdev.h"
#include "qdev-addr.h"

static int parse_taddr(DeviceState *dev, Property *prop, const char *str)
{
    uint64_t *ptr = qdev_get_prop_ptr(dev, prop);

    *ptr = strtoull(str, NULL, 16);
    return 0;
}

static int print_taddr(DeviceState *dev, Property *prop, char *dest, size_t len)
{
    uint64_t *ptr = qdev_get_prop_ptr(dev, prop);
    return snprintf(dest, len, "0x%16" PRIx64, *ptr);
}

PropertyInfo qdev_prop_taddr = {
    .name  = "taddr",
    .type  = PROP_TYPE_TADDR,
    .size  = sizeof(uint64_t),
    .parse = parse_taddr,
    .print = print_taddr,
};

void qdev_prop_set_taddr(DeviceState *dev, const char *name, uint64_t value)
{
    qdev_prop_set(dev, name, &value, PROP_TYPE_TADDR);
}
