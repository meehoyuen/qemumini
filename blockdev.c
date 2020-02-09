#include "block.h"
#include "blockdev.h"
#include "qemu-option.h"
#include "sysemu.h"
#include "block_int.h"

static QTAILQ_HEAD(drivelist, DriveInfo) drives = QTAILQ_HEAD_INITIALIZER(drives);

static const char *const if_name[IF_COUNT] = {
    [IF_NONE] = "none",
    [IF_IDE] = "ide",
    [IF_SCSI] = "scsi",
    [IF_FLOPPY] = "floppy",
};

static const int if_max_devs[IF_COUNT] = {
    /*
     * Do not change these numbers!  They govern how drive option
     * index maps to unit and bus.  That mapping is ABI.
     *
     * All controllers used to imlement if=T drives need to support
     * if_max_devs[T] units, for any T with if_max_devs[T] != 0.
     * Otherwise, some index values map to "impossible" bus, unit
     * values.
     *
     * For instance, if you change [IF_SCSI] to 255, -drive
     * if=scsi,index=12 no longer means bus=1,unit=5, but
     * bus=0,unit=12.  With an lsi53c895a controller (7 units max),
     * the drive can't be set up.  Regression.
     */
    [IF_IDE] = 2,
    [IF_SCSI] = 7,
};

/*
 * We automatically delete the drive when a device using it gets
 * unplugged.  Questionable feature, but we can't just drop it.
 * Device models call blockdev_mark_auto_del() to schedule the
 * automatic deletion, and generic qdev code calls blockdev_auto_del()
 * when deletion is actually safe.
 */
void blockdev_mark_auto_del(BlockDriverState *bs)
{
    DriveInfo *dinfo = drive_get_by_blockdev(bs);

    if (dinfo) {
        dinfo->auto_del = 1;
    }
}

void blockdev_auto_del(BlockDriverState *bs)
{
    DriveInfo *dinfo = drive_get_by_blockdev(bs);

    if (dinfo && dinfo->auto_del) {
        drive_put_ref(dinfo);
    }
}

static int drive_index_to_bus_id(BlockInterfaceType type, int index)
{
    int max_devs = if_max_devs[type];
    return max_devs ? index / max_devs : 0;
}

static int drive_index_to_unit_id(BlockInterfaceType type, int index)
{
    int max_devs = if_max_devs[type];
    return max_devs ? index % max_devs : index;
}

QemuOpts *drive_def(const char *optstr)
{
    return qemu_opts_parse(qemu_find_opts("drive"), optstr, 0);
}

QemuOpts *drive_add(BlockInterfaceType type, int index, const char *file,
                    const char *optstr)
{
    QemuOpts *opts;
    char buf[32];
printf("drive_add type:%d,index:%d,file:%s,optstr:%s\n", type, index, file, optstr);
    opts = drive_def(optstr);
    if (!opts) {
        return NULL;
    }

    qemu_opt_set(opts, "if", if_name[type]);

    if (index >= 0) {
        snprintf(buf, sizeof(buf), "%d", index);
        qemu_opt_set(opts, "index", buf);
    }
    if (file)
        qemu_opt_set(opts, "file", file);
    return opts;
}

DriveInfo *drive_get(BlockInterfaceType type, int bus, int unit)
{
    DriveInfo *dinfo;

    /* seek interface, bus and unit */

    QTAILQ_FOREACH(dinfo, &drives, next) {
        if (dinfo->type == type &&
	    dinfo->bus == bus &&
	    dinfo->unit == unit)
            return dinfo;
    }

    return NULL;
}

DriveInfo *drive_get_by_index(BlockInterfaceType type, int index)
{
    return drive_get(type,
                     drive_index_to_bus_id(type, index),
                     drive_index_to_unit_id(type, index));
}

int drive_get_max_bus(BlockInterfaceType type)
{
    int max_bus;
    DriveInfo *dinfo;

    max_bus = -1;
    QTAILQ_FOREACH(dinfo, &drives, next) {
        if(dinfo->type == type &&
           dinfo->bus > max_bus)
            max_bus = dinfo->bus;
    }
    return max_bus;
}

/* Get a block device.  This should only be used for single-drive devices
   (e.g. SD/Floppy/MTD).  Multi-disk devices (scsi/ide) should use the
   appropriate bus.  */
DriveInfo *drive_get_next(BlockInterfaceType type)
{
    static int next_block_unit[IF_COUNT];

    return drive_get(type, 0, next_block_unit[type]++);
}

DriveInfo *drive_get_by_blockdev(BlockDriverState *bs)
{
    DriveInfo *dinfo;

    QTAILQ_FOREACH(dinfo, &drives, next) {
        if (dinfo->bdrv == bs) {
            return dinfo;
        }
    }
    return NULL;
}

static void bdrv_format_print(void *opaque, const char *name)
{
    fprintf(stderr, " %s", name);
}

static void drive_uninit(DriveInfo *dinfo)
{
    qemu_opts_del(dinfo->opts);
    bdrv_delete(dinfo->bdrv);
    free(dinfo->id);
    dinfo->id = NULL;
    QTAILQ_REMOVE(&drives, dinfo, next);
    dinfo = NULL;
}

void drive_put_ref(DriveInfo *dinfo)
{
    assert(dinfo->refcount);
    if (--dinfo->refcount == 0) {
        drive_uninit(dinfo);
    }
}

void drive_get_ref(DriveInfo *dinfo)
{
    dinfo->refcount++;
}

static int parse_block_error_action(const char *buf, int is_read)
{
    if (!strcmp(buf, "ignore")) {
        return BLOCK_ERR_IGNORE;
    } else if (!is_read && !strcmp(buf, "enospc")) {
        return BLOCK_ERR_STOP_ENOSPC;
    } else if (!strcmp(buf, "stop")) {
        return BLOCK_ERR_STOP_ANY;
    } else if (!strcmp(buf, "report")) {
        return BLOCK_ERR_REPORT;
    } else {
        printf("'%s' invalid %s error action",
                     buf, is_read ? "read" : "write");
        return -1;
    }
}

DriveInfo *drive_init(QemuOpts *opts)
{
    const char *buf;
    const char *file = NULL;
    char devname[128];
    const char *mediastr = "";
    BlockInterfaceType type;
    enum { MEDIA_DISK, MEDIA_CDROM } media;
    int bus_id, unit_id;
    int cyls, heads, secs, translation;
    BlockDriver *drv = NULL;
    int max_devs;
    int index;
    int ro = 0;
    int bdrv_flags = 0;
    int on_read_error, on_write_error;
    const char *devaddr;
    DriveInfo *dinfo;
    int ret;

    translation = BIOS_ATA_TRANSLATION_AUTO;
    media = MEDIA_DISK;

    /* extract parameters */
    bus_id  = qemu_opt_get_number(opts, "bus", 0);
    unit_id = qemu_opt_get_number(opts, "unit", -1);
    index   = qemu_opt_get_number(opts, "index", -1);

    cyls  = qemu_opt_get_number(opts, "cyls", 0);
    heads = qemu_opt_get_number(opts, "heads", 0);
    secs  = qemu_opt_get_number(opts, "secs", 0);

    ro = qemu_opt_get_bool(opts, "readonly", 0);

    file = qemu_opt_get(opts, "file");

    if ((buf = qemu_opt_get(opts, "if")) != NULL) {
        pstrcpy(devname, sizeof(devname), buf);
        for (type = 0; type < IF_COUNT && strcmp(buf, if_name[type]); type++)
            ;
        if (type == IF_COUNT) {
            printf("unsupported bus type '%s'", buf);
            return NULL;
	}
    } else {
        type = IF_IDE;
        pstrcpy(devname, sizeof(devname), if_name[type]);
    }

    max_devs = if_max_devs[type];

    if (cyls || heads || secs) {
        if (cyls < 1 || (type == IF_IDE && cyls > 16383)) {
            printf("invalid physical cyls number");
	    return NULL;
	}
        if (heads < 1 || (type == IF_IDE && heads > 16)) {
            printf("invalid physical heads number");
	    return NULL;
	}
        if (secs < 1 || (type == IF_IDE && secs > 63)) {
            printf("invalid physical secs number");
	    return NULL;
	}
    }

    if ((buf = qemu_opt_get(opts, "trans")) != NULL) {
        if (!cyls) {
            printf("'%s' trans must be used with cyls, heads and secs",
                         buf);
            return NULL;
        }
        if (!strcmp(buf, "none"))
            translation = BIOS_ATA_TRANSLATION_NONE;
        else if (!strcmp(buf, "lba"))
            translation = BIOS_ATA_TRANSLATION_LBA;
        else if (!strcmp(buf, "auto"))
            translation = BIOS_ATA_TRANSLATION_AUTO;
	else {
            printf("'%s' invalid translation type", buf);
	    return NULL;
	}
    }

    if ((buf = qemu_opt_get(opts, "media")) != NULL) {
        if (!strcmp(buf, "disk")) {
	    media = MEDIA_DISK;
	} else if (!strcmp(buf, "cdrom")) {
            if (cyls || secs || heads) {
                printf("CHS can't be set with media=%s", buf);
	        return NULL;
            }
	    media = MEDIA_CDROM;
	} else {
	    printf("'%s' invalid media", buf);
	    return NULL;
	}
    }

    if ((buf = qemu_opt_get(opts, "cache")) != NULL) {
        if (bdrv_parse_cache_flags(buf, &bdrv_flags) != 0) {
            printf("invalid cache option");
            return NULL;
        }
    }

    if ((buf = qemu_opt_get(opts, "format")) != NULL) {
       if (strcmp(buf, "?") == 0) {
           fprintf(stderr, "Supported formats:");
           bdrv_iterate_format(bdrv_format_print, NULL);
           fprintf(stderr, "\n");
           return NULL;
        }
        drv = bdrv_find_format(buf);
        if (!drv) {
            printf("'%s' invalid format", buf);
            return NULL;
        }
    }

    on_write_error = BLOCK_ERR_STOP_ENOSPC;
    if ((buf = qemu_opt_get(opts, "werror")) != NULL) {
        if (type != IF_IDE && type != IF_SCSI && type != IF_NONE) {
            printf("werror is not supported by this bus type");
            return NULL;
        }

        on_write_error = parse_block_error_action(buf, 0);
        if (on_write_error < 0) {
            return NULL;
        }
    }

    on_read_error = BLOCK_ERR_REPORT;
    if ((buf = qemu_opt_get(opts, "rerror")) != NULL) {
        if (type != IF_IDE && type != IF_SCSI && type != IF_NONE) {
            printf("rerror is not supported by this bus type");
            return NULL;
        }

        on_read_error = parse_block_error_action(buf, 1);
        if (on_read_error < 0) {
            return NULL;
        }
    }

    if ((devaddr = qemu_opt_get(opts, "addr")) != NULL) {
        printf("addr is not supported by this bus type");
        return NULL;
    }

    /* compute bus and unit according index */

    if (index != -1) {
        if (bus_id != 0 || unit_id != -1) {
            printf("index cannot be used with bus and unit");
            return NULL;
        }
        bus_id = drive_index_to_bus_id(type, index);
        unit_id = drive_index_to_unit_id(type, index);
    }

    /* if user doesn't specify a unit_id,
     * try to find the first free
     */

    if (unit_id == -1) {
       unit_id = 0;
       while (drive_get(type, bus_id, unit_id) != NULL) {
           unit_id++;
           if (max_devs && unit_id >= max_devs) {
               unit_id -= max_devs;
               bus_id++;
           }
       }
    }

    /* check unit id */

    if (max_devs && unit_id >= max_devs) {
        printf("unit %d too big (max is %d)",
                     unit_id, max_devs - 1);
        return NULL;
    }

    /*
     * catch multiple definitions
     */

    if (drive_get(type, bus_id, unit_id) != NULL) {
        printf("drive with bus=%d, unit=%d (index=%d) exists",
                     bus_id, unit_id, index);
        return NULL;
    }

    /* init */

    dinfo = calloc(1, sizeof(*dinfo));
    if ((buf = qemu_opts_id(opts)) != NULL) {
        dinfo->id = strdup(buf);
    } else {
        /* no id supplied -> create one */
        dinfo->id = calloc(1, 32);
        if (type == IF_IDE || type == IF_SCSI)
            mediastr = (media == MEDIA_CDROM) ? "-cd" : "-hd";
        if (max_devs)
            snprintf(dinfo->id, 32, "%s%i%s%i",
                     devname, bus_id, mediastr, unit_id);
        else
            snprintf(dinfo->id, 32, "%s%s%i",
                     devname, mediastr, unit_id);
    }
    dinfo->bdrv = bdrv_new(dinfo->id);
    dinfo->devaddr = devaddr;
    dinfo->type = type;
    dinfo->bus = bus_id;
    dinfo->unit = unit_id;
    dinfo->opts = opts;
    dinfo->refcount = 1;
    QTAILQ_INSERT_TAIL(&drives, dinfo, next);

    bdrv_set_on_error(dinfo->bdrv, on_read_error, on_write_error);

    switch(type) {
    case IF_IDE:
    case IF_SCSI:
    case IF_NONE:
        switch(media) {
		case MEDIA_DISK:
				if (cyls != 0) {
					bdrv_set_geometry_hint(dinfo->bdrv, cyls, heads, secs);
					bdrv_set_translation_hint(dinfo->bdrv, translation);
				}
			break;
		case MEDIA_CDROM:
				dinfo->media_cd = 1;
			break;
		}
        break;
    case IF_FLOPPY:
        break;
    default:
        abort();
    }
    if (!file || !*file) {
        return dinfo;
    }

    if (media == MEDIA_CDROM) {
        /* CDROM is fine for any interface, don't check.  */
        ro = 1;
    }

    bdrv_flags |= ro ? 0 : BDRV_O_RDWR;

    ret = bdrv_open(dinfo->bdrv, file, bdrv_flags, drv);
    if (ret < 0) {
        printf("could not open disk image %s: %s",
                     file, strerror(-ret));
        goto err;
    }

    return dinfo;

err:
    bdrv_delete(dinfo->bdrv);
    free(dinfo->id);
    dinfo->id = NULL;
    QTAILQ_REMOVE(&drives, dinfo, next);
    free(dinfo);
    dinfo = NULL;
    return NULL;
}
