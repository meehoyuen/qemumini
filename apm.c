#include "apm.h"
#include "hw.h"

//#define DEBUG

#ifdef DEBUG
# define APM_DPRINTF(format, ...)       printf(format, ## __VA_ARGS__)
#else
# define APM_DPRINTF(format, ...)       do { } while (0)
#endif

/* fixed I/O location */
#define APM_CNT_IOPORT  0xb2
#define APM_STS_IOPORT  0xb3

static void apm_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    APMState *apm = opaque;
    addr &= 1;
    APM_DPRINTF("apm_ioport_writeb addr=0x%x val=0x%02x\n", addr, val);
    if (addr == 0) {
        apm->apmc = val;

        if (apm->callback) {
            (apm->callback)(val, apm->arg);
        }
    } else {
        apm->apms = val;
    }
}

static uint32_t apm_ioport_readb(void *opaque, uint32_t addr)
{
    APMState *apm = opaque;
    uint32_t val;

    addr &= 1;
    if (addr == 0) {
        val = apm->apmc;
    } else {
        val = apm->apms;
    }
    APM_DPRINTF("apm_ioport_readb addr=0x%x val=0x%02x\n", addr, val);
    return val;
}

void apm_init(APMState *apm, apm_ctrl_changed_t callback, void *arg)
{
    apm->callback = callback;
    apm->arg = arg;

    /* ioport 0xb2, 0xb3 */
    register_ioport_write(APM_CNT_IOPORT, 2, 1, apm_ioport_writeb, apm);
    register_ioport_read(APM_CNT_IOPORT, 2, 1, apm_ioport_readb, apm);
}
