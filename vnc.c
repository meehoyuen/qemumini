#include <netdb.h>

#include "qemu-common.h"
#include "qemu-queue.h"
#include "console.h"

#define BITMAP_LAST_WORD_MASK(nbits)                                    \
    (                                                                   \
        ((nbits) % 64) ?                                     \
        (1UL<<((nbits) % 64))-1 : ~0UL                       \
        )

#define small_nbits(nbits)      ((nbits) <= 64)
#define BITS_TO_LONGS(nr)       (((nr) + 63) / 64)
#define BIT_MASK(nr)            (1UL << ((nr) % 64))
#define BIT_WORD(nr)            ((nr) / 64)

static inline unsigned long hweight_long(unsigned long w)
{
    unsigned long count;

    for (count = 0; w; w >>= 1) {
        count += w & 1;
    }
    return count;
}

static inline void set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p  |= mask;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p &= ~mask;
}

static inline int test_bit(int nr, const volatile unsigned long *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & 63));
}

static inline int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    unsigned long old = *p; 

    *p = old & ~mask;
    return (old & mask) != 0;
}

int slow_bitmap_empty(const unsigned long *bitmap, int bits);
static inline int bitmap_empty(const unsigned long *src, int nbits)
{
    if (small_nbits(nbits)) {
        return ! (*src & BITMAP_LAST_WORD_MASK(nbits));
    } else {
        return slow_bitmap_empty(src, nbits);
    }
}

void bitmap_set(unsigned long *map, int i, int len);
void bitmap_clear(unsigned long *map, int start, int nr);

int inet_listen(const char *str, char *ostr, int olen,
                int socktype, int port_offset)
{
    char addr[64];
    char port[33];
    int  sock = -1;
    int  on = 1;
    struct sockaddr_in sa;

    if (2 != sscanf(str,"%64[0-9.]:%32[^,]",addr,port)) {
        fprintf(stderr, "%s: ipv4 parse error (%s)\n", __FUNCTION__, str);
        return -1;
    }
    if (atoi(addr) != 0) {
        fprintf(stderr, "host addr %s not supported\n", str);
        return -1;
    }

    snprintf(port, sizeof(port), "%d", atoi(port) + port_offset);


    sock = socket(PF_INET, socktype, 0);
    if (sock >= 0) {
        qemu_set_cloexec(sock);
    }else {
        fprintf(stderr,"%s: socket: %s\n", __FUNCTION__, strerror(errno));
        return -1;
    }

    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void*)&on,sizeof(on));

    memset(&sa,0, sizeof(sa));
    sa.sin_family = AF_INET;  
    sa.sin_addr.s_addr = 0;
    sa.sin_port = htons(atoi(port));
    if (bind(sock, &sa, sizeof(sa))) {
        close(sock);
        return -1;
    }

    if (listen(sock,1) != 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;
}

// #define _VNC_DEBUG 1

#ifdef _VNC_DEBUG
#define VNC_DEBUG(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define VNC_DEBUG(fmt, ...) do { } while (0)
#endif

#define VNC_PALETTE_HASH_SIZE 256
#define VNC_PALETTE_MAX_SIZE  256

#include "qemu-common.h"

typedef struct {
	const char* name;
	int keysym;
} name2keysym_t;

struct key_range {
    int start;
    int end;
    struct key_range *next;
};

#define MAX_NORMAL_KEYCODE 512
#define MAX_EXTRA_COUNT 256
typedef struct {
    uint16_t keysym2keycode[MAX_NORMAL_KEYCODE];
    struct {
	int keysym;
	uint16_t keycode;
    } keysym2keycode_extra[MAX_EXTRA_COUNT];
    int extra_count;
    struct key_range *keypad_range;
    struct key_range *numlock_range;
} kbd_layout_t;

typedef struct VncPaletteEntry {
    int idx;
    uint32_t color;
    QLIST_ENTRY(VncPaletteEntry) next;
} VncPaletteEntry;

typedef struct VncPalette {
    VncPaletteEntry pool[VNC_PALETTE_MAX_SIZE];
    size_t size;
    size_t max;
    int bpp;
    QLIST_HEAD(,VncPaletteEntry) table[VNC_PALETTE_HASH_SIZE];
} VncPalette;

/*****************************************************************************
 *
 * Core data structures
 *
 *****************************************************************************/

typedef struct Buffer
{
    size_t capacity;
    size_t offset;
    uint8_t *buffer;
} Buffer;

typedef struct VncState VncState;
typedef struct VncJob VncJob;
typedef struct VncRect VncRect;
typedef struct VncRectEntry VncRectEntry;

typedef int VncReadEvent(VncState *vs, uint8_t *data, size_t len);

typedef void VncWritePixels(VncState *vs, struct PixelFormat *pf, void *data, int size);

typedef void VncSendHextileTile(VncState *vs,
                                int x, int y, int w, int h,
                                void *last_bg,
                                void *last_fg,
                                int *has_bg, int *has_fg);

/* VNC_MAX_WIDTH must be a multiple of 16. */
#define VNC_MAX_WIDTH 2560
#define VNC_MAX_HEIGHT 2048

/* VNC_DIRTY_BITS is the number of bits in the dirty bitmap. */
#define VNC_DIRTY_BITS (VNC_MAX_WIDTH / 16)

#define VNC_STAT_RECT  64
#define VNC_STAT_COLS (VNC_MAX_WIDTH / VNC_STAT_RECT)
#define VNC_STAT_ROWS (VNC_MAX_HEIGHT / VNC_STAT_RECT)

#define VNC_AUTH_CHALLENGE_SIZE 16

typedef struct VncDisplay VncDisplay;


struct VncRectStat
{
    /* time of last 10 updates, to find update frequency */
    struct timeval times[10];
    int idx;

    double freq;        /* Update frequency (in Hz) */
    bool updated;       /* Already updated during this refresh */
};

typedef struct VncRectStat VncRectStat;

struct VncSurface
{
    struct timeval last_freq_check;
    unsigned long dirty[VNC_MAX_HEIGHT][BITS_TO_LONGS(VNC_MAX_WIDTH/16)];
    VncRectStat stats[VNC_STAT_ROWS][VNC_STAT_COLS];
    DisplaySurface *ds;
};

struct VncDisplay
{
    QTAILQ_HEAD(, VncState) clients;
    QEMUTimer *timer;
    int timer_interval;
    int lsock;
    DisplayState *ds;
    kbd_layout_t *kbd_layout;
    int lock_key_sync;
    QEMUCursor *cursor;
    int cursor_msize;
    uint8_t *cursor_mask;

    struct VncSurface guest;   /* guest visible surface (aka ds->surface) */
    DisplaySurface *server;  /* vnc server surface */

    char *display;
    char *password;
    time_t expires;
    int auth;
    bool lossy;
    bool non_adaptive;
};

struct VncJob
{
    VncState *vs;
    int rectangles;
    size_t saved_offset;
};

struct VncState
{
    int csock;

    DisplayState *ds;
    unsigned long dirty[VNC_MAX_HEIGHT][BITS_TO_LONGS(VNC_DIRTY_BITS)];
    uint8_t **lossy_rect; /* Not an Array to avoid costly memcpy in
                           * vnc-jobs-async.c */

    VncDisplay *vd;
    int need_update;
    int force_update;
    uint32_t features;
    int absolute;
    int last_x;
    int last_y;
    int client_width;
    int client_height;

    uint32_t vnc_encoding;

    int major;
    int minor;

    int auth;
    char challenge[VNC_AUTH_CHALLENGE_SIZE];

    Buffer output;
    Buffer input;
    /* current output mode information */
    VncWritePixels *write_pixels;
    DisplaySurface clientds;

    VncReadEvent *read_handler;
    size_t read_handler_expect;
    /* input */
    uint8_t modifiers_state[256];
    QEMUPutLEDEntry *led;

    bool abort;
    VncJob job;

    Notifier mouse_mode_notifier;

    QTAILQ_ENTRY(VncState) next;
};


/*****************************************************************************
 *
 * Authentication modes
 *
 *****************************************************************************/

enum {
    VNC_AUTH_INVALID = 0,
    VNC_AUTH_NONE = 1,
};

/*****************************************************************************
 *
 * Encoding types
 *
 *****************************************************************************/

#define VNC_ENCODING_RAW                  0x00000000
#define VNC_ENCODING_COPYRECT             0x00000001
#define VNC_ENCODING_RRE                  0x00000002
#define VNC_ENCODING_CORRE                0x00000004
#define VNC_ENCODING_HEXTILE              0x00000005
#define VNC_ENCODING_ZLIB                 0x00000006
#define VNC_ENCODING_TIGHT                0x00000007
#define VNC_ENCODING_ZLIBHEX              0x00000008
#define VNC_ENCODING_TRLE                 0x0000000f
#define VNC_ENCODING_ZRLE                 0x00000010
#define VNC_ENCODING_ZYWRLE               0x00000011
#define VNC_ENCODING_COMPRESSLEVEL0       0xFFFFFF00 /* -256 */
#define VNC_ENCODING_QUALITYLEVEL0        0xFFFFFFE0 /* -32  */
#define VNC_ENCODING_XCURSOR              0xFFFFFF10 /* -240 */
#define VNC_ENCODING_RICH_CURSOR          0xFFFFFF11 /* -239 */
#define VNC_ENCODING_POINTER_POS          0xFFFFFF18 /* -232 */
#define VNC_ENCODING_LASTRECT             0xFFFFFF20 /* -224 */
#define VNC_ENCODING_DESKTOPRESIZE        0xFFFFFF21 /* -223 */
#define VNC_ENCODING_POINTER_TYPE_CHANGE  0XFFFFFEFF /* -257 */
#define VNC_ENCODING_EXT_KEY_EVENT        0XFFFFFEFE /* -258 */
#define VNC_ENCODING_AUDIO                0XFFFFFEFD /* -259 */
#define VNC_ENCODING_TIGHT_PNG            0xFFFFFEFC /* -260 */
#define VNC_ENCODING_WMVi                 0x574D5669


/*****************************************************************************
 *
 * Features
 *
 *****************************************************************************/
#define VNC_FEATURE_RESIZE                   0
#define VNC_FEATURE_HEXTILE                  1
#define VNC_FEATURE_POINTER_TYPE_CHANGE      2
#define VNC_FEATURE_WMVI                     3
#define VNC_FEATURE_TIGHT                    4
#define VNC_FEATURE_ZLIB                     5
#define VNC_FEATURE_COPYRECT                 6
#define VNC_FEATURE_RICH_CURSOR              7
#define VNC_FEATURE_TIGHT_PNG                8
#define VNC_FEATURE_ZRLE                     9
#define VNC_FEATURE_ZYWRLE                  10

#define VNC_FEATURE_RESIZE_MASK              (1 << VNC_FEATURE_RESIZE)
#define VNC_FEATURE_HEXTILE_MASK             (1 << VNC_FEATURE_HEXTILE)
#define VNC_FEATURE_POINTER_TYPE_CHANGE_MASK (1 << VNC_FEATURE_POINTER_TYPE_CHANGE)
#define VNC_FEATURE_WMVI_MASK                (1 << VNC_FEATURE_WMVI)
#define VNC_FEATURE_TIGHT_MASK               (1 << VNC_FEATURE_TIGHT)
#define VNC_FEATURE_ZLIB_MASK                (1 << VNC_FEATURE_ZLIB)
#define VNC_FEATURE_COPYRECT_MASK            (1 << VNC_FEATURE_COPYRECT)
#define VNC_FEATURE_RICH_CURSOR_MASK         (1 << VNC_FEATURE_RICH_CURSOR)
#define VNC_FEATURE_TIGHT_PNG_MASK           (1 << VNC_FEATURE_TIGHT_PNG)
#define VNC_FEATURE_ZRLE_MASK                (1 << VNC_FEATURE_ZRLE)
#define VNC_FEATURE_ZYWRLE_MASK              (1 << VNC_FEATURE_ZYWRLE)


/* Client -> Server message IDs */
#define VNC_MSG_CLIENT_SET_PIXEL_FORMAT           0
#define VNC_MSG_CLIENT_SET_ENCODINGS              2
#define VNC_MSG_CLIENT_FRAMEBUFFER_UPDATE_REQUEST 3
#define VNC_MSG_CLIENT_KEY_EVENT                  4
#define VNC_MSG_CLIENT_POINTER_EVENT              5
#define VNC_MSG_CLIENT_CUT_TEXT                   6
#define VNC_MSG_CLIENT_VMWARE_0                   127
#define VNC_MSG_CLIENT_CALL_CONTROL               249
#define VNC_MSG_CLIENT_XVP                        250
#define VNC_MSG_CLIENT_SET_DESKTOP_SIZE           251
#define VNC_MSG_CLIENT_TIGHT                      252
#define VNC_MSG_CLIENT_GII                        253
#define VNC_MSG_CLIENT_VMWARE_1                   254
#define VNC_MSG_CLIENT_QEMU                       255

/* Server -> Client message IDs */
#define VNC_MSG_SERVER_FRAMEBUFFER_UPDATE         0
#define VNC_MSG_SERVER_SET_COLOUR_MAP_ENTRIES     1
#define VNC_MSG_SERVER_BELL                       2
#define VNC_MSG_SERVER_CUT_TEXT                   3
#define VNC_MSG_SERVER_VMWARE_0                   127
#define VNC_MSG_SERVER_CALL_CONTROL               249
#define VNC_MSG_SERVER_XVP                        250
#define VNC_MSG_SERVER_TIGHT                      252
#define VNC_MSG_SERVER_GII                        253
#define VNC_MSG_SERVER_VMWARE_1                   254
#define VNC_MSG_SERVER_QEMU                       255


/* QEMU client -> server message IDs */
#define VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT         0

/*****************************************************************************
 *
 * Internal APIs
 *
 *****************************************************************************/

/* Event loop functions */
void vnc_client_read(void *opaque);
void vnc_client_write(void *opaque);

long vnc_client_read_buf(VncState *vs, uint8_t *data, size_t datalen);
long vnc_client_write_buf(VncState *vs, const uint8_t *data, size_t datalen);

/* Protocol I/O functions */
void vnc_write(VncState *vs, const void *data, size_t len);
void vnc_write_u32(VncState *vs, uint32_t value);
void vnc_write_s32(VncState *vs, int32_t value);
void vnc_write_u16(VncState *vs, uint16_t value);
void vnc_write_u8(VncState *vs, uint8_t value);
void vnc_flush(VncState *vs);
void vnc_read_when(VncState *vs, VncReadEvent *func, size_t expecting);


/* Buffer I/O functions */
uint8_t read_u8(uint8_t *data, size_t offset);
uint16_t read_u16(uint8_t *data, size_t offset);
int32_t read_s32(uint8_t *data, size_t offset);
uint32_t read_u32(uint8_t *data, size_t offset);

/* Protocol stage functions */
void vnc_client_error(VncState *vs);
int vnc_client_io_error(VncState *vs, int ret, int last_errno);
void start_client_init(VncState *vs);

/* Buffer management */
void buffer_reserve(Buffer *buffer, size_t len);
int buffer_empty(Buffer *buffer);
uint8_t *buffer_end(Buffer *buffer);
void buffer_reset(Buffer *buffer);
void buffer_free(Buffer *buffer);
void buffer_append(Buffer *buffer, const void *data, size_t len);


/* Misc helpers */
char *vnc_socket_local_addr(const char *format, int fd);

static inline uint32_t vnc_has_feature(VncState *vs, int feature) {
    return (vs->features & (1 << feature));
}

/* Framebuffer */
void vnc_framebuffer_update(VncState *vs, int x, int y, int w, int h,
                            int32_t encoding);

void vnc_convert_pixel(VncState *vs, uint8_t *buf, uint32_t v);
double vnc_update_freq(VncState *vs, int x, int y, int w, int h);
void vnc_sent_lossy_rect(VncState *vs, int x, int y, int w, int h);

/* Encodings */
int vnc_send_framebuffer_update(VncState *vs, int x, int y, int w, int h);

int vnc_raw_send_framebuffer_update(VncState *vs, int x, int y, int w, int h);

#include "sysemu.h"
#include "qemu-timer.h"

#define VNC_REFRESH_INTERVAL_BASE 30
#define VNC_REFRESH_INTERVAL_INC  50
#define VNC_REFRESH_INTERVAL_MAX  2000
static const struct timeval VNC_REFRESH_STATS = { 0, 500000 };
static const struct timeval VNC_REFRESH_LOSSY = { 2, 0 };

/* Jobs */
VncJob *vnc_job_new(VncState *vs);
int vnc_job_add_rect(VncJob *job, int x, int y, int w, int h);
void vnc_job_push(VncJob *job);

/* scancode without modifiers */
#define SCANCODE_KEYMASK 0xff
/* scancode without grey or up bit */
#define SCANCODE_KEYCODEMASK 0x7f

/* "grey" keys will usually need a 0xe0 prefix */
#define SCANCODE_GREY   0x80
#define SCANCODE_EMUL0  0xE0
/* "up" flag */
#define SCANCODE_UP     0x80

/* Additional modifiers to use if not catched another way. */
#define SCANCODE_SHIFT  0x100
#define SCANCODE_CTRL   0x200
#define SCANCODE_ALT    0x400
#define SCANCODE_ALTGR  0x800


static const name2keysym_t name2keysym[]={
/* ascii */
    { "space",                0x020},
    { "exclam",               0x021},
    { "quotedbl",             0x022},
    { "numbersign",           0x023},
    { "dollar",               0x024},
    { "percent",              0x025},
    { "ampersand",            0x026},
    { "apostrophe",           0x027},
    { "parenleft",            0x028},
    { "parenright",           0x029},
    { "asterisk",             0x02a},
    { "plus",                 0x02b},
    { "comma",                0x02c},
    { "minus",                0x02d},
    { "period",               0x02e},
    { "slash",                0x02f},
    { "0",                    0x030},
    { "1",                    0x031},
    { "2",                    0x032},
    { "3",                    0x033},
    { "4",                    0x034},
    { "5",                    0x035},
    { "6",                    0x036},
    { "7",                    0x037},
    { "8",                    0x038},
    { "9",                    0x039},
    { "colon",                0x03a},
    { "semicolon",            0x03b},
    { "less",                 0x03c},
    { "equal",                0x03d},
    { "greater",              0x03e},
    { "question",             0x03f},
    { "at",                   0x040},
    { "A",                    0x041},
    { "B",                    0x042},
    { "C",                    0x043},
    { "D",                    0x044},
    { "E",                    0x045},
    { "F",                    0x046},
    { "G",                    0x047},
    { "H",                    0x048},
    { "I",                    0x049},
    { "J",                    0x04a},
    { "K",                    0x04b},
    { "L",                    0x04c},
    { "M",                    0x04d},
    { "N",                    0x04e},
    { "O",                    0x04f},
    { "P",                    0x050},
    { "Q",                    0x051},
    { "R",                    0x052},
    { "S",                    0x053},
    { "T",                    0x054},
    { "U",                    0x055},
    { "V",                    0x056},
    { "W",                    0x057},
    { "X",                    0x058},
    { "Y",                    0x059},
    { "Z",                    0x05a},
    { "bracketleft",          0x05b},
    { "backslash",            0x05c},
    { "bracketright",         0x05d},
    { "asciicircum",          0x05e},
    { "underscore",           0x05f},
    { "grave",                0x060},
    { "a",                    0x061},
    { "b",                    0x062},
    { "c",                    0x063},
    { "d",                    0x064},
    { "e",                    0x065},
    { "f",                    0x066},
    { "g",                    0x067},
    { "h",                    0x068},
    { "i",                    0x069},
    { "j",                    0x06a},
    { "k",                    0x06b},
    { "l",                    0x06c},
    { "m",                    0x06d},
    { "n",                    0x06e},
    { "o",                    0x06f},
    { "p",                    0x070},
    { "q",                    0x071},
    { "r",                    0x072},
    { "s",                    0x073},
    { "t",                    0x074},
    { "u",                    0x075},
    { "v",                    0x076},
    { "w",                    0x077},
    { "x",                    0x078},
    { "y",                    0x079},
    { "z",                    0x07a},
    { "braceleft",            0x07b},
    { "bar",                  0x07c},
    { "braceright",           0x07d},
    { "asciitilde",           0x07e},

/* latin 1 extensions */
{ "nobreakspace",         0x0a0},
{ "exclamdown",           0x0a1},
{ "cent",         	  0x0a2},
{ "sterling",             0x0a3},
{ "currency",             0x0a4},
{ "yen",                  0x0a5},
{ "brokenbar",            0x0a6},
{ "section",              0x0a7},
{ "diaeresis",            0x0a8},
{ "copyright",            0x0a9},
{ "ordfeminine",          0x0aa},
{ "guillemotleft",        0x0ab},
{ "notsign",              0x0ac},
{ "hyphen",               0x0ad},
{ "registered",           0x0ae},
{ "macron",               0x0af},
{ "degree",               0x0b0},
{ "plusminus",            0x0b1},
{ "twosuperior",          0x0b2},
{ "threesuperior",        0x0b3},
{ "acute",                0x0b4},
{ "mu",                   0x0b5},
{ "paragraph",            0x0b6},
{ "periodcentered",       0x0b7},
{ "cedilla",              0x0b8},
{ "onesuperior",          0x0b9},
{ "masculine",            0x0ba},
{ "guillemotright",       0x0bb},
{ "onequarter",           0x0bc},
{ "onehalf",              0x0bd},
{ "threequarters",        0x0be},
{ "questiondown",         0x0bf},
{ "Agrave",               0x0c0},
{ "Aacute",               0x0c1},
{ "Acircumflex",          0x0c2},
{ "Atilde",               0x0c3},
{ "Adiaeresis",           0x0c4},
{ "Aring",                0x0c5},
{ "AE",                   0x0c6},
{ "Ccedilla",             0x0c7},
{ "Egrave",               0x0c8},
{ "Eacute",               0x0c9},
{ "Ecircumflex",          0x0ca},
{ "Ediaeresis",           0x0cb},
{ "Igrave",               0x0cc},
{ "Iacute",               0x0cd},
{ "Icircumflex",          0x0ce},
{ "Idiaeresis",           0x0cf},
{ "ETH",                  0x0d0},
{ "Eth",                  0x0d0},
{ "Ntilde",               0x0d1},
{ "Ograve",               0x0d2},
{ "Oacute",               0x0d3},
{ "Ocircumflex",          0x0d4},
{ "Otilde",               0x0d5},
{ "Odiaeresis",           0x0d6},
{ "multiply",             0x0d7},
{ "Ooblique",             0x0d8},
{ "Oslash",               0x0d8},
{ "Ugrave",               0x0d9},
{ "Uacute",               0x0da},
{ "Ucircumflex",          0x0db},
{ "Udiaeresis",           0x0dc},
{ "Yacute",               0x0dd},
{ "THORN",                0x0de},
{ "Thorn",                0x0de},
{ "ssharp",               0x0df},
{ "agrave",               0x0e0},
{ "aacute",               0x0e1},
{ "acircumflex",          0x0e2},
{ "atilde",               0x0e3},
{ "adiaeresis",           0x0e4},
{ "aring",                0x0e5},
{ "ae",                   0x0e6},
{ "ccedilla",             0x0e7},
{ "egrave",               0x0e8},
{ "eacute",               0x0e9},
{ "ecircumflex",          0x0ea},
{ "ediaeresis",           0x0eb},
{ "igrave",               0x0ec},
{ "iacute",               0x0ed},
{ "icircumflex",          0x0ee},
{ "idiaeresis",           0x0ef},
{ "eth",                  0x0f0},
{ "ntilde",               0x0f1},
{ "ograve",               0x0f2},
{ "oacute",               0x0f3},
{ "ocircumflex",          0x0f4},
{ "otilde",               0x0f5},
{ "odiaeresis",           0x0f6},
{ "division",             0x0f7},
{ "oslash",               0x0f8},
{ "ooblique",             0x0f8},
{ "ugrave",               0x0f9},
{ "uacute",               0x0fa},
{ "ucircumflex",          0x0fb},
{ "udiaeresis",           0x0fc},
{ "yacute",               0x0fd},
{ "thorn",                0x0fe},
{ "ydiaeresis",           0x0ff},
{"EuroSign", 0x20ac},  /* XK_EuroSign */

/* latin 2 - Polish national characters */
{ "eogonek",              0x1ea},
{ "Eogonek",              0x1ca},
{ "aogonek",              0x1b1},
{ "Aogonek",              0x1a1},
{ "sacute",               0x1b6},
{ "Sacute",               0x1a6},
{ "lstroke",              0x1b3},
{ "Lstroke",              0x1a3},
{ "zabovedot",            0x1bf},
{ "Zabovedot",            0x1af},
{ "zacute",               0x1bc},
{ "Zacute",               0x1ac},
{ "cacute",               0x1e6},
{ "Cacute",               0x1c6},
{ "nacute",               0x1f1},
{ "Nacute",               0x1d1},

    /* modifiers */
{"ISO_Level3_Shift", 0xfe03}, /* XK_ISO_Level3_Shift */
{"Control_L", 0xffe3}, /* XK_Control_L */
{"Control_R", 0xffe4}, /* XK_Control_R */
{"Alt_L", 0xffe9},     /* XK_Alt_L */
{"Alt_R", 0xffea},     /* XK_Alt_R */
{"Caps_Lock", 0xffe5}, /* XK_Caps_Lock */
{"Meta_L", 0xffe7},    /* XK_Meta_L */
{"Meta_R", 0xffe8},    /* XK_Meta_R */
{"Shift_L", 0xffe1},   /* XK_Shift_L */
{"Shift_R", 0xffe2},   /* XK_Shift_R */
{"Super_L", 0xffeb},   /* XK_Super_L */
{"Super_R", 0xffec},   /* XK_Super_R */

    /* special keys */
{"BackSpace", 0xff08}, /* XK_BackSpace */
{"Tab", 0xff09},       /* XK_Tab */
{"Return", 0xff0d},    /* XK_Return */
{"Right", 0xff53},     /* XK_Right */
{"Left", 0xff51},      /* XK_Left */
{"Up", 0xff52},        /* XK_Up */
{"Down", 0xff54},      /* XK_Down */
{"Page_Down", 0xff56}, /* XK_Page_Down */
{"Page_Up", 0xff55},   /* XK_Page_Up */
{"Insert", 0xff63},    /* XK_Insert */
{"Delete", 0xffff},    /* XK_Delete */
{"Home", 0xff50},      /* XK_Home */
{"End", 0xff57},       /* XK_End */
{"Scroll_Lock", 0xff14}, /* XK_Scroll_Lock */
{"KP_Home", 0xff95},
{"KP_Left", 0xff96},
{"KP_Up", 0xff97},
{"KP_Right", 0xff98},
{"KP_Down", 0xff99},
{"KP_Prior", 0xff9a},
{"KP_Page_Up", 0xff9a},
{"KP_Next", 0xff9b},
{"KP_Page_Down", 0xff9b},
{"KP_End", 0xff9c},
{"KP_Begin", 0xff9d},
{"KP_Insert", 0xff9e},
{"KP_Delete", 0xff9f},
{"F1", 0xffbe},        /* XK_F1 */
{"F2", 0xffbf},        /* XK_F2 */
{"F3", 0xffc0},        /* XK_F3 */
{"F4", 0xffc1},        /* XK_F4 */
{"F5", 0xffc2},        /* XK_F5 */
{"F6", 0xffc3},        /* XK_F6 */
{"F7", 0xffc4},        /* XK_F7 */
{"F8", 0xffc5},        /* XK_F8 */
{"F9", 0xffc6},        /* XK_F9 */
{"F10", 0xffc7},       /* XK_F10 */
{"F11", 0xffc8},       /* XK_F11 */
{"F12", 0xffc9},       /* XK_F12 */
{"F13", 0xffca},       /* XK_F13 */
{"F14", 0xffcb},       /* XK_F14 */
{"F15", 0xffcc},       /* XK_F15 */
{"Sys_Req", 0xff15},   /* XK_Sys_Req */
{"KP_0", 0xffb0},      /* XK_KP_0 */
{"KP_1", 0xffb1},      /* XK_KP_1 */
{"KP_2", 0xffb2},      /* XK_KP_2 */
{"KP_3", 0xffb3},      /* XK_KP_3 */
{"KP_4", 0xffb4},      /* XK_KP_4 */
{"KP_5", 0xffb5},      /* XK_KP_5 */
{"KP_6", 0xffb6},      /* XK_KP_6 */
{"KP_7", 0xffb7},      /* XK_KP_7 */
{"KP_8", 0xffb8},      /* XK_KP_8 */
{"KP_9", 0xffb9},      /* XK_KP_9 */
{"KP_Add", 0xffab},    /* XK_KP_Add */
{"KP_Separator", 0xffac},/* XK_KP_Separator */
{"KP_Decimal", 0xffae},  /* XK_KP_Decimal */
{"KP_Divide", 0xffaf},   /* XK_KP_Divide */
{"KP_Enter", 0xff8d},    /* XK_KP_Enter */
{"KP_Equal", 0xffbd},    /* XK_KP_Equal */
{"KP_Multiply", 0xffaa}, /* XK_KP_Multiply */
{"KP_Subtract", 0xffad}, /* XK_KP_Subtract */
{"help", 0xff6a},        /* XK_Help */
{"Menu", 0xff67},        /* XK_Menu */
{"Print", 0xff61},       /* XK_Print */
{"Mode_switch", 0xff7e}, /* XK_Mode_switch */
{"Num_Lock", 0xff7f},    /* XK_Num_Lock */
{"Pause", 0xff13},       /* XK_Pause */
{"Escape", 0xff1b},      /* XK_Escape */

/* dead keys */
{"dead_grave", 0xfe50}, /* XK_dead_grave */
{"dead_acute", 0xfe51}, /* XK_dead_acute */
{"dead_circumflex", 0xfe52}, /* XK_dead_circumflex */
{"dead_tilde", 0xfe53}, /* XK_dead_tilde */
{"dead_macron", 0xfe54}, /* XK_dead_macron */
{"dead_breve", 0xfe55}, /* XK_dead_breve */
{"dead_abovedot", 0xfe56}, /* XK_dead_abovedot */
{"dead_diaeresis", 0xfe57}, /* XK_dead_diaeresis */
{"dead_abovering", 0xfe58}, /* XK_dead_abovering */
{"dead_doubleacute", 0xfe59}, /* XK_dead_doubleacute */
{"dead_caron", 0xfe5a}, /* XK_dead_caron */
{"dead_cedilla", 0xfe5b}, /* XK_dead_cedilla */
{"dead_ogonek", 0xfe5c}, /* XK_dead_ogonek */
{"dead_iota", 0xfe5d}, /* XK_dead_iota */
{"dead_voiced_sound", 0xfe5e}, /* XK_dead_voiced_sound */
{"dead_semivoiced_sound", 0xfe5f}, /* XK_dead_semivoiced_sound */
{"dead_belowdot", 0xfe60}, /* XK_dead_belowdot */
{"dead_hook", 0xfe61}, /* XK_dead_hook */
{"dead_horn", 0xfe62}, /* XK_dead_horn */


    /* localized keys */
{"BackApostrophe", 0xff21},
{"Muhenkan", 0xff22},
{"Katakana", 0xff27},
{"Hankaku", 0xff29},
{"Zenkaku_Hankaku", 0xff2a},
{"Henkan_Mode_Real", 0xff23},
{"Henkan_Mode_Ultra", 0xff3e},
{"backslash_ja", 0xffa5},
{"Katakana_Real", 0xff25},
{"Eisu_toggle", 0xff30},

{NULL,0},
};

void *init_keyboard_layout(const name2keysym_t *table, const char *language);
int keysym2scancode(void *kbd_layout, int keysym);
int keycode_is_keypad(void *kbd_layout, int keycode);
int keysym_is_numlock(void *kbd_layout, int keysym);


static VncDisplay *vnc_display; /* needed for info vnc */
static DisplayChangeListener *dcl;

static int vnc_cursor_define(VncState *vs);

static char *addr_to_string(const char *format,
                            struct sockaddr_storage *sa,
                            socklen_t salen) {
    char *addr;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int err;
    size_t addrlen;

    if ((err = getnameinfo((struct sockaddr *)sa, salen,
                           host, sizeof(host),
                           serv, sizeof(serv),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        VNC_DEBUG("Cannot resolve address %d: %s\n",
                  err, gai_strerror(err));
        return NULL;
    }

    /* Enough for the existing format + the 2 vars we're
     * substituting in. */
    addrlen = strlen(format) + strlen(host) + strlen(serv);
    addr = malloc(addrlen + 1);
    snprintf(addr, addrlen, format, host, serv);
    addr[addrlen] = '\0';

    return addr;
}


char *vnc_socket_local_addr(const char *format, int fd) {
    struct sockaddr_storage sa;
    socklen_t salen;

    salen = sizeof(sa);
    if (getsockname(fd, (struct sockaddr*)&sa, &salen) < 0)
        return NULL;

    return addr_to_string(format, &sa, salen);
}

/* TODO
   1) Get the queue working for IO.
   2) there is some weirdness when using the -S option (the screen is grey
      and not totally invalidated
   3) resolutions > 1024
*/

static int vnc_update_client(VncState *vs, int has_dirty);
static int vnc_update_client_sync(VncState *vs, int has_dirty);
static void vnc_disconnect_start(VncState *vs);
static void vnc_disconnect_finish(VncState *vs);
static void vnc_init_timer(VncDisplay *vd);
static void vnc_remove_timer(VncDisplay *vd);

static void vnc_colordepth(VncState *vs);
static void framebuffer_update_request(VncState *vs, int incremental,
                                       int x_position, int y_position,
                                       int w, int h);
static void vnc_refresh(void *opaque);
static int vnc_refresh_server_surface(VncDisplay *vd);

static void vnc_dpy_update(DisplayState *ds, int x, int y, int w, int h)
{
    int i;
    VncDisplay *vd = ds->opaque;
    struct VncSurface *s = &vd->guest;

    h += y;

    /* round x down to ensure the loop only spans one 16-pixel block per,
       iteration.  otherwise, if (x % 16) != 0, the last iteration may span
       two 16-pixel blocks but we only mark the first as dirty
    */
    w += (x % 16);
    x -= (x % 16);

    x = MIN(x, s->ds->width);
    y = MIN(y, s->ds->height);
    w = MIN(x + w, s->ds->width) - x;
    h = MIN(h, s->ds->height);

    for (; y < h; y++)
        for (i = 0; i < w; i += 16)
            set_bit((x + i) / 16, s->dirty[y]);
}

void vnc_framebuffer_update(VncState *vs, int x, int y, int w, int h,
                            int32_t encoding)
{
    vnc_write_u16(vs, x);
    vnc_write_u16(vs, y);
    vnc_write_u16(vs, w);
    vnc_write_u16(vs, h);

    vnc_write_s32(vs, encoding);
}

void buffer_reserve(Buffer *buffer, size_t len)
{
    if ((buffer->capacity - buffer->offset) < len) {
        buffer->capacity += (len + 1024);
        buffer->buffer = realloc(buffer->buffer, buffer->capacity);
        if (buffer->buffer == NULL) {
            fprintf(stderr, "vnc: out of memory\n");
            exit(1);
        }
    }
}

int buffer_empty(Buffer *buffer)
{
    return buffer->offset == 0;
}

uint8_t *buffer_end(Buffer *buffer)
{
    return buffer->buffer + buffer->offset;
}

void buffer_reset(Buffer *buffer)
{
        buffer->offset = 0;
}

void buffer_free(Buffer *buffer)
{
    free(buffer->buffer);
    buffer->buffer = NULL;
    buffer->offset = 0;
    buffer->capacity = 0;
    buffer->buffer = NULL;
}

void buffer_append(Buffer *buffer, const void *data, size_t len)
{
    memcpy(buffer->buffer + buffer->offset, data, len);
    buffer->offset += len;
}

static void vnc_desktop_resize(VncState *vs)
{
    DisplayState *ds = vs->ds;

    if (vs->csock == -1 || !vnc_has_feature(vs, VNC_FEATURE_RESIZE)) {
        return;
    }
    if (vs->client_width == ds_get_width(ds) &&
        vs->client_height == ds_get_height(ds)) {
        return;
    }
    vs->client_width = ds_get_width(ds);
    vs->client_height = ds_get_height(ds);
    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1); /* number of rects */
    vnc_framebuffer_update(vs, 0, 0, vs->client_width, vs->client_height,
                           VNC_ENCODING_DESKTOPRESIZE);
    vnc_flush(vs);
}

static void vnc_dpy_resize(DisplayState *ds)
{
    VncDisplay *vd = ds->opaque;
    VncState *vs;

    /* server surface */
    if (!vd->server)
        vd->server = calloc(1, sizeof(*vd->server));
    if (vd->server->data)
        free(vd->server->data);
        vd->server->data = NULL;
    *(vd->server) = *(ds->surface);
    vd->server->data = calloc(1, vd->server->linesize *
                                    vd->server->height);

    /* guest surface */
    if (!vd->guest.ds)
        vd->guest.ds = calloc(1, sizeof(*vd->guest.ds));
    if (ds_get_bytes_per_pixel(ds) != vd->guest.ds->pf.bytes_per_pixel)
        console_color_init(ds);
    *(vd->guest.ds) = *(ds->surface);
    memset(vd->guest.dirty, 0xFF, sizeof(vd->guest.dirty));

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        vnc_colordepth(vs);
        vnc_desktop_resize(vs);
        if (vs->vd->cursor) {
            vnc_cursor_define(vs);
        }
        memset(vs->dirty, 0xFF, sizeof(vs->dirty));
    }
}

/* fastest code */
static void vnc_write_pixels_copy(VncState *vs, struct PixelFormat *pf,
                                  void *pixels, int size)
{
    vnc_write(vs, pixels, size);
}

/* slowest but generic code. */
void vnc_convert_pixel(VncState *vs, uint8_t *buf, uint32_t v)
{
    uint8_t r, g, b;
    VncDisplay *vd = vs->vd;

    r = ((((v & vd->server->pf.rmask) >> vd->server->pf.rshift) << vs->clientds.pf.rbits) >>
        vd->server->pf.rbits);
    g = ((((v & vd->server->pf.gmask) >> vd->server->pf.gshift) << vs->clientds.pf.gbits) >>
        vd->server->pf.gbits);
    b = ((((v & vd->server->pf.bmask) >> vd->server->pf.bshift) << vs->clientds.pf.bbits) >>
        vd->server->pf.bbits);
    v = (r << vs->clientds.pf.rshift) |
        (g << vs->clientds.pf.gshift) |
        (b << vs->clientds.pf.bshift);
    switch(vs->clientds.pf.bytes_per_pixel) {
    case 1:
        buf[0] = v;
        break;
    case 2:
        if (vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) {
            buf[0] = v >> 8;
            buf[1] = v;
        } else {
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    default:
    case 4:
        if (vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) {
            buf[0] = v >> 24;
            buf[1] = v >> 16;
            buf[2] = v >> 8;
            buf[3] = v;
        } else {
            buf[3] = v >> 24;
            buf[2] = v >> 16;
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    }
}

static void vnc_write_pixels_generic(VncState *vs, struct PixelFormat *pf,
                                     void *pixels1, int size)
{
    uint8_t buf[4];

    if (pf->bytes_per_pixel == 4) {
        uint32_t *pixels = pixels1;
        int n, i;
        n = size >> 2;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else if (pf->bytes_per_pixel == 2) {
        uint16_t *pixels = pixels1;
        int n, i;
        n = size >> 1;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else if (pf->bytes_per_pixel == 1) {
        uint8_t *pixels = pixels1;
        int n, i;
        n = size;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else {
        fprintf(stderr, "vnc_write_pixels_generic: VncState color depth not supported\n");
    }
}

int vnc_raw_send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
    int i;
    uint8_t *row;
    VncDisplay *vd = vs->vd;

    row = vd->server->data + y * ds_get_linesize(vs->ds) + x * ds_get_bytes_per_pixel(vs->ds);
    for (i = 0; i < h; i++) {
        vs->write_pixels(vs, &vd->server->pf, row, w * ds_get_bytes_per_pixel(vs->ds));
        row += ds_get_linesize(vs->ds);
    }
    return 1;
}

int vnc_send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
    int n = 0;

	vnc_framebuffer_update(vs, x, y, w, h, VNC_ENCODING_RAW);
	n = vnc_raw_send_framebuffer_update(vs, x, y, w, h);

    return n;
}

static void vnc_copy(VncState *vs, int src_x, int src_y, int dst_x, int dst_y, int w, int h)
{
    /* send bitblit op to the vnc client */
    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1); /* number of rects */
    vnc_framebuffer_update(vs, dst_x, dst_y, w, h, VNC_ENCODING_COPYRECT);
    vnc_write_u16(vs, src_x);
    vnc_write_u16(vs, src_y);
    vnc_flush(vs);
}

static void vnc_dpy_copy(DisplayState *ds, int src_x, int src_y, int dst_x, int dst_y, int w, int h)
{
    VncDisplay *vd = ds->opaque;
    VncState *vs, *vn;
    uint8_t *src_row;
    uint8_t *dst_row;
    int i,x,y,pitch,depth,inc,w_lim,s;
    int cmp_bytes;

    vnc_refresh_server_surface(vd);
    QTAILQ_FOREACH_SAFE(vs, &vd->clients, next, vn) {
        if (vnc_has_feature(vs, VNC_FEATURE_COPYRECT)) {
            vs->force_update = 1;
            vnc_update_client_sync(vs, 1);
            /* vs might be free()ed here */
        }
    }

    /* do bitblit op on the local surface too */
    pitch = ds_get_linesize(vd->ds);
    depth = ds_get_bytes_per_pixel(vd->ds);
    src_row = vd->server->data + pitch * src_y + depth * src_x;
    dst_row = vd->server->data + pitch * dst_y + depth * dst_x;
    y = dst_y;
    inc = 1;
    if (dst_y > src_y) {
        /* copy backwards */
        src_row += pitch * (h-1);
        dst_row += pitch * (h-1);
        pitch = -pitch;
        y = dst_y + h - 1;
        inc = -1;
    }
    w_lim = w - (16 - (dst_x % 16));
    if (w_lim < 0)
        w_lim = w;
    else
        w_lim = w - (w_lim % 16);
    for (i = 0; i < h; i++) {
        for (x = 0; x <= w_lim;
                x += s, src_row += cmp_bytes, dst_row += cmp_bytes) {
            if (x == w_lim) {
                if ((s = w - w_lim) == 0)
                    break;
            } else if (!x) {
                s = (16 - (dst_x % 16));
                s = MIN(s, w_lim);
            } else {
                s = 16;
            }
            cmp_bytes = s * depth;
            if (memcmp(src_row, dst_row, cmp_bytes) == 0)
                continue;
            memmove(dst_row, src_row, cmp_bytes);
            QTAILQ_FOREACH(vs, &vd->clients, next) {
                if (!vnc_has_feature(vs, VNC_FEATURE_COPYRECT)) {
                    set_bit(((x + dst_x) / 16), vs->dirty[y]);
                }
            }
        }
        src_row += pitch - w * depth;
        dst_row += pitch - w * depth;
        y += inc;
    }

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        if (vnc_has_feature(vs, VNC_FEATURE_COPYRECT)) {
            vnc_copy(vs, src_x, src_y, dst_x, dst_y, w, h);
        }
    }
}

static void vnc_mouse_set(int x, int y, int visible)
{
    /* can we ask the client(s) to move the pointer ??? */
}

static int vnc_cursor_define(VncState *vs)
{
    QEMUCursor *c = vs->vd->cursor;
    PixelFormat pf = qemu_default_pixelformat(32);
    int isize;

    if (vnc_has_feature(vs, VNC_FEATURE_RICH_CURSOR)) {
        vnc_write_u8(vs,  VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
        vnc_write_u8(vs,  0);  /*  padding     */
        vnc_write_u16(vs, 1);  /*  # of rects  */
        vnc_framebuffer_update(vs, c->hot_x, c->hot_y, c->width, c->height,
                               VNC_ENCODING_RICH_CURSOR);
        isize = c->width * c->height * vs->clientds.pf.bytes_per_pixel;
        vnc_write_pixels_generic(vs, &pf, c->data, isize);
        vnc_write(vs, vs->vd->cursor_mask, vs->vd->cursor_msize);
        return 0;
    }
    return -1;
}

static void vnc_dpy_cursor_define(QEMUCursor *c)
{
    VncDisplay *vd = vnc_display;
    VncState *vs;

    cursor_put(vd->cursor);
    free(vd->cursor_mask);
    vd->cursor_mask = NULL;

    vd->cursor = c;
    cursor_get(vd->cursor);
    vd->cursor_msize = cursor_get_mono_bpl(c) * c->height;
    vd->cursor_mask = calloc(1, vd->cursor_msize);
    cursor_get_mono_mask(c, 0, vd->cursor_mask);

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        vnc_cursor_define(vs);
    }
}

static int find_and_clear_dirty_height(struct VncState *vs,
                                       int y, int last_x, int x, int height)
{
    int h;

    for (h = 1; h < (height - y); h++) {
        int tmp_x;
        if (!test_bit(last_x, vs->dirty[y + h])) {
            break;
        }
        for (tmp_x = last_x; tmp_x < x; tmp_x++) {
            clear_bit(tmp_x, vs->dirty[y + h]);
        }
    }

    return h;
}

static int vnc_update_client_sync(VncState *vs, int has_dirty)
{
    return vnc_update_client(vs, has_dirty);
}

static int vnc_update_client(VncState *vs, int has_dirty)
{
    if (vs->need_update && vs->csock != -1) {
        VncDisplay *vd = vs->vd;
        VncJob *job;
        int y;
        int width, height;
        int n = 0;


        if (vs->output.offset && !vs->force_update)
            /* kernel send buffers are full -> drop frames to throttle */
            return 0;

        if (!has_dirty && !vs->force_update)
            return 0;

        /*
         * Send screen updates to the vnc client using the server
         * surface and server dirty map.  guest surface updates
         * happening in parallel don't disturb us, the next pass will
         * send them to the client.
         */
        job = vnc_job_new(vs);

        width = MIN(vd->server->width, vs->client_width);
        height = MIN(vd->server->height, vs->client_height);

        for (y = 0; y < height; y++) {
            int x;
            int last_x = -1;
            for (x = 0; x < width / 16; x++) {
                if (test_and_clear_bit(x, vs->dirty[y])) {
                    if (last_x == -1) {
                        last_x = x;
                    }
                } else {
                    if (last_x != -1) {
                        int h = find_and_clear_dirty_height(vs, y, last_x, x,
                                                            height);

                        n += vnc_job_add_rect(job, last_x * 16, y,
                                              (x - last_x) * 16, h);
                    }
                    last_x = -1;
                }
            }
            if (last_x != -1) {
                int h = find_and_clear_dirty_height(vs, y, last_x, x, height);
                n += vnc_job_add_rect(job, last_x * 16, y,
                                      (x - last_x) * 16, h);
            }
        }

        vnc_job_push(job);
        vs->force_update = 0;
        return n;
    }

    if (vs->csock == -1)
        vnc_disconnect_finish(vs);

    return 0;
}

static void vnc_disconnect_start(VncState *vs)
{
    if (vs->csock == -1)
        return;
    qemu_set_fd_handler2(vs->csock, NULL, NULL, NULL, NULL);
    close(vs->csock);
    vs->csock = -1;
}

static void vnc_disconnect_finish(VncState *vs)
{
    int i;

    buffer_free(&vs->input);
    buffer_free(&vs->output);

    QTAILQ_REMOVE(&vs->vd->clients, vs, next);

    if (QTAILQ_EMPTY(&vs->vd->clients)) {
        dcl->idle = 1;
    }

    qemu_remove_mouse_mode_change_notifier(&vs->mouse_mode_notifier);
    vnc_remove_timer(vs->vd);
    if (vs->vd->lock_key_sync)
        qemu_remove_led_event_handler(vs->led);

    for (i = 0; i < VNC_STAT_ROWS; ++i) {
        free(vs->lossy_rect[i]);
        vs->lossy_rect[i] = NULL;
    }
    free(vs->lossy_rect);
    vs->lossy_rect = NULL;
    free(vs);
    vs = NULL;
}

int vnc_client_io_error(VncState *vs, int ret, int last_errno)
{
    if (ret == 0 || ret == -1) {
        if (ret == -1) {
            switch (last_errno) {
                case EINTR:
                case EAGAIN:
                    return 0;
                default:
                    break;
            }
        }

        VNC_DEBUG("Closing down client sock: ret %d, errno %d\n",
                  ret, ret < 0 ? last_errno : 0);
        vnc_disconnect_start(vs);

        return 0;
    }
    return ret;
}


void vnc_client_error(VncState *vs)
{
    VNC_DEBUG("Closing down client sock: protocol error\n");
    vnc_disconnect_start(vs);
}


/*
 * Called to write a chunk of data to the client socket. The data may
 * be the raw data, or may have already been encoded by SASL.
 * The data will be written either straight onto the socket, or
 * written via the GNUTLS wrappers, if TLS/SSL encryption is enabled
 *
 * NB, it is theoretically possible to have 2 layers of encryption,
 * both SASL, and this TLS layer. It is highly unlikely in practice
 * though, since SASL encryption will typically be a no-op if TLS
 * is active
 *
 * Returns the number of bytes written, which may be less than
 * the requested 'datalen' if the socket would block. Returns
 * -1 on error, and disconnects the client socket.
 */
long vnc_client_write_buf(VncState *vs, const uint8_t *data, size_t datalen)
{
    long ret;
    ret = send(vs->csock, (const void *)data, datalen, 0);
    VNC_DEBUG("Wrote wire %p %zd -> %ld\n", data, datalen, ret);
    return vnc_client_io_error(vs, ret, errno);
}


/*
 * Called to write buffered data to the client socket, when not
 * using any SASL SSF encryption layers. Will write as much data
 * as possible without blocking. If all buffered data is written,
 * will switch the FD poll() handler back to read monitoring.
 *
 * Returns the number of bytes written, which may be less than
 * the buffered output data if the socket would block. Returns
 * -1 on error, and disconnects the client socket.
 */
static long vnc_client_write_plain(VncState *vs)
{
    long ret;

    ret = vnc_client_write_buf(vs, vs->output.buffer, vs->output.offset);
    if (!ret)
        return 0;

    memmove(vs->output.buffer, vs->output.buffer + ret, (vs->output.offset - ret));
    vs->output.offset -= ret;

    if (vs->output.offset == 0) {
        qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);
    }

    return ret;
}


/*
 * First function called whenever there is data to be written to
 * the client socket. Will delegate actual work according to whether
 * SASL SSF layers are enabled (thus requiring encryption calls)
 */
static void vnc_client_write_locked(void *opaque)
{
    VncState *vs = opaque;

	vnc_client_write_plain(vs);
}

void vnc_client_write(void *opaque)
{
    VncState *vs = opaque;

    if (vs->output.offset) {
        vnc_client_write_locked(opaque);
    } else if (vs->csock != -1) {
        qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);
    }
}

void vnc_read_when(VncState *vs, VncReadEvent *func, size_t expecting)
{
    vs->read_handler = func;
    vs->read_handler_expect = expecting;
}


/*
 * Called to read a chunk of data from the client socket. The data may
 * be the raw data, or may need to be further decoded by SASL.
 * The data will be read either straight from to the socket, or
 * read via the GNUTLS wrappers, if TLS/SSL encryption is enabled
 *
 * NB, it is theoretically possible to have 2 layers of encryption,
 * both SASL, and this TLS layer. It is highly unlikely in practice
 * though, since SASL encryption will typically be a no-op if TLS
 * is active
 *
 * Returns the number of bytes read, which may be less than
 * the requested 'datalen' if the socket would block. Returns
 * -1 on error, and disconnects the client socket.
 */
long vnc_client_read_buf(VncState *vs, uint8_t *data, size_t datalen)
{
    long ret;
    ret = recv(vs->csock, data, datalen, 0);
    VNC_DEBUG("Read wire %p %zd -> %ld\n", data, datalen, ret);
    return vnc_client_io_error(vs, ret, errno); 
}


/*
 * Called to read data from the client socket to the input buffer,
 * when not using any SASL SSF encryption layers. Will read as much
 * data as possible without blocking.
 *
 * Returns the number of bytes read. Returns -1 on error, and
 * disconnects the client socket.
 */
static long vnc_client_read_plain(VncState *vs)
{
    int ret;
    VNC_DEBUG("Read plain %p size %zd offset %zd\n",
              vs->input.buffer, vs->input.capacity, vs->input.offset);
    buffer_reserve(&vs->input, 4096);
    ret = vnc_client_read_buf(vs, buffer_end(&vs->input), 4096);
    if (!ret)
        return 0;
    vs->input.offset += ret;
    return ret;
}


/*
 * First function called whenever there is more data to be read from
 * the client socket. Will delegate actual work according to whether
 * SASL SSF layers are enabled (thus requiring decryption calls)
 */
void vnc_client_read(void *opaque)
{
    VncState *vs = opaque;
    long ret;

	ret = vnc_client_read_plain(vs);
    if (!ret) {
        if (vs->csock == -1)
            vnc_disconnect_finish(vs);
        return;
    }

    while (vs->read_handler && vs->input.offset >= vs->read_handler_expect) {
        size_t len = vs->read_handler_expect;
        int ret;

        ret = vs->read_handler(vs, vs->input.buffer, len);
        if (vs->csock == -1) {
            vnc_disconnect_finish(vs);
            return;
        }

        if (!ret) {
            memmove(vs->input.buffer, vs->input.buffer + len, (vs->input.offset - len));
            vs->input.offset -= len;
        } else {
            vs->read_handler_expect = ret;
        }
    }
}

void vnc_write(VncState *vs, const void *data, size_t len)
{
    buffer_reserve(&vs->output, len);

    if (vs->csock != -1 && buffer_empty(&vs->output)) {
        qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, vnc_client_write, vs);
    }

    buffer_append(&vs->output, data, len);
}

void vnc_write_s32(VncState *vs, int32_t value)
{
    vnc_write_u32(vs, *(uint32_t *)&value);
}

void vnc_write_u32(VncState *vs, uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >>  8) & 0xFF;
    buf[3] = value & 0xFF;

    vnc_write(vs, buf, 4);
}

void vnc_write_u16(VncState *vs, uint16_t value)
{
    uint8_t buf[2];

    buf[0] = (value >> 8) & 0xFF;
    buf[1] = value & 0xFF;

    vnc_write(vs, buf, 2);
}

void vnc_write_u8(VncState *vs, uint8_t value)
{
    vnc_write(vs, (char *)&value, 1);
}

void vnc_flush(VncState *vs)
{
    if (vs->csock != -1 && vs->output.offset) {
        vnc_client_write_locked(vs);
    }
}

uint8_t read_u8(uint8_t *data, size_t offset)
{
    return data[offset];
}

uint16_t read_u16(uint8_t *data, size_t offset)
{
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
}

int32_t read_s32(uint8_t *data, size_t offset)
{
    return (int32_t)((data[offset] << 24) | (data[offset + 1] << 16) |
                     (data[offset + 2] << 8) | data[offset + 3]);
}

uint32_t read_u32(uint8_t *data, size_t offset)
{
    return ((data[offset] << 24) | (data[offset + 1] << 16) |
            (data[offset + 2] << 8) | data[offset + 3]);
}

static void client_cut_text(VncState *vs, size_t len, uint8_t *text)
{
}

static void check_pointer_type_change(Notifier *notifier, void *data)
{
    VncState *vs = container_of(notifier, VncState, mouse_mode_notifier);
    int absolute = kbd_mouse_is_absolute();

    if (vnc_has_feature(vs, VNC_FEATURE_POINTER_TYPE_CHANGE) && vs->absolute != absolute) {
        vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
        vnc_write_u8(vs, 0);
        vnc_write_u16(vs, 1);
        vnc_framebuffer_update(vs, absolute, 0,
                               ds_get_width(vs->ds), ds_get_height(vs->ds),
                               VNC_ENCODING_POINTER_TYPE_CHANGE);
        vnc_flush(vs);
    }
    vs->absolute = absolute;
}

static void pointer_event(VncState *vs, int button_mask, int x, int y)
{
    int buttons = 0;
    int dz = 0;

    if (button_mask & 0x01)
        buttons |= MOUSE_EVENT_LBUTTON;
    if (button_mask & 0x02)
        buttons |= MOUSE_EVENT_MBUTTON;
    if (button_mask & 0x04)
        buttons |= MOUSE_EVENT_RBUTTON;
    if (button_mask & 0x08)
        dz = -1;
    if (button_mask & 0x10)
        dz = 1;

    if (vs->absolute) {
        kbd_mouse_event(ds_get_width(vs->ds) > 1 ?
                          x * 0x7FFF / (ds_get_width(vs->ds) - 1) : 0x4000,
                        ds_get_height(vs->ds) > 1 ?
                          y * 0x7FFF / (ds_get_height(vs->ds) - 1) : 0x4000,
                        dz, buttons);
    } else if (vnc_has_feature(vs, VNC_FEATURE_POINTER_TYPE_CHANGE)) {
        x -= 0x7FFF;
        y -= 0x7FFF;

        kbd_mouse_event(x, y, dz, buttons);
    } else {
        if (vs->last_x != -1)
            kbd_mouse_event(x - vs->last_x,
                            y - vs->last_y,
                            dz, buttons);
        vs->last_x = x;
        vs->last_y = y;
    }
}

static void reset_keys(VncState *vs)
{
    int i;
    for(i = 0; i < 256; i++) {
        if (vs->modifiers_state[i]) {
            if (i & SCANCODE_GREY)
                kbd_put_keycode(SCANCODE_EMUL0);
            kbd_put_keycode(i | SCANCODE_UP);
            vs->modifiers_state[i] = 0;
        }
    }
}

static void press_key(VncState *vs, int keysym)
{
    int keycode = keysym2scancode(vs->vd->kbd_layout, keysym) & SCANCODE_KEYMASK;
    if (keycode & SCANCODE_GREY)
        kbd_put_keycode(SCANCODE_EMUL0);
    kbd_put_keycode(keycode & SCANCODE_KEYCODEMASK);
    if (keycode & SCANCODE_GREY)
        kbd_put_keycode(SCANCODE_EMUL0);
    kbd_put_keycode(keycode | SCANCODE_UP);
}

static void kbd_leds(void *opaque, int ledstate)
{
    VncState *vs = opaque;
    int caps, num;

    caps = ledstate & QEMU_CAPS_LOCK_LED ? 1 : 0;
    num  = ledstate & QEMU_NUM_LOCK_LED  ? 1 : 0;

    if (vs->modifiers_state[0x3a] != caps) {
        vs->modifiers_state[0x3a] = caps;
    }
    if (vs->modifiers_state[0x45] != num) {
        vs->modifiers_state[0x45] = num;
    }
}

static void do_key_event(VncState *vs, int down, int keycode, int sym)
{
    /* QEMU console switch */
    switch(keycode) {
    case 0x2a:                          /* Left Shift */
    case 0x36:                          /* Right Shift */
    case 0x1d:                          /* Left CTRL */
    case 0x9d:                          /* Right CTRL */
    case 0x38:                          /* Left ALT */
    case 0xb8:                          /* Right ALT */
        if (down)
            vs->modifiers_state[keycode] = 1;
        else
            vs->modifiers_state[keycode] = 0;
        break;
    case 0x02 ... 0x0a: /* '1' to '9' keys */
        if (down && vs->modifiers_state[0x1d] && vs->modifiers_state[0x38]) {
            /* Reset the modifiers sent to the current console */
            reset_keys(vs);
            console_select(keycode - 0x02);
            return;
        }
        break;
    case 0x3a:                        /* CapsLock */
    case 0x45:                        /* NumLock */
        if (down)
            vs->modifiers_state[keycode] ^= 1;
        break;
    }

    if (down && vs->vd->lock_key_sync &&
        keycode_is_keypad(vs->vd->kbd_layout, keycode)) {
        /* If the numlock state needs to change then simulate an additional
           keypress before sending this one.  This will happen if the user
           toggles numlock away from the VNC window.
        */
        if (keysym_is_numlock(vs->vd->kbd_layout, sym & 0xFFFF)) {
            if (!vs->modifiers_state[0x45]) {
                vs->modifiers_state[0x45] = 1;
                press_key(vs, 0xff7f);
            }
        } else {
            if (vs->modifiers_state[0x45]) {
                vs->modifiers_state[0x45] = 0;
                press_key(vs, 0xff7f);
            }
        }
    }

    if (down && vs->vd->lock_key_sync &&
        ((sym >= 'A' && sym <= 'Z') || (sym >= 'a' && sym <= 'z'))) {
        /* If the capslock state needs to change then simulate an additional
           keypress before sending this one.  This will happen if the user
           toggles capslock away from the VNC window.
        */
        int uppercase = !!(sym >= 'A' && sym <= 'Z');
        int shift = !!(vs->modifiers_state[0x2a] | vs->modifiers_state[0x36]);
        int capslock = !!(vs->modifiers_state[0x3a]);
        if (capslock) {
            if (uppercase == shift) {
                vs->modifiers_state[0x3a] = 0;
                press_key(vs, 0xffe5);
            }
        } else {
            if (uppercase != shift) {
                vs->modifiers_state[0x3a] = 1;
                press_key(vs, 0xffe5);
            }
        }
    }

    if (keycode & SCANCODE_GREY)
        kbd_put_keycode(SCANCODE_EMUL0);
    if (down)
        kbd_put_keycode(keycode & SCANCODE_KEYCODEMASK);
    else
        kbd_put_keycode(keycode | SCANCODE_UP);
}

static void key_event(VncState *vs, int down, uint32_t sym)
{
    int keycode;
    int lsym = sym;

    if (lsym >= 'A' && lsym <= 'Z') {
        lsym = lsym - 'A' + 'a';
    }

    keycode = keysym2scancode(vs->vd->kbd_layout, lsym & 0xFFFF) & SCANCODE_KEYMASK;
    do_key_event(vs, down, keycode, sym);
}

static void ext_key_event(VncState *vs, int down,
                          uint32_t sym, uint16_t keycode)
{
    do_key_event(vs, down, keycode, sym);
}

static void framebuffer_update_request(VncState *vs, int incremental,
                                       int x_position, int y_position,
                                       int w, int h)
{
    int i;
    const size_t width = ds_get_width(vs->ds) / 16;

    if (y_position > ds_get_height(vs->ds))
        y_position = ds_get_height(vs->ds);
    if (y_position + h >= ds_get_height(vs->ds))
        h = ds_get_height(vs->ds) - y_position;

    vs->need_update = 1;
    if (!incremental) {
        vs->force_update = 1;
        for (i = 0; i < h; i++) {
            bitmap_set(vs->dirty[y_position + i], 0, width);
            bitmap_clear(vs->dirty[y_position + i], width,
                         VNC_DIRTY_BITS - width);
        }
    }
}

static void send_ext_key_event_ack(VncState *vs)
{
    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, 0, 0, ds_get_width(vs->ds), ds_get_height(vs->ds),
                           VNC_ENCODING_EXT_KEY_EVENT);
    vnc_flush(vs);
}

static void set_encodings(VncState *vs, int32_t *encodings, size_t n_encodings)
{
    int i;
    unsigned int enc = 0;

    vs->features = 0;
    vs->vnc_encoding = 0;
    vs->absolute = -1;

    /*
     * Start from the end because the encodings are sent in order of preference.
     * This way the prefered encoding (first encoding defined in the array)
     * will be set at the end of the loop.
     */
    for (i = n_encodings - 1; i >= 0; i--) {
        enc = encodings[i];
        switch (enc) {
        case VNC_ENCODING_RAW:
            vs->vnc_encoding = enc;
            break;
        case VNC_ENCODING_COPYRECT:
            vs->features |= VNC_FEATURE_COPYRECT_MASK;
            break;
        case VNC_ENCODING_DESKTOPRESIZE:
            vs->features |= VNC_FEATURE_RESIZE_MASK;
            break;
        case VNC_ENCODING_POINTER_TYPE_CHANGE:
            vs->features |= VNC_FEATURE_POINTER_TYPE_CHANGE_MASK;
            break;
        case VNC_ENCODING_RICH_CURSOR:
            vs->features |= VNC_FEATURE_RICH_CURSOR_MASK;
            break;
        case VNC_ENCODING_EXT_KEY_EVENT:
            send_ext_key_event_ack(vs);
            break;
        case VNC_ENCODING_WMVi:
            vs->features |= VNC_FEATURE_WMVI_MASK;
            break;
        default:
            VNC_DEBUG("Unknown encoding: %d (0x%.8x): %d\n", i, enc, enc);
            break;
        }
    }
    vnc_desktop_resize(vs);
    check_pointer_type_change(&vs->mouse_mode_notifier, NULL);
}

static void set_pixel_conversion(VncState *vs)
{
    if ((vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) ==
        (vs->ds->surface->flags & QEMU_BIG_ENDIAN_FLAG) &&
        !memcmp(&(vs->clientds.pf), &(vs->ds->surface->pf), sizeof(PixelFormat))) {
        vs->write_pixels = vnc_write_pixels_copy;
    } else {
        vs->write_pixels = vnc_write_pixels_generic;
    }
}

static void set_pixel_format(VncState *vs,
                             int bits_per_pixel, int depth,
                             int big_endian_flag, int true_color_flag,
                             int red_max, int green_max, int blue_max,
                             int red_shift, int green_shift, int blue_shift)
{
    if (!true_color_flag) {
        vnc_client_error(vs);
        return;
    }

    vs->clientds = *(vs->vd->guest.ds);
    vs->clientds.pf.rmax = red_max;
    vs->clientds.pf.rbits = hweight_long(red_max);
    vs->clientds.pf.rshift = red_shift;
    vs->clientds.pf.rmask = red_max << red_shift;
    vs->clientds.pf.gmax = green_max;
    vs->clientds.pf.gbits = hweight_long(green_max);
    vs->clientds.pf.gshift = green_shift;
    vs->clientds.pf.gmask = green_max << green_shift;
    vs->clientds.pf.bmax = blue_max;
    vs->clientds.pf.bbits = hweight_long(blue_max);
    vs->clientds.pf.bshift = blue_shift;
    vs->clientds.pf.bmask = blue_max << blue_shift;
    vs->clientds.pf.bits_per_pixel = bits_per_pixel;
    vs->clientds.pf.bytes_per_pixel = bits_per_pixel / 8;
    vs->clientds.pf.depth = bits_per_pixel == 32 ? 24 : bits_per_pixel;
    vs->clientds.flags = big_endian_flag ? QEMU_BIG_ENDIAN_FLAG : 0x00;

    set_pixel_conversion(vs);

    vga_hw_invalidate();
    vga_hw_update();
}

static void pixel_format_message (VncState *vs) {
    char pad[3] = { 0, 0, 0 };

    vnc_write_u8(vs, vs->ds->surface->pf.bits_per_pixel); /* bits-per-pixel */
    vnc_write_u8(vs, vs->ds->surface->pf.depth); /* depth */

    vnc_write_u8(vs, 0);             /* big-endian-flag */
    vnc_write_u8(vs, 1);             /* true-color-flag */
    vnc_write_u16(vs, vs->ds->surface->pf.rmax);     /* red-max */
    vnc_write_u16(vs, vs->ds->surface->pf.gmax);     /* green-max */
    vnc_write_u16(vs, vs->ds->surface->pf.bmax);     /* blue-max */
    vnc_write_u8(vs, vs->ds->surface->pf.rshift);    /* red-shift */
    vnc_write_u8(vs, vs->ds->surface->pf.gshift);    /* green-shift */
    vnc_write_u8(vs, vs->ds->surface->pf.bshift);    /* blue-shift */

    vs->clientds = *(vs->ds->surface);
    vs->clientds.flags &= ~QEMU_ALLOCATED_FLAG;
    vs->write_pixels = vnc_write_pixels_copy;

    vnc_write(vs, pad, 3);           /* padding */
}

static void vnc_dpy_setdata(DisplayState *ds)
{
    /* We don't have to do anything */
}

static void vnc_colordepth(VncState *vs)
{
    if (vnc_has_feature(vs, VNC_FEATURE_WMVI)) {
        /* Sending a WMVi message to notify the client*/
        vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
        vnc_write_u8(vs, 0);
        vnc_write_u16(vs, 1); /* number of rects */
        vnc_framebuffer_update(vs, 0, 0, ds_get_width(vs->ds),
                               ds_get_height(vs->ds), VNC_ENCODING_WMVi);
        pixel_format_message(vs);
        vnc_flush(vs);
    } else {
        set_pixel_conversion(vs);
    }
}

static int protocol_client_msg(VncState *vs, uint8_t *data, size_t len)
{
    int i;
    uint16_t limit;
    VncDisplay *vd = vs->vd;

    if (data[0] > 3) {
        vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
        if (!qemu_timer_expired(vd->timer, qemu_get_clock_ms(rt_clock) + vd->timer_interval))
            qemu_mod_timer(vd->timer, qemu_get_clock_ms(rt_clock) + vd->timer_interval);
    }

    switch (data[0]) {
    case VNC_MSG_CLIENT_SET_PIXEL_FORMAT:
        if (len == 1)
            return 20;

        set_pixel_format(vs, read_u8(data, 4), read_u8(data, 5),
                         read_u8(data, 6), read_u8(data, 7),
                         read_u16(data, 8), read_u16(data, 10),
                         read_u16(data, 12), read_u8(data, 14),
                         read_u8(data, 15), read_u8(data, 16));
        break;
    case VNC_MSG_CLIENT_SET_ENCODINGS:
        if (len == 1)
            return 4;

        if (len == 4) {
            limit = read_u16(data, 2);
            if (limit > 0)
                return 4 + (limit * 4);
        } else
            limit = read_u16(data, 2);

        for (i = 0; i < limit; i++) {
            int32_t val = read_s32(data, 4 + (i * 4));
            memcpy(data + 4 + (i * 4), &val, sizeof(val));
        }

        set_encodings(vs, (int32_t *)(data + 4), limit);
        break;
    case VNC_MSG_CLIENT_FRAMEBUFFER_UPDATE_REQUEST:
        if (len == 1)
            return 10;

        framebuffer_update_request(vs,
                                   read_u8(data, 1), read_u16(data, 2), read_u16(data, 4),
                                   read_u16(data, 6), read_u16(data, 8));
        break;
    case VNC_MSG_CLIENT_KEY_EVENT:
        if (len == 1)
            return 8;

        key_event(vs, read_u8(data, 1), read_u32(data, 4));
        break;
    case VNC_MSG_CLIENT_POINTER_EVENT:
        if (len == 1)
            return 6;

        pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
        break;
    case VNC_MSG_CLIENT_CUT_TEXT:
        if (len == 1)
            return 8;

        if (len == 8) {
            uint32_t dlen = read_u32(data, 4);
            if (dlen > 0)
                return 8 + dlen;
        }

        client_cut_text(vs, read_u32(data, 4), data + 8);
        break;
    case VNC_MSG_CLIENT_QEMU:
        if (len == 1)
            return 2;

        switch (read_u8(data, 1)) {
        case VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT:
            if (len == 2)
                return 12;

            ext_key_event(vs, read_u16(data, 2),
                          read_u32(data, 4), read_u32(data, 8));
            break;

        default:
            printf("Msg: %d\n", read_u16(data, 0));
            vnc_client_error(vs);
            break;
        }
        break;
    default:
        printf("Msg: %d\n", data[0]);
        vnc_client_error(vs);
        break;
    }

    vnc_read_when(vs, protocol_client_msg, 1);
    return 0;
}

static int protocol_client_init(VncState *vs, uint8_t *data, size_t len)
{
    vs->client_width = ds_get_width(vs->ds);
    vs->client_height = ds_get_height(vs->ds);
    vnc_write_u16(vs, vs->client_width);
    vnc_write_u16(vs, vs->client_height);

    pixel_format_message(vs);

    vnc_write_u32(vs, 4);
    vnc_write(vs, "QEMU", 4);
    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_msg, 1);

    return 0;
}

void start_client_init(VncState *vs)
{
    vnc_read_when(vs, protocol_client_init, 1);
}

static int protocol_client_auth(VncState *vs, uint8_t *data, size_t len)
{
    /* We only advertise 1 auth scheme at a time, so client
     * must pick the one we sent. Verify this */
    if (data[0] != vs->auth) { /* Reject auth */
       VNC_DEBUG("Reject auth %d because it didn't match advertized\n", (int)data[0]);
       vnc_write_u32(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Authentication failed";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    } else { /* Accept requested auth */
       VNC_DEBUG("Client requested auth %d\n", (int)data[0]);
       switch (vs->auth) {
       case VNC_AUTH_NONE:
           VNC_DEBUG("Accept auth none\n");
           if (vs->minor >= 8) {
               vnc_write_u32(vs, 0); /* Accept auth completion */
               vnc_flush(vs);
           }
           start_client_init(vs);
           break;

       default: /* Should not be possible, but just in case */
           VNC_DEBUG("Reject auth %d server code bug\n", vs->auth);
           vnc_write_u8(vs, 1);
           if (vs->minor >= 8) {
               static const char err[] = "Authentication failed";
               vnc_write_u32(vs, sizeof(err));
               vnc_write(vs, err, sizeof(err));
           }
           vnc_client_error(vs);
       }
    }
    return 0;
}

static int protocol_version(VncState *vs, uint8_t *version, size_t len)
{
    char local[13];

    memcpy(local, version, 12);
    local[12] = 0;

    if (sscanf(local, "RFB %03d.%03d\n", &vs->major, &vs->minor) != 2) {
        VNC_DEBUG("Malformed protocol version %s\n", local);
        vnc_client_error(vs);
        return 0;
    }
    VNC_DEBUG("Client request protocol version %d.%d\n", vs->major, vs->minor);
    if (vs->major != 3 ||
        (vs->minor != 3 &&
         vs->minor != 4 &&
         vs->minor != 5 &&
         vs->minor != 7 &&
         vs->minor != 8)) {
        VNC_DEBUG("Unsupported client version\n");
        vnc_write_u32(vs, VNC_AUTH_INVALID);
        vnc_flush(vs);
        vnc_client_error(vs);
        return 0;
    }
    /* Some broken clients report v3.4 or v3.5, which spec requires to be treated
     * as equivalent to v3.3 by servers
     */
    if (vs->minor == 4 || vs->minor == 5)
        vs->minor = 3;

    if (vs->minor == 3) {
        if (vs->auth == VNC_AUTH_NONE) {
            VNC_DEBUG("Tell client auth none\n");
            vnc_write_u32(vs, vs->auth);
            vnc_flush(vs);
            start_client_init(vs);
       } else {
            VNC_DEBUG("Unsupported auth %d for protocol 3.3\n", vs->auth);
            vnc_write_u32(vs, VNC_AUTH_INVALID);
            vnc_flush(vs);
            vnc_client_error(vs);
       }
    } else {
        VNC_DEBUG("Telling client we support auth %d\n", vs->auth);
        vnc_write_u8(vs, 1); /* num auth */
        vnc_write_u8(vs, vs->auth);
        vnc_read_when(vs, protocol_client_auth, 1);
        vnc_flush(vs);
    }

    return 0;
}

static VncRectStat *vnc_stat_rect(VncDisplay *vd, int x, int y)
{
    struct VncSurface *vs = &vd->guest;

    return &vs->stats[y / VNC_STAT_RECT][x / VNC_STAT_RECT];
}

void vnc_sent_lossy_rect(VncState *vs, int x, int y, int w, int h)
{
    int i, j;

    w = (x + w) / VNC_STAT_RECT;
    h = (y + h) / VNC_STAT_RECT;
    x /= VNC_STAT_RECT;
    y /= VNC_STAT_RECT;

    for (j = y; j <= h; j++) {
        for (i = x; i <= w; i++) {
            vs->lossy_rect[j][i] = 1;
        }
    }
}

static int vnc_refresh_lossy_rect(VncDisplay *vd, int x, int y)
{
    VncState *vs;
    int sty = y / VNC_STAT_RECT;
    int stx = x / VNC_STAT_RECT;
    int has_dirty = 0;

    y = y / VNC_STAT_RECT * VNC_STAT_RECT;
    x = x / VNC_STAT_RECT * VNC_STAT_RECT;

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        int j;

        /* kernel send buffers are full -> refresh later */
        if (vs->output.offset) {
            continue;
        }

        if (!vs->lossy_rect[sty][stx]) {
            continue;
        }

        vs->lossy_rect[sty][stx] = 0;
        for (j = 0; j < VNC_STAT_RECT; ++j) {
            bitmap_set(vs->dirty[y + j], x / 16, VNC_STAT_RECT / 16);
        }
        has_dirty++;
    }

    return has_dirty;
}

static int vnc_update_stats(VncDisplay *vd,  struct timeval * tv)
{
    int x, y;
    struct timeval res;
    int has_dirty = 0;

    for (y = 0; y < vd->guest.ds->height; y += VNC_STAT_RECT) {
        for (x = 0; x < vd->guest.ds->width; x += VNC_STAT_RECT) {
            VncRectStat *rect = vnc_stat_rect(vd, x, y);

            rect->updated = false;
        }
    }

    timersub(tv, &VNC_REFRESH_STATS, &res);

    if (timercmp(&vd->guest.last_freq_check, &res, >)) {
        return has_dirty;
    }
    vd->guest.last_freq_check = *tv;

    for (y = 0; y < vd->guest.ds->height; y += VNC_STAT_RECT) {
        for (x = 0; x < vd->guest.ds->width; x += VNC_STAT_RECT) {
            VncRectStat *rect= vnc_stat_rect(vd, x, y);
            int count = ARRAY_SIZE(rect->times);
            struct timeval min, max;

            if (!timerisset(&rect->times[count - 1])) {
                continue ;
            }

            max = rect->times[(rect->idx + count - 1) % count];
            timersub(tv, &max, &res);

            if (timercmp(&res, &VNC_REFRESH_LOSSY, >)) {
                rect->freq = 0;
                has_dirty += vnc_refresh_lossy_rect(vd, x, y);
                memset(rect->times, 0, sizeof (rect->times));
                continue ;
            }

            min = rect->times[rect->idx];
            max = rect->times[(rect->idx + count - 1) % count];
            timersub(&max, &min, &res);

            rect->freq = res.tv_sec + res.tv_usec / 1000000.;
            rect->freq /= count;
            rect->freq = 1. / rect->freq;
        }
    }
    return has_dirty;
}

double vnc_update_freq(VncState *vs, int x, int y, int w, int h)
{
    int i, j;
    double total = 0;
    int num = 0;

    x =  (x / VNC_STAT_RECT) * VNC_STAT_RECT;
    y =  (y / VNC_STAT_RECT) * VNC_STAT_RECT;

    for (j = y; j <= y + h; j += VNC_STAT_RECT) {
        for (i = x; i <= x + w; i += VNC_STAT_RECT) {
            total += vnc_stat_rect(vs->vd, i, j)->freq;
            num++;
        }
    }

    if (num) {
        return total / num;
    } else {
        return 0;
    }
}

static void vnc_rect_updated(VncDisplay *vd, int x, int y, struct timeval * tv)
{
    VncRectStat *rect;

    rect = vnc_stat_rect(vd, x, y);
    if (rect->updated) {
        return ;
    }
    rect->times[rect->idx] = *tv;
    rect->idx = (rect->idx + 1) % ARRAY_SIZE(rect->times);
    rect->updated = true;
}

static int vnc_refresh_server_surface(VncDisplay *vd)
{
    int y;
    uint8_t *guest_row;
    uint8_t *server_row;
    int cmp_bytes;
    VncState *vs;
    int has_dirty = 0;

    struct timeval tv = { 0, 0 };

    if (!vd->non_adaptive) {
        gettimeofday(&tv, NULL);
        has_dirty = vnc_update_stats(vd, &tv);
    }

    /*
     * Walk through the guest dirty map.
     * Check and copy modified bits from guest to server surface.
     * Update server dirty map.
     */
    cmp_bytes = 16 * ds_get_bytes_per_pixel(vd->ds);
    guest_row  = vd->guest.ds->data;
    server_row = vd->server->data;
    for (y = 0; y < vd->guest.ds->height; y++) {
        if (!bitmap_empty(vd->guest.dirty[y], VNC_DIRTY_BITS)) {
            int x;
            uint8_t *guest_ptr;
            uint8_t *server_ptr;

            guest_ptr  = guest_row;
            server_ptr = server_row;

            for (x = 0; x < vd->guest.ds->width;
                    x += 16, guest_ptr += cmp_bytes, server_ptr += cmp_bytes) {
                if (!test_and_clear_bit((x / 16), vd->guest.dirty[y]))
                    continue;
                if (memcmp(server_ptr, guest_ptr, cmp_bytes) == 0)
                    continue;
                memcpy(server_ptr, guest_ptr, cmp_bytes);
                if (!vd->non_adaptive)
                    vnc_rect_updated(vd, x, y, &tv);
                QTAILQ_FOREACH(vs, &vd->clients, next) {
                    set_bit((x / 16), vs->dirty[y]);
                }
                has_dirty++;
            }
        }
        guest_row  += ds_get_linesize(vd->ds);
        server_row += ds_get_linesize(vd->ds);
    }
    return has_dirty;
}

static void vnc_refresh(void *opaque)
{
    VncDisplay *vd = opaque;
    VncState *vs, *vn;
    int has_dirty, rects = 0;

    vga_hw_update();

    has_dirty = vnc_refresh_server_surface(vd);

    QTAILQ_FOREACH_SAFE(vs, &vd->clients, next, vn) {
        rects += vnc_update_client(vs, has_dirty);
        /* vs might be free()ed here */
    }

    /* vd->timer could be NULL now if the last client disconnected,
     * in this case don't update the timer */
    if (vd->timer == NULL)
        return;

    if (has_dirty && rects) {
        vd->timer_interval /= 2;
        if (vd->timer_interval < VNC_REFRESH_INTERVAL_BASE)
            vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
    } else {
        vd->timer_interval += VNC_REFRESH_INTERVAL_INC;
        if (vd->timer_interval > VNC_REFRESH_INTERVAL_MAX)
            vd->timer_interval = VNC_REFRESH_INTERVAL_MAX;
    }
    qemu_mod_timer(vd->timer, qemu_get_clock_ms(rt_clock) + vd->timer_interval);
}

static void vnc_init_timer(VncDisplay *vd)
{
    vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
    if (vd->timer == NULL && !QTAILQ_EMPTY(&vd->clients)) {
        vd->timer = qemu_new_timer_ms(rt_clock, vnc_refresh, vd);
        vnc_dpy_resize(vd->ds);
        vnc_refresh(vd);
    }
}

static void vnc_remove_timer(VncDisplay *vd)
{
    if (vd->timer != NULL && QTAILQ_EMPTY(&vd->clients)) {
        qemu_del_timer(vd->timer);
        qemu_free_timer(vd->timer);
        vd->timer = NULL;
    }
}

static void vnc_connect(VncDisplay *vd, int csock)
{
    VncState *vs = calloc(1, sizeof(VncState));
    int i;

    vs->csock = csock;

    vs->auth = VNC_AUTH_NONE;
    vs->lossy_rect = calloc(1, VNC_STAT_ROWS * sizeof (*vs->lossy_rect));
    for (i = 0; i < VNC_STAT_ROWS; ++i) {
        vs->lossy_rect[i] = calloc(1, VNC_STAT_COLS * sizeof (uint8_t));
    }

    dcl->idle = 0;
    i = fcntl(vs->csock, F_GETFL);
    fcntl(vs->csock, F_SETFL, i | O_NONBLOCK);
    qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);

    vs->vd = vd;
    vs->ds = vd->ds;
    vs->last_x = -1;
    vs->last_y = -1;

    QTAILQ_INSERT_HEAD(&vd->clients, vs, next);

    vga_hw_update();

    vnc_write(vs, "RFB 003.008\n", 12);
    vnc_flush(vs);
    vnc_read_when(vs, protocol_version, 12);
    reset_keys(vs);
    if (vs->vd->lock_key_sync)
        vs->led = qemu_add_led_event_handler(kbd_leds, vs);

    vs->mouse_mode_notifier.notify = check_pointer_type_change;
    qemu_add_mouse_mode_change_notifier(&vs->mouse_mode_notifier);

    vnc_init_timer(vd);

    /* vs might be free()ed here */
}

static void vnc_listen_read(void *opaque)
{
    VncDisplay *vs = opaque;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    /* Catch-up */
    vga_hw_update();

    int csock = accept(vs->lsock, (struct sockaddr *)&addr, &addrlen);
    if (csock != -1) {
        vnc_connect(vs, csock);
    }
}

void vnc_display_init(DisplayState *ds)
{
    VncDisplay *vs = calloc(1,sizeof(*vs));

    dcl = calloc(1,sizeof(DisplayChangeListener));

    assert(vs && dcl);
    ds->opaque = vs;
    dcl->idle = 1;
    vnc_display = vs;

    vs->lsock = -1;

    vs->ds = ds;
    QTAILQ_INIT(&vs->clients);
    vs->expires = TIME_MAX;

    vs->kbd_layout = init_keyboard_layout(name2keysym, "en-us");

    if (!vs->kbd_layout)
        exit(1);

    dcl->dpy_copy = vnc_dpy_copy;
    dcl->dpy_update = vnc_dpy_update;
    dcl->dpy_resize = vnc_dpy_resize;
    dcl->dpy_setdata = vnc_dpy_setdata;
    register_displaychangelistener(ds, dcl);
    ds->mouse_set = vnc_mouse_set;
    ds->cursor_define = vnc_dpy_cursor_define;
}

void vnc_display_close(DisplayState *ds)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;

    if (!vs)
        return;
    if (vs->display) {
        free(vs->display);
        vs->display = NULL;
    }
    if (vs->lsock != -1) {
        qemu_set_fd_handler2(vs->lsock, NULL, NULL, NULL, NULL);
        close(vs->lsock);
        vs->lsock = -1;
    }
    vs->auth = VNC_AUTH_INVALID;
}

char *vnc_display_local_addr(DisplayState *ds)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;

    return vnc_socket_local_addr("%s:%s", vs->lsock);
}

int vnc_display_open(DisplayState *ds, const char *display)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;
    char *dpy;

    if (!vnc_display)
        return -1;
    vnc_display_close(ds);
    if (strcmp(display, "none") == 0)
        return 0;

    if (!(vs->display = strdup(display)))
        return -1;

    vs->auth = VNC_AUTH_NONE;

    vs->lock_key_sync = 1;

    /* listen for connects */
    dpy = malloc(256);
    vs->lsock = inet_listen(display, dpy, 256, SOCK_STREAM, 5900);
    if (-1 == vs->lsock) {
        printf("inet_listen %s failed\n", display);
        free(dpy);
        return -1;
    } else {
        free(vs->display);
        vs->display = dpy;
    }

    return qemu_set_fd_handler2(vs->lsock, NULL, vnc_listen_read, NULL, vs);
}

VncJob *vnc_job_new(VncState *vs)
{
    vs->job.vs = vs;
    vs->job.rectangles = 0;

    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vs->job.saved_offset = vs->output.offset;
    vnc_write_u16(vs, 0);
    return &vs->job;
}

void vnc_job_push(VncJob *job)
{
    VncState *vs = job->vs;

    vs->output.buffer[job->saved_offset] = (job->rectangles >> 8) & 0xFF;
    vs->output.buffer[job->saved_offset + 1] = job->rectangles & 0xFF;
    vnc_flush(job->vs);
}

int vnc_job_add_rect(VncJob *job, int x, int y, int w, int h)
{
    int n;

    n = vnc_send_framebuffer_update(job->vs, x, y, w, h);
    if (n >= 0)
        job->rectangles += n;
    return n;
}


static int get_keysym(const name2keysym_t *table,
		      const char *name)
{
    const name2keysym_t *p;
    for(p = table; p->name != NULL; p++) {
        if (!strcmp(p->name, name))
            return p->keysym;
    }
    return 0;
}


static void add_to_key_range(struct key_range **krp, int code) {
    struct key_range *kr;
    for (kr = *krp; kr; kr = kr->next) {
	if (code >= kr->start && code <= kr->end)
	    break;
	if (code == kr->start - 1) {
	    kr->start--;
	    break;
	}
	if (code == kr->end + 1) {
	    kr->end++;
	    break;
	}
    }
    if (kr == NULL) {
	kr = calloc(1, sizeof(*kr));
        kr->start = kr->end = code;
        kr->next = *krp;
        *krp = kr;
    }
}

static void add_keysym(char *line, int keysym, int keycode, kbd_layout_t *k) {
    if (keysym < MAX_NORMAL_KEYCODE) {
	//fprintf(stderr,"Setting keysym %s (%d) to %d\n",line,keysym,keycode);
	k->keysym2keycode[keysym] = keycode;
    } else {
	if (k->extra_count >= MAX_EXTRA_COUNT) {
	    fprintf(stderr,
		    "Warning: Could not assign keysym %s (0x%x) because of memory constraints.\n",
		    line, keysym);
	} else {
	    k->keysym2keycode_extra[k->extra_count].
		keysym = keysym;
	    k->keysym2keycode_extra[k->extra_count].
		keycode = keycode;
	    k->extra_count++;
	}
    }
}

static kbd_layout_t *parse_keyboard_layout(const name2keysym_t *table,
					   const char *language,
					   kbd_layout_t * k)
{
    FILE *f;
    char * filename;
    char line[1024];
    int len;

    filename = qemu_find_file(QEMU_FILE_TYPE_KEYMAP, language);

    if (!k)
	k = calloc(1, sizeof(kbd_layout_t));
    if (!(filename && (f = fopen(filename, "r")))) {
	fprintf(stderr,
		"Could not read keymap file: '%s'\n", language);
	return NULL;
    }
    free(filename);
    filename = NULL;
    for(;;) {
	if (fgets(line, 1024, f) == NULL)
            break;
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0] == '#')
	    continue;
	if (!strncmp(line, "map ", 4))
	    continue;
	if (!strncmp(line, "include ", 8)) {
	    parse_keyboard_layout(table, line + 8, k);
        } else {
	    char *end_of_keysym = line;
	    while (*end_of_keysym != 0 && *end_of_keysym != ' ')
		end_of_keysym++;
	    if (*end_of_keysym) {
		int keysym;
		*end_of_keysym = 0;
		keysym = get_keysym(table, line);
		if (keysym == 0) {
                    //fprintf(stderr, "Warning: unknown keysym %s\n", line);
		} else {
		    const char *rest = end_of_keysym + 1;
		    char *rest2;
		    int keycode = strtol(rest, &rest2, 0);

		    if (rest && strstr(rest, "numlock")) {
			add_to_key_range(&k->keypad_range, keycode);
			add_to_key_range(&k->numlock_range, keysym);
			//fprintf(stderr, "keypad keysym %04x keycode %d\n", keysym, keycode);
		    }

		    if (rest && strstr(rest, "shift"))
			keycode |= SCANCODE_SHIFT;
		    if (rest && strstr(rest, "altgr"))
			keycode |= SCANCODE_ALTGR;
		    if (rest && strstr(rest, "ctrl"))
			keycode |= SCANCODE_CTRL;

		    add_keysym(line, keysym, keycode, k);

		    if (rest && strstr(rest, "addupper")) {
			char *c;
			for (c = line; *c; c++)
			    *c = qemu_toupper(*c);
			keysym = get_keysym(table, line);
			if (keysym)
			    add_keysym(line, keysym, keycode | SCANCODE_SHIFT, k);
		    }
		}
	    }
	}
    }
    fclose(f);
    return k;
}


void *init_keyboard_layout(const name2keysym_t *table, const char *language)
{
    return parse_keyboard_layout(table, language, NULL);
}


int keysym2scancode(void *kbd_layout, int keysym)
{
    kbd_layout_t *k = kbd_layout;
    if (keysym < MAX_NORMAL_KEYCODE) {
	if (k->keysym2keycode[keysym] == 0)
	    fprintf(stderr, "Warning: no scancode found for keysym %d\n",
		    keysym);
	return k->keysym2keycode[keysym];
    } else {
	int i;
#ifdef XK_ISO_Left_Tab
	if (keysym == XK_ISO_Left_Tab)
	    keysym = XK_Tab;
#endif
	for (i = 0; i < k->extra_count; i++)
	    if (k->keysym2keycode_extra[i].keysym == keysym)
		return k->keysym2keycode_extra[i].keycode;
    }
    return 0;
}

int keycode_is_keypad(void *kbd_layout, int keycode)
{
    kbd_layout_t *k = kbd_layout;
    struct key_range *kr;

    for (kr = k->keypad_range; kr; kr = kr->next)
        if (keycode >= kr->start && keycode <= kr->end)
            return 1;
    return 0;
}

int keysym_is_numlock(void *kbd_layout, int keysym)
{
    kbd_layout_t *k = kbd_layout;
    struct key_range *kr;

    for (kr = k->numlock_range; kr; kr = kr->next)
        if (keysym >= kr->start && keysym <= kr->end)
            return 1;
    return 0;
}
int slow_bitmap_empty(const unsigned long *bitmap, int bits)
{
    int k, lim = bits/64;

    for (k = 0; k < lim; ++k) {
        if (bitmap[k]) {
            return 0;
        }
    }
    if (bits % 64) {
        if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits)) {
            return 0;
        }
    }

    return 1;
}

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % 64))

void bitmap_set(unsigned long *map, int start, int nr)
{
    unsigned long *p = map + BIT_WORD(start);
    const int size = start + nr;
    int bits_to_set = 64 - (start % 64);
    unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

    while (nr - bits_to_set >= 0) {
        *p |= mask_to_set;
        nr -= bits_to_set;
        bits_to_set = 64;
        mask_to_set = ~0UL;
        p++;
    }
    if (nr) {
        mask_to_set &= BITMAP_LAST_WORD_MASK(size);
        *p |= mask_to_set;
    }
}

void bitmap_clear(unsigned long *map, int start, int nr)
{
    unsigned long *p = map + BIT_WORD(start);
    const int size = start + nr;
    int bits_to_clear = 64 - (start % 64);
    unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

    while (nr - bits_to_clear >= 0) {
        *p &= ~mask_to_clear;
        nr -= bits_to_clear;
        bits_to_clear = 64;
        mask_to_clear = ~0UL;
        p++;
    }
    if (nr) {
        mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
        *p &= ~mask_to_clear;
    }
}
