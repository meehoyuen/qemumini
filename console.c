/*
 * QEMU graphical console
 */
#include "qemu-common.h"
#include "console.h"
#include "qemu-timer.h"

#define DEFAULT_BACKSCROLL 512
#define MAX_CONSOLES 12

#define QEMU_RGBA(r, g, b, a) (((a) << 24) | ((r) << 16) | ((g) << 8) | (b))
#define QEMU_RGB(r, g, b) QEMU_RGBA(r, g, b, 0xff)

typedef struct TextAttributes {
    uint8_t fgcol:4;
    uint8_t bgcol:4;
    uint8_t bold:1;
    uint8_t uline:1;
    uint8_t blink:1;
    uint8_t invers:1;
    uint8_t unvisible:1;
} TextAttributes;

typedef struct TextCell {
    uint8_t ch;
    TextAttributes t_attrib;
} TextCell;

#define MAX_ESC_PARAMS 3

enum TTYState {
    TTY_STATE_NORM,
    TTY_STATE_ESC,
    TTY_STATE_CSI,
};

typedef struct QEMUFIFO {
    uint8_t *buf;
    int buf_size;
    int count, wptr, rptr;
} QEMUFIFO;

typedef enum {
    GRAPHIC_CONSOLE,
} console_type_t;

struct TextConsole {
    int index;
    console_type_t console_type;
    DisplayState *ds;
    /* Graphic console state.  */
    vga_hw_update_ptr hw_update;
    vga_hw_invalidate_ptr hw_invalidate;
    vga_hw_text_update_ptr hw_text_update;
    void *hw;

    int g_width, g_height;
    int width;
    int height;
    int total_height;
    int backscroll_height;
    int x, y;
    int x_saved, y_saved;
    int y_displayed;
    int y_base;
    TextAttributes t_attrib_default; /* default text attributes */
    TextAttributes t_attrib; /* currently active text attributes */
    TextCell *cells;
    int text_x[2], text_y[2], cursor_invalidate;
    int echo;

    int update_x0;
    int update_y0;
    int update_x1;
    int update_y1;

    enum TTYState state;
    int esc_params[MAX_ESC_PARAMS];
    int nb_esc_params;

    CharDriverState *chr;
    /* fifo for key pressed */
    QEMUFIFO out_fifo;
    uint8_t out_fifo_buf[16];
    QEMUTimer *kbd_timer;
};

static DisplayState *display_state;
static TextConsole *active_console;
static TextConsole *consoles[MAX_CONSOLES];
static int nb_consoles = 0;

void vga_hw_update(void)
{
    if (active_console && active_console->hw_update)
        active_console->hw_update(active_console->hw);
}

void vga_hw_invalidate(void)
{
    if (active_console && active_console->hw_invalidate)
        active_console->hw_invalidate(active_console->hw);
}

void vga_hw_text_update(console_ch_t *chardata)
{
    if (active_console && active_console->hw_text_update)
        active_console->hw_text_update(active_console->hw, chardata);
}

/* convert a RGBA color to a color index usable in graphic primitives */
static unsigned int vga_get_color(DisplayState *ds, unsigned int rgba)
{
    unsigned int r, g, b, color;

    switch(ds_get_bits_per_pixel(ds)) {
#if 0
    case 8:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = (rgb_to_index[r] * 6 * 6) +
            (rgb_to_index[g] * 6) +
            (rgb_to_index[b]);
        break;
#endif
    case 15:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3);
        break;
    case 16:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
        break;
    case 32:
    default:
        color = rgba;
        break;
    }
    return color;
}

/***********************************************************/
/* basic char display */

#define FONT_HEIGHT 16
#define FONT_WIDTH 8

#define cbswap_32(__x) \
((uint32_t)( \
		(((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) ))

#define PAT(x) cbswap_32(x)

static const uint32_t dmask16[16] = {
    PAT(0x00000000),
    PAT(0x000000ff),
    PAT(0x0000ff00),
    PAT(0x0000ffff),
    PAT(0x00ff0000),
    PAT(0x00ff00ff),
    PAT(0x00ffff00),
    PAT(0x00ffffff),
    PAT(0xff000000),
    PAT(0xff0000ff),
    PAT(0xff00ff00),
    PAT(0xff00ffff),
    PAT(0xffff0000),
    PAT(0xffff00ff),
    PAT(0xffffff00),
    PAT(0xffffffff),
};

static const uint32_t dmask4[4] = {
    PAT(0x00000000),
    PAT(0x0000ffff),
    PAT(0xffff0000),
    PAT(0xffffffff),
};

static uint32_t color_table[2][8];

#ifndef CONFIG_CURSES
enum color_names {
    COLOR_BLACK   = 0,
    COLOR_RED     = 1,
    COLOR_GREEN   = 2,
    COLOR_YELLOW  = 3,
    COLOR_BLUE    = 4,
    COLOR_MAGENTA = 5,
    COLOR_CYAN    = 6,
    COLOR_WHITE   = 7
};
#endif

static const uint32_t color_table_rgb[2][8] = {
    {   /* dark */
        QEMU_RGB(0x00, 0x00, 0x00),  /* black */
        QEMU_RGB(0xaa, 0x00, 0x00),  /* red */
        QEMU_RGB(0x00, 0xaa, 0x00),  /* green */
        QEMU_RGB(0xaa, 0xaa, 0x00),  /* yellow */
        QEMU_RGB(0x00, 0x00, 0xaa),  /* blue */
        QEMU_RGB(0xaa, 0x00, 0xaa),  /* magenta */
        QEMU_RGB(0x00, 0xaa, 0xaa),  /* cyan */
        QEMU_RGB(0xaa, 0xaa, 0xaa),  /* white */
    },
    {   /* bright */
        QEMU_RGB(0x00, 0x00, 0x00),  /* black */
        QEMU_RGB(0xff, 0x00, 0x00),  /* red */
        QEMU_RGB(0x00, 0xff, 0x00),  /* green */
        QEMU_RGB(0xff, 0xff, 0x00),  /* yellow */
        QEMU_RGB(0x00, 0x00, 0xff),  /* blue */
        QEMU_RGB(0xff, 0x00, 0xff),  /* magenta */
        QEMU_RGB(0x00, 0xff, 0xff),  /* cyan */
        QEMU_RGB(0xff, 0xff, 0xff),  /* white */
    }
};

static inline unsigned int col_expand(DisplayState *ds, unsigned int col)
{
    switch(ds_get_bits_per_pixel(ds)) {
    case 8:
        col |= col << 8;
        col |= col << 16;
        break;
    case 15:
    case 16:
        col |= col << 16;
        break;
    default:
        break;
    }

    return col;
}

void console_select(unsigned int index)
{
    TextConsole *s;

    if (index >= MAX_CONSOLES)
        return;
    if (active_console) {
        active_console->g_width = ds_get_width(active_console->ds);
        active_console->g_height = ds_get_height(active_console->ds);
    }
    s = consoles[index];
    if (s) {
        DisplayState *ds = s->ds;
        active_console = s;
        if (ds_get_bits_per_pixel(s->ds)) {
            ds->surface = qemu_resize_displaysurface(ds, s->g_width, s->g_height);
        } else {
            s->ds->surface->width = s->width;
            s->ds->surface->height = s->height;
        }
        dpy_resize(s->ds);
        vga_hw_invalidate();
    }
}

static TextConsole *new_console(DisplayState *ds, console_type_t console_type)
{
    TextConsole *s;
    int i;

    if (nb_consoles >= MAX_CONSOLES)
        return NULL;
    s = calloc(1, sizeof(TextConsole));
    if (!active_console || ((active_console->console_type != GRAPHIC_CONSOLE) &&
        (console_type == GRAPHIC_CONSOLE))) {
        active_console = s;
    }
    s->ds = ds;
    s->console_type = console_type;

    for (i = nb_consoles; i > 0; i--) {
        if (consoles[i - 1]->console_type == GRAPHIC_CONSOLE)
            break;
        consoles[i] = consoles[i - 1];
        consoles[i]->index = i;
    }
    s->index = i;
    consoles[i] = s;
    nb_consoles++;

    return s;
}

static DisplaySurface* defaultallocator_create_displaysurface(int width, int height)
{
    DisplaySurface *surface = (DisplaySurface*) calloc(1, sizeof(DisplaySurface));

    int linesize = width * 4;
    qemu_alloc_display(surface, width, height, linesize,
                       qemu_default_pixelformat(32), 0);
    return surface;
}

static DisplaySurface* defaultallocator_resize_displaysurface(DisplaySurface *surface,
                                          int width, int height)
{
    int linesize = width * 4;
    qemu_alloc_display(surface, width, height, linesize,
                       qemu_default_pixelformat(32), 0);
    return surface;
}

void qemu_alloc_display(DisplaySurface *surface, int width, int height,
                        int linesize, PixelFormat pf, int newflags)
{
    void *data;
    surface->width = width;
    surface->height = height;
    surface->linesize = linesize;
    surface->pf = pf;
    if (surface->flags & QEMU_ALLOCATED_FLAG) {
        data = realloc(surface->data,
                            surface->linesize * surface->height);
    } else {
        data = malloc(surface->linesize * surface->height);
    }
    surface->data = (uint8_t *)data;
    surface->flags = newflags | QEMU_ALLOCATED_FLAG;
}

DisplaySurface* qemu_create_displaysurface_from(int width, int height, int bpp,
                                              int linesize, uint8_t *data)
{
    DisplaySurface *surface = (DisplaySurface*) calloc(1, sizeof(DisplaySurface));

    surface->width = width;
    surface->height = height;
    surface->linesize = linesize;
    surface->pf = qemu_default_pixelformat(bpp);
    surface->data = data;

    return surface;
}

static void defaultallocator_free_displaysurface(DisplaySurface *surface)
{
    if (surface == NULL)
        return;
    if (surface->flags & QEMU_ALLOCATED_FLAG)
    {
        free(surface->data);
        surface->data = NULL;
    }
    free(surface);
    surface = NULL;
}

static struct DisplayAllocator default_allocator = {
    defaultallocator_create_displaysurface,
    defaultallocator_resize_displaysurface,
    defaultallocator_free_displaysurface
};

static void dumb_display_init(void)
{
    DisplayState *ds = calloc(1, sizeof(DisplayState));
    int width = 640;
    int height = 480;

    ds->allocator = &default_allocator;
    if (is_fixedsize_console()) {
        width = active_console->g_width;
        height = active_console->g_height;
    }
    ds->surface = qemu_create_displaysurface(ds, width, height);
    register_displaystate(ds);
}

/***********************************************************/
/* register display */

void register_displaystate(DisplayState *ds)
{
    DisplayState **s;
    s = &display_state;
    while (*s != NULL)
        s = &(*s)->next;
    ds->next = NULL;
    *s = ds;
}

DisplayState *get_displaystate(void)
{
    if (!display_state) {
        dumb_display_init ();
    }
    return display_state;
}

DisplayAllocator *register_displayallocator(DisplayState *ds, DisplayAllocator *da)
{
    if(ds->allocator ==  &default_allocator) {
        DisplaySurface *surf;
        surf = da->create_displaysurface(ds_get_width(ds), ds_get_height(ds));
        defaultallocator_free_displaysurface(ds->surface);
        ds->surface = surf;
        ds->allocator = da;
    }
    return ds->allocator;
}

DisplayState *graphic_console_init(vga_hw_update_ptr update,
                                   vga_hw_invalidate_ptr invalidate,
                                   vga_hw_text_update_ptr text_update,
                                   void *opaque)
{
    TextConsole *s;
    DisplayState *ds;

    ds = (DisplayState *) calloc(1, sizeof(DisplayState));
    ds->allocator = &default_allocator; 
    ds->surface = qemu_create_displaysurface(ds, 640, 480);

    s = new_console(ds, GRAPHIC_CONSOLE);
    if (s == NULL) {
        qemu_free_displaysurface(ds);
        free(ds);
        ds = NULL;
        return NULL;
    }
    s->hw_update = update;
    s->hw_invalidate = invalidate;
    s->hw_text_update = text_update;
    s->hw = opaque;

    register_displaystate(ds);
    return ds;
}

int is_fixedsize_console(void)
{
    return !!active_console;
}

void console_color_init(DisplayState *ds)
{
    int i, j;
    for (j = 0; j < 2; j++) {
        for (i = 0; i < 8; i++) {
            color_table[j][i] = col_expand(ds,
                   vga_get_color(ds, color_table_rgb[j][i]));
        }
    }
}

static TextConsole *get_graphic_console(DisplayState *ds)
{
    int i;
    TextConsole *s;
    for (i = 0; i < nb_consoles; i++) {
        s = consoles[i];
        if (s->console_type == GRAPHIC_CONSOLE && s->ds == ds)
            return s;
    }
    return NULL;
}

void qemu_console_resize(DisplayState *ds, int width, int height)
{
    TextConsole *s = get_graphic_console(ds);
    if (!s) return;

    s->g_width = width;
    s->g_height = height;
    ds->surface = qemu_resize_displaysurface(ds, width, height);
    dpy_resize(ds);
}

void qemu_console_copy(DisplayState *ds, int src_x, int src_y,
                       int dst_x, int dst_y, int w, int h)
{
    dpy_copy(ds, src_x, src_y, dst_x, dst_y, w, h);
}

PixelFormat qemu_different_endianness_pixelformat(int bpp)
{
    PixelFormat pf;

    memset(&pf, 0x00, sizeof(PixelFormat));

    pf.bits_per_pixel = bpp;
    pf.bytes_per_pixel = bpp / 8;
    pf.depth = bpp == 32 ? 24 : bpp;

    switch (bpp) {
        case 24:
            pf.rmask = 0x000000FF;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x00FF0000;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 0;
            pf.gshift = 8;
            pf.bshift = 16;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            break;
        case 32:
            pf.rmask = 0x0000FF00;
            pf.gmask = 0x00FF0000;
            pf.bmask = 0xFF000000;
            pf.amask = 0x00000000;
            pf.amax = 255;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.ashift = 0;
            pf.rshift = 8;
            pf.gshift = 16;
            pf.bshift = 24;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            pf.abits = 8;
            break;
        default:
            break;
    }
    return pf;
}

PixelFormat qemu_default_pixelformat(int bpp)
{
    PixelFormat pf;

    memset(&pf, 0x00, sizeof(PixelFormat));

    pf.bits_per_pixel = bpp;
    pf.bytes_per_pixel = bpp / 8;
    pf.depth = bpp == 32 ? 24 : bpp;

    switch (bpp) {
        case 15:
            pf.bits_per_pixel = 16;
            pf.bytes_per_pixel = 2;
            pf.rmask = 0x00007c00;
            pf.gmask = 0x000003E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 31;
            pf.bmax = 31;
            pf.rshift = 10;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 5;
            pf.bbits = 5;
            break;
        case 16:
            pf.rmask = 0x0000F800;
            pf.gmask = 0x000007E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 63;
            pf.bmax = 31;
            pf.rshift = 11;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 6;
            pf.bbits = 5;
            break;
        case 24:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
        case 32:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.amax = 255;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.ashift = 24;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            pf.abits = 8;
            break;
        default:
            break;
    }
    return pf;
}
