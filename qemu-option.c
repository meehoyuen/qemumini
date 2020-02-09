#include <stdio.h>
#include <string.h>

#include "qemu-common.h"
#include "qemu-option.h"
#include "qdev.h"

/*
 * Extracts the name of an option from the parameter string (p points at the
 * first byte of the option name)
 *
 * The option name is delimited by delim (usually , or =) or the string end
 * and is copied into buf. If the option name is longer than buf_size, it is
 * truncated. buf is always zero terminated.
 *
 * The return value is the position of the delimiter/zero byte after the option
 * name in p.
 */
const char *get_opt_name(char *buf, int buf_size, const char *p, char delim)
{
    char *q;

    q = buf;
    while (*p != '\0' && *p != delim) {
        if (q && (q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    if (q)
        *q = '\0';

    return p;
}

/*
 * Extracts the value of an option from the parameter string p (p points at the
 * first byte of the option value)
 *
 * This function is comparable to get_opt_name with the difference that the
 * delimiter is fixed to be comma which starts a new option. To specify an
 * option value that contains commas, double each comma.
 */
const char *get_opt_value(char *buf, int buf_size, const char *p)
{
    char *q;

    q = buf;
    while (*p != '\0') {
        if (*p == ',') {
            if (*(p + 1) != ',')
                break;
            p++;
        }
        if (q && (q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    if (q)
        *q = '\0';

    return p;
}

int get_next_param_value(char *buf, int buf_size,
                         const char *tag, const char **pstr)
{
    const char *p;
    char option[128];

    p = *pstr;
    for(;;) {
        p = get_opt_name(option, sizeof(option), p, '=');
        if (*p != '=')
            break;
        p++;
        if (!strcmp(tag, option)) {
            *pstr = get_opt_value(buf, buf_size, p);
            if (**pstr == ',') {
                (*pstr)++;
            }
            return strlen(buf);
        } else {
            p = get_opt_value(NULL, 0, p);
        }
        if (*p != ',')
            break;
        p++;
    }
    return 0;
}

int get_param_value(char *buf, int buf_size,
                    const char *tag, const char *str)
{
    return get_next_param_value(buf, buf_size, tag, &str);
}

int check_params(char *buf, int buf_size,
                 const char * const *params, const char *str)
{
    const char *p;
    int i;

    p = str;
    while (*p != '\0') {
        p = get_opt_name(buf, buf_size, p, '=');
        if (*p != '=') {
            return -1;
        }
        p++;
        for (i = 0; params[i] != NULL; i++) {
            if (!strcmp(params[i], buf)) {
                break;
            }
        }
        if (params[i] == NULL) {
            return -1;
        }
        p = get_opt_value(NULL, 0, p);
        if (*p != ',') {
            break;
        }
        p++;
    }
    return 0;
}

/*
 * Searches an option list for an option with the given name
 */
QEMUOptionParameter *get_option_parameter(QEMUOptionParameter *list,
    const char *name)
{
    while (list && list->name) {
        if (!strcmp(list->name, name)) {
            return list;
        }
        list++;
    }

    return NULL;
}

static int parse_option_bool(const char *name, const char *value, bool *ret)
{
    if (value != NULL) {
        if (!strcmp(value, "on")) {
            *ret = 1;
        } else if (!strcmp(value, "off")) {
            *ret = 0;
        } else {
            printf("QERR_INVALID_PARAMETER_VALUE, name:%s, 'on' or 'off'\n", name);
            return -1;
        }
    } else {
        *ret = 1;
    }
    return 0;
}

static int parse_option_number(const char *name, const char *value, uint64_t *ret)
{
    char *postfix;
    uint64_t number;

    if (value != NULL) {
        number = strtoull(value, &postfix, 0);
        if (*postfix != '\0') {
            printf("QERR_INVALID_PARAMETER_VALUE, name:%s, a number\n", name);
            return -1;
        }
        *ret = number;
    } else {
        printf("QERR_INVALID_PARAMETER_VALUE, name:%s, a number\n", name);
        return -1;
    }
    return 0;
}

static int parse_option_size(const char *name, const char *value, uint64_t *ret)
{
    char *postfix;
    double sizef;

    if (value != NULL) {
        sizef = strtod(value, &postfix);
        switch (*postfix) {
        case 'T':
            sizef *= 1024;
        case 'G':
            sizef *= 1024;
        case 'M':
            sizef *= 1024;
        case 'K':
        case 'k':
            sizef *= 1024;
        case 'b':
        case '\0':
            *ret = (uint64_t) sizef;
            break;
        default:
            printf("QERR_INVALID_PARAMETER_VALUE, name:%s, a size\n", name);
            printf("You may use k, M, G or T suffixes for "
                    "kilobytes, megabytes, gigabytes and terabytes.\n");
            return -1;
        }
    } else {
        printf("QERR_INVALID_PARAMETER_VALUE, name:%s, a size\n", name);
        return -1;
    }
    return 0;
}

/*
 * Sets the value of a parameter in a given option list. The parsing of the
 * value depends on the type of option:
 *
 * OPT_FLAG (uses value.n):
 *      If no value is given, the flag is set to 1.
 *      Otherwise the value must be "on" (set to 1) or "off" (set to 0)
 *
 * OPT_STRING (uses value.s):
 *      value is strdup()ed and assigned as option value
 *
 * OPT_SIZE (uses value.n):
 *      The value is converted to an integer. Suffixes for kilobytes etc. are
 *      allowed (powers of 1024).
 *
 * Returns 0 on succes, -1 in error cases
 */
int set_option_parameter(QEMUOptionParameter *list, const char *name,
    const char *value)
{
    bool flag;

    // Find a matching parameter
    list = get_option_parameter(list, name);
    if (list == NULL) {
        fprintf(stderr, "Unknown option '%s'\n", name);
        return -1;
    }

    // Process parameter
    switch (list->type) {
    case OPT_FLAG:
        if (parse_option_bool(name, value, &flag) == -1)
            return -1;
        list->value.n = flag;
        break;

    case OPT_STRING:
        if (value != NULL) {
            list->value.s = strdup(value);
        } else {
            fprintf(stderr, "Option '%s' needs a parameter\n", name);
            return -1;
        }
        break;

    case OPT_SIZE:
        if (parse_option_size(name, value, &list->value.n) == -1)
            return -1;
        break;

    default:
        fprintf(stderr, "Bug: Option '%s' has an unknown type\n", name);
        return -1;
    }

    return 0;
}

/*
 * Sets the given parameter to an integer instead of a string.
 * This function cannot be used to set string options.
 *
 * Returns 0 on success, -1 in error cases
 */
int set_option_parameter_int(QEMUOptionParameter *list, const char *name,
    uint64_t value)
{
    // Find a matching parameter
    list = get_option_parameter(list, name);
    if (list == NULL) {
        fprintf(stderr, "Unknown option '%s'\n", name);
        return -1;
    }

    // Process parameter
    switch (list->type) {
    case OPT_FLAG:
    case OPT_NUMBER:
    case OPT_SIZE:
        list->value.n = value;
        break;

    default:
        return -1;
    }

    return 0;
}

/*
 * Frees a option list. If it contains strings, the strings are freed as well.
 */
void free_option_parameters(QEMUOptionParameter *list)
{
    QEMUOptionParameter *cur = list;

    while (cur && cur->name) {
        if (cur->type == OPT_STRING) {
            free(cur->value.s);
            cur->value.s = NULL;
        }
        cur++;
    }

    free(list);
    list = NULL;
}

/*
 * Count valid options in list
 */
static size_t count_option_parameters(QEMUOptionParameter *list)
{
    size_t num_options = 0;

    while (list && list->name) {
        num_options++;
        list++;
    }

    return num_options;
}

/*
 * Append an option list (list) to an option list (dest).
 *
 * If dest is NULL, a new copy of list is created.
 *
 * Returns a pointer to the first element of dest (or the newly allocated copy)
 */
QEMUOptionParameter *append_option_parameters(QEMUOptionParameter *dest,
    QEMUOptionParameter *list)
{
    size_t num_options, num_dest_options;

    num_options = count_option_parameters(dest);
    num_dest_options = num_options;

    num_options += count_option_parameters(list);

    dest = realloc(dest, (num_options + 1) * sizeof(QEMUOptionParameter));
    dest[num_dest_options].name = NULL;

    while (list && list->name) {
        if (get_option_parameter(dest, list->name) == NULL) {
            dest[num_dest_options++] = *list;
            dest[num_dest_options].name = NULL;
        }
        list++;
    }

    return dest;
}

/*
 * Parses a parameter string (param) into an option list (dest).
 *
 * list is the template option list. If dest is NULL, a new copy of list is
 * created. If list is NULL, this function fails.
 *
 * A parameter string consists of one or more parameters, separated by commas.
 * Each parameter consists of its name and possibly of a value. In the latter
 * case, the value is delimited by an = character. To specify a value which
 * contains commas, double each comma so it won't be recognized as the end of
 * the parameter.
 *
 * For more details of the parsing see above.
 *
 * Returns a pointer to the first element of dest (or the newly allocated copy)
 * or NULL in error cases
 */
QEMUOptionParameter *parse_option_parameters(const char *param,
    QEMUOptionParameter *list, QEMUOptionParameter *dest)
{
    QEMUOptionParameter *allocated = NULL;
    char name[256];
    char value[256];
    char *param_delim, *value_delim;
    char next_delim;

    if (list == NULL) {
        return NULL;
    }

    if (dest == NULL) {
        dest = allocated = append_option_parameters(NULL, list);
    }

    while (*param) {

        // Find parameter name and value in the string
        param_delim = strchr(param, ',');
        value_delim = strchr(param, '=');

        if (value_delim && (value_delim < param_delim || !param_delim)) {
            next_delim = '=';
        } else {
            next_delim = ',';
            value_delim = NULL;
        }

        param = get_opt_name(name, sizeof(name), param, next_delim);
        if (value_delim) {
            param = get_opt_value(value, sizeof(value), param + 1);
        }
        if (*param != '\0') {
            param++;
        }

        // Set the parameter
        if (set_option_parameter(dest, name, value_delim ? value : NULL)) {
            goto fail;
        }
    }

    return dest;

fail:
    // Only free the list if it was newly allocated
    free_option_parameters(allocated);
    return NULL;
}

/*
 * Prints all options of a list that have a value to stdout
 */
void print_option_parameters(QEMUOptionParameter *list)
{
    while (list && list->name) {
        switch (list->type) {
            case OPT_STRING:
                 if (list->value.s != NULL) {
                     printf("%s='%s' ", list->name, list->value.s);
                 }
                break;
            case OPT_FLAG:
                printf("%s=%s ", list->name, list->value.n ? "on" : "off");
                break;
            case OPT_SIZE:
            case OPT_NUMBER:
                printf("%s=%" PRId64 " ", list->name, list->value.n);
                break;
            default:
                printf("%s=(unkown type) ", list->name);
                break;
        }
        list++;
    }
}

/*
 * Prints an overview of all available options
 */
void print_option_help(QEMUOptionParameter *list)
{
    printf("Supported options:\n");
    while (list && list->name) {
        printf("%-16s %s\n", list->name,
            list->help ? list->help : "No description available");
        list++;
    }
}

/* ------------------------------------------------------------------ */

struct QemuOpt {
    const char   *name;
    const char   *str;

    const QemuOptDesc *desc;
    union {
        bool boolean;
        uint64_t uint;
    } value;

    QemuOpts     *opts;
    QTAILQ_ENTRY(QemuOpt) next;
};

struct QemuOpts {
    char *id;
    QemuOptsList *list;
    QTAILQ_HEAD(QemuOptHead, QemuOpt) head;
    QTAILQ_ENTRY(QemuOpts) next;
};

static QemuOpt *qemu_opt_find(QemuOpts *opts, const char *name)
{
    QemuOpt *opt;

    QTAILQ_FOREACH_REVERSE(opt, &opts->head, QemuOptHead, next) {
        if (strcmp(opt->name, name) != 0)
            continue;
        return opt;
    }
    return NULL;
}

const char *qemu_opt_get(QemuOpts *opts, const char *name)
{
    QemuOpt *opt = qemu_opt_find(opts, name);
    return opt ? opt->str : NULL;
}

bool qemu_opt_get_bool(QemuOpts *opts, const char *name, bool defval)
{
    QemuOpt *opt = qemu_opt_find(opts, name);

    if (opt == NULL)
        return defval;
    assert(opt->desc && opt->desc->type == QEMU_OPT_BOOL);
    return opt->value.boolean;
}

uint64_t qemu_opt_get_number(QemuOpts *opts, const char *name, uint64_t defval)
{
    QemuOpt *opt = qemu_opt_find(opts, name);

    if (opt == NULL)
        return defval;
    assert(opt->desc && opt->desc->type == QEMU_OPT_NUMBER);
    return opt->value.uint;
}

uint64_t qemu_opt_get_size(QemuOpts *opts, const char *name, uint64_t defval)
{
    QemuOpt *opt = qemu_opt_find(opts, name);

    if (opt == NULL)
        return defval;
    assert(opt->desc && opt->desc->type == QEMU_OPT_SIZE);
    return opt->value.uint;
}

static int qemu_opt_parse(QemuOpt *opt)
{
    if (opt->desc == NULL)
        return 0;
    switch (opt->desc->type) {
    case QEMU_OPT_STRING:
        /* nothing */
        return 0;
    case QEMU_OPT_BOOL:
        return parse_option_bool(opt->name, opt->str, &opt->value.boolean);
    case QEMU_OPT_NUMBER:
        return parse_option_number(opt->name, opt->str, &opt->value.uint);
    case QEMU_OPT_SIZE:
        return parse_option_size(opt->name, opt->str, &opt->value.uint);
    default:
        abort();
    }
}

static void qemu_opt_del(QemuOpt *opt)
{
    QTAILQ_REMOVE(&opt->opts->head, opt, next);
    free((/* !const */ char*)opt->name);
    opt->name = NULL;
    free((/* !const */ char*)opt->str);
    opt->str = NULL;
    free(opt);
    opt =  NULL;
}

int qemu_opt_set(QemuOpts *opts, const char *name, const char *value)
{
    QemuOpt *opt;
    const QemuOptDesc *desc = opts->list->desc;
    int i;

    for (i = 0; desc[i].name != NULL; i++) {
        if (strcmp(desc[i].name, name) == 0) {
            break;
        }
    }
    if (desc[i].name == NULL) {
        if (i == 0) {
            /* empty list -> allow any */;
        } else {
            printf("QERR_INVALID_PARAMETER, name:%s\n", name);
            return -1;
        }
    }

    opt = calloc(1, sizeof(*opt));
    opt->name = strdup(name);
    opt->opts = opts;
    QTAILQ_INSERT_TAIL(&opts->head, opt, next);
    if (desc[i].name != NULL) {
        opt->desc = desc+i;
    }
    if (value) {
        opt->str = strdup(value);
    }
    if (qemu_opt_parse(opt) < 0) {
        qemu_opt_del(opt);
        return -1;
    }
    return 0;
}

int qemu_opt_set_bool(QemuOpts *opts, const char *name, bool val)
{
    QemuOpt *opt;
    const QemuOptDesc *desc = opts->list->desc;
    int i;

    for (i = 0; desc[i].name != NULL; i++) {
        if (strcmp(desc[i].name, name) == 0) {
            break;
        }
    }
    if (desc[i].name == NULL) {
        if (i == 0) {
            /* empty list -> allow any */;
        } else {
            printf("QERR_INVALID_PARAMETER, name:%s\n", name);
            return -1;
        }
    }

    opt = calloc(1, sizeof(*opt));
    opt->name = strdup(name);
    opt->opts = opts;
    QTAILQ_INSERT_TAIL(&opts->head, opt, next);
    if (desc[i].name != NULL) {
        opt->desc = desc+i;
    }
    opt->value.boolean = !!val;
    return 0;
}

int qemu_opt_foreach(QemuOpts *opts, qemu_opt_loopfunc func, void *opaque,
                     int abort_on_failure)
{
    QemuOpt *opt;
    int rc = 0;

    QTAILQ_FOREACH(opt, &opts->head, next) {
        rc = func(opt->name, opt->str, opaque);
        if (abort_on_failure  &&  rc != 0)
            break;
    }
    return rc;
}

QemuOpts *qemu_opts_find(QemuOptsList *list, const char *id)
{
    QemuOpts *opts;

    QTAILQ_FOREACH(opts, &list->head, next) {
        if (!opts->id) {
            continue;
        }
        if (strcmp(opts->id, id) != 0) {
            continue;
        }
        return opts;
    }
    return NULL;
}

static int id_wellformed(const char *id)
{
    int i;

    if (!qemu_isalpha(id[0])) {
        return 0;
    }
    for (i = 1; id[i]; i++) {
        if (!qemu_isalnum(id[i]) && !strchr("-._", id[i])) {
            return 0;
        }
    }
    return 1;
}

QemuOpts *qemu_opts_create(QemuOptsList *list, const char *id, int fail_if_exists)
{
    QemuOpts *opts = NULL;

    if (id) {
        if (!id_wellformed(id)) {
            printf("QERR_INVALID_PARAMETER_VALUE, id, an identifier\n");
            printf("Identifiers consist of letters, digits, '-', '.', '_', starting with a letter.\n");
            return NULL;
        }
        opts = qemu_opts_find(list, id);
        if (opts != NULL) {
            if (fail_if_exists) {
                printf("QERR_DUPLICATE_ID, id, list->name:%s\n", list->name);
                return NULL;
            } else {
                return opts;
            }
        }
    }
    opts = calloc(1, sizeof(*opts));
    if (id) {
        opts->id = strdup(id);
    }
    opts->list = list;
    QTAILQ_INIT(&opts->head);
    QTAILQ_INSERT_TAIL(&list->head, opts, next);
    return opts;
}

void qemu_opts_reset(QemuOptsList *list)
{
    QemuOpts *opts, *next_opts;

    QTAILQ_FOREACH_SAFE(opts, &list->head, next, next_opts) {
        qemu_opts_del(opts);
    }
}

int qemu_opts_set(QemuOptsList *list, const char *id,
                  const char *name, const char *value)
{
    QemuOpts *opts;

    opts = qemu_opts_create(list, id, 1);
    if (opts == NULL) {
        return -1;
    }
    return qemu_opt_set(opts, name, value);
}

const char *qemu_opts_id(QemuOpts *opts)
{
    return opts->id;
}

void qemu_opts_del(QemuOpts *opts)
{
    QemuOpt *opt;

    for (;;) {
        opt = QTAILQ_FIRST(&opts->head);
        if (opt == NULL)
            break;
        qemu_opt_del(opt);
    }
    QTAILQ_REMOVE(&opts->list->head, opts, next);
    free(opts->id);
    opts->id = NULL;
    free(opts);
    opts = NULL;
}

int qemu_opts_print(QemuOpts *opts, void *dummy)
{
    QemuOpt *opt;

    fprintf(stderr, "%s: %s:", opts->list->name,
            opts->id ? opts->id : "<noid>");
    QTAILQ_FOREACH(opt, &opts->head, next) {
        fprintf(stderr, " %s=\"%s\"", opt->name, opt->str);
    }
    fprintf(stderr, "\n");
    return 0;
}

int qemu_opts_do_parse(QemuOpts *opts, const char *params, const char *firstname)
{
    char option[128], value[1024];
    const char *p,*pe,*pc;

    for (p = params; *p != '\0'; p++) {
        pe = strchr(p, '=');
        pc = strchr(p, ',');
        if (!pe || (pc && pc < pe)) {
            /* found "foo,more" */
            if (p == params && firstname) {
                /* implicitly named first option */
                pstrcpy(option, sizeof(option), firstname);
                p = get_opt_value(value, sizeof(value), p);
            } else {
                /* option without value, probably a flag */
                p = get_opt_name(option, sizeof(option), p, ',');
                if (strncmp(option, "no", 2) == 0) {
                    memmove(option, option+2, strlen(option+2)+1);
                    pstrcpy(value, sizeof(value), "off");
                } else {
                    pstrcpy(value, sizeof(value), "on");
                }
            }
        } else {
            /* found "foo=bar,more" */
            p = get_opt_name(option, sizeof(option), p, '=');
            if (*p != '=') {
                break;
            }
            p++;
            p = get_opt_value(value, sizeof(value), p);
        }
        if (strcmp(option, "id") != 0) {
            /* store and parse */
            if (qemu_opt_set(opts, option, value) == -1) {
                return -1;
            }
        }
        if (*p != ',') {
            break;
        }
    }
    return 0;
}

QemuOpts *qemu_opts_parse(QemuOptsList *list, const char *params,
                          int permit_abbrev)
{
    const char *firstname;
    char value[1024], *id = NULL;
    const char *p;
    QemuOpts *opts;

    assert(!permit_abbrev || list->implied_opt_name);
    firstname = permit_abbrev ? list->implied_opt_name : NULL;

    if (strncmp(params, "id=", 3) == 0) {
        get_opt_value(value, sizeof(value), params+3);
        id = value;
    } else if ((p = strstr(params, ",id=")) != NULL) {
        get_opt_value(value, sizeof(value), p+4);
        id = value;
    }
    opts = qemu_opts_create(list, id, 1);
    if (opts == NULL)
        return NULL;

    if (qemu_opts_do_parse(opts, params, firstname) != 0) {
        qemu_opts_del(opts);
        return NULL;
    }

    return opts;
}

/* Validate parsed opts against descriptions where no
 * descriptions were provided in the QemuOptsList.
 */
int qemu_opts_validate(QemuOpts *opts, const QemuOptDesc *desc)
{
    QemuOpt *opt;

    assert(opts->list->desc[0].name == NULL);

    QTAILQ_FOREACH(opt, &opts->head, next) {
        int i;

        for (i = 0; desc[i].name != NULL; i++) {
            if (strcmp(desc[i].name, opt->name) == 0) {
                break;
            }
        }
        if (desc[i].name == NULL) {
            printf("QERR_INVALID_PARAMETER, opt->name:%s\n", opt->name);
            return -1;
        }

        opt->desc = &desc[i];

        if (qemu_opt_parse(opt) < 0) {
            return -1;
        }
    }

    return 0;
}

int qemu_opts_foreach(QemuOptsList *list, qemu_opts_loopfunc func, void *opaque,
                      int abort_on_failure)
{
    QemuOpts *opts;
    int rc = 0;

    QTAILQ_FOREACH(opts, &list->head, next) {
        rc |= func(opts, opaque);
        if (abort_on_failure  &&  rc != 0)
            break;
    }
    return rc;
}

static QemuOptsList qemu_drive_opts = {
    .name = "drive",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_drive_opts.head),
    .desc = {
        {
            .name = "bus",
            .type = QEMU_OPT_NUMBER,
            .help = "bus number",
        },{
            .name = "unit",
            .type = QEMU_OPT_NUMBER,
            .help = "unit number (i.e. lun for scsi)",
        },{
            .name = "if",
            .type = QEMU_OPT_STRING,
            .help = "interface (ide, scsi, sd, mtd, floppy, pflash, virtio)",
        },{
            .name = "index",
            .type = QEMU_OPT_NUMBER,
            .help = "index number",
        },{
            .name = "cyls",
            .type = QEMU_OPT_NUMBER,
            .help = "number of cylinders (ide disk geometry)",
        },{
            .name = "heads",
            .type = QEMU_OPT_NUMBER,
            .help = "number of heads (ide disk geometry)",
        },{
            .name = "secs",
            .type = QEMU_OPT_NUMBER,
            .help = "number of sectors (ide disk geometry)",
        },{
            .name = "trans",
            .type = QEMU_OPT_STRING,
            .help = "chs translation (auto, lba. none)",
        },{
            .name = "media",
            .type = QEMU_OPT_STRING,
            .help = "media type (disk, cdrom)",
        },{
            .name = "snapshot",
            .type = QEMU_OPT_BOOL,
            .help = "enable/disable snapshot mode",
        },{
            .name = "file",
            .type = QEMU_OPT_STRING,
            .help = "disk image",
        },{
            .name = "cache",
            .type = QEMU_OPT_STRING,
            .help = "host cache usage (none, writeback, writethrough, "
                    "directsync, unsafe)",
        },{
            .name = "aio",
            .type = QEMU_OPT_STRING,
            .help = "host AIO implementation (threads, native)",
        },{
            .name = "format",
            .type = QEMU_OPT_STRING,
            .help = "disk format (raw, qcow2, ...)",
        },{
            .name = "serial",
            .type = QEMU_OPT_STRING,
            .help = "disk serial number",
        },{
            .name = "rerror",
            .type = QEMU_OPT_STRING,
            .help = "read error action",
        },{
            .name = "werror",
            .type = QEMU_OPT_STRING,
            .help = "write error action",
        },{
            .name = "addr",
            .type = QEMU_OPT_STRING,
            .help = "pci address (virtio only)",
        },{
            .name = "readonly",
            .type = QEMU_OPT_BOOL,
            .help = "open drive file as read-only",
        },
        { /* end of list */ }
    },
};


static QemuOptsList qemu_net_opts = {
    .name = "net",
    .implied_opt_name = "type",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_net_opts.head),
    .desc = {
        /*
         * no elements => accept any params
         * validation will happen later
         */
        { /* end of list */ }
    },
};

static QemuOptsList qemu_cpudef_opts = {
    .name = "cpudef",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_cpudef_opts.head),
    .desc = {
        {
            .name = "name",
            .type = QEMU_OPT_STRING,
        },{
            .name = "level",
            .type = QEMU_OPT_NUMBER,
        },{
            .name = "vendor",
            .type = QEMU_OPT_STRING,
        },{
            .name = "family",
            .type = QEMU_OPT_NUMBER,
        },{
            .name = "model",
            .type = QEMU_OPT_NUMBER,
        },{
            .name = "stepping",
            .type = QEMU_OPT_NUMBER,
        },{
            .name = "feature_edx",      /* cpuid 0000_0001.edx */
            .type = QEMU_OPT_STRING,
        },{
            .name = "feature_ecx",      /* cpuid 0000_0001.ecx */
            .type = QEMU_OPT_STRING,
        },{
            .name = "extfeature_edx",   /* cpuid 8000_0001.edx */
            .type = QEMU_OPT_STRING,
        },{
            .name = "extfeature_ecx",   /* cpuid 8000_0001.ecx */
            .type = QEMU_OPT_STRING,
        },{
            .name = "xlevel",
            .type = QEMU_OPT_NUMBER,
        },{
            .name = "model_id",
            .type = QEMU_OPT_STRING,
        },{
            .name = "vendor_override",
            .type = QEMU_OPT_NUMBER,
        },
        { /* end of list */ }
    },
};


QemuOptsList qemu_boot_opts = {
    .name = "boot-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_boot_opts.head),
    .desc = {
        /* the three names below are not used now */
        {
            .name = "order",
            .type = QEMU_OPT_STRING,
        }, {
            .name = "once",
            .type = QEMU_OPT_STRING,
        }, {
            .name = "menu",
            .type = QEMU_OPT_STRING,
        },
        { /*End of list */ }
    },
};

static QemuOptsList *vm_config_groups[32] = {
    &qemu_drive_opts,
    &qemu_net_opts,
    &qemu_cpudef_opts,
    NULL,
};


QemuOptsList *qemu_find_opts(const char *group)
{
    int i;
    QemuOptsList **lists = vm_config_groups;

    for (i = 0; lists[i] != NULL; i++) {
        if (strcmp(lists[i]->name, group) == 0)
            break;
    }
    if (lists[i] == NULL) {
        printf("there is no option group \"%s\"", group);
    }
    return lists[i];
}
