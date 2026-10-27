#include "log.h"

#include "parsock.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static int enabled = -1;

void ps_log_init(void)
{
    if (enabled >= 0)
        return;
    const char *e = getenv("PS_DEBUG");
    enabled = (e && e[0] != '\0' && e[0] != '0') ? 1 : 0;
}

static void write_line(const char *fmt, va_list ap)
{
    flockfile(stderr);
    fputs("libparsock: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}

void ps_log(const char *fmt, ...)
{
    ps_log_init();
    if (!enabled)
        return;
    va_list ap;
    va_start(ap, fmt);
    write_line(fmt, ap);
    va_end(ap);
}

void ps_notice(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    write_line(fmt, ap);
    va_end(ap);
}

static _Thread_local int recent_error;

void ps_note_error(int err)
{
    recent_error = err > 0 ? err : PS_ERR_IO;
}

int ps_recent_error(void)
{
    return recent_error > 0 ? recent_error : PS_ERR_IO;
}
