#include "log.h"

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

void ps_log(const char *fmt, ...)
{
    ps_log_init();
    if (!enabled)
        return;
    flockfile(stderr);
    fputs("libparsock: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}
