#ifndef PARSOCK_LOG_H
#define PARSOCK_LOG_H

void ps_log_init(void);
void ps_log(const char *fmt, ...);
/* Printed on stderr even when PS_DEBUG is unset. Setup and failures only. */
void ps_notice(const char *fmt, ...);
void ps_note_error(int err);
int ps_recent_error(void);

#endif
