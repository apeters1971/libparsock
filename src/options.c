#include "parsock.h"

#include <string.h>

void ps_options_init(struct ps_options *opt)
{
    if (!opt)
        return;
    memset(opt, 0, sizeof(*opt));
    opt->scale_mode = PS_SCALE_FIXED;
    opt->min_sockets = 1;
    opt->max_sockets = 4;
    opt->initial_sockets = 4;
    opt->worker_threads = 0;
    opt->scale_interval_ms = 500;
    opt->min_transfer_size = 1ull << 20;
    opt->frame_size = 65536;
    opt->receive_window = 8ull << 20;
    opt->aead = PS_AEAD_AES_256_GCM;
    opt->min_protection = PS_PROTECTION_CONFIDENTIAL;
    opt->connect_timeout_ms = 10000;
    opt->io_timeout_ms = 120000;
    opt->max_poller_bytes = 2ull << 20;
    opt->max_poller_records = 32;
}

const char *ps_strerror(int err)
{
    switch (err) {
    case PS_OK: return "ok";
    case PS_ERR_INVAL: return "invalid argument";
    case PS_ERR_NOMEM: return "out of memory";
    case PS_ERR_TLS: return "TLS failure";
    case PS_ERR_PROTO: return "protocol error";
    case PS_ERR_CRYPTO: return "cryptographic failure";
    case PS_ERR_CLOSED: return "connection closed";
    case PS_ERR_FLOW: return "flow control violation";
    case PS_ERR_IO: return "I/O error";
    case PS_ERR_AGAIN: return "try again";
    case PS_ERR_AUTH: return "authentication failure";
    case PS_ERR_LIMIT: return "cryptographic usage limit";
    case PS_ERR_TIMEOUT: return "timed out";
    default: return "unknown error";
    }
}
