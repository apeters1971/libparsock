#include "rdma.h"

#include <stdio.h>

int main(void)
{
    int available = ps_rdma_available();
    if (available != 0 && available != 1) {
        fprintf(stderr, "rdma availability is not 0 or 1\n");
        return 1;
    }
    if (!available) {
        struct ps_rdma_cfg cfg;
        cfg.is_server = 1;
        cfg.device = NULL;
        cfg.send_depth = 16;
        cfg.recv_depth = 64;
        cfg.max_lanes = 1;
        cfg.message_bytes = 4096;
        uint16_t port = 0;
        if (ps_rdma_open(&cfg, &port) != NULL) {
            fprintf(stderr, "rdma open succeeded without a backend\n");
            return 1;
        }
        struct ps_device_mem mem;
        mem.type = PS_MEM_HOST;
        mem.ptr = &cfg;
        mem.length = sizeof(cfg);
        mem.dmabuf_fd = -1;
        mem.offset = 0;
        mem.internal_mr = NULL;
        if (ps_rdma_register_device_mem(NULL, &mem) != -PS_ERR_PROTO) {
            fprintf(stderr, "rdma reg device mem unexpectedly succeeded or wrong error\n");
            return 1;
        }
        if (ps_rdma_deregister_device_mem(NULL, &mem) != -PS_ERR_PROTO) {
            fprintf(stderr, "rdma dereg device mem unexpectedly succeeded or wrong error\n");
            return 1;
        }
        if (ps_rdma_reg_device_mem(NULL, &mem) != -PS_ERR_INVAL) {
            fprintf(stderr, "ps_rdma_reg_device_mem(NULL, ...) expected -PS_ERR_INVAL\n");
            return 1;
        }
        if (ps_rdma_dereg_device_mem(NULL, &mem) != -PS_ERR_INVAL) {
            fprintf(stderr, "ps_rdma_dereg_device_mem(NULL, ...) expected -PS_ERR_INVAL\n");
            return 1;
        }
        if (ps_recv_device(NULL, &mem, 10) != -PS_ERR_INVAL) {
            fprintf(stderr, "ps_recv_device(NULL, ...) expected -PS_ERR_INVAL\n");
            return 1;
        }
        if (ps_send_device(NULL, &mem, 10, PS_PROTECTION_AUTHENTICATED) != -PS_ERR_INVAL) {
            fprintf(stderr, "ps_send_device(NULL, ...) expected -PS_ERR_INVAL\n");
            return 1;
        }
    }
    printf("rdma %s\n", available ? "on" : "off");
    return 0;
}
