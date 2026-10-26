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
    }
    printf("rdma %s\n", available ? "on" : "off");
    return 0;
}
