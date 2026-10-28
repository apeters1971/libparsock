#include "parsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    printf("test_gpu: checking device memory API structures and fallback semantics\n");

    struct ps_device_mem mem;
    memset(&mem, 0, sizeof(mem));
    mem.type = PS_MEM_CUDA;
    mem.ptr = (void *)0x1000;
    mem.length = 1048576;
    mem.dmabuf_fd = -1;
    mem.offset = 0;
    mem.internal_mr = NULL;

    if (mem.type != PS_MEM_CUDA) {
        fprintf(stderr, "fail: mem type mismatch\n");
        return 1;
    }

    /* Validations against NULL connection */
    if (ps_rdma_reg_device_mem(NULL, &mem) != -PS_ERR_INVAL) {
        fprintf(stderr, "fail: ps_rdma_reg_device_mem(NULL) should return -PS_ERR_INVAL\n");
        return 1;
    }

    if (ps_rdma_dereg_device_mem(NULL, &mem) != -PS_ERR_INVAL) {
        fprintf(stderr, "fail: ps_rdma_dereg_device_mem(NULL) should return -PS_ERR_INVAL\n");
        return 1;
    }

    if (ps_recv_device(NULL, &mem, 1024) != -PS_ERR_INVAL) {
        fprintf(stderr, "fail: ps_recv_device(NULL) should return -PS_ERR_INVAL\n");
        return 1;
    }

    if (ps_send_device(NULL, &mem, 1024, PS_PROTECTION_AUTHENTICATED) != -PS_ERR_INVAL) {
        fprintf(stderr, "fail: ps_send_device(NULL) should return -PS_ERR_INVAL\n");
        return 1;
    }

    printf("test_gpu: pass\n");
    return 0;
}
