# [SPT Extension RFC] GPUDirect RDMA & Device Memory Support for libparsocket

**Project:** libparsocket  
**Protocol:** Secure Parallel Transport (SPT/0.1)  
**Extension:** GPUDirect RDMA (GDR) & Device Memory Subsystem  
**Target Architecture:** NVIDIA CUDA (GPUDirect RDMA via `nvidia-peermem`), AMD ROCm (`amdgpu` KFD), Linux DMA-BUF  
**Integration Clients:** XIOFS (`xiofsd`, `xiofscli`), NIXL Storage Plugin, cuFile (GDS)  
**Status:** Design Specification & Implementation Roadmap  

---

## 1. Executive Summary

At 200–800 Gbps network line rates, copying data through CPU DRAM and host L3 caches creates a severe throughput bottleneck and starves CPU cores. For AI training, inference (e.g., vLLM, TensorRT-LLM weight streaming), and high-energy physics analysis workflows, storage data must land directly in GPU High Bandwidth Memory (HBM/VRAM).

`libparsocket` already separates the logical ordered byte stream from its underlying transport backends (parallel TCP, RDMA RC, and QUIC). This document specifies the additions required in `libparsocket` to enable **zero-copy GPUDirect RDMA** transfers directly into and out of GPU device memory.

---

## 2. Architecture Overview

### Current Host-Only Data Path (Two Memory Bounces):
```
[ NIC Hardware ]
       │  (PCIe DMA)
       ▼
[ Host CPU RAM ] ──(copy via ps_recv)──► [ Userspace Buffer ] ──(cudaMemcpy)──► [ GPU VRAM ]
```

### GPUDirect RDMA Data Path (Zero Bounce):
```
[ NIC Hardware ]
       │
       │  (PCIe Peer-to-Peer DMA via nvidia-peermem / KFD)
       ▼
[ GPU VRAM (cudaMalloc) ] ◄── Verified by CPU via HMAC-SHA-256 header tags
```

---

## 3. Core Requirements & Obstacles

### 3.1 Memory Registration with Peer Memory
Standard `ibv_reg_mr()` only accepts host virtual addresses unless a peer memory client is registered in the kernel:
- **NVIDIA:** Requires the `nvidia-peermem` kernel module. Once loaded, `ibv_reg_mr(pd, gpu_ptr, length, access)` succeeds transparently on pointers allocated via `cudaMalloc()` or `cuMemAlloc()`.
- **AMD:** Handled via ROCm KFD peer memory driver.
- **Alignment:** GPU memory allocations registered with InfiniBand/RoCE verbs must be aligned to GPU page granularity (typically 64 KiB or 2 MiB).

### 3.2 Crypto & Protection Mode Compatibility
- AES-GCM (used in `PS_PROTECTION_CONFIDENTIAL`) requires CPU instructions (`VAES`, `VPCLMULQDQ`) to decrypt ciphertext. Decrypting data in GPU VRAM requires either reading it across PCIe back to the CPU (defeating zero-copy) or writing GPU CUDA decrypt kernels.
- **Solution:** Use **`PS_PROTECTION_AUTHENTICATED`** mode.
  - HTTP/2 request headers, authorization tokens, and metadata are sent confidentially via TLS 1.3 / AEAD over the control connection or confidential records.
  - Bulk file payloads (HTTP/2 `DATA` frames) are transmitted in plaintext protected by HMAC-SHA-256 (or RDMA ICRC/RoCE transport integrity).
  - The RDMA NIC DMAs the payload directly into GPU VRAM. The CPU only processes record headers and tag validation.

---

## 4. API Additions in `include/parsock.h`

Add memory registration, buffer descriptors, and device-aware I/O functions:

```c
/* ========================================================================= */
/* Device Memory (GPU / DMA-BUF) Extensions                                 */
/* ========================================================================= */

typedef enum {
    PS_MEM_HOST = 0,
    PS_MEM_CUDA = 1,      /* NVIDIA CUDA device pointer */
    PS_MEM_ROCM = 2,      /* AMD ROCm / HIP device pointer */
    PS_MEM_DMABUF = 3     /* Linux DMA-BUF file descriptor */
} ps_mem_type_t;

struct ps_device_mem {
    ps_mem_type_t type;
    void         *ptr;         /* GPU virtual address */
    int           dmabuf_fd;   /* FD if type == PS_MEM_DMABUF, else -1 */
    size_t        length;
    uint64_t      offset;
    void         *internal_mr; /* Opaque struct ibv_mr* cache */
};

/* Explicitly register a GPU memory region with the RDMA protection domain.
 * Caches the struct ibv_mr so repeated reads/writes avoid registration latency. */
int ps_rdma_reg_device_mem(ps_connection_t *conn, struct ps_device_mem *mem);

/* Deregister a previously registered GPU memory region. */
int ps_rdma_dereg_device_mem(ps_connection_t *conn, struct ps_device_mem *mem);

/* Receive incoming stream data directly into registered GPU memory.
 * Returns bytes received, or negative -PS_ERR_* code. */
ssize_t ps_recv_device(ps_connection_t *conn, struct ps_device_mem *dest, size_t length);

/* Transmit data directly from registered GPU memory. */
ssize_t ps_send_device(ps_connection_t *conn, const struct ps_device_mem *src, size_t length,
                       ps_protection_t protection);
```

---

## 5. Implementation Instructions for `src/rdma.c`

### Step 1: Detect GPUDirect Capability
In `src/rdma.c`, add a check during device opening to confirm peer-to-peer DMA support:
```c
static int check_gdr_support(struct ibv_context *ctx)
{
    /* Check if experimental or standard GDR attributes are supported */
    struct ibv_device_attr attr;
    if (ibv_query_device(ctx, &attr) != 0)
        return 0;
    /* On Linux, verify /sys/kernel/mm/memory_peers/nv_mem exists */
    return access("/sys/kernel/mm/memory_peers/nv_mem", F_OK) == 0 ? 1 : 0;
}
```

### Step 2: Implement GPU Memory Registration
Add `ps_rdma_reg_device_mem`:
```c
int ps_rdma_reg_device_mem(ps_connection_t *conn, struct ps_device_mem *mem)
{
    if (!conn || !mem || !mem->ptr || mem->length == 0)
        return -PS_ERR_INVAL;

    struct ps_session *s = conn->session;
    struct ps_rdma *r = s->rdma;
    if (!r || !r->pd)
        return -PS_ERR_PROTO;

    int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    struct ibv_mr *mr = ibv_reg_mr(r->pd, mem->ptr, mem->length, access);
    if (!mr) {
        ps_notice("GPU ibv_reg_mr failed: %s (ptr=%p len=%zu)", strerror(errno), mem->ptr, mem->length);
        return -PS_ERR_IO;
    }

    mem->internal_mr = mr;
    return PS_OK;
}
```

### Step 3: Zero-Copy SGE Posting for Receive
In `src/rdma.c`, modify `post_recv_slot`:
- Support custom scatter/gather elements (`struct ibv_sge`) pointing directly to `mem->internal_mr->lkey` and `dest->ptr`.
- When `ps_recv_device` is called, route the RDMA RC SEND/RECV queue pair directly into the GPU SGE instead of the intermediate host bounce buffer.

### Step 4: Tag Authentication on CPU
For incoming records with `PS_PROTECTION_AUTHENTICATED`:
1. Receive the 40-byte record header and 16-byte HMAC tag into a small host bounce buffer.
2. The payload bytes land directly in GPU VRAM via peer-to-peer PCIe DMA.
3. Compute or validate the HMAC-SHA-256 tag over the header and sequence state to verify message authenticity without copying or mutating the payload.

---

## 6. How Clients Hook Into This

### 6.1 NIXL (NVIDIA Inference Xfer Layer) Storage Plugin
NIXL storage plugins load weights and KV caches directly into VRAM:
1. NIXL initializes the storage client with an `spt://` or `parsock://` endpoint.
2. NIXL pre-allocates GPU memory via `cudaMalloc(&gpu_buf, len)`.
3. The plugin calls `ps_rdma_reg_device_mem(&dev_mem)`.
4. The plugin issues an HTTP/2 `Range GET` request over `XioHttp2`.
5. Incoming HTTP/2 `DATA` frames are streamed directly into `gpu_buf` via `ps_recv_device()`.

### 6.2 XIOFS Userspace FUSE / cuFile Integration
1. Extend `XioClient::read_gpu(path, offset, length, void *gpu_ptr)`.
2. Map file offsets directly to HTTP/2 Range headers.
3. Stream data over parsocket RDMA directly into `gpu_ptr`.

---

## 7. Verification Plan

1. **Unit Test (`tests/test_gpu.c`):**
   - Allocate GPU buffer via `cudaMalloc`.
   - Call `ps_rdma_reg_device_mem()`.
   - Perform a round-trip loopback send/recv over `PS_TRANSPORT_RDMA_RC`.
   - Run a CUDA kernel or `cudaMemcpy` back to host to assert pattern integrity.
2. **Integration Test with XrdHttp2:**
   - Server runs on host with an RDMA-capable NIC (`http.parsock transport rdma`).
   - Client requests a 1 GB file using `xiofscli` directly into GPU memory.
   - Verify zero host-DRAM memory copy overhead and GPU memory pattern correctness.
