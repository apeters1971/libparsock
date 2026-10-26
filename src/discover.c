#define _GNU_SOURCE

#include "discover.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#if defined(__linux__)
#include <linux/tcp.h>
#endif

static void copy_name(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, cap, "%s", src);
}

static int same_addr(const struct sockaddr *a, const struct sockaddr *b)
{
    if (!a || !b || a->sa_family != b->sa_family)
        return 0;
    if (a->sa_family == AF_INET) {
        return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
               ((const struct sockaddr_in *)b)->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
                      &((const struct sockaddr_in6 *)b)->sin6_addr, 16) == 0;
    }
    return 0;
}

static void discover_iface(int fd, struct ps_hwinfo *out)
{
    struct sockaddr_storage local;
    socklen_t llen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &llen) != 0)
        return;
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return;
    for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !(ifa->ifa_flags & IFF_UP))
            continue;
        if (!same_addr(ifa->ifa_addr, (struct sockaddr *)&local))
            continue;
        copy_name(out->ifname, sizeof(out->ifname), ifa->ifa_name);
        break;
    }
    freeifaddrs(list);
    if (out->ifname[0] == '\0')
        return;

#if defined(__linux__)
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", out->ifname);
    FILE *f = fopen(path, "r");
    if (f) {
        long mbps = 0;
        if (fscanf(f, "%ld", &mbps) == 1 && mbps > 0)
            out->link_bps = (uint64_t)mbps * 1000000ull;
        fclose(f);
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", out->ifname);
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, "rx-", 3) == 0)
                out->rx_queues++;
            else if (strncmp(de->d_name, "tx-", 3) == 0)
                out->tx_queues++;
        }
        closedir(d);
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/numa_node", out->ifname);
    f = fopen(path, "r");
    if (f) {
        int node = -1;
        if (fscanf(f, "%d", &node) == 1)
            out->numa_node = node;
        fclose(f);
    }
#else
    (void)fd;
#endif
}

int ps_tcp_stats(int fd, uint32_t *rtt_us, uint64_t *retrans)
{
    if (rtt_us)
        *rtt_us = 0;
    if (retrans)
        *retrans = 0;
    if (fd < 0)
        return -1;
#if defined(__linux__)
    struct tcp_info info;
    socklen_t len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) != 0)
        return -1;
    if (rtt_us)
        *rtt_us = info.tcpi_rtt;
    if (retrans)
        *retrans = info.tcpi_total_retrans;
    return 0;
#elif defined(__APPLE__)
    struct tcp_connection_info info;
    socklen_t len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) != 0)
        return -1;
    if (rtt_us)
        *rtt_us = info.tcpi_rttcur * 1000u;
    if (retrans)
        *retrans = info.tcpi_txretransmitpackets;
    return 0;
#else
    (void)fd;
    return -1;
#endif
}

void ps_discover_fd(int fd, struct ps_hwinfo *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->numa_node = -1;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus > 0)
        out->cpus = (unsigned)cpus;
    if (fd >= 0) {
        discover_iface(fd, out);
        uint32_t rtt = 0;
        if (ps_tcp_stats(fd, &rtt, NULL) == 0)
            out->rtt_us = rtt;
    }
}

unsigned ps_suggest_sockets(const struct ps_hwinfo *hw, unsigned min_sockets,
                            unsigned max_sockets)
{
    unsigned min_s = min_sockets ? min_sockets : 1;
    unsigned max_s = max_sockets ? max_sockets : min_s;
    if (max_s < min_s)
        max_s = min_s;
    unsigned cap = max_s;
    if (hw && hw->cpus > 0 && hw->cpus < cap)
        cap = hw->cpus;
    if (hw && hw->rx_queues > 0 && hw->rx_queues < cap)
        cap = hw->rx_queues;
    if (cap < min_s)
        cap = min_s;
    unsigned start = 2;
    if (hw && hw->link_bps >= 200000000000ull)
        start = 4;
    else if (hw && hw->link_bps >= 100000000000ull)
        start = 2;
    if (start < min_s)
        start = min_s;
    if (start > cap)
        start = cap;
    if (start == 0)
        start = 1;
    return start;
}

uint64_t ps_bdp_bytes(uint64_t link_bps, uint32_t rtt_us)
{
    if (link_bps == 0 || rtt_us == 0)
        return 0;
    return (link_bps / 8ull) * (uint64_t)rtt_us / 1000000ull;
}
