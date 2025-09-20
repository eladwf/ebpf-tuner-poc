// SPDX-License-Identifier: GPL-2.0
#include "common.h"

// Avoid including system linux headers to prevent clashes with vmlinux.h
// Define the minimal socket/TCP constants we need (from Linux UAPI)
#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_KEEPALIVE
#define SO_KEEPALIVE 9
#endif
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 4
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 5
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 6
#endif

char LICENSE[] SEC("license") = "GPL";

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
    int op = (int)skops->op;
    if (op != BPF_SOCK_OPS_TCP_CONNECT_CB &&
        op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;

    // Try to set BBR
    char cong[] = "bbr";
    bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong)-1);

    // Enable keepalive + tune timings
    int one = 1, idle = 30, intvl = 10, cnt = 6;
    bpf_setsockopt(skops, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    bpf_setsockopt(skops, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    bpf_setsockopt(skops, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    bpf_setsockopt(skops, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    return 0;
}