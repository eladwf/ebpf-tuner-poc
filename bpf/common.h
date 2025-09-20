// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


struct TaskStats {
    __u64 last_oncpu_ts_ns; /* last time this TID went on-CPU (ns) */
    __u64 ewma_runq_us;     /* wake -> on-CPU delay (EWMA, usec) */
    __u64 ewma_futex_us;    /* futex wait (EWMA, usec) */
    __u64 page_faults;      /* user faults (count) */
    __u64 total_oncpu_us;   /* accumulated on-CPU time (usec) */
    __u32 last_cpu;         /* last CPU seen */
};

struct tuner_event {
    __u32 pid;     /* TGID (userspace stores as pid) */
    __u32 kind;    /* event kind */
    __u64 val_us;  /* value in usec or generic payload */
    __u64 ts_ns;   /* timestamp */
};

struct comm_event {
    __u32 type; /* 1 = wake, 2 = futex */
    __u32 pad;
    union {
        struct { __u32 waker_tid; __u32 wakee_tid; } wake;
        struct { __u64 uaddr; __u32 tid; __u32 op; } futex;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} COMM_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   // tgid
    __type(value, __u8);  // 1
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} TARGET_TGIDS SEC(".maps");



static __always_inline bool is_target_tgid(__u32 tgid)
{
    __u8 *one = bpf_map_lookup_elem(&TARGET_TGIDS, &tgid);
    return one != NULL;
}


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} EVENTS SEC(".maps");

static __always_inline void emit_evt(__u32 tgid, __u32 kind, __u64 val_us)
{
    struct tuner_event *e = bpf_ringbuf_reserve(&EVENTS, sizeof(*e), 0);
    if (!e)
        return;
    e->pid   = tgid;            
    e->kind  = kind;
    e->val_us = val_us;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
}