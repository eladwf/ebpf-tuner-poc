// bpf/tuner.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include "common.h"

#ifndef FUTEX_SPIKE_US
#define FUTEX_SPIKE_US 5000
#endif

#ifndef EWMA_N
#define EWMA_N 8
#endif


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);            // tid
    __type(value, struct TaskStats);
} TID_STATS SEC(".maps");

struct Agg { __u64 futex_us; __u64 page_faults; };
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct Agg);
} AGG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // tid
    __type(value, __u64); // ts_ns
} FUTEX_TS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // tid
    __type(value, __u64); // ts_ns
} TID_WAKE_TS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} CFG_FOLLOW SEC(".maps");

static __always_inline bool cfg_follow_descendants(void)
{
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&CFG_FOLLOW, &k);
    return v && (*v != 0);
}

static __always_inline void agg_add(__u64 futex_us_delta, __u64 pf_delta) {
  __u32 k = 0;
  struct Agg *a = bpf_map_lookup_elem(&AGG, &k);
  if (!a) return;
  __sync_fetch_and_add(&a->futex_us, futex_us_delta);
  if (pf_delta) __sync_fetch_and_add(&a->page_faults, pf_delta);
}



static __always_inline __u64 ktime_ns(void)
{
    return bpf_ktime_get_ns();
}

static __always_inline __u64 ns_to_us(__u64 ns)
{
    return ns / 1000;
}

static __always_inline __u64 ns_to_us_round_up(__u64 ns)
{
    // 0..999ns -> 1us, etc.
    return (ns + 999) / 1000;
}


// EWMA with integer math
static __always_inline void ewma_update(__u64 *ewma_us, __u64 sample_us)
{
    __u64 old = *ewma_us;
    if (old == 0) {
        *ewma_us = sample_us;
        return;
    }
    // new = (old*(N-1) + sample)/N
    *ewma_us = (old * (EWMA_N - 1) + sample_us) / EWMA_N;
}

static __always_inline struct TaskStats *get_or_init_stats(__u32 tid)
{
    struct TaskStats *st = bpf_map_lookup_elem(&TID_STATS, &tid);
    if (!st) {
        struct TaskStats zero = {};
        bpf_map_update_elem(&TID_STATS, &tid, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&TID_STATS, &tid);
    }
    return st;
}


SEC("tp_btf/sched_waking")
int BPF_PROG(ev_sched_waking, struct task_struct *p)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 waker = (u32)id;
    u32 wakee = 0;
    if (!p) return 0;
    bpf_core_read(&wakee, sizeof(wakee), &p->pid);

    struct comm_event *e = bpf_ringbuf_reserve(&COMM_EVENTS, sizeof(*e), 0);
    if (!e) return 0;
    e->type = 1; e->pad = 0;
    e->wake.waker_tid = waker;
    e->wake.wakee_tid = wakee;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    __u32 next_tgid = BPF_CORE_READ(next, tgid);
    if (!is_target_tgid(next_tgid))
        return 0;

    __u32 next_tid = BPF_CORE_READ(next, pid);
    __u64 now = ktime_ns();

    __u64 *wts = bpf_map_lookup_elem(&TID_WAKE_TS, &next_tid);
    if (wts) {
        __u64 delay_ns = now - *wts;
        __u64 delay_us = ns_to_us(delay_ns);
        struct TaskStats *st = get_or_init_stats(next_tid);
        if (st) {
            ewma_update(&st->ewma_runq_us, delay_us);
            st->last_cpu = bpf_get_smp_processor_id();
        }
        bpf_map_delete_elem(&TID_WAKE_TS, &next_tid);
    }

    __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
    if (is_target_tgid(prev_tgid)) {
        __u32 prev_tid = BPF_CORE_READ(prev, pid);
        struct TaskStats *pst = bpf_map_lookup_elem(&TID_STATS, &prev_tid);
        if (pst && pst->last_oncpu_ts_ns != 0) {
            __u64 delta_us = ns_to_us(now - pst->last_oncpu_ts_ns);
            pst->total_oncpu_us += delta_us;
            pst->last_oncpu_ts_ns = 0;
        }
    }

    // Mark the start of on-CPU for next
    {
        struct TaskStats *nst = get_or_init_stats(next_tid);
        if (nst) nst->last_oncpu_ts_ns = now;
    }

    return 0;
}




// raw tracepoint: futex → (uaddr, tid, op)
SEC("raw_tracepoint/futex")
int ev_raw_futex(struct bpf_raw_tracepoint_args *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;

    struct comm_event *e = bpf_ringbuf_reserve(&COMM_EVENTS, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 2; e->pad = 0;
    e->futex.tid   = tid;
    e->futex.uaddr = (__u64)ctx->args[1];
    e->futex.op    = (__u32)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int tp_enter_futex(void *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid))
        return 0;

    __u32 tid = (__u32)pt;
    __u64 now = ktime_ns();
    bpf_map_update_elem(&FUTEX_TS, &tid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int tp_exit_futex(void *ctx) {
  __u64 pt = bpf_get_current_pid_tgid();
  __u32 tgid = pt >> 32;
  if (!is_target_tgid(tgid)) return 0;
  __u32 tid = (__u32)pt;
  __u64 *ts = bpf_map_lookup_elem(&FUTEX_TS, &tid);
  if (!ts) return 0;
  __u64 delta_us = ns_to_us_round_up(ktime_ns() - *ts);
  bpf_map_delete_elem(&FUTEX_TS, &tid);
  agg_add(delta_us, 0);
  return 0;
}


/* Some kernels use futex2 waitv */
SEC("tracepoint/syscalls/sys_enter_futex_waitv")
int tp_enter_futex_waitv(void *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid)) return 0;
    __u32 tid = (__u32)pt;
    __u64 now = ktime_ns();
    bpf_map_update_elem(&FUTEX_TS, &tid, &now, BPF_ANY);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_futex_waitv")
int tp_exit_futex_waitv(void *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid)) return 0;
    /* treat waitv like futex: use FUTEX_TS above */
    __u32 tid = (__u32)pt;
    __u64 *ts = bpf_map_lookup_elem(&FUTEX_TS, &tid);
    if (!ts) return 0;
    __u64 delta_us = ns_to_us_round_up(ktime_ns() - *ts);
    struct TaskStats *st = get_or_init_stats(tid);
    if (st) ewma_update(&st->ewma_futex_us, delta_us);
    bpf_map_delete_elem(&FUTEX_TS, &tid);
    return 0;
}

#if 0
/* Raw syscalls fallback: check syscall id for futex/futex_waitv */
#ifndef __NR_futex
#define __NR_futex 202
#endif
#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif

struct raw_enter { long id; long args[6]; };
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_raw_sys_enter(struct raw_enter *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid)) return 0;

    long id = ctx->id;
    if (id == __NR_futex || id == __NR_futex_waitv) {
        __u32 tid = (__u32)pt;
        __u64 now = ktime_ns();
        bpf_map_update_elem(&FUTEX_TS, &tid, &now, BPF_ANY);
    }
    return 0;
}

struct raw_exit { long id; long ret; };
SEC("tracepoint/raw_syscalls/sys_exit")
int tp_raw_sys_exit(struct raw_exit *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid)) return 0;

    long id = ctx->id;
    if (id == __NR_futex || id == __NR_futex_waitv) {
        __u32 tid = (__u32)pt;
        __u64 *ts = bpf_map_lookup_elem(&FUTEX_TS, &tid);
        if (!ts) return 0;
        __u64 delta_us = ns_to_us(ktime_ns() - *ts);
        struct TaskStats *st = get_or_init_stats(tid);
        if (st) ewma_update(&st->ewma_futex_us, delta_us);
        bpf_map_delete_elem(&FUTEX_TS, &tid);
    }
    return 0;
}
#endif

SEC("tracepoint/exceptions/page_fault_user")
int tp_pf_user(void *ctx)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = pt >> 32;
    if (!is_target_tgid(tgid))
        return 0;

    __u32 tid = (__u32)pt;
    struct TaskStats *st = get_or_init_stats(tid);
    if (st) {
        st->page_faults += 1;
    }
    return 0;
}

SEC("raw_tracepoint/page_fault_user")
int raw_pf_user(void *ctx) {
    return tp_pf_user(ctx);
}


SEC("tp_btf/sched_process_fork")
int BPF_PROG(tp_proc_fork, struct task_struct *parent, struct task_struct *child)
{
    if (!cfg_follow_descendants()) return 0;
    __u32 ptgid = BPF_CORE_READ(parent, tgid);
    if (!is_target_tgid(ptgid))
        return 0;

    __u32 ctgid = BPF_CORE_READ(child, tgid);
    __u8 one = 1;
    bpf_map_update_elem(&TARGET_TGIDS, &ctgid, &one, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(tp_proc_exit, struct task_struct *p)
{
    __u32 tgid = BPF_CORE_READ(p, tgid);
    bpf_map_delete_elem(&TARGET_TGIDS, &tgid);
    return 0;
}



struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} LLC_MISS SEC(".maps");

SEC("perf_event")
int on_llc_miss(struct bpf_perf_event_data *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 *v = bpf_map_lookup_elem(&LLC_MISS, &tgid);
    if (!v) { __u64 one = 1; bpf_map_update_elem(&LLC_MISS, &tgid, &one, BPF_ANY); }
    else    { (*v)++; }
    return 0;
}


struct io_pattern { __u64 last_sector; __u64 seq; __u64 rnd; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct io_pattern);
} IO_PAT SEC(".maps");

struct rq_complete_s { unsigned long long sector; };
SEC("tracepoint/block/block_rq_complete")
int on_rq_complete(struct rq_complete_s *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_pattern *p = bpf_map_lookup_elem(&IO_PAT, &tgid);
    if (!p) {
        struct io_pattern z = {}; z.last_sector = ctx->sector;
        bpf_map_update_elem(&IO_PAT, &tgid, &z, BPF_ANY);
        return 0;
    }
    __u64 sector = ctx->sector;
    __u64 delta = (sector > p->last_sector) ? (sector - p->last_sector) : (p->last_sector - sector);
    if (delta == 0 || delta < 64) p->seq++; else p->rnd++;
    p->last_sector = sector;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";