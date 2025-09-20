# ebpf-tuner-poc

**Status:** experimental / proof‑of‑concept

A small tuner agent for Linux that uses **eBPF** for low‑overhead telemetry and **Rust** for orchestration.  
The goal is to test whether a lightweight agent can *observe* key kernel signals (sched, futex, I/O) and *nudge*
workloads toward better behavior with simple policies. This is a POC — expect rough edges.

---

## What it is
- A **Rust** daemon (Tokio) that subscribes to a stream of kernel events and counters.
- A set of **eBPF programs** (CO‑RE via **libbpf‑rs**) that attach to common performance pain points:
  - `sched:*` tracepoints (e.g., context switches, wakeups) for run‑queue pressure and on‑CPU ratios
  - futex wait/wake sites for lock contention signals
  - optional net/blk hooks for bursts that correlate with tail latency (kernel‑version dependent)
- A **policy engine** that maps signals → safe “nudges”: change a cgroup weight, spread or pin threads, back off work on high PSI, etc.

**Not production.** The main point is to explore the shape of an “always‑on, low‑overhead” tuner.

---

## High‑level architecture
```
[eBPF programs]  ->  [ringbuf/perfbuf]  ->  [Rust Orchestrator]
         ^                                         |
         |                                         v
     [maps/counters]                        [Actions (effects)]
```

- **Metrics pipeline**
  - eBPF emits compact events (counts/timestamps) over ring buffers/maps.
  - The Rust side aggregates into rolling windows (EWMA, percentiles, simple burst detectors).
- **Strategies**
  - `HeuristicStrategy`: thresholded rules (“if run‑queue > N and PSI > X% → spread threads”).
  - `LearnedStrategy` (stub): placeholder for model‑driven decisions.
- **Actions**
  - `cpu_weight`: adjust cgroup CPU.weight to de‑prioritize noisy neighbors or raise weight on starved groups.
  - `cpuset_spread`: spread a target across CPUs to reduce same‑core contention.
  - `numa_rebalance`: nudge a workload toward a preferred NUMA node when cross‑node misses spike.
  - `pressure_backoff`: when PSI (memory/CPU) is high, gently reduce concurrency.
  - `io_prefetch` (stub): hook for read‑ahead / pre‑touch strategies.
- **Scopes**
  - target a **PID set** or an entire **cgroup v2** subtree.

---

## What works today
- Builds on recent Linux with BTF available.
- eBPF side compiled via Clang/LLVM (CO‑RE), loaded from Rust using **libbpf‑rs**.
- Sched + futex signals; simple aggregation in Rust; a handful of actions wired in.
- Dry‑run mode for audits (see below).

---

## Build
```bash
# from repo root
cargo build --release
```

If your environment lacks kernel headers/BTF, use your distro’s `-dbg`/`-dbgsym` or install `kernel-debuginfo`.

---

## Stack
- **Rust** orchestrator (Tokio, Serde).
- **eBPF** built as CO‑RE C and loaded with **libbpf‑rs**.
- Minimal dependencies; tries to keep hot paths lean.

---

## License
MIT for the POC code unless stated otherwise in subfolders.

---

## Disclaimer
This is an experiment. It may change direction or get torn apart and rebuilt.