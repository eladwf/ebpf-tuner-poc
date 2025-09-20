// src/metrics.rs
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use std::path::{Path};
use serde::Serialize;


#[derive(Clone, Debug, Default, Serialize)]
pub struct Psi{
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub some_total_us: u64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
    pub full_total_us: u64,
    pub scope: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Config {
    pub llc_spread_threshold: f64,
    pub runq_compact_cutoff: f64,
    pub runq_compact_cutoff_high: f64,
    pub min_switch_interval_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct IoSnapshot {
    pub dev: String,
    pub seq_ratio: f64,
}


#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub target_pid: i32,
    pub threads: usize,
    pub runq_ewma_us_mean: f64,
    pub futex_ewma_us_mean: f64,
    pub page_faults_sum: u64,
    pub llc_delta_per_thread: f64,
    pub io: Option<IoSnapshot>,
    pub total_cpus: usize,
    pub comm_wake: u64,
    pub comm_futex: u64,
    pub spikes: u64,
    pub config: Config,
    pub psi: Option<Psi>,
    pub psi_mem: Option<Psi>,
}

#[derive(Clone, Debug)]
pub enum Event {
    PrefetchFault { tgid: u32, dev: u64, ino: u64, pgoff: u64, ts_ns: u64 },
    FutexSpike { us: u64 },
}

static mut PREV_SCHED: Option<HashMap<i32,(u64,u64)>> = None;
static mut EWMA_RUNQ: Option<f64> = None;
static mut EWMA_FUTEX: Option<f64> = None;
static mut PREV_FAULTS: Option<HashMap<i32,u64>> = None;
static mut LAST_SAMPLE: Option<Instant> = None;

fn update_futex_ewma(futex_us_now: f64) -> f64 {
    unsafe {
        let ew = EWMA_FUTEX.get_or_insert(0.0);
        *ew = 0.7 * *ew + 0.3 * futex_us_now;
        *ew
    }
}


fn read_psi_cpu(cgroup_path: Option<&Path>) -> Option<Psi> {
    let (path, scope) = if let Some(cg) = cgroup_path {
        let p = cg.join("cpu.pressure");
        if p.exists() { (p, "cgroup") } else { (PathBuf::from("/proc/pressure/cpu"), "system") }
    } else {
        (PathBuf::from("/proc/pressure/cpu"), "system")
   };
    let text = fs::read_to_string(&path).ok()?;

    let mut out = Psi::default();
    out.scope = scope;
    for line in text.lines() {
        let mut avg10 = 0.0;
        let mut avg60 = 0.0;
        let mut avg300 = 0.0;
        let mut total: u64 = 0;
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }
        let kind = parts[0];
       for p in &parts[1..] {
            if let Some(v) = p.strip_prefix("avg10=") { avg10 = v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("avg60=") { avg60 = v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("avg300="){ avg300= v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("total="){ total = v.parse().unwrap_or(0); }
        }
        match kind {
            "some" => { out.some_avg10=avg10; out.some_avg60=avg60; out.some_avg300=avg300; out.some_total_us=total; }
            "full" => { out.full_avg10=avg10; out.full_avg60=avg60; out.full_avg300=avg300; out.full_total_us=total; }
            _ => {}
        }
    }
    Some(out)
}

fn read_psi_mem(cgroup_path: Option<&Path>) -> Option<Psi> {
    let (path, scope) = if let Some(cg) = cgroup_path {
        let p = cg.join("memory.pressure");
        if p.exists() { (p, "cgroup") } else { (PathBuf::from("/proc/pressure/memory"), "system") }
    } else {
        (PathBuf::from("/proc/pressure/memory"), "system")
    };
    let text = fs::read_to_string(&path).ok()?;
    let mut out = Psi::default();
    out.scope = scope;
    for line in text.lines() {
       let mut avg10 = 0.0;
        let mut avg60 = 0.0;
        let mut avg300 = 0.0;
        let mut total: u64 = 0;
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }
        let kind = parts[0];
        for p in &parts[1..] {
            if let Some(v) = p.strip_prefix("avg10=") { avg10 = v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("avg60=") { avg60 = v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("avg300="){ avg300= v.parse().unwrap_or(0.0); }
            if let Some(v) = p.strip_prefix("total="){ total = v.parse().unwrap_or(0); }
        }
        match kind {
            "some" => { out.some_avg10=avg10; out.some_avg60=avg60; out.some_avg300=avg300; out.some_total_us=total; }
            "full" => { out.full_avg10=avg10; out.full_avg60=avg60; out.full_avg300=avg300; out.full_total_us=total; }
            _ => {}
        }
    }
    Some(out)
}

fn read_online_cpus() -> usize {
    if let Ok(s) = fs::read_to_string("/sys/devices/system/cpu/online") {
        let mut count = 0usize;
        for part in s.trim().split(',') {
            if let Some((a,b)) = part.split_once('-') {
                if let (Ok(a),Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) { count += b.saturating_sub(a)+1; }
            } else if !part.is_empty() { count += 1; }
        }
        return count.max(1);
    }
    num_cpus::get()
}

fn list_tids(pid: i32) -> Vec<i32> {
    let mut tids = Vec::new();
    let p = format!("/proc/{}/task", pid);
    if let Ok(rd) = fs::read_dir(p) {
        for e in rd.flatten() {
            if let Ok(s) = e.file_name().into_string() {
                if let Ok(t) = s.parse::<i32>() { tids.push(t); }
            }
        }
    }
    tids
}

fn read_tid_schedstat(pid: i32, tid: i32) -> Option<(u64,u64)> {
    let p = PathBuf::from(format!("/proc/{}/task/{}/schedstat", pid, tid));
    let s = fs::read_to_string(p).ok()?;
    let mut it = s.split_whitespace();
    let run_ns = it.next()?.parse::<u64>().ok()?;   
    let runq_ns = it.next()?.parse::<u64>().ok()?; 
    Some((run_ns, runq_ns))
}

fn read_tid_minflt(pid: i32, tid: i32) -> Option<u64> {
    let p = PathBuf::from(format!("/proc/{}/task/{}/stat", pid, tid));
    let s = fs::read_to_string(p).ok()?;
    let fields: Vec<&str> = s.split_whitespace().collect();
    if fields.len() > 11 {
        fields[9].parse::<u64>().ok() 
    } else { None }
}

fn read_psi(path: &str) -> f64 {
    if let Ok(s) = fs::read_to_string(path) {
        for line in s.lines() {
            let line = line.trim();
            if !line.starts_with("some ") { continue; }
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("avg10=") {
                    return v.parse::<f64>().unwrap_or(0.0);
                }
            }
        }
    }
    0.0
}

pub fn collect_snapshot(bpf: &crate::bpf::AgentBpf) -> Result<Snapshot> {
    let target_pid = std::env::var("TUNER_PID").ok().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    let tids = if target_pid > 0 { list_tids(target_pid) } else { Vec::new() };
    let threads = tids.len();

    let now = Instant::now();
    let dt_ms = unsafe {
        let dt = LAST_SAMPLE.map(|t| now.duration_since(t).as_millis() as u64).unwrap_or(500);
        LAST_SAMPLE = Some(now);
        dt
    }.max(1);

    let mut runq_us_sum_delta = 0u64;
    let mut faults_sum = 0u64;
    let psi = read_psi_cpu(None);
    let psi_mem = read_psi_mem(None);
    let mut current: HashMap<i32,(u64,u64)> = HashMap::new();
    for &tid in &tids {
        if let Some((run_ns, runq_ns)) = read_tid_schedstat(target_pid, tid) {
            current.insert(tid, (run_ns, runq_ns));
        }
        if let Some(mf) = read_tid_minflt(target_pid, tid) { faults_sum = faults_sum.saturating_add(mf); }
    }

    unsafe {
        if PREV_SCHED.is_none() { PREV_SCHED = Some(current.clone()); }
        if PREV_FAULTS.is_none() {
            let mut f = HashMap::new();
            for &tid in &tids {
                if let Some(mf) = read_tid_minflt(target_pid, tid) { f.insert(tid, mf); }
            }
            PREV_FAULTS = Some(f);
        }
    }

    unsafe {
        if let Some(prev) = PREV_SCHED.as_ref() {
            for (&tid, &(run_ns, runq_ns)) in &current {
                if let Some((prun, prunq)) = prev.get(&tid) {
                    let d_runq = runq_ns.saturating_sub(*prunq);
                    runq_us_sum_delta = runq_us_sum_delta.saturating_add(d_runq / 1000);
                }
            }
        }
        PREV_SCHED = Some(current);
    }

    let agg = bpf.read_and_reset_agg();
    let futex_us_now = agg.futex_us as f64;
    let futex_ewma_total = update_futex_ewma(futex_us_now);
    let futex_ewma_us_mean = futex_ewma_total / (threads.max(1) as f64);

    let runq_ewma_us_mean = unsafe {
        let ew = EWMA_RUNQ.get_or_insert(0.0);
        let runq_per_tick = runq_us_sum_delta as f64 / (threads.max(1) as f64);
        *ew = 0.6*(*ew) + 0.4*runq_per_tick;
        *ew
    };

    let page_faults_sum = faults_sum;


    Ok(Snapshot {
        target_pid,
        threads,
        runq_ewma_us_mean,
        futex_ewma_us_mean,
        page_faults_sum,
        llc_delta_per_thread: {
            let llc = bpf.read_llc_for_pid(target_pid as u32) as f64;
            if threads > 0 { llc / threads as f64 } else { 0.0 }
        },
        io: detect_io_dev(target_pid).and_then(|dev| {
            let (seq,rnd) = bpf.read_io_pattern_for_pid(target_pid as u32);
            let total = (seq + rnd) as f64;
            let ratio = if total > 0.0 { (seq as f64)/total } else { 0.0 };
            Some(IoSnapshot { dev, seq_ratio: ratio })
        }),
        total_cpus: read_online_cpus(),
        comm_wake: bpf.read_comm_wake(),
        comm_futex: futex_us_now as u64,
        spikes: bpf.read_spikes(),
        config: Config {
            llc_spread_threshold: 1000.0,
            runq_compact_cutoff: 0.3,
            runq_compact_cutoff_high: 0.7,
            min_switch_interval_ms: 1200,
        },
        psi: psi,
        psi_mem: psi_mem
    })
}


fn detect_io_dev(pid: i32) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    use std::fs;
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut majmin: Option<(u64,u64)> = None;
    if let Ok(rd) = fs::read_dir(fd_dir) {
        for e in rd.flatten() {
            if let Ok(path) = fs::read_link(e.path()) {
                let meta = fs::metadata(&path).ok()?;
                let rdev = meta.rdev();
                let major = (rdev >> 8) & 0xfff;
                let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
                if major > 0 {
                    majmin = Some((major, minor));
                    break;
                }
            }
        }
    }
    let (maj, min) = majmin?;
    let bb = format!("/sys/dev/block/{}:{}", maj, min);
    if let Ok(name) = fs::read_link(&bb) {
        if let Some(dev) = name.file_name().and_then(|s| s.to_str()) {
            return Some(dev.to_string());
        }
    }
    None
}