// src/rate_limit.rs
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::io::Write;

use crate::actions::Action;
use crate::metrics::Snapshot;

pub struct TickScheduler;
impl TickScheduler {
    pub fn sleep_for_remainder(start: Instant, interval: Duration) {
        let elapsed = start.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }
    }
}

pub struct ActionGate {
    last: HashMap<String, Instant>,
    cooldown: Duration,
    idle_ticks: u32,
    idle_limit: u32,
    idle_us_per_thread: f64,
    last_reason: &'static str,
}

impl ActionGate {
    pub fn new(cooldown: Duration, idle_limit: u32, idle_us_per_thread: f64) -> Self {
        Self { last: HashMap::new(), cooldown, idle_ticks: 0, idle_limit, idle_us_per_thread, last_reason: "ok" }
    }

    pub fn filter(&mut self, snap: &Snapshot, actions: Vec<Action>) -> Vec<Action> {
        let total_load = snap.runq_ewma_us_mean + snap.futex_ewma_us_mean;
        let idle_thresh = self.idle_us_per_thread * (snap.threads.max(1) as f64);
        let psi_idle = if let Some(ref psi) = snap.psi {
            (psi.some_avg10 < 0.5) && (psi.full_avg10 < 0.1)
        } else { false };
        let idle_like = psi_idle && (total_load < idle_thresh);
        if idle_like { self.idle_ticks += 1; } else { self.idle_ticks = 0; }
        if self.idle_ticks >= self.idle_limit {
            self.last_reason = if psi_idle { "psi-idle" } else { "idle" };
            return Vec::new();
        }
        let now = Instant::now();
        let mut out = Vec::new();
        let mut dropped = false;
        for a in actions {
            let k = stable_key(&a);
            match self.last.get(&k) {
                Some(&ts) if now.duration_since(ts) < self.cooldown => { dropped = true; }                _ => { self.last.insert(k, now); out.push(a); }
            }
        }
        self.last_reason = if dropped { "cooldown" } else { "ok" };
        out
    }
    pub fn reason(&self) -> &'static str { self.last_reason }
}

pub(crate) fn stable_key(a: &Action) -> String {
    match a {
        Action::SetCpuset { cgroup, cpus } => format!("cpuset:{}:{:?}", cgroup, cpus),
        Action::SetCpuWeight { weight } => format!("cpuweight:{}", weight),
        Action::SetNice { prio } => format!("nice:{}", prio),
        Action::SetIoPriority { class, prio } => format!("ioprio:{}:{}", class, prio),
        Action::SetSchedBatch { enable } => format!("sched_batch:{}", enable),
        Action::CompactWithinNUMA { node } => format!("plan_compact:{:?}", node),
        Action::SpreadAcrossNUMA { width } => format!("plan_spread:{}", width),
        Action::Prefetch(prefetch_action) => format!("prefetch_action:{:?}", prefetch_action),
    }
}

pub fn log_tick(mut file: &std::fs::File, snap: &Snapshot, actions: &[Action], strat: &str, gate_reason: &str) {    use std::time::{SystemTime, UNIX_EPOCH};
    use std::io::Write;

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();

    let mut kinds: std::collections::HashMap<&'static str, usize> = std::collections::HashMap::new();
    for a in actions {
        let k = match a {
            Action::SetCpuset { .. } => "SetCpuset",
            Action::SetCpuWeight { .. } => "SetCpuWeight",
            Action::SetNice { .. } => "SetNice",
            Action::SetIoPriority { .. } => "SetIoPriority",
            Action::SetSchedBatch { .. } => "SetSchedBatch",
            Action::CompactWithinNUMA { .. } => "PlanCompact",
            Action::SpreadAcrossNUMA { .. } => "PlanSpread",
            Action::Prefetch(prefetch_action) => "Prefetch",
        };
        *kinds.entry(k).or_default() += 1;
    }
    let kinds_str = kinds
        .into_iter()
        .map(|(k, v)| format!("\"{}\":{}", k, v))
        .collect::<Vec<_>>()
        .join(",");

    let line = format!(
        r#"{{"ts":{}.{},"strategy":"{}","threads":{},"runq_ewma_us":{:.0},"futex_ewma_us":{:.0},"gate":"{}","actions":{{{}}}}}"#,

        ts.as_secs(),
        ts.subsec_nanos(),
        strat,
        snap.threads,
        snap.runq_ewma_us_mean,
        snap.futex_ewma_us_mean,
        gate_reason,
        kinds_str
    );

    let _ = file.write_all(line.as_bytes());
}