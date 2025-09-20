// src/orchestrator.rs
use anyhow::Result;
use crate::actions::Action;
use crate::bpf::{dump_target_tgids_fd};
use crate::{metrics::collect_snapshot, actions::Applier};
use crate::policy::Strategy;
use std::time::Instant;
use std::{fs::OpenOptions, fs::File, io::Write, time::{Duration, SystemTime, UNIX_EPOCH}};
use serde_json::{self, json};
use crate::metrics::{Event, Snapshot};
use std::{fs};
use crate::planner::lower_numa_plans;
use crate::rate_limit::{log_tick, ActionGate, TickScheduler};
pub struct Orchestrator<S: Strategy> { bpf: crate::bpf::AgentBpf, strategy: S, interval: std::time::Duration, log: Option<std::fs::File> }
use tokio::time::{interval, MissedTickBehavior};


fn cgv2_path_of_pid(pid: i32) -> String {
    let cgfile = format!("/proc/{}/cgroup", pid);
    if let Ok(s) = fs::read_to_string(&cgfile) {
        for line in s.lines() {
            if let Some(rest) = line.splitn(3, ':').nth(2) {
                return format!("/sys/fs/cgroup{}", rest.trim());
            }
        }
    }
    "/sys/fs/cgroup".to_string()
}
static mut LAST_DUMP: Option<std::time::Instant> = None;

impl<S: Strategy> Orchestrator<S> {
    pub fn new(bpf: crate::bpf::AgentBpf, strategy: S, interval_ms: u64) -> Self {
        let log = std::env::var("AGENT_LOG_JSON").ok().and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());

        Self { bpf, strategy, interval: std::time::Duration::from_millis(interval_ms), log }
    }
    pub async fn run(&mut self) -> Result<()> {
        let idle_per_thread = (self.interval.as_millis() as f64) * 1000.0 * 0.05;
        let mut gate = ActionGate::new(
            std::time::Duration::from_secs(5),
            6, 
            idle_per_thread,
        );
        let mut last_map_dump = Instant::now();
        let mut ticker = interval(self.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let start = std::time::Instant::now();
        let snap: Snapshot = tokio::task::spawn_blocking({
                let bpf_ptr = &self.bpf as *const _;
                move || unsafe { crate::metrics::collect_snapshot(&*bpf_ptr) }
            }).await??;
        let mut actions: Vec<Action> = self.strategy.tick(&snap);


        self.bpf.poll();

    
        for pevt in self.bpf.drain_prefetch_events() {
            let evt = Event::PrefetchFault {
                tgid:  pevt.tgid,
                dev:   pevt.sb_dev, 
                ino:   pevt.ino,
                pgoff: pevt.pgoff,
                ts_ns: pevt.ts_ns,
            };
            if let Some(a) = self.strategy.on_event(&evt) {
                actions.push(a);
            }
        }
        

        let dry = std::env::var("AGENT_DRY_RUN").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);

        let cg = cgv2_path_of_pid(snap.target_pid as i32);
        let applier = Applier { cg, dry };
        
        actions = lower_numa_plans(actions, &snap, snap.target_pid as i32);

        actions = gate.filter(&snap, actions);

        if dry {
            eprintln!("[dry-run] actions: {:?}", actions);
        } else {
            eprintln!("actions: {:?}", actions);
            applier.apply_all(&actions)?;
        }
        if let Some(mut file) = self.log.as_ref() {
            let kinds: Vec<String> = actions.iter().map(|a| crate::rate_limit::stable_key(a)).collect();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap();
            let line = json!({
                "ts": { "sec": ts.as_secs(), "nsec": ts.subsec_nanos() },
                "strategy": self.strategy.name(),
                "gate": gate.reason(),
                "snapshot": &snap,
                "actions": kinds
            });
            use std::io::Write;
            writeln!(file, "{}", serde_json::to_string(&line).unwrap()).ok();
        }

            let elapsed = start.elapsed();
            if elapsed < self.interval {
                ticker.tick().await;
            } else {
                while ticker.tick().await.elapsed() < self.interval {}
            }
        }
    }
}

