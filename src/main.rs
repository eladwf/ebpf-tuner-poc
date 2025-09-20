// src/main.rs
mod orchestrator; mod policy;
mod bpf; mod events; mod metrics; mod actions;
mod topology; mod bandit;
mod planner;
mod numa;
mod rate_limit;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tokio::{self, sync::Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum StrategyKind { Learned }

#[derive(Parser, Debug)]
struct Opts {
    #[arg(long, default_value_t=false)]
    no_cpuset: bool,
    #[arg(long)]
    log_json: Option<String>,
    #[arg(long, default_value_t = 0)]
    pid: i32,
    #[arg(long, value_enum, default_value_t = StrategyKind::Learned)]
    strategy: StrategyKind,
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,
    #[arg(long, default_value_t=true)]
    with_descendants: bool,
    #[arg(long, default_value_t=true)]
    follow_new: bool,
    #[arg(long, default_value_t=false)]
    attach_sockops: bool,
    #[arg(long, default_value_t=false)]
    dry_run: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    std::env::set_var("TUNER_PID", opts.pid.to_string());
    if let Some(ref p) = opts.log_json { std::env::set_var("AGENT_LOG_JSON", p); }
    if opts.no_cpuset { std::env::set_var("AGENT_NO_CPUSET", "1"); }
    if let Some(ref p) = opts.log_json { std::env::set_var("AGENT_LOG_JSON", p); }
    if opts.no_cpuset { std::env::set_var("AGENT_NO_CPUSET", "1"); }
    if opts.dry_run { std::env::set_var("AGENT_DRY_RUN", "1"); }

    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(4096);
    let bpf = crate::bpf::AgentBpf::load_and_attach(opts.pid, opts.with_descendants, opts.follow_new, opts.attach_sockops)?;
    let bpf = Arc::new(Mutex::new(bpf));
    let cancel = CancellationToken::new();
    let child_token = cancel.child_token();

    let poll_ms = std::env::var("AGENT_POLL_MS").ok()
        .and_then(|v| v.parse::<u64>().ok()).unwrap_or(10);
    spawn_ringbuf_poller(bpf.clone(), tx, child_token, Duration::from_millis(poll_ms));

    let strategy = match opts.strategy {
        StrategyKind::Learned => crate::policy::learned::LearnedStrategy::new(),
    };

    let mut orch = Orchestrator {
        bpf: bpf.clone(),
        strategy,
        interval: Duration::from_millis(opts.interval_ms as u64),
        log: None, 
        cancel: cancel.clone(),
        events: rx,
    };

    tokio::select! {
        res = orch.run() => res,
        _ = signal::ctrl_c() => {
            eprintln!("[main] Ctrl-C; shutting down...");
            cancel.cancel();
            Ok(())
        }
    }

}