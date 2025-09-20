// src/policy/learned.rs

use crate::metrics::Event;
use crate::actions::prefetch::{PrefetchAction, PrefetchBackend};

use std::collections::{HashMap, VecDeque};

const LEARNED_DEBUG: bool = true;

#[derive(Default)]
struct SeqState { hist: VecDeque<u64> }

#[derive(Default)]
struct PrefetchModel {
    files: HashMap<(u32,u64,u64), SeqState>, // (tgid, dev, ino) -> history of pgoff
}

impl PrefetchModel {
    fn on_fault(&mut self, tgid: u32, dev: u64, ino: u64, pgoff: u64) -> Option<PrefetchAction> {
        let key = (tgid, dev, ino);
        let st = self.files.entry(key).or_default();
        if st.hist.len() >= 32 { st.hist.pop_front(); }
        st.hist.push_back(pgoff);
        // simple stride detection on last 6 deltas
        if st.hist.len() < 7 { return None; }
        let deltas: Vec<u64> = st.hist.iter().copied().collect::<Vec<_>>().windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        let n = deltas.len();
        let recent = &deltas[n-6..];
        let candidate = {
            let mut freq = std::collections::HashMap::<u64,usize>::new();
            for &d in recent { *freq.entry(d).or_default() += 1; }
            freq.into_iter().max_by_key(|(_,c)| *c).map(|(d,_)| d).unwrap_or(0)
        };
        if candidate == 0 { return None; }
        let agree = recent.iter().filter(|&&d| d == candidate).count();
        if agree < 5 { return None; } // strong agreement
        // Plan next 8 pages into 128KB chunks
        let page = 4096u64;
        let mut ranges = Vec::<(u64,u64)>::new();
        for k in 1..=8 {
            let off = (pgoff.wrapping_add(candidate*saturating_as_u64(k))) * page;
            // push 128KB per page predicted (coalesce later if needed)
            let len = 128*1024;
            ranges.push((off, len));
        }
        Some(PrefetchAction { tgid, dev, ino, ranges, backend: PrefetchBackend::Fadvise })
    }
}
fn saturating_as_u64(x: usize) -> u64 { x as u64 }

use crate::{actions::Action, metrics::Snapshot, bandit::LinUcb};
use super::Strategy;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct LearnedCfg {
    pub epsilon: f64,
    pub min_threads_for_numa: usize,
    pub allow_cpu_weight: bool,
    pub smooth_alpha: f64,
    pub enabled_arms: [bool; 5], // 0..=4


}

impl Default for LearnedCfg {
    fn default() -> Self {
        Self {
            epsilon: 0.05,
            min_threads_for_numa: 2,
            allow_cpu_weight: true,
            smooth_alpha: 0.2,
            enabled_arms: [true, true, true, true, true], // 0,3,4 enabled
        }
    }
}

pub struct Learned {
    prefetch: PrefetchModel,
    bandit: LinUcb,
    last_x: Option<Vec<f64>>,
    last_arm: Option<usize>,
    last_score: Option<f64>,
    sm_runq: f64,
    sm_futex: f64,
    cfg: LearnedCfg,
    last_switch: Option<Instant>,
    last_switch_score: Option<f64>,
    ticks_since_switch: u32,
    min_dwell: Duration,
    effect_delay_ticks: u32,
    // delayed credit queue
    pending: Vec<Pending>,
}

#[derive(Clone)]
struct Pending {
    arm: usize,
    x: Vec<f64>,
    due: u32,
    baseline: f64,
}

pub type LearnedStrategy = Learned;

impl Learned {
    pub fn new() -> Self {
             Self::with_cfg(LearnedCfg::default()) }

    pub fn with_cfg(cfg: LearnedCfg) -> Self {
           // prefetch: PrefetchModel::default(),
        // Arms: 0=Noop, 1=CpuWeight160, 2=Nice-1, 3=CompactNUMA, 4=SpreadNUMA
        let bandit = LinUcb::new(5, 4, 0.75);
        Self {
            prefetch: PrefetchModel::default(),
            bandit,
            last_x: None,
            last_arm: None,
            last_score: None,
            sm_runq: 0.0,
            sm_futex: 0.0,
            cfg,
            last_switch: None,
            last_switch_score: None,
            ticks_since_switch: 0,
            min_dwell: Duration::from_secs(5),
            effect_delay_ticks: 4,
            pending: Vec::new(),
        }
    }

    pub fn set_allow_cpu_weight(&mut self, allow: bool) { self.cfg.allow_cpu_weight = allow; }

    fn features(&self, s: &Snapshot) -> Vec<f64> {
        let runq = self.sm_runq.max(0.0);
        let futex = self.sm_futex.max(0.0);
        let total = (runq + futex).max(1.0);
        let fut_share = (futex / total).clamp(0.0, 1.0);
        let over = if s.total_cpus > 0 { (s.threads as f64)/(s.total_cpus as f64) } else { 0.0 };
        let over_n = over.clamp(0.0, 1.0);
        let runq_n = (runq / 1.0e5).clamp(0.0, 1.0);
        vec![1.0, runq_n, fut_share, over_n] // [bias, cpu pressure, futex mix, oversub]
    }

    fn score(runq: f64, futex: f64) -> f64 {
        let total = (runq + futex).max(1.0);
        let fut_share = (futex / total).clamp(0.0, 1.0);
        ((runq + 1.4*futex) / (total + 1.0)) + 0.1*fut_share
    }

    fn pick_actions_for_arm(&self, arm: usize, snap: &Snapshot) -> Vec<Action> {
        eprintln!("pick_actions_for_arm {}", arm);
        match arm {
            0 => Vec::new(), // Noop
            1 => vec![Action::SetCpuWeight { weight: 160 }],
            2 => vec![Action::SetNice { prio: -1 }],
            3 => vec![Action::CompactWithinNUMA { node: None }],
            4 => {
                let width = (snap.threads as usize).clamp(1, snap.total_cpus.max(1));
                vec![Action::SpreadAcrossNUMA { width }]
            }
            _ => Vec::new(),
        }
    }

    fn choose_arm(&self, x: &Vec<f64>, allowed: &[usize]) -> usize {
        if self.cfg.epsilon > 0.0 && !allowed.is_empty() {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let r = (nanos % 10_000) as f64 / 10_000.0;
            if r < self.cfg.epsilon {
                return allowed[(nanos as usize) % allowed.len()];
            }
        }
        self.bandit.select(x, Some(allowed))
    }
}

impl Strategy for Learned {
    fn tick(&mut self, snap: &Snapshot) -> Vec<Action> {
        let a = self.cfg.smooth_alpha;

        self.sm_runq = a * snap.runq_ewma_us_mean.max(0.0) + (1.0 - a) * self.sm_runq;
        self.sm_futex = a * snap.futex_ewma_us_mean.max(0.0) + (1.0 - a) * self.sm_futex;

        let (psi_some10, psi_full10) = if let Some(ref psi) = snap.psi {
            (psi.some_avg10 / 100.0, psi.full_avg10 / 100.0)
        } else { (0.0, 0.0) };

        let (psi_mem_some10, psi_mem_full10) = if let Some(ref m) = snap.psi_mem {
            (m.some_avg10 / 100.0, m.full_avg10 / 100.0)
        } else { (0.0, 0.0) };

        
        if LEARNED_DEBUG {
            eprintln!("[learned] sm_runq={:.1}us sm_futex={:.1}us psi: some10={:.3} full10={:.3} mem_some10={:.3} mem_full10={:.3}",
                self.sm_runq, self.sm_futex, psi_some10, psi_full10, psi_mem_some10, psi_mem_full10);
        }


        let current_score = Self::score(self.sm_runq, self.sm_futex)
            + 0.5 * psi_some10
            + 1.0 * psi_full10
            + 0.7 * psi_mem_some10    
            + 1.3 * psi_mem_full10;   

        for p in self.pending.iter_mut() {
            if p.due > 0 { p.due -= 1; }
        }
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].due == 0 {
               let base = self.pending[i].baseline;
                let improv = (base - current_score) / base.max(1.0);
                let reward = improv.clamp(-1.0, 1.0);
                let arm = self.pending[i].arm;
                let x = self.pending[i].x.clone();
                self.bandit.update(arm, &x, reward);
                self.pending.remove(i);
            } else {
                i += 1;
            }
        }

        let mut allowed: Vec<usize> = Vec::new();

        if self.cfg.enabled_arms[0] { allowed.push(0); }

        if self.cfg.enabled_arms[1] && self.cfg.allow_cpu_weight {
            allowed.push(1);
        }

        if self.cfg.enabled_arms[2] { allowed.push(2); }

        if snap.total_cpus >= 2 && snap.threads >= self.cfg.min_threads_for_numa {
            if self.cfg.enabled_arms[3] { allowed.push(3); }
            if self.cfg.enabled_arms[4] { allowed.push(4); }
        }

        if psi_mem_some10 > 0.005 || psi_mem_full10 > 0.0005 {
            allowed.retain(|&a| a != 4 /* SpreadAcrossNUMA */);
        }

        let now = Instant::now();
        if let Some(sw) = self.last_switch {
            if now.duration_since(sw) < self.min_dwell {
                let was_numa = matches!(self.last_arm, Some(3|4));
                if was_numa {
                    allowed.retain(|&a| a == 0 || matches!(a, 3|4));
                }
            }
        }

        if allowed.is_empty() { allowed.push(0); }
        if LEARNED_DEBUG { eprintln!("[learned] allowed initial = {:?}", allowed); }
        if allowed.len() == 1 && allowed[0] == 0 {
            if self.cfg.enabled_arms[1] && self.cfg.allow_cpu_weight && !allowed.contains(&1) {
                allowed.push(1);
                if LEARNED_DEBUG { eprintln!("[learned] fallback: added CpuWeight"); }
            } else if self.cfg.enabled_arms[2] && !allowed.contains(&2) {
                allowed.push(2);
                if LEARNED_DEBUG { eprintln!("[learned] fallback: added Nice-1"); }
            }
        }
        if LEARNED_DEBUG { eprintln!("[learned] allowed final = {:?}", allowed); }

        let x = self.features(snap);
        if psi_some10 < 0.002 && psi_full10 < 0.0005 &&
           psi_mem_some10 < 0.002 && psi_mem_full10 < 0.0005 &&
           (self.sm_runq + self.sm_futex) < 200.0 
        {
            eprintln!("[learned] idle-guard: psi_some10={:.4} psi_full10={:.4} mem_some10={:.4} mem_full10={:.4} runq+futex={:.1} => no action", psi_some10, psi_full10, psi_mem_some10, psi_mem_full10, self.sm_runq + self.sm_futex);
                        return Vec::new();
        }
        if LEARNED_DEBUG { eprintln!("[learned] x={:?} allowed={:?}", x, allowed); }
        let arm = self.choose_arm(&x, &allowed);
        self.last_arm = Some(arm);
        if LEARNED_DEBUG { eprintln!("[learned] chose arm {}", arm); }
        self.last_x = Some(x);
        self.last_score = Some(Self::score(self.sm_runq, self.sm_futex));

        if arm != 0 {
            self.pending.push(Pending { arm, x: self.last_x.clone().unwrap(), due: self.effect_delay_ticks, baseline: current_score });
        }

        if matches!(arm, 3|4) && !matches!(self.last_arm, Some(a) if a==arm) {
            self.last_switch = Some(now);
            self.last_switch_score = Some(current_score);
            self.ticks_since_switch = 0;
        } else {
            self.ticks_since_switch = self.ticks_since_switch.saturating_add(1);
        }

        self.pick_actions_for_arm(arm, snap)
    }
    fn on_event(&mut self, evt: &crate::metrics::Event) -> Option<crate::actions::Action> {
        if LEARNED_DEBUG { eprintln!("[learned] on_event"); }
        if let crate::metrics::Event::PrefetchFault { tgid, dev, ino, pgoff, ts_ns } = *evt { if LEARNED_DEBUG { eprintln!("[learned] prefetch fault tgid={} dev={} ino={} pgoff={} ts={}", tgid, dev, ino, pgoff, ts_ns); }
            if let Some(a) = self.prefetch.on_fault(tgid, dev, ino, pgoff) {
                return Some(crate::actions::Action::Prefetch(a));
            }
        }
        None
    }
    fn name(&self) -> &'static str { "learned" }
}

