// src/actions/mod.rs
use anyhow::Result;

pub mod affinity;
pub mod weight;
pub mod priority;
pub mod prefetch;

#[derive(Debug, Clone)]
pub enum Action {
    Prefetch(prefetch::PrefetchAction),
    // Existing:
    SetCpuset { cgroup: String, cpus: Vec<usize> },

    // New:
    SetCpuWeight { weight: u32 },
    SetNice { prio: i32 },
    SetIoPriority { class: i32, prio: i32 },
    SetSchedBatch { enable: bool },
    CompactWithinNUMA { node: Option<u32> },
    SpreadAcrossNUMA { width: usize },
}

pub struct Applier {
    pub cg: String,
    pub dry: bool,
}

impl Applier {
    pub fn apply_all(&self, acts: &[Action]) -> Result<()> {
        for a in acts {
            match a {
                Action::SetCpuset { cgroup, cpus } => {
                    let cg = if cgroup.is_empty() { &self.cg } else { cgroup };
                    affinity::apply_cpus_with_mems(cg, cpus)?;
                }
                Action::SetCpuWeight { weight } => {
                    weight::set_weight(&self.cg, *weight, self.dry)?;
                }
                Action::SetNice { prio } => {
                    priority::set_nice_for_cgroup(&self.cg, *prio)?;
                }
                Action::SetIoPriority { class, prio } => {
                    priority::set_ioprio_for_cgroup(&self.cg, *class, *prio)?;
                }
                Action::SetSchedBatch { enable } => {
                    priority::set_sched_batch_for_cgroup(&self.cg, *enable)?;
                }
                Action::CompactWithinNUMA { .. } | Action::SpreadAcrossNUMA { .. } => {}
                Action::Prefetch(a) => { prefetch::exec(a)?; }
            }
        }
        Ok(())
    }
}