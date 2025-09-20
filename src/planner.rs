use crate::{actions::Action, metrics::Snapshot, numa};

pub fn lower_numa_plans(actions: Vec<Action>, snap: &Snapshot, pid: i32) -> Vec<Action> {
    use Action::*;
    let topo = match numa::cpu_topology() {
        Ok(t) => t,
        Err(_) => return actions,
    };
    let mut out = Vec::new();
    for a in actions {
        match a {
            CompactWithinNUMA { node } => {
                let sel = node.or_else(|| numa::dominant_node_for_pid(pid));
                if let Some(n) = sel {
                    let need = (snap.threads as usize).max(1).min(snap.total_cpus.max(1));
                let cpus = {
                    let per_node = topo.get(&n).map(|v| v.len()).unwrap_or(0);
                    let need = (snap.threads as usize).min(per_node.max(1));
                    numa::pick_compact(n, need, &topo)
                };
                }
            }
            SpreadAcrossNUMA { width } => {
                let k = width.max(1).min(snap.total_cpus.max(1));
                let cpus = numa::pick_spread(k, &topo);
                if !cpus.is_empty() {
                    out.push(SetCpuset { cgroup: String::new(), cpus });
                }
            }
            other => out.push(other),
        }
    }
    out
}