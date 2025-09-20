// src/actions/affinity.rs
use anyhow::{Result, Context};
use std::{fs, path::Path};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;

fn cpus_to_mems(cpus: &[usize]) -> Result<String> {
    let mut nodes = vec![];
    for &cpu in cpus {
        let cpu_dir = format!("/sys/devices/system/cpu/cpu{}/", cpu);
        let mut found = None;
        if let Ok(entries) = fs::read_dir(cpu_dir) {
            for e in entries {
                if let Ok(e) = e {
                    if let Some(name) = e.file_name().to_str() {
                        if name.starts_with("node") {
                            if let Ok(n) = name.trim_start_matches("node").parse::<usize>() {
                                found = Some(n);
                                break;
                            }
                        }
                    }
                }
            }
        }
        if let Some(n) = found { nodes.push(n); }
    }
    nodes.sort_unstable(); nodes.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < nodes.len() {
        let start = nodes[i]; let mut j = i;
        while j+1 < nodes.len() && nodes[j+1] == nodes[j]+1 { j+=1; }
        if !out.is_empty() { out.push(','); }
        if j == i { out.push_str(&format!("{}", start)); }
        else { out.push_str(&format!("{}-{}", start, nodes[j])); }
        i = j+1;
    }
    if out.is_empty() { out.push('0'); }
    Ok(out)
}

pub fn set_affinity(pid: i32, cpus: &Vec<usize>) -> Result<()> {
    let mut set = CpuSet::new();
    for &c in cpus {
        set.set(c).context("cpuset bit")?;
    }
    sched_setaffinity(Pid::from_raw(pid), &set).context("sched_setaffinity")?;
    Ok(())
}

pub fn spread_across_llc(_pid: i32) -> Result<()> { Ok(()) }
pub fn compact_within_numa(_pid: i32) -> Result<()> { Ok(()) }

pub fn write_cpuset_paths(cg: &str, cpus: &str, mems: Option<&str>) -> Result<()> {
    let cpu_path = format!("{}/cpuset.cpus", cg);
    fs::write(&cpu_path, cpus).with_context(|| format!("write {}", cpu_path))?;
    let mems_path = format!("{}/cpuset.mems", cg);
    if Path::new(&mems_path).exists() {
        let mems = mems.map(|s| s.to_string()).unwrap_or_else(|| "0".to_string());
        fs::write(&mems_path, mems).with_context(|| format!("write {}", mems_path))?;
    }
    Ok(())
}

pub fn apply_cpus_with_mems(cg: &str, cpus: &[usize]) -> Result<()> {
    let cpus_str = crate::topology::to_cpuset_list(cpus);
    let mems_str = cpus_to_mems(cpus)?;
    match write_cpuset_paths(cg, &cpus_str, Some(&mems_str)) {
        Ok(_) => Ok(()),
        Err(err) => {
            let perm_denied = err.downcast_ref::<std::io::Error>()
                .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false);
            if perm_denied {
                eprintln!("[agent] cpuset write denied for {cg}; falling back to per-task sched_setaffinity");
                let procs_path = format!("{}/cgroup.procs", cg);
                if let Ok(list) = std::fs::read_to_string(&procs_path) {
                    let v = cpus.to_vec();
                    for line in list.lines() {
                        if let Ok(pid) = line.trim().parse::<i32>() {
                            let _ = set_affinity(pid, &v);
                        }
                    }
                }
                Ok(()) // best-effort
            } else {
                Err(err)
            }
        }
    }
}


pub fn apply_cpus_per_task(cg: &str, cpus: &[usize]) -> Result<()> {
    let procs_path = format!("{}/cgroup.procs", cg);
    let list = std::fs::read_to_string(&procs_path)?;
    let v = cpus.to_vec();
    for line in list.lines() {
        if let Ok(pid) = line.trim().parse::<i32>() {
            let _ = set_affinity(pid, &v);
        }
    }
    Ok(())
}