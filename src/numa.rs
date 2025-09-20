use anyhow::{Context, Result};
use std::{collections::BTreeMap, fs};

fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in s.trim().split(',') {
        if let Some((a,b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                for x in a.min(b)..=a.max(b) { out.push(x); }
            }
        } else if let Ok(v) = part.trim().parse::<usize>() {
            out.push(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn cpu_topology() -> Result<BTreeMap<u32, Vec<usize>>> {
    let mut topo = BTreeMap::new();
    let nodes = fs::read_dir("/sys/devices/system/node")
        .context("read /sys/devices/system/node")?;
    for e in nodes {
        let e = e?;
        let name = e.file_name().into_string().unwrap_or_default();
        if !name.starts_with("node") { continue; }
        let idx: u32 = name[4..].parse().unwrap_or(u32::MAX);
        if idx == u32::MAX { continue; }
        let path = format!("{}/cpulist", e.path().display());
        if let Ok(s) = fs::read_to_string(&path) {
            topo.insert(idx, parse_cpu_list(&s));
        }
    }
    if topo.is_empty() {
        if let Ok(s) = fs::read_to_string("/sys/devices/system/cpu/online") {
            topo.insert(0, parse_cpu_list(&s));
        }
    }
    Ok(topo)
}

pub fn dominant_node_for_pid(pid: i32) -> Option<u32> {
    let p = format!("/proc/{}/numa_maps", pid);
    let text = fs::read_to_string(&p).ok()?;
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for line in text.lines() {
        for tok in line.split_whitespace() {
            if let Some(rest) = tok.strip_prefix('N') {
                if let Some((n, v)) = rest.split_once('=') {
                    if let (Ok(n), Ok(v)) = (n.parse::<u32>(), v.parse::<u64>()) {
                        *counts.entry(n).or_default() += v;
                    }
                }
            }
        }
    }
    counts.into_iter().max_by_key(|(_,v)| *v).map(|(n,_)| n)
}

pub fn pick_compact(node: u32, k: usize, topo: &BTreeMap<u32, Vec<usize>>) -> Vec<usize> {
    if let Some(cpus) = topo.get(&node) {
        return cpus.iter().cloned().take(k.max(1)).collect();
    }
    Vec::new()
}

pub fn pick_spread(k: usize, topo: &BTreeMap<u32, Vec<usize>>) -> Vec<usize> {
    if k == 0 || topo.is_empty() { return Vec::new(); }
    let mut order: Vec<(u32, &Vec<usize>)> = topo.iter().map(|(n, v)| (*n, v)).collect();
    order.sort_by_key(|(n,_)| *n);
    let mut idx = vec![0usize; order.len()];
    let mut out = Vec::new();
    'outer: loop {
        for (i, (_, list)) in order.iter().enumerate() {
            if idx[i] < list.len() {
                out.push(list[idx[i]]);
                idx[i] += 1;
                if out.len() >= k { break 'outer; }
            }
        }
        if out.len() >= k || idx.iter().zip(order.iter()).all(|(i,(_,l))| *i >= l.len()) {
            break;
        }
    }
    out
}