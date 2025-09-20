// src/actions/priority.rs
use anyhow::{Context, Result};
use std::fs;

const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;
const IOPRIO_WHO_PROCESS: i32 = 1;

fn for_each_pid_in_cgroup<F>(cg: &str, mut f: F) -> Result<()>
where
    F: FnMut(i32),
{
    let procs = format!("{}/cgroup.procs", cg);
    let data = fs::read_to_string(&procs).with_context(|| format!("read {}", procs))?;
    for line in data.lines() {
        if let Ok(pid) = line.trim().parse::<i32>() {
            f(pid);
        }
    }
    Ok(())
}

/// Set nice value (-20..19) for all tasks in cgroup
pub fn set_nice_for_cgroup(cg: &str, prio: i32) -> Result<()> {
    let prio = prio.clamp(-20, 19);
    unsafe {
        for_each_pid_in_cgroup(cg, |pid| {
            let _ = libc::setpriority(libc::PRIO_PROCESS, pid as u32, prio);
        })?;
    }
    Ok(())
}

/// Set I/O priority for all tasks in cgroup.
/// class: 1=RT, 2=BE, 3=IDLE. prio: 0..7 (0 highest) for RT/BE; ignored for IDLE.
pub fn set_ioprio_for_cgroup(cg: &str, class: i32, prio: i32) -> Result<()> {
    let class = match class {
        1 => IOPRIO_CLASS_RT,
        2 => IOPRIO_CLASS_BE,
        3 => IOPRIO_CLASS_IDLE,
        _ => IOPRIO_CLASS_BE,
    };
    let prio = prio.clamp(0, 7);
    let ioprio = ((class & 0x3) << 13) | (prio & 0x7);
    unsafe {
        for_each_pid_in_cgroup(cg, |pid| {
            let _ = libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid, ioprio);
        })?;
    }
    Ok(())
}

/// Toggle SCHED_BATCH for all tasks (0 priority).
pub fn set_sched_batch_for_cgroup(cg: &str, enable: bool) -> Result<()> {
    unsafe {
        let mut param = libc::sched_param {
            sched_priority: 0,
        };
        let policy = if enable { libc::SCHED_BATCH } else { libc::SCHED_OTHER };
        for_each_pid_in_cgroup(cg, |pid| {
            let _ = libc::sched_setscheduler(pid, policy, &mut param as *mut _);
        })?;
    }
    Ok(())
}