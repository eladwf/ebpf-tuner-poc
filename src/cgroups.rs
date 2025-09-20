use anyhow::{Context, Result};
use std::{fs, io::Write, path::{Path, PathBuf}};

pub fn ensure_unified() -> Result<bool> {
    Ok(Path::new("/sys/fs/cgroup/cgroup.controllers").exists())
}

fn write_if_exists(path: &Path, data: &str) -> Result<()> {
    if path.exists() {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?
            .write_all(data.as_bytes())
            .with_context(|| format!("write {}='{}'", path.display(), data.trim()))?;
    }
    Ok(())
}

fn enable_controllers(parent: &Path, ctrls: &[&str]) -> Result<()> {
    let supported = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .unwrap_or_default();
    let want: Vec<&str> = ctrls.iter().copied()
        .filter(|c| supported.split_whitespace().any(|s| s == *c))
        .collect();
    if want.is_empty() { return Ok(()); }
    let payload = want.iter().map(|c| format!("+{}", c)).collect::<Vec<_>>().join(" ");
    let sc = parent.join("cgroup.subtree_control");
    let _ = fs::OpenOptions::new().write(true).open(&sc)
        .and_then(|mut f| f.write_all(payload.as_bytes()));
    Ok(())
}

pub fn create_and_attach(cg_path: &str, pid: i32) -> Result<()> {
    let cg = Path::new(cg_path);
    let parent: PathBuf = cg.parent().unwrap_or(Path::new("/sys/fs/cgroup")).to_path_buf();

    fs::create_dir_all(&parent).with_context(|| format!("create {}", parent.display()))?;
    enable_controllers(&parent, &["cpu","cpuset","io","memory","pids"])?;

    fs::create_dir_all(&cg).with_context(|| format!("create {}", cg.display()))?;

    let child_cpus = cg.join("cpuset.cpus");
    let child_mems = cg.join("cpuset.mems");
    if child_cpus.exists() || child_mems.exists() {
        let parent_cpus = fs::read_to_string(parent.join("cpuset.cpus.effective"))
            .or_else(|_| fs::read_to_string(parent.join("cpuset.cpus")))
            .unwrap_or_else(|_| "0-0".to_string());
        let parent_mems = fs::read_to_string(parent.join("cpuset.mems.effective"))
            .or_else(|_| fs::read_to_string(parent.join("cpuset.mems")))
            .unwrap_or_else(|_| "0".to_string());
        write_if_exists(&child_cpus, parent_cpus.trim())?;
        write_if_exists(&child_mems, parent_mems.trim())?;
    }

    let procs = cg.join("cgroup.procs");
    fs::OpenOptions::new().write(true).open(&procs)
        .with_context(|| format!("open {}", procs.display()))?
        .write_all(pid.to_string().as_bytes())
        .with_context(|| format!("attach pid {} to {}", pid, cg.display()))?;

    Ok(())
}