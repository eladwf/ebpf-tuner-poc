// src/actions/io.rs
use anyhow::{Result, Context};
use std::fs;
pub fn tune(dev: &str, readahead_kb: u32, scheduler: Option<&str>) -> Result<()> {
    let ra = format!("/sys/block/{}/queue/read_ahead_kb", dev);
    fs::write(&ra, format!("{}", readahead_kb)).with_context(|| format!("write {}", ra))?;
    if let Some(s) = scheduler {
        let sch = format!("/sys/block/{}/queue/scheduler", dev);
        fs::write(&sch, s).with_context(|| format!("write {}", sch))?;
    }
    Ok(())
}