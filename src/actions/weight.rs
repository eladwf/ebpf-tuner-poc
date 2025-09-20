// src/actions/weight.rs
use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;

pub fn set_weight(cg: &str, weight: u32, dry: bool) -> Result<()> {
    let w = weight.clamp(1, 10000);
    let path = format!("{}/cpu.weight", cg);
    if dry {
        eprintln!("[dry-run] would write {} -> {}", path, w);
        return Ok(());
    }
    match fs::write(&path, format!("{}\n", w)) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            eprintln!("[agent] cpu.weight write denied for {}; skipping (EACCES)", path);
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("write {}", path)),
    }
}