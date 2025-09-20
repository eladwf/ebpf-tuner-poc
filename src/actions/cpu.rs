use anyhow::Result;
use std::{fs, path::Path};

pub fn set_weight(cg: &str, weight: u64, dry: bool) -> Result<()> {
    let path = format!("{}/cpu.weight", cg);
    if dry {
        eprintln!("[dry] would set {} to {}", path, weight);
        return Ok(());
    }
    if Path::new(&path).exists() {
        if let Err(e) = fs::write(&path, weight.to_string()) {
            eprintln!("[warn] set cpu.weight={} failed on {}: {e}", weight, path);
        }
    } else {
        eprintln!("[warn] {} not present; skipping cpu.weight", path);
    }
    Ok(())
}