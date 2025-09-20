use anyhow::Result; use std::fs;
#[derive(Debug, Default, Clone, Copy)]
pub struct PsiSnap 
{ pub cpu_some: f64, pub io_some: f64, pub mem_some: f64 }


pub fn available() -> bool {
    std::path::Path::new("/proc/pressure").exists()
}

fn parse_some_avg10(s: &str) -> Option<f64> {
    for line in s.lines() {
        let line = line.trim();
        if !line.starts_with("some") { continue; }
        for tok in line.split_whitespace() {
            if let Some(v) = tok.strip_prefix("avg10=") {
                if let Ok(x) = v.parse::<f64>() { return Some(x); }
            }
        }
    }
    None
}

impl PsiSnap {

pub fn read_all(cg_path: Option<&str>) -> Result<PsiSnap> {
    let (cpu_path, io_path, mem_path) = if let Some(cg) = cg_path {
        (format!("{cg}/cpu.pressure"),
         format!("{cg}/io.pressure"),
         format!("{cg}/memory.pressure"))
    } else {
        ("/proc/pressure/cpu".into(),
         "/proc/pressure/io".into(),
         "/proc/pressure/memory".into())
    };

    if !std::path::Path::new(&cpu_path).exists() {
        return Ok(PsiSnap::default());
    }

    let cpu_some = fs::read_to_string(&cpu_path).ok()
        .and_then(|s| parse_some_avg10(&s)).unwrap_or(0.0);
    let io_some  = fs::read_to_string(&io_path).ok()
        .and_then(|s| parse_some_avg10(&s)).unwrap_or(0.0);
    let mem_some = fs::read_to_string(&mem_path).ok()
        .and_then(|s| parse_some_avg10(&s)).unwrap_or(0.0);

    Ok(PsiSnap { cpu_some, io_some, mem_some })
}

}


fn read(p: &str) -> Result<f64> 
{ let s = fs::read_to_string(p)?;
    for line in s.lines() 
    { 
        if line.starts_with("some ") 
    { 
        for tok in line.split_whitespace() 
        { 
            if tok.starts_with("avg10=") 
        { 
            return Ok(tok[6..].parse::<f64>().unwrap_or(0.0)); 
        } 
    } 
} 
} Ok(0.0) 
}