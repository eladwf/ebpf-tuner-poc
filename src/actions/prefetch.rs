
// src/actions/prefetch.rs
use anyhow::{Result, Context};
use std::{fs::File, os::fd::AsRawFd, os::unix::prelude::FromRawFd, collections::HashMap, time::Instant, io::Read};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use std::os::unix::io::RawFd;
use std::sync::Mutex;
use lazy_static::lazy_static;

#[derive(Debug, Clone)]
pub enum PrefetchBackend { Fadvise, Readahead }

#[derive(Debug, Clone)]
pub struct PrefetchAction {
    pub tgid: u32,
    pub dev: u64,
    pub ino: u64,
    pub ranges: Vec<(u64,u64)>, // (offset, len)
    pub backend: PrefetchBackend,
}

lazy_static! {
    static ref FD_CACHE: Mutex<HashMap<(u32,u64,u64), RawFd>> = Mutex::new(HashMap::new());
}

fn resolve_fd(tgid: u32, dev: u64, ino: u64) -> Result<RawFd> {
    let key = (tgid, dev, ino);
    // fast path
    if let Some(fd) = FD_CACHE.lock().unwrap().get(&key).copied() {
        return Ok(fd);
    }
    // Scan /proc/<tgid>/maps for matching dev:ino and open path
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", tgid))
        .with_context(|| format!("read /proc/{}/maps", tgid))?;
    for line in maps.lines() {
        // sample: 7f9f... r--p 00000000 08:01 131339 /lib/x.so
        // fields: addr perms offset dev inode pathname
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        let _perms = parts.next();
        let _off = parts.next();
        let dev_field = parts.next();
        let ino_field = parts.next();
        let path = parts.collect::<Vec<_>>().join(" ");
        if dev_field.is_none() || ino_field.is_none() || path.is_empty() { continue; }
        let dev_s = dev_field.unwrap();
        let ino_s = ino_field.unwrap();
        let mut dm = dev_s.split(':');
        let maj = u64::from_str_radix(dm.next().unwrap_or("0"),16).unwrap_or(0);
        let min = u64::from_str_radix(dm.next().unwrap_or("0"),16).unwrap_or(0);
        let dev_num = (maj << 20) | min;
        let ino_num = ino_s.parse::<u64>().unwrap_or(0);
        if dev_num == dev && ino_num == ino {
            // open
            if !path.is_empty() && path.starts_with('/') {
                let f = File::open(&path).with_context(|| format!("open {}", path))?;
                let fd = f.as_raw_fd();
                // leak the file descriptor intentionally, keep it in cache
                std::mem::forget(f);
                FD_CACHE.lock().unwrap().insert(key, fd);
                return Ok(fd);
            }
        }
    }
    anyhow::bail!("failed to resolve fd for tgid={} dev={} ino={}", tgid, dev, ino);
}

pub fn exec(a: &PrefetchAction) -> Result<()> {
    let fd = resolve_fd(a.tgid, a.dev, a.ino)?;
    for (off, len) in &a.ranges {
        unsafe {
            match a.backend {
                PrefetchBackend::Fadvise => {
                    let _ = posix_fadvise(fd, *off as i64, *len as i64, PosixFadviseAdvice::POSIX_FADV_WILLNEED);
                }
                PrefetchBackend::Readahead => {
                    let _ = libc::readahead(fd, *off as libc::off64_t, *len as libc::size_t);
                }
            }
        }
    }
    Ok(())
}