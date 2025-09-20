// src/bpf.rs
use anyhow::{Result, Context};
use libbpf_rs::{MapCore, MapFlags, RingBuffer, RingBufferBuilder};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_sys::{bpf_map_get_next_key, bpf_map_lookup_elem};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use std::os::fd::{AsFd, AsRawFd};
use std::mem::{size_of, MaybeUninit};
use crate::events::{parse_comm_event, parse_tuner_event};


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefetchEvt {
    pub tgid: u32,
    pub pid: u32,
    pub ts_ns: u64,
    pub sb_dev: u64,
    pub ino: u64,
    pub pgoff: u64,
}
include!(concat!(env!("OUT_DIR"), "/tuner.skel.rs"));
mod sockops_skel { include!(concat!(env!("OUT_DIR"), "/sockops.skel.rs")); }
mod prefetch_skel { include!(concat!(env!("OUT_DIR"), "/prefetch.skel.rs")); }
use sockops_skel::SockopsSkelBuilder;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Agg { pub(crate) futex_us: u64, page_faults: u64 }


pub fn dump_target_tgids_fd(fd: i32, max: usize) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    let mut cur_key: Option<u32> = None; // None => start from beginning

    for _ in 0..max {
        let mut next_key: u32 = 0;

        let ret = unsafe {
            bpf_map_get_next_key(
                fd,
                match cur_key {
                    Some(ref k) => (k as *const u32) as *const c_void,
                    None => std::ptr::null(),
                },
                (&mut next_key as *mut u32) as *mut c_void,
            )
        };

        if ret != 0 {
            break; // ENOENT => end of iteration
        }

        let mut val: u8 = 0;
        let _ = unsafe {
            bpf_map_lookup_elem(
                fd,
                (&next_key as *const u32) as *const c_void,
                (&mut val as *mut u8) as *mut c_void,
            )
        };
        out.push((next_key, val));
        cur_key = Some(next_key); // advance
    }
    out
}

pub struct AgentBpf {
    // Prefetch sensor skeleton & ringbuf
    prefetch: Option<prefetch_skel::PrefetchSkel<'static>>,
    prefetch_rb: Option<RingBuffer<'static>>,
    prefetch_buf: Arc<std::sync::Mutex<Vec<PrefetchEvt>>>,
    pub skel: TunerSkel<'static>,
    rb: Option<RingBuffer<'static>>,
    // counters
    comm_wake: Arc<AtomicU64>,
    comm_futex: Arc<AtomicU64>,
    spikes: Arc<AtomicU64>,
    // optional sockops (kept alive to retain link)
    _sockops: Option<sockops_skel::SockopsSkel<'static>>,
    target_pid: i32,
 }

fn bytes_to_agg(b: &[u8]) -> Agg {
    assert_eq!(b.len(), size_of::<Agg>());
    let mut out = MaybeUninit::<Agg>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            b.as_ptr(),
            out.as_mut_ptr() as *mut u8,
            size_of::<Agg>(),
        );
        out.assume_init()
    }
}
fn zero_blob() -> Vec<u8> { vec![0u8; size_of::<Agg>()] }

impl AgentBpf {
    pub fn load_and_attach(target_pid: i32, with_descendants: bool, follow_new: bool, attach_sockops: bool) -> Result<Self> {
        // builder.open requires MaybeUninit<OpenObject>
        let leaked: &'static mut core::mem::MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(core::mem::MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
        let mut open = TunerSkelBuilder::default().open(leaked).context("open tuner skeleton")?;
        // Disable block rq_complete autoload (kernel ctx layout varies)
        open.progs.on_rq_complete.set_autoload(false);
        eprintln!("[agent] on_rq_complete autoload disabled");
        let mut skel = open.load().context("load tuner skeleton")?;
        skel.maps.TARGET_TGIDS.pin("/sys/fs/bpf/TARGET_TGIDS")?;

        // seed TGID
        if target_pid > 0 {
            let m = &skel.maps.TARGET_TGIDS;
            let key: u32 = target_pid as u32;
            let val: u8 = 1;
            m.update(&key.to_ne_bytes(), &[val], MapFlags::ANY).context("seed TARGET_TGIDS")?;
        }

        // CFG_FOLLOW (descendants)
        let key0: u32 = 0;
        let val_follow: u32 = if with_descendants { 1 } else { 0 };
        skel.maps.CFG_FOLLOW.update(&key0.to_ne_bytes(), &val_follow.to_ne_bytes(), MapFlags::ANY).ok();

        // attach core tracepoints/probes (field style, like your loader.rs)
        let l1 = skel.progs.ev_sched_waking.attach().context("attach sched_waking")?;
        skel.links.ev_sched_waking = Some(l1);

        let l2 = skel.progs.tp_switch.attach().context("attach sched_switch")?;
        skel.links.tp_switch = Some(l2);

        if let Ok(link) = skel.progs.tp_pf_user.attach() {
            skel.links.tp_pf_user = Some(link);
        }

        // futex (enter/exit + waitv variants if present)
        if let Ok(l) = skel.progs.tp_enter_futex.attach() {
            skel.links.tp_enter_futex = Some(l);
            if let Ok(l2) = skel.progs.tp_exit_futex.attach() {
                skel.links.tp_exit_futex = Some(l2);
            }
        }
        if let Ok(l) = skel.progs.tp_enter_futex_waitv.attach() {
            skel.links.tp_enter_futex_waitv = Some(l);
            if let Ok(l2) = skel.progs.tp_exit_futex_waitv.attach() {
                skel.links.tp_exit_futex_waitv = Some(l2);
            }
        }

        if follow_new {
            if let Ok(l) = skel.progs.tp_proc_fork.attach() { skel.links.tp_proc_fork = Some(l); }
            if let Ok(l) = skel.progs.tp_proc_exit.attach() { skel.links.tp_proc_exit = Some(l); }
        }

        // ring buffers (COMM_EVENTS, EVENTS)
        let comm_wake = Arc::new(AtomicU64::new(0));
        let comm_futex= Arc::new(AtomicU64::new(0));
        let spikes    = Arc::new(AtomicU64::new(0));

        let mut rb = RingBufferBuilder::new();
        {
            let w = Arc::clone(&comm_wake);
            let f = Arc::clone(&comm_futex);
            rb.add(&skel.maps.COMM_EVENTS, move |data: &[u8]| -> i32 {
                if let Some(ev) = parse_comm_event(data) {
                    match ev {
                        crate::events::CommEv::Wake { .. } => { w.fetch_add(1, Relaxed); }
                        crate::events::CommEv::Futex { .. } => { f.fetch_add(1, Relaxed); }
                    }
                }
                0
            })?;
        }
        {
            let s = Arc::clone(&spikes);
            rb.add(&skel.maps.EVENTS, move |data: &[u8]| -> i32 {
                if parse_tuner_event(data).is_some() {
                    eprintln!("EVENTS");
                    s.fetch_add(1, Relaxed);
                }
                0
            })?;
        }
        let rb = Some(rb.build()?);

        let mut sock_skel: Option<sockops_skel::SockopsSkel<'static>> = None;
        if attach_sockops {
            let leaked: &'static mut core::mem::MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(core::mem::MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
            let open = SockopsSkelBuilder::default().open(leaked)?;
            let mut so = open.load()?;
            if let Ok(file) = std::fs::File::open("/sys/fs/cgroup") {
                let fd = file.as_raw_fd();
                if let Ok(link) = so.progs.sockops_prog.attach_cgroup(fd) {
                    so.links.sockops_prog = Some(link);
                }
            }
            sock_skel = Some(so);
        }
        
        let prefetch_buf: std::sync::Arc<std::sync::Mutex<Vec<PrefetchEvt>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(4096)));

        let leaked_pref: &'static mut core::mem::MaybeUninit<libbpf_rs::OpenObject> =
            Box::leak(Box::new(core::mem::MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
        let pref_open = prefetch_skel::PrefetchSkelBuilder::default()
            .open(leaked_pref).context("open prefetch skeleton")?;
        let mut prefetch_skel = pref_open.load().context("load prefetch skeleton")?;
        if let Ok(link) = prefetch_skel.progs.on_filemap_fault.attach() {
            prefetch_skel.links.on_filemap_fault = Some(link);
        }
        let mut prefetch_rb_builder = RingBufferBuilder::new();
        {
            let buf = std::sync::Arc::clone(&prefetch_buf);
            prefetch_rb_builder.add(&prefetch_skel.maps.PREFETCH_EVENTS, move |data: &[u8]| -> i32 {
                if data.len() >= core::mem::size_of::<PrefetchEvt>() {
                    eprintln!("PrefetchEvt");
                    // SAFETY: PrefetchEvt is POD written by BPF
                    let ev: PrefetchEvt = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const PrefetchEvt) };
                    if let Ok(mut v) = buf.lock() { v.push(ev); }
                }
                0
            })?;
        }
        let prefetch_rb = Some(prefetch_rb_builder.build().context("build prefetch ringbuf")?);
        

        Ok(Self {
            skel,
            rb,
            comm_wake,
            comm_futex,
            spikes,
            _sockops: sock_skel,
            // NEW:
            prefetch: Some(prefetch_skel),
            prefetch_rb,
            prefetch_buf,
            target_pid,
        })    }

    pub fn poll(&mut self) {
        if let Some(r) = self.rb.as_mut() {
            let _ = r.poll(Duration::from_millis(0));
        }
        if let Some(rp) = self.prefetch_rb.as_mut() {
            let _ = rp.poll(Duration::from_millis(0));
        }
    }

    pub fn read_comm_wake(&self) -> u64 { self.comm_wake.load(Relaxed) }
    pub fn read_comm_futex(&self) -> u64 { self.comm_futex.load(Relaxed) }
    pub fn read_spikes(&self) -> u64 { self.spikes.load(Relaxed) }

    pub fn read_llc_for_pid(&self, tgid: u32) -> u64 {
        let map = &self.skel.maps.LLC_MISS;
        let key = tgid.to_ne_bytes();
        if let Ok(Some(val)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
            if val.len() >= 8 { return u64::from_ne_bytes(val[0..8].try_into().unwrap()); }
        }
        0
    }
    pub fn target_tgids_fd(&self) -> Option<i32> {
        Some(self.skel.maps.TARGET_TGIDS.as_fd().as_raw_fd())
    }

    pub fn read_and_reset_agg(&self) -> Agg {
      let key: u32 = 0;
        let key_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&key as *const u32) as *const u8,
                size_of::<u32>(),
            )
        };

        let raw = match self.skel.maps.AGG.lookup_percpu(key_bytes, MapFlags::ANY) {
            Ok(Some(v)) => v,
            _ => return Agg::default(),
        };

        let mut sum = Agg::default();
        for v in &raw {
            let a = bytes_to_agg(v);
            sum.futex_us += a.futex_us;
            sum.page_faults += a.page_faults;
        }

        let zeros: Vec<Vec<u8>> = raw.iter().map(|v| vec![0u8; v.len()]).collect();
        let _ = self.skel.maps.AGG.update_percpu(key_bytes, &zeros, MapFlags::ANY);

        sum
    }

    pub fn read_io_pattern_for_pid(&self, tgid: u32) -> (u64,u64) {
        let map = &self.skel.maps.IO_PAT;
        let key = tgid.to_ne_bytes();
        if let Ok(Some(val)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
            if val.len() >= 24 {
                let seq = u64::from_ne_bytes(val[8..16].try_into().unwrap());
                let rnd = u64::from_ne_bytes(val[16..24].try_into().unwrap());
                return (seq, rnd);
            }
        }
        (0,0)
    }
}

impl AgentBpf {
     pub fn drain_prefetch_events(&self) -> Vec<PrefetchEvt> {
         let mut guard = self.prefetch_buf.lock().unwrap();
         let out = guard.clone();
         guard.clear();
         out
     }
 
}