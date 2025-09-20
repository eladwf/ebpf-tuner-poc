// src/events.rs
#[derive(Debug, Clone, Copy)]
pub enum CommEv {
     Wake { waker: u32, wakee: u32 }, 
     Futex { uaddr: u64, tid: u32, op: u32 } }

#[derive(Debug, Clone, Copy)]
pub struct TunerEvent 
{ pub pid: u32, pub kind: u32, pub val_us: u64, pub ts_ns: u64 }

pub fn parse_comm_event(data: &[u8]) -> Option<CommEv> {
    if data.len() < 8 { return None; }
    let typ = u32::from_ne_bytes([data[0],data[1],data[2],data[3]]);
    match typ {
        1 => {
            if data.len() < 16 { return None; }
            let waker = u32::from_ne_bytes([data[8],data[9],data[10],data[11]]);
            let wakee = u32::from_ne_bytes([data[12],data[13],data[14],data[15]]);
            Some(CommEv::Wake { waker, wakee })
        }
        2 => {
            if data.len() < 24 { return None; }
            let uaddr = u64::from_ne_bytes([data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15]]);
            let tid   = u32::from_ne_bytes([data[16],data[17],data[18],data[19]]);
            let op    = u32::from_ne_bytes([data[20],data[21],data[22],data[23]]);
            Some(CommEv::Futex { uaddr, tid, op })
        }
        _ => None
    }
}

pub fn parse_tuner_event(data: &[u8]) -> Option<TunerEvent> {

    if data.len() < 24 { return None; }
    let pid   = u32::from_ne_bytes(data[0..4].try_into().ok()?);
    let kind  = u32::from_ne_bytes(data[4..8].try_into().ok()?);
    let val_us= u64::from_ne_bytes(data[8..16].try_into().ok()?);
    let ts_ns = u64::from_ne_bytes(data[16..24].try_into().ok()?);
    Some(TunerEvent { pid, kind, val_us, ts_ns })
}