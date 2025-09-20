use std::time::{Duration, Instant};
#[derive(Debug, Default)] pub struct Cooldown { until: Option<Instant> }
impl Cooldown 
{ 
    pub fn ready(&self) -> bool 
    { self.until.map(|u| Instant::now() >= u).unwrap_or(true) } 
    pub fn arm_ms(&mut self, ms: u64) 
    { self.until = Some(Instant::now() + Duration::from_millis(ms)); } 
}
