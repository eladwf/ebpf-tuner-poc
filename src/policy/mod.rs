// src/policy/mod.rs
use crate::{metrics::Snapshot, actions::Action};

pub trait Strategy: Send {
    fn tick(&mut self, snap: &Snapshot) -> Vec<Action>;
    fn on_event(&mut self, _evt: &crate::metrics::Event) -> Option<Action> { None }
    fn name(&self) -> &'static str;
}

pub mod learned;