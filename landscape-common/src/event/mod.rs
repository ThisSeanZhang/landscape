use nat::NatEvent;
use serde::{Deserialize, Serialize};

pub mod dns;
pub mod hub;
pub mod nat;

#[derive(Debug, Serialize, Deserialize)]
pub enum LandscapeEvent {
    NAT(NatEvent),
}
