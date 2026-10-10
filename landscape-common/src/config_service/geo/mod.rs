pub mod api;
pub mod config;
pub mod error;

pub use api::*;
pub use config::*;
pub use error::GeoError;

#[derive(Debug)]
pub enum RawDatState {
    Ready(Vec<u8>),
    Started,
    Running,
}
