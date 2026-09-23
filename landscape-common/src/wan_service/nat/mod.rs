pub mod config;
pub mod dataplane;
pub mod error;

/// Schema-only view of a [`core::ops::Range<u16>`] port range.
///
/// `Range` does not implement `utoipa::ToSchema` and serde serializes it as
/// `{ "start": ..., "end": ... }`, so fields annotated with
/// `#[schema(value_type = PortRange)]` expose the typed shape to OpenAPI/TS
/// instead of an untyped object.
#[cfg(feature = "openapi")]
#[derive(utoipa::ToSchema)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}
