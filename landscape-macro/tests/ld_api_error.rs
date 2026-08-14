//! Integration tests for the `#[derive(LdApiError)]` proc-macro.
//!
//! These tests exercise the macro-generated `LdApiErrorInfo` implementation
//! against a local minimal copy of the trait, covering every supported variant
//! shape (unit / named / tuple / boxed-serialize / transparent).

use landscape_macro::LdApiError;

/// Minimal local copy of `landscape_common::error::LdApiErrorInfo`.
pub mod error {
    use serde_json::Value;

    pub trait LdApiErrorInfo {
        fn error_id(&self) -> &'static str;
        fn http_status_code(&self) -> u16;
        fn error_args(&self) -> Value;
    }
}

#[derive(Debug, serde::Serialize)]
pub struct BoxedDetails {
    pub iface_name: String,
    pub slot_range: String,
}

impl std::fmt::Display for BoxedDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "boxed error: {} {}", self.iface_name, self.slot_range)
    }
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum TestApiError {
    #[error("unit error")]
    #[api_error(id = "test.unit", status = 400)]
    Unit,

    #[error("named error: {iface_name}")]
    #[api_error(id = "test.named", status = 409)]
    Named { iface_name: String, code: u8 },

    #[error("tuple error: {0} {1}")]
    #[api_error(id = "test.tuple", status = 500)]
    Tuple(String, u8),

    #[error("{0}")]
    #[api_error(id = "test.boxed", status = 422, serialize)]
    Boxed(Box<BoxedDetails>),

    #[error(transparent)]
    #[api_error(id = "test.internal", status = 500)]
    Internal(#[from] std::io::Error),
}

use error::LdApiErrorInfo;
use serde_json::json;

#[test]
fn unit_variant_has_no_args() {
    let err = TestApiError::Unit;
    assert_eq!(err.error_id(), "test.unit");
    assert_eq!(err.http_status_code(), 400);
    assert_eq!(err.error_args(), json!({}));
}

#[test]
fn named_variant_exposes_field_keys() {
    let err = TestApiError::Named { iface_name: "lan0".into(), code: 7 };
    assert_eq!(err.error_id(), "test.named");
    assert_eq!(err.http_status_code(), 409);
    assert_eq!(err.error_args(), json!({ "iface_name": "lan0", "code": 7 }));
}

#[test]
fn tuple_variant_without_serialize_keeps_positional_args() {
    let err = TestApiError::Tuple("lan0".into(), 7);
    assert_eq!(err.error_id(), "test.tuple");
    assert_eq!(err.http_status_code(), 500);
    assert_eq!(err.error_args(), json!({ "0": "lan0", "1": "7" }));
}

#[test]
fn boxed_serialize_variant_serializes_inner_struct() {
    let err = TestApiError::Boxed(Box::new(BoxedDetails {
        iface_name: "lan0".into(),
        slot_range: "1-3".into(),
    }));
    assert_eq!(err.error_id(), "test.boxed");
    assert_eq!(err.http_status_code(), 422);
    assert_eq!(err.error_args(), json!({ "iface_name": "lan0", "slot_range": "1-3" }));
    assert_eq!(err.to_string(), "boxed error: lan0 1-3");
}

#[test]
fn from_variant_is_transparent() {
    let err: TestApiError = std::io::Error::other("boom").into();
    assert_eq!(err.error_id(), "test.internal");
    assert_eq!(err.http_status_code(), 500);
    assert_eq!(err.error_args(), json!({}));
}
