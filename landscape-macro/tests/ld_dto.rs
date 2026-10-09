//! Integration tests for the `LdCreate` / `LdUpdate` / `LdView` proc-macros.
//! Compiling at all also proves the shared `#[ld(...)]` helper attribute
//! works across multiple derives on one struct.

use landscape_macro::{LdCreate, LdUpdate, LdView};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn gen_id() -> u64 {
    42
}

fn now_ts() -> f64 {
    1.5
}

#[derive(Debug, Clone, Serialize, Deserialize, LdCreate, LdUpdate, LdView)]
pub struct DemoConfig {
    #[serde(default = "gen_id")]
    pub id: u64,
    #[ld(internal)]
    pub mirror: Option<String>,
    pub name: String,
    #[serde(default)]
    pub remark: Option<String>,
    #[serde(default = "now_ts")]
    pub update_at: f64,
}

/// Key without a default fn path: `#[serde(default)]` fills via `Default`.
#[derive(Debug, Clone, Serialize, Deserialize, LdCreate)]
pub struct TraitKeyConfig {
    #[serde(default)]
    pub id: u64,
    pub name: String,
}

/// Nested struct whose view hides a secret field.
#[derive(Debug, Clone, Serialize, Deserialize, LdView)]
pub struct TargetConfig {
    pub a: u8,
    #[ldv(hidden)]
    pub secret: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, LdCreate, LdUpdate, LdView)]
pub struct NestedDemoConfig {
    #[serde(default = "gen_id")]
    pub id: u64,
    #[ldv(view_type(TargetConfigView))]
    pub target: TargetConfig,
    #[serde(default = "now_ts")]
    pub update_at: f64,
}

#[test]
fn create_conversion_fills_server_fields() {
    let create = CreateDemoConfig { name: "n".into(), remark: None };
    let config: DemoConfig = create.into();
    assert_eq!(config.id, 42);
    assert_eq!(config.update_at, 1.5);
    assert_eq!(config.mirror, None);
    assert_eq!(config.name, "n");
}

#[test]
fn create_json_ignores_echoed_server_fields() {
    // id/update_at absent: fine, they are server-assigned.
    let create: CreateDemoConfig = serde_json::from_value(json!({ "name": "x" })).unwrap();
    let config: DemoConfig = create.into();
    assert_eq!(config.id, 42);

    // Echoed stale id/update_at (e.g. an upsert-style POST or a clipboard
    // import) is ignored: the conversion re-assigns server values, so the
    // echoed key never reaches the DB.
    let create: CreateDemoConfig =
        serde_json::from_value(json!({ "name": "x", "id": 999, "update_at": 9.9 })).unwrap();
    let config: DemoConfig = create.into();
    assert_eq!(config.id, 42);
    assert_eq!(config.update_at, 1.5);

    // Internal fields are likewise ignored (re-derived server-side).
    let create: CreateDemoConfig =
        serde_json::from_value(json!({ "name": "x", "mirror": "m" })).unwrap();
    let config: DemoConfig = create.into();
    assert_eq!(config.mirror, None);
}

#[test]
fn create_still_requires_mandatory_business_fields() {
    let missing = serde_json::from_value::<CreateDemoConfig>(json!({ "remark": "r" }));
    assert!(missing.is_err(), "name must stay required in the create DTO");
}

#[test]
fn create_uses_trait_default_when_no_fn_path() {
    let create = CreateTraitKeyConfig { name: "n".into() };
    let config: TraitKeyConfig = create.into();
    assert_eq!(config.id, 0);
}

#[test]
fn update_requires_id_and_update_at() {
    let missing = serde_json::from_value::<UpdateDemoConfig>(json!({ "name": "x" }));
    assert!(missing.is_err(), "update_at (optimistic lock) must be required");

    let ok: UpdateDemoConfig =
        serde_json::from_value(json!({ "id": 7, "name": "x", "update_at": 2.5 })).unwrap();
    let config: DemoConfig = ok.into();
    assert_eq!(config.id, 7);
    assert_eq!(config.update_at, 2.5);
    assert_eq!(config.mirror, None, "internal field is re-derived server-side");
}

#[test]
fn view_hides_internal_fields() {
    let config = DemoConfig {
        id: 1,
        mirror: Some("m".into()),
        name: "n".into(),
        remark: None,
        update_at: 3.0,
    };
    let view: DemoConfigView = config.into();
    let value = serde_json::to_value(&view).unwrap();
    assert!(value.get("mirror").is_none());
    assert_eq!(value["id"], 1);
    assert_eq!(value["name"], "n");
    assert_eq!(value["update_at"], 3.0);
}

#[test]
fn view_maps_nested_type_and_hides_nested_secret() {
    let nested = NestedDemoConfig {
        id: 1,
        target: TargetConfig { a: 3, secret: 9 },
        update_at: 1.0,
    };
    let view: NestedDemoConfigView = nested.into();
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["target"]["a"], 3);
    assert!(value["target"].get("secret").is_none());
}

#[test]
fn create_keeps_nested_plain_type() {
    // hidden is view-only: the create DTO still takes the full nested struct.
    let create: CreateNestedDemoConfig =
        serde_json::from_value(json!({ "target": { "a": 3, "secret": 9 } })).unwrap();
    let config: NestedDemoConfig = create.into();
    assert_eq!(config.target.secret, 9);
    assert_eq!(config.id, 42);
}
