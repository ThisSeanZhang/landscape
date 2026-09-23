use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;
use sea_orm_migration::sea_orm::FromQueryResult;
use sea_orm_migration::sea_query::Expr;
use sea_orm_migration::{schema::*, sea_orm};
use std::collections::HashMap;
use uuid::Uuid;

use crate::tables::ddns::DdnsJobs;
use crate::tables::dhcp_v6_client::DHCPv6ClientConfigs;
use crate::tables::firewall::FirewallServiceConfigs;
use crate::tables::flow_rule::FlowConfigs;
use crate::tables::iface_ip::IfaceIpServiceConfigs;
use crate::tables::lan_ipv6_v2::LanIPv6ServiceConfigsV2;
use crate::tables::mss_clamp::MssClampServiceConfigs;
use crate::tables::nat::NatServiceConfigs;
use crate::tables::pppd::PPPDServiceConfigs;
use crate::tables::wan_link::WanLinks;

#[derive(DeriveMigrationName)]
pub struct Migration;

const DEFAULT_PD_SECTION: &str =
    r#"{"enable":false,"mac":"00:00:00:00:00:00","expected_pd_len":null}"#;
const DEFAULT_NAT_SECTION: &str =
    r#"{"enable":false,"tcp_range":null,"udp_range":null,"icmp_in_range":null}"#;
const DEFAULT_FIREWALL_SECTION: &str = r#"{"enable":false}"#;
const DEFAULT_MSS_SECTION: &str = r#"{"enable":false,"clamp_size":null}"#;

/// Backfill state for one link row, keyed by the legacy "net iface" (the
/// kernel interface the legacy per-service rows were keyed by: the attach
/// iface for ethernet / native PPPoE, the pppX device for pppd).
#[derive(Debug)]
struct PartialLink {
    id: Uuid,
    net_iface: String,
    attach_iface_name: String,
    kind: serde_json::Value,
    v4: serde_json::Value,
    pd: Option<serde_json::Value>,
    nat: Option<serde_json::Value>,
    firewall: Option<serde_json::Value>,
    mss: Option<serde_json::Value>,
    update_at: f64,
}

impl PartialLink {
    fn new(net_iface: String, attach_iface_name: String, update_at: f64) -> Self {
        Self {
            id: Uuid::new_v4(),
            net_iface: net_iface.clone(),
            attach_iface_name,
            // The initial name is the legacy net-iface name — a pure remark,
            // the reference key is the uuid.
            kind: serde_json::json!({"t": "ethernet"}),
            v4: serde_json::json!({"enable": false, "model": {"t": "nothing"}}),
            pd: None,
            nat: None,
            firewall: None,
            mss: None,
            update_at,
        }
    }

    fn bump(&mut self, ts: f64) {
        if ts > self.update_at {
            self.update_at = ts;
        }
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm::ConnectionTrait;

        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        db.execute(
            backend.build(
                &Table::create()
                    .table(WanLinks::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(WanLinks::Id).uuid().primary_key())
                    .col(ColumnDef::new(WanLinks::Name).string().not_null().default(""))
                    .col(ColumnDef::new(WanLinks::AttachIfaceName).string().not_null())
                    .col(json(WanLinks::Kind))
                    .col(json(WanLinks::V4))
                    .col(json(WanLinks::Pd))
                    .col(json(WanLinks::Nat))
                    .col(json(WanLinks::Firewall))
                    .col(json(WanLinks::Mss))
                    .col(double(WanLinks::UpdateAt).default(0))
                    .to_owned(),
            ),
        )
        .await?;

        // Idempotent: never backfill into a non-empty table (e.g. a restore
        // from an exported config that already contains links).
        if existing_links(db, backend).await? > 0 {
            return Ok(());
        }

        let mut links: Vec<PartialLink> = Vec::new();
        let mut idx: HashMap<String, usize> = HashMap::new();

        // ---- 1. pppd rows first: they define the ppp links that the
        // per-iface rows below resolve to. ----
        for row in read_rows::<PppdRow, _>(db, backend, PPPDServiceConfigs::Table).await? {
            let mut link = PartialLink::new(
                row.iface_name.clone(),
                row.attach_iface_name.clone(),
                row.update_at,
            );
            link.kind = serde_json::json!({
                "t": "pppd",
                "ppp_iface_name": row.iface_name,
                "peer_id": row.peer_id,
                "password": row.password,
                "ac": row.ac,
                "plugin": normalize_plugin(&row.plugin),
            });
            // The v4 address comes from IPCP; the legacy `enable` gated the
            // whole session, which maps to the v4 acquisition switch.
            link.v4 = serde_json::json!({
                "enable": row.enable,
                "model": {"t": "ipcp", "default_router": row.default_route},
            });
            idx.insert(link.net_iface.clone(), links.len());
            links.push(link);
        }

        // ---- 2. iface_ip_service_configs: the PPPoE model becomes a
        // PppoeNative link, everything else an Ethernet link. ----
        for row in read_rows::<IfaceIpRow, _>(db, backend, IfaceIpServiceConfigs::Table).await? {
            if idx.contains_key(&row.iface_name) {
                // A pppd link already owns this net iface; an ipconfig row on
                // a pppX device is legacy garbage — skip it.
                continue;
            }
            let mut link =
                PartialLink::new(row.iface_name.clone(), row.iface_name.clone(), row.update_at);
            let model: serde_json::Value =
                serde_json::from_str(&row.ip_model).unwrap_or(serde_json::json!({"t": "nothing"}));
            let model_tag = model.get("t").and_then(|v| v.as_str()).unwrap_or("nothing");
            match model_tag {
                "pppoe" => {
                    let mru = model.get("mtu").and_then(|v| v.as_u64()).unwrap_or(1492);
                    let mru = <u16 as TryFrom<u64>>::try_from(mru).unwrap_or(1492);
                    link.kind = serde_json::json!({
                        "t": "pppoe_native",
                        "username": json_str(&model, "username").unwrap_or_default(),
                        "password": json_str(&model, "password").unwrap_or_default(),
                        "requested_mru": mru,
                        "ac_name": json_str(&model, "ac_name"),
                        "lcp_echo_interval": null,
                        "redial_backoff_base_secs": null,
                    });
                    link.v4 = serde_json::json!({
                        "enable": row.enable,
                        "model": {
                            "t": "ipcp",
                            "default_router": json_bool(&model, "default_router"),
                        },
                    });
                }
                "static" => {
                    link.v4 = serde_json::json!({
                        "enable": row.enable,
                        "model": {
                            "t": "static",
                            "ipv4": json_str(&model, "ipv4"),
                            "ipv4_mask": model.get("ipv4_mask").and_then(|v| v.as_u64()),
                            "ipv6": json_str(&model, "ipv6"),
                            "default_router": json_bool(&model, "default_router"),
                            "default_router_ip": json_str(&model, "default_router_ip"),
                        },
                    });
                }
                "dhcpclient" => {
                    link.v4 = serde_json::json!({
                        "enable": row.enable,
                        "model": {
                            "t": "dhcp_client",
                            "hostname": json_str(&model, "hostname"),
                            "default_router": json_bool(&model, "default_router"),
                            "custome_opts": model
                                .get("custome_opts")
                                .cloned()
                                .unwrap_or(serde_json::json!([])),
                        },
                    });
                }
                _ => {
                    link.v4 = serde_json::json!({"enable": row.enable, "model": {"t": "nothing"}});
                }
            }
            idx.insert(link.net_iface.clone(), links.len());
            links.push(link);
        }

        // ---- 3. per-iface service rows attach to the link owning their net
        // iface; orphans implicitly create an idle ethernet link. ----
        for row in read_rows::<DhcpV6Row, _>(db, backend, DHCPv6ClientConfigs::Table).await? {
            let link = ensure_link(&mut links, &mut idx, &row.iface_name, row.update_at);
            // Legacy rows all carry the column default 60 — preserved
            // verbatim, consistent with the "never reinterpret stored
            // values" migration rule.
            link.pd = Some(serde_json::json!({
                "enable": row.enable,
                "mac": row.mac,
                "expected_pd_len": row.expected_pd_len.unwrap_or(60),
            }));
            link.bump(row.update_at);
        }

        for row in read_rows::<NatRow, _>(db, backend, NatServiceConfigs::Table).await? {
            let link = ensure_link(&mut links, &mut idx, &row.iface_name, row.update_at);
            link.nat = Some(serde_json::json!({
                "enable": row.enable,
                "tcp_range": {"start": row.tcp_range_start, "end": row.tcp_range_end},
                "udp_range": {"start": row.udp_range_start, "end": row.udp_range_end},
                "icmp_in_range": {"start": row.icmp_in_range_start, "end": row.icmp_in_range_end},
            }));
            link.bump(row.update_at);
        }

        for row in read_rows::<FirewallRow, _>(db, backend, FirewallServiceConfigs::Table).await? {
            let link = ensure_link(&mut links, &mut idx, &row.iface_name, row.update_at);
            link.firewall = Some(serde_json::json!({"enable": row.enable}));
            link.bump(row.update_at);
        }

        for row in read_rows::<MssRow, _>(db, backend, MssClampServiceConfigs::Table).await? {
            let link = ensure_link(&mut links, &mut idx, &row.iface_name, row.update_at);
            // Verbatim mapping including the legacy default 1492: never
            // reinterpret a stored value as "auto".
            link.mss = Some(serde_json::json!({
                "enable": row.enable,
                "clamp_size": row.clamp_size,
            }));
            link.bump(row.update_at);
        }

        // ---- 4. insert links ----
        for link in &links {
            let insert = Query::insert()
                .into_table(WanLinks::Table)
                .columns([
                    WanLinks::Id,
                    WanLinks::Name,
                    WanLinks::AttachIfaceName,
                    WanLinks::Kind,
                    WanLinks::V4,
                    WanLinks::Pd,
                    WanLinks::Nat,
                    WanLinks::Firewall,
                    WanLinks::Mss,
                    WanLinks::UpdateAt,
                ])
                .values_panic([
                    link.id.into(),
                    link.net_iface.clone().into(),
                    link.attach_iface_name.clone().into(),
                    link.kind.clone().into(),
                    link.v4.clone().into(),
                    link.pd
                        .clone()
                        .unwrap_or_else(|| serde_json::from_str(DEFAULT_PD_SECTION).unwrap())
                        .into(),
                    link.nat
                        .clone()
                        .unwrap_or_else(|| serde_json::from_str(DEFAULT_NAT_SECTION).unwrap())
                        .into(),
                    link.firewall
                        .clone()
                        .unwrap_or_else(|| serde_json::from_str(DEFAULT_FIREWALL_SECTION).unwrap())
                        .into(),
                    link.mss
                        .clone()
                        .unwrap_or_else(|| serde_json::from_str(DEFAULT_MSS_SECTION).unwrap())
                        .into(),
                    link.update_at.into(),
                ])
                .to_owned();
            db.execute(backend.build(&insert)).await?;
        }

        // ---- 5. remap persisted owner references (old net-iface name →
        // link uuid) in flow targets and DDNS sources. ----
        let remap: HashMap<String, String> =
            links.iter().map(|l| (l.net_iface.clone(), l.id.to_string())).collect();
        if !remap.is_empty() {
            remap_flow_targets(db, backend, &remap).await?;
            remap_ddns_sources(db, backend, &remap).await?;
            remap_lan_ipv6_pd_parents(db, backend, &remap).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(WanLinks::Table).if_exists().to_owned()).await
    }
}

async fn existing_links<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
) -> Result<u64, DbErr> {
    let select =
        Query::select().expr(Expr::col(WanLinks::Id).count()).from(WanLinks::Table).to_owned();
    let row =
        db.query_one(backend.build(&select)).await?.expect("count query always returns a row");
    let c: i64 = row.try_get_by_index(0)?;
    Ok(c as u64)
}

fn ensure_link<'a>(
    links: &'a mut Vec<PartialLink>,
    idx: &mut HashMap<String, usize>,
    net_iface: &str,
    update_at: f64,
) -> &'a mut PartialLink {
    if !idx.contains_key(net_iface) {
        idx.insert(net_iface.to_string(), links.len());
        links.push(PartialLink::new(net_iface.to_string(), net_iface.to_string(), update_at));
    }
    let i = idx[net_iface];
    &mut links[i]
}

async fn read_rows<T: FromQueryResult, C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    table: impl IntoTableRef,
) -> Result<Vec<T>, DbErr> {
    let select = Query::select().expr(Expr::col(Asterisk)).from(table).to_owned();
    T::find_by_statement(backend.build(&select)).all(db).await
}

fn normalize_plugin(raw: &str) -> String {
    match raw {
        "pppoe" => "pppoe".to_string(),
        _ => "rp_pppoe".to_string(),
    }
}

fn json_bool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

/// Reference rewriting is strictly ADDITIVE: `name` / `iface_name` /
/// `wan_pd_id` keep their legacy iface values (downgraded binaries resolve by
/// them), while the injected `link_id` / `wan_pd_link_id` fields carry the
/// link uuid for the new code. A dangling legacy `link_id` (e.g. after a
/// down() → up() cycle regenerated uuids) is overwritten by re-resolving
/// through the legacy name; unresolvable references get their `link_id`
/// cleared instead of guessed.
async fn remap_flow_targets<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
) -> Result<(), DbErr> {
    for row in read_rows::<FlowRow, _>(db, backend, FlowConfigs::Table).await? {
        let Ok(mut targets) =
            serde_json::from_str::<serde_json::Value>(&row.packet_handle_iface_name)
        else {
            continue;
        };
        let mut changed = false;
        if let Some(arr) = targets.as_array_mut() {
            for target in arr.iter_mut() {
                let inner = match target.get_mut("target") {
                    Some(inner) => inner,
                    None => continue,
                };
                if inner.get("t").and_then(|v| v.as_str()) != Some("interface") {
                    continue;
                }
                let name = inner.get("name").and_then(|v| v.as_str()).map(str::to_string);
                let resolved = name.as_deref().and_then(|n| remap.get(n)).cloned();
                match &resolved {
                    Some(uuid) => {
                        let new_value = serde_json::json!(uuid);
                        if inner.get("link_id") != Some(&new_value) {
                            inner["link_id"] = new_value;
                            changed = true;
                        }
                    }
                    None => {
                        // Unresolvable: clear a stale link_id rather than
                        // guessing from the name. An absent link_id is
                        // already the desired state — no write.
                        if inner.get("link_id").is_some() {
                            inner.as_object_mut().map(|o| o.remove("link_id"));
                            changed = true;
                        }
                    }
                }
            }
        }
        if !changed {
            continue;
        }
        let update = Query::update()
            .table(FlowConfigs::Table)
            .value(
                FlowConfigs::PacketHandleIfaceName,
                Expr::val(Value::Json(Some(Box::new(targets)))),
            )
            .and_where(Expr::col(FlowConfigs::Id).eq(row.id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

async fn remap_ddns_sources<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
) -> Result<(), DbErr> {
    for row in read_rows::<DdnsRow, _>(db, backend, DdnsJobs::Table).await? {
        let Ok(mut sources) = serde_json::from_str::<serde_json::Value>(&row.source) else {
            continue;
        };
        let mut changed = false;
        if let Some(arr) = sources.as_array_mut() {
            for source in arr.iter_mut() {
                let field = match source.get("t").and_then(|v| v.as_str()) {
                    Some("local_wan") => ("iface_name", "link_id"),
                    Some("enrolled_device") => ("wan_pd_id", "wan_pd_link_id"),
                    _ => continue,
                };
                let (legacy_field, link_field) = field;
                let name = source.get(legacy_field).and_then(|v| v.as_str()).map(str::to_string);
                let resolved = name.as_deref().and_then(|n| remap.get(n)).cloned();
                match &resolved {
                    Some(uuid) => {
                        let new_value = serde_json::json!(uuid);
                        if source.get(link_field) != Some(&new_value) {
                            source[link_field] = new_value;
                            changed = true;
                        }
                    }
                    // Only clear a stale link_id when there was a legacy
                    // reference to resolve; `wan_pd_id = null` (auto) never
                    // carries a link id.
                    None if name.is_some() && source.get(link_field).is_some() => {
                        source.as_object_mut().map(|o| o.remove(link_field));
                        changed = true;
                    }
                    None => {}
                }
            }
        }
        if !changed {
            continue;
        }
        let update = Query::update()
            .table(DdnsJobs::Table)
            .value(DdnsJobs::Source, Expr::val(Value::Json(Some(Box::new(sources)))))
            .and_where(Expr::col(DdnsJobs::Id).eq(row.id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

/// LAN IPv6 prefix groups whose parent is a PD source reference the
/// PD-providing link by the legacy WAN net iface (`depend_iface`). Rewriting
/// is strictly ADDITIVE: `depend_iface` keeps its legacy value (downgraded
/// binaries resolve by it), while the injected `link_id` carries the link uuid
/// for the new code. A stale legacy `link_id` (e.g. after a down() → up() cycle
/// regenerated uuids) is overwritten by re-resolving through `depend_iface`;
/// an unresolvable reference gets its `link_id` cleared instead of guessed.
async fn remap_lan_ipv6_pd_parents<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
) -> Result<(), DbErr> {
    for row in read_rows::<LanV6Row, _>(db, backend, LanIPv6ServiceConfigsV2::Table).await? {
        let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&row.config) else {
            continue;
        };
        let mut changed = false;
        if let Some(groups) = config.get_mut("prefix_groups").and_then(|g| g.as_array_mut()) {
            for group in groups.iter_mut() {
                let parent = match group.get_mut("parent") {
                    Some(parent) => parent,
                    None => continue,
                };
                if parent.get("t").and_then(|v| v.as_str()) != Some("pd") {
                    continue;
                }
                let name = parent.get("depend_iface").and_then(|v| v.as_str()).map(str::to_string);
                let resolved = name.as_deref().and_then(|n| remap.get(n)).cloned();
                match &resolved {
                    Some(uuid) => {
                        let new_value = serde_json::json!(uuid);
                        if parent.get("link_id") != Some(&new_value) {
                            parent["link_id"] = new_value;
                            changed = true;
                        }
                    }
                    None => {
                        // Only clear a stale link_id when there was a legacy
                        // reference to resolve; a parent without `depend_iface`
                        // never carries a link id.
                        if name.is_some() && parent.get("link_id").is_some() {
                            parent.as_object_mut().map(|o| o.remove("link_id"));
                            changed = true;
                        }
                    }
                }
            }
        }
        if !changed {
            continue;
        }
        let update = Query::update()
            .table(LanIPv6ServiceConfigsV2::Table)
            .value(LanIPv6ServiceConfigsV2::Config, Expr::val(Value::Json(Some(Box::new(config)))))
            .and_where(Expr::col(LanIPv6ServiceConfigsV2::IfaceName).eq(row.iface_name))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

#[derive(FromQueryResult)]
struct PppdRow {
    iface_name: String,
    attach_iface_name: String,
    enable: bool,
    default_route: bool,
    peer_id: String,
    password: String,
    update_at: f64,
    ac: Option<String>,
    plugin: String,
}

#[derive(FromQueryResult)]
struct IfaceIpRow {
    iface_name: String,
    enable: bool,
    ip_model: String,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct DhcpV6Row {
    iface_name: String,
    enable: bool,
    mac: String,
    expected_pd_len: Option<u8>,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct NatRow {
    iface_name: String,
    enable: bool,
    tcp_range_start: u16,
    tcp_range_end: u16,
    udp_range_start: u16,
    udp_range_end: u16,
    icmp_in_range_start: u16,
    icmp_in_range_end: u16,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct FirewallRow {
    iface_name: String,
    enable: bool,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct MssRow {
    iface_name: String,
    enable: bool,
    clamp_size: u16,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct FlowRow {
    id: Uuid,
    packet_handle_iface_name: String,
}

#[derive(FromQueryResult)]
struct DdnsRow {
    id: Uuid,
    source: String,
}

#[derive(FromQueryResult)]
struct LanV6Row {
    iface_name: String,
    config: String,
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{Database, Statement};

    use super::*;

    const LEGACY_SCHEMA: &str = r#"
        CREATE TABLE pppd_service_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            attach_iface_name TEXT NOT NULL,
            enable BOOLEAN NOT NULL,
            default_route BOOLEAN NOT NULL,
            peer_id TEXT NOT NULL,
            password TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0,
            ac TEXT,
            plugin TEXT NOT NULL DEFAULT 'rp_pppoe'
        );
        CREATE TABLE iface_ip_service_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            ip_model TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE dhcp_v6_client_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            mac TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0,
            expected_pd_len INTEGER DEFAULT 60
        );
        CREATE TABLE nat_service_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            tcp_range_start SMALLINT UNSIGNED NOT NULL,
            tcp_range_end SMALLINT UNSIGNED NOT NULL,
            udp_range_start SMALLINT UNSIGNED NOT NULL,
            udp_range_end SMALLINT UNSIGNED NOT NULL,
            icmp_in_range_start SMALLINT UNSIGNED NOT NULL,
            icmp_in_range_end SMALLINT UNSIGNED NOT NULL,
            enable BOOLEAN NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE firewall_service_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE mss_clamp_service_configs (
            iface_name TEXT PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            clamp_size SMALLINT UNSIGNED NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE flow_configs (
            id UUID PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            flow_id INTEGER UNSIGNED NOT NULL,
            flow_match_rules TEXT NOT NULL,
            packet_handle_iface_name TEXT NOT NULL,
            remark TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE ddns_jobs (
            id UUID PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            enable BOOLEAN NOT NULL,
            source TEXT NOT NULL,
            zone_name TEXT NOT NULL,
            provider_profile_id UUID NOT NULL,
            ttl INTEGER,
            records TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE lan_ipv6_service_configs_v2 (
            iface_name TEXT PRIMARY KEY NOT NULL,
            enable BOOLEAN NOT NULL,
            config TEXT,
            update_at REAL NOT NULL DEFAULT 0
        );
    "#;

    async fn test_db() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(LEGACY_SCHEMA).await.unwrap();
        db
    }

    async fn query_json(db: &sea_orm::DatabaseConnection, sql: &str) -> Vec<serde_json::Value> {
        let rows =
            db.query_all(Statement::from_string(DbBackend::Sqlite, sql.to_string())).await.unwrap();
        rows.iter()
            .map(|row| {
                let raw: String = row.try_get_by_index(0).unwrap();
                serde_json::from_str(&raw).unwrap()
            })
            .collect()
    }

    #[tokio::test]
    async fn migrates_pppd_dhcp_and_sub_services_into_one_link() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO pppd_service_configs
                (iface_name, attach_iface_name, enable, default_route, peer_id, password, update_at, ac, plugin)
            VALUES ('ppp0', 'wan0', TRUE, TRUE, 'user', 'pass', 10.0, 'ac1', 'pppoe');

            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at) VALUES
                ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"hostname":"router","custome_opts":[]}', 20.0),
                ('wan1', TRUE, '{"t":"pppoe","default_router":false,"username":"u1","password":"p1","mtu":1492}', 30.0),
                ('wan2', TRUE, '{"t":"static","ipv4":"192.168.1.2","ipv4_mask":24,"default_router":true}', 5.0);

            INSERT INTO dhcp_v6_client_configs (iface_name, enable, mac, update_at, expected_pd_len)
            VALUES ('ppp0', TRUE, '02:00:00:00:00:01', 40.0, 56);

            INSERT INTO nat_service_configs
                (iface_name, enable, tcp_range_start, tcp_range_end, udp_range_start, udp_range_end, icmp_in_range_start, icmp_in_range_end, update_at)
            VALUES ('wan0', TRUE, 1024, 2048, 1024, 2048, 1024, 2048, 50.0);

            INSERT INTO firewall_service_configs (iface_name, enable, update_at) VALUES ('wan0', TRUE, 60.0);
            INSERT INTO mss_clamp_service_configs (iface_name, enable, clamp_size, update_at) VALUES ('ppp0', TRUE, 1452, 70.0);
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // 4 links: ppp0 (pppd), wan0 (ethernet dhcp), wan1 (pppoe native), wan2 (ethernet static)
        let kinds =
            query_json(&db, "SELECT kind FROM wan_links ORDER BY attach_iface_name, name").await;
        assert_eq!(kinds.len(), 4);

        let pppd = kinds.iter().find(|k| k["t"] == "pppd").unwrap();
        assert_eq!(pppd["ppp_iface_name"], "ppp0");
        assert_eq!(pppd["plugin"], "pppoe");
        assert_eq!(pppd["ac"], "ac1");

        let native = kinds.iter().find(|k| k["t"] == "pppoe_native").unwrap();
        assert_eq!(native["requested_mru"], 1492);

        // v4 sections
        let v4s = query_json(&db, "SELECT v4 FROM wan_links ORDER BY name").await;
        let ppp0_v4 = v4s
            .iter()
            .find(|v| v["model"]["t"] == "ipcp" && v["model"]["default_router"] == true)
            .unwrap();
        assert_eq!(ppp0_v4["enable"], true);

        let static_v4 = v4s.iter().find(|v| v["model"]["t"] == "static").unwrap();
        assert_eq!(static_v4["model"]["ipv4"], "192.168.1.2");
        assert_eq!(static_v4["model"]["ipv4_mask"], 24);

        // sub-services merged onto the right links
        let nats = query_json(&db, "SELECT nat FROM wan_links WHERE name = 'wan0'").await;
        assert_eq!(nats[0]["enable"], true);
        assert_eq!(nats[0]["tcp_range"]["start"], 1024);

        let pds = query_json(&db, "SELECT pd FROM wan_links WHERE name = 'ppp0'").await;
        assert_eq!(pds[0]["enable"], true);
        assert_eq!(pds[0]["expected_pd_len"], 56);

        let mss = query_json(&db, "SELECT mss FROM wan_links WHERE name = 'ppp0'").await;
        // explicit clamp preserved verbatim — never auto-derived
        assert_eq!(mss[0]["clamp_size"], 1452);
        assert_eq!(mss[0]["enable"], true);

        // update_at = max of merged rows
        let wan0_ts: f64 = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT update_at FROM wan_links WHERE name = 'wan0'".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(wan0_ts, 60.0);
    }

    #[tokio::test]
    async fn orphan_service_rows_create_idle_ethernet_links() {
        let db = test_db().await;
        db.execute_unprepared(
            r#"
            INSERT INTO dhcp_v6_client_configs (iface_name, enable, mac, update_at, expected_pd_len)
            VALUES ('wan9', TRUE, '02:00:00:00:00:09', 1.0, 60);
        "#,
        )
        .await
        .unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let rows = query_json(&db, "SELECT kind FROM wan_links").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["t"], "ethernet");

        let v4 = query_json(&db, "SELECT v4 FROM wan_links").await;
        assert_eq!(v4[0]["enable"], false);
        assert_eq!(v4[0]["model"]["t"], "nothing");
    }

    #[tokio::test]
    async fn remaps_flow_targets_and_ddns_sources_to_uuids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, remark)
            VALUES (x'11111111111111111111111111111111', TRUE, 1, '[]',
                    '[{"target":{"t":"interface","name":"wan0"},"weight":1},{"target":{"t":"interface","name":"lan0"},"weight":2}]',
                    '');

            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'22222222222222222222222222222222', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":"wan0","family":"ipv4"},{"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":"wan0","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let uuid: Uuid = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();

        let raw: String = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT packet_handle_iface_name FROM flow_configs".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        let flow: serde_json::Value = serde_json::from_str(&raw).unwrap();
        // additive remap: the legacy name keeps its iface value (downgraded
        // binaries resolve by it), the uuid rides in link_id
        assert_eq!(flow[0]["target"]["name"], "wan0");
        assert_eq!(flow[0]["target"]["link_id"], uuid.to_string());
        // non-link references are fully untouched (no link_id injected)
        assert_eq!(flow[1]["target"]["name"], "lan0");
        assert!(flow[1]["target"].get("link_id").is_none());

        let ddns = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        assert_eq!(ddns[0]["iface_name"], "wan0");
        assert_eq!(ddns[0]["link_id"], uuid.to_string());
        assert_eq!(ddns[1]["wan_pd_id"], "wan0");
        assert_eq!(ddns[1]["wan_pd_link_id"], uuid.to_string());
    }

    #[tokio::test]
    async fn remaps_lan_ipv6_pd_parents_to_uuids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"stateful","lifetime":300,"prefix_groups":[{"group_id":"g0","parent":{"t":"pd","depend_iface":"wan0","expected_pd_len_snapshot":60,"link_id":"00000000-0000-0000-0000-000000000000"},"ra":null,"na":null,"pd":null},{"group_id":"g1","parent":{"t":"static","base_prefix":"fd00::","parent_prefix_len":60},"ra":null,"na":null,"pd":null},{"group_id":"g2","parent":{"t":"pd","depend_iface":"ghost","expected_pd_len_snapshot":56,"link_id":"00000000-0000-0000-0000-000000000001"},"ra":null,"na":null,"pd":null}]}',
                    1.0);
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let uuid: Uuid = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();

        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        let groups = config["prefix_groups"].as_array().unwrap();

        // resolvable PD parent: legacy name kept, stale link_id overwritten
        assert_eq!(groups[0]["parent"]["depend_iface"], "wan0");
        assert_eq!(groups[0]["parent"]["link_id"], uuid.to_string());

        // static parent is never touched (not a WAN reference)
        assert_eq!(groups[1]["parent"]["t"], "static");
        assert!(groups[1]["parent"].get("link_id").is_none());

        // unresolvable PD parent: stale link_id cleared, no guessing
        assert_eq!(groups[2]["parent"]["depend_iface"], "ghost");
        assert!(groups[2]["parent"].get("link_id").is_none());
    }

    #[tokio::test]
    async fn stale_link_ids_are_healed_after_down_up_cycle() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, remark)
            VALUES (x'11111111111111111111111111111111', TRUE, 1, '[]',
                    '[{"target":{"t":"interface","name":"wan0","link_id":"00000000-0000-0000-0000-000000000000"},"weight":1},{"target":{"t":"interface","name":"ghost","link_id":"00000000-0000-0000-0000-000000000001"},"weight":2}]',
                    '');
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let fresh: Uuid = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_ne!(fresh.to_string(), "00000000-0000-0000-0000-000000000000");

        // simulate the down() → up() cycle: drop the links table, rerun up()
        Migration.down(&SchemaManager::new(&db)).await.unwrap();
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let regenerated: Uuid = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_ne!(regenerated, fresh, "backfill assigns fresh uuids");

        let flow = &query_json(&db, "SELECT packet_handle_iface_name FROM flow_configs").await[0];
        // resolvable reference: stale link_id overwritten with the new uuid
        assert_eq!(flow[0]["target"]["name"], "wan0");
        assert_eq!(flow[0]["target"]["link_id"], regenerated.to_string());
        // unresolvable reference: stale link_id cleared, no guessing
        assert_eq!(flow[1]["target"]["name"], "ghost");
        assert!(flow[1]["target"].get("link_id").is_none());
    }

    #[tokio::test]
    async fn rerunning_up_is_idempotent() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);
        "#)
            .await
            .unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let count: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn empty_legacy_tables_produce_no_links() {
        let db = test_db().await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let count: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(count, 0);
    }
}
