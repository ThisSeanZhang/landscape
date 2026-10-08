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
use crate::tables::nat::{NatServiceConfigs, StaticNatMappingV4Configs, StaticNatMappingV6Configs};
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

/// Collects every legacy source of WAN link identity into one link list
/// BEFORE any row is inserted, so reference rewriting always resolves through
/// a complete name → uuid map and the uuid is never in a half-assigned state.
///
/// Sources, in priority order:
/// 1. per-iface service rows (`pppd`, `iface_ip`, then section-only rows)
/// 2. WAN references held by other configs (flow targets, DDNS sources, LAN
///    IPv6 PD parents, static NAT WAN bindings) — a name that only appears as
///    a reference becomes an idle ethernet link, exactly like an orphan
///    service row. Nothing is left unresolvable.
#[derive(Default)]
struct LinkCollector {
    links: Vec<PartialLink>,
    idx: HashMap<String, usize>,
}

impl LinkCollector {
    fn ensure_link(&mut self, net_iface: &str, update_at: f64) -> &mut PartialLink {
        if !self.idx.contains_key(net_iface) {
            self.idx.insert(net_iface.to_string(), self.links.len());
            self.links.push(PartialLink::new(
                net_iface.to_string(),
                net_iface.to_string(),
                update_at,
            ));
        }
        let i = self.idx[net_iface];
        &mut self.links[i]
    }

    fn contains(&self, net_iface: &str) -> bool {
        self.idx.contains_key(net_iface)
    }

    fn remap(&self) -> HashMap<String, String> {
        self.links.iter().map(|l| (l.net_iface.clone(), l.id.to_string())).collect()
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

        // SQLite has no `ADD COLUMN IF NOT EXISTS`; guard through the schema
        // manager's column probe so reruns and down() → up() cycles stay clean.
        if !manager.has_column("static_nat_mapping_v4_configs", "wan_link_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(StaticNatMappingV4Configs::Table)
                        .add_column(
                            ColumnDef::new(StaticNatMappingV4Configs::WanLinkId).uuid().null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("static_nat_mapping_v6_configs", "wan_link_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(StaticNatMappingV6Configs::Table)
                        .add_column(
                            ColumnDef::new(StaticNatMappingV6Configs::WanLinkId).uuid().null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // Idempotent: never backfill into a non-empty table (e.g. a restore
        // from an exported config that already contains links).
        if existing_links(db, backend).await? > 0 {
            return Ok(());
        }

        let mut collector = LinkCollector::default();

        // ---- 1. pppd rows first: they define the ppp links that the
        // per-iface rows below resolve to. ----
        for row in read_rows::<PppdRow, _>(db, backend, PPPDServiceConfigs::Table).await? {
            let link = collector.ensure_link(&row.iface_name, row.update_at);
            link.attach_iface_name = row.attach_iface_name.clone();
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
        }

        // ---- 2. iface_ip_service_configs: the PPPoE model becomes a
        // PppoeNative link, everything else an Ethernet link. ----
        for row in read_rows::<IfaceIpRow, _>(db, backend, IfaceIpServiceConfigs::Table).await? {
            if collector.contains(&row.iface_name) {
                // A pppd link already owns this net iface; an ipconfig row on
                // a pppX device is legacy garbage — skip it.
                continue;
            }
            let link = collector.ensure_link(&row.iface_name, row.update_at);
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
        }

        // ---- 3. per-iface section rows attach to the link owning their net
        // iface; orphans implicitly create an idle ethernet link. ----
        for row in read_rows::<DhcpV6Row, _>(db, backend, DHCPv6ClientConfigs::Table).await? {
            let link = collector.ensure_link(&row.iface_name, row.update_at);
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
            let link = collector.ensure_link(&row.iface_name, row.update_at);
            link.nat = Some(serde_json::json!({
                "enable": row.enable,
                "tcp_range": {"start": row.tcp_range_start, "end": row.tcp_range_end},
                "udp_range": {"start": row.udp_range_start, "end": row.udp_range_end},
                "icmp_in_range": {"start": row.icmp_in_range_start, "end": row.icmp_in_range_end},
            }));
            link.bump(row.update_at);
        }

        for row in read_rows::<FirewallRow, _>(db, backend, FirewallServiceConfigs::Table).await? {
            let link = collector.ensure_link(&row.iface_name, row.update_at);
            link.firewall = Some(serde_json::json!({"enable": row.enable}));
            link.bump(row.update_at);
        }

        for row in read_rows::<MssRow, _>(db, backend, MssClampServiceConfigs::Table).await? {
            let link = collector.ensure_link(&row.iface_name, row.update_at);
            // Verbatim mapping including the legacy default 1492: never
            // reinterpret a stored value as "auto".
            link.mss = Some(serde_json::json!({
                "enable": row.enable,
                "clamp_size": row.clamp_size,
            }));
            link.bump(row.update_at);
        }

        // ---- 4. WAN references held by other configs: read them once,
        // ensure every referenced net iface owns a link (an idle ethernet
        // link for a name that has no service rows), then rewrite the
        // references to the link uuid after the links are inserted. ----
        let flow_rows = read_rows::<FlowRow, _>(db, backend, FlowConfigs::Table).await?;
        let ddns_rows = read_rows::<DdnsRow, _>(db, backend, DdnsJobs::Table).await?;
        let lan_v6_rows =
            read_rows::<LanV6Row, _>(db, backend, LanIPv6ServiceConfigsV2::Table).await?;
        let snat4_rows =
            read_rows::<SnatV4Row, _>(db, backend, StaticNatMappingV4Configs::Table).await?;
        let snat6_rows =
            read_rows::<SnatV6Row, _>(db, backend, StaticNatMappingV6Configs::Table).await?;

        for (name, ts) in flow_rows.iter().flat_map(|r| {
            flow_target_names(&r.packet_handle_iface_name)
                .into_iter()
                .map(move |n| (n, r.update_at))
        }) {
            collector.ensure_link(&name, ts);
        }
        for (name, ts) in ddns_rows
            .iter()
            .flat_map(|r| ddns_source_names(&r.source).into_iter().map(move |n| (n, r.update_at)))
        {
            collector.ensure_link(&name, ts);
        }
        for (name, ts) in lan_v6_rows.iter().flat_map(|r| {
            lan_v6_pd_parent_names(&r.config).into_iter().map(move |n| (n, r.update_at))
        }) {
            collector.ensure_link(&name, ts);
        }
        macro_rules! collect_snat_refs {
            ($rows:expr) => {
                for row in &$rows {
                    if let Some(name) = row.wan_iface_name.as_deref().filter(|n| !n.is_empty()) {
                        collector.ensure_link(name, row.update_at);
                    }
                }
            };
        }
        collect_snat_refs!(snat4_rows);
        collect_snat_refs!(snat6_rows);

        // ---- 5. insert links ----
        for link in &collector.links {
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

        // ---- 6. remap persisted references (legacy net-iface name →
        // link uuid). A non-empty name always resolves (the collector
        // ensured every referenced name owns a link). An unusable name
        // (null/blank/absent) is handled per reference kind, matching each
        // new-type field's serde contract:
        //   * flow targets and DDNS sources carry a mandatory `link_id`
        //     (no `serde(default)`), so they get a fresh dangling uuid to
        //     stay deserializable — any pre-existing uuid dates from an
        //     earlier backfill round and is provably dead.
        //   * LAN IPv6 PD parents carry a serde-defaulted `link_id`, so a
        //     stale value degrades instead of poisoning the read and the
        //     existing id is kept.
        // Legacy names stay in place so a best-effort downgrade can still
        // resolve every reference by name (see `down`); the runtime also
        // dual-writes them on every later save. ----
        let remap = collector.remap();
        remap_flow_targets(db, backend, &remap, flow_rows).await?;
        remap_ddns_sources(db, backend, &remap, ddns_rows).await?;
        remap_lan_ipv6_pd_parents(db, backend, &remap, lan_v6_rows).await?;
        remap_static_nat_wan_links(db, backend, &remap, snat4_rows, snat6_rows).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort downgrade: the legacy name mirrors are dual-written on
        // every runtime save (the repository `prepare` hook re-derives them
        // from `link_id`), so a downgraded binary can still resolve every
        // reference by name. The columns holding the uuids can simply be
        // dropped.
        if manager.has_column("static_nat_mapping_v4_configs", "wan_link_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(StaticNatMappingV4Configs::Table)
                        .drop_column(StaticNatMappingV4Configs::WanLinkId)
                        .to_owned(),
                )
                .await?;
        }
        if manager.has_column("static_nat_mapping_v6_configs", "wan_link_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(StaticNatMappingV6Configs::Table)
                        .drop_column(StaticNatMappingV6Configs::WanLinkId)
                        .to_owned(),
                )
                .await?;
        }

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

/// Net-iface names referenced by flow targets.
fn flow_target_names(raw: &str) -> Vec<String> {
    let Ok(targets) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    targets
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target.get("target"))
        .filter(|inner| inner.get("t").and_then(|v| v.as_str()) == Some("interface"))
        .filter_map(|inner| inner.get("name").and_then(|v| v.as_str()))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Net-iface names referenced by DDNS sources.
fn ddns_source_names(raw: &str) -> Vec<String> {
    let Ok(sources) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    sources
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|source| match source.get("t").and_then(|v| v.as_str()) {
            Some("local_wan") => source.get("iface_name").and_then(|v| v.as_str()),
            Some("enrolled_device") => source.get("wan_pd_id").and_then(|v| v.as_str()),
            _ => None,
        })
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Net-iface names referenced by LAN IPv6 PD prefix-group parents.
fn lan_v6_pd_parent_names(raw: &str) -> Vec<String> {
    let Ok(config) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    config
        .get("prefix_groups")
        .and_then(|g| g.as_array())
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("parent"))
        .filter(|parent| parent.get("t").and_then(|v| v.as_str()) == Some("pd"))
        .filter_map(|parent| parent.get("depend_iface").and_then(|v| v.as_str()))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Rewrites flow interface targets to the referenced link's uuid. A
/// non-empty name always resolves (the collector ensured every referenced
/// name owns a link), so a stale `link_id` (e.g. after a down() → up()
/// cycle regenerated uuids) is healed by re-resolving through the name. An
/// unusable name (null/blank/absent) pins a fresh dangling uuid — `link_id`
/// is mandatory on the new type and any pre-existing value dates from an
/// earlier backfill round, so it is overwritten rather than trusted.
/// `name` is a mandatory String on both the legacy and the new type, so a
/// null/missing value is normalized to "" (the reference key is `link_id`).
async fn remap_flow_targets<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
    rows: Vec<FlowRow>,
) -> Result<(), DbErr> {
    for row in rows {
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
                let uuid = inner
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|name| !name.is_empty())
                    .and_then(|name| remap.get(name))
                    .cloned()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                let uuid_value = serde_json::json!(uuid);
                if inner.get("link_id") != Some(&uuid_value) {
                    inner["link_id"] = uuid_value;
                    changed = true;
                }
                if !matches!(inner.get("name"), Some(serde_json::Value::String(_))) {
                    inner["name"] = serde_json::json!("");
                    changed = true;
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
                Expr::val(Value::String(Some(Box::new(targets.to_string())))),
            )
            .and_where(Expr::col(FlowConfigs::Id).eq(row.id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

/// Rewrites DDNS source references: `local_wan.link_id` and
/// `enrolled_device.wan_pd_link_id`. A non-empty legacy name always resolves
/// (the collector ensured every referenced name owns a link), so stale or
/// renamed uuids are healed through the name. An unusable name
/// (null/blank/absent — the old "auto" encoding, unreachable through the
/// legacy API) pins a fresh dangling uuid unconditionally: the remap only
/// runs alongside a fresh backfill, so any pre-existing value dates from an
/// earlier round and is provably dead. The legacy name mirror is left
/// untouched; the runtime dual-writes it from `link_id` on every later save.
// CLEAN when 1.0.0 (name mirrors are dropped with the fields)
async fn remap_ddns_sources<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
    rows: Vec<DdnsRow>,
) -> Result<(), DbErr> {
    for row in rows {
        let Ok(mut sources) = serde_json::from_str::<serde_json::Value>(&row.source) else {
            continue;
        };
        let mut changed = false;
        if let Some(arr) = sources.as_array_mut() {
            for source in arr.iter_mut() {
                let (legacy_field, link_field) = match source.get("t").and_then(|v| v.as_str()) {
                    Some("local_wan") => ("iface_name", "link_id"),
                    Some("enrolled_device") => ("wan_pd_id", "wan_pd_link_id"),
                    _ => continue,
                };

                // Resolve the legacy name first so a stale or renamed link id
                // is healed. With no usable name pin a fresh dangling one
                // unconditionally: the remap only runs alongside a fresh
                // backfill, so any pre-existing value dates from an earlier
                // round and is provably dead.
                let uuid = match source
                    .get(legacy_field)
                    .and_then(|v| v.as_str())
                    .filter(|name| !name.is_empty())
                    .and_then(|name| remap.get(name))
                {
                    Some(resolved) => resolved.clone(),
                    None => Uuid::new_v4().to_string(),
                };
                let uuid_value = serde_json::json!(uuid);
                if source.get(link_field) != Some(&uuid_value) {
                    source[link_field] = uuid_value;
                    changed = true;
                }

                // A hand-edited row may carry an explicit JSON null where the
                // typed runtime expects a string; normalize it so the row
                // stays readable.
                if source.get(legacy_field).is_some_and(|v| v.is_null()) {
                    source[legacy_field] = serde_json::json!("");
                    changed = true;
                }
                // `iface_name` is a mandatory String on the legacy type (the
                // new type merely serde-defaults it): a missing value — only
                // reachable through hand-editing — would poison a downgraded
                // binary. Materialize "" so both binaries can read the row.
                // (`wan_pd_id` is Option-typed on both sides and legitimately
                // absent, so it is deliberately not materialized.)
                if legacy_field == "iface_name"
                    && !matches!(source.get("iface_name"), Some(serde_json::Value::String(_)))
                {
                    source["iface_name"] = serde_json::json!("");
                    changed = true;
                }
            }
        }
        if !changed {
            continue;
        }
        let update = Query::update()
            .table(DdnsJobs::Table)
            .value(DdnsJobs::Source, Expr::val(Value::String(Some(Box::new(sources.to_string())))))
            .and_where(Expr::col(DdnsJobs::Id).eq(row.id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

/// Rewrites LAN IPv6 prefix-group PD parents to the PD-providing link's uuid
/// (`link_id`). The legacy `depend_iface` name is resolved first so a stale or
/// renamed uuid is healed; with no usable name the existing uuid is kept (the
/// field is serde-defaulted on the new type, so a stale value degrades
/// instead of poisoning the read). `depend_iface` is a mandatory String on
/// the legacy type, so a null/missing value is normalized to "" to keep the
/// row readable for a downgraded binary. The name mirror itself is otherwise
/// left untouched; the runtime dual-writes it from `link_id` on every later
/// save.
// CLEAN when 1.0.0 (name mirror is dropped with the field)
async fn remap_lan_ipv6_pd_parents<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
    rows: Vec<LanV6Row>,
) -> Result<(), DbErr> {
    for row in rows {
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
                // `depend_iface` is a mandatory String on the legacy type
                // (the new type merely serde-defaults it): a null or missing
                // value — both only reachable through hand-editing — would
                // poison a downgraded binary even though the new runtime
                // reads the row fine. Normalize/materialize "" so both
                // binaries can read the row. This runs before the `continue`
                // below so unreachable parents are normalized too.
                if !matches!(parent.get("depend_iface"), Some(serde_json::Value::String(_))) {
                    parent["depend_iface"] = serde_json::json!("");
                    changed = true;
                }
                // Resolve the legacy name first so a stale or renamed link id
                // is healed. With no usable name (a new-runtime row, whose mirror
                // is deliberately blank) the existing uuid is authoritative and
                // kept; when neither is usable the parent is left untouched.
                let uuid = match parent
                    .get("depend_iface")
                    .and_then(|v| v.as_str())
                    .filter(|name| !name.is_empty())
                    .and_then(|name| remap.get(name))
                    .cloned()
                {
                    Some(resolved) => Some(resolved),
                    None => match parent.get("link_id").and_then(|v| v.as_str()) {
                        Some(existing) if !existing.is_empty() => Some(existing.to_string()),
                        _ => None,
                    },
                };
                let Some(uuid) = uuid else {
                    continue;
                };
                let uuid_value = serde_json::json!(uuid);
                if parent.get("link_id") != Some(&uuid_value) {
                    parent["link_id"] = uuid_value;
                    changed = true;
                }
            }
        }
        if !changed {
            continue;
        }
        let update = Query::update()
            .table(LanIPv6ServiceConfigsV2::Table)
            .value(
                LanIPv6ServiceConfigsV2::Config,
                Expr::val(Value::String(Some(Box::new(config.to_string())))),
            )
            .and_where(Expr::col(LanIPv6ServiceConfigsV2::IfaceName).eq(row.iface_name))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    Ok(())
}

/// Fills the `wan_link_id` column on static NAT mappings from their legacy
/// `wan_iface_name` binding. `wan_iface_name = null` (unbound) stays null.
async fn remap_static_nat_wan_links<C: sea_orm::ConnectionTrait>(
    db: &C,
    backend: DbBackend,
    remap: &HashMap<String, String>,
    snat4_rows: Vec<SnatV4Row>,
    snat6_rows: Vec<SnatV6Row>,
) -> Result<(), DbErr> {
    for row in snat4_rows {
        let Some(uuid) = row.wan_iface_name.as_deref().and_then(|n| remap.get(n)) else {
            continue;
        };
        let update = Query::update()
            .table(StaticNatMappingV4Configs::Table)
            .value(
                StaticNatMappingV4Configs::WanLinkId,
                Expr::val(Uuid::parse_str(uuid).expect("generated uuid is valid")),
            )
            .and_where(Expr::col(StaticNatMappingV4Configs::Id).eq(row.id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }
    for row in snat6_rows {
        let Some(uuid) = row.wan_iface_name.as_deref().and_then(|n| remap.get(n)) else {
            continue;
        };
        let update = Query::update()
            .table(StaticNatMappingV6Configs::Table)
            .value(
                StaticNatMappingV6Configs::WanLinkId,
                Expr::val(Uuid::parse_str(uuid).expect("generated uuid is valid")),
            )
            .and_where(Expr::col(StaticNatMappingV6Configs::Id).eq(row.id))
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
    update_at: f64,
}

#[derive(FromQueryResult)]
struct DdnsRow {
    id: Uuid,
    source: String,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct LanV6Row {
    iface_name: String,
    config: String,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct SnatV4Row {
    id: Uuid,
    wan_iface_name: Option<String>,
    update_at: f64,
}

#[derive(FromQueryResult)]
struct SnatV6Row {
    id: Uuid,
    wan_iface_name: Option<String>,
    update_at: f64,
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
            name TEXT NOT NULL DEFAULT '',
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
        CREATE TABLE static_nat_mapping_v4_configs (
            id UUID PRIMARY KEY NOT NULL,
            name TEXT,
            enable BOOLEAN NOT NULL,
            remark TEXT NOT NULL,
            wan_iface_name TEXT,
            mapping_pair_ports TEXT NOT NULL,
            lan_target TEXT,
            lan_ipv4 TEXT,
            l4_protocols TEXT NOT NULL,
            update_at REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE static_nat_mapping_v6_configs (
            id UUID PRIMARY KEY NOT NULL,
            name TEXT,
            enable BOOLEAN NOT NULL,
            remark TEXT NOT NULL,
            wan_iface_name TEXT,
            port_config TEXT NOT NULL,
            lan_target TEXT,
            lan_ipv6 TEXT,
            l4_protocols TEXT NOT NULL,
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

    async fn link_uuids(db: &sea_orm::DatabaseConnection) -> HashMap<String, String> {
        let rows = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT name, id FROM wan_links".to_string(),
            ))
            .await
            .unwrap();
        rows.iter()
            .map(|row| {
                let name: String = row.try_get_by_index(0).unwrap();
                let id: Uuid = row.try_get_by_index(1).unwrap();
                (name, id.to_string())
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
    async fn referenced_names_without_service_rows_become_idle_links() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, remark)
            VALUES (x'11111111111111111111111111111111', TRUE, 1, '[]',
                    '[{"target":{"t":"interface","name":"ghost-wan"},"weight":1}]',
                    '');

            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'22222222222222222222222222222222', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":"wan0","family":"ipv4"},{"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":"pd-only","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');

            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"slaac","lifetime":300,"prefix_groups":[{"group_id":"g0","parent":{"t":"pd","depend_iface":"pd-only","expected_pd_len_snapshot":56}}]}',
                    1.0);

            INSERT INTO static_nat_mapping_v4_configs (id, name, enable, remark, wan_iface_name, mapping_pair_ports, l4_protocols)
            VALUES (x'55555555555555555555555555555555', NULL, TRUE, '', 'ppp-only', '[]', '[6]');

            INSERT INTO static_nat_mapping_v6_configs (id, name, enable, remark, wan_iface_name, port_config, l4_protocols)
            VALUES (x'66666666666666666666666666666666', NULL, TRUE, '', NULL, '"all"', '[17]');
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // wan0 (service row) + ghost-wan (flow ref) + pd-only (ddns/lanv6 ref)
        // + ppp-only (static nat ref) = 4 links; every reference resolves.
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
        assert_eq!(count, 4);

        let uuids = link_uuids(&db).await;

        // flow reference rewritten with the fresh uuid
        let flow = &query_json(&db, "SELECT packet_handle_iface_name FROM flow_configs").await[0];
        assert_eq!(flow[0]["target"]["name"], "ghost-wan");
        assert_eq!(flow[0]["target"]["link_id"], uuids["ghost-wan"]);

        // ddns local_wan + enrolled_device wan_pd references rewritten; the
        // server-authoritative name mirrors stay in place.
        let ddns = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        assert_eq!(ddns[0]["link_id"], uuids["wan0"]);
        assert_eq!(ddns[0]["iface_name"], "wan0");
        assert_eq!(ddns[1]["wan_pd_link_id"], uuids["pd-only"]);
        assert_eq!(ddns[1]["wan_pd_id"], "pd-only");

        // lan ipv6 pd parent rewritten; the name mirror is kept and refreshed
        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        assert_eq!(config["prefix_groups"][0]["parent"]["link_id"], uuids["pd-only"]);
        assert_eq!(config["prefix_groups"][0]["parent"]["depend_iface"], "pd-only");

        // static nat v4 bound to a link; v6 unbound stays null
        let snat4_link: Option<Uuid> = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT wan_link_id FROM static_nat_mapping_v4_configs".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(snat4_link, Uuid::parse_str(&uuids["ppp-only"]).ok());

        let snat6_link: Option<Uuid> = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT wan_link_id FROM static_nat_mapping_v6_configs".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(snat6_link, None);
    }

    #[tokio::test]
    async fn stale_link_ids_are_healed_after_down_up_cycle() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, remark)
            VALUES (x'11111111111111111111111111111111', TRUE, 1, '[]',
                    '[{"target":{"t":"interface","name":"wan0","link_id":"00000000-0000-0000-0000-000000000000"},"weight":1},{"target":{"t":"interface","name":"wan0"},"weight":2}]',
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
        assert_ne!(fresh, Uuid::nil());

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
        // both targets heal to the regenerated uuid through the name
        assert_eq!(flow[0]["target"]["name"], "wan0");
        assert_eq!(flow[0]["target"]["link_id"], regenerated.to_string());
        assert_eq!(flow[1]["target"]["link_id"], regenerated.to_string());
    }

    #[tokio::test]
    async fn ddns_and_lan_stale_link_ids_are_healed_after_down_up_cycle() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'22222222222222222222222222222222', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":"wan0","link_id":"00000000-0000-0000-0000-000000000000","family":"ipv4"},
                      {"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":"pd-only","wan_pd_link_id":"00000000-0000-0000-0000-000000000000","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');

            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"slaac","lifetime":300,"prefix_groups":[{"group_id":"g0","parent":{"t":"pd","depend_iface":"pd-only","link_id":"00000000-0000-0000-0000-000000000000","expected_pd_len_snapshot":56}}]}',
                    1.0);
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let first = link_uuids(&db).await;
        let ddns = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        assert_eq!(ddns[0]["link_id"], first["wan0"]);
        assert_eq!(ddns[1]["wan_pd_link_id"], first["pd-only"]);
        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        assert_eq!(config["prefix_groups"][0]["parent"]["link_id"], first["pd-only"]);

        // down() → up(): fresh uuids, so the stale ids must heal through the name
        Migration.down(&SchemaManager::new(&db)).await.unwrap();
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let second = link_uuids(&db).await;
        assert_ne!(first["wan0"], second["wan0"]);
        let ddns = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        assert_eq!(ddns[0]["link_id"], second["wan0"]);
        assert_eq!(ddns[1]["wan_pd_link_id"], second["pd-only"]);
        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        assert_eq!(config["prefix_groups"][0]["parent"]["link_id"], second["pd-only"]);
    }

    #[tokio::test]
    async fn ddns_blank_name_sources_get_fresh_dangling_link_ids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'55555555555555555555555555555555', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":"","link_id":"11111111-1111-1111-1111-111111111111","family":"ipv4"},
                      {"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":null,"wan_pd_link_id":"22222222-2222-2222-2222-222222222222","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // A blank name must not create a link.
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

        // The stored ids date from an earlier backfill round (down() drops
        // the wan_links table) and are provably dead: both are replaced with
        // fresh dangling uuids so the mandatory fields stay populated.
        let ddns = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        let local = Uuid::parse_str(ddns[0]["link_id"].as_str().unwrap()).unwrap();
        let enrolled = Uuid::parse_str(ddns[1]["wan_pd_link_id"].as_str().unwrap()).unwrap();
        assert_ne!(local.to_string(), "11111111-1111-1111-1111-111111111111");
        assert_ne!(enrolled.to_string(), "22222222-2222-2222-2222-222222222222");
        assert_ne!(local, Uuid::nil());
        assert_ne!(enrolled, Uuid::nil());
        assert_ne!(local, enrolled);
        // null legacy mirror normalized to ""
        assert_eq!(ddns[1]["wan_pd_id"], "");
    }

    #[tokio::test]
    async fn lan_v6_blank_name_parents_keep_their_link_ids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"slaac","lifetime":300,"prefix_groups":[{"group_id":"g0","parent":{"t":"pd","depend_iface":"","link_id":"22222222-2222-2222-2222-222222222222","expected_pd_len_snapshot":56}}]}',
                    1.0);
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // The pd-parent link id is serde-defaulted on the new type, so a
        // blank-name parent keeps its stored id verbatim (a stale value
        // degrades instead of poisoning the read); no link is created.
        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        assert_eq!(
            config["prefix_groups"][0]["parent"]["link_id"],
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(config["prefix_groups"][0]["parent"]["depend_iface"], "");

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

    #[tokio::test]
    async fn ddns_null_name_sources_get_fresh_dangling_link_ids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'77777777777777777777777777777777', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":null,"family":"ipv4"},
                      {"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":null,"family":"ipv6"},
                      {"t":"enrolled_device","device_id":"44444444-4444-4444-4444-444444444444","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');
        "#)
            .await
            .unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // Both link-id fields are mandatory uuids after the migration: a
        // null/absent legacy name gets a fresh (dangling) uuid so the row
        // stays readable instead of poisoning the whole table.
        let source = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        let local = Uuid::parse_str(source[0]["link_id"].as_str().unwrap()).unwrap();
        let enrolled = Uuid::parse_str(source[1]["wan_pd_link_id"].as_str().unwrap()).unwrap();
        let absent_field = Uuid::parse_str(source[2]["wan_pd_link_id"].as_str().unwrap()).unwrap();
        assert_ne!(local, Uuid::nil());
        assert_ne!(enrolled, Uuid::nil());
        assert_ne!(absent_field, Uuid::nil());
        // each source gets its own uuid (no shared sentinel)
        assert_ne!(enrolled, absent_field);

        // dangling refs must not create wan_links rows
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

    #[tokio::test]
    async fn flow_targets_without_usable_names_get_dangling_link_ids() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO iface_ip_service_configs (iface_name, enable, ip_model, update_at)
            VALUES ('wan0', TRUE, '{"t":"dhcpclient","default_router":true,"custome_opts":[]}', 1.0);

            INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, remark)
            VALUES (x'88888888888888888888888888888888', TRUE, 1, '[]',
                    '[{"target":{"t":"interface","name":"wan0"},"weight":1},
                      {"target":{"t":"interface","name":"","link_id":"00000000-0000-0000-0000-000000000000"},"weight":2},
                      {"target":{"t":"interface"},"weight":3},
                      {"target":{"t":"interface","name":null},"weight":4},
                      {"target":{"t":"netns","container_name":"c1"},"weight":5}]',
                    '');
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let uuids = link_uuids(&db).await;
        let flow = &query_json(&db, "SELECT packet_handle_iface_name FROM flow_configs").await[0];

        // A usable name resolves to the fresh uuid; the name stays in place.
        assert_eq!(flow[0]["target"]["link_id"], uuids["wan0"]);
        assert_eq!(flow[0]["target"]["name"], "wan0");

        // Blank/absent/null names: `link_id` and `name` are both mandatory on
        // the new type, so the stale/missing value is replaced with a fresh
        // dangling uuid and the name is normalized to "" — the row stays
        // readable for both the legacy and the new runtime.
        let dangled: Vec<Uuid> = [1usize, 2, 3]
            .iter()
            .map(|i| Uuid::parse_str(flow[*i]["target"]["link_id"].as_str().unwrap()).unwrap())
            .collect();
        for uuid in &dangled {
            assert_ne!(*uuid, Uuid::nil());
            assert!(!uuids.values().any(|v| v == &uuid.to_string()));
        }
        let distinct: std::collections::HashSet<_> = dangled.iter().collect();
        assert_eq!(distinct.len(), dangled.len(), "each target gets its own uuid");
        assert_eq!(flow[1]["target"]["name"], "");
        assert_eq!(flow[2]["target"]["name"], "");
        assert_eq!(flow[3]["target"]["name"], "");

        // Non-interface targets are untouched.
        assert!(flow[4]["target"].get("link_id").is_none());
        assert_eq!(flow[4]["target"]["container_name"], "c1");

        assert_eq!(uuids.len(), 1);
    }

    #[tokio::test]
    async fn lan_v6_missing_depend_iface_is_materialized() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"slaac","lifetime":300,"prefix_groups":[{"group_id":"g0","parent":{"t":"pd","expected_pd_len_snapshot":56}},{"group_id":"g1","parent":{"t":"pd","depend_iface":null,"expected_pd_len_snapshot":56}}]}',
                    1.0);
        "#).await.unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // `depend_iface` is a mandatory String on the legacy type: null and
        // missing are both normalized to "" so a downgraded binary can still
        // read the row. Neither parent resolves a link, and the serde-defaulted
        // `link_id` is left untouched.
        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        assert_eq!(config["prefix_groups"][0]["parent"]["depend_iface"], "");
        assert!(config["prefix_groups"][0]["parent"].get("link_id").is_none());
        assert_eq!(config["prefix_groups"][1]["parent"]["depend_iface"], "");
        assert!(config["prefix_groups"][1]["parent"].get("link_id").is_none());

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

    #[tokio::test]
    async fn down_keeps_references_intact() {
        let db = test_db().await;
        db.execute_unprepared(r#"
            INSERT INTO ddns_jobs (id, name, enable, source, zone_name, provider_profile_id, ttl, records)
            VALUES (x'88888888888888888888888888888888', 'j', TRUE,
                    '[{"t":"local_wan","iface_name":"wan0","family":"ipv4"},
                      {"t":"local_wan","iface_name":"","family":"ipv4"},
                      {"t":"enrolled_device","device_id":"33333333-3333-3333-3333-333333333333","wan_pd_id":"pd0","family":"ipv6"},
                      {"t":"enrolled_device","device_id":"44444444-4444-4444-4444-444444444444","family":"ipv6"}]',
                    'e.com', x'44444444444444444444444444444444', 300, '[]');

            INSERT INTO lan_ipv6_service_configs_v2 (iface_name, enable, config, update_at)
            VALUES ('lan0', TRUE,
                    '{"mode":"slaac","lifetime":300,"prefix_groups":[
                       {"group_id":"keep","parent":{"t":"pd","depend_iface":"pd0","expected_pd_len_snapshot":56}},
                       {"group_id":"drop","parent":{"t":"pd","depend_iface":"","expected_pd_len_snapshot":56}},
                       {"group_id":"static","parent":{"t":"static","base_prefix":"fd00::","parent_prefix_len":60}}]}',
                     1.0);
        "#)
            .await
            .unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        Migration.down(&SchemaManager::new(&db)).await.unwrap();

        // The legacy name mirrors are dual-written by the runtime, so the
        // downgrade must not drop any reference; it only drops the uuid
        // columns and the wan_links table.
        let source = &query_json(&db, "SELECT source FROM ddns_jobs").await[0];
        let sources: &Vec<serde_json::Value> = source.as_array().unwrap();
        assert_eq!(sources.len(), 4);

        let config = &query_json(&db, "SELECT config FROM lan_ipv6_service_configs_v2").await[0];
        let groups = config["prefix_groups"].as_array().unwrap();
        let group_ids: Vec<&str> = groups.iter().map(|g| g["group_id"].as_str().unwrap()).collect();
        assert_eq!(group_ids, vec!["keep", "drop", "static"]);
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
