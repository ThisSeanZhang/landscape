use sea_orm_migration::{prelude::*, schema::*, sea_orm::FromQueryResult};
use uuid::Uuid;

use crate::tables::nat::{
    StaticNatMappingConfigs, StaticNatMappingV4Configs, StaticNatMappingV6Configs,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm_migration::sea_orm::{ConnectionTrait, TransactionTrait};

        let db = manager.get_connection();
        let txn = db.begin().await?;
        let builder = manager.get_database_backend();

        // 1. Create v4 table
        txn.execute(
            builder.build(
                &Table::create()
                    .table(StaticNatMappingV4Configs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(StaticNatMappingV4Configs::Id).uuid().primary_key())
                    .col(ColumnDef::new(StaticNatMappingV4Configs::Enable).boolean().default(false))
                    .col(string_null(StaticNatMappingV4Configs::Remark))
                    .col(json(StaticNatMappingV4Configs::MappingPairPorts))
                    .col(string_null(StaticNatMappingV4Configs::WanIfaceName))
                    .col(string_null(StaticNatMappingV4Configs::LanIpv4))
                    .col(json_null(StaticNatMappingV4Configs::LanTarget))
                    .col(json(StaticNatMappingV4Configs::L4Protocols))
                    .col(double(StaticNatMappingV4Configs::UpdateAt).default(0))
                    .to_owned(),
            ),
        )
        .await?;

        // 2. Create v6 table
        txn.execute(
            builder.build(
                &Table::create()
                    .table(StaticNatMappingV6Configs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(StaticNatMappingV6Configs::Id).uuid().primary_key())
                    .col(ColumnDef::new(StaticNatMappingV6Configs::Enable).boolean().default(false))
                    .col(string_null(StaticNatMappingV6Configs::Remark))
                    .col(json(StaticNatMappingV6Configs::PortConfig))
                    .col(string_null(StaticNatMappingV6Configs::WanIfaceName))
                    .col(string_null(StaticNatMappingV6Configs::LanIpv6))
                    .col(json_null(StaticNatMappingV6Configs::LanTarget))
                    .col(json(StaticNatMappingV6Configs::L4Protocols))
                    .col(double(StaticNatMappingV6Configs::UpdateAt).default(0))
                    .to_owned(),
            ),
        )
        .await?;

        // 3. Read all rows from old table
        let select = Query::select()
            .columns([
                Alias::new("id"),
                Alias::new("enable"),
                Alias::new("remark"),
                Alias::new("wan_iface_name"),
                Alias::new("mapping_pair_ports"),
                Alias::new("lan_target"),
                Alias::new("lan_ipv4"),
                Alias::new("lan_ipv6"),
                Alias::new("ipv4_l4_protocol"),
                Alias::new("ipv6_l4_protocol"),
                Alias::new("update_at"),
            ])
            .from(StaticNatMappingConfigs::Table)
            .to_owned();

        let rows: Vec<OldStaticNatRow> =
            OldStaticNatRow::find_by_statement(builder.build(&select)).all(&txn).await?;

        if rows.is_empty() {
            txn.commit().await?;
            return Ok(());
        }

        // 4. Migrate data
        for row in &rows {
            let ipv4_l4: serde_json::Value =
                serde_json::from_str(&row.ipv4_l4_protocol).unwrap_or(serde_json::json!([]));
            let ipv6_l4: serde_json::Value =
                serde_json::from_str(&row.ipv6_l4_protocol).unwrap_or(serde_json::json!([]));
            let mapping_ports: serde_json::Value =
                serde_json::from_str(&row.mapping_pair_ports).unwrap_or(serde_json::json!([]));

            let has_v4 = !matches!(&ipv4_l4, serde_json::Value::Array(a) if a.is_empty())
                && !matches!(&ipv4_l4, serde_json::Value::Null);
            let has_v6 = !matches!(&ipv6_l4, serde_json::Value::Array(a) if a.is_empty())
                && !matches!(&ipv6_l4, serde_json::Value::Null);

            let lan_target: Option<serde_json::Value> =
                row.lan_target.as_deref().and_then(|t| serde_json::from_str(t).ok());

            if has_v4 {
                let v4_target = build_v4_target(lan_target.as_ref(), row.lan_ipv4.as_deref());
                let insert = Query::insert()
                    .into_table(StaticNatMappingV4Configs::Table)
                    .columns([
                        StaticNatMappingV4Configs::Id,
                        StaticNatMappingV4Configs::Enable,
                        StaticNatMappingV4Configs::Remark,
                        StaticNatMappingV4Configs::MappingPairPorts,
                        StaticNatMappingV4Configs::WanIfaceName,
                        StaticNatMappingV4Configs::LanIpv4,
                        StaticNatMappingV4Configs::LanTarget,
                        StaticNatMappingV4Configs::L4Protocols,
                        StaticNatMappingV4Configs::UpdateAt,
                    ])
                    .values_panic([
                        Uuid::new_v4().into(),
                        row.enable.into(),
                        row.remark.clone().into(),
                        mapping_ports.clone().into(),
                        row.wan_iface_name.clone().into(),
                        row.lan_ipv4.clone().into(),
                        v4_target.into(),
                        ipv4_l4.into(),
                        row.update_at.into(),
                    ])
                    .to_owned();
                txn.execute(builder.build(&insert)).await?;
            }

            if has_v6 {
                let v6_target = build_v6_target(lan_target.as_ref(), row.lan_ipv6.as_deref());
                let v6_port_config = build_v6_port_config(&mapping_ports);
                let insert = Query::insert()
                    .into_table(StaticNatMappingV6Configs::Table)
                    .columns([
                        StaticNatMappingV6Configs::Id,
                        StaticNatMappingV6Configs::Enable,
                        StaticNatMappingV6Configs::Remark,
                        StaticNatMappingV6Configs::PortConfig,
                        StaticNatMappingV6Configs::WanIfaceName,
                        StaticNatMappingV6Configs::LanIpv6,
                        StaticNatMappingV6Configs::LanTarget,
                        StaticNatMappingV6Configs::L4Protocols,
                        StaticNatMappingV6Configs::UpdateAt,
                    ])
                    .values_panic([
                        Uuid::new_v4().into(),
                        row.enable.into(),
                        row.remark.clone().into(),
                        v6_port_config.into(),
                        row.wan_iface_name.clone().into(),
                        row.lan_ipv6.clone().into(),
                        v6_target.into(),
                        ipv6_l4.into(),
                        row.update_at.into(),
                    ])
                    .to_owned();
                txn.execute(builder.build(&insert)).await?;
            }
        }

        txn.commit().await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let builder = manager.get_database_backend();
        db.execute(
            builder.build(
                &Table::drop().table(StaticNatMappingV6Configs::Table).if_exists().to_owned(),
            ),
        )
        .await?;
        db.execute(
            builder.build(
                &Table::drop().table(StaticNatMappingV4Configs::Table).if_exists().to_owned(),
            ),
        )
        .await?;
        Ok(())
    }
}

#[derive(FromQueryResult)]
#[allow(dead_code)]
struct OldStaticNatRow {
    id: Uuid,
    enable: bool,
    remark: String,
    wan_iface_name: Option<String>,
    mapping_pair_ports: String,
    lan_target: Option<String>,
    lan_ipv4: Option<String>,
    lan_ipv6: Option<String>,
    ipv4_l4_protocol: String,
    ipv6_l4_protocol: String,
    update_at: f64,
}

fn build_v4_target(
    lan_target: Option<&serde_json::Value>,
    lan_ipv4: Option<&str>,
) -> Option<serde_json::Value> {
    if let Some(target) = lan_target {
        let t = target.get("t").and_then(|v| v.as_str());
        match t {
            Some("address") => {
                let ipv4 = target.get("ipv4").and_then(|v| v.as_str());
                let obj = serde_json::json!({"t": "address", "ipv4": ipv4});
                Some(obj)
            }
            Some("local") => Some(serde_json::json!({"t": "local"})),
            Some("device") => {
                let device_id = target.get("device_id").and_then(|v| v.as_str());
                let obj = serde_json::json!({"t": "device", "device_id": device_id});
                Some(obj)
            }
            _ => build_v4_target_from_ip(lan_ipv4),
        }
    } else {
        build_v4_target_from_ip(lan_ipv4)
    }
}

fn build_v4_target_from_ip(lan_ipv4: Option<&str>) -> Option<serde_json::Value> {
    let ipv4 = lan_ipv4?;
    if ipv4 == "0.0.0.0" {
        Some(serde_json::json!({"t": "local"}))
    } else {
        Some(serde_json::json!({"t": "address", "ipv4": ipv4}))
    }
}

fn build_v6_target(
    lan_target: Option<&serde_json::Value>,
    lan_ipv6: Option<&str>,
) -> Option<serde_json::Value> {
    if let Some(target) = lan_target {
        let t = target.get("t").and_then(|v| v.as_str());
        match t {
            Some("address") => {
                let ipv6 = target.get("ipv6").and_then(|v| v.as_str());
                let obj = serde_json::json!({"t": "address", "ipv6": ipv6});
                Some(obj)
            }
            Some("local") => Some(serde_json::json!({"t": "local"})),
            Some("device") => {
                let device_id = target.get("device_id").and_then(|v| v.as_str());
                match device_id {
                    Some(id) => {
                        let obj = serde_json::json!({"t": "device", "device_ids": [id]});
                        Some(obj)
                    }
                    None => build_v6_target_from_ip(lan_ipv6),
                }
            }
            _ => build_v6_target_from_ip(lan_ipv6),
        }
    } else {
        build_v6_target_from_ip(lan_ipv6)
    }
}

fn build_v6_target_from_ip(lan_ipv6: Option<&str>) -> Option<serde_json::Value> {
    let ipv6 = lan_ipv6?;
    if ipv6 == "::" {
        Some(serde_json::json!({"t": "local"}))
    } else {
        Some(serde_json::json!({"t": "address", "ipv6": ipv6}))
    }
}

fn build_v6_port_config(mapping_ports: &serde_json::Value) -> serde_json::Value {
    // The new v6 static-NAT system no longer supports per-pair WAN/LAN port
    // remapping — a single port list is shared for both sides.  We therefore
    // intentionally extract only lan_port from the legacy mapping_pair_ports
    // and use it for both wan_port and lan_port in the eBPF entries.
    let ports: Vec<u16> = mapping_ports
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| pair.get("lan_port").and_then(|v| v.as_u64()))
        .filter_map(|p| <u16 as TryFrom<_>>::try_from(p).ok())
        .filter(|&p| p != 0)
        .collect();

    if ports.is_empty() {
        serde_json::json!({"mode": "all"})
    } else {
        serde_json::json!({"mode": "ports", "ports": ports})
    }
}
