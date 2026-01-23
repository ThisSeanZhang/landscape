use sea_orm_migration::{prelude::*, schema::*, sea_orm::FromQueryResult};
use uuid::Uuid;

use crate::tables::nat::StaticNatMappingConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm_migration::sea_orm::{ConnectionTrait, TransactionTrait};

        let db = manager.get_connection();

        // Wrap everything in a transaction to ensure data safety
        let txn = db.begin().await?;

        // 1. Query all existing static NAT mapping configs to preserve data
        let select = Query::select()
            .columns([
                Alias::new("id"),
                Alias::new("enable"),
                Alias::new("remark"),
                Alias::new("wan_port"),
                Alias::new("wan_iface_name"),
                Alias::new("lan_port"),
                Alias::new("lan_ipv4"),
                Alias::new("lan_ipv6"),
                Alias::new("ipv4_l4_protocol"),
                Alias::new("ipv6_l4_protocol"),
                Alias::new("update_at"),
            ])
            .from(Alias::new("static_nat_mapping_configs"))
            .to_owned();

        let builder = manager.get_database_backend();
        let rows: Vec<OldStaticNatMappingConfigRow> =
            OldStaticNatMappingConfigRow::find_by_statement(builder.build(&select))
                .all(&txn)
                .await?;

        // 2. Drop old table
        txn.execute(builder.build(&Table::drop().table(StaticNatMappingConfigs::Table).to_owned()))
            .await?;

        // 3. Create new table with mapping_pair_ports field
        txn.execute(
            builder.build(
                &Table::create()
                    .table(StaticNatMappingConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(StaticNatMappingConfigs::Id).uuid().primary_key())
                    .col(ColumnDef::new(StaticNatMappingConfigs::Enable).boolean().default(false))
                    .col(string_null(StaticNatMappingConfigs::Remark))
                    .col(json(StaticNatMappingConfigs::MappingPairPorts))
                    .col(string_null(StaticNatMappingConfigs::WanIfaceName))
                    .col(string_null(StaticNatMappingConfigs::LanIpv4))
                    .col(string_null(StaticNatMappingConfigs::LanIpv6))
                    .col(json(StaticNatMappingConfigs::Ipv4L4Protocol))
                    .col(json(StaticNatMappingConfigs::Ipv6L4Protocol))
                    .col(double(StaticNatMappingConfigs::UpdateAt).default(0))
                    .to_owned(),
            ),
        )
        .await?;

        // 4. Migrate existing data: convert single port pair to array of port pairs
        // Use batch insert for better performance
        if !rows.is_empty() {
            let mut insert = Query::insert()
                .into_table(StaticNatMappingConfigs::Table)
                .columns([
                    StaticNatMappingConfigs::Id,
                    StaticNatMappingConfigs::Enable,
                    StaticNatMappingConfigs::Remark,
                    StaticNatMappingConfigs::MappingPairPorts,
                    StaticNatMappingConfigs::WanIfaceName,
                    StaticNatMappingConfigs::LanIpv4,
                    StaticNatMappingConfigs::LanIpv6,
                    StaticNatMappingConfigs::Ipv4L4Protocol,
                    StaticNatMappingConfigs::Ipv6L4Protocol,
                    StaticNatMappingConfigs::UpdateAt,
                ])
                .to_owned();

            for row in rows {
                // Convert single port pair to array of port pair objects
                let mapping_pair_ports = serde_json::json!([{
                    "wan_port": row.wan_port,
                    "lan_port": row.lan_port
                }]);

                // Parse ipv4_l4_protocol and ipv6_l4_protocol as JSON values
                let ipv4_l4_protocol: serde_json::Value =
                    serde_json::from_str(&row.ipv4_l4_protocol)
                        .unwrap_or_else(|_| serde_json::json!(null));
                let ipv6_l4_protocol: serde_json::Value =
                    serde_json::from_str(&row.ipv6_l4_protocol)
                        .unwrap_or_else(|_| serde_json::json!(null));

                insert.values_panic([
                    row.id.into(),
                    row.enable.into(),
                    row.remark.into(),
                    mapping_pair_ports.into(),
                    row.wan_iface_name.into(),
                    row.lan_ipv4.into(),
                    row.lan_ipv6.into(),
                    ipv4_l4_protocol.into(),
                    ipv6_l4_protocol.into(),
                    row.update_at.into(),
                ]);
            }

            txn.execute(builder.build(&insert)).await?;
        }

        // Commit the transaction
        txn.commit().await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm_migration::sea_orm::{ConnectionTrait, TransactionTrait};

        let db = manager.get_connection();

        // Wrap everything in a transaction to ensure data safety
        let txn = db.begin().await?;

        // 1. Query all existing static NAT mapping configs
        let select = Query::select()
            .columns([
                Alias::new("id"),
                Alias::new("enable"),
                Alias::new("remark"),
                Alias::new("mapping_pair_ports"),
                Alias::new("wan_iface_name"),
                Alias::new("lan_ipv4"),
                Alias::new("lan_ipv6"),
                Alias::new("ipv4_l4_protocol"),
                Alias::new("ipv6_l4_protocol"),
                Alias::new("update_at"),
            ])
            .from(Alias::new("static_nat_mapping_configs"))
            .to_owned();

        let builder = manager.get_database_backend();
        let rows: Vec<NewStaticNatMappingConfigRow> =
            NewStaticNatMappingConfigRow::find_by_statement(builder.build(&select))
                .all(&txn)
                .await?;

        // 2. Drop new table
        txn.execute(builder.build(&Table::drop().table(StaticNatMappingConfigs::Table).to_owned()))
            .await?;

        // 3. Recreate old table structure with single port fields
        txn.execute(
            builder.build(
                &Table::create()
                    .table(StaticNatMappingConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(StaticNatMappingConfigs::Id).uuid().primary_key())
                    .col(ColumnDef::new(StaticNatMappingConfigs::Enable).boolean().default(false))
                    .col(string_null(StaticNatMappingConfigs::Remark))
                    .col(integer(StaticNatMappingConfigs::WanPort))
                    .col(string_null(StaticNatMappingConfigs::WanIfaceName))
                    .col(integer(StaticNatMappingConfigs::LanPort))
                    .col(string_null(StaticNatMappingConfigs::LanIpv4))
                    .col(string_null(StaticNatMappingConfigs::LanIpv6))
                    .col(json(StaticNatMappingConfigs::Ipv4L4Protocol))
                    .col(json(StaticNatMappingConfigs::Ipv6L4Protocol))
                    .col(double(StaticNatMappingConfigs::UpdateAt).default(0))
                    .to_owned(),
            ),
        )
        .await?;

        // 4. Restore data: extract first port pair from mapping_pair_ports array
        // Use batch insert for better performance
        if !rows.is_empty() {
            let mut insert = Query::insert()
                .into_table(StaticNatMappingConfigs::Table)
                .columns([
                    StaticNatMappingConfigs::Id,
                    StaticNatMappingConfigs::Enable,
                    StaticNatMappingConfigs::Remark,
                    StaticNatMappingConfigs::WanPort,
                    StaticNatMappingConfigs::WanIfaceName,
                    StaticNatMappingConfigs::LanPort,
                    StaticNatMappingConfigs::LanIpv4,
                    StaticNatMappingConfigs::LanIpv6,
                    StaticNatMappingConfigs::Ipv4L4Protocol,
                    StaticNatMappingConfigs::Ipv6L4Protocol,
                    StaticNatMappingConfigs::UpdateAt,
                ])
                .to_owned();

            for row in rows {
                let mapping_pair_ports: Result<Vec<serde_json::Value>, _> =
                    serde_json::from_str(&row.mapping_pair_ports);

                // Extract first port pair, or use default values
                let (wan_port, lan_port) = if let Ok(pairs) = mapping_pair_ports {
                    if let Some(first_pair) = pairs.first() {
                        (
                            first_pair["wan_port"].as_u64().unwrap_or(0) as u16,
                            first_pair["lan_port"].as_u64().unwrap_or(0) as u16,
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

                // Parse ipv4_l4_protocol and ipv6_l4_protocol as JSON values
                let ipv4_l4_protocol: serde_json::Value =
                    serde_json::from_str(&row.ipv4_l4_protocol)
                        .unwrap_or_else(|_| serde_json::json!(null));
                let ipv6_l4_protocol: serde_json::Value =
                    serde_json::from_str(&row.ipv6_l4_protocol)
                        .unwrap_or_else(|_| serde_json::json!(null));

                insert.values_panic([
                    row.id.into(),
                    row.enable.into(),
                    row.remark.into(),
                    wan_port.into(),
                    row.wan_iface_name.into(),
                    lan_port.into(),
                    row.lan_ipv4.into(),
                    row.lan_ipv6.into(),
                    ipv4_l4_protocol.into(),
                    ipv6_l4_protocol.into(),
                    row.update_at.into(),
                ]);
            }

            txn.execute(builder.build(&insert)).await?;
        }

        // Commit the transaction
        txn.commit().await?;

        Ok(())
    }
}

/// Old table structure row for data preservation during upgrade
#[derive(FromQueryResult)]
struct OldStaticNatMappingConfigRow {
    id: Uuid,
    enable: bool,
    remark: Option<String>,
    wan_port: u16,
    wan_iface_name: Option<String>,
    lan_port: u16,
    lan_ipv4: Option<String>,
    lan_ipv6: Option<String>,
    ipv4_l4_protocol: String,
    ipv6_l4_protocol: String,
    update_at: f64,
}

/// New table structure row for rollback during downgrade
#[derive(FromQueryResult)]
struct NewStaticNatMappingConfigRow {
    id: Uuid,
    enable: bool,
    remark: Option<String>,
    mapping_pair_ports: String,
    wan_iface_name: Option<String>,
    lan_ipv4: Option<String>,
    lan_ipv6: Option<String>,
    ipv4_l4_protocol: String,
    ipv6_l4_protocol: String,
    update_at: f64,
}
