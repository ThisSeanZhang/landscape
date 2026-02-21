use crate::sea_orm::Statement;
use sea_orm_migration::prelude::*;

use super::tables::dhcp_v4_server::DHCPv4ServerConfigs;
use super::tables::mac_binding::IpMacBinding;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IpMacBinding::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IpMacBinding::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpMacBinding::UpdateAt).double().not_null())
                    .col(ColumnDef::new(IpMacBinding::IfaceName).string())
                    .col(ColumnDef::new(IpMacBinding::Name).string().not_null())
                    .col(ColumnDef::new(IpMacBinding::FakeName).string())
                    .col(ColumnDef::new(IpMacBinding::Remark).string())
                    .col(ColumnDef::new(IpMacBinding::Mac).string().not_null())
                    .col(ColumnDef::new(IpMacBinding::Ipv4).string())
                    .col(ColumnDef::new(IpMacBinding::Ipv4Int).unsigned())
                    .col(ColumnDef::new(IpMacBinding::Ipv6).string())
                    .col(ColumnDef::new(IpMacBinding::Tag).json().not_null())
                    .to_owned(),
            )
            .await?;

        // Add the column to existing DHCP configs if it doesn't exist
        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv4ServerConfigs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DHCPv4ServerConfigs::NetworkStart)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv4ServerConfigs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DHCPv4ServerConfigs::NetworkEnd)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Populate NetworkStart/NetworkEnd from existing data
        let db = manager.get_connection();
        let rows = db
            .query_all(Statement::from_string(
                manager.get_database_backend(),
                "SELECT iface_name, server_ip_addr, network_mask FROM dhcp_v4_server_configs",
            ))
            .await?;

        for row in rows {
            let iface_name: String = row.try_get("", "iface_name")?;
            let server_ip_str: String = row.try_get("", "server_ip_addr")?;
            let mask: u8 = row.try_get("", "network_mask")?;

            if let Ok(ip) = server_ip_str.parse::<std::net::Ipv4Addr>() {
                let ip_u32 = u32::from(ip);
                let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
                let network_start = ip_u32 & mask_u32;
                let network_end = network_start | !mask_u32;

                db.execute(Statement::from_sql_and_values(
                    manager.get_database_backend(),
                    "UPDATE dhcp_v4_server_configs SET network_start = ?, network_end = ? WHERE iface_name = ?",
                    [network_start.into(), network_end.into(), iface_name.into()],
                ))
                .await?;
            }
        }

        manager
            .create_index(
                Index::create()
                    .name("idx-mac-binding-mac")
                    .table(IpMacBinding::Table)
                    .col(IpMacBinding::Mac)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Partial unique index: only enforce uniqueness when ipv4_int is not null.
        // This allows multiple bindings without an IP while preventing two MACs
        // from being assigned the same static IPv4 address.
        db.execute(sea_orm::Statement::from_string(
            manager.get_database_backend(),
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_mac_binding_ipv4_int \
             ON ip_mac_bindings (ipv4_int) WHERE ipv4_int IS NOT NULL",
        ))
        .await?;

        // Populate IpMacBinding from existing DHCP MacBindingRecords
        let rows = db
            .query_all(Statement::from_string(
                manager.get_database_backend(),
                "SELECT iface_name, mac_binding_records FROM dhcp_v4_server_configs WHERE mac_binding_records IS NOT NULL",
            ))
            .await?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        for row in rows {
            let iface_name: String = row.try_get("", "iface_name")?;
            let records_json: Option<serde_json::Value> = row.try_get("", "mac_binding_records")?;

            if let Some(records) = records_json {
                if let Some(records_array) = records.as_array() {
                    for record in records_array {
                        let mac = record.get("mac").and_then(|m| m.as_str());
                        let ip = record.get("ip").and_then(|i| i.as_str());

                        if let (Some(mac_str), Some(ip_str)) = (mac, ip) {
                            let ip_u32 = if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
                                Some(u32::from(ipv4))
                            } else {
                                None
                            };

                            db.execute(Statement::from_sql_and_values(
                                manager.get_database_backend(),
                                "INSERT OR IGNORE INTO ip_mac_bindings (id, update_at, iface_name, name, mac, ipv4, ipv4_int, tag) 
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                [
                                    uuid::Uuid::new_v4().into(),
                                    timestamp.into(),
                                    iface_name.clone().into(),
                                    format!("DHCP: {}", iface_name).into(),
                                    mac_str.into(),
                                    ip_str.into(),
                                    ip_u32.into(),
                                    serde_json::Value::Array(vec![]).into(),
                                ],
                            ))
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute(sea_orm::Statement::from_string(
            manager.get_database_backend(),
            "DROP INDEX IF EXISTS idx_mac_binding_ipv4_int",
        ))
        .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv4ServerConfigs::Table)
                    .drop_column(DHCPv4ServerConfigs::NetworkStart)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv4ServerConfigs::Table)
                    .drop_column(DHCPv4ServerConfigs::NetworkEnd)
                    .to_owned(),
            )
            .await?;

        manager.drop_table(Table::drop().table(IpMacBinding::Table).to_owned()).await
    }
}
