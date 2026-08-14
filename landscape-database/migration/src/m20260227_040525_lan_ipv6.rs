use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::lan_ipv6::LanIPv6ServiceConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Create new table
        manager
            .create_table(
                Table::create()
                    .table(LanIPv6ServiceConfigs::Table)
                    .if_not_exists()
                    .col(string(LanIPv6ServiceConfigs::IfaceName).primary_key())
                    .col(boolean(LanIPv6ServiceConfigs::Enable))
                    .col(json_null(LanIPv6ServiceConfigs::Config))
                    .col(double(LanIPv6ServiceConfigs::UpdateAt).default(0.0))
                    .to_owned(),
            )
            .await?;

        // 2. Copy all rows from old table to new table, migrating JSON config
        let db = manager.get_connection();

        // First, copy rows as-is (serde(default) handles the new `mode` field)
        db.execute_unprepared(
            "INSERT INTO lan_ipv6_service_configs (iface_name, enable, config, update_at) \
             SELECT iface_name, enable, config, update_at FROM ipv6_ra_service_configs",
        )
        .await?;

        // 3. Migrate JSON: convert old source/dhcpv6.source to new flat sources list
        // Read all rows and update each one
        let rows = db
            .query_all(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT iface_name, config FROM lan_ipv6_service_configs".to_string(),
            ))
            .await?;

        for row in rows {
            let iface_name: String = row.try_get("", "iface_name")?;
            let config_str: String = row.try_get("", "config")?;

            if let Ok(mut config_json) = serde_json::from_str::<serde_json::Value>(&config_str) {
                let migrated = migrate_config_json(&mut config_json);
                if migrated {
                    let new_config_str = serde_json::to_string(&config_json).unwrap_or(config_str);
                    db.execute_unprepared(&format!(
                        "UPDATE lan_ipv6_service_configs SET config = '{}' WHERE iface_name = '{}'",
                        new_config_str.replace('\'', "''"),
                        iface_name.replace('\'', "''")
                    ))
                    .await?;
                }
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(LanIPv6ServiceConfigs::Table).to_owned()).await?;
        Ok(())
    }
}

/// Migrate old config JSON to new format:
/// - config.source[i] → config.sources[i] (converted to new LanIPv6SourceConfig variants)
/// - config.dhcpv6.source[i] → appended to config.sources
/// - config.dhcpv6.source removed
/// - config.dhcpv6.ia_pd.max_source_prefix_len, pool_start_index, pool_end_index removed
///
/// Returns true if any migration was performed.
fn migrate_config_json(config: &mut serde_json::Value) -> bool {
    let mut migrated = false;
    let mut new_sources: Vec<serde_json::Value> = Vec::new();

    // Extract ia_pd info for PD source migration
    let ia_pd_info = config.get("dhcpv6").and_then(|d| d.get("ia_pd")).and_then(|pd| {
        let delegate_prefix_len = pd.get("delegate_prefix_len")?.as_u64()? as u8;
        let max_source_prefix_len =
            pd.get("max_source_prefix_len").and_then(|v| v.as_u64()).unwrap_or(56) as u8;
        let pool_start_index =
            pd.get("pool_start_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        Some((delegate_prefix_len, max_source_prefix_len, pool_start_index))
    });

    let ia_na_exists = config.get("dhcpv6").and_then(|d| d.get("ia_na")).is_some();

    let _ia_pd_exists = ia_pd_info.is_some();

    // 1. Migrate config.source → config.sources (RA sources)
    if let Some(old_sources) = config.get("source").and_then(|s| s.as_array()).cloned() {
        for src in old_sources {
            if let Some(new_src) = migrate_ra_source(&src) {
                new_sources.push(new_src);
            }
        }
        migrated = true;
    }

    // 2. Migrate config.dhcpv6.source → append to config.sources (Na/Pd sources)
    if let Some(dhcpv6_sources) =
        config.get("dhcpv6").and_then(|d| d.get("source")).and_then(|s| s.as_array()).cloned()
    {
        for src in dhcpv6_sources {
            // Add NA source if ia_na exists
            if ia_na_exists {
                if let Some(na_src) = migrate_na_source(&src) {
                    new_sources.push(na_src);
                }
            }
            // Add PD source if ia_pd exists
            if let Some((delegate_prefix_len, max_source_prefix_len, pool_start_index)) = ia_pd_info
            {
                if let Some(pd_src) = migrate_pd_source(
                    &src,
                    delegate_prefix_len,
                    max_source_prefix_len,
                    pool_start_index,
                ) {
                    new_sources.push(pd_src);
                }
            }
        }
        migrated = true;
    }

    if migrated {
        // Set new sources field
        config["sources"] = serde_json::Value::Array(new_sources);
        // Remove old source field
        config.as_object_mut().map(|m| m.remove("source"));

        // Clean up dhcpv6
        if let Some(dhcpv6) = config.get_mut("dhcpv6") {
            dhcpv6.as_object_mut().map(|m| m.remove("source"));
            // Clean up ia_pd: remove old fields
            if let Some(ia_pd) = dhcpv6.get_mut("ia_pd") {
                if let Some(m) = ia_pd.as_object_mut() {
                    m.remove("max_source_prefix_len");
                    m.remove("pool_start_index");
                    m.remove("pool_end_index");
                }
            }
        }
    }

    migrated
}

/// Convert old RA source to new RaStatic/RaPd
fn migrate_ra_source(src: &serde_json::Value) -> Option<serde_json::Value> {
    let t = src.get("t")?.as_str()?;
    match t {
        "static" => {
            let base_prefix = src.get("base_prefix")?.as_str()?;
            let pool_index = src.get("sub_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let preferred_lifetime =
                src.get("ra_preferred_lifetime").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
            let valid_lifetime =
                src.get("ra_valid_lifetime").and_then(|v| v.as_u64()).unwrap_or(600) as u32;
            Some(serde_json::json!({
                "t": "ra_static",
                "base_prefix": base_prefix,
                "pool_index": pool_index,
                "preferred_lifetime": preferred_lifetime,
                "valid_lifetime": valid_lifetime,
            }))
        }
        "pd" => {
            let depend_iface = src.get("depend_iface")?.as_str()?;
            let pool_index = src.get("subnet_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let preferred_lifetime =
                src.get("ra_preferred_lifetime").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
            let valid_lifetime =
                src.get("ra_valid_lifetime").and_then(|v| v.as_u64()).unwrap_or(600) as u32;
            Some(serde_json::json!({
                "t": "ra_pd",
                "depend_iface": depend_iface,
                "pool_index": pool_index,
                "preferred_lifetime": preferred_lifetime,
                "valid_lifetime": valid_lifetime,
            }))
        }
        _ => None,
    }
}

/// Convert old DHCPv6 source to NaStatic/NaPd
fn migrate_na_source(src: &serde_json::Value) -> Option<serde_json::Value> {
    let t = src.get("t")?.as_str()?;
    match t {
        "static" => {
            let base_prefix = src.get("base_prefix")?.as_str()?;
            let pool_index = src.get("sub_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            Some(serde_json::json!({
                "t": "na_static",
                "base_prefix": base_prefix,
                "pool_index": pool_index,
            }))
        }
        "pd" => {
            let depend_iface = src.get("depend_iface")?.as_str()?;
            let pool_index = src.get("subnet_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            Some(serde_json::json!({
                "t": "na_pd",
                "depend_iface": depend_iface,
                "pool_index": pool_index,
            }))
        }
        _ => None,
    }
}

/// Convert old DHCPv6 source to PdStatic/PdPd
fn migrate_pd_source(
    src: &serde_json::Value,
    delegate_prefix_len: u8,
    max_source_prefix_len: u8,
    pool_start_index: u32,
) -> Option<serde_json::Value> {
    let t = src.get("t")?.as_str()?;
    match t {
        "static" => {
            let base_prefix = src.get("base_prefix")?.as_str()?;
            let base_prefix_len =
                src.get("sub_prefix_len").and_then(|v| v.as_u64()).unwrap_or(48) as u8;
            Some(serde_json::json!({
                "t": "pd_static",
                "base_prefix": base_prefix,
                "base_prefix_len": base_prefix_len,
                "pool_index": 0,
                "pool_len": delegate_prefix_len,
            }))
        }
        "pd" => {
            let depend_iface = src.get("depend_iface")?.as_str()?;
            Some(serde_json::json!({
                "t": "pd_pd",
                "depend_iface": depend_iface,
                "max_source_prefix_len": max_source_prefix_len,
                "pool_index": pool_start_index,
                "pool_len": delegate_prefix_len,
            }))
        }
        _ => None,
    }
}
