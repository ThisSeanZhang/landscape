use std::collections::{HashMap, HashSet};

use sea_orm_migration::{prelude::*, sea_orm::FromQueryResult};
use serde_json::{Value, json};
use uuid::Uuid;

use super::tables::{cert::Certs, dns_provider_profile::DnsProviderProfiles};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
struct CertRow {
    id: Uuid,
    name: String,
    cert_type: String,
}

#[derive(Debug, FromQueryResult)]
struct DnsProviderProfileRow {
    id: Uuid,
    name: String,
    provider_config: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DnsProviderProfiles::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(DnsProviderProfiles::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(DnsProviderProfiles::Name).string().not_null())
                    .col(ColumnDef::new(DnsProviderProfiles::ProviderConfig).json().not_null())
                    .col(ColumnDef::new(DnsProviderProfiles::Remark).text())
                    .col(ColumnDef::new(DnsProviderProfiles::DdnsDefaultTtl).unsigned())
                    .col(
                        ColumnDef::new(DnsProviderProfiles::UpdateAt)
                            .double()
                            .not_null()
                            .default(0.0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-dns-provider-profiles-name")
                    .table(DnsProviderProfiles::Table)
                    .col(DnsProviderProfiles::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        migrate_cert_dns_providers_to_profiles(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        restore_cert_dns_providers_from_profiles(manager).await?;
        manager.drop_table(Table::drop().table(DnsProviderProfiles::Table).to_owned()).await
    }
}

async fn migrate_cert_dns_providers_to_profiles(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let select = Query::select()
        .columns([Certs::Id, Certs::Name, Certs::CertType])
        .from(Certs::Table)
        .to_owned();

    let builder = manager.get_database_backend();
    let db = manager.get_connection();
    let rows: Vec<CertRow> = CertRow::find_by_statement(builder.build(&select)).all(db).await?;

    let mut profile_ids_by_config = HashMap::<String, Uuid>::new();
    let mut used_names = HashSet::<String>::new();

    for row in rows {
        let Ok(mut cert_type) = serde_json::from_str::<Value>(&row.cert_type) else {
            continue;
        };
        let Some(provider_config) = extract_dns_provider_config(&cert_type) else {
            continue;
        };

        let provider_key = serde_json::to_string(&provider_config).unwrap_or_default();
        let profile_id = if let Some(existing_id) = profile_ids_by_config.get(&provider_key) {
            *existing_id
        } else {
            let profile_id = Uuid::new_v4();
            let provider_kind = dns_provider_kind(&provider_config);
            let profile_name =
                next_migrated_profile_name(&mut used_names, &row.name, provider_kind);
            let insert = Query::insert()
                .into_table(DnsProviderProfiles::Table)
                .columns([
                    DnsProviderProfiles::Id,
                    DnsProviderProfiles::Name,
                    DnsProviderProfiles::ProviderConfig,
                    DnsProviderProfiles::Remark,
                    DnsProviderProfiles::DdnsDefaultTtl,
                    DnsProviderProfiles::UpdateAt,
                ])
                .values_panic([
                    profile_id.into(),
                    profile_name.into(),
                    provider_key.clone().into(),
                    Some(format!("Migrated from certificate '{}'", row.name)).into(),
                    default_ddns_ttl_for_provider(provider_kind).into(),
                    0.0.into(),
                ])
                .to_owned();
            manager.exec_stmt(insert).await?;
            profile_ids_by_config.insert(provider_key.clone(), profile_id);
            profile_id
        };

        if rewrite_cert_dns_provider_to_profile_id(&mut cert_type, profile_id) {
            let update = Query::update()
                .table(Certs::Table)
                .values([(Certs::CertType, serde_json::to_string(&cert_type).unwrap().into())])
                .and_where(Expr::col(Certs::Id).eq(row.id))
                .to_owned();
            manager.exec_stmt(update).await?;
        }
    }

    Ok(())
}

async fn restore_cert_dns_providers_from_profiles(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let builder = manager.get_database_backend();
    let db = manager.get_connection();

    let profile_select = Query::select()
        .columns([
            DnsProviderProfiles::Id,
            DnsProviderProfiles::Name,
            DnsProviderProfiles::ProviderConfig,
        ])
        .from(DnsProviderProfiles::Table)
        .to_owned();
    let profile_rows: Vec<DnsProviderProfileRow> =
        DnsProviderProfileRow::find_by_statement(builder.build(&profile_select)).all(db).await?;
    let mut provider_config_by_id = HashMap::<Uuid, Value>::new();
    for row in profile_rows {
        let provider_config =
            serde_json::from_str::<Value>(&row.provider_config).map_err(|err| {
                DbErr::Custom(format!(
                    "failed to parse provider_config for dns provider profile '{}' ({}): {}",
                    row.name, row.id, err
                ))
            })?;
        provider_config_by_id.insert(row.id, provider_config);
    }

    let cert_select = Query::select()
        .columns([Certs::Id, Certs::Name, Certs::CertType])
        .from(Certs::Table)
        .to_owned();
    let cert_rows: Vec<CertRow> =
        CertRow::find_by_statement(builder.build(&cert_select)).all(db).await?;

    let mut pending_updates = Vec::<(Uuid, String)>::new();

    for row in cert_rows {
        let mut cert_type = serde_json::from_str::<Value>(&row.cert_type).map_err(|err| {
            DbErr::Custom(format!(
                "failed to parse cert_type for cert '{}' ({}): {}",
                row.name, row.id, err
            ))
        })?;
        let Some(profile_id) = extract_dns_provider_profile_id(&cert_type) else {
            continue;
        };
        let provider_config = provider_config_by_id.get(&profile_id).ok_or_else(|| {
            DbErr::Custom(format!(
                "cannot rollback cert '{}' ({}): referenced dns provider profile {} not found",
                row.name, row.id, profile_id
            ))
        })?;

        if !rewrite_cert_profile_id_to_dns_provider(&mut cert_type, provider_config.clone()) {
            return Err(DbErr::Custom(format!(
                "cannot rollback cert '{}' ({}): failed to rewrite provider profile reference",
                row.name, row.id
            )));
        }

        pending_updates.push((row.id, serde_json::to_string(&cert_type).unwrap()));
    }

    for (cert_id, cert_type) in pending_updates {
        let update = Query::update()
            .table(Certs::Table)
            .values([(Certs::CertType, cert_type.into())])
            .and_where(Expr::col(Certs::Id).eq(cert_id))
            .to_owned();
        manager.exec_stmt(update).await?;
    }

    Ok(())
}

fn extract_dns_provider_config(cert_type: &Value) -> Option<Value> {
    cert_type.get("t").and_then(Value::as_str).filter(|kind| *kind == "acme")?;
    cert_type.get("challenge_type")?.get("dns")?.get("dns_provider").cloned()
}

fn extract_dns_provider_profile_id(cert_type: &Value) -> Option<Uuid> {
    cert_type.get("t").and_then(Value::as_str).filter(|kind| *kind == "acme")?;
    cert_type
        .get("challenge_type")?
        .get("dns")?
        .get("provider_profile_id")?
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn rewrite_cert_dns_provider_to_profile_id(cert_type: &mut Value, profile_id: Uuid) -> bool {
    let Some(cert_type_obj) = cert_type.as_object_mut() else {
        return false;
    };
    if cert_type_obj.get("t").and_then(Value::as_str) != Some("acme") {
        return false;
    }
    let Some(challenge_type) = cert_type_obj.get_mut("challenge_type") else {
        return false;
    };
    let Some(challenge_type_obj) = challenge_type.as_object_mut() else {
        return false;
    };
    let Some(dns) = challenge_type_obj.get_mut("dns") else {
        return false;
    };
    let Some(dns_obj) = dns.as_object_mut() else {
        return false;
    };

    dns_obj.remove("dns_provider");
    dns_obj.insert("provider_profile_id".to_string(), json!(profile_id));

    true
}

fn rewrite_cert_profile_id_to_dns_provider(cert_type: &mut Value, provider_config: Value) -> bool {
    let Some(cert_type_obj) = cert_type.as_object_mut() else {
        return false;
    };
    if cert_type_obj.get("t").and_then(Value::as_str) != Some("acme") {
        return false;
    }
    let Some(challenge_type) = cert_type_obj.get_mut("challenge_type") else {
        return false;
    };
    let Some(challenge_type_obj) = challenge_type.as_object_mut() else {
        return false;
    };
    let Some(dns) = challenge_type_obj.get_mut("dns") else {
        return false;
    };
    let Some(dns_obj) = dns.as_object_mut() else {
        return false;
    };

    dns_obj.remove("provider_profile_id");
    dns_obj.insert("dns_provider".to_string(), provider_config);

    true
}

fn dns_provider_kind(provider_config: &Value) -> &str {
    if let Some(kind) = provider_config.as_str() {
        return kind;
    }
    provider_config
        .as_object()
        .and_then(|obj| obj.keys().next().map(String::as_str))
        .unwrap_or("dns")
}

fn default_ddns_ttl_for_provider(provider_kind: &str) -> Option<u32> {
    match provider_kind {
        "aliyun" => Some(600),
        _ => Some(120),
    }
}

fn next_migrated_profile_name(
    used_names: &mut HashSet<String>,
    cert_name: &str,
    provider_kind: &str,
) -> String {
    let sanitized_name = cert_name.trim();
    let base_name = if sanitized_name.is_empty() {
        format!("Migrated {} DNS profile", provider_kind)
    } else {
        format!("{} ({})", sanitized_name, provider_kind)
    };
    if used_names.insert(base_name.clone()) {
        return base_name;
    }

    let mut index = 2;
    loop {
        let candidate = format!("{} #{}", base_name, index);
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
        index += 1;
    }
}
