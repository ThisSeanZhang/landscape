use std::collections::HashMap;

use sea_orm_migration::{prelude::*, schema::*, sea_orm::FromQueryResult};
use uuid::Uuid;

use crate::tables::dns_rule::{DNSRuleConfigs, DNSUpstreamConfigs};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DNSUpstreamConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(DNSUpstreamConfigs::Id).uuid().not_null().primary_key())
                    .col(string_null(DNSUpstreamConfigs::Remark))
                    .col(json_null(DNSUpstreamConfigs::Mode))
                    .col(json_null(DNSUpstreamConfigs::Ips))
                    .col(ColumnDef::new(DNSUpstreamConfigs::Port).unsigned().null())
                    .col(double(DNSUpstreamConfigs::UpdateAt).default(0))
                    .to_owned(),
            )
            .await?;

        let uuid_bytes = Uuid::new_v4().as_bytes().to_vec();
        manager
            .alter_table(
                Table::alter()
                    .table(DNSRuleConfigs::Table)
                    .add_column(
                        ColumnDef::new(DNSRuleConfigs::UpstreamId)
                            .uuid()
                            .not_null()
                            .default(Expr::value(uuid_bytes)),
                    )
                    .to_owned(),
            )
            .await?;

        let select = Query::select()
            .columns([Alias::new("id"), Alias::new("resolve_mode")])
            .from(Alias::new("dns_rule_configs"))
            .to_owned();

        let builder = manager.get_database_backend();
        let db = manager.get_connection();
        let rows: Vec<RuleRow> = RuleRow::find_by_statement(builder.build(&select)).all(db).await?;
        let mut upstream_cache: HashMap<String, Uuid> = HashMap::new();

        for row in rows {
            let upstream_id = if let Some(cached_id) = upstream_cache.get(&row.resolve_mode) {
                *cached_id
            } else {
                let Ok(mode_value) = serde_json::from_str::<serde_json::Value>(&row.resolve_mode)
                else {
                    continue;
                };
                // let mode_value: Value = serde_json::from_str(&row.resolve_mode).unwrap_or(Value::Null);
                // // 生成新 ID
                let new_id = Uuid::new_v4();
                upstream_cache.insert(row.resolve_mode, new_id);

                let new_mode: String;
                let ips: String;
                let port: String;
                match mode_value["t"].as_str() {
                    Some("cloudflare") => {
                        let Some(mode) = mode_value["mode"].as_str() else {
                            continue;
                        };
                        match mode {
                            "plaintext" => {
                                new_mode = "{ \"t\": \"plaintext\"}".to_string();
                                port = "53".to_string();
                            }
                            "tls" => {
                                new_mode = "{ \"t\": \"tls\", \"domain\": \"cloudflare-dns.com\"}"
                                    .to_string();
                                port = "853".to_string();
                            }
                            "https" => {
                                new_mode =
                                    "{ \"t\": \"https\", \"domain\": \"cloudflare-dns.com\"}"
                                        .to_string();
                                port = "443".to_string();
                            }
                            _ => continue,
                        }
                        ips = "[\"1.1.1.1\", \"1.0.0.1\"]".to_string();
                    }
                    Some("upstream") => {
                        ips = mode_value["ips"].to_string();
                        port = mode_value["port"].to_string();
                        new_mode = mode_value["upstream"].to_string();
                    }
                    Some("redirect") | _ => {
                        continue;
                    }
                }
                // 插入新记录
                let insert = Query::insert()
                    .into_table(DNSUpstreamConfigs::Table)
                    .columns([
                        DNSUpstreamConfigs::Id,
                        DNSUpstreamConfigs::Remark,
                        DNSUpstreamConfigs::Mode,
                        DNSUpstreamConfigs::Ips,
                        DNSUpstreamConfigs::Port,
                        DNSUpstreamConfigs::UpdateAt,
                    ])
                    .values_panic([
                        Expr::value(new_id.as_bytes().to_vec()),
                        "migration config".into(),
                        new_mode.into(),
                        ips.into(),
                        port.into(),
                        "0".into(),
                    ])
                    .to_owned();

                manager.exec_stmt(insert).await?;

                new_id
            };

            let update = Query::update()
                .table(DNSRuleConfigs::Table)
                .values([(DNSRuleConfigs::UpstreamId, upstream_id.into())])
                .and_where(Expr::col(DNSRuleConfigs::Id).eq(row.id))
                .to_owned();

            manager.exec_stmt(update).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(DNSUpstreamConfigs::Table).to_owned()).await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DNSRuleConfigs::Table)
                    .drop_column(DNSRuleConfigs::UpstreamId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(FromQueryResult)]
struct RuleRow {
    id: Uuid,
    resolve_mode: String,
}
