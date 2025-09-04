use std::collections::HashMap;

use sea_orm_migration::{prelude::*, schema::*};

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

        manager
            .alter_table(
                Table::alter()
                    .table(DNSRuleConfigs::Table)
                    .add_column(ColumnDef::new(DNSRuleConfigs::UpstreamId).uuid().null())
                    .to_owned(),
            )
            .await
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

// async fn migrate_resolve_mode_to_upstreams(db: &sea_orm::DbConn) -> Result<(), DbErr> {
//     use sea_orm::ColumnTrait;
//     use sea_orm::EntityTrait;
//     use sea_orm::QueryTrait;

//     // 用于缓存已有的 upstream 配置 -> id
//     let mut upstream_cache: HashMap<String, Uuid> = HashMap::new();

//     // 查询所有 DNSRuleConfigs
//     let rows: Vec<(Uuid, Option<String>)> = DNSRuleConfigsEntity::find()
//         .select_only()
//         .column(DNSRuleConfigsColumn::Id)
//         .column(DNSRuleConfigsColumn::ResolveMode)
//         .into_tuple()
//         .all(db)
//         .await?;

//     for (rule_id, resolve_mode_json) in rows {
//         if let Some(json_str) = resolve_mode_json {
//             let mode_value: Value = serde_json::from_str(&json_str).unwrap_or_else(|_| Value::Null);

//             // 用 JSON 字符串本身做 key
//             let key = json_str.clone();

//             let upstream_id = if let Some(cached_id) = upstream_cache.get(&key) {
//                 *cached_id
//             } else {
//                 // 新建 upstream 配置
//                 let new_id = Uuid::new_v4();

//                 let new_upstream = DNSUpstreamConfigsActiveModel {
//                     id: Set(new_id),
//                     mode: Set(Some(mode_value.clone())),
//                     remark: Set(None),
//                     ips: Set(None),
//                     port: Set(None),
//                     update_at: Set(chrono::Utc::now().timestamp_millis() as f64),
//                 };

//                 DNSUpstreamConfigsEntity::insert(new_upstream).exec(db).await?;

//                 upstream_cache.insert(key, new_id);
//                 new_id
//             };

//             // 更新 DNSRuleConfigs.UpstreamId
//             DNSRuleConfigsEntity::update_many()
//                 .col_expr(DNSRuleConfigsColumn::UpstreamId, Expr::value(upstream_id))
//                 .filter(DNSRuleConfigsColumn::Id.eq(rule_id))
//                 .exec(db)
//                 .await?;
//         }
//     }

//     Ok(())
// }
