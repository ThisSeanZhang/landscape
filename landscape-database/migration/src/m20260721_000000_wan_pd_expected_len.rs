use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::dhcp_v6_client::DHCPv6ClientConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv6ClientConfigs::Table)
                    .add_column_if_not_exists(
                        tiny_unsigned(DHCPv6ClientConfigs::ExpectedPdLen).default(60),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DHCPv6ClientConfigs::Table)
                    .drop_column(DHCPv6ClientConfigs::ExpectedPdLen)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    use super::*;

    #[async_std::test]
    async fn existing_rows_receive_default_expected_pd_len() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database
            .execute_unprepared(
                r#"
                CREATE TABLE dhcp_v6_client_configs (
                    iface_name TEXT PRIMARY KEY NOT NULL,
                    enable BOOLEAN NOT NULL,
                    mac TEXT NOT NULL,
                    update_at REAL NOT NULL DEFAULT 0
                );
                INSERT INTO dhcp_v6_client_configs (iface_name, enable, mac, update_at)
                VALUES ('wan0', TRUE, '02:00:00:00:00:01', 0);
                "#,
            )
            .await
            .unwrap();

        Migration.up(&SchemaManager::new(&database)).await.unwrap();

        let row = database
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT expected_pd_len FROM dhcp_v6_client_configs WHERE iface_name = 'wan0'",
            ))
            .await
            .unwrap()
            .unwrap();
        let expected_pd_len: u8 = row.try_get("", "expected_pd_len").unwrap();
        assert_eq!(expected_pd_len, 60);
    }
}
