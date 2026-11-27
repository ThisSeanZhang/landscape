use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, Statement};
use serde_json::{Map, Value};

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "wan_links";
const COLUMN: &str = "pd";

/// Rewrite the `pd` JSON object of every existing WAN link. Rows whose `pd`
/// value is not a JSON object are left untouched.
async fn rewrite_pd<F>(manager: &SchemaManager<'_>, mut rewrite: F) -> Result<(), DbErr>
where
    F: FnMut(&mut Map<String, Value>),
{
    let db = manager.get_connection();
    let backend = manager.get_database_backend();
    let rows = db
        .query_all(Statement::from_string(backend, format!("SELECT id, {COLUMN} FROM {TABLE}")))
        .await?;

    for row in rows {
        let id: String = row.try_get("", "id")?;
        let raw: String = row.try_get("", COLUMN)?;
        let Ok(mut pd) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(object) = pd.as_object_mut() else {
            continue;
        };
        rewrite(object);

        let encoded = serde_json::to_string(&pd)
            .map_err(|err| DbErr::Custom(format!("serialize {TABLE}.{COLUMN}: {err}")))?;
        db.execute(Statement::from_sql_and_values(
            backend,
            format!("UPDATE {TABLE} SET {COLUMN} = ? WHERE id = ?"),
            [encoded.into(), id.into()],
        ))
        .await?;
    }

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Preserve the pre-toggle behaviour: every existing link was treated
        // as an IPv6 default before this field existed.
        rewrite_pd(manager, |pd| {
            pd.insert("default_router".to_string(), Value::Bool(true));
        })
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rewrite_pd(manager, |pd| {
            pd.remove("default_router");
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    use super::*;

    async fn test_db() -> sea_orm_migration::sea_orm::DatabaseConnection {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database
            .execute_unprepared(
                r#"
                CREATE TABLE wan_links (
                    id TEXT PRIMARY KEY NOT NULL,
                    pd TEXT NOT NULL
                );
                INSERT INTO wan_links (id, pd) VALUES
                    ('00000000-0000-0000-0000-000000000001',
                     '{"enable":true,"mac":"00:11:22:33:44:55","expected_pd_len":60}'),
                    ('00000000-0000-0000-0000-000000000002', '{}'),
                    ('00000000-0000-0000-0000-000000000003', '[]');
                "#,
            )
            .await
            .unwrap();
        database
    }

    async fn pd_of(
        db: &sea_orm_migration::sea_orm::DatabaseConnection,
        id: &str,
    ) -> serde_json::Value {
        let row = db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT pd FROM wan_links WHERE id = ?",
                [id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        let raw: String = row.try_get("", "pd").unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[tokio::test]
    async fn existing_links_default_to_router() {
        let db = test_db().await;
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();

        let first = pd_of(&db, "00000000-0000-0000-0000-000000000001").await;
        assert_eq!(first["default_router"], serde_json::json!(true));
        assert_eq!(first["enable"], serde_json::json!(true));

        let second = pd_of(&db, "00000000-0000-0000-0000-000000000002").await;
        assert_eq!(second["default_router"], serde_json::json!(true));

        // Non-object values are skipped instead of replaced.
        let third = pd_of(&db, "00000000-0000-0000-0000-000000000003").await;
        assert_eq!(third, serde_json::json!([]));
    }

    #[tokio::test]
    async fn up_is_idempotent_and_down_removes_the_field() {
        let db = test_db().await;
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        assert_eq!(
            pd_of(&db, "00000000-0000-0000-0000-000000000001").await["default_router"],
            serde_json::json!(true)
        );

        Migration.down(&manager).await.unwrap();
        let first = pd_of(&db, "00000000-0000-0000-0000-000000000001").await;
        assert!(first.get("default_router").is_none());
        assert_eq!(first["enable"], serde_json::json!(true));
    }
}
