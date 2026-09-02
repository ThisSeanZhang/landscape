use std::collections::HashSet;
use std::time::SystemTime;

use sea_orm_migration::sea_orm::{
    ActiveValue, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, QueryTrait,
    TransactionTrait,
};
use sea_orm_migration::{seaql_migrations, MigrationTrait, MigratorTrait, SchemaManager};

/// Apply all pending migrations of `M`, wrapping each migration together with
/// its `seaql_migrations` bookkeeping row in a single transaction.
///
/// `Migrator::up` only wraps migrations in a transaction on Postgres; on
/// SQLite it commits the migration body and the version-row insert separately.
/// A crash in between leaves the schema half-migrated while the migration is
/// still considered pending, and re-applying it fails (e.g. `duplicate column
/// name`). SQLite DDL is transactional, so running both steps in one
/// transaction lets a crashed migration roll back cleanly and re-apply on the
/// next start.
///
/// Like `Migrator::up`, this rejects versions that are recorded in the
/// database but have no migration file anymore, mirroring the safety check of
/// `Migrator::get_migration_with_status`.
///
/// `steps` limits the number of pending migrations applied in this call,
/// mirroring the `steps` argument of `Migrator::up`; `None` applies all
/// pending migrations.
///
/// [`down_transactional`] mirrors this design for `Migrator::down`: each
/// rolled-back migration together with the removal of its `seaql_migrations`
/// row runs in a single transaction, so a failed or interrupted rollback
/// leaves schema and version table consistent and re-runnable.
///
/// Upstream status: as of sea-orm-migration 1.1.20 (pinned by this workspace)
/// the version-row insert and the migration body are not committed atomically
/// on SQLite, and there is no opt-in hook. SeaQL/sea-orm#2980 added a
/// per-migration `MigrationTrait::use_transaction()` control but it only
/// landed in 2.0.0, and even there SQLite still defaults to no transaction
/// (see SeaQL/sea-orm#3136, still open). If/when this workspace upgrades to
/// sea-orm 2.x, prefer overriding `use_transaction() -> Some(true)` on
/// `Migrator` over this custom runner and delete this module.
pub async fn up_transactional<M, C>(db: &C, steps: Option<u32>) -> Result<(), DbErr>
where
    M: MigratorTrait,
    C: ConnectionTrait + TransactionTrait + Sync,
{
    let migrations = M::migrations();
    let applied: HashSet<String> = applied_versions::<M, C>(db).await?.into_iter().collect();

    let mut remaining = steps;
    for migration in migrations {
        if applied.contains(migration.name()) {
            continue;
        }
        if remaining == Some(0) {
            break;
        }
        remaining = remaining.map(|n| n - 1);

        let txn = db.begin().await?;
        match apply_one::<M>(migration.as_ref(), &txn).await {
            Ok(()) => txn.commit().await?,
            // Roll back explicitly: dropping the transaction would only queue
            // the rollback and swallow a rollback failure. If the rollback
            // fails too, surface both errors.
            Err(err) => {
                return match txn.rollback().await {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(DbErr::Custom(format!(
                        "migration '{}' failed: {err}; rollback also failed: {rollback_err}",
                        migration.name()
                    ))),
                };
            }
        }
    }

    Ok(())
}

/// Roll back the most recently applied migrations of `M`, wrapping each
/// migration's `down` together with the removal of its `seaql_migrations` row
/// in a single transaction.
///
/// Mirrors the semantics of `Migrator::down`: migrations are rolled back in
/// reverse application order (most recent first), and `steps` limits how many
/// are rolled back in this call (`None` rolls back all applied migrations).
/// Like `Migrator::down`, this refuses to run when a version recorded in the
/// database has no migration file anymore; see [`applied_versions`].
///
/// Per-migration atomicity means a migration whose `down` fails halfway
/// (e.g. crashes, or a check constraint that the migration itself drops)
/// rolls back cleanly and stays recorded as applied, so the next invocation
/// retries the same rollback instead of finding a half-rolled-back schema.
pub async fn down_transactional<M, C>(db: &C, steps: Option<u32>) -> Result<(), DbErr>
where
    M: MigratorTrait,
    C: ConnectionTrait + TransactionTrait + Sync,
{
    let applied: HashSet<String> = applied_versions::<M, C>(db).await?.into_iter().collect();

    let migrations = M::migrations();

    let mut remaining = steps;
    for migration in migrations.iter().rev() {
        if !applied.contains(migration.name()) {
            continue;
        }
        if remaining == Some(0) {
            break;
        }
        remaining = remaining.map(|n| n - 1);

        let txn = db.begin().await?;
        match rollback_one::<M>(migration.as_ref(), migration.name(), &txn).await {
            Ok(()) => txn.commit().await?,
            // Roll back explicitly: dropping the transaction would only queue
            // the rollback and swallow a rollback failure. If the rollback
            // fails too, surface both errors.
            Err(err) => {
                return match txn.rollback().await {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(DbErr::Custom(format!(
                        "rollback of migration '{}' failed: {err}; rollback also failed: {rollback_err}",
                        migration.name()
                    ))),
                };
            }
        }
    }

    Ok(())
}

/// Versions currently recorded in the `seaql_migrations` table, in ascending
/// (application) order.
///
/// Mirrors the safety check of `Migrator::get_migration_with_status`: a
/// version that is recorded but has no migration file anymore is an error
/// rather than something to silently skip, because neither up nor down can
/// safely reason about it (up would re-apply a half-migrated schema, down
/// would strand a schema change it cannot undo).
///
/// Calling this creates the `seaql_migrations` table if it does not exist yet.
async fn applied_versions<M, C>(db: &C) -> Result<Vec<String>, DbErr>
where
    M: MigratorTrait,
    C: ConnectionTrait,
{
    let models = M::get_migration_models(db).await?;

    let migrations = M::migrations();
    let names_in_fs: HashSet<&str> = migrations.iter().map(|m| m.name()).collect();
    let missing_in_fs: Vec<&str> =
        models.iter().map(|m| m.version.as_str()).filter(|v| !names_in_fs.contains(v)).collect();
    if !missing_in_fs.is_empty() {
        return Err(DbErr::Custom(format!(
            "Migration file of version '{}' is missing, this migration has been applied but its file is missing",
            missing_in_fs.join("', '")
        )));
    }

    Ok(models.into_iter().map(|m| m.version).collect())
}

async fn apply_one<M>(
    migration: &dyn MigrationTrait,
    txn: &DatabaseTransaction,
) -> Result<(), DbErr>
where
    M: MigratorTrait,
{
    let manager = SchemaManager::new(txn);
    migration.up(&manager).await?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| DbErr::Custom(format!("SystemTime before UNIX EPOCH: {e}")))?;
    let mut insert = seaql_migrations::Entity::insert(seaql_migrations::ActiveModel {
        version: ActiveValue::Set(migration.name().to_owned()),
        applied_at: ActiveValue::Set(now.as_secs() as i64),
    });
    QueryTrait::query(&mut insert).into_table(M::migration_table_name());
    insert.exec(txn).await?;

    Ok(())
}

/// Run a single migration's `down` on `txn` and remove its
/// `seaql_migrations` row, so both commit or roll back together.
async fn rollback_one<M>(
    migration: &dyn MigrationTrait,
    version: &str,
    txn: &DatabaseTransaction,
) -> Result<(), DbErr>
where
    M: MigratorTrait,
{
    let manager = SchemaManager::new(txn);
    migration.down(&manager).await?;

    let mut delete = seaql_migrations::Entity::delete(seaql_migrations::ActiveModel {
        version: ActiveValue::Set(version.to_owned()),
        applied_at: ActiveValue::NotSet,
    });
    QueryTrait::query(&mut delete).from_table(M::migration_table_name());
    delete.exec(txn).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::prelude::*;
    use sea_orm_migration::sea_orm::{ConnectOptions, Database, DatabaseConnection};

    use super::{down_transactional, up_transactional};

    struct GoodMigration;

    impl MigrationName for GoodMigration {
        fn name(&self) -> &str {
            "m000000_000001_good"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for GoodMigration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .exec_stmt(
                    Table::create()
                        .table(Alias::new("t_good"))
                        .col(
                            ColumnDef::new(Alias::new("id"))
                                .integer()
                                .not_null()
                                .auto_increment()
                                .primary_key(),
                        )
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager.drop_table(Table::drop().table(Alias::new("t_good")).to_owned()).await
        }
    }

    struct SecondGoodMigration;

    impl MigrationName for SecondGoodMigration {
        fn name(&self) -> &str {
            "m000000_000002_second_good"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for SecondGoodMigration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .exec_stmt(
                    Table::create()
                        .table(Alias::new("t_second_good"))
                        .col(ColumnDef::new(Alias::new("id")).integer().not_null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager.drop_table(Table::drop().table(Alias::new("t_second_good")).to_owned()).await
        }
    }

    struct BadMigration;

    impl MigrationName for BadMigration {
        fn name(&self) -> &str {
            "m000000_000002_bad"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for BadMigration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .exec_stmt(
                    Table::create()
                        .table(Alias::new("t_bad"))
                        .col(ColumnDef::new(Alias::new("id")).integer().not_null())
                        .to_owned(),
                )
                .await?;
            Err(DbErr::Custom("deliberate failure".to_owned()))
        }
    }

    struct FailingDownMigration;

    impl MigrationName for FailingDownMigration {
        fn name(&self) -> &str {
            "m000000_000003_failing_down"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for FailingDownMigration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .exec_stmt(
                    Table::create()
                        .table(Alias::new("t_failing_down"))
                        .col(ColumnDef::new(Alias::new("id")).integer().not_null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(Alias::new("t_failing_down")).to_owned())
                .await?;
            Err(DbErr::Custom("deliberate down failure".to_owned()))
        }
    }

    struct FullMigrator;
    struct TwoGoodMigrator;
    struct GoodOnlyMigrator;
    struct BadOnlyMigrator;
    struct FailingDownMigrator;

    #[async_trait::async_trait]
    impl MigratorTrait for TwoGoodMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(GoodMigration), Box::new(SecondGoodMigration)]
        }
    }

    #[async_trait::async_trait]
    impl MigratorTrait for FullMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(GoodMigration), Box::new(BadMigration)]
        }
    }

    #[async_trait::async_trait]
    impl MigratorTrait for GoodOnlyMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(GoodMigration)]
        }
    }

    #[async_trait::async_trait]
    impl MigratorTrait for BadOnlyMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(BadMigration)]
        }
    }

    #[async_trait::async_trait]
    impl MigratorTrait for FailingDownMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(FailingDownMigration)]
        }
    }

    async fn mem_db() -> DatabaseConnection {
        let mut opt: ConnectOptions = "sqlite::memory:".into();
        opt.max_connections(1);
        Database::connect(opt).await.expect("connect in-memory db")
    }

    #[tokio::test]
    async fn failing_migration_rolls_back_atomically() {
        let db = mem_db().await;

        let err = up_transactional::<FullMigrator, _>(&db, None).await.unwrap_err();
        assert!(err.to_string().contains("deliberate failure"));

        // The failing migration rolls back atomically: its own DDL does not
        // survive and no version row is recorded for it.
        let manager = SchemaManager::new(&db);
        assert!(!manager.has_table("t_bad").await.unwrap());

        // Migrations committed before the failure stay applied and recorded.
        assert!(manager.has_table("t_good").await.unwrap());
        let models = FullMigrator::get_migration_models(&db).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].version, "m000000_000001_good");

        // Retry after the failing migration is removed: nothing pending, no-op.
        up_transactional::<GoodOnlyMigrator, _>(&db, None).await.unwrap();
        assert_eq!(GoodOnlyMigrator::get_migration_models(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn version_without_migration_file_is_rejected() {
        let db = mem_db().await;

        up_transactional::<GoodOnlyMigrator, _>(&db, None).await.unwrap();

        let err = up_transactional::<BadOnlyMigrator, _>(&db, None).await.unwrap_err();
        assert!(err.to_string().contains("is missing"));
        assert!(!SchemaManager::new(&db).has_table("t_bad").await.unwrap());
    }

    #[tokio::test]
    async fn steps_limits_the_number_of_applied_migrations() {
        let db = mem_db().await;

        // One step: only the first pending migration is applied.
        up_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        let manager = SchemaManager::new(&db);
        assert!(manager.has_table("t_good").await.unwrap());
        assert!(!manager.has_table("t_second_good").await.unwrap());
        let models = TwoGoodMigrator::get_migration_models(&db).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].version, "m000000_000001_good");

        // The next step applies the remaining migration.
        up_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        assert!(manager.has_table("t_second_good").await.unwrap());
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 2);

        // Nothing pending: further steps are a no-op.
        up_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 2);

        // steps = 0 applies nothing.
        up_transactional::<TwoGoodMigrator, _>(&db, Some(0)).await.unwrap();
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn down_rolls_back_one_migration_per_step() {
        let db = mem_db().await;
        up_transactional::<TwoGoodMigrator, _>(&db, None).await.unwrap();

        // One step: only the most recently applied migration is rolled back.
        down_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        let manager = SchemaManager::new(&db);
        assert!(!manager.has_table("t_second_good").await.unwrap());
        assert!(manager.has_table("t_good").await.unwrap());
        let models = TwoGoodMigrator::get_migration_models(&db).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].version, "m000000_000001_good");

        // The next step rolls back the remaining migration.
        down_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        assert!(!manager.has_table("t_good").await.unwrap());
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 0);

        // Nothing applied: further steps are a no-op.
        down_transactional::<TwoGoodMigrator, _>(&db, Some(1)).await.unwrap();
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 0);

        // steps = 0 rolls back nothing.
        up_transactional::<TwoGoodMigrator, _>(&db, None).await.unwrap();
        down_transactional::<TwoGoodMigrator, _>(&db, Some(0)).await.unwrap();
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn down_rolls_back_all_and_reapply_is_possible() {
        let db = mem_db().await;
        up_transactional::<TwoGoodMigrator, _>(&db, None).await.unwrap();

        down_transactional::<TwoGoodMigrator, _>(&db, None).await.unwrap();
        let manager = SchemaManager::new(&db);
        assert!(!manager.has_table("t_good").await.unwrap());
        assert!(!manager.has_table("t_second_good").await.unwrap());
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 0);

        // Clean slate: the migrations can be applied again from scratch.
        up_transactional::<TwoGoodMigrator, _>(&db, None).await.unwrap();
        assert!(manager.has_table("t_good").await.unwrap());
        assert!(manager.has_table("t_second_good").await.unwrap());
        assert_eq!(TwoGoodMigrator::get_migration_models(&db).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failing_down_rolls_back_atomically() {
        let db = mem_db().await;
        up_transactional::<FailingDownMigrator, _>(&db, None).await.unwrap();

        let err = down_transactional::<FailingDownMigrator, _>(&db, None).await.unwrap_err();
        assert!(err.to_string().contains("deliberate down failure"));

        // The failed down rolls back atomically: its DDL does not survive and
        // the version row is still recorded, so the migration is still
        // considered applied and the next run retries the same rollback.
        let manager = SchemaManager::new(&db);
        assert!(manager.has_table("t_failing_down").await.unwrap());
        let models = FailingDownMigrator::get_migration_models(&db).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].version, "m000000_000003_failing_down");

        let err = down_transactional::<FailingDownMigrator, _>(&db, None).await.unwrap_err();
        assert!(err.to_string().contains("deliberate down failure"));
    }

    #[tokio::test]
    async fn down_rejects_version_without_migration_file() {
        let db = mem_db().await;
        up_transactional::<GoodOnlyMigrator, _>(&db, None).await.unwrap();

        // BadOnlyMigrator does not contain the applied 'good' migration file:
        // refuse to roll anything back rather than strand a schema change.
        let err = down_transactional::<BadOnlyMigrator, _>(&db, None).await.unwrap_err();
        assert!(err.to_string().contains("is missing"));
        assert!(SchemaManager::new(&db).has_table("t_good").await.unwrap());
        assert_eq!(GoodOnlyMigrator::get_migration_models(&db).await.unwrap().len(), 1);
    }
}
