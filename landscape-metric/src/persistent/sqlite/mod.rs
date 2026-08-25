pub(crate) mod connect;
pub(crate) mod dns;

use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

/// 读(web 查询)与写(worker 批量写入/cleanup 大范围删除)并发,
/// 必须用 WAL + synchronous=NORMAL 避免读在写入期间报 SQLITE_BUSY。
fn connect_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
}

pub(crate) async fn open_connect_pool(path: &Path) -> Result<SqlitePool, String> {
    let options = connect_options(path);
    let pool = SqlitePoolOptions::new().max_connections(4).connect_with(options).await.map_err(
        |error| format!("failed to open connect sqlite at {}: {}", path.display(), error),
    )?;
    connect::initialize_schema(&pool).await.map_err(|error| {
        format!("failed to initialize connect sqlite schema at {}: {}", path.display(), error)
    })?;
    // 缓存与 summary 写入/删除在同一事务内更新,不会漂移;仅当缓存从未
    // 被写入过(新库)才需要全表重建,避免每次启动都全表扫描。
    let stats = connect::query_global_stats(&pool).await.map_err(|error| {
        format!("failed to read connect global stats cache at {}: {}", path.display(), error)
    })?;
    if stats.last_calculate_time == 0 {
        connect::rebuild_global_stats_cache(&pool).await.map_err(|error| {
            format!("failed to rebuild connect global stats cache at {}: {}", path.display(), error)
        })?;
    }
    Ok(pool)
}

pub(crate) async fn open_dns_pool(path: &Path) -> Result<SqlitePool, String> {
    let options = connect_options(path);
    let pool =
        SqlitePoolOptions::new().max_connections(4).connect_with(options).await.map_err(
            |error| format!("failed to open dns sqlite at {}: {}", path.display(), error),
        )?;
    dns::initialize_schema(&pool).await.map_err(|error| {
        format!("failed to initialize dns sqlite schema at {}: {}", path.display(), error)
    })?;
    Ok(pool)
}
