pub(crate) mod connect;
pub(crate) mod dns;

use std::path::Path;
use std::time::Duration;

use futures_util::future::BoxFuture;
use sqlx::pool::PoolConnectionMetadata;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

pub(crate) use crate::agg::dns_bucket::clean_ip_string;

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

async fn apply_connection_pragmas(
    conn: &mut sqlx::sqlite::SqliteConnection,
    max_bytes: u64,
) -> Result<(), sqlx::Error> {
    // 尽力而为:auto_vacuum 仅对空库(首次创建)生效,WAL 先于该 pragma 落盘时会被
    // 静默忽略;真正约束容量的是 max_page_count(硬顶) + 删除后 freelist 复用。
    sqlx::query("PRAGMA auto_vacuum = INCREMENTAL").execute(&mut *conn).await?;
    let page_size =
        sqlx::query("PRAGMA page_size").fetch_one(&mut *conn).await?.get::<i64, _>(0).max(1) as u64;
    if max_bytes > 0 {
        // WAL 预留按上限缩放:小上限下若仍预留固定 16MB,主库预算会被压到 1 页,
        // 任何写入都直接 SQLITE_FULL,数据库形同不可用。
        const WAL_RESERVE_BYTES: u64 = 16 * 1024 * 1024;
        let wal_reserve = WAL_RESERVE_BYTES.min(max_bytes / 2).max(page_size);
        let main_budget = max_bytes.saturating_sub(wal_reserve).max(page_size * 256);
        let max_pages = main_budget.div_ceil(page_size);
        sqlx::query(&format!("PRAGMA max_page_count = {max_pages}")).execute(&mut *conn).await?;
        sqlx::query(&format!("PRAGMA journal_size_limit = {wal_reserve}"))
            .execute(&mut *conn)
            .await?;
        let autocheckpoint_pages = wal_reserve.div_ceil(page_size);
        sqlx::query(&format!("PRAGMA wal_autocheckpoint = {autocheckpoint_pages}"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// 连接级 PRAGMA 必须逐连接应用:`max_page_count` / `journal_size_limit` 是
/// per-connection 设置,若只配置池的首条连接,其余连接可绕过容量上限,
/// SQLITE_FULL(及热回收)将无法触发。
fn connection_pragmas(
    max_bytes: u64,
) -> impl Fn(
    &mut sqlx::sqlite::SqliteConnection,
    PoolConnectionMetadata,
) -> BoxFuture<'_, Result<(), sqlx::Error>>
       + Send
       + Sync {
    move |conn, _meta| Box::pin(apply_connection_pragmas(conn, max_bytes))
}

pub(crate) async fn open_connect_pool(path: &Path, max_bytes: u64) -> Result<SqlitePool, String> {
    let options = connect_options(path);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .after_connect(connection_pragmas(max_bytes))
        .connect_with(options)
        .await
        .map_err(|error| {
            format!("failed to open connect sqlite at {}: {}", path.display(), error)
        })?;
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

pub(crate) async fn open_dns_pool(path: &Path, max_bytes: u64) -> Result<SqlitePool, String> {
    let options = connect_options(path);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .after_connect(connection_pragmas(max_bytes))
        .connect_with(options)
        .await
        .map_err(|error| format!("failed to open dns sqlite at {}: {}", path.display(), error))?;
    dns::initialize_schema(&pool).await.map_err(|error| {
        format!("failed to initialize dns sqlite schema at {}: {}", path.display(), error)
    })?;
    Ok(pool)
}

/// 主库逻辑占用:(page_count - freelist_count) × page_size。
///
/// WAL 模式下已提交的删除立即可见(无需 checkpoint),是清理收敛判定的正确口径;
/// 物理文件尺寸在 checkpoint 前滞后,且在 auto_vacuum 非 INCREMENTAL 时永不缩小,
/// 不能用作循环收敛条件。
pub(crate) async fn logical_main_size_bytes(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let page_count =
        sqlx::query("PRAGMA page_count").fetch_one(pool).await?.get::<i64, _>(0).max(0) as u64;
    let freelist_count =
        sqlx::query("PRAGMA freelist_count").fetch_one(pool).await?.get::<i64, _>(0).max(0) as u64;
    let page_size =
        sqlx::query("PRAGMA page_size").fetch_one(pool).await?.get::<i64, _>(0).max(1) as u64;
    Ok(page_count.saturating_sub(freelist_count).saturating_mul(page_size))
}

/// SQLITE_FULL(13):数据库因容量上限(`max_page_count`)或磁盘空间不足而无法增长。
/// 写入路径据此触发热路径回收并重试一次。
pub(crate) fn is_sqlite_full(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => {
            db_error.code().as_deref() == Some("13")
                || db_error.message().to_lowercase().contains("database or disk is full")
        }
        _ => false,
    }
}

pub(crate) async fn checkpoint_and_compact(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // A truncate checkpoint reclaims completed WAL segments. It can report busy while a reader is
    // active; keep going so incremental_vacuum can still reclaim deleted pages.
    if let Err(error) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").fetch_all(pool).await {
        tracing::warn!("sqlite checkpoint deferred (busy readers): {error}");
    }
    sqlx::query("PRAGMA incremental_vacuum(1024)").execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn clean_ip_string_keeps_ipv4_as_is() {
        assert_eq!(clean_ip_string(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), "10.0.0.1");
        assert_eq!(clean_ip_string(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))), "0.0.0.0");
    }

    #[test]
    fn clean_ip_string_normalizes_ipv4_mapped_ipv6() {
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0280);
        assert_eq!(clean_ip_string(&IpAddr::V6(mapped)), "192.0.2.128");
    }

    #[test]
    fn clean_ip_string_keeps_plain_ipv6_untouched() {
        let loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(clean_ip_string(&loopback), "::1");
        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(clean_ip_string(&v6), "2001:db8::1");
    }

    #[tokio::test]
    async fn small_cap_keeps_main_database_usable() {
        let dir = tempfile::tempdir().unwrap();
        // 1MB 上限:WAL 预留按上限缩放,主库预算不应被压到 1 页(否则任何写入都 SQLITE_FULL)。
        let db_path = dir.path().join("connect.db");
        let pool = open_connect_pool(&db_path, 1024 * 1024).await.unwrap();

        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size").fetch_one(&pool).await.unwrap();
        let max_pages: i64 =
            sqlx::query_scalar("PRAGMA max_page_count").fetch_one(&pool).await.unwrap();
        assert!(max_pages >= 256, "main database must keep at least 256 pages");
        assert!(max_pages as u64 * page_size as u64 >= 256 * 4096);

        // 至少能写入一页以上的数据(1 页上限下任何 INSERT 都会失败)。
        sqlx::query(
            "INSERT INTO conn_summaries (
                create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto,
                flow_id, trace_id, ifindex, last_report_time,
                total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts,
                status, create_time_ms, gress
            ) VALUES (1, 1, '10.0.0.1', '10.0.0.2', 1, 2, 6, 4, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    async fn max_page_count_is_applied_to_every_pooled_connection() {
        // 回归:max_page_count 是 per-connection 设置,必须通过 after_connect
        // 应用到池内所有连接,否则容量上限形同虚设(SQLITE_FULL 永不触发)。
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("connect.db");
        let pool = open_connect_pool(&db_path, 1024 * 1024).await.unwrap();

        let expected_max_pages: i64 = {
            let page_size: i64 =
                sqlx::query_scalar("PRAGMA page_size").fetch_one(&pool).await.unwrap();
            let wal_reserve = (1024 * 1024 / 2).max(page_size as u64);
            let main_budget = (1024 * 1024 - wal_reserve).max(page_size as u64 * 256);
            (main_budget.div_ceil(page_size as u64)) as i64
        };
        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                let max_pages: i64 =
                    sqlx::query_scalar("PRAGMA max_page_count").fetch_one(&pool).await.unwrap();
                assert_eq!(
                    max_pages, expected_max_pages,
                    "every pooled connection must carry the cap"
                );
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        pool.close().await;
    }
}
