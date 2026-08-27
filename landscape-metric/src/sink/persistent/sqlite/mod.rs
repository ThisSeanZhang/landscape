pub(crate) mod connect;
pub(crate) mod dns;

use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

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
}
