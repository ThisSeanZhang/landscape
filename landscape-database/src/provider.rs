use std::time::Duration;

use landscape_common::{
    config::{InitConfig, StoreRuntimeConfig},
    database::error::DbError,
};
use migration::Migrator;
use sea_orm::{
    ActiveModelTrait, Database, DatabaseConnection, DatabaseTransaction, EntityTrait,
    TransactionTrait,
};

use crate::{
    cert::repository::CertRepository, cert_account::repository::CertAccountRepository,
    ddns::repository::DdnsJobRepository, dhcp_v4_server::repository::DHCPv4ServerRepository,
    dhcp_v6_client::repository::DHCPv6ClientRepository,
    dns_provider_profile::repository::DnsProviderProfileRepository,
    dns_redirect::repository::DNSRedirectRuleRepository, dns_rule::repository::DNSRuleRepository,
    dns_upstream::repository::DnsUpstreamRepository, dst_ip_rule::repository::DstIpRuleRepository,
    enrolled_device::repository::EnrolledDeviceRepository,
    firewall::repository::FirewallServiceRepository,
    firewall_blacklist::repository::FirewallBlacklistRepository,
    firewall_rule::repository::FirewallRuleRepository, flow_rule::repository::FlowConfigRepository,
    flow_wan::repository::FlowWanServiceRepository,
    gateway::repository::GatewayHttpUpstreamRepository,
    geo_ip::repository::GeoIpSourceConfigRepository, geo_site::repository::GeoSiteConfigRepository,
    iface::repository::NetIfaceRepository, iface_ip::repository::IfaceIpServiceRepository,
    lan_ipv6_v2::repository::LanIPv6V2ServiceRepository,
    mss_clamp::repository::MssClampServiceRepository, nat::repository::NatServiceRepository,
    pppd::repository::PPPDServiceRepository, route_lan::repository::RouteLanServiceRepository,
    route_wan::repository::RouteWanServiceRepository,
    static_nat_mapping_v4::repository::StaticNatMappingV4Repository,
    static_nat_mapping_v6::repository::StaticNatMappingV6Repository,
    wifi::repository::WifiServiceRepository,
};

pub async fn db_action(
    config: &StoreRuntimeConfig,
    rollback: &bool,
    steps: &u32,
) -> Result<(), DbError> {
    let opt: migration::sea_orm::ConnectOptions = config.database_path.clone().into();
    let database = Database::connect(opt).await?;

    if *rollback {
        migration::runner::down_transactional::<Migrator, _>(&database, Some(*steps)).await?;
    } else {
        migration::runner::up_transactional::<Migrator, _>(&database, Some(*steps)).await?;
    }

    Ok(())
}

pub async fn rollback_interactive(config: &StoreRuntimeConfig) -> Result<(), DbError> {
    crate::rollback::interactive_rollback(config).await
}

/// Storage provider; to be abstracted further if needed.
#[derive(Clone)]
pub struct LandscapeDBServiceProvider {
    database: DatabaseConnection,
}

/// All connection failures are retried with the bounded backoff below: during
/// boot even "unable to open database file" can be transient (mount point not
/// ready yet, disk busy), so no error class is fail-fast. Permanent failures
/// (bad path, permissions) surface after at most ~15s of total delay.
const MAX_CONNECT_ATTEMPTS: usize = 5;
const CONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

async fn connect_with_retry(
    opt: migration::sea_orm::ConnectOptions,
) -> Result<DatabaseConnection, DbError> {
    let mut backoff = CONNECT_BACKOFF_START;
    let mut last_err = None;

    for attempt in 1..=MAX_CONNECT_ATTEMPTS {
        match Database::connect(opt.clone()).await {
            Ok(database) => return Ok(database),
            Err(err) => {
                tracing::error!(
                    "database connection attempt {}/{} failed: {err:?}",
                    attempt,
                    MAX_CONNECT_ATTEMPTS
                );
                last_err = Some(err);
                if attempt < MAX_CONNECT_ATTEMPTS {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(CONNECT_BACKOFF_MAX);
                }
            }
        }
    }

    Err(DbError::Database(last_err.expect("at least one attempt was made")))
}

impl LandscapeDBServiceProvider {
    pub async fn new(config: &StoreRuntimeConfig) -> Result<Self, DbError> {
        let mut opt: migration::sea_orm::ConnectOptions = config.database_path.clone().into();
        let (lever, _) = opt.get_sqlx_slow_statements_logging_settings();
        opt.sqlx_slow_statements_logging_settings(lever, Duration::from_secs(10));
        opt.map_sqlx_sqlite_opts(|sqlite_opts| {
            sqlite_opts
                .journal_mode(sea_orm::sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5))
                .foreign_keys(true)
        });

        let database = connect_with_retry(opt).await?;

        // Migration failures are persistent (bad/half-applied schema), not
        // transient: no retry, fail fast with a clean error.
        if let Err(err) = migration::runner::up_transactional::<Migrator, _>(&database, None).await
        {
            tracing::error!("database migration failed: {err:?}");
            return Err(err.into());
        }

        Ok(Self { database })
    }
    pub async fn mem_test_db() -> Self {
        let mut opt: migration::sea_orm::ConnectOptions = "sqlite::memory:".into();
        // in-memory DB: every connection is a separate database, so force a single connection
        opt.max_connections(1);
        let database = Database::connect(opt).await.expect("Database connection failed");
        migration::runner::up_transactional::<Migrator, _>(&database, None).await.unwrap();
        Self { database }
    }

    /// File-backed test DB with a real multi-connection pool (WAL enabled).
    ///
    /// Unlike `mem_test_db`, each instance connects to the same file, so
    /// concurrent writers actually contend and can hit
    /// SQLITE_BUSY_SNAPSHOT / primary-key races. The caller must delete
    /// `path` afterwards.
    ///
    /// The path is embedded in a SQLite URL, so it must be a plain absolute
    /// path without `?`, `#` or spaces (tempfile paths qualify).
    pub async fn file_test_db(path: &std::path::Path) -> Self {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        Self::new(&StoreRuntimeConfig { database_path: url })
            .await
            .expect("file test db init failed")
    }

    pub async fn validate_init_config_can_import(config: InitConfig) -> Result<(), DbError> {
        Self::mem_test_db().await.truncate_and_fit_from(Some(config)).await
    }
}

macro_rules! truncate_tables_reverse {
    ($txn:expr,) => {};
    ($txn:expr, $store_name:ident : ($repo_type:ty, $init_field:ident), $($rest:tt)*) => {{
        truncate_tables_reverse!($txn, $($rest)*);
        <<$repo_type as crate::repository::Repository>::Entity as EntityTrait>::delete_many()
            .exec($txn)
            .await?;
    }};
}

macro_rules! define_store {
    ( $( $store_name:ident : ($repo_type:ty, $init_field:ident) ),* $(,)? ) => {
        impl LandscapeDBServiceProvider {
            $(
                // Generates a getter
                pub fn $store_name(&self) -> $repo_type {
                    <$repo_type>::new(self.database.clone())
                }
            )*

            async fn import_init_config_in_transaction(
                txn: &DatabaseTransaction,
                cfg: InitConfig,
            ) -> Result<(), DbError> {
                truncate_tables_reverse!(
                    txn,
                    $( $store_name : ($repo_type, $init_field), )*
                );

                $(
                    for each_config in cfg.$init_field {
                        let active_model: <$repo_type as crate::repository::Repository>::ActiveModel =
                            each_config.into();
                        active_model.insert(txn).await?;
                    }
                )*

                Ok(())
            }

            pub async fn truncate_and_fit_from_before_commit<F>(
                &self,
                config: InitConfig,
                before_commit: F,
            ) -> Result<(), DbError>
            where
                F: FnOnce() -> Result<(), DbError>,
            {
                let txn = self.database.begin().await?;
                let result = async {
                    Self::import_init_config_in_transaction(&txn, config).await?;
                    before_commit()?;
                    Ok::<(), DbError>(())
                }
                .await;

                match result {
                    Ok(()) => {
                        txn.commit().await?;
                        Ok(())
                    }
                    Err(e) => {
                        if let Err(rollback_err) = txn.rollback().await {
                            tracing::warn!("failed to rollback init config import transaction: {rollback_err}");
                        }
                        Err(e)
                    }
                }
            }

            pub async fn truncate_and_fit_from(&self, config: Option<InitConfig>) -> Result<(), DbError> {
                if let Some(cfg) = config {
                    self.truncate_and_fit_from_before_commit(cfg, || Ok(())).await?;
                }

                Ok(())
            }
        }
    }
}

define_store!(
    iface_store: (NetIfaceRepository, ifaces),
    dhcp_v4_server_store: (DHCPv4ServerRepository, dhcpv4_services),
    wifi_service_store: (WifiServiceRepository, wifi_configs),
    firewall_service_store: (FirewallServiceRepository, firewalls),
    firewall_rule_store: (FirewallRuleRepository, firewall_rules),
    firewall_blacklist_store: (FirewallBlacklistRepository, firewall_blacklists),
    iface_ip_service_store: (IfaceIpServiceRepository, ipconfigs),
    nat_service_store: (NatServiceRepository, nats),
    flow_rule_store: (FlowConfigRepository, flow_rules),
    flow_wan_service_store: (FlowWanServiceRepository, marks),
    dst_ip_rule_store: (DstIpRuleRepository, dst_ip_mark),
    pppd_service_store: (PPPDServiceRepository, pppds),
    dns_rule_store: (DNSRuleRepository, dns_rules),
    dhcp_v6_client_store: (DHCPv6ClientRepository, dhcpv6pds),
    mss_clamp_service_store: (MssClampServiceRepository, mss_clamps),
    geo_ip_rule_store: (GeoIpSourceConfigRepository, geo_ips),
    geo_site_rule_store: (GeoSiteConfigRepository, geo_sites),
    route_lan_service_store: (RouteLanServiceRepository, route_lans),
    route_wan_service_store: (RouteWanServiceRepository, route_wans),
    static_nat_mapping_v4_store: (StaticNatMappingV4Repository, static_nat_mappings_v4),
    static_nat_mapping_v6_store: (StaticNatMappingV6Repository, static_nat_mappings_v6),
    dns_redirect_rule_store: (DNSRedirectRuleRepository, dns_redirects),
    dns_upstream_config_store: (DnsUpstreamRepository, dns_upstream_configs),
    enrolled_device_store: (EnrolledDeviceRepository, enrolled_devices),
    lan_ipv6_v2_service_store: (LanIPv6V2ServiceRepository, lan_ipv6s),
    cert_account_store: (CertAccountRepository, cert_accounts),
    cert_store: (CertRepository, certs),
    gateway_http_upstream_store: (GatewayHttpUpstreamRepository, gateway_rules),
    dns_provider_profile_store: (DnsProviderProfileRepository, dns_provider_profiles),
    ddns_job_store: (DdnsJobRepository, ddns_jobs),
);

#[cfg(test)]
mod tests {
    use landscape_common::config::{InitConfig, StoreRuntimeConfig};
    use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
    use landscape_common::database::error::DbError;
    use landscape_common::database::LandscapeStore;

    use crate::provider::LandscapeDBServiceProvider;

    #[tokio::test]
    pub async fn test_run_database() {
        landscape_common::init_tracing!();

        let dir = tempfile::tempdir().unwrap();
        let config = StoreRuntimeConfig {
            database_path: format!("sqlite://{}?mode=rwc", dir.path().join("test.db").display()),
        };
        let _provider = LandscapeDBServiceProvider::new(&config).await.unwrap();
    }

    #[tokio::test]
    pub async fn reopening_database_after_migrations_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.db");

        let _first = LandscapeDBServiceProvider::file_test_db(&path).await;
        // Second open must find zero pending migrations and succeed (the
        // transactional runner re-derives pending state from seaql_migrations).
        let _second = LandscapeDBServiceProvider::file_test_db(&path).await;
    }

    #[tokio::test]
    pub async fn truncate_and_fit_from_none_returns_ok() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;

        provider.truncate_and_fit_from(None).await.unwrap();
    }

    #[tokio::test]
    pub async fn truncate_and_fit_from_returns_error_on_insert_failure() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let duplicate =
            NetworkIfaceConfig::crate_bridge("dup0".to_string(), Some(IfaceZoneType::Lan));
        let init_config = InitConfig {
            ifaces: vec![duplicate.clone(), duplicate],
            ..Default::default()
        };

        let result = provider.truncate_and_fit_from(Some(init_config)).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    pub async fn truncate_and_fit_from_imports_valid_config() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let iface =
            NetworkIfaceConfig::crate_bridge("br-test".to_string(), Some(IfaceZoneType::Lan));
        let init_config = InitConfig { ifaces: vec![iface], ..Default::default() };

        provider.truncate_and_fit_from(Some(init_config)).await.unwrap();

        let imported = provider.iface_store().list().await.unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "br-test");
    }

    #[tokio::test]
    pub async fn truncate_and_fit_from_rolls_back_when_before_commit_fails() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let original =
            NetworkIfaceConfig::crate_bridge("br-original".to_string(), Some(IfaceZoneType::Lan));
        provider
            .truncate_and_fit_from(Some(InitConfig {
                ifaces: vec![original],
                ..Default::default()
            }))
            .await
            .unwrap();

        let replacement = NetworkIfaceConfig::crate_bridge(
            "br-replacement".to_string(),
            Some(IfaceZoneType::Lan),
        );
        let result = provider
            .truncate_and_fit_from_before_commit(
                InitConfig { ifaces: vec![replacement], ..Default::default() },
                || Err(DbError::Internal("config write failed".to_string())),
            )
            .await;

        assert!(result.is_err());
        let imported = provider.iface_store().list().await.unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "br-original");
    }

    #[tokio::test]
    pub async fn validate_init_config_can_import_returns_error_on_invalid_config() {
        let duplicate =
            NetworkIfaceConfig::crate_bridge("dup0".to_string(), Some(IfaceZoneType::Lan));
        let init_config = InitConfig {
            ifaces: vec![duplicate.clone(), duplicate],
            ..Default::default()
        };

        let result = LandscapeDBServiceProvider::validate_init_config_can_import(init_config).await;

        assert!(result.is_err());
    }
}
