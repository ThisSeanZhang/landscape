use landscape_common::database::error::DbError;
use landscape_common::database::validator::StoreValidator;
use landscape_common::ddns::{DdnsJob, DdnsSource};
use landscape_common::service::ServiceConfigError;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{Column, DdnsJobActiveModel, DdnsJobEntity, DdnsJobModel};
use crate::DBId;
use crate::repository::Repository;
use crate::wan_link::repository::{WanLinkRepository, resolve_wan_link_name};

#[derive(Clone)]
pub struct DdnsJobRepository {
    db: DatabaseConnection,
}

impl DdnsJobRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_enabled(&self) -> Result<Vec<DdnsJob>, DbError> {
        let models = DdnsJobEntity::find().filter(Column::Enable.eq(true)).all(self.db()).await?;
        Ok(models.into_iter().map(Into::into).collect())
    }
}

crate::impl_repository!(
    DdnsJobRepository,
    DdnsJobModel,
    DdnsJobEntity,
    DdnsJobActiveModel,
    DdnsJob,
    DBId
);

#[async_trait::async_trait]
impl StoreValidator<DdnsJob> for DdnsJobRepository {
    async fn check_zone(&self, _config: &DdnsJob) -> Result<(), ServiceConfigError> {
        Ok(())
    }

    /// WAN sources reference wan links by uuid (`local_wan.link_id`,
    /// `enrolled_device.wan_pd_link_id`); resolve strictly and refresh the
    /// net-iface name mirrors.
    async fn validate_cross(&self, config: &mut DdnsJob) -> Result<(), ServiceConfigError> {
        let links = WanLinkRepository::new(self.db.clone())
            .net_iface_map()
            .await
            .map_err(ServiceConfigError::internal)?;
        for source in &mut config.sources {
            match source {
                DdnsSource::LocalWan { link_id, iface_name, .. } => {
                    let iface = resolve_wan_link_name(&links, *link_id, "DDNS source")?;
                    if iface_name != iface {
                        *iface_name = iface.to_string();
                    }
                }
                DdnsSource::EnrolledDevice { wan_pd_link_id, wan_pd_id, .. } => {
                    let iface =
                        resolve_wan_link_name(&links, *wan_pd_link_id, "DDNS source wan_pd")?;
                    if wan_pd_id.as_deref() != Some(iface) {
                        *wan_pd_id = Some(iface.to_string());
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::database::store::ConfigStore;
    use landscape_common::ddns::{DdnsJob, DdnsRecordConfig, DdnsSource, IpFamily};
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn link(id: Uuid, attach: &str, kind: WanLinkKind) -> WanLinkConfig {
        WanLinkConfig {
            id,
            name: String::new(),
            attach_iface_name: attach.to_string(),
            link_chain_id: 0,
            kind,
            v4: Default::default(),
            pd: Default::default(),
            nat: Default::default(),
            firewall: Default::default(),
            mss: Default::default(),
            update_at: 0.0,
        }
    }

    fn pppd(ppp: &str) -> WanLinkKind {
        WanLinkKind::Pppd {
            ppp_iface_name: ppp.to_string(),
            peer_id: "peer".to_string(),
            password: "pass".to_string(),
            ac: None,
            plugin: Default::default(),
        }
    }

    fn job(sources: Vec<DdnsSource>) -> DdnsJob {
        DdnsJob {
            id: Uuid::new_v4(),
            name: "job".to_string(),
            enable: true,
            sources,
            zone_name: "example.com".to_string(),
            provider_profile_id: Uuid::new_v4(),
            ttl: Some(300),
            records: vec![DdnsRecordConfig { name: "www".to_string(), enable: true }],
            update_at: 0.0,
        }
    }

    async fn setup() -> (LandscapeDBServiceProvider, Uuid, Uuid, Uuid) {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let profile_id = Uuid::new_v4();
        provider
            .dns_provider_profile_store()
            .upsert(landscape_common::dns::provider_profile::DnsProviderProfile {
                id: profile_id,
                name: "profile".to_string(),
                provider_config: Default::default(),
                remark: None,
                ddns_default_ttl: None,
                update_at: 0.0,
            })
            .await
            .unwrap();
        let eth_id = Uuid::new_v4();
        let pppd_id = Uuid::new_v4();
        provider
            .wan_link_store()
            .upsert(link(eth_id, "eth0", WanLinkKind::Ethernet))
            .await
            .unwrap();
        provider.wan_link_store().upsert(link(pppd_id, "eth1", pppd("ppp0"))).await.unwrap();
        (provider, profile_id, eth_id, pppd_id)
    }

    #[tokio::test]
    async fn source_mirrors_are_rewritten_from_the_links() {
        let (provider, profile_id, eth_id, pppd_id) = setup().await;

        let mut cfg = job(vec![
            DdnsSource::LocalWan {
                link_id: eth_id,
                iface_name: "stale".to_string(),
                family: IpFamily::Ipv4,
            },
            DdnsSource::EnrolledDevice {
                device_id: Uuid::new_v4(),
                wan_pd_link_id: pppd_id,
                wan_pd_id: Some("stale".to_string()),
                family: IpFamily::Ipv6,
            },
        ]);
        cfg.provider_profile_id = profile_id;

        let saved = provider.ddns_job_store().checked_upsert(cfg).await.unwrap().new;

        // ethernet mirrors attach_iface_name; pppd mirrors ppp_iface_name
        match &saved.sources[0] {
            DdnsSource::LocalWan { iface_name, .. } => assert_eq!(iface_name, "eth0"),
            other => panic!("expected local_wan source, got {other:?}"),
        }
        match &saved.sources[1] {
            DdnsSource::EnrolledDevice { wan_pd_id, .. } => {
                assert_eq!(wan_pd_id.as_deref(), Some("ppp0"))
            }
            other => panic!("expected enrolled_device source, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_local_wan_link_id_is_rejected() {
        let (provider, ..) = setup().await;

        let result = provider
            .ddns_job_store()
            .checked_upsert(job(vec![DdnsSource::LocalWan {
                link_id: Uuid::new_v4(),
                iface_name: "eth0".to_string(),
                family: IpFamily::Ipv4,
            }]))
            .await;
        assert!(result.is_err(), "an unknown link_id must be rejected");
    }

    #[tokio::test]
    async fn unknown_wan_pd_link_id_is_rejected() {
        let (provider, ..) = setup().await;

        let result = provider
            .ddns_job_store()
            .checked_upsert(job(vec![DdnsSource::EnrolledDevice {
                device_id: Uuid::new_v4(),
                wan_pd_link_id: Uuid::new_v4(),
                wan_pd_id: Some("ppp0".to_string()),
                family: IpFamily::Ipv6,
            }]))
            .await;
        assert!(result.is_err(), "an unknown wan_pd_link_id must be rejected");
    }
}
