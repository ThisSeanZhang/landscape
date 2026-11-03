use landscape_common::dns::config::DnsUpstreamConfig;
use sea_orm::{DatabaseConnection, EntityTrait, TransactionTrait};

use super::entity::{
    DnsUpstreamConfigActiveModel, DnsUpstreamConfigEntity, DnsUpstreamConfigModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct DnsUpstreamRepository {
    db: DatabaseConnection,
}

impl DnsUpstreamRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn check_wan_dns_transaction(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        configs: &[DnsUpstreamConfig],
    ) -> Result<(), crate::writer::UpsertErr> {
        use crate::{
            dns_rule::entity::DNSRuleConfigEntity, flow_rule::entity::FlowConfigEntity,
            wan_link::entity::WanLinkConfigEntity, writer::UpsertErr,
        };
        use landscape_common::{
            database::error::DbError, dns::rule::DNSRuleConfig, flow::config::FlowConfig,
            service::ServiceConfigError,
        };
        let invalid = |reason: String| {
            UpsertErr::Database(DbError::Validation(ServiceConfigError::InvalidConfig { reason }))
        };
        let rules: Vec<_> = DNSRuleConfigEntity::find()
            .all(txn)
            .await?
            .into_iter()
            .map(DNSRuleConfig::from)
            .collect();
        let flows: Vec<_> =
            FlowConfigEntity::find().all(txn).await?.into_iter().map(FlowConfig::from).collect();
        for config in configs {
            if !config.is_independent_wan_group()
                && rules.iter().any(|rule| {
                    rule.wan_upstreams.iter().any(|mapping| mapping.upstream_id == config.id)
                })
            {
                return Err(invalid("This upstream is selected by a rule's WAN mapping; keep server IPs and remove its own flow/source/WAN binding".into()));
            }
            if let Some(id) = config.bind_config.follow_flow.filter(|id| *id != 0)
                && !flows.iter().any(|flow| {
                    flow.flow_id == id && flow.enable && flow.failover.ordered_targets()
                })
            {
                return Err(invalid(
                    "DNS WAN binding requires an enabled primary/backup flow".into(),
                ));
            }
            for servers in &config.bind_config.wan_servers {
                if WanLinkConfigEntity::find_by_id(servers.link_id).one(txn).await?.is_none() {
                    return Err(invalid(format!("DNS WAN {} does not exist", servers.link_id)));
                }
            }
        }
        Ok(())
    }

    /// Reference check and deletion share a transaction with rule insertion's
    /// checks, so a concurrent mapping cannot leave a dangling upstream.
    pub async fn delete_unreferenced(
        &self,
        id: DBId,
    ) -> Result<Option<DnsUpstreamConfig>, landscape_common::database::error::DbError> {
        use crate::{dns_rule::entity::DNSRuleConfigEntity, writer::UpsertErr};
        use landscape_common::{
            database::error::DbError, dns::rule::DNSRuleConfig, service::ServiceConfigError,
        };
        crate::writer::txn_retry_loop!(self, |txn| async move {
            let Some(upstream) = DnsUpstreamConfigEntity::find_by_id(id).one(txn).await? else {
                return Ok::<_, UpsertErr>(None);
            };
            let mut references: Vec<_> = DNSRuleConfigEntity::find()
                .all(txn)
                .await?
                .into_iter()
                .map(DNSRuleConfig::from)
                .filter(|rule| {
                    (rule.wan_upstreams.is_empty() && rule.upstream_id == id)
                        || rule.wan_upstreams.iter().any(|mapping| mapping.upstream_id == id)
                })
                .map(|rule| format!("分流 {} 的规则“{}” ({})", rule.flow_id, rule.name, rule.id))
                .collect();
            references.sort();
            if !references.is_empty() {
                return Err(UpsertErr::Database(DbError::Validation(
                    ServiceConfigError::DnsUpstreamInUse { references: references.join("、") },
                )));
            }
            DnsUpstreamConfigEntity::delete_by_id(id).exec(txn).await?;
            Ok(Some(upstream.into()))
        })
    }
}

crate::impl_repository!(
    DnsUpstreamRepository,
    DnsUpstreamConfigModel,
    DnsUpstreamConfigEntity,
    DnsUpstreamConfigActiveModel,
    DnsUpstreamConfig,
    DBId,
    transactional_check = check_wan_dns_transaction
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<DnsUpstreamConfig>
    for DnsUpstreamRepository
{
    async fn check_zone(
        &self,
        _: &DnsUpstreamConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }
    async fn validate_cross(
        &self,
        config: &mut DnsUpstreamConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        use landscape_common::{database::store::ConfigStore, service::ServiceConfigError};
        if !config.is_independent_wan_group() {
            let rules = crate::dns_rule::repository::DNSRuleRepository::new(self.db.clone())
                .list()
                .await
                .map_err(ServiceConfigError::internal)?;
            if rules
                .iter()
                .any(|rule| rule.wan_upstreams.iter().any(|m| m.upstream_id == config.id))
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "This upstream is selected by a rule's WAN mapping; keep server IPs and remove its own flow/source/WAN binding".into(),
                });
            }
        }
        if let Some(id) = config.bind_config.follow_flow.filter(|id| *id != 0) {
            let flows = crate::flow_rule::repository::FlowConfigRepository::new(self.db.clone())
                .list()
                .await
                .map_err(ServiceConfigError::internal)?;
            if !flows
                .iter()
                .any(|flow| flow.flow_id == id && flow.enable && flow.failover.ordered_targets())
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "DNS WAN binding requires an enabled primary/backup flow".into(),
                });
            }
        }
        if !config.bind_config.wan_servers.is_empty() {
            let links = crate::wan_link::repository::WanLinkRepository::new(self.db.clone())
                .net_iface_map()
                .await
                .map_err(ServiceConfigError::internal)?;
            for servers in &config.bind_config.wan_servers {
                if !links.contains_key(&servers.link_id) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!("DNS WAN {} does not exist", servers.link_id),
                    });
                }
            }
        }
        config.bind_config.resolved_wan = None;
        Ok(())
    }
}
