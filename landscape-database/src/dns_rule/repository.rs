use landscape_common::config::{DEFAULT_FLOW_ID, FlowId};
use landscape_common::database::error::DbError;
use landscape_common::database::store::Change;
use landscape_common::database::validator::{StoreValidator, ValidatableConfig};
use landscape_common::dns::rule::DNSRuleConfig;
use landscape_common::service::ServiceConfigError;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait, QueryFilter,
    TransactionTrait,
};

use crate::flow_rule::entity::{Column as FlowConfigColumn, FlowConfigEntity};
use crate::writer::{StoreWriter, UpsertErr, txn_retry_loop};
use crate::{
    DBId,
    dns_rule::entity::{DNSRuleConfigActiveModel, DNSRuleConfigEntity, DNSRuleConfigModel},
};

#[derive(Clone)]
pub struct DNSRuleRepository {
    db: DatabaseConnection,
}

impl DNSRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_id(&self, id: DBId) -> Result<Option<DNSRuleConfig>, DbErr> {
        Ok(DNSRuleConfigEntity::find_by_id(id).one(&self.db).await?.map(DNSRuleConfig::from))
    }

    // REPO_DESIGN: `impl_repository!` cannot run cross-domain validation inside
    // the write txn yet, so these methods hand-roll a `txn_retry_loop!` that
    // checks flow existence and writes the rule(s) in one transaction. Fold
    // them back into the macro once its redesign runs cross-domain validation
    // inside the write transaction.
    pub async fn checked_upsert_flow_rule(
        &self,
        mut config: DNSRuleConfig,
    ) -> Result<Change<DNSRuleConfig>, DbError> {
        self.validate_for_checked_write(&mut config).await?;
        let writer = StoreWriter::<DNSRuleConfigEntity, DNSRuleConfig>::new(self.db.clone());
        let (writer, config) = (&writer, &config);
        txn_retry_loop!(self, |txn| async move {
            Self::ensure_flow_exists(txn, config.flow_id).await?;
            writer.upsert_inner(txn, config.clone(), true).await
        })
    }

    pub async fn checked_upsert_flow_rules(
        &self,
        mut configs: Vec<DNSRuleConfig>,
    ) -> Result<Vec<Change<DNSRuleConfig>>, DbError> {
        for config in &mut configs {
            self.validate_for_checked_write(config).await?;
        }
        let writer = StoreWriter::<DNSRuleConfigEntity, DNSRuleConfig>::new(self.db.clone());
        let (writer, configs) = (&writer, &configs);
        txn_retry_loop!(self, |txn| async move {
            for config in configs.iter() {
                Self::ensure_flow_exists(txn, config.flow_id).await?;
            }
            writer.upsert_many_inner(txn, configs, true).await
        })
    }

    /// Mirrors the validation sequence `impl_repository!` injects into
    /// `checked_upsert`. These checks are in-memory or same-table reads, so
    /// the row-level optimistic lock already closes their races; they stay
    /// outside the write txn.
    async fn validate_for_checked_write(&self, config: &mut DNSRuleConfig) -> Result<(), DbError> {
        if let Err(error) = ValidatableConfig::validate(config) {
            return Err(DbError::Validation(error));
        }
        if let Err(error) = StoreValidator::<DNSRuleConfig>::check_zone(self, config).await {
            return Err(DbError::Validation(error));
        }
        if let Err(error) = StoreValidator::<DNSRuleConfig>::validate_cross(self, config).await {
            return Err(DbError::Validation(error));
        }
        Ok(())
    }

    /// Reads the owning flow inside the caller's write txn; `DEFAULT_FLOW_ID`
    /// is the implicit flow for seeded rules and has no `FlowConfig` row.
    /// A validation rejection maps to `UpsertErr::Database`: no retry, the
    /// txn rolls back and the error surfaces unchanged.
    async fn ensure_flow_exists(
        txn: &DatabaseTransaction,
        flow_id: FlowId,
    ) -> Result<(), UpsertErr> {
        if flow_id == DEFAULT_FLOW_ID {
            return Ok(());
        }
        let exists =
            FlowConfigEntity::find().filter(FlowConfigColumn::FlowId.eq(flow_id)).one(txn).await?;
        if exists.is_none() {
            return Err(UpsertErr::Database(DbError::Validation(
                ServiceConfigError::InvalidConfig {
                    reason: format!("flow {flow_id} does not exist"),
                },
            )));
        }
        Ok(())
    }
}

crate::impl_repository!(
    DNSRuleRepository,
    DNSRuleConfigModel,
    DNSRuleConfigEntity,
    DNSRuleConfigActiveModel,
    DNSRuleConfig,
    DBId
);

crate::impl_flow_store!(DNSRuleRepository, DNSRuleConfigModel, DNSRuleConfigEntity);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<DNSRuleConfig> for DNSRuleRepository {
    async fn check_zone(
        &self,
        _config: &DNSRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &mut DNSRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        if let Some(existing) = self
            .find_by_id(config.id)
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            && existing.flow_id != config.flow_id
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "flow_id of DNS rule '{}' cannot be changed after creation",
                    config.id
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod flow_existence_tests {
    use landscape_common::config::FlowId;
    use landscape_common::database::error::DbError;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::dns::rule::{DNSRuleConfig, FilterResult};
    use landscape_common::flow::config::FlowConfig;
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn flow(flow_id: FlowId) -> FlowConfig {
        FlowConfig {
            id: Uuid::new_v4(),
            enable: true,
            flow_id,
            flow_match_rules: vec![],
            flow_targets: vec![],
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        }
    }

    fn dns_rule(flow_id: FlowId) -> DNSRuleConfig {
        DNSRuleConfig {
            id: Uuid::new_v4(),
            name: format!("dns-{flow_id}"),
            index: 0,
            enable: true,
            filter: FilterResult::default(),
            upstream_id: Uuid::new_v4(),
            mark: Default::default(),
            source: vec![],
            flow_id,
            update_at: 0.0,
        }
    }

    #[tokio::test]
    async fn upsert_flow_rule_succeeds_when_flow_exists() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.flow_rule_store().upsert(flow(7)).await.unwrap();

        let rule = dns_rule(7);
        provider.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await.unwrap();

        let stored = provider.dns_rule_store().find_by_id(rule.id).await.unwrap();
        assert_eq!(stored.map(|rule| rule.flow_id), Some(7));
    }

    #[tokio::test]
    async fn upsert_flow_rule_rejects_missing_flow() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;

        let rule = dns_rule(99);
        let result = provider.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await;

        assert!(matches!(result, Err(DbError::Validation(_))));
        assert!(provider.dns_rule_store().find_by_id(rule.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn default_flow_rule_succeeds_without_flow_config() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;

        let rule = dns_rule(landscape_common::config::DEFAULT_FLOW_ID);
        provider.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await.unwrap();

        let stored = provider.dns_rule_store().find_by_id(rule.id).await.unwrap();
        assert_eq!(stored.map(|rule| rule.flow_id), Some(0));
    }

    #[tokio::test]
    async fn batch_upsert_rejects_all_when_any_flow_missing() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.flow_rule_store().upsert(flow(7)).await.unwrap();

        let good = dns_rule(7);
        let bad = dns_rule(99);
        let result =
            provider.dns_rule_store().checked_upsert_flow_rules(vec![good.clone(), bad]).await;

        assert!(matches!(result, Err(DbError::Validation(_))));
        assert!(provider.dns_rule_store().find_by_id(good.id).await.unwrap().is_none());
    }
}
