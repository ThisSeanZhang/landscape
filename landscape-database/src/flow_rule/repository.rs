use landscape_common::config::FlowId;
use landscape_common::database::LandscapeFlowTrait;
use landscape_common::database::{repository::Repository, LandscapeDBTrait};
use landscape_common::error::LdError;
use landscape_common::flow::config::FlowConfig;
use landscape_common::flow::FlowTarget;
use migration::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::flow_rule::entity::Column;
use crate::DBId;

use super::entity::{FlowConfigActiveModel, FlowConfigEntity, FlowConfigModel};

#[derive(Clone)]
pub struct FlowConfigRepository {
    db: DatabaseConnection,
}

impl FlowConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_flow_id(&self, flow_id: FlowId) -> Result<Option<FlowConfig>, LdError> {
        let result =
            FlowConfigEntity::find().filter(Column::FlowId.eq(flow_id)).one(&self.db).await?;

        Ok(result.map(From::from))
    }

    pub async fn find_by_target(&self, t: FlowTarget) -> Result<Vec<FlowConfig>, LdError> {
        // 构造条件 SQL 和参数
        let (condition_sql, param_value) = match t {
        FlowTarget::Interface { name } => (
            "json_extract(json_each.value, '$.t') = 'interface' AND json_extract(json_each.value, '$.name') = ?",
            name,
        ),
        FlowTarget::Netns { container_name } => (
            "json_extract(json_each.value, '$.t') = 'netns' AND json_extract(json_each.value, '$.container_name') = ?",
            container_name,
        ),
    };

        let full_sql = format!(
            "EXISTS (
            SELECT 1 FROM json_each(packet_handle_iface_name)
            WHERE {}
        )",
            condition_sql
        );

        let expr = Expr::cust_with_values(
            &full_sql,
            vec![sea_orm::Value::String(Some(Box::new(param_value)))],
        );

        // 查询执行
        let result = FlowConfigEntity::find().filter(expr).all(&self.db).await?;

        Ok(result.into_iter().map(From::from).collect())
    }
}

#[async_trait::async_trait]
impl LandscapeDBTrait for FlowConfigRepository {}

#[async_trait::async_trait]
impl LandscapeFlowTrait for FlowConfigRepository {}

#[async_trait::async_trait]
impl Repository for FlowConfigRepository {
    type Model = FlowConfigModel;
    type Entity = FlowConfigEntity;
    type ActiveModel = FlowConfigActiveModel;
    type Data = FlowConfig;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
