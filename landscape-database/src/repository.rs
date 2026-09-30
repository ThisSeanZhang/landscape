use std::fmt::Debug;

use async_trait::async_trait;
use landscape_common::config::FlowId;
use landscape_common::database::error::DbError;
use landscape_common::database::repository::LandscapeDBStore;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, DatabaseConnection, EntityTrait, FromQueryResult,
    IntoActiveModel, PrimaryKeyTrait,
};

/// Maps domain data onto a Sea-ORM ActiveModel.
pub trait UpdateActiveModel<ActiveModel> {
    fn update(self, active: &mut ActiveModel);
}

/// Sea-ORM-specific Repository trait (implementation detail).
#[async_trait]
pub trait Repository
where
    Self: Sync + Send,
{
    type Model: Send + Into<Self::Data> + FromQueryResult + IntoActiveModel<Self::ActiveModel>;
    type Entity: EntityTrait<Model = Self::Model, ActiveModel = Self::ActiveModel>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + Send + ActiveModelBehavior;
    type Data: Send
        + Sync
        + Into<Self::ActiveModel>
        + From<Self::Model>
        + UpdateActiveModel<Self::ActiveModel>
        + LandscapeDBStore<Self::Id>
        + Debug;
    type Id: Into<<<Self::Entity as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType>
        + Send
        + Sync
        + Debug;

    /// Provides the database connection.
    fn db(&self) -> &DatabaseConnection;

    /// Finds by ID.
    #[allow(dead_code)]
    async fn find_by_id(&self, id: Self::Id) -> Result<Option<Self::Data>, DbError> {
        let pk_value = id.into();
        let result = <Self::Entity as EntityTrait>::find_by_id(pk_value).one(self.db()).await?;
        Ok(result.map(From::from))
    }
}

/// Flow filter expression (Sea-ORM specific).
pub trait FlowFilterExpr {
    fn get_flow_filter(id: FlowId) -> sea_orm::sea_query::SimpleExpr;
}
