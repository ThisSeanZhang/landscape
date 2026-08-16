use std::fmt::Debug;

use async_trait::async_trait;
use landscape_common::config::FlowId;
use landscape_common::database::repository::LandscapeDBStore;
use landscape_common::error::LdError;
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

    /// Lists all data.
    #[allow(dead_code)]
    async fn list_all(&self) -> Result<Vec<Self::Data>, LdError> {
        let models: Vec<Self::Model> = <Self::Entity as EntityTrait>::find().all(self.db()).await?;
        Ok(models.into_iter().map(From::from).collect())
    }

    /// Inserts data, always refreshing `update_at`: every write path must bump
    /// the version, otherwise `checked_upsert` cannot detect stale writes.
    /// A pure insert has no previous version, so the server clock defines it.
    #[allow(dead_code)]
    async fn set_model(&self, mut data: Self::Data) -> Result<Self::Data, LdError> {
        data.set_update_at(landscape_common::utils::time::get_f64_timestamp());
        let active_model: Self::ActiveModel = data.into();
        let inserted = active_model.insert(self.db()).await?;
        Ok(inserted.into())
    }

    /// Deletes by ID.
    #[allow(dead_code)]
    async fn delete_model(&self, id: Self::Id) -> Result<(), LdError> {
        <Self::Entity as EntityTrait>::delete_by_id(id).exec(self.db()).await?;
        Ok(())
    }

    /// Finds by ID.
    #[allow(dead_code)]
    async fn find_by_id(&self, id: Self::Id) -> Result<Option<Self::Data>, LdError> {
        let pk_value = id.into();
        let result = <Self::Entity as EntityTrait>::find_by_id(pk_value).one(self.db()).await?;
        Ok(result.map(From::from))
    }

    #[allow(dead_code)]
    async fn find_by_ids(&self, ids: Vec<Self::Id>) -> Vec<Self::Data> {
        let mut result = Vec::with_capacity(ids.len());
        for id in ids.into_iter() {
            if let Ok(Some(r)) = self.find_by_id(id).await {
                result.push(r);
            }
        }
        result
    }

    /// Truncates the table.
    #[allow(dead_code)]
    async fn truncate_table(&self) -> Result<(), LdError> {
        <Self::Entity as EntityTrait>::delete_many().exec(self.db()).await?;
        Ok(())
    }

    /// Read-only conflict check: compares the incoming `update_at` with the stored one.
    #[allow(dead_code)]
    async fn check_conflict_by_id(
        &self,
        id: Self::Id,
        incoming_update_at: f64,
    ) -> Result<Option<Self::Data>, LdError> {
        if let Some(existing) = self.find_by_id(id).await? {
            if (existing.get_update_at() - incoming_update_at).abs() > f64::EPSILON {
                return Err(LdError::ConfigConflict);
            }
            Ok(Some(existing))
        } else {
            Ok(None)
        }
    }

    /// Optimistic-lock set: check `update_at`, refresh the timestamp, then write.
    #[allow(dead_code)]
    async fn checked_set_or_update_model(
        &self,
        id: Self::Id,
        mut config: Self::Data,
    ) -> Result<Self::Data, LdError> {
        if let Some(existing) = self.find_by_id(id).await? {
            if (existing.get_update_at() - config.get_update_at()).abs() > f64::EPSILON {
                return Err(LdError::ConfigConflict);
            }
            // Bump the version monotonically from the stored one (see set_or_update_model).
            config.set_update_at(
                existing.next_update_at(landscape_common::utils::time::get_f64_timestamp()),
            );
            let mut active: Self::ActiveModel = existing.into();
            config.update(&mut active);
            Ok(active.update(self.db()).await?.into())
        } else {
            config.set_update_at(landscape_common::utils::time::get_f64_timestamp());
            let active_model: Self::ActiveModel = config.into();
            Ok(active_model.insert(self.db()).await?.into())
        }
    }

    #[allow(dead_code)]
    async fn set_or_update_model(
        &self,
        id: Self::Id,
        mut config: Self::Data,
    ) -> Result<Self::Data, LdError> {
        if let Some(data) = self.find_by_id(id).await? {
            // Derive the new version from the row just read, not the client's
            // echoed `update_at`: two requests with the same stale version could
            // otherwise write identical versions in the same millisecond, or
            // even smaller ones on clock rollback.
            config.set_update_at(
                data.next_update_at(landscape_common::utils::time::get_f64_timestamp()),
            );
            let mut d: Self::ActiveModel = data.into();
            config.update(&mut d);
            Ok(d.update(self.db()).await?.into())
        } else {
            match self.set_model(config).await {
                Ok(data) => Ok(data),
                Err(e) => {
                    tracing::error!("e: {e:?}");
                    Err(e)
                }
            }
        }
    }
}

/// Flow filter expression (Sea-ORM specific).
pub trait FlowFilterExpr {
    fn get_flow_filter(id: FlowId) -> sea_orm::sea_query::SimpleExpr;
}
