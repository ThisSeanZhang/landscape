use std::fmt::Debug;

use async_trait::async_trait;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, DatabaseConnection, EntityTrait, FromQueryResult,
    IntoActiveModel, PrimaryKeyTrait,
};

use crate::error::LdError;

/// 通用 Repository Trait
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

    /// 提供数据库连接
    fn db(&self) -> &DatabaseConnection;

    /// 列出所有数据
    #[allow(dead_code)]
    async fn list_all(&self) -> Result<Vec<Self::Data>, LdError> {
        let models: Vec<Self::Model> = <Self::Entity as EntityTrait>::find().all(self.db()).await?;
        Ok(models.into_iter().map(From::from).collect())
    }

    /// 插入数据
    #[allow(dead_code)]
    async fn set_model(&self, data: Self::Data) -> Result<Self::Data, LdError> {
        let active_model: Self::ActiveModel = data.into();
        let inserted = active_model.insert(self.db()).await?;
        Ok(inserted.into())
    }

    /// 删除
    #[allow(dead_code)]
    async fn delete_model(&self, id: Self::Id) -> Result<(), LdError> {
        <Self::Entity as EntityTrait>::delete_by_id(id).exec(self.db()).await?;
        Ok(())
    }

    /// 查找指定 ID
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

    /// 清空
    #[allow(dead_code)]
    async fn truncate_table(&self) -> Result<(), LdError> {
        <Self::Entity as EntityTrait>::delete_many().exec(self.db()).await?;
        Ok(())
    }

    #[allow(dead_code)]
    async fn set_or_update_model(
        &self,
        id: Self::Id,
        config: Self::Data,
    ) -> Result<Self::Data, LdError> {
        // tracing::info!("try to find id: {id:?}");
        if let Some(data) = self.find_by_id(id).await? {
            // tracing::info!("data: {data:?}");
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

pub trait UpdateActiveModel<ActiveModel> {
    fn update(self, active: &mut ActiveModel);
}

pub trait LandscapeDBStore<Id> {
    fn get_id(&self) -> Id;
}
