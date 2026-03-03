use crate::repository::UpdateActiveModel;
use landscape_common::cert::account::CertAccountConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type CertAccountModel = Model;
pub type CertAccountEntity = Entity;
pub type CertAccountActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "cert_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub provider_config: DBJson,
    pub email: String,
    pub account_private_key: Option<String>,
    pub acme_account_url: Option<String>,
    pub use_staging: bool,
    pub terms_agreed: bool,
    pub status: String,
    pub status_message: Option<String>,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert && self.id.is_not_set() {
            self.id = Set(Uuid::new_v4());
        }
        Ok(self)
    }
}

impl From<Model> for CertAccountConfig {
    fn from(entity: Model) -> Self {
        CertAccountConfig {
            id: entity.id,
            name: entity.name,
            provider_config: serde_json::from_value(entity.provider_config).unwrap(),
            email: entity.email,
            account_private_key: entity.account_private_key,
            acme_account_url: entity.acme_account_url,
            use_staging: entity.use_staging,
            terms_agreed: entity.terms_agreed,
            status: serde_json::from_value(serde_json::Value::String(entity.status)).unwrap(),
            status_message: entity.status_message,
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for CertAccountConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for CertAccountConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.provider_config = Set(serde_json::to_value(self.provider_config).unwrap());
        active.email = Set(self.email);
        active.account_private_key = Set(self.account_private_key);
        active.acme_account_url = Set(self.acme_account_url);
        active.use_staging = Set(self.use_staging);
        active.terms_agreed = Set(self.terms_agreed);
        active.status =
            Set(serde_json::to_value(&self.status).unwrap().as_str().unwrap().to_string());
        active.status_message = Set(self.status_message);
        active.update_at = Set(self.update_at);
    }
}
