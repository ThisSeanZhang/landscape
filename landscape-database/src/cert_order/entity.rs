use crate::repository::UpdateActiveModel;
use landscape_common::cert::order::CertOrderConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type CertOrderModel = Model;
pub type CertOrderEntity = Entity;
pub type CertOrderActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "cert_orders")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub account_id: DBId,
    pub domains: DBJson,
    pub challenge_type: DBJson,
    pub key_type: String,
    pub status: String,
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub certificate_chain: Option<String>,
    pub acme_order_url: Option<String>,
    pub expires_at: Option<DBTimestamp>,
    pub issued_at: Option<DBTimestamp>,
    pub auto_renew: bool,
    pub renew_before_days: i32,
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

impl From<Model> for CertOrderConfig {
    fn from(entity: Model) -> Self {
        CertOrderConfig {
            id: entity.id,
            name: entity.name,
            account_id: entity.account_id,
            domains: serde_json::from_value(entity.domains).unwrap(),
            challenge_type: serde_json::from_value(entity.challenge_type).unwrap(),
            key_type: serde_json::from_value(serde_json::Value::String(entity.key_type)).unwrap(),
            status: serde_json::from_value(serde_json::Value::String(entity.status)).unwrap(),
            private_key: entity.private_key,
            certificate: entity.certificate,
            certificate_chain: entity.certificate_chain,
            acme_order_url: entity.acme_order_url,
            expires_at: entity.expires_at,
            issued_at: entity.issued_at,
            auto_renew: entity.auto_renew,
            renew_before_days: entity.renew_before_days as u32,
            status_message: entity.status_message,
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for CertOrderConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for CertOrderConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.account_id = Set(self.account_id);
        active.domains = Set(serde_json::to_value(self.domains).unwrap());
        active.challenge_type = Set(serde_json::to_value(self.challenge_type).unwrap());
        active.key_type =
            Set(serde_json::to_value(&self.key_type).unwrap().as_str().unwrap().to_string());
        active.status =
            Set(serde_json::to_value(&self.status).unwrap().as_str().unwrap().to_string());
        active.private_key = Set(self.private_key);
        active.certificate = Set(self.certificate);
        active.certificate_chain = Set(self.certificate_chain);
        active.acme_order_url = Set(self.acme_order_url);
        active.expires_at = Set(self.expires_at);
        active.issued_at = Set(self.issued_at);
        active.auto_renew = Set(self.auto_renew);
        active.renew_before_days = Set(self.renew_before_days as i32);
        active.status_message = Set(self.status_message);
        active.update_at = Set(self.update_at);
    }
}
