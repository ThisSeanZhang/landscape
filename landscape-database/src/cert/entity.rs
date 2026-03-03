use crate::repository::UpdateActiveModel;
use landscape_common::cert::order::CertConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type CertModel = Model;
pub type CertEntity = Entity;
pub type CertActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "certs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub domains: DBJson,
    pub status: String,
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub certificate_chain: Option<String>,
    pub expires_at: Option<DBTimestamp>,
    pub issued_at: Option<DBTimestamp>,
    pub status_message: Option<String>,
    pub cert_type: DBJson,
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

impl From<Model> for CertConfig {
    fn from(entity: Model) -> Self {
        CertConfig {
            id: entity.id,
            name: entity.name,
            domains: serde_json::from_value(entity.domains).unwrap(),
            status: serde_json::from_value(serde_json::Value::String(entity.status)).unwrap(),
            private_key: entity.private_key,
            certificate: entity.certificate,
            certificate_chain: entity.certificate_chain,
            expires_at: entity.expires_at,
            issued_at: entity.issued_at,
            status_message: entity.status_message,
            cert_type: serde_json::from_value(entity.cert_type).unwrap(),
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for CertConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for CertConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.domains = Set(serde_json::to_value(self.domains).unwrap());
        active.status =
            Set(serde_json::to_value(&self.status).unwrap().as_str().unwrap().to_string());
        active.private_key = Set(self.private_key);
        active.certificate = Set(self.certificate);
        active.certificate_chain = Set(self.certificate_chain);
        active.expires_at = Set(self.expires_at);
        active.issued_at = Set(self.issued_at);
        active.status_message = Set(self.status_message);
        active.cert_type = Set(serde_json::to_value(&self.cert_type).unwrap());
        active.update_at = Set(self.update_at);
    }
}
