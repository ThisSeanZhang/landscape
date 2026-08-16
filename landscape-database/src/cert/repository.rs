use std::collections::HashSet;

use landscape_common::cert::account::AccountStatus;
use landscape_common::cert::order::{CertConfig, CertStatus, CertType};
use landscape_common::database::error::DbError;
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, TransactionError, TransactionTrait,
};

use super::entity::{CertActiveModel, CertEntity, CertModel};
use crate::DBId;

#[derive(Clone)]
pub struct CertRepository {
    db: DatabaseConnection,
}

pub struct SyncAccountHintTxResult {
    pub changed_cert_ids: Vec<DBId>,
    pub cancelled_cert_ids: Vec<DBId>,
}

impl CertRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn sync_account_status_hint_tx(
        &self,
        account_id: DBId,
        account_status: &AccountStatus,
        hint_prefix: &str,
    ) -> Result<SyncAccountHintTxResult, DbError> {
        let account_is_registered = matches!(account_status, AccountStatus::Registered);
        let hint = format!("{hint_prefix} {:?}", account_status);
        let hint_prefix = hint_prefix.to_string();
        let hint_opt = if account_is_registered { None } else { Some(hint) };

        self.db
            .transaction::<_, SyncAccountHintTxResult, DbError>(|txn| {
                let hint_prefix = hint_prefix.clone();
                let hint_opt = hint_opt.clone();
                Box::pin(async move {
                    let cert_models = CertEntity::find().all(txn).await?;
                    let mut changed_cert_ids = Vec::new();
                    let mut cancelled_cert_ids = HashSet::new();

                    for cert_model in cert_models {
                        let mut cert: CertConfig = cert_model.clone().into();
                        let CertType::Acme(acme) = &cert.cert_type else {
                            continue;
                        };
                        if acme.account_id != account_id {
                            continue;
                        }

                        let mut changed = false;
                        if let Some(hint) = &hint_opt {
                            if matches!(cert.status, CertStatus::Processing) {
                                cert.status = CertStatus::Cancelled;
                                cancelled_cert_ids.insert(cert.id);
                                changed = true;
                            }
                            if cert.status_message.as_deref() != Some(hint.as_str()) {
                                cert.status_message = Some(hint.clone());
                                changed = true;
                            }
                        } else if cert
                            .status_message
                            .as_deref()
                            .is_some_and(|m| m.starts_with(&hint_prefix))
                        {
                            cert.status_message = None;
                            changed = true;
                        }

                        if changed {
                            let active: CertActiveModel = cert.into();
                            active.update(txn).await?;
                            changed_cert_ids.push(cert_model.id);
                        }
                    }

                    Ok(SyncAccountHintTxResult {
                        changed_cert_ids,
                        cancelled_cert_ids: cancelled_cert_ids.into_iter().collect(),
                    })
                })
            })
            .await
            .map_err(|e| match e {
                TransactionError::Connection(db_err) => DbError::Database(db_err),
                TransactionError::Transaction(ld_err) => ld_err,
            })
    }
}

crate::impl_repository!(CertRepository, CertModel, CertEntity, CertActiveModel, CertConfig, DBId);
