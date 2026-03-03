use std::collections::HashMap;
use std::sync::Mutex;

use landscape_common::cert::CertError;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Deserialize;

use super::DnsChallengeSolver;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareSolver {
    client: Client,
    api_token: String,
    /// Maps (domain, value) → (zone_id, record_id) for cleanup
    records: Mutex<HashMap<(String, String), (String, String)>>,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Option<Vec<CfError>>,
}

#[derive(Deserialize)]
struct CfError {
    message: String,
}

#[derive(Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
}

impl CloudflareSolver {
    pub fn new(api_token: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            records: Mutex::new(HashMap::new()),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_token)
    }

    fn cf_error(resp: &Option<Vec<CfError>>) -> String {
        resp.as_ref()
            .and_then(|errs| errs.first().map(|e| e.message.clone()))
            .unwrap_or_else(|| "unknown Cloudflare API error".to_string())
    }

    /// Find the zone ID for a domain by trying progressively shorter suffixes.
    async fn find_zone_id(&self, domain: &str) -> Result<String, CertError> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len().saturating_sub(1) {
            let candidate = parts[i..].join(".");
            let url = format!("{CF_API_BASE}/zones?name={candidate}");
            let resp = self
                .client
                .get(&url)
                .header(AUTHORIZATION, self.auth_header())
                .send()
                .await
                .map_err(|e| {
                    CertError::DnsChallengeSetupFailed(format!(
                        "Cloudflare API request failed: {e}"
                    ))
                })?;

            let text = resp.text().await.map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to read Cloudflare response: {e}"
                ))
            })?;

            let body: CfResponse<Vec<CfZone>> = serde_json::from_str(&text).map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to parse Cloudflare response: {e}"
                ))
            })?;

            if body.success {
                if let Some(zones) = body.result {
                    if let Some(zone) = zones.into_iter().next() {
                        return Ok(zone.id);
                    }
                }
            }
        }
        Err(CertError::DnsChallengeSetupFailed(format!(
            "Could not find Cloudflare zone for domain: {domain}"
        )))
    }
}

#[async_trait::async_trait]
impl DnsChallengeSolver for CloudflareSolver {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let zone_id = self.find_zone_id(domain).await?;
        let record_name = format!("_acme-challenge.{domain}");

        let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
        let payload = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120
        });

        let resp = self
            .client
            .post(&url)
            .header(AUTHORIZATION, self.auth_header())
            .header(CONTENT_TYPE, "application/json")
            .body(payload.to_string())
            .send()
            .await
            .map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!("Failed to create DNS record: {e}"))
            })?;

        let text = resp.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to read Cloudflare response: {e}"))
        })?;

        let body: CfResponse<CfDnsRecord> = serde_json::from_str(&text).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to parse Cloudflare response: {e}"))
        })?;

        if !body.success {
            return Err(CertError::DnsChallengeSetupFailed(format!(
                "Cloudflare DNS record creation failed: {}",
                Self::cf_error(&body.errors)
            )));
        }

        if let Some(record) = body.result {
            let mut records = self.records.lock().unwrap();
            records.insert((domain.to_string(), value.to_string()), (zone_id, record.id));
        }

        tracing::info!("Created TXT record _acme-challenge.{domain}");
        Ok(())
    }

    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let key = (domain.to_string(), value.to_string());
        let entry = {
            let records = self.records.lock().unwrap();
            records.get(&key).cloned()
        };

        let Some((zone_id, record_id)) = entry else {
            tracing::warn!("No record found to clean up for _acme-challenge.{domain}");
            return Ok(());
        };

        let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}");
        let resp = self
            .client
            .delete(&url)
            .header(AUTHORIZATION, self.auth_header())
            .send()
            .await
            .map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!("Failed to delete DNS record: {e}"))
            })?;

        let text = resp.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to read Cloudflare response: {e}"))
        })?;

        let body: CfResponse<serde_json::Value> = serde_json::from_str(&text).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to parse Cloudflare response: {e}"))
        })?;

        if !body.success {
            tracing::warn!(
                "Failed to clean up TXT record for {domain}: {}",
                Self::cf_error(&body.errors)
            );
        } else {
            tracing::info!("Cleaned up TXT record _acme-challenge.{domain}");
        }

        let mut records = self.records.lock().unwrap();
        records.remove(&key);

        Ok(())
    }
}
