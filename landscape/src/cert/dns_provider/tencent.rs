use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use landscape_common::cert::CertError;
use reqwest::header::{CONTENT_TYPE, HOST};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::common::{candidate_zones, relative_record_name, RecordStore};
use super::{DnsChallengeSolver, DnsRecordUpdater};

const TENCENT_API_BASE: &str = "https://dnspod.tencentcloudapi.com/";
const TENCENT_API_HOST: &str = "dnspod.tencentcloudapi.com";
const TENCENT_API_VERSION: &str = "2021-03-23";
const TENCENT_SERVICE: &str = "dnspod";
const TENCENT_SIGNED_HEADERS: &str = "content-type;host;x-tc-action";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct TencentCleanupRecord {
    domain: String,
    record_id: u64,
}

pub struct TencentSolver {
    client: Client,
    secret_id: String,
    secret_key: String,
    base_url: String,
    records: RecordStore<TencentCleanupRecord>,
}

#[derive(Debug, Deserialize)]
struct TencentEnvelope<T> {
    #[serde(rename = "Response")]
    response: TencentResponse<T>,
}

#[derive(Debug, Deserialize)]
struct TencentResponse<T> {
    #[serde(rename = "RequestId")]
    #[allow(dead_code)]
    request_id: Option<String>,
    #[serde(rename = "Error")]
    error: Option<TencentError>,
    #[serde(flatten)]
    body: T,
}

#[derive(Debug, Deserialize)]
struct TencentError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Deserialize)]
struct TencentDomainInfo {
    #[serde(rename = "DomainInfo")]
    #[allow(dead_code)]
    domain_info: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct TencentCreateRecordBody {
    #[serde(rename = "RecordId")]
    record_id: u64,
}

#[derive(Debug, Deserialize)]
struct TencentEmptyBody {}

#[derive(Debug, Deserialize)]
struct TencentDescribeRecordListBody {
    #[serde(rename = "RecordList", default)]
    record_list: Vec<TencentRecordItem>,
}

#[derive(Debug, Deserialize)]
struct TencentRecordItem {
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
}

impl TencentSolver {
    pub fn new(secret_id: String, secret_key: String) -> Self {
        Self::with_base_url(secret_id, secret_key, TENCENT_API_BASE)
    }

    pub fn with_base_url(
        secret_id: String,
        secret_key: String,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            secret_id,
            secret_key,
            base_url: base_url.into(),
            records: RecordStore::new(),
        }
    }

    fn sha256_hex(value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hmac_sha256(key: &[u8], message: &str) -> Result<Vec<u8>, CertError> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to initialize Tencent signer: {e}"))
        })?;
        mac.update(message.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn host_header(&self) -> Result<String, CertError> {
        let url = reqwest::Url::parse(&self.base_url).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Invalid Tencent API base URL: {e}"))
        })?;
        let host = url.host_str().unwrap_or(TENCENT_API_HOST);
        let Some(port) = url.port() else {
            return Ok(host.to_string());
        };
        Ok(format!("{host}:{port}"))
    }

    fn authorization(
        &self,
        action: &str,
        timestamp: i64,
        payload: &str,
    ) -> Result<String, CertError> {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\n",
            self.host_header()?,
            action.to_ascii_lowercase()
        );
        let canonical_request = format!(
            "POST\n/\n\n{canonical_headers}\n{TENCENT_SIGNED_HEADERS}\n{}",
            Self::sha256_hex(payload)
        );
        let credential_scope = format!("{date}/{TENCENT_SERVICE}/tc3_request");
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
            Self::sha256_hex(&canonical_request)
        );

        let secret_date = Self::hmac_sha256(format!("TC3{}", self.secret_key).as_bytes(), &date)?;
        let secret_service = Self::hmac_sha256(&secret_date, TENCENT_SERVICE)?;
        let secret_signing = Self::hmac_sha256(&secret_service, "tc3_request")?;
        let signature = Self::hmac_sha256(&secret_signing, &string_to_sign)?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Ok(format!(
            "TC3-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={TENCENT_SIGNED_HEADERS}, Signature={signature}",
            self.secret_id
        ))
    }

    async fn request<T>(&self, action: &str, payload: Value) -> Result<T, CertError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let payload_str = serde_json::to_string(&payload).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to serialize Tencent payload: {e}"))
        })?;
        let timestamp = Utc::now().timestamp();
        let authorization = self.authorization(action, timestamp, &payload_str)?;

        let response = self
            .client
            .post(self.base_url.clone())
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .header(HOST, self.host_header()?)
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Version", TENCENT_API_VERSION)
            .header("Authorization", authorization)
            .body(payload_str)
            .send()
            .await
            .map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!("Tencent API request failed: {e}"))
            })?;

        let text = response.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to read Tencent response: {e}"))
        })?;
        let envelope: TencentEnvelope<T> = serde_json::from_str(&text).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to parse Tencent response: {e}"))
        })?;

        if let Some(error) = envelope.response.error {
            return Err(CertError::DnsChallengeSetupFailed(format!(
                "Tencent {action} failed [{}]: {}",
                error.code, error.message
            )));
        }

        Ok(envelope.response.body)
    }

    async fn validate_credentials(&self) -> Result<(), CertError> {
        self.request::<Value>("DescribeDomainList", json!({ "Offset": 0, "Limit": 1 }))
            .await
            .map(|_| ())
    }

    async fn validate_zone_access(&self, zone_name: &str) -> Result<(), CertError> {
        self.request::<TencentDomainInfo>("DescribeDomain", json!({ "Domain": zone_name }))
            .await
            .map(|_| ())
    }

    async fn validate_domain_access(&self, domain: &str) -> Result<(), CertError> {
        self.find_zone_name(domain).await.map(|_| ())
    }

    fn is_domain_not_found(err: &CertError) -> bool {
        let text = err.to_string().to_ascii_lowercase();
        text.contains("nodataofdomain")
            || text.contains("domainnotfound")
            || text.contains("domainnotexists")
            || text.contains("not found")
    }

    async fn find_zone_name(&self, domain: &str) -> Result<String, CertError> {
        for candidate in candidate_zones(domain) {
            match self
                .request::<TencentDomainInfo>("DescribeDomain", json!({ "Domain": candidate }))
                .await
            {
                Ok(_) => return Ok(candidate),
                Err(err) if Self::is_domain_not_found(&err) => continue,
                Err(err) => return Err(err),
            }
        }

        Err(CertError::DnsChallengeSetupFailed(format!(
            "Could not find Tencent DNS zone for domain: {domain}"
        )))
    }

    async fn upsert_dns_record(
        &self,
        zone_name: &str,
        sub_domain: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), CertError> {
        let list: TencentDescribeRecordListBody = self
            .request(
                "DescribeRecordList",
                json!({ "Domain": zone_name, "Subdomain": sub_domain, "RecordType": record_type }),
            )
            .await?;

        if let Some(record_id) = list
            .record_list
            .into_iter()
            .find(|item| item.name == sub_domain && item.record_type == record_type)
            .map(|item| item.record_id)
        {
            let _: TencentEmptyBody = self
                .request(
                    "ModifyRecord",
                    json!({
                        "Domain": zone_name,
                        "RecordId": record_id,
                        "SubDomain": sub_domain,
                        "RecordType": record_type,
                        "RecordLine": "默认",
                        "RecordLineId": "0",
                        "Value": value,
                        "TTL": ttl
                    }),
                )
                .await?;
        } else {
            let _: TencentCreateRecordBody = self
                .request(
                    "CreateRecord",
                    json!({
                        "Domain": zone_name,
                        "SubDomain": sub_domain,
                        "RecordType": record_type,
                        "RecordLine": "默认",
                        "RecordLineId": "0",
                        "Value": value,
                        "TTL": ttl
                    }),
                )
                .await?;
        }
        Ok(())
    }
}

pub async fn validate_credentials(secret_id: &str, secret_key: &str) -> Result<(), CertError> {
    TencentSolver::new(secret_id.to_string(), secret_key.to_string()).validate_credentials().await
}

pub async fn validate_zone_access(
    secret_id: &str,
    secret_key: &str,
    zone_name: &str,
) -> Result<(), CertError> {
    TencentSolver::new(secret_id.to_string(), secret_key.to_string())
        .validate_zone_access(zone_name)
        .await
}

pub async fn validate_domain_access(
    secret_id: &str,
    secret_key: &str,
    domain: &str,
) -> Result<(), CertError> {
    TencentSolver::new(secret_id.to_string(), secret_key.to_string())
        .validate_domain_access(domain)
        .await
}

#[async_trait::async_trait]
impl DnsRecordUpdater for TencentSolver {
    async fn upsert_record(
        &self,
        zone_name: &str,
        record_name: &str,
        value: &str,
        record_type: &str,
        ttl: u32,
    ) -> Result<(), CertError> {
        self.upsert_dns_record(zone_name, record_name, record_type, value, ttl).await
    }
}

#[async_trait::async_trait]
impl DnsChallengeSolver for TencentSolver {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let zone_name = self.find_zone_name(domain).await?;
        let sub_domain = relative_record_name(domain, &zone_name)?;
        let response = self
            .request::<TencentCreateRecordBody>(
                "CreateRecord",
                json!({
                    "Domain": zone_name,
                    "SubDomain": sub_domain,
                    "RecordType": "TXT",
                    "RecordLine": "默认",
                    "RecordLineId": "0",
                    "Value": value,
                    "TTL": 120
                }),
            )
            .await?;

        self.records.insert(
            domain,
            value,
            TencentCleanupRecord { domain: zone_name, record_id: response.record_id },
        );
        tracing::info!("Created Tencent TXT record for {domain}");
        Ok(())
    }

    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let Some(record) = self.records.get_cloned(domain, value) else {
            tracing::warn!("No Tencent TXT record found to clean up for {domain}");
            return Ok(());
        };

        self.request::<TencentEmptyBody>(
            "DeleteRecord",
            json!({
                "Domain": record.domain,
                "RecordId": record.record_id
            }),
        )
        .await?;
        self.records.remove(domain, value);
        tracing::info!("Cleaned up Tencent TXT record for {domain}");
        Ok(())
    }
}
