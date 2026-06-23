// API reference:
//   DescribeSubDomainRecords:
//     https://help.aliyun.com/document_detail/29779.html
//   AddDomainRecord:
//     https://help.aliyun.com/document_detail/29772.html
//   UpdateDomainRecord:
//     https://help.aliyun.com/document_detail/29774.html
//   DeleteDomainRecord:
//     https://help.aliyun.com/document_detail/29773.html
//   DescribeDomainInfo:
//     https://help.aliyun.com/document_detail/29780.html
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use landscape_common::cert::CertError;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;
use uuid::Uuid;

use super::common::{candidate_zones, relative_record_name, RecordStore};
use super::{DnsChallengeSolver, DnsRecordUpdater};

const ALIYUN_API_BASE: &str = "https://alidns.aliyuncs.com/";
const ALIYUN_API_VERSION: &str = "2015-01-09";
const ALIYUN_TXT_TTL: &str = "600";

type HmacSha1 = Hmac<Sha1>;

pub struct AliyunSolver {
    client: Client,
    access_key_id: String,
    access_key_secret: String,
    base_url: String,
    records: RecordStore<String>,
}

#[derive(Debug, Deserialize)]
struct AliyunErrorResponse {
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "Message")]
    message: Option<String>,
}

impl AliyunSolver {
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self::with_base_url(access_key_id, access_key_secret, ALIYUN_API_BASE)
    }

    pub fn with_base_url(
        access_key_id: String,
        access_key_secret: String,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            access_key_id,
            access_key_secret,
            base_url: base_url.into(),
            records: RecordStore::new(),
        }
    }

    fn now_timestamp() -> String {
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn percent_encode(input: &str) -> String {
        let mut encoded = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => encoded.push_str(&format!("%{:02X}", byte)),
            }
        }
        encoded
    }

    fn sign_params(&self, params: &[(String, String)]) -> Result<String, CertError> {
        let canonicalized = params
            .iter()
            .map(|(key, value)| {
                format!("{}={}", Self::percent_encode(key), Self::percent_encode(value))
            })
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("GET&%2F&{}", Self::percent_encode(&canonicalized));
        let mut mac = HmacSha1::new_from_slice(format!("{}&", self.access_key_secret).as_bytes())
            .map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to initialize Aliyun signer: {e}"))
        })?;
        mac.update(string_to_sign.as_bytes());
        Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
    }

    async fn request(
        &self,
        action: &str,
        extra_params: Vec<(String, String)>,
    ) -> Result<Value, CertError> {
        let mut params = vec![
            ("AccessKeyId".to_string(), self.access_key_id.clone()),
            ("Action".to_string(), action.to_string()),
            ("Format".to_string(), "JSON".to_string()),
            ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
            ("SignatureNonce".to_string(), Uuid::new_v4().to_string()),
            ("SignatureVersion".to_string(), "1.0".to_string()),
            ("Timestamp".to_string(), Self::now_timestamp()),
            ("Version".to_string(), ALIYUN_API_VERSION.to_string()),
        ];
        params.extend(extra_params);
        params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let signature = self.sign_params(&params)?;
        params.push(("Signature".to_string(), signature));

        let query = params
            .into_iter()
            .map(|(key, value)| {
                format!("{}={}", Self::percent_encode(&key), Self::percent_encode(&value))
            })
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}?{query}", self.base_url.trim_end_matches('/'));

        let response = self.client.get(url).send().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Aliyun API request failed: {e}"))
        })?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to read Aliyun response: {e}"))
        })?;
        let value: Value = serde_json::from_str(&text).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to parse Aliyun response: {e}"))
        })?;

        if status.is_success() && value.get("Code").is_none() {
            return Ok(value);
        }

        let parsed = serde_json::from_value::<AliyunErrorResponse>(value.clone())
            .unwrap_or(AliyunErrorResponse { code: None, message: None });
        let code = parsed.code.unwrap_or_else(|| status.to_string());
        let message = parsed.message.unwrap_or_else(|| "unknown Aliyun API error".to_string());
        Err(CertError::DnsChallengeSetupFailed(format!(
            "Aliyun {action} failed [{code}]: {message}"
        )))
    }

    async fn validate_credentials(&self) -> Result<(), CertError> {
        self.request(
            "DescribeDomains",
            vec![
                ("PageNumber".to_string(), "1".to_string()),
                ("PageSize".to_string(), "1".to_string()),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn validate_zone_access(&self, zone_name: &str) -> Result<(), CertError> {
        self.request("DescribeDomainInfo", vec![("DomainName".to_string(), zone_name.to_string())])
            .await
            .map(|_| ())
    }

    async fn validate_domain_access(&self, domain: &str) -> Result<(), CertError> {
        self.find_zone_name(domain).await.map(|_| ())
    }

    fn is_domain_not_found(err: &CertError) -> bool {
        let text = err.to_string().to_ascii_lowercase();
        text.contains("domainnamenotexist")
            || text.contains("forbidden.domainnotexist")
            || text.contains("not exist")
            || text.contains("not found")
    }

    async fn find_zone_name(&self, domain: &str) -> Result<String, CertError> {
        for candidate in candidate_zones(domain) {
            match self
                .request("DescribeDomainInfo", vec![("DomainName".to_string(), candidate.clone())])
                .await
            {
                Ok(_) => return Ok(candidate),
                Err(err) if Self::is_domain_not_found(&err) => continue,
                Err(err) => return Err(err),
            }
        }

        Err(CertError::DnsChallengeSetupFailed(format!(
            "Could not find Aliyun DNS zone for domain: {domain}"
        )))
    }

    async fn upsert_dns_record(
        &self,
        zone_name: &str,
        rr: &str,
        fqdn: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), CertError> {
        let query = self
            .request(
                "DescribeSubDomainRecords",
                vec![
                    ("SubDomain".to_string(), fqdn.to_string()),
                    ("Type".to_string(), record_type.to_string()),
                    ("PageSize".to_string(), "1".to_string()),
                ],
            )
            .await?;

        let existing_id = query
            .get("DomainRecords")
            .and_then(|v| v.get("Record"))
            .and_then(Value::as_array)
            .and_then(|records| records.first())
            .and_then(|record| record.get("RecordId"))
            .and_then(|id| match id {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });

        let mut params = vec![
            ("RR".to_string(), rr.to_string()),
            ("Type".to_string(), record_type.to_string()),
            ("Value".to_string(), value.to_string()),
            ("TTL".to_string(), ttl.to_string()),
        ];

        if let Some(record_id) = existing_id {
            params.push(("RecordId".to_string(), record_id));
            self.request("UpdateDomainRecord", params).await?;
        } else {
            params.push(("DomainName".to_string(), zone_name.to_string()));
            self.request("AddDomainRecord", params).await?;
        }
        Ok(())
    }
}

pub async fn validate_credentials(
    access_key_id: &str,
    access_key_secret: &str,
) -> Result<(), CertError> {
    AliyunSolver::new(access_key_id.to_string(), access_key_secret.to_string())
        .validate_credentials()
        .await
}

pub async fn validate_zone_access(
    access_key_id: &str,
    access_key_secret: &str,
    zone_name: &str,
) -> Result<(), CertError> {
    AliyunSolver::new(access_key_id.to_string(), access_key_secret.to_string())
        .validate_zone_access(zone_name)
        .await
}

pub async fn validate_domain_access(
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
) -> Result<(), CertError> {
    AliyunSolver::new(access_key_id.to_string(), access_key_secret.to_string())
        .validate_domain_access(domain)
        .await
}

#[async_trait::async_trait]
impl DnsRecordUpdater for AliyunSolver {
    async fn upsert_record(
        &self,
        zone_name: &str,
        record_name: &str,
        value: &str,
        record_type: &str,
        ttl: u32,
    ) -> Result<(), CertError> {
        let fqdn = if record_name == "@" {
            zone_name.to_string()
        } else {
            format!("{record_name}.{zone_name}")
        };
        self.upsert_dns_record(zone_name, record_name, &fqdn, record_type, value, ttl).await
    }

    async fn reconcile_records(
        &self,
        zone_name: &str,
        record_name: &str,
        record_type: &str,
        desired_values: &[String],
        ttl: u32,
    ) -> Result<(), CertError> {
        let fqdn = if record_name == "@" {
            zone_name.to_string()
        } else {
            format!("{record_name}.{zone_name}")
        };

        let query = self
            .request(
                "DescribeSubDomainRecords",
                vec![
                    ("SubDomain".to_string(), fqdn),
                    ("Type".to_string(), record_type.to_string()),
                ],
            )
            .await?;

        let existing_records: Vec<(String, String)> = query
            .get("DomainRecords")
            .and_then(|v| v.get("Record"))
            .and_then(Value::as_array)
            .map(|records| {
                records
                    .iter()
                    .filter_map(|record| {
                        let id = record.get("RecordId").and_then(|id| match id {
                            Value::String(s) => Some(s.clone()),
                            Value::Number(n) => Some(n.to_string()),
                            _ => None,
                        });
                        let value =
                            record.get("Value").and_then(Value::as_str).map(|s| s.to_string());
                        match (id, value) {
                            (Some(id), Some(value)) => Some((id, value)),
                            _ => None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let desired_set: std::collections::HashSet<&str> =
            desired_values.iter().map(|v| v.as_str()).collect();
        let existing_value_set: std::collections::HashSet<&str> =
            existing_records.iter().map(|(_, v)| v.as_str()).collect();

        for (record_id, record_value) in &existing_records {
            if !desired_set.contains(record_value.as_str()) {
                self.request(
                    "DeleteDomainRecord",
                    vec![("RecordId".to_string(), record_id.clone())],
                )
                .await?;
            }
        }

        for value in desired_values {
            if !existing_value_set.contains(value.as_str()) {
                self.request(
                    "AddDomainRecord",
                    vec![
                        ("DomainName".to_string(), zone_name.to_string()),
                        ("RR".to_string(), record_name.to_string()),
                        ("Type".to_string(), record_type.to_string()),
                        ("Value".to_string(), value.clone()),
                        ("TTL".to_string(), ttl.to_string()),
                    ],
                )
                .await?;
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsChallengeSolver for AliyunSolver {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let zone_name = self.find_zone_name(domain).await?;
        let rr = relative_record_name(domain, &zone_name)?;
        let response = self
            .request(
                "AddDomainRecord",
                vec![
                    ("DomainName".to_string(), zone_name),
                    ("RR".to_string(), rr),
                    ("TTL".to_string(), ALIYUN_TXT_TTL.to_string()),
                    ("Type".to_string(), "TXT".to_string()),
                    ("Value".to_string(), value.to_string()),
                ],
            )
            .await?;

        let record_id = response.get("RecordId").and_then(Value::as_str).ok_or_else(|| {
            CertError::DnsChallengeSetupFailed(
                "Aliyun AddDomainRecord response did not include RecordId".to_string(),
            )
        })?;
        self.records.insert(domain, value, record_id.to_string());
        tracing::info!("Created Aliyun TXT record for {domain}");
        Ok(())
    }

    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let Some(record_id) = self.records.get_cloned(domain, value) else {
            tracing::warn!("No Aliyun TXT record found to clean up for {domain}");
            return Ok(());
        };

        self.request("DeleteDomainRecord", vec![("RecordId".to_string(), record_id.clone())])
            .await?;
        self.records.remove(domain, value);
        tracing::info!("Cleaned up Aliyun TXT record for {domain}");
        Ok(())
    }
}
