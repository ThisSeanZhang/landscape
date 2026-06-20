use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use landscape_common::cert::CertError;
use quick_xml::de::from_str as from_xml_str;
use reqwest::header::HOST;
use reqwest::{Client, Method};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::common::{
    candidate_zones, fqdn, quote_txt_value, record_name, unquote_txt_value, RecordStore,
};
use super::DnsChallengeSolver;

const AWS_ROUTE53_BASE: &str = "https://route53.amazonaws.com";
const AWS_ROUTE53_CHINA_BASE: &str = "https://route53.amazonaws.com.cn";
const AWS_ROUTE53_SERVICE: &str = "route53";
const AWS_ROUTE53_DEFAULT_REGION: &str = "us-east-1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AwsCleanupRecord {
    zone_id: String,
    record_fqdn: String,
}

#[derive(Clone)]
struct AwsRecordSet {
    name: String,
    ttl: u64,
    values: Vec<String>,
}

pub struct AwsSolver {
    client: Client,
    access_key_id: String,
    secret_access_key: String,
    signing_region: String,
    base_url: String,
    records: RecordStore<AwsCleanupRecord>,
}

#[derive(Debug, Deserialize)]
struct AwsHostedZonesByNameResponse {
    #[serde(rename = "HostedZones")]
    hosted_zones: AwsHostedZones,
}

#[derive(Debug, Deserialize)]
struct AwsHostedZones {
    #[serde(rename = "HostedZone", default)]
    items: Vec<AwsHostedZone>,
}

#[derive(Debug, Deserialize)]
struct AwsHostedZone {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Config")]
    config: Option<AwsHostedZoneConfig>,
}

#[derive(Debug, Deserialize)]
struct AwsHostedZoneConfig {
    #[serde(rename = "PrivateZone")]
    private_zone: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AwsRecordSetListResponse {
    #[serde(rename = "ResourceRecordSets")]
    resource_record_sets: AwsRecordSetList,
}

#[derive(Debug, Deserialize)]
struct AwsRecordSetList {
    #[serde(rename = "ResourceRecordSet", default)]
    items: Vec<AwsRecordSetXml>,
}

#[derive(Debug, Deserialize)]
struct AwsRecordSetXml {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "TTL")]
    ttl: Option<u64>,
    #[serde(rename = "ResourceRecords")]
    resource_records: Option<AwsResourceRecords>,
}

#[derive(Debug, Deserialize)]
struct AwsResourceRecords {
    #[serde(rename = "ResourceRecord", default)]
    items: Vec<AwsResourceRecord>,
}

#[derive(Debug, Deserialize)]
struct AwsResourceRecord {
    #[serde(rename = "Value")]
    value: String,
}

impl AwsSolver {
    pub fn new(access_key_id: String, secret_access_key: String, region: String) -> Self {
        let signing_region = if region.starts_with("cn-") {
            region.clone()
        } else {
            AWS_ROUTE53_DEFAULT_REGION.to_string()
        };
        let base_url = if region.starts_with("cn-") {
            AWS_ROUTE53_CHINA_BASE.to_string()
        } else {
            AWS_ROUTE53_BASE.to_string()
        };
        Self::with_base_url(access_key_id, secret_access_key, signing_region, base_url)
    }

    pub fn with_base_url(
        access_key_id: String,
        secret_access_key: String,
        signing_region: String,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            access_key_id,
            secret_access_key,
            signing_region,
            base_url: base_url.into(),
            records: RecordStore::new(),
        }
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

    fn sha256_hex(value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hmac_sha256(key: &[u8], data: &str) -> Result<Vec<u8>, CertError> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to initialize AWS signer: {e}"))
        })?;
        mac.update(data.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn host_header(&self) -> Result<String, CertError> {
        let url = reqwest::Url::parse(&self.base_url).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Invalid AWS API base URL: {e}"))
        })?;
        let host = url.host_str().unwrap_or("route53.amazonaws.com");
        let Some(port) = url.port() else {
            return Ok(host.to_string());
        };
        Ok(format!("{host}:{port}"))
    }

    fn authorization(
        &self,
        method: &str,
        path: &str,
        query: &str,
        payload: &str,
        amz_date: &str,
        date_scope: &str,
    ) -> Result<String, CertError> {
        let host = self.host_header()?;
        let payload_hash = Self::sha256_hex(payload);
        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let credential_scope =
            format!("{date_scope}/{}/{AWS_ROUTE53_SERVICE}/aws4_request", self.signing_region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            Self::sha256_hex(&canonical_request)
        );

        let secret_date =
            Self::hmac_sha256(format!("AWS4{}", self.secret_access_key).as_bytes(), date_scope)?;
        let secret_region = Self::hmac_sha256(&secret_date, &self.signing_region)?;
        let secret_service = Self::hmac_sha256(&secret_region, AWS_ROUTE53_SERVICE)?;
        let secret_signing = Self::hmac_sha256(&secret_service, "aws4_request")?;
        let signature = Self::hmac_sha256(&secret_signing, &string_to_sign)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        ))
    }

    async fn signed_request(
        &self,
        method: Method,
        path: &str,
        query_params: Vec<(String, String)>,
        body: String,
    ) -> Result<String, CertError> {
        let mut query_params = query_params;
        query_params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let query = query_params
            .iter()
            .map(|(key, value)| {
                format!("{}={}", Self::percent_encode(key), Self::percent_encode(value))
            })
            .collect::<Vec<_>>()
            .join("&");

        let base = self.base_url.trim_end_matches('/');
        let url = if query.is_empty() {
            format!("{base}{path}")
        } else {
            format!("{base}{path}?{query}")
        };

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_scope = now.format("%Y%m%d").to_string();
        let authorization =
            self.authorization(method.as_str(), path, &query, &body, &amz_date, &date_scope)?;
        let payload_hash = Self::sha256_hex(&body);

        let mut request = self
            .client
            .request(method, url)
            .header(HOST, self.host_header()?)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", payload_hash)
            .header("Authorization", authorization);
        if !body.is_empty() {
            request = request.header("Content-Type", "application/xml").body(body);
        }

        let response = request.send().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("AWS Route53 request failed: {e}"))
        })?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Failed to read AWS Route53 response: {e}"))
        })?;
        if !status.is_success() {
            return Err(CertError::DnsChallengeSetupFailed(format!(
                "AWS Route53 request failed ({status}): {text}"
            )));
        }
        Ok(text)
    }

    async fn validate_credentials(&self) -> Result<(), CertError> {
        self.signed_request(
            Method::GET,
            "/2013-04-01/hostedzones",
            vec![("maxitems".to_string(), "1".to_string())],
            String::new(),
        )
        .await
        .map(|_| ())
    }

    async fn validate_zone_access(&self, zone_name: &str) -> Result<(), CertError> {
        let response = self
            .signed_request(
                Method::GET,
                "/2013-04-01/hostedzonesbyname",
                vec![
                    ("dnsname".to_string(), fqdn(zone_name)),
                    ("maxitems".to_string(), "100".to_string()),
                ],
                String::new(),
            )
            .await?;
        let parsed: AwsHostedZonesByNameResponse = from_xml_str(&response).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to parse AWS hosted zone response: {e}"
            ))
        })?;
        if parsed.hosted_zones.items.into_iter().any(|zone| {
            zone.name == fqdn(zone_name)
                && !zone.config.as_ref().and_then(|config| config.private_zone).unwrap_or(false)
        }) {
            Ok(())
        } else {
            Err(CertError::DnsChallengeSetupFailed(format!(
                "Could not find AWS Route53 hosted zone: {zone_name}"
            )))
        }
    }

    async fn validate_domain_access(&self, domain: &str) -> Result<(), CertError> {
        self.find_zone_id(domain).await.map(|_| ())
    }

    async fn find_zone_id(&self, domain: &str) -> Result<String, CertError> {
        for candidate in candidate_zones(domain) {
            let response = self
                .signed_request(
                    Method::GET,
                    "/2013-04-01/hostedzonesbyname",
                    vec![
                        ("dnsname".to_string(), fqdn(&candidate)),
                        ("maxitems".to_string(), "100".to_string()),
                    ],
                    String::new(),
                )
                .await?;
            let parsed: AwsHostedZonesByNameResponse = from_xml_str(&response).map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to parse AWS hosted zone response: {e}"
                ))
            })?;
            if let Some(zone) = parsed.hosted_zones.items.into_iter().find(|zone| {
                zone.name == fqdn(&candidate)
                    && !zone.config.as_ref().and_then(|config| config.private_zone).unwrap_or(false)
            }) {
                return Ok(zone.id.trim_start_matches("/hostedzone/").to_string());
            }
        }

        Err(CertError::DnsChallengeSetupFailed(format!(
            "Could not find AWS Route53 hosted zone for domain: {domain}"
        )))
    }

    async fn get_record_set(
        &self,
        zone_id: &str,
        record_fqdn: &str,
    ) -> Result<Option<AwsRecordSet>, CertError> {
        let response = self
            .signed_request(
                Method::GET,
                &format!("/2013-04-01/hostedzone/{zone_id}/rrset"),
                vec![
                    ("maxitems".to_string(), "1".to_string()),
                    ("name".to_string(), record_fqdn.to_string()),
                    ("type".to_string(), "TXT".to_string()),
                ],
                String::new(),
            )
            .await?;
        let parsed: AwsRecordSetListResponse = from_xml_str(&response).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to parse AWS record set response: {e}"
            ))
        })?;
        let Some(record_set) = parsed.resource_record_sets.items.into_iter().next() else {
            return Ok(None);
        };
        if record_set.name != record_fqdn || record_set.record_type != "TXT" {
            return Ok(None);
        }

        Ok(Some(AwsRecordSet {
            name: record_set.name,
            ttl: record_set.ttl.unwrap_or(120),
            values: record_set
                .resource_records
                .map(|records| {
                    records
                        .items
                        .into_iter()
                        .map(|record| unquote_txt_value(&record.value))
                        .collect()
                })
                .unwrap_or_default(),
        }))
    }

    fn change_batch_xml(action: &str, record_set: &AwsRecordSet) -> String {
        let resource_records = record_set
            .values
            .iter()
            .map(|value| {
                format!(
                    "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                    quote_txt_value(value)
                )
            })
            .collect::<String>();

        format!(
            concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                r#"<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">"#,
                r#"<ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet>"#,
                r#"<Name>{name}</Name><Type>TXT</Type><TTL>{ttl}</TTL><ResourceRecords>{resource_records}</ResourceRecords>"#,
                r#"</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#
            ),
            action = action,
            name = record_set.name,
            ttl = record_set.ttl,
            resource_records = resource_records,
        )
    }

    async fn apply_change(
        &self,
        zone_id: &str,
        action: &str,
        record_set: &AwsRecordSet,
    ) -> Result<(), CertError> {
        self.signed_request(
            Method::POST,
            &format!("/2013-04-01/hostedzone/{zone_id}/rrset"),
            Vec::new(),
            Self::change_batch_xml(action, record_set),
        )
        .await?;
        Ok(())
    }
}

pub async fn validate_credentials(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
) -> Result<(), CertError> {
    AwsSolver::new(access_key_id.to_string(), secret_access_key.to_string(), region.to_string())
        .validate_credentials()
        .await
}

pub async fn validate_zone_access(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    zone_name: &str,
) -> Result<(), CertError> {
    AwsSolver::new(access_key_id.to_string(), secret_access_key.to_string(), region.to_string())
        .validate_zone_access(zone_name)
        .await
}

pub async fn validate_domain_access(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    domain: &str,
) -> Result<(), CertError> {
    AwsSolver::new(access_key_id.to_string(), secret_access_key.to_string(), region.to_string())
        .validate_domain_access(domain)
        .await
}

#[async_trait::async_trait]
impl DnsChallengeSolver for AwsSolver {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let zone_id = self.find_zone_id(domain).await?;
        let record_fqdn = fqdn(&record_name(domain));
        let mut record_set =
            self.get_record_set(&zone_id, &record_fqdn).await?.unwrap_or(AwsRecordSet {
                name: record_fqdn.clone(),
                ttl: 120,
                values: Vec::new(),
            });

        if !record_set.values.iter().any(|existing| existing == value) {
            record_set.values.push(value.to_string());
            self.apply_change(&zone_id, "UPSERT", &record_set).await?;
        }

        self.records.insert(domain, value, AwsCleanupRecord { zone_id, record_fqdn });
        tracing::info!("Created AWS Route53 TXT record for {domain}");
        Ok(())
    }

    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let Some(record) = self.records.get_cloned(domain, value) else {
            tracing::warn!("No AWS Route53 TXT record found to clean up for {domain}");
            return Ok(());
        };
        let Some(mut current_record_set) =
            self.get_record_set(&record.zone_id, &record.record_fqdn).await?
        else {
            self.records.remove(domain, value);
            return Ok(());
        };

        let original_len = current_record_set.values.len();
        current_record_set.values.retain(|existing| existing != value);
        if current_record_set.values.len() == original_len {
            self.records.remove(domain, value);
            return Ok(());
        }

        if current_record_set.values.is_empty() {
            let delete_record = AwsRecordSet {
                name: current_record_set.name,
                ttl: current_record_set.ttl,
                values: vec![value.to_string()],
            };
            self.apply_change(&record.zone_id, "DELETE", &delete_record).await?;
        } else {
            self.apply_change(&record.zone_id, "UPSERT", &current_record_set).await?;
        }

        self.records.remove(domain, value);
        tracing::info!("Cleaned up AWS Route53 TXT record for {domain}");
        Ok(())
    }
}
