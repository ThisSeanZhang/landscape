use std::sync::Mutex;

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use landscape_common::cert::CertError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::DnsChallengeSolver;
use super::common::{RecordStore, candidate_zones, fqdn, record_name, unquote_txt_value};

const GOOGLE_DNS_API_BASE: &str = "https://dns.googleapis.com/dns/v1";
const GOOGLE_DNS_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const DEFAULT_PROVIDER_TTL: u32 = 120;

#[derive(Clone)]
struct GoogleManagedZone {
    name: String,
}

#[derive(Clone)]
struct GoogleCleanupRecord {
    managed_zone: String,
    record_fqdn: String,
}

#[derive(Clone)]
struct GoogleToken {
    access_token: String,
    expires_at: i64,
}

#[derive(Clone)]
struct GoogleRecordSet {
    name: String,
    ttl: u32,
    rrdatas: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
    #[serde(default = "default_google_token_uri")]
    token_uri: String,
}

#[derive(Debug, Serialize)]
struct GoogleServiceAccountClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct GoogleManagedZonesResponse {
    #[serde(rename = "managedZones", default)]
    managed_zones: Vec<GoogleManagedZoneResponse>,
}

#[derive(Debug, Deserialize)]
struct GoogleManagedZoneResponse {
    name: String,
    #[serde(rename = "dnsName")]
    dns_name: String,
    visibility: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleRrsetsResponse {
    #[serde(rename = "rrsets", default)]
    rrsets: Vec<GoogleRecordSetResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GoogleRecordSetResponse {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: Option<u32>,
    #[serde(default)]
    rrdatas: Vec<String>,
}

fn default_google_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

pub struct GoogleSolver {
    client: Client,
    account: GoogleServiceAccount,
    base_url: String,
    ttl: Option<u32>,
    token_cache: Mutex<Option<GoogleToken>>,
    records: RecordStore<GoogleCleanupRecord>,
}

impl GoogleSolver {
    pub fn new(service_account_json: String, ttl: Option<u32>) -> Result<Self, CertError> {
        Self::with_base_url(service_account_json, ttl, GOOGLE_DNS_API_BASE)
    }

    pub fn with_base_url(
        service_account_json: String,
        ttl: Option<u32>,
        base_url: impl Into<String>,
    ) -> Result<Self, CertError> {
        let account: GoogleServiceAccount =
            serde_json::from_str(&service_account_json).map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to parse Google service account JSON: {e}"
                ))
            })?;
        if account.project_id.trim().is_empty() {
            return Err(CertError::DnsChallengeSetupFailed(
                "Google service account JSON must include project_id".to_string(),
            ));
        }

        Ok(Self {
            client: Client::new(),
            account,
            base_url: base_url.into(),
            ttl,
            token_cache: Mutex::new(None),
            records: RecordStore::new(),
        })
    }

    fn encoding_key(&self) -> Result<EncodingKey, CertError> {
        EncodingKey::from_rsa_pem(self.account.private_key.as_bytes()).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to parse Google service account private key: {e}"
            ))
        })
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

    fn append_query(url: &str, query: &[(String, String)]) -> String {
        if query.is_empty() {
            return url.to_string();
        }

        let query_string = query
            .iter()
            .map(|(key, value)| {
                format!("{}={}", Self::percent_encode(key), Self::percent_encode(value))
            })
            .collect::<Vec<_>>()
            .join("&");
        format!("{url}?{query_string}")
    }

    async fn access_token(&self) -> Result<String, CertError> {
        let now = Utc::now().timestamp();
        if let Some(token) = self.token_cache.lock().unwrap().clone()
            && token.expires_at - 60 > now
        {
            return Ok(token.access_token);
        }

        let iat = now;
        let exp = now + 3600;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.account.private_key_id.clone();
        let claims = GoogleServiceAccountClaims {
            iss: &self.account.client_email,
            scope: GOOGLE_DNS_SCOPE,
            aud: &self.account.token_uri,
            exp,
            iat,
        };
        let assertion =
            jsonwebtoken::encode(&header, &claims, &self.encoding_key()?).map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to sign Google service account JWT: {e}"
                ))
            })?;
        let form_body = format!(
            "grant_type={}&assertion={}",
            Self::percent_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            Self::percent_encode(&assertion)
        );

        let response = self
            .client
            .post(&self.account.token_uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Google OAuth token request failed: {e}"
                ))
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to read Google OAuth token response: {e}"
            ))
        })?;
        if !status.is_success() {
            return Err(CertError::DnsChallengeSetupFailed(format!(
                "Google OAuth token request failed ({status}): {body}"
            )));
        }
        let token: GoogleTokenResponse = serde_json::from_str(&body).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to parse Google OAuth token response: {e}"
            ))
        })?;
        let cached = GoogleToken {
            access_token: token.access_token.clone(),
            expires_at: now + token.expires_in,
        };
        *self.token_cache.lock().unwrap() = Some(cached);
        Ok(token.access_token)
    }

    async fn request<T>(
        &self,
        method: reqwest::Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<serde_json::Value>,
    ) -> Result<T, CertError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let token = self.access_token().await?;
        let url = Self::append_query(
            &format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/')),
            &query,
        );
        let mut request = self.client.request(method, url).bearer_auth(token);
        if let Some(body) = body {
            let body = serde_json::to_string(&body).map_err(|e| {
                CertError::DnsChallengeSetupFailed(format!(
                    "Failed to serialize Google Cloud DNS request body: {e}"
                ))
            })?;
            request = request.header("Content-Type", "application/json").body(body);
        }

        let response = request.send().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!("Google Cloud DNS request failed: {e}"))
        })?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to read Google Cloud DNS response: {e}"
            ))
        })?;
        if !status.is_success() {
            return Err(CertError::DnsChallengeSetupFailed(format!(
                "Google Cloud DNS request failed ({status}): {text}"
            )));
        }

        serde_json::from_str(&text).map_err(|e| {
            CertError::DnsChallengeSetupFailed(format!(
                "Failed to parse Google Cloud DNS response: {e}"
            ))
        })
    }

    async fn validate_credentials(&self) -> Result<(), CertError> {
        self.request::<GoogleManagedZonesResponse>(
            reqwest::Method::GET,
            &format!("projects/{}/managedZones", self.account.project_id),
            vec![("maxResults".to_string(), "1".to_string())],
            None,
        )
        .await
        .map(|_| ())
    }

    async fn validate_zone_access(&self, zone_name: &str) -> Result<(), CertError> {
        let response: GoogleManagedZonesResponse = self
            .request(
                reqwest::Method::GET,
                &format!("projects/{}/managedZones", self.account.project_id),
                vec![("dnsName".to_string(), fqdn(zone_name))],
                None,
            )
            .await?;
        if response.managed_zones.into_iter().any(|zone| {
            zone.dns_name == fqdn(zone_name)
                && !zone
                    .visibility
                    .as_deref()
                    .is_some_and(|visibility| visibility.eq_ignore_ascii_case("private"))
        }) {
            Ok(())
        } else {
            Err(CertError::DnsChallengeSetupFailed(format!(
                "Could not find Google Cloud DNS managed zone: {zone_name}"
            )))
        }
    }

    async fn validate_domain_access(&self, domain: &str) -> Result<(), CertError> {
        self.find_managed_zone(domain).await.map(|_| ())
    }

    async fn find_managed_zone(&self, domain: &str) -> Result<GoogleManagedZone, CertError> {
        for candidate in candidate_zones(domain) {
            let response: GoogleManagedZonesResponse = self
                .request(
                    reqwest::Method::GET,
                    &format!("projects/{}/managedZones", self.account.project_id),
                    vec![("dnsName".to_string(), fqdn(&candidate))],
                    None,
                )
                .await?;
            if let Some(zone) = response.managed_zones.into_iter().find(|zone| {
                zone.dns_name == fqdn(&candidate)
                    && !zone
                        .visibility
                        .as_deref()
                        .is_some_and(|visibility| visibility.eq_ignore_ascii_case("private"))
            }) {
                return Ok(GoogleManagedZone { name: zone.name });
            }
        }

        Err(CertError::DnsChallengeSetupFailed(format!(
            "Could not find Google Cloud DNS managed zone for domain: {domain}"
        )))
    }

    async fn get_record_set(
        &self,
        managed_zone: &str,
        record_fqdn: &str,
    ) -> Result<Option<GoogleRecordSet>, CertError> {
        let response: GoogleRrsetsResponse = self
            .request(
                reqwest::Method::GET,
                &format!("projects/{}/managedZones/{managed_zone}/rrsets", self.account.project_id),
                vec![
                    ("name".to_string(), record_fqdn.to_string()),
                    ("type".to_string(), "TXT".to_string()),
                ],
                None,
            )
            .await?;
        let Some(rrset) = response.rrsets.into_iter().next() else {
            return Ok(None);
        };
        if rrset.name != record_fqdn || rrset.record_type != "TXT" {
            return Ok(None);
        }

        Ok(Some(GoogleRecordSet {
            name: rrset.name,
            ttl: rrset.ttl.unwrap_or(120),
            rrdatas: rrset.rrdatas.into_iter().map(|value| unquote_txt_value(&value)).collect(),
        }))
    }

    async fn apply_change(
        &self,
        managed_zone: &str,
        deletions: Vec<GoogleRecordSet>,
        additions: Vec<GoogleRecordSet>,
    ) -> Result<(), CertError> {
        let deletions = deletions
            .into_iter()
            .map(|record| {
                json!({
                    "name": record.name,
                    "type": "TXT",
                    "ttl": record.ttl,
                    "rrdatas": record.rrdatas
                })
            })
            .collect::<Vec<_>>();
        let additions = additions
            .into_iter()
            .map(|record| {
                json!({
                    "name": record.name,
                    "type": "TXT",
                    "ttl": record.ttl,
                    "rrdatas": record.rrdatas
                })
            })
            .collect::<Vec<_>>();

        let mut payload = serde_json::Map::new();
        if !deletions.is_empty() {
            payload.insert("deletions".to_string(), serde_json::Value::Array(deletions));
        }
        if !additions.is_empty() {
            payload.insert("additions".to_string(), serde_json::Value::Array(additions));
        }

        let _: serde_json::Value = self
            .request(
                reqwest::Method::POST,
                &format!(
                    "projects/{}/managedZones/{managed_zone}/changes",
                    self.account.project_id
                ),
                Vec::new(),
                Some(serde_json::Value::Object(payload)),
            )
            .await?;
        Ok(())
    }
}

pub async fn validate_credentials(service_account_json: &str) -> Result<(), CertError> {
    GoogleSolver::new(service_account_json.to_string(), None)?.validate_credentials().await
}

pub async fn validate_zone_access(
    service_account_json: &str,
    zone_name: &str,
) -> Result<(), CertError> {
    GoogleSolver::new(service_account_json.to_string(), None)?.validate_zone_access(zone_name).await
}

pub async fn validate_domain_access(
    service_account_json: &str,
    domain: &str,
) -> Result<(), CertError> {
    GoogleSolver::new(service_account_json.to_string(), None)?.validate_domain_access(domain).await
}

#[async_trait::async_trait]
impl DnsChallengeSolver for GoogleSolver {
    fn provider_ttl(&self) -> u32 {
        self.ttl.unwrap_or(DEFAULT_PROVIDER_TTL)
    }

    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let zone = self.find_managed_zone(domain).await?;
        let record_fqdn = fqdn(&record_name(domain));
        let current = self.get_record_set(&zone.name, &record_fqdn).await?;

        match current {
            Some(mut record) => {
                if !record.rrdatas.iter().any(|existing| existing == value) {
                    let previous = record.clone();
                    record.rrdatas.push(value.to_string());
                    self.apply_change(&zone.name, vec![previous], vec![record]).await?;
                }
            }
            None => {
                self.apply_change(
                    &zone.name,
                    Vec::new(),
                    vec![GoogleRecordSet {
                        name: record_fqdn.clone(),
                        ttl: self.provider_ttl(),
                        rrdatas: vec![value.to_string()],
                    }],
                )
                .await?;
            }
        }

        self.records.insert(
            domain,
            value,
            GoogleCleanupRecord { managed_zone: zone.name, record_fqdn },
        );
        tracing::info!("Created Google Cloud DNS TXT record for {domain}");
        Ok(())
    }

    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError> {
        let Some(record) = self.records.get_cloned(domain, value) else {
            tracing::warn!("No Google Cloud DNS TXT record found to clean up for {domain}");
            return Ok(());
        };
        let Some(mut current) =
            self.get_record_set(&record.managed_zone, &record.record_fqdn).await?
        else {
            self.records.remove(domain, value);
            return Ok(());
        };

        let previous = current.clone();
        let previous_len = current.rrdatas.len();
        current.rrdatas.retain(|existing| existing != value);
        if current.rrdatas.len() == previous_len {
            self.records.remove(domain, value);
            return Ok(());
        }

        if current.rrdatas.is_empty() {
            self.apply_change(&record.managed_zone, vec![previous], Vec::new()).await?;
        } else {
            self.apply_change(&record.managed_zone, vec![previous], vec![current]).await?;
        }

        self.records.remove(domain, value);
        tracing::info!("Cleaned up Google Cloud DNS TXT record for {domain}");
        Ok(())
    }
}
