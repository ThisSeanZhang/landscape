pub(crate) mod aliyun;
mod aws;
mod cloudflare;
mod common;
mod google;
pub(crate) mod tencent;

use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::cert::CertError;

#[async_trait::async_trait]
pub trait DnsChallengeSolver: Send + Sync {
    /// Create a TXT record: _acme-challenge.{domain} → value
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError>;
    /// Remove the TXT record after validation
    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError>;
}

#[async_trait::async_trait]
pub trait DnsRecordUpdater: Send + Sync {
    async fn upsert_record(
        &self,
        zone_name: &str,
        record_name: &str,
        value: &str,
        record_type: &str,
        ttl: u32,
    ) -> Result<(), CertError>;

    async fn reconcile_records(
        &self,
        zone_name: &str,
        record_name: &str,
        record_type: &str,
        desired_values: &[String],
        ttl: u32,
    ) -> Result<(), CertError>;
}

/// Factory: build solver from reusable DNS provider profile config.
pub fn build_solver(
    provider: &DnsProviderConfig,
) -> Result<Box<dyn DnsChallengeSolver>, CertError> {
    match provider {
        DnsProviderConfig::Cloudflare { api_token } => {
            Ok(Box::new(cloudflare::CloudflareSolver::new(api_token.clone())))
        }
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => Ok(Box::new(
            aliyun::AliyunSolver::new(access_key_id.clone(), access_key_secret.clone()),
        )),
        DnsProviderConfig::Tencent { secret_id, secret_key } => {
            Ok(Box::new(tencent::TencentSolver::new(secret_id.clone(), secret_key.clone())))
        }
        DnsProviderConfig::Aws { access_key_id, secret_access_key, region } => Ok(Box::new(
            aws::AwsSolver::new(access_key_id.clone(), secret_access_key.clone(), region.clone()),
        )),
        DnsProviderConfig::Google { service_account_json } => {
            Ok(Box::new(google::GoogleSolver::new(service_account_json.clone())?))
        }
        DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
            "manual DNS not supported for async issuance".into(),
        )),
    }
}

pub fn build_record_updater(
    provider: &DnsProviderConfig,
) -> Result<Box<dyn DnsRecordUpdater>, CertError> {
    match provider {
        DnsProviderConfig::Cloudflare { api_token } => {
            Ok(Box::new(cloudflare::CloudflareSolver::new(api_token.clone())))
        }
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => Ok(Box::new(
            aliyun::AliyunSolver::new(access_key_id.clone(), access_key_secret.clone()),
        )),
        DnsProviderConfig::Tencent { secret_id, secret_key } => {
            Ok(Box::new(tencent::TencentSolver::new(secret_id.clone(), secret_key.clone())))
        }
        DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
            "manual DNS provider does not support DDNS updates".into(),
        )),
        _ => Err(CertError::DnsChallengeSetupFailed(
            "selected DNS provider does not support DDNS updates yet".into(),
        )),
    }
}

pub async fn validate_provider_credentials(provider: &DnsProviderConfig) -> Result<(), CertError> {
    match provider {
        DnsProviderConfig::Cloudflare { api_token } => {
            cloudflare::validate_credentials(api_token).await
        }
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => {
            aliyun::validate_credentials(access_key_id, access_key_secret).await
        }
        DnsProviderConfig::Tencent { secret_id, secret_key } => {
            tencent::validate_credentials(secret_id, secret_key).await
        }
        DnsProviderConfig::Aws { access_key_id, secret_access_key, region } => {
            aws::validate_credentials(access_key_id, secret_access_key, region).await
        }
        DnsProviderConfig::Google { service_account_json } => {
            google::validate_credentials(service_account_json).await
        }
        DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
            "manual DNS provider cannot be validated as a reusable profile".to_string(),
        )),
    }
}

pub async fn validate_provider_zone_access(
    provider: &DnsProviderConfig,
    zone_name: &str,
) -> Result<(), CertError> {
    match provider {
        DnsProviderConfig::Cloudflare { api_token } => {
            cloudflare::validate_zone_access(api_token, zone_name).await
        }
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => {
            aliyun::validate_zone_access(access_key_id, access_key_secret, zone_name).await
        }
        DnsProviderConfig::Tencent { secret_id, secret_key } => {
            tencent::validate_zone_access(secret_id, secret_key, zone_name).await
        }
        DnsProviderConfig::Aws { access_key_id, secret_access_key, region } => {
            aws::validate_zone_access(access_key_id, secret_access_key, region, zone_name).await
        }
        DnsProviderConfig::Google { service_account_json } => {
            google::validate_zone_access(service_account_json, zone_name).await
        }
        DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
            "manual DNS provider cannot manage hosted zones".to_string(),
        )),
    }
}

pub async fn validate_provider_domain_access(
    provider: &DnsProviderConfig,
    domain: &str,
) -> Result<(), CertError> {
    let domain = common::normalize_validation_domain(domain);
    match provider {
        DnsProviderConfig::Cloudflare { api_token } => {
            cloudflare::validate_domain_access(api_token, &domain).await
        }
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => {
            aliyun::validate_domain_access(access_key_id, access_key_secret, &domain).await
        }
        DnsProviderConfig::Tencent { secret_id, secret_key } => {
            tencent::validate_domain_access(secret_id, secret_key, &domain).await
        }
        DnsProviderConfig::Aws { access_key_id, secret_access_key, region } => {
            aws::validate_domain_access(access_key_id, secret_access_key, region, &domain).await
        }
        DnsProviderConfig::Google { service_account_json } => {
            google::validate_domain_access(service_account_json, &domain).await
        }
        DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
            "manual DNS provider cannot manage DNS challenge domains".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};
    use serde_json::{json, Value};

    use super::common::unquote_txt_value;
    use super::{aliyun, aws, build_solver, cloudflare, google, tencent, DnsChallengeSolver};

    async fn spawn_router(router: Router) -> String {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve test router");
        });
        format!("http://{addr}")
    }

    #[test]
    fn build_solver_supports_common_dns_providers() {
        let configs = [
            landscape_common::cert::order::DnsProviderConfig::Cloudflare {
                api_token: "token".into(),
            },
            landscape_common::cert::order::DnsProviderConfig::Aliyun {
                access_key_id: "id".into(),
                access_key_secret: "secret".into(),
            },
            landscape_common::cert::order::DnsProviderConfig::Tencent {
                secret_id: "id".into(),
                secret_key: "secret".into(),
            },
            landscape_common::cert::order::DnsProviderConfig::Aws {
                access_key_id: "id".into(),
                secret_access_key: "secret".into(),
                region: "us-east-1".into(),
            },
            landscape_common::cert::order::DnsProviderConfig::Google {
                service_account_json: json!({
                    "project_id": "test-project",
                    "client_email": "test@example.com",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
                })
                .to_string(),
            },
        ];

        for challenge in configs {
            assert!(build_solver(&challenge).is_ok());
        }
    }

    #[tokio::test]
    async fn cloudflare_solver_creates_and_cleans_up_records() {
        #[derive(Default)]
        struct CloudflareState {
            created: Mutex<Vec<(String, String, String)>>,
            deleted: Mutex<Vec<(String, String)>>,
        }

        async fn list_zones(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
            let result = if query.get("name").is_some_and(|name| name == "example.com") {
                vec![json!({ "id": "zone-1" })]
            } else {
                Vec::new()
            };
            Json(json!({ "success": true, "result": result, "errors": [] }))
        }

        async fn create_record(
            Path(zone_id): Path<String>,
            State(state): State<Arc<CloudflareState>>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            state.created.lock().unwrap().push((
                zone_id,
                payload["name"].as_str().unwrap_or_default().to_string(),
                payload["content"].as_str().unwrap_or_default().to_string(),
            ));
            Json(json!({ "success": true, "result": { "id": "record-1" }, "errors": [] }))
        }

        async fn delete_record(
            Path((zone_id, record_id)): Path<(String, String)>,
            State(state): State<Arc<CloudflareState>>,
        ) -> Json<Value> {
            state.deleted.lock().unwrap().push((zone_id, record_id));
            Json(json!({ "success": true, "result": {}, "errors": [] }))
        }

        let state = Arc::new(CloudflareState::default());
        let router = Router::new()
            .route("/client/v4/zones", get(list_zones))
            .route("/client/v4/zones/{zone_id}/dns_records", post(create_record))
            .route("/client/v4/zones/{zone_id}/dns_records/{record_id}", delete(delete_record))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let solver = cloudflare::CloudflareSolver::with_base_url(
            "token".into(),
            format!("{base_url}/client/v4"),
        );

        solver.create_txt_record("www.example.com", "value-1").await.expect("cloudflare create");
        solver.cleanup_txt_record("www.example.com", "value-1").await.expect("cloudflare cleanup");

        assert_eq!(
            state.created.lock().unwrap().as_slice(),
            &[(
                "zone-1".to_string(),
                "_acme-challenge.www.example.com".to_string(),
                "value-1".to_string()
            )]
        );
        assert_eq!(
            state.deleted.lock().unwrap().as_slice(),
            &[("zone-1".to_string(), "record-1".to_string())]
        );
    }

    #[tokio::test]
    async fn aliyun_solver_creates_and_cleans_up_records() {
        #[derive(Default)]
        struct AliyunState {
            added: Mutex<Vec<(String, String, String, String)>>,
            deleted: Mutex<Vec<String>>,
        }

        async fn handle_aliyun(
            State(state): State<Arc<AliyunState>>,
            Query(query): Query<HashMap<String, String>>,
        ) -> Json<Value> {
            match query.get("Action").map(String::as_str) {
                Some("DescribeDomainInfo") => {
                    if query.get("DomainName").is_some_and(|domain| domain == "example.com") {
                        Json(json!({ "DomainName": "example.com" }))
                    } else {
                        Json(json!({
                            "Code": "DomainNameNotExist",
                            "Message": "domain not exist"
                        }))
                    }
                }
                Some("AddDomainRecord") => {
                    state.added.lock().unwrap().push((
                        query.get("DomainName").cloned().unwrap_or_default(),
                        query.get("RR").cloned().unwrap_or_default(),
                        query.get("TTL").cloned().unwrap_or_default(),
                        query.get("Value").cloned().unwrap_or_default(),
                    ));
                    Json(json!({ "RecordId": "aliyun-record-1" }))
                }
                Some("DeleteDomainRecord") => {
                    state
                        .deleted
                        .lock()
                        .unwrap()
                        .push(query.get("RecordId").cloned().unwrap_or_default());
                    Json(json!({ "RequestId": "request-id" }))
                }
                _ => Json(json!({ "Code": "InvalidAction", "Message": "unsupported" })),
            }
        }

        let state = Arc::new(AliyunState::default());
        let router = Router::new().route("/", get(handle_aliyun)).with_state(state.clone());
        let base_url = spawn_router(router).await;
        let solver = aliyun::AliyunSolver::with_base_url(
            "id".into(),
            "secret".into(),
            format!("{base_url}/"),
        );

        solver.create_txt_record("www.example.com", "value-1").await.expect("aliyun create");
        solver.cleanup_txt_record("www.example.com", "value-1").await.expect("aliyun cleanup");

        assert_eq!(
            state.added.lock().unwrap().as_slice(),
            &[(
                "example.com".to_string(),
                "_acme-challenge.www".to_string(),
                "600".to_string(),
                "value-1".to_string()
            )]
        );
        assert_eq!(state.deleted.lock().unwrap().as_slice(), &["aliyun-record-1".to_string()]);
    }

    #[tokio::test]
    async fn tencent_solver_creates_and_cleans_up_records() {
        #[derive(Default)]
        struct TencentState {
            created: Mutex<Vec<(String, String, String)>>,
            deleted: Mutex<Vec<(String, u64)>>,
        }

        async fn handle_tencent(
            State(state): State<Arc<TencentState>>,
            headers: HeaderMap,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            match headers.get("x-tc-action").and_then(|value| value.to_str().ok()) {
                Some("DescribeDomain") => {
                    if payload["Domain"].as_str().is_some_and(|domain| domain == "example.com") {
                        Json(
                            json!({ "Response": { "RequestId": "rid", "DomainInfo": { "Domain": "example.com" } } }),
                        )
                    } else {
                        Json(json!({
                            "Response": {
                                "RequestId": "rid",
                                "Error": {
                                    "Code": "ResourceNotFound.NoDataOfDomain",
                                    "Message": "domain not found"
                                }
                            }
                        }))
                    }
                }
                Some("CreateRecord") => {
                    state.created.lock().unwrap().push((
                        payload["Domain"].as_str().unwrap_or_default().to_string(),
                        payload["SubDomain"].as_str().unwrap_or_default().to_string(),
                        payload["Value"].as_str().unwrap_or_default().to_string(),
                    ));
                    Json(json!({ "Response": { "RequestId": "rid", "RecordId": 42 } }))
                }
                Some("DeleteRecord") => {
                    state.deleted.lock().unwrap().push((
                        payload["Domain"].as_str().unwrap_or_default().to_string(),
                        payload["RecordId"].as_u64().unwrap_or_default(),
                    ));
                    Json(json!({ "Response": { "RequestId": "rid" } }))
                }
                _ => Json(json!({
                    "Response": {
                        "RequestId": "rid",
                        "Error": {
                            "Code": "Unsupported",
                            "Message": "unsupported"
                        }
                    }
                })),
            }
        }

        let state = Arc::new(TencentState::default());
        let router = Router::new().route("/", post(handle_tencent)).with_state(state.clone());
        let base_url = spawn_router(router).await;
        let solver = tencent::TencentSolver::with_base_url(
            "id".into(),
            "secret".into(),
            format!("{base_url}/"),
        );

        solver.create_txt_record("www.example.com", "value-1").await.expect("tencent create");
        solver.cleanup_txt_record("www.example.com", "value-1").await.expect("tencent cleanup");

        assert_eq!(
            state.created.lock().unwrap().as_slice(),
            &[(
                "example.com".to_string(),
                "_acme-challenge.www".to_string(),
                "value-1".to_string()
            )]
        );
        assert_eq!(state.deleted.lock().unwrap().as_slice(), &[("example.com".to_string(), 42)]);
    }

    #[tokio::test]
    async fn aws_solver_merges_and_removes_multiple_txt_values() {
        #[derive(Default)]
        struct AwsState {
            values: Mutex<Vec<String>>,
        }

        fn aws_rrsets_xml(values: &[String]) -> String {
            if values.is_empty() {
                return r#"<?xml version="1.0" encoding="UTF-8"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>"#.to_string();
            }

            let records = values
                .iter()
                .map(|value| format!("<ResourceRecord><Value>\"{value}\"</Value></ResourceRecord>"))
                .collect::<String>();
            format!(
                concat!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                    r#"<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">"#,
                    r#"<ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.example.com.</Name>"#,
                    r#"<Type>TXT</Type><TTL>120</TTL><ResourceRecords>{records}</ResourceRecords>"#,
                    r#"</ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"#
                ),
                records = records
            )
        }

        fn extract_tag_values(body: &str, tag: &str) -> Vec<String> {
            let start = format!("<{tag}>");
            let end = format!("</{tag}>");
            let mut remaining = body;
            let mut values = Vec::new();
            while let Some(start_idx) = remaining.find(&start) {
                let after_start = &remaining[start_idx + start.len()..];
                let Some(end_idx) = after_start.find(&end) else {
                    break;
                };
                values.push(after_start[..end_idx].to_string());
                remaining = &after_start[end_idx + end.len()..];
            }
            values
        }

        async fn list_hosted_zones() -> impl IntoResponse {
            (
                StatusCode::OK,
                r#"<?xml version="1.0" encoding="UTF-8"?><ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones></ListHostedZonesByNameResponse>"#,
            )
        }

        async fn list_rrsets(State(state): State<Arc<AwsState>>) -> impl IntoResponse {
            (StatusCode::OK, aws_rrsets_xml(&state.values.lock().unwrap()))
        }

        async fn change_rrsets(
            State(state): State<Arc<AwsState>>,
            body: Bytes,
        ) -> impl IntoResponse {
            let body = String::from_utf8(body.to_vec()).expect("aws change body");
            let next_values = extract_tag_values(&body, "Value")
                .into_iter()
                .map(|value| unquote_txt_value(&value))
                .collect::<Vec<_>>();
            if body.contains("<Action>DELETE</Action>") {
                state.values.lock().unwrap().clear();
            } else {
                *state.values.lock().unwrap() = next_values;
            }
            (
                StatusCode::OK,
                r#"<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeInfo><Id>/change/1</Id><Status>INSYNC</Status></ChangeInfo></ChangeResourceRecordSetsResponse>"#,
            )
        }

        let state = Arc::new(AwsState::default());
        let router = Router::new()
            .route("/2013-04-01/hostedzonesbyname", get(list_hosted_zones))
            .route("/2013-04-01/hostedzone/{zone_id}/rrset", get(list_rrsets).post(change_rrsets))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let solver = aws::AwsSolver::with_base_url(
            "id".into(),
            "secret".into(),
            "us-east-1".into(),
            base_url,
        );

        solver.create_txt_record("example.com", "value-1").await.expect("aws create first");
        solver.create_txt_record("example.com", "value-2").await.expect("aws create second");
        assert_eq!(
            state.values.lock().unwrap().as_slice(),
            &["value-1".to_string(), "value-2".to_string()]
        );

        solver.cleanup_txt_record("example.com", "value-1").await.expect("aws cleanup first");
        assert_eq!(state.values.lock().unwrap().as_slice(), &["value-2".to_string()]);

        solver.cleanup_txt_record("example.com", "value-2").await.expect("aws cleanup second");
        assert!(state.values.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn google_solver_merges_and_removes_multiple_txt_values() {
        #[derive(Default)]
        struct GoogleState {
            values: Mutex<Vec<String>>,
        }

        async fn issue_token() -> Json<Value> {
            Json(json!({
                "access_token": "token-1",
                "expires_in": 3600,
                "token_type": "Bearer"
            }))
        }

        async fn managed_zones(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
            let zones = if query.get("dnsName").is_some_and(|name| name == "example.com.") {
                vec![json!({
                    "name": "zone-1",
                    "dnsName": "example.com.",
                    "visibility": "public"
                })]
            } else {
                Vec::new()
            };
            Json(json!({ "managedZones": zones }))
        }

        async fn rrsets(State(state): State<Arc<GoogleState>>) -> Json<Value> {
            let values = state.values.lock().unwrap().clone();
            if values.is_empty() {
                Json(json!({ "rrsets": [] }))
            } else {
                Json(json!({
                    "rrsets": [{
                        "name": "_acme-challenge.example.com.",
                        "type": "TXT",
                        "ttl": 120,
                        "rrdatas": values
                    }]
                }))
            }
        }

        async fn apply_change(
            State(state): State<Arc<GoogleState>>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            if let Some(additions) = payload.get("additions").and_then(Value::as_array) {
                let next_values = additions
                    .first()
                    .and_then(|addition| addition.get("rrdatas"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                *state.values.lock().unwrap() = next_values;
            } else {
                state.values.lock().unwrap().clear();
            }

            Json(json!({ "status": "done" }))
        }

        let state = Arc::new(GoogleState::default());
        let router = Router::new()
            .route("/oauth2/token", post(issue_token))
            .route("/dns/v1/projects/test-project/managedZones", get(managed_zones))
            .route("/dns/v1/projects/test-project/managedZones/zone-1/rrsets", get(rrsets))
            .route("/dns/v1/projects/test-project/managedZones/zone-1/changes", post(apply_change))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let service_account_json = json!({
            "project_id": "test-project",
            "client_email": "test@example.com",
            "private_key_id": "kid-1",
            "private_key": r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMSnPxN8uWZgATBK
MV86CIgKAkDuXfLv7f6E7Uyy9ppBF6tyUqO/xxKP47Q2nUqEZaGATOF5p8yhv9sp
nat3PEaG+9PHZYQ2quVPSwKBuL+fLAApaSx97lGfE1Bi141BSWlRXu/WXQOo3yUO
OJ8hWhKF3ZyHZ8nNMJE2CqRL/0oZAgMBAAECgYEAqoVLkJ5KNZdx8GmlPimYVD45
jgwjsxCRkm25RxS3+TIQUD4lopAdEt9qV040PfVoGw6hm7Jd6ncnYedILPKLdCYK
DcW29pL5WJ59f2hDRZlM9GvBQ1okRSIzz5XPilkMSc597+ei9b6WNGJz3UO34yvU
faoNVycKLtb/L87SQnECQQDzy4OmegLnIox2lbZZFR5iqwQmExZ6QvtR91iVu6sB
Q3AsekUDWaV4SRsKFNNXJ879JZv/ooXhuZa2ue+iFdjzAkEAzn+QC0aE7H+8VOxy
K+gYQEteig8TdVGRe8HF/RSH/SRSpsJm3c/TmLOmQik9OR4tY76k+x3THgn0DyLV
gPsTwwJAQCtXMaB31yKu2h+56WS3pLzi0KrBhdjPkdmLBY5qCmEXy307YRBdj3We
ml606gHeZ59YmkbK+okA9IOoYX9ipQJBAJ1V2Fye+Hxxvv89wKfviTrDsl6iqgLD
iYOv2ri/wfWAjXD9wf7TcLdyegUDAuDYO2E6St4ClW7XypsVwXMq2p0CQFywKknG
yWNscX6DYU0gtUc1UxfIG9vX0jd4W8BVMEWKjwBLS+hL5gI5pTj7m/4HZ/8RJH2H
5bzUXbz8OhEw88g=
-----END PRIVATE KEY-----"#,
            "token_uri": format!("{base_url}/oauth2/token")
        })
        .to_string();
        let solver =
            google::GoogleSolver::with_base_url(service_account_json, format!("{base_url}/dns/v1"))
                .expect("google solver");

        solver.create_txt_record("example.com", "value-1").await.expect("google create first");
        solver.create_txt_record("example.com", "value-2").await.expect("google create second");
        assert_eq!(
            state.values.lock().unwrap().as_slice(),
            &["value-1".to_string(), "value-2".to_string()]
        );

        solver.cleanup_txt_record("example.com", "value-1").await.expect("google cleanup first");
        assert_eq!(state.values.lock().unwrap().as_slice(), &["value-2".to_string()]);

        solver.cleanup_txt_record("example.com", "value-2").await.expect("google cleanup second");
        assert!(state.values.lock().unwrap().is_empty());
    }
}
