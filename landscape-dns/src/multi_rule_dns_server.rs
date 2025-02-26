use core::panic;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::PathBuf,
    sync::Arc,
};

use hickory_proto::op::{Header, ResponseCode};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use crate::rule::ResolutionRule;
use landscape_common::dns::{DNSRuleConfig, DomainConfig};

static RESOLVER_CONF: &'static str = "/etc/resolv.conf";
static RESOLVER_CONF_LD_BACK: &'static str = "/etc/resolv.conf.ld_back";

fn check_resolver_conf() {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);
    let new_content = "nameserver 127.0.0.1\n";

    if resolver_file.is_symlink() {
        // 如果是符号链接，直接删除
        fs::remove_file(&resolver_file).unwrap();
    } else if resolver_file.exists() {
        if resolver_file.is_file() {
            // 如果是普通文件，检查备份文件
            if resolver_file_back.exists() {
                fs::remove_file(&resolver_file).unwrap();
            } else {
                let Ok(()) = fs::rename(&resolver_file, &resolver_file_back) else {
                    println!("move {resolver_file:?} error, Skip it");
                    return;
                };
            }
        } else {
            panic!("other kind file");
        }
    }

    // 写入新内容到 /etc/resolv.conf
    fs::write(&resolver_file, new_content).unwrap();
}

/// 整个 DNS 规则匹配树
pub struct DnsServer {
    /// 所有的域名处理对象
    /// 遍历的顺序是小到大
    resolves: BTreeMap<u32, Arc<ResolutionRule>>,
}

impl DnsServer {
    pub fn new(
        dns_rules: Vec<DNSRuleConfig>,
        geo_map: HashMap<String, Vec<DomainConfig>>,
    ) -> DnsServer {
        check_resolver_conf();

        let mut resolves = BTreeMap::new();

        for rule in dns_rules.into_iter() {
            // println!("dns_rules: {:?}", rule);
            resolves.insert(rule.index, Arc::new(ResolutionRule::new(rule, &geo_map)));
        }
        drop(geo_map);
        DnsServer { resolves }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let domain = request.query().name().to_string();
        let query_type = request.query().query_type();

        let response_builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);
        header.set_authoritative(true);
        header.set_recursion_available(true);

        let mut records = vec![];

        // TODO: 修改逻辑
        for (_index, resolver) in self.resolves.iter() {
            if resolver.is_match(&domain).await {
                records = match resolver.lookup(&domain, query_type).await {
                    Ok(rdata_vec) => rdata_vec,
                    Err(error_code) => {
                        // 构建并返回错误响应
                        header.set_response_code(error_code);
                        let response = MessageResponseBuilder::from_message_request(request)
                            .build_no_records(header);
                        let result = response_handle.send_response(response).await;
                        return match result {
                            Err(e) => {
                                log::error!("Request failed: {}", e);
                                serve_failed()
                            }
                            Ok(info) => info,
                        };
                    }
                };
                break;
            }
        }

        // 如果没有找到记录，返回 NXDomain 响应
        if records.is_empty() {
            // header.set_response_code(ResponseCode::NXDomain);
            let response = response_builder.build_no_records(header);
            let result = response_handle.send_response(response).await;
            return match result {
                Err(e) => {
                    log::error!("Request failed: {}", e);
                    serve_failed()
                }
                Ok(info) => info,
            };
        }

        let response = response_builder.build(
            header,
            records.iter(),
            vec![].into_iter(),
            vec![].into_iter(),
            vec![].into_iter(),
        );

        let result = response_handle.send_response(response).await;
        match result {
            Err(e) => {
                log::error!("Request failed: {}", e);
                serve_failed()
            }
            Ok(info) => info,
        }
    }
}

fn serve_failed() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}
