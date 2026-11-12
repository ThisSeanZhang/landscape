//! Select independently managed carrier DNS groups without falling through to
//! another rule when a WAN/group is missing. DNS transport prefers IPv4 when
//! both families are available; either transport can answer A and AAAA queries.
use std::collections::HashMap;

use landscape_common::dns::{
    bind::{DnsBindConfig, DnsWanServers},
    config::DnsUpstreamConfig,
    rule::DNSRuleConfig,
};
use uuid::Uuid;

pub(super) fn select(
    rule: &DNSRuleConfig,
    upstreams: &HashMap<Uuid, DnsUpstreamConfig>,
) -> Option<DnsUpstreamConfig> {
    if rule.wan_upstreams.is_empty() {
        return upstreams.get(&rule.upstream_id).cloned();
    }
    if let Some(binding) = &rule.resolved_wan {
        for ipv6 in [false, true] {
            let link = if ipv6 && binding.ipv6.is_some() {
                binding.ipv6_link_id
            } else if !ipv6 && binding.ipv4.is_some() {
                binding.ipv4_link_id
            } else {
                None
            };
            let Some(mapping) = rule.wan_upstreams.iter().find(|m| Some(m.link_id) == link) else {
                continue;
            };
            let Some(group) = upstreams.get(&mapping.upstream_id) else {
                continue;
            };
            if !group.is_independent_wan_group() || !group.ips.iter().any(|ip| ip.is_ipv6() == ipv6)
            {
                continue;
            }
            let mut selected = group.clone();
            selected.bind_config = DnsBindConfig {
                follow_flow: Some(rule.flow_id),
                wan_servers: vec![DnsWanServers {
                    link_id: mapping.link_id,
                    ips: group.ips.clone(),
                }],
                resolved_wan: Some(binding.clone()),
                ..Default::default()
            };
            return Some(selected);
        }
    }
    // A stable, isolated identity keeps the matched rule unavailable instead
    // of skipping it and accidentally using a later proxy/public resolver.
    Some(DnsUpstreamConfig {
        id: rule.id,
        ips: vec![],
        bind_config: DnsBindConfig {
            follow_flow: Some(rule.flow_id),
            wan_servers: vec![DnsWanServers { link_id: Uuid::nil(), ips: vec![] }],
            ..Default::default()
        },
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::dns::{bind::DnsWanBinding, rule::DnsWanUpstream};

    fn fixture() -> (DNSRuleConfig, HashMap<Uuid, DnsUpstreamConfig>, Uuid, Uuid) {
        let cu = Uuid::new_v4();
        let ct = Uuid::new_v4();
        let mut a = DnsUpstreamConfig::default();
        a.ips = vec!["210.21.196.6".parse().unwrap()];
        let mut b = DnsUpstreamConfig::default();
        b.ips = vec!["202.96.128.86".parse().unwrap()];
        let rule: DNSRuleConfig = serde_json::from_value(serde_json::json!({
            "name":"carrier groups", "index":20, "enable":true,
            "flow_id":20, "upstream_id":a.id,
            "wan_upstreams":[
                {"link_id":cu,"upstream_id":a.id},
                {"link_id":ct,"upstream_id":b.id}
            ]
        }))
        .unwrap();
        (rule, HashMap::from([(a.id, a), (b.id, b)]), cu, ct)
    }

    #[test]
    fn separate_carrier_groups_follow_failure_and_recovery() {
        let (mut rule, groups, cu, ct) = fixture();
        for (link, iface, server) in
            [(cu, "cu", "210.21.196.6"), (ct, "ct", "202.96.128.86"), (cu, "cu", "210.21.196.6")]
        {
            rule.resolved_wan = Some(DnsWanBinding {
                ipv4: Some((iface.into(), "192.0.2.1".parse().unwrap())),
                ipv4_link_id: Some(link),
                ..Default::default()
            });
            let selected = select(&rule, &groups).unwrap();
            assert_eq!(
                selected.id,
                rule.wan_upstreams.iter().find(|m| m.link_id == link).unwrap().upstream_id
            );
            assert_eq!(selected.bind_config.interface(false), Some(iface));
            assert_eq!(selected.bind_config.socket_mark(0x8000), 0x8014);
            assert_eq!(
                selected.bind_config.server_ips(&selected.ips),
                vec![server.parse::<std::net::IpAddr>().unwrap()]
            );
        }
        assert!(groups.values().all(|g| g.bind_config == DnsBindConfig::default()));
    }

    #[test]
    fn absent_wan_or_group_never_uses_static_fallback() {
        let (mut rule, mut groups, cu, _) = fixture();
        let missing = select(&rule, &groups).unwrap();
        assert!(missing.bind_config.server_ips(&missing.ips).is_empty());
        rule.resolved_wan = Some(DnsWanBinding {
            ipv4: Some(("cu".into(), "192.0.2.1".parse().unwrap())),
            ipv4_link_id: Some(cu),
            ..Default::default()
        });
        groups.remove(&rule.wan_upstreams[0].upstream_id);
        let missing = select(&rule, &groups).unwrap();
        assert_eq!(missing.id, rule.id);
        assert!(missing.bind_config.server_ips(&missing.ips).is_empty());
    }

    #[test]
    fn split_families_never_send_carrier_dns_via_another_wan() {
        let (mut rule, mut groups, cu, ct) = fixture();
        groups
            .get_mut(&rule.wan_upstreams[0].upstream_id)
            .unwrap()
            .ips
            .push("2001:db8:1::53".parse().unwrap());
        groups
            .get_mut(&rule.wan_upstreams[1].upstream_id)
            .unwrap()
            .ips
            .push("2001:db8:2::53".parse().unwrap());
        rule.resolved_wan = Some(DnsWanBinding {
            ipv4: Some(("cu".into(), "192.0.2.1".parse().unwrap())),
            ipv4_link_id: Some(cu),
            ipv6: Some(("ct".into(), "2001:db8:2::1".parse().unwrap())),
            ipv6_link_id: Some(ct),
        });
        let selected = select(&rule, &groups).unwrap();
        assert_eq!(
            selected.bind_config.server_ips(&selected.ips),
            vec!["210.21.196.6".parse::<std::net::IpAddr>().unwrap()]
        );
        rule.resolved_wan.as_mut().unwrap().ipv4 = None;
        let selected = select(&rule, &groups).unwrap();
        assert_eq!(
            selected.bind_config.server_ips(&selected.ips),
            vec!["2001:db8:2::53".parse::<std::net::IpAddr>().unwrap()]
        );
    }
}

#[cfg(test)]
mod packet_tests {
    use super::*;
    use crate::upstream::{LandscapeResolver, pool::ResolvePool};
    use hickory_proto::{
        op::{Message, OpCode},
        rr::{RData, Record, RecordType, rdata::A},
    };
    use landscape_common::dns::bind::DnsWanBinding;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn independent_groups_query_only_the_selected_carrier_and_recover() {
        if std::env::var("LANDSCAPE_PRIVILEGED_CI").as_deref() != Ok("1") {
            return;
        }
        let first = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = tokio::net::UdpSocket::bind(("127.0.0.3", port)).await.unwrap();
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let mut tasks = Vec::new();
        for (index, socket) in [first, second].into_iter().enumerate() {
            let counts = counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                    counts[index].fetch_add(1, Ordering::SeqCst);
                    let request = Message::from_vec(&buffer[..size]).unwrap();
                    let query = request.queries[0].clone();
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.metadata.recursion_desired = true;
                    response.metadata.recursion_available = true;
                    response.add_query(query.clone()).add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, index as u8 + 1))),
                    ));
                    socket.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
                }
            }));
        }
        let cu = Uuid::new_v4();
        let ct = Uuid::new_v4();
        let a = DnsUpstreamConfig {
            ips: vec!["127.0.0.2".parse().unwrap()],
            port: Some(port),
            ..Default::default()
        };
        let b = DnsUpstreamConfig {
            ips: vec!["127.0.0.3".parse().unwrap()],
            port: Some(port),
            ..Default::default()
        };
        let mut rule: DNSRuleConfig = serde_json::from_value(serde_json::json!({
            "name":"separate groups","index":10,"enable":true,"flow_id":20,"upstream_id":a.id,
            "wan_upstreams":[{"link_id":cu,"upstream_id":a.id},{"link_id":ct,"upstream_id":b.id}]
        }))
        .unwrap();
        let groups = HashMap::from([(a.id, a), (b.id, b)]);
        let pool = ResolvePool::default();
        let mut previous = None;
        for (link, answer, expected) in
            [(cu, "192.0.2.1", [1, 0]), (ct, "192.0.2.2", [1, 1]), (cu, "192.0.2.1", [2, 1])]
        {
            rule.resolved_wan = Some(DnsWanBinding {
                ipv4: Some(("lo".into(), "127.0.0.1".parse().unwrap())),
                ipv4_link_id: Some(link),
                ..Default::default()
            });
            let upstream = select(&rule, &groups).unwrap();
            let resolver = pool.get_or_create(20, 0x8014, &upstream).unwrap();
            if let Some(old) = previous {
                assert!(!Arc::ptr_eq(&resolver, &old));
            }
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                resolver.lookup("independent.test.", RecordType::A),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(result.answers().iter().any(|r| r.data.to_string() == answer));
            assert_eq!(
                [counts[0].load(Ordering::SeqCst), counts[1].load(Ordering::SeqCst)],
                expected
            );
            previous = Some(resolver);
        }
        rule.resolved_wan = None;
        let resolver = pool.get_or_create(20, 0x8014, &select(&rule, &groups).unwrap()).unwrap();
        assert!(matches!(*resolver, LandscapeResolver::Unavailable));
        assert!(resolver.lookup("independent.test.", RecordType::A).await.is_err());
        assert_eq!([counts[0].load(Ordering::SeqCst), counts[1].load(Ordering::SeqCst)], [2, 1]);
        for task in tasks {
            task.abort();
        }
    }
}
