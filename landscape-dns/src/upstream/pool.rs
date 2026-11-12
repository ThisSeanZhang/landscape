use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use landscape_common::dns::{bind::DnsBindConfig, config::DnsUpstreamConfig};
use uuid::Uuid;

use crate::upstream::{LandscapeResolver, create_resolver};

/// Key under which resolvers are shared: the DNS mark (the SO_MARK applied to
/// upstream connections, i.e. the flow component plus the always-set reuse
/// port bit `0x8000`) plus the upstream server identity. The DNS mark never
/// encodes the rule action (Direct -> flow 0, Redirect -> target flow,
/// otherwise the owning flow), matching the legacy per-rule computation, so
/// rules with the same mark share one resolver instance and therefore one
/// connection pool to the upstream. Source-address binding lives on the
/// upstream config, so `upstream_id` already implies it and it needs no
/// separate key component.
type ResolverKey = (u32, Uuid);

/// Global resolver pool shared across all flows. `UpstreamsChanged` triggers
/// `invalidate()` for the affected ids, so the next flow refresh rebuilds
/// resolvers unconditionally. Dropping an entry releases its engine: the
/// legacy resolver or the experimental pool (idle connections close with it).
///
/// Known tradeoff (accepted for now): entries are ONLY dropped on upstream
/// change (or process restart). When a rule's mark/flow changes or a rule is
/// deleted (`RulesChanged` does a ResolveOnly refresh and never invalidates),
/// the old `(mark, upstream)` entry stays in the map forever, keeping its
/// connection pool alive until that upstream changes or the daemon restarts.
/// Harmless today (lightweight, cache_size = 0) but worth a sweep that drops
/// entries no rule references anymore if this ever becomes a problem.
#[derive(Debug, Default)]
pub struct ResolvePool {
    resolvers: RwLock<HashMap<ResolverKey, (DnsBindConfig, Arc<LandscapeResolver>)>>,
}

impl ResolvePool {
    /// Returns the shared resolver for `(dns_mark, upstream)`, building it
    /// on first use. A failed build is never cached so a later retry can
    /// succeed; the caller skips the rule, matching the pre-pool behaviour.
    pub(crate) fn get_or_create(
        &self,
        flow_id: u32,
        dns_mark: u32,
        upstream: &DnsUpstreamConfig,
    ) -> Option<Arc<LandscapeResolver>> {
        let dns_mark = upstream.bind_config.socket_mark(dns_mark);
        let key = (dns_mark, upstream.id);
        if let Some((binding, resolver)) =
            self.resolvers.read().unwrap_or_else(|e| e.into_inner()).get(&key)
            && binding == &upstream.bind_config
        {
            return Some(resolver.clone());
        }

        let resolver = Arc::new(create_resolver(flow_id, dns_mark, upstream.clone())?);

        let mut resolvers = self.resolvers.write().unwrap_or_else(|e| e.into_inner());
        if let Some((binding, current)) = resolvers.get(&key)
            && binding == &upstream.bind_config
        {
            return Some(current.clone());
        }
        resolvers.insert(key, (upstream.bind_config.clone(), resolver.clone()));
        Some(resolver)
    }

    /// Unconditionally drops every resolver for the given upstream ids. Old
    /// instances stay alive until the last `Arc` (in-flight queries, rules)
    /// is released, then their connections close naturally.
    pub(crate) fn invalidate(&self, upstream_ids: &HashSet<Uuid>) {
        if upstream_ids.is_empty() {
            return;
        }
        self.resolvers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, upstream_id), _| !upstream_ids.contains(upstream_id));
    }

    /// Test-only snapshot of the current pool keys.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<(u32, Uuid)> {
        self.resolvers.read().unwrap_or_else(|e| e.into_inner()).keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream() -> DnsUpstreamConfig {
        DnsUpstreamConfig::default()
    }

    #[tokio::test]
    async fn carrier_dns_switches_destination_and_pool_then_recovers() {
        use hickory_proto::{
            op::{Message, OpCode},
            rr::{RData, Record, RecordType, rdata::A},
        };
        use landscape_common::dns::bind::{DnsWanBinding, DnsWanServers};
        use std::sync::atomic::{AtomicUsize, Ordering};
        if std::env::var("LANDSCAPE_PRIVILEGED_CI").as_deref() != Ok("1") {
            return;
        }
        let cu_socket = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let port = cu_socket.local_addr().unwrap().port();
        let ct_socket = tokio::net::UdpSocket::bind(("127.0.0.3", port)).await.unwrap();
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let mut tasks = Vec::new();
        for (index, socket) in [cu_socket, ct_socket].into_iter().enumerate() {
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
        let mut upstream = upstream();
        upstream.port = Some(port);
        // A deliberately unusable static fallback must never be queried.
        upstream.ips = vec!["192.0.2.53".parse().unwrap()];
        upstream.bind_config.follow_flow = Some(7);
        upstream.bind_config.wan_servers = vec![
            DnsWanServers {
                link_id: cu,
                ips: vec!["127.0.0.2".parse().unwrap()],
            },
            DnsWanServers {
                link_id: ct,
                ips: vec!["127.0.0.3".parse().unwrap()],
            },
        ];
        upstream.bind_config.resolved_wan = Some(DnsWanBinding {
            ipv4: Some(("lo".into(), "127.0.0.1".parse().unwrap())),
            ipv4_link_id: Some(cu),
            ..Default::default()
        });
        let pool = ResolvePool::default();
        for (link, expected, queries) in
            [(cu, "192.0.2.1", [1, 0]), (ct, "192.0.2.2", [1, 1]), (cu, "192.0.2.1", [2, 1])]
        {
            upstream.bind_config.resolved_wan.as_mut().unwrap().ipv4_link_id = Some(link);
            let resolver = pool.get_or_create(7, 0x8007, &upstream).unwrap();
            let answer = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                resolver.lookup("example.test.", RecordType::A),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(answer.answers().iter().any(|record| record.data.to_string() == expected));
            assert_eq!(
                [counts[0].load(Ordering::SeqCst), counts[1].load(Ordering::SeqCst)],
                queries
            );
        }
        upstream.bind_config.resolved_wan = None;
        let blocked = pool.get_or_create(7, 0x8007, &upstream).unwrap();
        assert!(matches!(*blocked, LandscapeResolver::Unavailable));
        assert!(blocked.lookup("example.test.", RecordType::A).await.is_err());
        assert_eq!([counts[0].load(Ordering::SeqCst), counts[1].load(Ordering::SeqCst)], [2, 1]);
        for task in tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn wan_address_change_replaces_transport_pool() {
        let pool = ResolvePool::default();
        let mut upstream = upstream();
        upstream.bind_config.follow_flow = Some(7);
        upstream.bind_config.resolved_wan = Some(landscape_common::dns::bind::DnsWanBinding {
            ipv4: Some(("wan1".into(), "192.0.2.1".parse().unwrap())),
            ipv6: None,
            ..Default::default()
        });
        let first = pool.get_or_create(3, 0x8003, &upstream).unwrap();
        upstream.bind_config.resolved_wan.as_mut().unwrap().ipv4 =
            Some(("wan2".into(), "198.51.100.1".parse().unwrap()));
        let second = pool.get_or_create(3, 0x8003, &upstream).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(pool.keys(), vec![(0x8007, upstream.id)]);
    }

    #[tokio::test]
    async fn same_key_reuses_resolver() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let first = pool.get_or_create(7, 0x8005, &upstream).unwrap();
        let second = pool.get_or_create(7, 0x8005, &upstream).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(pool.keys(), vec![(0x8005, upstream.id)]);
    }

    #[tokio::test]
    async fn different_marks_build_separate_resolvers() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let flow5 = pool.get_or_create(5, 0x8005, &upstream).unwrap();
        let flow7 = pool.get_or_create(7, 0x8007, &upstream).unwrap();

        assert!(!Arc::ptr_eq(&flow5, &flow7));
        let mut keys = pool.keys();
        keys.sort();
        assert_eq!(keys, vec![(0x8005, upstream.id), (0x8007, upstream.id)]);
    }

    #[tokio::test]
    async fn invalidate_drops_only_targeted_upstreams() {
        let pool = ResolvePool::default();
        let upstream_a = upstream();
        let upstream_b = upstream();
        let a = pool.get_or_create(7, 0x8000, &upstream_a).unwrap();
        let b = pool.get_or_create(7, 0x8000, &upstream_b).unwrap();

        pool.invalidate(&HashSet::from([upstream_a.id]));

        let a_rebuilt = pool.get_or_create(7, 0x8000, &upstream_a).unwrap();
        let b_kept = pool.get_or_create(7, 0x8000, &upstream_b).unwrap();
        assert!(!Arc::ptr_eq(&a, &a_rebuilt));
        assert!(Arc::ptr_eq(&b, &b_kept));
    }

    #[tokio::test]
    async fn invalidate_empty_set_is_noop() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let first = pool.get_or_create(7, 0x8005, &upstream).unwrap();

        pool.invalidate(&HashSet::new());

        let second = pool.get_or_create(7, 0x8005, &upstream).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
