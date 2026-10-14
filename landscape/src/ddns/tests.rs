use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::ddns::{
    DdnsJobStatus, DdnsRuntimeReason, DdnsSource, DdnsTaskPhase, IpFamily,
};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::lan_service::lan_ipv6::{combine_ipv6_prefix_suffix, extract_ipv6_suffix};
use landscape_common::sys_service::route_service::RouteOwner;
use landscape_core::lan_device::AddressSourceV6;

use super::job_sync::select_enrolled_device_raw_ipv6;
use super::runtime_state::{
    DdnsRecordCleanupTarget, apply_job_runtime_summary, cleanup_targets_from_runtime,
    effective_ddns_ttl, runtime_message_for_reason,
};
use super::*;
use crate::sys_service::route::WanRouteEventKind;

#[test]
fn task_registry_insert_and_duplicate() {
    let registry = DdnsTaskRegistry::default();
    let id = Uuid::new_v4();

    assert!(registry.progress_snapshot().is_empty());
    let token = registry.insert(id).expect("first insert should succeed");
    assert_eq!(registry.progress_snapshot().len(), 1);
    assert!(registry.insert(id).is_err(), "duplicate insert should fail");

    let snapshot = registry.progress_snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].job_id, id);
    assert_eq!(snapshot[0].phase, DdnsTaskPhase::ResolvingSource);

    drop(token);
}

#[test]
fn task_registry_cancel_token_survives_phase_updates() {
    let registry = DdnsTaskRegistry::default();
    let id = Uuid::new_v4();
    let token = registry.insert(id).expect("insert should succeed");

    registry.update_phase(id, DdnsTaskPhase::Publishing, Some("@ (ipv4, 1/2)".into()));
    assert!(registry.cancel_task(id));
    assert!(token.is_cancelled());

    let snapshot = registry.progress_snapshot();
    assert_eq!(snapshot[0].phase, DdnsTaskPhase::Publishing);
    assert_eq!(snapshot[0].phase_detail.as_deref(), Some("@ (ipv4, 1/2)"));
    assert!(snapshot[0].updated_at >= snapshot[0].started_at);
}

#[test]
fn task_registry_remove_and_cancel_missing() {
    let registry = DdnsTaskRegistry::default();
    let id = Uuid::new_v4();
    registry.insert(id).expect("insert should succeed");

    registry.remove(id);
    registry.remove(id);

    assert!(registry.progress_snapshot().is_empty());
    assert!(!registry.cancel_task(id));
    registry.update_phase(id, DdnsTaskPhase::Publishing, None);
    assert!(registry.progress_snapshot().is_empty());
}

#[test]
fn task_registry_cancel_all() {
    let registry = DdnsTaskRegistry::default();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let first_token = registry.insert(first).expect("insert should succeed");
    let second_token = registry.insert(second).expect("insert should succeed");

    registry.cancel_all();
    assert!(first_token.is_cancelled());
    assert!(second_token.is_cancelled());
}

#[test]
fn task_registry_start_or_mark_and_finish_or_continue() {
    let registry = DdnsTaskRegistry::default();
    let id = Uuid::new_v4();

    assert!(!registry.has_task(id));
    let DdnsTaskStart::Started(token) = registry.start_or_mark(id) else {
        panic!("free slot should start");
    };
    assert!(registry.has_task(id));

    assert!(matches!(registry.start_or_mark(id), DdnsTaskStart::MarkedPending));
    assert!(!token.is_cancelled(), "marking pending must not cancel the task");

    // Pending was set: the entry survives and progress resets.
    assert!(matches!(registry.finish_or_continue(id), DdnsTaskFinish::Continue));
    assert!(registry.has_task(id));
    assert_eq!(registry.progress_snapshot().len(), 1);

    // No new mark: the entry is removed.
    assert!(matches!(registry.finish_or_continue(id), DdnsTaskFinish::Stopped));
    assert!(!registry.has_task(id));

    // Slot is free again for a fresh start.
    assert!(matches!(registry.start_or_mark(id), DdnsTaskStart::Started(_)));
}

#[test]
fn task_registry_strict_insert_rejects_busy_slot() {
    let registry = DdnsTaskRegistry::default();
    let id = Uuid::new_v4();
    registry.insert(id).expect("insert should succeed");
    assert!(registry.has_task(id));
    assert!(registry.insert(id).is_err());
}

#[test]
fn cleanup_targets_only_include_published_families() {
    let mut job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: Uuid::nil(),
        family: IpFamily::Ipv4,
    }]);
    job.records
        .push(landscape_common::ddns::DdnsRecordConfig { name: "home".to_string(), enable: true });

    let mut runtime = DdnsJobRuntime::from_config(&job);
    runtime.records[0].ipv4.last_published_ips =
        vec![IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10))];
    runtime.records[1].ipv6.last_published_ips = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];

    let mut targets = cleanup_targets_from_runtime(&runtime);
    targets.sort_by(|a, b| a.record_name.cmp(&b.record_name));
    assert_eq!(
        targets,
        vec![
            DdnsRecordCleanupTarget {
                record_name: "@".to_string(),
                family: IpFamily::Ipv4
            },
            DdnsRecordCleanupTarget {
                record_name: "home".to_string(),
                family: IpFamily::Ipv6
            },
        ]
    );

    runtime.records[0].ipv4.last_published_ips.clear();
    runtime.records[1].ipv6.last_published_ips.clear();
    assert!(cleanup_targets_from_runtime(&runtime).is_empty());
}

fn test_job(sources: Vec<DdnsSource>) -> DdnsJob {
    DdnsJob {
        id: Uuid::nil(),
        name: "test".to_string(),
        enable: true,
        sources,
        zone_name: "example.com".to_string(),
        provider_profile_id: Uuid::nil(),
        ttl: Some(120),
        records: vec![landscape_common::ddns::DdnsRecordConfig {
            name: "@".to_string(),
            enable: true,
        }],
        update_at: 0.0,
    }
}

fn test_profile(ddns_default_ttl: Option<u32>) -> DnsProviderProfile {
    DnsProviderProfile {
        id: Uuid::nil(),
        name: "profile".to_string(),
        provider_config: DnsProviderConfig::Cloudflare { api_token: "token".to_string() },
        remark: None,
        ddns_default_ttl,
        update_at: 0.0,
    }
}

#[test]
fn wan_event_only_matches_same_iface_and_family() {
    let wan0 = Uuid::nil();
    let wan1 = Uuid::new_v4();
    let job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: wan0,
        family: IpFamily::Ipv4,
    }]);

    assert!(job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan0),
            family: IpFamily::Ipv4,
            kind: WanRouteEventKind::Upserted,
        }
    ));
    assert!(!job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan1),
            family: IpFamily::Ipv4,
            kind: WanRouteEventKind::Upserted,
        }
    ));
    assert!(!job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan0),
            family: IpFamily::Ipv6,
            kind: WanRouteEventKind::Upserted,
        }
    ));
}

#[test]
fn fast_retry_only_applies_before_first_publish() {
    let job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: Uuid::nil(),
        family: IpFamily::Ipv4,
    }]);
    let mut runtime = DdnsJobRuntime::from_config(&job);
    runtime.records[0].ipv4.reason = DdnsRuntimeReason::WaitingWanIp;
    runtime.records[0].ipv4.retryable = true;
    runtime.records[0].ipv4.next_retry_at = Some(0.0);

    assert!(job_needs_retry(&job, Some(&runtime)));

    runtime.records[0].ipv4.last_published_ips =
        vec![IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10))];
    runtime.records[0].ipv4.status = DdnsJobStatus::Error;
    assert!(!job_needs_retry(&job, Some(&runtime)));
}

#[test]
fn custom_job_ttl_overrides_profile_default() {
    let job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: Uuid::nil(),
        family: IpFamily::Ipv4,
    }]);

    assert_eq!(effective_ddns_ttl(&job, &test_profile(Some(600))), Some(120));
    assert_eq!(effective_ddns_ttl(&job, &test_profile(None)), Some(120));
}

#[test]
fn inherited_job_ttl_uses_profile_default() {
    let mut job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: Uuid::nil(),
        family: IpFamily::Ipv4,
    }]);
    job.ttl = None;

    assert_eq!(effective_ddns_ttl(&job, &test_profile(Some(600))), Some(600));
    assert_eq!(effective_ddns_ttl(&job, &test_profile(None)), None);
}

#[test]
fn single_stack_job_summary_ignores_unconfigured_family() {
    let job = test_job(vec![DdnsSource::LocalWan {
        iface_name: "wan0".to_string(),
        link_id: Uuid::nil(),
        family: IpFamily::Ipv6,
    }]);
    let mut runtime = DdnsJobRuntime::from_config(&job);

    runtime.records[0].ipv6.status = DdnsJobStatus::Success;
    runtime.records[0].ipv6.reason = DdnsRuntimeReason::UpToDate;
    runtime.records[0].ipv6.message =
        Some(runtime_message_for_reason(DdnsRuntimeReason::UpToDate).to_string());

    apply_job_runtime_summary(&mut runtime);

    assert_eq!(runtime.records[0].ipv4.reason, DdnsRuntimeReason::NotConfigured);
    assert_eq!(runtime.status, DdnsJobStatus::Success);
    assert_eq!(runtime.reason, DdnsRuntimeReason::UpToDate);
}

#[test]
fn wan_event_matches_enrolled_device_source() {
    let wan0 = Uuid::nil();
    let wan1 = Uuid::new_v4();
    let job = test_job(vec![DdnsSource::EnrolledDevice {
        device_id: Uuid::nil(),
        wan_pd_link_id: wan0,
        wan_pd_id: Some("wan0".to_string()),
        family: IpFamily::Ipv4,
    }]);

    assert!(job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan0),
            family: IpFamily::Ipv4,
            kind: WanRouteEventKind::Upserted,
        }
    ));
    assert!(!job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan0),
            family: IpFamily::Ipv6,
            kind: WanRouteEventKind::Upserted,
        }
    ));
    assert!(!job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Link(wan1),
            family: IpFamily::Ipv4,
            kind: WanRouteEventKind::Upserted,
        }
    ));
}

#[test]
fn wan_event_does_not_match_netns_owner_for_enrolled_device() {
    let job = test_job(vec![DdnsSource::EnrolledDevice {
        device_id: Uuid::nil(),
        wan_pd_link_id: Uuid::nil(),
        wan_pd_id: None,
        family: IpFamily::Ipv4,
    }]);

    assert!(!job_matches_wan_event(
        &job,
        &WanRouteEvent {
            owner: RouteOwner::Netns("any".to_string()),
            family: IpFamily::Ipv4,
            kind: WanRouteEventKind::Upserted,
        }
    ));
}

#[test]
fn config_change_pd_sync_ignores_missing_wan_pd_id_mirror() {
    let job = test_job(vec![
        DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_link_id: Uuid::nil(),
            wan_pd_id: None,
            family: IpFamily::Ipv6,
        },
        DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_link_id: Uuid::new_v4(),
            wan_pd_id: None,
            family: IpFamily::Ipv4,
        },
    ]);

    assert!(job_has_enrolled_device_ipv6(&job));
    assert!(job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::nil()));
    assert!(!job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::new_v4()));
}

#[test]
fn ipv6_gua_and_ula_accepted_not_link_local() {
    let gua = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let loopback = Ipv6Addr::LOCALHOST;
    let multicast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    let acceptable = |addr: Ipv6Addr| -> bool {
        (addr.segments()[0] & 0xe000) == 0x2000 || addr.is_unique_local()
    };

    assert!(acceptable(gua));
    assert!(acceptable(ula));
    assert!(!acceptable(link_local));
    assert!(!acceptable(loopback));
    assert!(!acceptable(multicast));
}

#[test]
fn enrolled_device_suffix_dedup_produces_unique_ips() {
    let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
    let pd_len = 64;

    let device_ips = vec![
        Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
        Ipv6Addr::new(0x2001, 0xdb8, 0x2, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
    ];

    let mut seen_suffixes = HashSet::new();
    let mut result: Vec<IpAddr> = Vec::new();
    for raw_ip in &device_ips {
        if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
            continue;
        }
        let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
        if seen_suffixes.insert(suffix) {
            let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
            result.push(IpAddr::V6(ip));
        }
    }

    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20))
    );
}

#[test]
fn enrolled_device_different_suffixes_produce_multiple_ips() {
    let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
    let pd_len = 64;

    let device_ips = vec![
        Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0),
    ];

    let mut seen_suffixes = HashSet::new();
    let mut result: Vec<IpAddr> = Vec::new();
    for raw_ip in &device_ips {
        if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
            continue;
        }
        let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
        if seen_suffixes.insert(suffix) {
            let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
            result.push(IpAddr::V6(ip));
        }
    }

    assert_eq!(result.len(), 2);
}

#[test]
fn enrolled_device_fe80_is_filtered_out() {
    let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
    let pd_len = 64;

    let device_ips = vec![Ipv6Addr::new(0xfe80, 0, 0, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20)];

    let mut seen_suffixes = HashSet::new();
    let mut result: Vec<IpAddr> = Vec::new();
    for raw_ip in &device_ips {
        if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
            continue;
        }
        let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
        if seen_suffixes.insert(suffix) {
            let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
            result.push(IpAddr::V6(ip));
        }
    }

    assert!(result.is_empty());
}

#[test]
fn select_enrolled_device_raw_ipv6_prefers_gua_over_ula() {
    let mut addrs = HashMap::new();
    let gua = Ipv6Addr::new(0x240e, 0x1234, 0x5678, 0x9000, 0, 0, 0, 1);
    let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    addrs.insert(ula, AddressSourceV6::Static);
    addrs.insert(gua, AddressSourceV6::Slaac);

    let selected = select_enrolled_device_raw_ipv6(&addrs);
    assert_eq!(
        selected,
        Some(gua),
        "must prefer GUA when available even if ULA has higher priority rank"
    );
}

#[test]
fn select_enrolled_device_raw_ipv6_prefers_static_and_lowest_ip() {
    let mut addrs = HashMap::new();
    let gua_slaac = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 1);
    let gua_static = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 2);

    addrs.insert(gua_slaac, AddressSourceV6::Slaac);
    addrs.insert(gua_static, AddressSourceV6::Static);

    let selected = select_enrolled_device_raw_ipv6(&addrs);
    assert_eq!(
        selected,
        Some(gua_static),
        "Static should have higher priority than Slaac within GUA"
    );

    let mut addrs_same_rank = HashMap::new();
    let ip_small = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 10);
    let ip_large = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 20);
    addrs_same_rank.insert(ip_large, AddressSourceV6::Dhcpv6);
    addrs_same_rank.insert(ip_small, AddressSourceV6::Dhcpv6);

    let selected_same_rank = select_enrolled_device_raw_ipv6(&addrs_same_rank);
    assert_eq!(
        selected_same_rank,
        Some(ip_small),
        "should select lexicographically lowest IP among same source rank within GUA"
    );
}

#[test]
fn select_enrolled_device_raw_ipv6_fallback_ula_and_link_local_none() {
    let mut addrs_ula = HashMap::new();
    let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    addrs_ula.insert(ula, AddressSourceV6::Slaac);
    addrs_ula.insert(link_local, AddressSourceV6::Static);

    let selected_ula = select_enrolled_device_raw_ipv6(&addrs_ula);
    assert_eq!(
        selected_ula,
        Some(ula),
        "should fall back to usable ULA when no usable GUA is available"
    );

    let mut addrs_ll = HashMap::new();
    addrs_ll.insert(link_local, AddressSourceV6::Static);

    let selected_ll = select_enrolled_device_raw_ipv6(&addrs_ll);
    assert_eq!(selected_ll, None, "should return None when only link-local addresses exist");
}

#[test]
fn enrolled_device_multi_pd_and_accumulator_dedup() {
    let raw_ip = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 0x50);
    let pd1_prefix = Ipv6Addr::new(0x240e, 0x1, 0x4a01, 0, 0, 0, 0, 0);
    let pd2_prefix = Ipv6Addr::new(0x240e, 0x2, 0x4a11, 0, 0, 0, 0, 0);
    let prefix_len = 56;

    let suffix = extract_ipv6_suffix(raw_ip, prefix_len);
    let ip1 = combine_ipv6_prefix_suffix(pd1_prefix, prefix_len, suffix);
    let ip2 = combine_ipv6_prefix_suffix(pd2_prefix, prefix_len, suffix);

    let mut accumulator = HashSet::new();
    accumulator.insert(IpAddr::V6(ip1));
    accumulator.insert(IpAddr::V6(ip2));

    assert_eq!(
        accumulator.len(),
        2,
        "the same raw IPv6 combined with two distinct PD prefixes should produce 2 distinct AAAA records"
    );

    // Accumulate same PD and same IID; should dedup to 1
    let mut dedup_acc = HashSet::new();
    dedup_acc.insert(IpAddr::V6(ip1));
    dedup_acc.insert(IpAddr::V6(ip1));
    assert_eq!(
        dedup_acc.len(),
        1,
        "accumulator should dedup identical PD and identical IID into 1 record"
    );
}
