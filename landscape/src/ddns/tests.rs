use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::ddns::{
    DdnsJobStatus, DdnsRuntimeReason, DdnsSource, DdnsTaskPhase, IpFamily,
};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::lan_service::lan_ipv6::{combine_ipv6_prefix_suffix, extract_ipv6_suffix};
use landscape_common::sys_service::route_service::RouteOwner;
use landscape_core::lan_device::AddressSourceV6;

use super::job_sync::{dedup_and_sort_ips, is_global_unicast_ipv6, select_enrolled_device_ipv6};
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
        ipv6_ula_fallback: true,
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
        ipv6_ula_fallback: true,
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
            ipv6_ula_fallback: true,
        },
        DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_link_id: Uuid::new_v4(),
            wan_pd_id: None,
            family: IpFamily::Ipv4,
            ipv6_ula_fallback: true,
        },
    ]);

    assert!(job_has_enrolled_device_ipv6(&job));
    assert!(job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::nil()));
    assert!(!job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::new_v4()));
}

#[test]
fn ipv6_global_unicast_only_segment_is_publishable() {
    assert!(is_global_unicast_ipv6(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    assert!(!is_global_unicast_ipv6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
    assert!(!is_global_unicast_ipv6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    assert!(!is_global_unicast_ipv6(&Ipv6Addr::LOCALHOST));
    assert!(!is_global_unicast_ipv6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn enrolled_device_gua_and_ula_yield_one_record() {
    let pd_prefix = Ipv6Addr::new(0x240e, 0x1, 0x4a01, 0, 0, 0, 0, 0);
    let pd_len = 56;
    // Same interface identifier on the delegated prefix and inside the ULA
    // range: the old loop published both, mirrored onto the same PD.
    let gua = Ipv6Addr::new(0x240e, 0x1, 0x4a01, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20);
    let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20);

    let mut addrs = HashMap::new();
    addrs.insert(ula, AddressSourceV6::Static);
    addrs.insert(gua, AddressSourceV6::Slaac);

    // A weaker GUA still beats a stronger ULA.
    let selected = select_enrolled_device_ipv6(&addrs, true).expect("publishable address");
    assert_eq!(selected, gua);

    let suffix = extract_ipv6_suffix(selected, pd_len);
    let published = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
    assert_eq!(published, gua);
    assert_eq!(dedup_and_sort_ips([IpAddr::V6(published), IpAddr::V6(published)]).len(), 1);
}

#[test]
fn enrolled_device_ula_needs_the_fallback_switch() {
    let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    let mut addrs = HashMap::new();
    addrs.insert(link_local, AddressSourceV6::Static);
    addrs.insert(ula, AddressSourceV6::Dhcpv6);

    assert_eq!(select_enrolled_device_ipv6(&addrs, true), Some(ula));
    assert_eq!(select_enrolled_device_ipv6(&addrs, false), None);

    let mut link_local_only = HashMap::new();
    link_local_only.insert(link_local, AddressSourceV6::Slaac);
    assert_eq!(select_enrolled_device_ipv6(&link_local_only, true), None);
}

#[test]
fn enrolled_device_selection_prefers_static_source() {
    let static_ip = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 0x20);
    let slaac_ip = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 0x10);

    let mut addrs = HashMap::new();
    addrs.insert(slaac_ip, AddressSourceV6::Slaac);
    addrs.insert(static_ip, AddressSourceV6::Static);

    assert_eq!(select_enrolled_device_ipv6(&addrs, true), Some(static_ip));
}

#[test]
fn enrolled_device_selection_is_stable_for_equal_sources() {
    let low = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 0x10);
    let high = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 0x20);

    let mut addrs = HashMap::new();
    addrs.insert(high, AddressSourceV6::Dhcpv6);
    addrs.insert(low, AddressSourceV6::Dhcpv6);

    assert_eq!(select_enrolled_device_ipv6(&addrs, true), Some(low));
}

#[test]
fn multi_source_resolution_dedups_and_sorts() {
    let a = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));
    let b = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 1));

    let resolved = dedup_and_sort_ips([a, b, a, v6]);
    assert_eq!(resolved, vec![b, a, v6]);
}
