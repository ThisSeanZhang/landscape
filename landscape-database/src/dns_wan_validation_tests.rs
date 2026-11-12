use super::*;
use landscape_common::{
    config_service::iface::{CreateDevType, IfaceZoneType, NetworkIfaceConfig},
    database::{error::DbError, store::ConfigStore},
    dns::{bind::DnsWanServers, rule::DnsWanUpstream},
    flow::{
        FlowTargetMode, WeightedFlowTarget,
        ip_mark::WanIpRuleConfig,
        mark::{FlowMark, FlowMarkAction},
    },
    wan_link::WanLinkKind,
};
use sea_orm::prelude::Uuid;

use crate::provider::LandscapeDBServiceProvider;

fn fixture() -> InitConfig {
    let links: Vec<WanLinkConfig> = ["eth-a", "eth-b"]
        .iter()
        .enumerate()
        .map(|(index, iface)| {
            let mut link: WanLinkConfig =
                serde_json::from_value(serde_json::json!({ "attach_iface_name": iface })).unwrap();
            link.kind = WanLinkKind::Pppd {
                ppp_iface_name: format!("ppp{index}"),
                peer_id: "test".into(),
                password: "test".into(),
                ac: None,
                plugin: Default::default(),
            };
            link.v4.enable = true;
            link.health_check.enable = true;
            link.health_check.probe = serde_json::from_value(
                serde_json::json!({"t":"icmp", "targets":["192.0.2.53"],"probe_gateway":false}),
            )
            .unwrap();
            link
        })
        .collect();
    let groups = vec![DnsUpstreamConfig::default(), DnsUpstreamConfig::default()];
    let mut flow: FlowConfig = serde_json::from_value(serde_json::json!({
        "enable":true,"flow_id":20,"flow_match_rules":[],"flow_targets":[],"name":"家庭网络","remark":""
    })).unwrap();
    flow.failover.mode = FlowTargetMode::PrimaryBackup;
    flow.failover.enable = true;
    flow.flow_targets = links
        .iter()
        .map(|link| {
            WeightedFlowTarget::new(
                FlowTarget::Interface {
                    link_id: link.id,
                    name: link.section_iface_name().into(),
                },
                1,
            )
        })
        .collect();
    let mut rule: DNSRuleConfig = serde_json::from_value(serde_json::json!({
        "name":"国内网站","index":10,"enable":true,"flow_id":20,"upstream_id":groups[0].id
    }))
    .unwrap();
    rule.wan_upstreams = links
        .iter()
        .zip(&groups)
        .map(|(link, group)| DnsWanUpstream { link_id: link.id, upstream_id: group.id })
        .collect();
    InitConfig {
        ifaces: links
            .iter()
            .map(|link| NetworkIfaceConfig {
                name: link.attach_iface_name.clone(),
                create_dev_type: CreateDevType::NoNeedToCreate,
                controller_name: None,
                zone_type: IfaceZoneType::Wan,
                enable_in_boot: true,
                wifi_mode: Default::default(),
                xps_rps: None,
                update_at: 0.0,
            })
            .collect(),
        wan_links: links,
        flow_rules: vec![flow],
        dns_rules: vec![rule],
        dns_upstream_configs: groups,
        ..Default::default()
    }
}

#[test]
fn weighted_dns_requires_one_positive_weight_wan_identity() {
    let mut config = fixture();
    let flow = &mut config.flow_rules[0];
    flow.failover = Default::default();
    assert!(!supports_wan_dns(flow));
    flow.flow_targets[1].weight = 0;
    assert!(supports_wan_dns(flow));
    flow.flow_targets[1] = flow.flow_targets[0].clone();
    assert!(supports_wan_dns(flow));
    for target in &mut flow.flow_targets {
        target.weight = 0;
    }
    assert!(!supports_wan_dns(flow));
    flow.failover.mode = FlowTargetMode::PrimaryBackup;
    assert!(supports_wan_dns(flow), "manual primary mode still selects one WAN");
    flow.enable = false;
    assert!(!supports_wan_dns(flow));
}

#[tokio::test]
async fn rule_save_and_flow_edit_enforce_wan_identity_in_both_directions() {
    let mut config = fixture();
    let rule = config.dns_rules.pop().unwrap();
    config.flow_rules[0].failover = Default::default();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    assert!(matches!(
        db.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await,
        Err(DbError::Validation(ServiceConfigError::WanDnsFlowUnsupported { flow_id: 20 }))
    ));
    let mut flow = db.flow_rule_store().find_by_id(config.flow_rules[0].id).await.unwrap().unwrap();
    flow.flow_targets[1].weight = 0;
    let saved = db.flow_rule_store().checked_upsert(flow).await.unwrap().new;
    db.dns_rule_store().checked_upsert_flow_rule(rule).await.unwrap();
    for kind in 0..3 {
        let mut invalid = saved.clone();
        match kind {
            0 => invalid.flow_targets[1].weight = 1,
            1 => invalid.enable = false,
            _ => invalid.flow_id = 21,
        }
        assert!(matches!(
            db.flow_rule_store().checked_upsert(invalid).await,
            Err(DbError::Validation(ServiceConfigError::WanDnsFlowUnsupported { .. }))
        ));
    }
    let mut manual = saved;
    manual.failover.mode = FlowTargetMode::PrimaryBackup;
    manual.flow_targets[1].weight = 1;
    db.flow_rule_store().checked_upsert(manual).await.unwrap();
}

#[tokio::test]
async fn referenced_backup_group_and_wan_cannot_be_deleted() {
    let config = fixture();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    let backup = config.dns_upstream_configs[1].id;
    let error = db.dns_upstream_config_store().delete_unreferenced(backup).await.unwrap_err();
    assert!(
        matches!(&error, DbError::Validation(ServiceConfigError::DnsUpstreamInUse { references }) if references.contains("国内网站") && references.contains("20"))
    );
    assert!(db.dns_upstream_config_store().find_by_id(backup).await.unwrap().is_some());
    let wan = config.wan_links[1].id;
    let error = db.wan_link_store().delete_unreferenced(wan).await.unwrap_err();
    assert!(
        matches!(&error, DbError::Validation(ServiceConfigError::WanLinkInUse { references }) if references.contains("家庭网络") && references.contains("国内网站"))
    );
    db.flow_rule_store().delete_flow_with_rules(config.flow_rules[0].id).await.unwrap();
    assert!(db.dns_upstream_config_store().delete_unreferenced(backup).await.unwrap().is_some());
    assert!(db.wan_link_store().delete_unreferenced(wan).await.unwrap().is_some());
}

#[tokio::test]
async fn upstream_delete_protects_ordinary_rules_and_wan_delete_protects_legacy_servers() {
    let mut config = fixture();
    config.dns_rules[0].wan_upstreams.clear();
    let upstream_id = config.dns_rules[0].upstream_id;
    config.dns_upstream_configs[0].bind_config.follow_flow = Some(0);
    config.dns_upstream_configs[0].bind_config.wan_servers = vec![DnsWanServers {
        link_id: config.wan_links[0].id,
        ips: vec!["192.0.2.53".parse().unwrap()],
    }];
    config.flow_rules.clear();
    config.dns_rules[0].flow_id = 0;
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    assert!(matches!(
        db.dns_upstream_config_store().delete_unreferenced(upstream_id).await,
        Err(DbError::Validation(ServiceConfigError::DnsUpstreamInUse { .. }))
    ));
    assert!(matches!(
        db.wan_link_store().delete_unreferenced(config.wan_links[0].id).await,
        Err(DbError::Validation(ServiceConfigError::WanLinkInUse { .. }))
    ));
}

#[tokio::test]
async fn import_checks_whole_snapshot_and_preserves_legacy_defaults() {
    let mut config = fixture();
    config.wan_links.reverse();
    config.dns_upstream_configs.reverse();
    LandscapeDBServiceProvider::validate_init_config_can_import(config.clone()).await.unwrap();
    config.dns_rules[0].wan_upstreams.clear();
    let mut flow = serde_json::to_value(&config.flow_rules[0]).unwrap();
    flow.as_object_mut().unwrap().remove("failover");
    config.flow_rules[0] = serde_json::from_value(flow).unwrap();
    let mut rule = serde_json::to_value(&config.dns_rules[0]).unwrap();
    rule.as_object_mut().unwrap().remove("wan_upstreams");
    config.dns_rules[0] = serde_json::from_value(rule).unwrap();
    config.wan_links.iter_mut().for_each(|link| link.health_check.enable = false);
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    assert!(!db.flow_rule_store().list().await.unwrap()[0].failover.ordered_targets());
    assert!(db.dns_rule_store().list().await.unwrap()[0].wan_upstreams.is_empty());
}

#[tokio::test]
async fn invalid_imports_fail_before_touching_existing_data_or_callback() {
    let config = fixture();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    for case in 0..10 {
        let mut invalid = config.clone();
        match case {
            0 => {
                invalid.wan_links.remove(0);
            }
            1 => {
                invalid.dns_upstream_configs.remove(1);
            }
            2 => invalid.dns_upstream_configs[0].bind_config.follow_flow = Some(0),
            3 => {
                let duplicate = invalid.dns_rules[0].wan_upstreams[0].clone();
                invalid.dns_rules[0].wan_upstreams.push(duplicate);
            }
            4 => invalid.wan_links[0].health_check.enable = false,
            5 => {
                invalid.flow_rules[0].failover.bind_default_flow = true;
                let mut duplicate = invalid.flow_rules[0].clone();
                duplicate.id = Uuid::new_v4();
                duplicate.flow_id = 30;
                invalid.flow_rules.push(duplicate);
            }
            6 => invalid.flow_rules[0].flow_id = 256,
            7 => {
                let duplicate = invalid.dns_upstream_configs[0].clone();
                invalid.dns_upstream_configs.push(duplicate);
            }
            8 => invalid.dns_rules[0].flow_id = 99,
            _ => {
                invalid.dns_rules[0].wan_upstreams.clear();
                invalid.dns_rules[0].upstream_id = Uuid::new_v4();
            }
        }
        let called = std::sync::atomic::AtomicBool::new(false);
        let result = db
            .truncate_and_fit_from_before_commit(invalid, || {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(DbError::Validation(_))), "case {case}: {result:?}");
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(db.dns_rule_store().find_by_id(config.dns_rules[0].id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn disabled_ppp_can_pause_health_but_cannot_restart_without_it() {
    let config = fixture();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    let mut wan = db.wan_link_store().find_by_id(config.wan_links[0].id).await.unwrap().unwrap();
    wan.v4.enable = false;
    wan = db.wan_link_store().checked_upsert(wan).await.unwrap().new;
    wan.health_check.enable = false;
    wan = db.wan_link_store().checked_upsert(wan).await.unwrap().new;
    let mut paused = config.clone();
    paused.wan_links[0] = wan.clone();
    LandscapeDBServiceProvider::validate_init_config_can_import(paused.clone()).await.unwrap();
    wan.v4.enable = true;
    assert!(matches!(
        db.wan_link_store().checked_upsert(wan.clone()).await,
        Err(DbError::Validation(_))
    ));
    paused.wan_links[0] = wan;
    assert!(LandscapeDBServiceProvider::validate_init_config_can_import(paused).await.is_err());
}

#[tokio::test]
async fn batch_default_owners_are_checked_together_inside_transaction() {
    let mut config = fixture();
    config.dns_rules.clear();
    let mut second = config.flow_rules[0].clone();
    second.id = Uuid::new_v4();
    second.flow_id = 30;
    config.flow_rules.push(second);
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let mut flows = db.flow_rule_store().list().await.unwrap();
    flows.iter_mut().for_each(|flow| flow.failover.bind_default_flow = true);
    assert!(db.flow_rule_store().checked_upsert_many(flows).await.is_err());
    assert!(
        db.flow_rule_store()
            .list()
            .await
            .unwrap()
            .iter()
            .all(|flow| !flow.failover.bind_default_flow)
    );
}

#[tokio::test]
async fn concurrent_mapping_save_and_upstream_delete_never_leave_dangling_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let db = LandscapeDBServiceProvider::file_test_db(&dir.path().join("race.db")).await;
    let mut config = fixture();
    let rule = config.dns_rules.pop().unwrap();
    let id = config.dns_upstream_configs[1].id;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let rules = db.dns_rule_store();
    let upstreams = db.dns_upstream_config_store();
    let (save, delete) = tokio::join!(
        rules.checked_upsert_flow_rule(rule.clone()),
        upstreams.delete_unreferenced(id)
    );
    assert!(save.is_ok() ^ delete.is_ok(), "exactly one operation must succeed");
    if db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_some() {
        assert!(db.dns_upstream_config_store().find_by_id(id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn concurrent_mapping_save_and_flow_mode_edit_preserve_valid_binding() {
    let dir = tempfile::tempdir().unwrap();
    let db = LandscapeDBServiceProvider::file_test_db(&dir.path().join("race.db")).await;
    let mut config = fixture();
    let rule = config.dns_rules.pop().unwrap();
    let id = config.flow_rules[0].id;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let mut flow = db.flow_rule_store().find_by_id(id).await.unwrap().unwrap();
    flow.failover = Default::default();
    let rules = db.dns_rule_store();
    let flows = db.flow_rule_store();
    let (save, edit) =
        tokio::join!(rules.checked_upsert_flow_rule(rule.clone()), flows.checked_upsert(flow));
    assert!(save.is_ok() ^ edit.is_ok(), "exactly one operation must succeed");
    if db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_some() {
        assert!(supports_wan_dns(&db.flow_rule_store().find_by_id(id).await.unwrap().unwrap()));
    }
}

#[tokio::test]
async fn rule_save_rejects_each_non_independent_upstream_shape() {
    let mut config = fixture();
    let mut rule = config.dns_rules.pop().unwrap();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    for case in 0..5 {
        let mut group = DnsUpstreamConfig::default();
        match case {
            0 => group.ips.clear(),
            1 => group.bind_config.follow_flow = Some(0),
            2 => group.bind_config.bind_addr4 = Some("192.0.2.1".parse().unwrap()),
            3 => group.bind_config.bind_addr6 = Some("2001:db8::1".parse().unwrap()),
            _ => {
                group.bind_config.follow_flow = Some(0);
                group.bind_config.wan_servers = vec![DnsWanServers {
                    link_id: config.wan_links[0].id,
                    ips: vec!["192.0.2.53".parse().unwrap()],
                }];
            }
        }
        db.dns_upstream_config_store().checked_upsert(group.clone()).await.unwrap();
        rule.wan_upstreams[0].upstream_id = group.id;
        assert!(
            matches!(
                db.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await,
                Err(DbError::Validation(_))
            ),
            "case {case}"
        );
        assert!(db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn batch_invalid_wan_mapping_never_partially_updates_rules() {
    let config = fixture();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let saved = db.dns_rule_store().list().await.unwrap().remove(0);
    for missing_link in [false, true] {
        let mut changed = saved.clone();
        changed.name = "must not be saved".into();
        let mut invalid = saved.clone();
        invalid.id = Uuid::new_v4();
        if missing_link {
            invalid.wan_upstreams[0].link_id = Uuid::new_v4();
        } else {
            invalid.wan_upstreams[0].upstream_id = Uuid::new_v4();
        }
        assert!(
            db.dns_rule_store()
                .checked_upsert_flow_rules(vec![changed, invalid.clone()])
                .await
                .is_err()
        );
        let read = db.dns_rule_store().find_by_id(saved.id).await.unwrap().unwrap();
        assert_eq!(read.name, saved.name);
        assert_eq!(read.update_at, saved.update_at);
        assert!(db.dns_rule_store().find_by_id(invalid.id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn concurrent_mapping_save_and_upstream_binding_edit_preserve_independence() {
    let dir = tempfile::tempdir().unwrap();
    let db = LandscapeDBServiceProvider::file_test_db(&dir.path().join("race.db")).await;
    let mut config = fixture();
    let rule = config.dns_rules.pop().unwrap();
    let id = config.dns_upstream_configs[1].id;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let mut upstream = db.dns_upstream_config_store().find_by_id(id).await.unwrap().unwrap();
    upstream.bind_config.follow_flow = Some(0);
    let rules = db.dns_rule_store();
    let upstreams = db.dns_upstream_config_store();
    let (save, edit) = tokio::join!(
        rules.checked_upsert_flow_rule(rule.clone()),
        upstreams.checked_upsert(upstream)
    );
    assert!(save.is_ok() ^ edit.is_ok(), "exactly one operation must succeed");
    if db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_some() {
        assert!(
            db.dns_upstream_config_store()
                .find_by_id(id)
                .await
                .unwrap()
                .unwrap()
                .is_independent_wan_group()
        );
    }
}

#[tokio::test]
async fn concurrent_default_mapping_save_and_wan_delete_preserve_reference() {
    let dir = tempfile::tempdir().unwrap();
    let db = LandscapeDBServiceProvider::file_test_db(&dir.path().join("race.db")).await;
    let mut config = fixture();
    let mut rule = config.dns_rules.pop().unwrap();
    rule.flow_id = 0;
    config.flow_rules.clear();
    let id = config.wan_links[1].id;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let rules = db.dns_rule_store();
    let links = db.wan_link_store();
    let (save, delete) =
        tokio::join!(rules.checked_upsert_flow_rule(rule.clone()), links.delete_unreferenced(id));
    assert!(save.is_ok() ^ delete.is_ok(), "exactly one operation must succeed");
    if db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_some() {
        assert!(db.wan_link_store().find_by_id(id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn unused_single_upstream_can_be_deleted_until_mapping_is_removed() {
    let mut config = fixture();
    let unused = DnsUpstreamConfig::default();
    let id = unused.id;
    config.dns_upstream_configs.push(unused);
    config.dns_rules[0].upstream_id = id;
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    assert!(db.dns_upstream_config_store().delete_unreferenced(id).await.unwrap().is_some());
    let mut rule = db.dns_rule_store().list().await.unwrap().remove(0);
    let usable = rule.wan_upstreams[0].upstream_id;
    rule.wan_upstreams.clear();
    assert!(matches!(
        db.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await,
        Err(DbError::Validation(_))
    ));
    rule.upstream_id = usable;
    db.dns_rule_store().checked_upsert_flow_rule(rule).await.unwrap();
}

#[tokio::test]
async fn concurrent_single_upstream_rule_save_and_delete_preserve_reference() {
    let dir = tempfile::tempdir().unwrap();
    let db = LandscapeDBServiceProvider::file_test_db(&dir.path().join("race.db")).await;
    let mut config = fixture();
    let mut rule = config.dns_rules.pop().unwrap();
    rule.wan_upstreams.clear();
    let id = rule.upstream_id;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let rules = db.dns_rule_store();
    let upstreams = db.dns_upstream_config_store();
    let (save, delete) = tokio::join!(
        rules.checked_upsert_flow_rule(rule.clone()),
        upstreams.delete_unreferenced(id)
    );
    assert!(save.is_ok() ^ delete.is_ok());
    if db.dns_rule_store().find_by_id(rule.id).await.unwrap().is_some() {
        assert!(db.dns_upstream_config_store().find_by_id(id).await.unwrap().is_some());
    }
}

fn ip_rule(flow_id: u32, target: u8) -> WanIpRuleConfig {
    WanIpRuleConfig {
        id: Uuid::new_v4(),
        name: Some("游戏出口".into()),
        index: 10,
        enable: true,
        mark: FlowMark::new(FlowMarkAction::Redirect, target, false),
        source: vec![],
        remark: String::new(),
        flow_id,
        override_dns: false,
        update_at: 0.0,
    }
}

#[tokio::test]
async fn dns_and_ip_rule_redirects_require_existing_targets_but_allow_default_flow() {
    let mut config = fixture();
    let mut dns = config.dns_rules.pop().unwrap();
    dns.flow_id = 0;
    dns.wan_upstreams.clear();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    for target in [10, 0, 20] {
        dns.id = Uuid::new_v4();
        dns.mark = FlowMark::new(FlowMarkAction::Redirect, target, false);
        let dns_result = db.dns_rule_store().checked_upsert_flow_rule(dns.clone()).await;
        let ip_result = db.dst_ip_rule_store().checked_upsert_flow_rule(ip_rule(0, target)).await;
        if target == 10 {
            assert!(matches!(
                dns_result,
                Err(DbError::Validation(ServiceConfigError::FlowRedirectTargetMissing {
                    flow_id: 10
                }))
            ));
            assert!(matches!(
                ip_result,
                Err(DbError::Validation(ServiceConfigError::FlowRedirectTargetMissing {
                    flow_id: 10
                }))
            ));
        } else {
            assert!(dns_result.is_ok());
            assert!(ip_result.is_ok());
        }
    }
    // Stale non-redirect IDs never affect routing and remain allowed.
    for action in [FlowMarkAction::Direct, FlowMarkAction::KeepGoing, FlowMarkAction::Drop] {
        dns.id = Uuid::new_v4();
        dns.mark = FlowMark::new(action, 99, false);
        db.dns_rule_store().checked_upsert_flow_rule(dns.clone()).await.unwrap();
    }
}

#[tokio::test]
async fn redirect_references_block_flow_delete_and_renumber_but_own_rules_cascade() {
    let mut config = fixture();
    config.dns_rules[0].mark = FlowMark::new(FlowMarkAction::Redirect, 20, false);
    config.dst_ip_mark.push(ip_rule(20, 20));
    let mut external = config.dns_rules[0].clone();
    external.id = Uuid::new_v4();
    external.flow_id = 0;
    external.name = "默认国内解析".into();
    config.dns_rules.push(external.clone());
    let external_ip = ip_rule(0, 20);
    config.dst_ip_mark.push(external_ip.clone());
    let id = config.flow_rules[0].id;
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config)).await.unwrap();
    let error = db.flow_rule_store().delete_flow_with_rules(id).await.unwrap_err();
    assert!(
        matches!(error,DbError::Validation(ServiceConfigError::FlowReferenced {flow_id:20,references}) if references.contains("默认国内解析") && references.contains("游戏出口"))
    );
    let mut changed = db.flow_rule_store().find_by_id(id).await.unwrap().unwrap();
    changed.flow_id = 21;
    assert!(db.flow_rule_store().checked_upsert(changed).await.is_err());
    db.dns_rule_store().delete_and_get(external.id).await.unwrap();
    assert!(db.flow_rule_store().delete_flow_with_rules(id).await.is_err());
    db.dst_ip_rule_store().delete_and_get(external_ip.id).await.unwrap();
    assert!(db.flow_rule_store().delete_flow_with_rules(id).await.unwrap().is_some());
    assert!(db.dns_rule_store().list().await.unwrap().is_empty());
    assert!(db.dst_ip_rule_store().list().await.unwrap().is_empty());
}

#[test]
fn snapshot_checks_redirects_without_changing_other_mark_actions() {
    let mut config = fixture();
    config.dns_rules[0].mark = FlowMark::new(FlowMarkAction::Redirect, 10, false);
    assert!(matches!(
        validate_network_snapshot(&config),
        Err(ServiceConfigError::FlowRedirectTargetMissing { flow_id: 10 })
    ));
    config.dns_rules[0].mark = FlowMark::new(FlowMarkAction::Direct, 10, false);
    validate_network_snapshot(&config).unwrap();
    config.dst_ip_mark.push(ip_rule(0, 5));
    assert!(matches!(
        validate_network_snapshot(&config),
        Err(ServiceConfigError::FlowRedirectTargetMissing { flow_id: 5 })
    ));
    config.dst_ip_mark[0].mark = FlowMark::new(FlowMarkAction::Redirect, 0, false);
    validate_network_snapshot(&config).unwrap();
    config.dst_ip_mark[0].flow_id = 99;
    assert!(validate_network_snapshot(&config).is_err());
}

#[test]
fn snapshot_checks_ipv6_probe_switches_like_live_failover() {
    let mut config = fixture();
    config.wan_links[0].pd.enable = true;
    assert!(validate_network_snapshot(&config).is_err());
    config.wan_links[0].health_check.ipv6_probe_enabled = false;
    validate_network_snapshot(&config).unwrap();
    config.wan_links[0].health_check.ipv4_probe_enabled = false;
    assert!(validate_network_snapshot(&config).is_err());
}

#[tokio::test]
async fn disabled_mapping_allows_flow_maintenance_and_rechecks_on_enable() {
    let mut config = fixture();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    let mut rule = db.dns_rule_store().list().await.unwrap().remove(0);
    rule.enable = false;
    let mut rule = db.dns_rule_store().checked_upsert_flow_rule(rule).await.unwrap().new;
    let mut flow = db.flow_rule_store().list().await.unwrap().remove(0);
    flow.enable = false;
    let mut flow = db.flow_rule_store().checked_upsert(flow).await.unwrap().new;
    config.dns_rules[0] = rule.clone();
    config.flow_rules[0] = flow.clone();
    LandscapeDBServiceProvider::validate_init_config_can_import(config.clone()).await.unwrap();
    rule.enable = true;
    assert!(matches!(
        db.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await,
        Err(DbError::Validation(ServiceConfigError::WanDnsFlowUnsupported { flow_id: 20 }))
    ));
    // Paused rules still cannot retain references to deleted groups.
    config.dns_upstream_configs.clear();
    assert!(validate_network_snapshot(&config).is_err());
    flow.enable = true;
    db.flow_rule_store().checked_upsert(flow).await.unwrap();
    db.dns_rule_store().checked_upsert_flow_rule(rule).await.unwrap();
}

#[tokio::test]
async fn stopped_flow_allows_health_maintenance_but_reenable_rechecks_active_wans() {
    let mut config = fixture();
    config.dns_rules[0].enable = false;
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    db.truncate_and_fit_from(Some(config.clone())).await.unwrap();
    let mut flow = db.flow_rule_store().list().await.unwrap().remove(0);
    flow.enable = false;
    let mut flow = db.flow_rule_store().checked_upsert(flow).await.unwrap().new;
    let mut wan = db.wan_link_store().find_by_id(config.wan_links[0].id).await.unwrap().unwrap();
    assert!(wan.active());
    wan.health_check.enable = false;
    let mut wan = db.wan_link_store().checked_upsert(wan).await.unwrap().new;
    config.flow_rules[0] = flow.clone();
    config.wan_links[0] = wan.clone();
    LandscapeDBServiceProvider::validate_init_config_can_import(config.clone()).await.unwrap();
    flow.enable = true;
    assert!(matches!(
        db.flow_rule_store().checked_upsert(flow.clone()).await,
        Err(DbError::Validation(_))
    ));
    config.flow_rules[0] = flow.clone();
    assert!(LandscapeDBServiceProvider::validate_init_config_can_import(config).await.is_err());
    wan.health_check.enable = true;
    db.wan_link_store().checked_upsert(wan).await.unwrap();
    db.flow_rule_store().checked_upsert(flow).await.unwrap();
}

#[tokio::test]
async fn link_state_failover_allows_no_probes_but_health_mode_rechecks_them() {
    use landscape_common::flow::FlowFailoverTrigger;
    let mut cfg = fixture();
    cfg.flow_rules[0].failover.trigger = FlowFailoverTrigger::LinkState;
    for wan in &mut cfg.wan_links {
        wan.health_check.enable = false;
    }
    validate_network_snapshot(&cfg).unwrap();
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    provider.truncate_and_fit_from(Some(cfg.clone())).await.unwrap();
    let mut flow =
        provider.flow_rule_store().find_by_id(cfg.flow_rules[0].id).await.unwrap().unwrap();
    provider.flow_rule_store().checked_upsert(flow.clone()).await.unwrap();
    let wan = provider.wan_link_store().find_by_id(cfg.wan_links[0].id).await.unwrap().unwrap();
    provider.wan_link_store().checked_upsert(wan).await.unwrap();
    flow = provider.flow_rule_store().find_by_id(flow.id).await.unwrap().unwrap();
    flow.failover.trigger = FlowFailoverTrigger::HealthCheck;
    assert!(provider.flow_rule_store().checked_upsert(flow).await.is_err());
    cfg.flow_rules[0].failover.trigger = FlowFailoverTrigger::HealthCheck;
    assert!(validate_network_snapshot(&cfg).is_err());
}
