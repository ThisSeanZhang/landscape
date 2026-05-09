use landscape_common::dns::{
    CacheRuntimeConfig, FlowDnsDesiredState, RuntimeDnsRule, RuntimeRedirectRule,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowDnsAppliedState {
    pub dns_rules: Vec<RuntimeDnsRule>,
    pub redirect_rules: Vec<RuntimeRedirectRule>,
    pub cache_runtime: CacheRuntimeConfig,
}

impl FlowDnsAppliedState {
    pub fn from_desired_state(desired_state: &FlowDnsDesiredState) -> Self {
        Self {
            dns_rules: desired_state.dns_rules.clone(),
            redirect_rules: desired_state.redirect_rules.clone(),
            cache_runtime: desired_state.cache_runtime.clone(),
        }
    }

    fn apply_handler_plan(
        &self,
        desired_state: &FlowDnsDesiredState,
        handler_plan: &HandlerRefreshPlan,
    ) -> Self {
        let mut applied = self.clone();
        match handler_plan {
            HandlerRefreshPlan::ReplaceRules { include_redirects } => {
                applied.dns_rules = desired_state.dns_rules.clone();
                if *include_redirects {
                    applied.redirect_rules = desired_state.redirect_rules.clone();
                }
                applied.cache_runtime = desired_state.cache_runtime.clone();
            }
            HandlerRefreshPlan::ReplaceRedirects => {
                applied.redirect_rules = desired_state.redirect_rules.clone();
            }
            HandlerRefreshPlan::ApplyCacheRuntime { .. } => {
                applied.cache_runtime = desired_state.cache_runtime.clone();
            }
        }

        applied
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandlerRefreshPlan {
    ReplaceRedirects,
    ApplyCacheRuntime { rebuild_cache: bool },
    ReplaceRules { include_redirects: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRefreshPlan {
    Noop,
    ApplyHandler(HandlerRefreshPlan),
    RestartListener { handler_plan: Option<HandlerRefreshPlan> },
}

pub struct DnsRefreshPlanner;

impl DnsRefreshPlanner {
    pub fn build(
        previous: Option<&FlowDnsAppliedState>,
        desired_state: &FlowDnsDesiredState,
    ) -> DnsRefreshPlan {
        let Some(previous) = previous else {
            return DnsRefreshPlan::RestartListener {
                handler_plan: Some(HandlerRefreshPlan::ReplaceRules { include_redirects: true }),
            };
        };

        // DoH listen port/path are process-startup settings. Certificate/SNI
        // domain changes hot-reload through the shared resolver, so per-flow
        // refresh planning only reacts to rules, redirects, and cache runtime.
        Self::build_handler_plan(previous, desired_state)
            .map_or(DnsRefreshPlan::Noop, DnsRefreshPlan::ApplyHandler)
    }

    pub fn applied_after_failure(
        previous: Option<&FlowDnsAppliedState>,
        desired_state: &FlowDnsDesiredState,
        plan: &DnsRefreshPlan,
    ) -> Option<FlowDnsAppliedState> {
        match (previous, plan) {
            (None, DnsRefreshPlan::RestartListener { .. }) => None,
            (Some(previous), DnsRefreshPlan::RestartListener { handler_plan: None }) => {
                Some(previous.clone())
            }
            (
                Some(previous),
                DnsRefreshPlan::RestartListener { handler_plan: Some(handler_plan) },
            ) => Some(previous.apply_handler_plan(desired_state, handler_plan)),
            _ => None,
        }
    }

    fn build_handler_plan(
        previous: &FlowDnsAppliedState,
        desired_state: &FlowDnsDesiredState,
    ) -> Option<HandlerRefreshPlan> {
        let dns_rules_changed = previous.dns_rules != desired_state.dns_rules;
        let redirects_changed = previous.redirect_rules != desired_state.redirect_rules;
        let cache_runtime_changed = previous.cache_runtime != desired_state.cache_runtime;

        let cache_rebuild_required = previous.cache_runtime.cache_capacity
            != desired_state.cache_runtime.cache_capacity
            || previous.cache_runtime.cache_ttl != desired_state.cache_runtime.cache_ttl;

        if dns_rules_changed {
            Some(HandlerRefreshPlan::ReplaceRules { include_redirects: redirects_changed })
        } else if redirects_changed {
            Some(HandlerRefreshPlan::ReplaceRedirects)
        } else if cache_runtime_changed {
            Some(HandlerRefreshPlan::ApplyCacheRuntime { rebuild_cache: cache_rebuild_required })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use landscape_common::dns::upstream::DnsUpstreamMode;
    use landscape_common::dns::{
        CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDesiredState, RuntimeDnsRule,
        RuntimeRedirectRule, RuntimeUpstreamTarget,
    };

    use super::{DnsRefreshPlan, DnsRefreshPlanner, FlowDnsAppliedState, HandlerRefreshPlan};

    fn desired_state() -> FlowDnsDesiredState {
        FlowDnsDesiredState {
            flow_id: 1,
            dns_rules: vec![RuntimeDnsRule {
                rule_id: uuid::Uuid::new_v4(),
                order: 10,
                filter: Default::default(),
                upstream: RuntimeUpstreamTarget {
                    mode: DnsUpstreamMode::Plaintext,
                    ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                    port: Some(53),
                    enable_ip_validation: false,
                },
                bind_config: Default::default(),
                mark: Default::default(),
                sources: vec![],
            }],
            redirect_rules: vec![RuntimeRedirectRule {
                redirect_id: Some(uuid::Uuid::new_v4()),
                dynamic_source_id: None,
                order: 0,
                answer_mode: Default::default(),
                match_rules: vec![],
                result_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                ttl_secs: 10,
            }],
            cache_runtime: CacheRuntimeConfig {
                cache_capacity: 16,
                cache_ttl: 30,
                negative_cache_ttl: 5,
            },
            doh_runtime: Some(DohRuntimeConfig {
                listen_port: 443,
                http_endpoint: "/dns-query".into(),
            }),
        }
    }

    #[test]
    fn planner_detects_noop() {
        let desired = desired_state();
        let previous = FlowDnsAppliedState::from_desired_state(&desired);
        assert_eq!(DnsRefreshPlanner::build(Some(&previous), &desired), DnsRefreshPlan::Noop);
    }

    #[test]
    fn planner_detects_redirect_only() {
        let mut desired = desired_state();
        let previous = FlowDnsAppliedState::from_desired_state(&desired);
        desired.redirect_rules[0].ttl_secs = 20;
        assert_eq!(
            DnsRefreshPlanner::build(Some(&previous), &desired),
            DnsRefreshPlan::ApplyHandler(HandlerRefreshPlan::ReplaceRedirects)
        );
    }

    #[test]
    fn planner_detects_negative_ttl_only_change_without_cache_rebuild() {
        let mut desired = desired_state();
        let previous = FlowDnsAppliedState::from_desired_state(&desired);
        desired.cache_runtime.negative_cache_ttl = 99;
        assert_eq!(
            DnsRefreshPlanner::build(Some(&previous), &desired),
            DnsRefreshPlan::ApplyHandler(HandlerRefreshPlan::ApplyCacheRuntime {
                rebuild_cache: false,
            })
        );
    }

    #[test]
    fn planner_ignores_doh_runtime_changes() {
        let mut desired = desired_state();
        let previous = FlowDnsAppliedState::from_desired_state(&desired);
        desired.doh_runtime.as_mut().unwrap().listen_port = 8443;

        assert_eq!(DnsRefreshPlanner::build(Some(&previous), &desired), DnsRefreshPlan::Noop);
    }

    #[test]
    fn planner_keeps_handler_plan_when_doh_runtime_also_changes() {
        let previous_desired = desired_state();
        let previous = FlowDnsAppliedState::from_desired_state(&previous_desired);

        let mut desired = previous_desired.clone();
        desired.redirect_rules[0].ttl_secs = 20;
        desired.doh_runtime.as_mut().unwrap().listen_port = 8443;

        assert_eq!(
            DnsRefreshPlanner::build(Some(&previous), &desired),
            DnsRefreshPlan::ApplyHandler(HandlerRefreshPlan::ReplaceRedirects)
        );
    }
}
