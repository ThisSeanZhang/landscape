//! Opt-in host routing uses a dedicated table, leaving main-table routes intact.
//! The first rule preserves every non-default main-table route (LAN, VPN, WAN
//! peers). Only unmarked local packets reach the second rule. HostDirect health
//! probes and explicitly marked DNS/Flow sockets retain their own routing.
use landscape_common::sys_service::route_service::{RouteTargetInfo, RouterWanPolicy};
use serde_json::Value;
use tokio::process::Command;

const TABLE: &str = "42700";
const PROTOCOL: &str = "242";
const KEEP_LOCAL: &str = "10426";
const USE_WAN: &str = "10427";

pub(super) async fn command(args: &[String]) -> Result<std::process::Output, String> {
    Command::new("ip").args(args).output().await.map_err(|e| e.to_string())
}
pub(super) async fn apply(args: Vec<String>) -> Result<(), String> {
    let output = command(&args).await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr)))
    }
}
pub(super) fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).into()).collect()
}
pub(super) fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
fn rule_args(family: &str, action: &str, local: bool) -> Vec<String> {
    let mut args = strings(&[
        family,
        "rule",
        action,
        "pref",
        if local { KEEP_LOCAL } else { USE_WAN },
        "iif",
        "lo",
        "fwmark",
        "0x0/0xffffffff",
        "table",
        if local { "main" } else { TABLE },
        "protocol",
        PROTOCOL,
    ]);
    if local {
        args.extend(strings(&["suppress_prefixlength", "0"]));
    }
    args
}
pub(super) fn default_args(family: &str, target: Option<&RouteTargetInfo>) -> Vec<String> {
    let mut args = strings(&[family, "route", "replace", "table", TABLE]);
    if let Some(target) = target {
        args.push("default".into());
        if !target.dev_only_nexthop {
            args.extend(["via".into(), target.gateway_ip.to_string()]);
        }
        args.extend(["dev".into(), target.iface_name.clone()]);
        if !target.dev_only_nexthop {
            args.push("onlink".into());
        }
        args.extend(["src".into(), target.iface_ip.to_string()]);
    } else {
        args.extend(strings(&["blackhole", "default"]));
    }
    args.extend(strings(&["proto", PROTOCOL]));
    args
}
async fn reconcile_family(
    family: &str,
    enabled: bool,
    target: Option<&RouteTargetInfo>,
) -> Result<(), String> {
    let list = command(&strings(&["-j", family, "rule", "show"])).await?;
    if !list.status.success() {
        return Err(String::from_utf8_lossy(&list.stderr).into());
    }
    let rules: Vec<Value> = serde_json::from_slice(&list.stdout).map_err(|e| e.to_string())?;
    let mut present = [false; 2];
    for (index, priority) in [10426, 10427].into_iter().enumerate() {
        for rule in rules.iter().filter(|r| number(&r["priority"]) == Some(priority)) {
            let table_ok = if index == 0 {
                rule["table"] == "main" || number(&rule["table"]) == Some(254)
            } else {
                number(&rule["table"]) == Some(42700)
            };
            if number(&rule["protocol"]) != Some(242) || rule["iif"] != "lo" || !table_ok {
                if !enabled {
                    // Cleanup only removes our tagged rules. Another policy
                    // at the same priority must not strand our remaining rules.
                    continue;
                }
                return Err(format!(
                    "routing rule priority {priority} is already owned by another policy"
                ));
            }
            present[index] = true;
        }
    }
    if !enabled {
        // Remove the WAN lookup first, returning immediately to existing routing.
        if present[1] {
            apply(rule_args(family, "del", false)).await?;
        }
        if present[0] {
            apply(rule_args(family, "del", true)).await?;
        }
        // Rules may have been removed independently (for example by an
        // administrator). Their absence does not prove the owned routes are
        // gone. Always clean our protocol, preserving other users of the table.
        let flushed =
            command(&strings(&[family, "route", "flush", "table", TABLE, "proto", PROTOCOL]))
                .await?;
        if !flushed.status.success()
            && !String::from_utf8_lossy(&flushed.stderr).contains("FIB table does not exist")
        {
            return Err(String::from_utf8_lossy(&flushed.stderr).into());
        }
        return Ok(());
    }
    let list = command(&strings(&["-j", family, "route", "show", "table", TABLE])).await?;
    if list.status.success() {
        let routes: Vec<Value> = serde_json::from_slice(&list.stdout).map_err(|e| e.to_string())?;
        if routes.iter().any(|r| number(&r["protocol"]) != Some(242)) {
            return Err(format!("routing table {TABLE} contains routes owned by another policy"));
        }
    } else if !String::from_utf8_lossy(&list.stderr).contains("FIB table does not exist") {
        return Err(String::from_utf8_lossy(&list.stderr).into());
    }
    // Replace the default before publishing the lookup rule. An enabled policy
    // with no usable WAN is fail-closed, rather than falling through to main.
    apply(default_args(family, target)).await?;
    if !present[0] {
        apply(rule_args(family, "add", true)).await?;
    }
    if !present[1] {
        apply(rule_args(family, "add", false)).await?;
    }
    Ok(())
}

pub async fn sync_router_wan_policy(policy: Option<&RouterWanPolicy>) -> Result<(), String> {
    let mut errors = Vec::new();
    for (family, target) in
        [("-4", policy.and_then(|p| p.ipv4.as_ref())), ("-6", policy.and_then(|p| p.ipv6.as_ref()))]
    {
        if let Err(error) = reconcile_family(family, policy.is_some(), target).await {
            tracing::error!(family, %error, "failed to reconcile router WAN binding");
            errors.push(format!("{family}: {error}"));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}
