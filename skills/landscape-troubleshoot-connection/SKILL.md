---
name: landscape-troubleshoot-connection
description: |
  Diagnose network connection issues on a Landscape router. Use this skill when the user
  reports problems like "can't access a website", "connection is slow", "traffic blocked",
  "devices can't reach internet", or any network connectivity problem. Triggers on phrases
  like "troubleshoot", "diagnose", "not working", "can't connect", "blocked", "timeout",
  "latency", "packet loss", "connection issue", "网络不通", "连不上".
---

# Landscape Connection Troubleshooting

Diagnose why a device or application cannot reach a destination or why traffic is slow.

**Important: This skill ONLY works through MCP tools. Do NOT call the Landscape REST API
directly. If the MCP server is not configured, or the landscape MCP tools are not available,
tell the user to configure the MCP server (run the `landscape-setup` skill first). Without
MCP configured, this skill is not usable.**

## Prerequisites

Before starting, verify the token exists and is valid:

```bash
cat ~/.agents/skills/landscape-setup/.token 2>/dev/null
```

If the file is missing or the `exp` field has passed, tell the user to run the `landscape-setup` skill first.

## Workflow

Follow these steps in order. The goal is to identify where in the flow→DNS→routing→firewall→NAT chain the traffic is being dropped or delayed.

### Step 1: Identify the source

Ask the user:
- What device/application is having trouble? (IP address, MAC address, or hostname)
- What destination can't be reached? (IP address or domain name)
- What protocol/port? (TCP 443 for HTTPS, etc.)

### Step 2: System overview

Call `landscape_system_info` for basic router health context, then `landscape_service_statuses` to check all services are running.

### Step 3: Trace flow matching

Call `landscape_trace_flow_match` with the source IP or MAC to find which flow applies to this device.

If no flow matches: the device may not be recognized. Check DHCP leases (Step 7). If the `effective_flow_id` is 0, the device falls into the default flow.

### Step 4: Trace routing verdict

With the flow_id from Step 3, call `landscape_trace_flow_verdict` with the destination IPs to see how traffic is routed:
- Check `effective_rule_source`: `Default` means no rule matched, `IpRule` or `DnsRule` means a rule was applied.
- Check `cache_consistent`: `false` indicates stale cache.
- Check `effective_mark`: a drop/reject mark means the traffic is being blocked.

### Step 5: Inspect DNS (if domain involved)

If the destination is a domain name, call `landscape_check_dns` with the flow_id and domain:
- `records`: actual upstream resolution results
- `cache_records`: what's in the local cache
- `rule_filter`: whether a DNS rule is filtering records
- `query_filtered`: `true` means records were filtered by a rule

If `apply_filter=false` was used and records exist but `query_filtered=true` — a DNS rule is blocking. Cross-check with `landscape_list_dns_rules` to find the blocking rule.

### Step 6: Check flow rule configuration

Call `landscape_get_flow_rule` with the flow_id to see the full flow configuration including match rules and targets.

### Step 7: Check firewall and NAT

- Call `landscape_list_firewall_blacklists` — is the destination IP or geo region blacklisted?
- Call `landscape_list_static_nat_mappings` — is there a port forwarding rule affecting this traffic?
- Call `landscape_search_geo_cache` with relevant IPs to check if they fall into blocked geo regions

### Step 8: Check real-time connections

Call `landscape_get_connections` to see current active connections. Filter visually for the source/destination IP.

### Step 9: Check traffic stats

- Call `landscape_get_global_traffic_stats` to check for overall congestion
- Call `landscape_get_interface_stats` to see per-interface throughput

If any interface shows near-line-rate throughput, congestion may be the root cause.

### Step 10: Summarize findings

Present a clear diagnosis:
1. What flow the device is in
2. Whether DNS resolves correctly or is filtered
3. Whether routing/verdict allows or blocks the traffic
4. Whether firewall/NAT rules are interfering
5. Whether overall traffic levels could cause slowdowns
