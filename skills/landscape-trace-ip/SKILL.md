---
name: landscape-trace-ip
description: |
  Trace how a specific IP address is handled through all layers of the Landscape router:
  flow matching, routing verdict, DNS, firewall, NAT, geo, and connection tracking.
  Use when the user asks "trace this IP", "track traffic from X", "what happens to traffic
  from Y", "trace route for Z", "follow IP", "追踪IP", "IP追踪", or wants a full-stack
  analysis of how a given IP address is processed by the router.
---

# Landscape Full-Stack IP Trace

Trace how traffic from/to a specific IP address is handled through every layer.

**Important: This skill ONLY works through MCP tools. Do NOT call the Landscape REST API
directly. If the MCP server is not configured, or the landscape MCP tools are not available,
tell the user to configure the MCP server (run the `landscape-setup` skill first).**

## Prerequisites

Verify token validity:

```bash
cat ~/.agents/skills/landscape-setup/.token 2>/dev/null
```

If missing or expired, direct the user to `landscape-setup`.

## Workflow

### Step 1: Gather information

Ask the user:
- **Source IP/MAC** — the device to trace
- **Destination IPs/domains** — where the traffic is going (optional, for verdict check)
- **Time range** — recent hours, specific time window (optional)

### Step 2: Flow matching

Call `landscape_trace_flow_match` with the source IP or MAC:
- `flow_id_by_mac` / `flow_id_by_ip` — which flow each identifier maps to
- `effective_flow_id` — the winning flow
- `effective_flow_source` — which identifier (MAC, IPv4, IPv6) determined the match

### Step 3: Flow rule details

Call `landscape_get_flow_rule` with the `effective_flow_id`:
- `flow_match_rules` — what conditions trigger this flow?
- `flow_targets` — what actions does this flow take?
- `enable` — is the flow active?

### Step 4: DNS rules for this flow

Call `landscape_list_dns_rules` and filter by the flow_id from Step 2. Or if the API supports flow-scoped lookups, use that.

This tells you what DNS rules apply to this device — which domains are filtered, which upstream servers are used.

### Step 5: Routing verdict (if destinations provided)

If the user provided destination IPs, call `landscape_trace_flow_verdict`:
- `ip_rule_match` — destination IP rule matched?
- `dns_rule_match` — DNS rule matched?
- `effective_mark` — what action? (forward through WAN, drop, etc.)
- `cache_consistent` — is the eBPF cache stale?

### Step 6: Firewall and NAT

Call `landscape_list_firewall_blacklists` and `landscape_list_static_nat_mappings`:
- Does any blacklist contain or geoblock this source/destination?
- Is there a port forwarding rule for this IP?

### Step 7: Connection history

Call `landscape_get_connection_history` with `src_ip` set to the source IP:
- See all recent connections, destinations, ports, protocols
- Check `total_ingress_bytes` / `total_egress_bytes` for traffic volume
- Check `status` — 0=Active, 1=Closed

### Step 8: Geo check (if destination IPs provided)

Call `landscape_search_geo_cache` with destination IPs to see if they fall into any geo database.

### Step 9: DHCP context

Call `landscape_get_dhcp_leases` for relevant LAN interfaces to see if the source IP is a known DHCP client.

### Step 10: Full-stack summary

```
# Full-Stack IP Trace: <source IP/MAC>
## Identity
- DHCP: Known/Unknown | Hostname: ... | MAC: ...

## Flow
- effective_flow_id: N
- flow_source: MAC/IPv4/IPv6
- flow_enabled: true/false

## DNS Rules (N rules for this flow)
| index | filter | source | enabled |
|-------|--------|--------|---------|

## Routing Verdict (N destinations)
| dst_ip | rule_source | mark | cache_ok |
|--------|------------|------|----------|

## Firewall
- Blacklist matches: Y/N
- NAT mappings: Y/N

## Recent Connections (last N)
| dst_ip | dst_port | proto | bytes_in | bytes_out | status |
|--------|----------|-------|----------|-----------|--------|

## Summary
[Overall traffic pattern and any anomalies]
```
