---
name: landscape-audit-rules
description: |
  Audit all routing, firewall, DNS, and NAT rules on a Landscape router. Use when the user
  asks for "audit rules", "check rules", "review configuration", "inspect firewall",
  "show all rules", "what rules are set up", "审查规则", "检查配置", or wants a
  comprehensive inventory of all configured policies.
---

# Landscape Rules Audit

Comprehensive audit of all configured routing, firewall, blacklist, DNS, NAT, and geo rules.

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

Gather all rule types and produce a consolidated audit report.

### 1. Flow Rules

Call `landscape_list_flow_rules` to get all flow rules.
For each flow, note:
- `flow_id` — which device group this applies to
- `enable` — is it active?
- `flow_match_rules` — what sources match?
- `flow_targets` — where does matched traffic go?

### 2. DNS Rules

Call `landscape_list_dns_rules` to get all DNS rules. Flag:
- Rules with `enable: false` (inactive)
- Rules with `filter: Unfilter` (all records allowed) vs `OnlyIPv4`/`OnlyIPv6` (restrictive)
- Rules with empty `source` (match nothing)
- Any rule that blocks all record types

### 3. DNS Upstreams

Call `landscape_list_dns_upstreams`. Note:
- Total count and modes (plaintext/TLS/HTTPS/QUIC)
- Any upstream with empty `ips` (unconfigured)

### 4. Firewall Blacklists

Call `landscape_list_firewall_blacklists`. For each:
- `enable` status
- `source` — GeoKey or IP-based? Which Geo sources or IP blocks?
- Flag any enabled blacklist with no sources

### 5. Static NAT Mappings

Call `landscape_list_static_nat_mappings`. For each:
- `enable` status
- `wan_iface_name` — which WAN interface?
- `mapping_pair_ports` and `lan_target` — what's being forwarded where?
- `ipv4_l4_protocol` / `ipv6_l4_protocol` — TCP (6) / UDP (17)?

### 6. Geo Sources

Call `landscape_search_geo_cache` with `kind: ip` (no name/key) to list all Geo IP keys.
Call `landscape_search_geo_cache` with `kind: site` to list all Geo Site keys.

### 7. DDNS

Call `landscape_get_ddns_statuses` for runtime DDNS job state.

### Audit Report Format

```
# Landscape Rules Audit
## Flow Rules: N total, N active, N disabled
| flow_id | enabled | match_rule_count | target_count | remark |
|---------|---------|-----------------|--------------|--------|

## DNS Rules: N total, N active, N disabled
| index | enabled | filter | upstream_id | flow_id | sources |
|-------|---------|--------|-------------|---------|---------|

## DNS Upstreams: N total
| mode | ips | port |
|------|-----|------|

## Firewall Blacklists: N total, N active
| enabled | source_type | source_count | remark |
|---------|-------------|-------------|--------|

## Static NAT Mappings: N total, N active
| enabled | wan_iface | ports | lan_target | protocols |
|---------|-----------|-------|------------|-----------|

## Geo Cache
| kind | keys |
|------|------|

## DDNS: N jobs, N OK, N with errors

## Potential Issues
- [List any rules that could cause traffic blockage, conflicts, or excessive chaining]
```
