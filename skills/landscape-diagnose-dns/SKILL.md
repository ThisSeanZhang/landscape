---
name: landscape-diagnose-dns
description: |
  Diagnose DNS resolution and configuration issues on a Landscape router. Use when the user
  reports "DNS not working", "can't resolve domain", "DNS filtering", "DNS slow",
  "domain blocked", "域名解析", "DNS解析", "DNS problem", or wants to inspect DNS rule
  behavior and upstream health.
---

# Landscape DNS Diagnosis

Inspect DNS configuration, rules, upstream servers, DDNS, redirects, and test domain resolution.

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

### Step 1: Check DNS service

Call `landscape_service_statuses` and check `global.dns` is `Running`. If not, DNS resolution is completely down.

### Step 2: List DNS configuration

Call these tools to understand the DNS setup:
1. `landscape_list_dns_rules` — all filtering rules
2. `landscape_list_dns_upstreams` — all upstream DNS servers (plaintext, TLS, HTTPS, QUIC)
3. `landscape_get_ddns_statuses` — DDNS job sync state

### Step 3: Test resolution for specific domains

For each domain the user is having trouble with, call `landscape_check_dns`:

```
landscape_check_dns(flow_id=..., domain="...", record_type="A", apply_filter=false)
landscape_check_dns(flow_id=..., domain="...", record_type="AAAA", apply_filter=false)
```

With `apply_filter=false`, you see the full upstream/cache results alongside rule matching info. This reveals whether:
- The upstream returns records at all (if not: upstream unreachable or domain doesn't exist)
- The cache has stale records
- A DNS rule would filter the records (check `rule_filter` and `query_filtered`)

### Step 4: Cross-reference rules

If `query_filtered` is `true` for a domain:
1. Note the `rule_id` from the check_dns result
2. Cross-reference with `landscape_list_dns_rules` to find the specific rule
3. Check the rule's `filter` setting (Unfilter/OnlyIPv4/OnlyIPv6)
4. Check the rule's `source` — which domains/geo regions it applies to
5. Check `upstream_id` — which DNS server this rule routes through

### Step 5: Check DDNS state

If the issue is with dynamic DNS:
- `landscape_get_ddns_statuses` shows each job's last sync result
- Flag jobs with `status: Error` — check `message` for error details
- Flag jobs with `status: Syncing` for too long
- Flag jobs where `last_update_at` is far in the past

### Step 6: Diagnose and report

Summarize findings in this format:
```
# DNS Diagnosis

## Service: Running/Stopped

## Resolution Test: domain=T, flow_id=X
| Record Type | Upstream Records | Cache Records | Rule Matched | Filtered |
|-------------|-----------------|---------------|--------------|----------|

## Blocking Rule (if filtered):
- Rule index: ..., Name: ..., Filter: ..., Source: ...

## Upstream Health: N servers
| Mode | IPs | Status |
|------|-----|--------|

## DDNS: N jobs
| Name | Status | Last Update | Error |
|------|--------|------------|-------|

## Root Cause: ...
## Recommendation: ...
```
