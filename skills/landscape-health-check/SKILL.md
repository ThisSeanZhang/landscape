---
name: landscape-health-check
description: |
  Perform a comprehensive health check of a Landscape router. Use when the user asks for
  "health check", "status check", "router health", "system check", "is everything ok",
  "performance check", "monitor router", "运行状态", "巡检", "健康检查", or wants a quick
  overview of router operational state.
---

# Landscape Router Health Check

Get a comprehensive view of router health: hardware, services, interfaces, traffic, and Docker.

**Important: This skill ONLY works through MCP tools. Do NOT call the Landscape REST API
directly. If the MCP server is not configured, or the landscape MCP tools are not available,
tell the user to configure the MCP server (run the `landscape-setup` skill first).**

## Prerequisites

Verify token validity before starting:

```bash
cat ~/.agents/skills/landscape-setup/.token 2>/dev/null
```

If missing or expired, tell the user to run `landscape-setup` first.

## Workflow

Call these tools and aggregate results into a health report.

### 1. System Health

Call `landscape_system_info`:
- Check `host_name`, `kernel_version`, `landscape_version`
- Note `start_at` — long uptime is healthy, recent restart may indicate an issue

### 2. Service Health

Call `landscape_service_statuses`:
- Check `global.dns`, `global.metric`, `global.docker` are `Running`
- Check each `per_interface` service — flag any in `Error` or `Stopped` state
- Pay special attention to `dhcp_v4`, `firewall`, `nat`, `pppoe`, `wifi` for the relevant interfaces

### 3. Interface Health

Call `landscape_list_interfaces`:
- Check all expected interfaces are present
- Flag any interface with missing IP or `status: Down`
- Verify WAN interfaces have valid configs

### 4. Traffic Overview

Call `landscape_get_global_traffic_stats` for total throughput.
Call `landscape_get_interface_stats` for per-interface breakdown:
- Flag any interface with unusually high ingress/egress
- Flag any interface with zero active connections when it should have traffic

### 5. DNS Health

Call `landscape_list_dns_upstreams` to verify DNS servers are configured.
Call `landscape_get_ddns_statuses` to check DDNS sync state:
- Flag any DDNS job in `Error` state
- Note jobs with long `last_update_at` gaps

### 6. Docker Health

Call `landscape_list_docker_containers`:
- Flag any container not in `running` state that should be
- Check `status` for overall Docker engine health

### 7. Certificate Health

Call `landscape_list_certificates`:
- Flag any certificate with status `Expired`, `Revoked`, `Invalid`
- Note any certificate expiring within 30 days (`expires_at` within 2592000 seconds of now)

### 8. Active Connections

Call `landscape_get_connections` to see current active connections.

### Report Format

Present findings in this structure:

```
# Landscape Router Health Report
## System
- Hostname: ... | Kernel: ... | Version: ... | Uptime: ...

## Services (flagged)
- [ERROR/OK] ServiceName: iface — status

## Interfaces (summary)
- Total interfaces: N | WAN: N | LAN: N | Down: N

## Traffic
- Total ingress: ... | egress: ...
- Top interface: ...

## DNS
- Upstreams: N configured
- DDNS: N jobs, N OK, N with errors

## Docker
- Status: Running/Stopped
- Containers: N total, N running, N stopped

## Certificates
- N total, N valid, N expiring within 30 days, N expired

## Active Connections
- N active connections
```
