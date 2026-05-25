---
name: landscape-dhcp-inspection
description: |
  Inspect DHCP leases, ARP table, and LAN clients on a Landscape router. Use when the user
  asks "who is on my network", "list connected devices", "DHCP clients", "show IP assignments",
  "find a device", "DHCP检查", "局域网设备", "连接设备", or wants to see all LAN clients.
---

# Landscape DHCP and Client Inspection

Inspect DHCPv4 leases, ARP tables, and cross-reference with enrolled devices.

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

### Step 1: Identify LAN interfaces

Call `landscape_list_interfaces`. Look for interfaces with a LAN zone or with DHCP server enabled. Note their names (e.g., `lan0`, `br-lan`).

### Step 2: Get DHCP leases for each LAN interface

For each LAN interface identified, call `landscape_get_dhcp_leases` with the interface name (e.g., `lan0`).

The response contains `offered_ips` — a list of assigned IPs with:
- `ip` — assigned IPv4 address
- `mac` — MAC address
- `hostname` — hostname (if reported by the client)
- `expire_time` — lease remaining time in seconds
- `is_static` — whether this is a static reservation
- `relative_active_time` — how long the lease has been active

### Step 3: Check for issues

Analyze the lease data:

- **Duplicate IPs** — flag if the same IP appears multiple times
- **Nearly-full pool** — if many leases have short expire times, the pool may be small
- **Unknown MACs** — compare against known devices if the user provides a list
- **Expired leases** — `expire_time` near 0 means the lease is about to expire
- **Long-active with no hostname** — may indicate a device that doesn't report its name

### Step 4: Traffic check (if investigating a specific device)

If the user wants to investigate a specific client:
1. Call `landscape_get_connection_history` with `src_ip` set to the client's IP to see recent connections
2. Call `landscape_trace_flow_match` with the client's IP or MAC to find which flow it's in

### Step 5: Report

```
# LAN Client Report
## Interface: lan0
| IP | MAC | Hostname | Expires In | Static | Active For |
|----|-----|----------|-----------|--------|------------|

Total clients: N | Static: N | Dynamic: N

## Interface: lan1
...

## Alerts
- [Any issues found]
```
