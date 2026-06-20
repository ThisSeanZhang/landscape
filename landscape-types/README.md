# @landscape-router/types

TypeScript API client and type definitions for [Landscape Router REST API](https://github.com/ThisSeanZhang/landscape), auto-generated from OpenAPI spec via [orval](https://orval.dev/).

> **Generated code** — `openapi.json` and `src/api/` are auto-generated and gitignored. To regenerate locally, run `./gen_ts_bindings.sh` from the repository root.

## Install

```bash
npm install @landscape-router/types
# or
pnpm add @landscape-router/types
```

Requires `axios` as a peer dependency:

```bash
npm install axios
```

## Usage

### 1. Configure axios instance

Before calling any API function, you must set up the axios instance:

```ts
import axios from "axios";
import { setAxiosInstance } from "@landscape-router/types/mutator";

const instance = axios.create({
  baseURL: "https://your-landscape-router:6443",
  timeout: 30000,
});

setAxiosInstance(instance);
```

### 2. Call API functions

```ts
import { getFlowRules } from "@landscape-router/types/api/flow-rules/flow-rules";
import { getDnsRule } from "@landscape-router/types/api/dns-rules/dns-rules";

// Fetch all flow rules
const flows = await getFlowRules();

// Fetch a specific DNS rule
const rule = await getDnsRule("my-rule-id");
```

### 3. Use type definitions

```ts
import type { FlowConfig, DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
```

## Available API Modules

| Module | Import Path |
|--------|-------------|
| Auth | `@landscape-router/types/api/auth/auth` |
| Certificate Accounts | `@landscape-router/types/api/certificate-accounts/certificate-accounts` |
| Certificates | `@landscape-router/types/api/certificates/certificates` |
| Client | `@landscape-router/types/api/client/client` |
| DDNS | `@landscape-router/types/api/ddns/ddns` |
| Destination IP Rules | `@landscape-router/types/api/destination-ip-rules/destination-ip-rules` |
| DHCPv4 | `@landscape-router/types/api/dhcpv4/dhcpv4` |
| DNS Provider Profiles | `@landscape-router/types/api/dns-provider-profiles/dns-provider-profiles` |
| DNS Redirects | `@landscape-router/types/api/dns-redirects/dns-redirects` |
| DNS Rules | `@landscape-router/types/api/dns-rules/dns-rules` |
| DNS Service | `@landscape-router/types/api/dns-service/dns-service` |
| DNS Upstreams | `@landscape-router/types/api/dns-upstreams/dns-upstreams` |
| Docker | `@landscape-router/types/api/docker/docker` |
| Docker Images | `@landscape-router/types/api/docker-images/docker-images` |
| Docker Networks | `@landscape-router/types/api/docker-networks/docker-networks` |
| Enrolled Devices | `@landscape-router/types/api/enrolled-devices/enrolled-devices` |
| Firewall Blacklists | `@landscape-router/types/api/firewall-blacklists/firewall-blacklists` |
| Firewall Service | `@landscape-router/types/api/firewall-service/firewall-service` |
| Flow Rules | `@landscape-router/types/api/flow-rules/flow-rules` |
| Gateway | `@landscape-router/types/api/gateway/gateway` |
| Geo IPs | `@landscape-router/types/api/geo-ips/geo-ips` |
| Geo Sites | `@landscape-router/types/api/geo-sites/geo-sites` |
| Interfaces | `@landscape-router/types/api/interfaces/interfaces` |
| IP Config | `@landscape-router/types/api/ip-config/ip-config` |
| IPv6 PD | `@landscape-router/types/api/ipv6-pd/ipv6-pd` |
| LAN IPv6 | `@landscape-router/types/api/lan-ipv6/lan-ipv6` |
| Metric | `@landscape-router/types/api/metric/metric` |
| MSS Clamp | `@landscape-router/types/api/mss-clamp/mss-clamp` |
| NAT Service | `@landscape-router/types/api/nat-service/nat-service` |
| PPPoE | `@landscape-router/types/api/pppo-e/pppo-e` |
| Route | `@landscape-router/types/api/route/route` |
| Route LAN | `@landscape-router/types/api/route-lan/route-lan` |
| Route WAN | `@landscape-router/types/api/route-wan/route-wan` |
| Static NAT Mappings | `@landscape-router/types/api/static-nat-mappings/static-nat-mappings` |
| System Config | `@landscape-router/types/api/system-config/system-config` |
| System Info | `@landscape-router/types/api/system-info/system-info` |
| Wi-Fi | `@landscape-router/types/api/wi-fi/wi-fi` |
| Schemas (types only) | `@landscape-router/types/api/schemas` |

## License

[MIT](https://github.com/ThisSeanZhang/landscape/blob/main/LICENSE)
