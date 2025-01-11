# Landscape - Linux Router Configuration Tool

**Landscape** is a tool with a web-based UI that allows you to configure your favorite `Linux distribution` as a `router` easily.

> Built with Rust / eBPF / AF_PACKET.


[中文 README](README.zh.md)

## Screenshot

![](docs/images/1.png)

---

## Startup and Limitations

### System Requirements
- Supported Linux kernel version: `6.1` or higher.
- `iptables (require for mss clamping)`, `docker`

### Startup Steps
1. Create the configuration folder:
   ```shell
   mkdir -p ~/.landscape-router
   ```
2. Place the `geosite.dat` file into the above folder.

3. Start the service:
   After compiling, run the following command to start the service (default port: `6300`):
   ```shell
   ./landscape-webserver
   ```

---

## Compilation

### Dependencies Installation
Ensure the following dependencies are installed:
```shell
apt install pkg-config bpftool build-essential clang libelf1 libelf-dev zlib1g-dev
```

### Compilation Steps
Make sure `node`, `yarn`, and `rust` are installed, then run the following command to compile:
```shell
./build.sh
```

The compiled output will be located in the `output` folder.
For cross-compilation on an x86 host to target `aarch64`, refer to [Cross Compilation for aarch64](./docs/CROSS_COMPILATION.md).

---

## Features

| Feature Module  | Status | Description |
|-----------------|--------|-------------|
| **IP Configuration** |        |             |
| PPPoE           | ✅     | Supports multiple connections using the PPPD client |
| PPPoE           | ❌     | eBPF-based data packet handling cannot solve GSO/GRO issues |
| DHCP Client     | ✅     | Supports IP requests and IP configuration |
| DHCP Client     | ❌     | Specify DHCP options |
| DHCP Server     | ✅     | Provides simple IP address allocation and renewal  (default subnet: `192.168.5.1/24`) |
| DHCP Server     | ❌     | Custom configuration |
| **Marking Module** |      |             |
| Traffic Forwarding | ✅  | Forwards DNS-marked traffic to specific Docker containers |
| Traffic Statistics | ❌  | Logs and analyzes specific traffic |
| **DNS Configuration** |    |             |
| Upstream DNS    | ✅     | Resolves specific URLs using designated upstream DNS |
| GeoSite Support | ✅     | Uses `geosite.dat` to mark relevant traffic and avoid incorrect connections |
| GeoSite Updates | ❌     | Periodic updates to `geosite.dat` file; downloads if absent |
| **NAT Features** |       |             |
| Basic NAT       | ✅     | Implements basic NAT functionality using eBPF |
| Symmetric NAT   | ❌     | Restricts certain IPs or websites from NAT traversal with DNS and marking module |
| **Docker Support** |     |             |
| Container Management | ✅ | Supports simple Docker container management |
| Traffic Redirection | ✅ | Redirects traffic to tproxy programs running in Docker |
| **Wi-Fi**        |        |             |
| Create AP        | ❌     | Creates a Wi-Fi hotspot |
| Connect to AP    | ❌     | Connects to a Wi-Fi hotspot |
| **Miscellaneous** |      |             |
| Login UI        | ❌     | Adds login logic and interface |
| Log Standardization | ❌ | Improves logging standardization |
| English UI      | ❌     | Adds English version of the frontend page |
| NIC XPS/RSP Optimization | ❌ | Balances NIC load across CPU cores to improve throughput |

---

## Help Wanted 😥

1. **PPPoE MTU Issues**
   - Observed packets exceeding MTU size, likely caused by `GRO` or `GSO`. Disabling the feature increases NIC load. Currently, using `pppd` avoids the issue.
   - Relevant code reference: [PPPoE egress implementation](https://github.com/ThisSeanZhang/landscape/blob/424b842c29c469e4ad14503ee2bf9190ee24fd11/landscape/landscape-ebpf/src/bpf/pppoe.bpf.c#L68-L74)

2. **Code Structure Issues**
   - The code structure is currently unorganized, requiring better modularization.

---

## LICENSE

- `landscape-ebpf`: [GNU General Public License v2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
- Other parts: [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

For any suggestions or questions, feel free to submit feedback via [issues](./issues/new).
