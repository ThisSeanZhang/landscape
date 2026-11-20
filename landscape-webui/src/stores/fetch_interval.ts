import { defineStore } from "pinia";
import { usePolling } from "./usePolling";

import { useSysInfo } from "./systeminfo";
import { useIfaceNodeStore } from "./iface_node";
import { useWanLinkStore } from "./wan_link";
import { useDockerStore } from "./status_docker";
import { useLanIPv6Store } from "./status_lan_ipv6";
import { useLanDeviceStore } from "./lan_device";
import { useWifiConfigStore } from "./status_wifi";
import { useDHCPv4ConfigStore } from "./status_dhcp_v4";
import { useTopologyMetricsStore } from "./topologyMetrics";
import { useRouteLanConfigStore } from "./status_route_lan";
import { useRouteWanConfigStore } from "./status_route_wan";

import useDockerImgTask from "@/stores/docker_img_task";

export const useFetchIntervalStore = defineStore("fetch_interval", () => {
  const sysinfo = useSysInfo();
  const ifaceNodeStore = useIfaceNodeStore();
  const wanLinkStore = useWanLinkStore();
  const dockerStore = useDockerStore();
  const lanIpv6Store = useLanIPv6Store();
  const lanDeviceStore = useLanDeviceStore();
  const wifiConfigStore = useWifiConfigStore();
  const dhcpv4ConfigStore = useDHCPv4ConfigStore();
  const topologyMetrics = useTopologyMetricsStore();
  const routeLanConfigStore = useRouteLanConfigStore();
  const routeWanConfigStore = useRouteWanConfigStore();

  const dockerImgTask = useDockerImgTask();
  const services = [
    sysinfo,
    dockerStore,
    ifaceNodeStore,
    wanLinkStore,
    lanIpv6Store,
    lanDeviceStore,
    wifiConfigStore,
    dhcpv4ConfigStore,
    topologyMetrics,
    routeLanConfigStore,
    routeWanConfigStore,
  ];

  return usePolling(async (isCurrent) => {
    for (const service of services) {
      if (!isCurrent()) return;
      await service.UPDATE_INFO();
    }
    if (isCurrent()) dockerImgTask.CONNECT();
  });
});
