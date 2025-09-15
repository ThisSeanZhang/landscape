import { RouteRecordRaw } from "vue-router";

import IPv6PD from "@/views/status/IPv6PD.vue";
import DHCPv4Server from "@/views/status/DHCPv4Server.vue";

const service_status_route: Array<RouteRecordRaw> = [
  {
    path: "/ipv6-pd",
    name: "ipv6-pd",
    component: IPv6PD,
  },
  {
    path: "/dhcp-v4",
    name: "dhcp-v4",
    component: DHCPv4Server,
  },
];

export default service_status_route;
