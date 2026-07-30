import { RouteRecordRaw } from "vue-router";

import IPv6PD from "@/views/status/IPv6PD.vue";
import DHCPv4Server from "@/views/status/DHCPv4Server.vue";
import IPv6RA from "@/views/status/IPv6RA.vue";

const service_status_route: Array<RouteRecordRaw> = [
  {
    path: "/network/ipv6-pd",
    name: "routes.ipv6-pd",
    component: IPv6PD,
  },
  {
    path: "/network/dhcp-v4",
    name: "routes.dhcp-v4",
    component: DHCPv4Server,
  },
  {
    path: "/network/ipv6-ra",
    name: "routes.ipv6-ra",
    component: IPv6RA,
  },
];

export default service_status_route;
