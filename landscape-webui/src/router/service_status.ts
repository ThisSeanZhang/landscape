import { RouteRecordRaw } from "vue-router";

import IPv6PD from "@/views/status/IPv6PD.vue";
import LanDevices from "@/views/status/LanDevices.vue";
import RouteStatus from "@/views/status/RouteStatus.vue";

const service_status_route: Array<RouteRecordRaw> = [
  {
    path: "/network/routes",
    name: "routes.routes",
    component: RouteStatus,
  },
  {
    path: "/network/ipv6-pd",
    name: "routes.ipv6-pd",
    component: IPv6PD,
  },
  {
    path: "/network/lan-devices",
    name: "routes.lan-devices",
    component: LanDevices,
  },
];

export default service_status_route;
