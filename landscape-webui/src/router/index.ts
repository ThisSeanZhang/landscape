import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";

import Landscape from "@/views/Landscape.vue";
import LandscapeV2 from "@/views/LandscapeV2.vue";
import MainLayout from "@/views/MainLayout.vue";
import Flow from "@/views/Flow.vue";
import Docker from "@/views/Docker.vue";
import Topology from "@/views/Topology.vue";
import Firewall from "@/views/Firewall.vue";
import GeoDomain from "@/views/GeoDomain.vue";
import GeoIp from "@/views/GeoIp.vue";
import Config from "@/views/Config.vue";

import Login from "@/views/Login.vue";
import StaticNatMapping from "@/views/StaticNatMapping.vue";
import MacBinding from "@/views/MacBinding.vue";

import DnsRedirect from "@/views/dns/DnsRedirect.vue";
import DnsUpstream from "@/views/dns/DnsUpstream.vue";
import NotFound from "@/views/error/NotFound.vue";

import service_status_route from "./service_status";
import metric_route from "./metric";

const inner_zone: Array<RouteRecordRaw> = [
  {
    path: "/",
    name: "routes.dashboard",
    component: Landscape,
  },
  {
    path: "/dns-redirect",
    name: "routes.dns-redirect",
    component: DnsRedirect,
  },
  ...service_status_route,
  {
    path: "/dns-upstream",
    name: "routes.dns-upstream",
    component: DnsUpstream,
  },
  {
    path: "/nat",
    name: "routes.nat",
    component: StaticNatMapping,
  },
  {
    path: "/flow",
    name: "routes.flow",
    component: Flow,
  },
  {
    path: "/topology",
    name: "routes.topology",
    component: Topology,
  },
  {
    path: "/docker",
    name: "routes.docker",
    component: Docker,
  },
  {
    path: "/firewall",
    name: "routes.firewall",
    component: Firewall,
  },
  ...metric_route,
  {
    path: "/geo-domain",
    name: "routes.geo-domain",
    component: GeoDomain,
  },
  {
    path: "/geo-ip",
    name: "routes.geo-ip",
    component: GeoIp,
  },
  {
    path: "/config",
    name: "routes.config",
    component: Config,
  },
  {
    path: "/mac-binding",
    name: "routes.mac-binding",
    component: MacBinding,
  },
  {
    path: "/:pathMatch(.*)*",
    name: "NotFound",
    component: NotFound,
  },
];

const routes: Array<RouteRecordRaw> = [
  {
    path: "/",
    name: "MainLayout",
    component: MainLayout,
    children: [...inner_zone],
  },
  {
    path: "/login",
    name: "Login",
    component: Login,
  },
  {
    path: "/test",
    name: "LandscapeV2",
    component: LandscapeV2,
  },
];

const router = createRouter({ history: createWebHistory(), routes });

export default router;
