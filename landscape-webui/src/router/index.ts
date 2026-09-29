import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";

import Landscape from "@/views/Landscape.vue";
import MainLayout from "@/views/MainLayout.vue";
import Flow from "@/views/Flow.vue";
import Docker from "@/views/Docker.vue";
import Firewall from "@/views/Firewall.vue";
import GeoDomain from "@/views/GeoDomain.vue";
import GeoIp from "@/views/GeoIp.vue";
import Config from "@/views/Config.vue";
import About from "@/views/About.vue";

import Login from "@/views/Login.vue";
import StaticNatMappingV4 from "@/views/StaticNatMappingV4.vue";
import StaticNatMappingV6 from "@/views/StaticNatMappingV6.vue";
import EnrolledDevice from "@/views/EnrolledDevice.vue";

import DnsRedirect from "@/views/dns/DnsRedirect.vue";
import DnsUpstream from "@/views/dns/DnsUpstream.vue";
import CertAccounts from "@/views/cert/CertAccounts.vue";
import CertOrders from "@/views/cert/CertOrders.vue";
import DdnsJobs from "@/views/domain/DdnsJobs.vue";
import DnsProviderProfiles from "@/views/domain/DnsProviderProfiles.vue";
import Gateway from "@/views/Gateway.vue";
import NotFound from "@/views/error/NotFound.vue";
import Unavailable from "@/views/error/Unavailable.vue";
import { useCapabilityStore } from "@/stores/capability";

import service_status_route from "./service_status";
import metric_route from "./metric";
import self_monitor_route from "./self_monitor";

const inner_zone: Array<RouteRecordRaw> = [
  {
    path: "/",
    name: "routes.dashboard",
    component: Landscape,
  },
  {
    path: "/dns/redirect",
    name: "routes.dns-redirect",
    component: DnsRedirect,
  },
  ...service_status_route,
  {
    path: "/dns/upstream",
    name: "routes.dns-upstream",
    component: DnsUpstream,
  },
  {
    path: "/firewall-nat/nat/v4",
    name: "routes.nat-v4",
    component: StaticNatMappingV4,
  },
  {
    path: "/firewall-nat/nat/v6",
    name: "routes.nat-v6",
    component: StaticNatMappingV6,
  },
  {
    path: "/flow",
    name: "routes.flow",
    component: Flow,
  },
  {
    path: "/docker",
    name: "routes.docker",
    component: Docker,
  },
  {
    path: "/firewall-nat/firewall",
    name: "routes.firewall",
    component: Firewall,
  },
  ...metric_route,
  ...self_monitor_route,
  {
    path: "/geo/domain",
    name: "routes.geo-domain",
    component: GeoDomain,
  },
  {
    path: "/geo/ip",
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
    component: EnrolledDevice,
  },
  {
    path: "/domains/dns-providers",
    name: "routes.dns-provider-profiles",
    component: DnsProviderProfiles,
  },
  {
    path: "/domains/ddns",
    name: "routes.ddns",
    component: DdnsJobs,
  },
  {
    path: "/domains/cert-accounts",
    name: "routes.cert-accounts",
    component: CertAccounts,
  },
  {
    path: "/domains/certs",
    name: "routes.certs",
    component: CertOrders,
  },
  {
    path: "/gateway",
    name: "routes.gateway",
    component: Gateway,
    meta: { capability: "gateway" },
  },
  {
    path: "/about",
    name: "routes.about",
    component: About,
  },
  {
    path: "/unavailable",
    name: "routes.unavailable",
    component: Unavailable,
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
];

const router = createRouter({ history: createWebHistory(), routes });

router.beforeEach(async (to, from) => {
  const capability = to.meta.capability as string | undefined;
  if (!capability) {
    return true;
  }

  const capabilityStore = useCapabilityStore();
  await capabilityStore.LOAD();

  if (capabilityStore.HAS(capability)) {
    return true;
  }

  // Remember where the user came from so the unavailable page can offer a
  // back action. Avoid bouncing back to another unavailable route.
  const fromCapability = from.meta.capability as string | undefined;
  const origin =
    from.path !== "/unavailable" &&
    !(fromCapability && !capabilityStore.HAS(fromCapability))
      ? from.fullPath
      : "/";

  return { path: "/unavailable", state: { redirect: origin } };
});

export default router;
