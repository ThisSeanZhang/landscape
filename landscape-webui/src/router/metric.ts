import { RouteRecordRaw } from "vue-router";
import DNSMetricPage from "@/views/metric/DNSMetricPage.vue";
import LiveMetric from "@/views/metric/conn/LiveMetric.vue";
import HistoryMetric from "@/views/metric/conn/HistoryMetric.vue";
import IfaceMetric from "@/views/metric/conn/IfaceMetric.vue";
import LiveIpMetric from "@/views/metric/conn/LiveIpMetric.vue";
import HistoryIpMetric from "@/views/metric/conn/HistoryIpMetric.vue";

const metric_route: Array<RouteRecordRaw> = [
  {
    path: "/metrics/conn/live",
    name: "routes.connect-live",
    component: LiveMetric,
  },
  {
    path: "/metrics/conn/history",
    name: "routes.connect-history",
    component: HistoryMetric,
    meta: { capability: "metric_persistent" },
  },
  {
    path: "/metrics/conn/iface",
    name: "routes.connect-iface",
    component: IfaceMetric,
  },
  {
    path: "/metrics/conn/src",
    name: "routes.connect-src",
    component: LiveIpMetric,
    props: { direction: "src" },
  },
  {
    path: "/metrics/conn/dst",
    name: "routes.connect-dst",
    component: LiveIpMetric,
    props: { direction: "dst" },
  },
  {
    path: "/metrics/conn/history-src",
    name: "routes.connect-history-src",
    component: HistoryIpMetric,
    props: { direction: "src" },
    meta: {
      capability: "metric_persistent",
      activeMenu: "routes.connect-history",
    },
  },
  {
    path: "/metrics/conn/history-dst",
    name: "routes.connect-history-dst",
    component: HistoryIpMetric,
    props: { direction: "dst" },
    meta: {
      capability: "metric_persistent",
      activeMenu: "routes.connect-history",
    },
  },
  {
    path: "/metrics/dns",
    name: "routes.dns-metric",
    component: DNSMetricPage,
  },
];

export default metric_route;
