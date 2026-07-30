import { RouteRecordRaw } from "vue-router";
import DNSMetric from "@/views/metric/DNSMetric.vue";
import LiveMetric from "@/views/metric/conn/LiveMetric.vue";
import HistoryMetric from "@/views/metric/conn/HistoryMetric.vue";
import IfaceMetric from "@/views/metric/conn/IfaceMetric.vue";
import SrcIpMetric from "@/views/metric/conn/SrcIpMetric.vue";
import DstIpMetric from "@/views/metric/conn/DstIpMetric.vue";
import HistorySrcIpMetric from "@/views/metric/conn/HistorySrcIpMetric.vue";
import HistoryDstIpMetric from "@/views/metric/conn/HistoryDstIpMetric.vue";

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
  },
  {
    path: "/metrics/conn/iface",
    name: "routes.connect-iface",
    component: IfaceMetric,
  },
  {
    path: "/metrics/conn/src",
    name: "routes.connect-src",
    component: SrcIpMetric,
  },
  {
    path: "/metrics/conn/dst",
    name: "routes.connect-dst",
    component: DstIpMetric,
  },
  {
    path: "/metrics/conn/history-src",
    name: "routes.connect-history-src",
    component: HistorySrcIpMetric,
  },
  {
    path: "/metrics/conn/history-dst",
    name: "routes.connect-history-dst",
    component: HistoryDstIpMetric,
  },
  {
    path: "/metrics/dns",
    name: "routes.dns-metric",
    component: DNSMetric,
  },
];

export default metric_route;
