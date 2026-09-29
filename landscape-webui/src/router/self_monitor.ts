import { RouteRecordRaw } from "vue-router";
import MemSelfMonitor from "@/views/self_monitor/MemSelfMonitor.vue";

const self_monitor_route: Array<RouteRecordRaw> = [
  {
    path: "/self-monitor/memory",
    name: "routes.self-monitor-memory",
    component: MemSelfMonitor,
    meta: { capability: "mem_track" },
  },
];

export default self_monitor_route;
