export const dnsLatencyStats = [
  {
    field: "avg_duration_ms",
    label: "metric.dns.dash.avg",
    color: "successColor",
  },
  {
    field: "p50_duration_ms",
    label: "metric.dns.dash.p50",
    color: "infoColor",
  },
  {
    field: "p95_duration_ms",
    label: "metric.dns.dash.p95",
    color: "warningColor",
  },
  {
    field: "p99_duration_ms",
    label: "metric.dns.dash.p99",
    color: "errorColor",
  },
  {
    field: "max_duration_ms",
    label: "metric.dns.dash.max",
    color: "primaryColor",
  },
] as const;
