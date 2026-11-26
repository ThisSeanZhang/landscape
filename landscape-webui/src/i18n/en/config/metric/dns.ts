export default {
  dns_metric_title: "DNS metrics",
  dns_retention_days: "DNS Retention (Days)",
  dns_retention_days_desc:
    "Retention period for DNS query logs and metrics in days",
  dns_1m_retention_days: "DNS 1m Bucket Retention (Days)",
  dns_1m_retention_days_desc:
    "Retention for 1-minute pre-aggregated buckets (status card & dashboard); usually longer than raw logs",
  dns_db_max_mb: "DNS Database Size Cap (MB)",
  dns_db_max_mb_desc:
    "Maximum size of the DNS metrics database (0 = unlimited, min 16MB when non-zero); cleanup starts ahead of the cap to keep write headroom",
};
