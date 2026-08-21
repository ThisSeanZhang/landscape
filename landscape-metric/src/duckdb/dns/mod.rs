use landscape_common::metric::dns::{DnsHistoryQueryParams, DnsSummaryQueryParams};

pub(crate) mod history;
pub(crate) mod schema;
pub(crate) mod summary;

pub(crate) fn normalize_domain(domain: &mut String) {
    if domain.ends_with('.') && domain.len() > 1 {
        domain.pop();
    }
}

pub(crate) struct DnsWhereBuilder {
    clauses: Vec<String>,
    params: Vec<Box<dyn duckdb::ToSql>>,
}

impl DnsWhereBuilder {
    pub(crate) fn new() -> Self {
        Self { clauses: Vec::new(), params: Vec::new() }
    }

    pub(crate) fn push_param<T>(&mut self, clause: &str, value: T)
    where
        T: duckdb::ToSql + 'static,
    {
        self.clauses.push(clause.to_string());
        self.params.push(Box::new(value));
    }

    pub(crate) fn from_summary_params(params: &DnsSummaryQueryParams) -> Self {
        let mut builder = Self::new();
        builder.push_param("report_time >= ?", params.start_time as i64);
        builder.push_param("report_time <= ?", params.end_time as i64);
        if let Some(flow_id) = params.flow_id {
            builder.push_param("flow_id = ?", flow_id as i64);
        }
        builder
    }

    pub(crate) fn from_history_params(params: &DnsHistoryQueryParams) -> Self {
        let mut builder = Self::new();
        if let Some(start) = params.start_time {
            builder.push_param("report_time >= ?", start as i64);
        }
        if let Some(end) = params.end_time {
            builder.push_param("report_time <= ?", end as i64);
        }
        if let Some(flow_id) = params.flow_id {
            builder.push_param("flow_id = ?", flow_id as i64);
        }
        if let Some(mut domain) = params.domain.clone().filter(|domain| !domain.is_empty()) {
            normalize_domain(&mut domain);
            builder.push_param("domain LIKE ?", format!("%{}%", domain));
        }
        if let Some(src_ip) = params.src_ip.as_ref().filter(|src_ip| !src_ip.is_empty()) {
            builder.push_param("src_ip LIKE ?", format!("%{}%", src_ip));
        }
        if let Some(query_type) =
            params.query_type.as_ref().filter(|query_type| !query_type.is_empty())
        {
            builder.push_param("query_type = ?", query_type.clone());
        }
        if let Some(status) = params.status {
            builder.push_param("status = ?", serde_json::to_string(&status).unwrap_or_default());
        }
        if let Some(min_duration_ms) = params.min_duration_ms {
            builder.push_param("duration_ms >= ?", min_duration_ms as i64);
        }
        if let Some(max_duration_ms) = params.max_duration_ms {
            builder.push_param("duration_ms <= ?", max_duration_ms as i64);
        }
        builder
    }

    pub(crate) fn where_stmt(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.clauses.join(" AND "))
        }
    }

    pub(crate) fn where_stmt_with_extra(&self, extra_clause: &str) -> String {
        if self.clauses.is_empty() {
            format!("WHERE {}", extra_clause)
        } else {
            format!("WHERE {} AND {}", self.clauses.join(" AND "), extra_clause)
        }
    }

    pub(crate) fn param_refs(&self) -> Vec<&dyn duckdb::ToSql> {
        self.params.iter().map(|param| param.as_ref()).collect()
    }
}
