use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum GatewayHttpUpstreamRules {
    #[sea_orm(iden = "gateway_http_upstream_rules")]
    Table,
    Id,
    Name,
    Enable,
    MatchRule,
    Upstream,
    UpdateAt,
}
