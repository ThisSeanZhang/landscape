use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum DHCPv6ClientConfigs {
    #[sea_orm(iden = "dhcp_v6_client_configs")]
    Table,
    IfaceName,
    Enable,
    Mac,
    ExpectedPdLen,
    UpdateAt,
}
