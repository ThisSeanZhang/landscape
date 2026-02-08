use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum IpMacBinding {
    #[sea_orm(iden = "ip_mac_bindings")]
    Table,
    Id,
    UpdateAt,
    IfaceName,
    Name,
    FakeName,
    Remark,
    Mac,
    Ipv4,
    Ipv4Int,
    Ipv6,
    Tag,
}
