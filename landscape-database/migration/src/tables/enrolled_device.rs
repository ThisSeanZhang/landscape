use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum EnrolledDevice {
    #[sea_orm(iden = "enrolled_devices")]
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
