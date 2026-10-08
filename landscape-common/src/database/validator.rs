use crate::service::ServiceConfigError;

/// 纯内容校验(无 IO):`f(config)`。
///
/// 由 `impl_repository!` 在 checked 写路径中最先调用;每个入库 config
/// 必须实现,无检查需求的用 [`impl_trivial_validatable!`] 显式声明。
/// 跨表校验挂在 Repository 的 [`StoreValidator`] 上。
pub trait ValidatableConfig {
    fn validate(&self) -> Result<(), ServiceConfigError>;
}

/// DB 依赖校验(repo 侧):由 `impl_repository!` 在
/// [`ValidatableConfig::validate`] 之后调用。
///
/// 盲写路径(`upsert`/`upsert_many`)不做校验(可信系统路径)。
/// 校验只做 `f(config, DB)`:依赖运行时状态的检查留在服务层;
/// 跨域只经读方法,不触发校验、无递归;DB 读失败映射为
/// [`ServiceConfigError::internal`],不伪装成 422。
/// 校验是存在性保证而非原子性保证:并发写的跨域不变量可能在
/// 双方都过校验后落库。
#[async_trait::async_trait]
pub trait StoreValidator<D> {
    /// zone-aware 域委托 `ZoneChecker`;非 zone 域显式 `Ok(())`。
    async fn check_zone(&self, config: &D) -> Result<(), ServiceConfigError>;

    /// 跨域/跨行冲突检查(读其他表、本表旧行)。
    /// `&mut` 允许根据跨域数据规范化 config,改动会落库;
    /// 此前的 validate / check_zone 看到的是改动前的值。
    async fn validate_cross(&self, config: &mut D) -> Result<(), ServiceConfigError>;
}

/// 显式声明该 config 无纯内容校验需求。
#[macro_export]
macro_rules! impl_trivial_validatable {
    ($data:ty) => {
        impl $crate::database::validator::ValidatableConfig for $data {
            fn validate(&self) -> ::std::result::Result<(), $crate::service::ServiceConfigError> {
                Ok(())
            }
        }
    };
}
