pub(crate) mod answer;
pub(crate) mod cache;
pub(crate) mod chain;
pub(crate) mod engine;
pub(crate) mod local;
pub(crate) mod matcher;
pub(crate) mod redirect;
pub(crate) mod rule;

pub use local::LocalDnsAnswerProvider;
