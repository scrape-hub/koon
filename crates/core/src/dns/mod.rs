mod cache;
mod native;
mod resolver;

pub use native::NativeHttpsResolver;
pub use resolver::{DohConfig, DohResolver, HttpsRecord};

/// The lowest-`SvcPriority` record `query_https_records` returns, or `None` if it returned none.
/// Shared by `NativeHttpsResolver::query_https_record` and `DohResolver::query_https_record`, which
/// otherwise differ only in how they fetch records.
pub(crate) async fn first_https_record<F, Fut>(
    query_https_records: F,
) -> Result<Option<HttpsRecord>, crate::Error>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<HttpsRecord>, crate::Error>>,
{
    Ok(query_https_records().await?.into_iter().next())
}
