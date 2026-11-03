mod cache;
mod native;
mod resolver;

pub use native::NativeHttpsResolver;
pub use resolver::{DohConfig, DohResolver, HttpsRecord};

pub(crate) async fn first_https_record<F, Fut>(
    query_https_records: F,
) -> Result<Option<HttpsRecord>, crate::Error>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<HttpsRecord>, crate::Error>>,
{
    Ok(query_https_records().await?.into_iter().next())
}
