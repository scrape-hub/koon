use h3_quinn::quinn;

use crate::error::Error;
use crate::{http3, quic};

use super::response::HttpResponse;

impl super::Client {
    /// Try to establish an HTTP/3 connection and send a request.
    pub(super) async fn try_h3_connection(
        &self,
        host: &str,
        h3_port: u16,
        method: http::Method,
        uri: &http::Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
    ) -> Result<HttpResponse, Error> {
        let endpoint = self.get_or_create_quic_endpoint()?;

        let (mut send_request, mut driver) =
            http3::connect(&endpoint, host, h3_port, &self.profile).await?;

        // Spawn the H3 connection driver
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let response = http3::send_request(
            &mut send_request,
            method,
            uri,
            &self.profile,
            &self.custom_headers,
            body,
            cookie_header,
        )
        .await?;

        // Store H3 connection in pool (H3 is only used without proxy)
        self.pool.insert_h3(host, h3_port, None, send_request, None);

        Ok(response)
    }

    /// Get or lazily create the shared QUIC endpoint.
    pub(super) fn get_or_create_quic_endpoint(&self) -> Result<quinn::Endpoint, Error> {
        let mut ep = self.quic_endpoint.lock().unwrap();
        if let Some(endpoint) = ep.as_ref() {
            return Ok(endpoint.clone());
        }
        let quic_config = self
            .profile
            .quic
            .as_ref()
            .ok_or_else(|| Error::Quic("No QuicConfig in profile".into()))?;
        let endpoint = quic::transport::build_endpoint(quic_config)?;
        *ep = Some(endpoint.clone());
        Ok(endpoint)
    }
}
