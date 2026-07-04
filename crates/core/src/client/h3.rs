use h3_quinn::quinn;

use crate::error::Error;
use crate::{http3, quic};

use super::response::HttpResponse;

impl super::Client {
    /// Try to establish an HTTP/3 connection and send a request.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn try_h3_connection(
        &self,
        host: &str,
        port: u16,
        h3_port: u16,
        method: http::Method,
        uri: &http::Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        custom_headers: &[(String, String)],
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
            custom_headers,
            body,
            cookie_header,
            self.timeout,
        )
        .await?;

        // Store the H3 connection under the ORIGIN port, not the advertised
        // Alt-Svc h3_port — that's the key `execute_single_request` looks up,
        // so keying on h3_port (when it differs from 443) would prevent reuse.
        self.pool.insert_h3(host, port, None, send_request, None);

        Ok(response)
    }

    /// Get or lazily create the shared QUIC endpoint.
    pub(super) fn get_or_create_quic_endpoint(&self) -> Result<quinn::Endpoint, Error> {
        let mut ep = crate::util::lock_recover(&self.quic_endpoint);
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
