use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// HTTP response with body.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub version: String,
    pub url: String,
}

/// Exported session data (cookies + TLS sessions) for save/load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_sessions: Option<HashMap<String, String>>,
}

impl super::Client {
    /// Decompress an HTTP/3 response body.
    pub(super) fn decompress_response(&self, response: HttpResponse) -> Result<HttpResponse, Error> {
        let content_encoding = response
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(response.body, content_encoding)?;
        Ok(HttpResponse {
            body,
            ..response
        })
    }
}

/// Decompress response body based on Content-Encoding header.
pub(super) fn decompress_body(data: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>, Error> {
    match encoding {
        Some("gzip") => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("deflate") => {
            // HTTP "deflate" is zlib-wrapped (RFC 1950), but some servers send raw deflate.
            // Try zlib first, fall back to raw deflate.
            use std::io::Read;
            let mut decoder = flate2::read::ZlibDecoder::new(&data[..]);
            let mut out = Vec::new();
            match decoder.read_to_end(&mut out) {
                Ok(_) => Ok(out),
                Err(_) => {
                    let mut decoder = flate2::read::DeflateDecoder::new(&data[..]);
                    let mut out = Vec::new();
                    decoder.read_to_end(&mut out).map_err(Error::Io)?;
                    Ok(out)
                }
            }
        }
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(&data), &mut out)
                .map_err(Error::Io)?;
            Ok(out)
        }
        Some("zstd") => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(&data[..]).map_err(Error::Io)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        _ => Ok(data),
    }
}
