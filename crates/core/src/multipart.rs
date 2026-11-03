use rand::Rng;
use serde::{Deserialize, Serialize};

/// A single part of a `multipart/form-data` body.
#[derive(Debug, Clone)]
pub enum Part {
    /// A text form field with a name and string value.
    Text { name: String, value: String },
    /// A file upload field with filename, MIME type, and binary data.
    File {
        name: String,
        filename: String,
        content_type: String,
        data: Vec<u8>,
    },
}

/// How a browser or client encodes a multipart body: its boundary, and for `OkHttp` the part
/// headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum BoundaryStyle {
    /// Chromium and Safari: `----WebKitFormBoundary` + 16 random characters (Blink
    /// `FormDataEncoder::GenerateUniqueBoundaryString`).
    WebKit,
    /// Firefox: `----geckoformboundary` + two random 64-bit numbers in hex (`FSMultipartFormData`).
    Gecko,
    /// `OkHttp` 4: a random UUID (`MultipartBody.Builder`) and a Content-Length in every part.
    OkHttp4,
    /// `OkHttp` 5: a random UUID, no Content-Length in the parts.
    OkHttp5,
}

impl BoundaryStyle {
    fn generate(self) -> String {
        let mut rng = rand::rng();
        match self {
            Self::WebKit => {
                const MAP: &[u8; 64] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
                let suffix: String = (0..16)
                    .map(|_| MAP[rng.random_range(0..64)] as char)
                    .collect();
                format!("----WebKitFormBoundary{suffix}")
            }
            Self::Gecko => format!(
                "----geckoformboundary{:x}{:x}",
                rng.random::<u64>(),
                rng.random::<u64>()
            ),
            Self::OkHttp4 | Self::OkHttp5 => {
                let mut bytes: [u8; 16] = rng.random();
                bytes[6] = (bytes[6] & 0x0f) | 0x40;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "{}-{}-{}-{}-{}",
                    &hex[..8],
                    &hex[8..12],
                    &hex[12..16],
                    &hex[16..20],
                    &hex[20..]
                )
            }
        }
    }
}

/// Builder for multipart/form-data request bodies.
///
/// The boundary follows the browser: [`Client::post_multipart`] builds the body with the style of
/// the client's profile.
///
/// [`Client::post_multipart`]: crate::Client::post_multipart
///
/// # Example
/// ```
/// use koon_core::multipart::Multipart;
///
/// let (body, content_type) = Multipart::new()
///     .text("field", "value")
///     .file("upload", "test.txt", "text/plain", b"hello".to_vec())
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct Multipart {
    parts: Vec<Part>,
}

impl Multipart {
    /// Create an empty multipart builder.
    #[must_use]
    pub const fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// Add a text field.
    #[must_use]
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(Part::Text {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Add a file upload field.
    #[must_use]
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        self.parts.push(Part::File {
            name: name.into(),
            filename: filename.into(),
            content_type: content_type.into(),
            data,
        });
        self
    }

    /// Add a pre-built part.
    #[must_use]
    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    /// Build the body with a Chromium-style boundary. Returns the body bytes and the Content-Type
    /// header value.
    #[must_use]
    pub fn build(self) -> (Vec<u8>, String) {
        self.build_with(BoundaryStyle::WebKit)
    }

    /// Build the body as the given browser or client encodes it.
    #[must_use]
    pub fn build_with(self, style: BoundaryStyle) -> (Vec<u8>, String) {
        self.build_with_boundary(&style.generate(), style == BoundaryStyle::OkHttp4)
    }

    fn build_with_boundary(self, boundary: &str, part_lengths: bool) -> (Vec<u8>, String) {
        let mut body = Vec::new();
        for part in &self.parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match part {
                Part::Text { name, value } => {
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"\r\n",
                            escape(name)
                        )
                        .as_bytes(),
                    );
                    end_part_headers(&mut body, part_lengths, value.len());
                    body.extend_from_slice(value.as_bytes());
                }
                Part::File {
                    name,
                    filename,
                    content_type,
                    data,
                } => {
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                            escape(name),
                            escape(filename)
                        )
                        .as_bytes(),
                    );
                    let content_type = if content_type.contains(['\r', '\n']) {
                        "application/octet-stream"
                    } else {
                        content_type.as_str()
                    };
                    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
                    end_part_headers(&mut body, part_lengths, data.len());
                    body.extend_from_slice(data);
                }
            }
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (body, format!("multipart/form-data; boundary={boundary}"))
    }
}

fn end_part_headers(body: &mut Vec<u8>, part_lengths: bool, length: usize) {
    if part_lengths {
        body.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    body.extend_from_slice(b"\r\n");
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\n' => escaped.push_str("%0A"),
            '\r' => escaped.push_str("%0D"),
            '"' => escaped.push_str("%22"),
            c => escaped.push(c),
        }
    }
    escaped
}
