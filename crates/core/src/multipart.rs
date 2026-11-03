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
                // Blink's table: A-Z, a-z, 0-9, then A and B again.
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
                    // A content type with CR/LF would inject part headers.
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

/// Escape a field name or filename like browsers do (HTML Standard, multipart/form-data encoding):
/// LF, CR and `"` become %0A, %0D and %22.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary_of(content_type: &str) -> &str {
        content_type.split("boundary=").nth(1).unwrap()
    }

    #[test]
    fn test_escape() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a\nb\rc\"d"), "a%0Ab%0Dc%22d");
        assert_eq!(escape("\n\r\"\r\n"), "%0A%0D%22%0D%0A");
        // A literal percent-escape in the input is not itself special and passes through unchanged
        // (no re-processing of the output).
        assert_eq!(escape("%0A"), "%0A");
        // Multi-byte characters pass through untouched.
        assert_eq!(escape("café\n"), "café%0A");
    }

    #[test]
    fn test_webkit_boundary() {
        let (_, ct) = Multipart::new()
            .text("a", "b")
            .build_with(BoundaryStyle::WebKit);
        let boundary = boundary_of(&ct);
        let suffix = boundary.strip_prefix("----WebKitFormBoundary").unwrap();
        assert_eq!(suffix.len(), 16);
        assert!(suffix.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_gecko_boundary() {
        let (_, ct) = Multipart::new()
            .text("a", "b")
            .build_with(BoundaryStyle::Gecko);
        let suffix = boundary_of(&ct)
            .strip_prefix("----geckoformboundary")
            .unwrap();
        assert!(!suffix.is_empty() && suffix.len() <= 32);
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn okhttp_boundary_is_a_uuid() {
        for style in [BoundaryStyle::OkHttp4, BoundaryStyle::OkHttp5] {
            let (_, ct) = Multipart::new().text("a", "b").build_with(style);
            let boundary = boundary_of(&ct);
            let groups: Vec<usize> = boundary.split('-').map(str::len).collect();
            assert_eq!(groups, [8, 4, 4, 4, 12], "{boundary}");
            assert_eq!(&boundary[14..15], "4");
            assert!(matches!(&boundary[19..20], "8" | "9" | "a" | "b"));
            assert!(
                boundary
                    .bytes()
                    .all(|b| b == b'-' || (b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
            );
        }
    }

    /// `MultipartBody.writeOrCountBytes` of `OkHttp` 4.12.0 and 5.5.0.
    #[test]
    fn okhttp_part_headers() {
        let form = || {
            Multipart::new().text("field", "value").file(
                "upload",
                "a.txt",
                "text/plain",
                b"hello".to_vec(),
            )
        };
        let (body, ct) = form().build_with_boundary("b", true);
        assert_eq!(ct, "multipart/form-data; boundary=b");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--b\r\nContent-Disposition: form-data; name=\"field\"\r\nContent-Length: 5\r\n\r\n\
             value\r\n--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello\r\n--b--\r\n"
        );
        let (body, _) = form().build_with_boundary("b", false);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--b\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--b\r\n\
             Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\n\r\nhello\r\n--b--\r\n"
        );
    }

    #[test]
    fn test_text_field_encoding() {
        let (body, _ct) = Multipart::new().text("field1", "value1").build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(
            body_str.contains("Content-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n")
        );
        assert!(body_str.ends_with("--\r\n"));
    }

    #[test]
    fn test_file_field_encoding() {
        let (body, _ct) = Multipart::new()
            .file("upload", "test.txt", "text/plain", b"hello world".to_vec())
            .build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("name=\"upload\"; filename=\"test.txt\""));
        assert!(body_str.contains("Content-Type: text/plain\r\n\r\nhello world\r\n"));
    }

    #[test]
    fn test_names_are_escaped() {
        let (body, _) = Multipart::new()
            .file(
                "up\"load",
                "evil\r\nX-Injected: 1\".txt",
                "text/plain\r\nX: y",
                b"x".to_vec(),
            )
            .build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(
            body_str.contains("name=\"up%22load\"; filename=\"evil%0D%0AX-Injected: 1%22.txt\"")
        );
        assert!(body_str.contains("Content-Type: application/octet-stream\r\n"));
        assert!(!body_str.contains("\r\nX-Injected"));
    }

    #[test]
    fn test_closing_boundary() {
        let (body, ct) = Multipart::new().text("x", "y").build();
        let boundary = boundary_of(&ct).to_string();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.ends_with(&format!("--{boundary}--\r\n")));
    }
}
