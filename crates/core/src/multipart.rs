use rand::Rng;

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

/// Builder for multipart/form-data request bodies.
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
#[derive(Debug, Clone)]
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

impl Multipart {
    /// Create a new multipart builder with a random boundary.
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let alphanum: Vec<u8> = (0..24)
            .map(|_| {
                let idx = rng.random_range(0..62u8);
                match idx {
                    0..26 => b'a' + idx,
                    26..52 => b'A' + (idx - 26),
                    _ => b'0' + (idx - 52),
                }
            })
            .collect();
        let boundary = format!("----koon{}", String::from_utf8(alphanum).unwrap());
        Multipart {
            boundary,
            parts: Vec::new(),
        }
    }

    /// Add a text field.
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(Part::Text {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Add a file upload field.
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
    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    /// Get the Content-Type header value for this multipart body.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Build the multipart body bytes and Content-Type header value.
    pub fn build(self) -> (Vec<u8>, String) {
        let content_type = self.content_type();
        let mut body = Vec::new();

        for part in &self.parts {
            // Boundary delimiter
            body.extend_from_slice(b"--");
            body.extend_from_slice(self.boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            match part {
                Part::Text { name, value } => {
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
                    );
                    body.extend_from_slice(b"\r\n");
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
                            "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
                    body.extend_from_slice(b"\r\n");
                    body.extend_from_slice(data);
                }
            }

            body.extend_from_slice(b"\r\n");
        }

        // Closing boundary
        body.extend_from_slice(b"--");
        body.extend_from_slice(self.boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");

        (body, content_type)
    }
}

impl Default for Multipart {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_format() {
        let mp = Multipart::new();
        assert!(mp.boundary.starts_with("----koon"));
        assert_eq!(mp.boundary.len(), 8 + 24); // "----koon" + 24 alphanums
    }

    #[test]
    fn test_content_type() {
        let mp = Multipart::new();
        let ct = mp.content_type();
        assert!(ct.starts_with("multipart/form-data; boundary=----koon"));
    }

    #[test]
    fn test_text_field_encoding() {
        let (body, _ct) = Multipart::new().text("field1", "value1").build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("Content-Disposition: form-data; name=\"field1\""));
        assert!(body_str.contains("\r\n\r\nvalue1\r\n"));
        assert!(body_str.ends_with("--\r\n"));
    }

    #[test]
    fn test_file_field_encoding() {
        let (body, _ct) = Multipart::new()
            .file("upload", "test.txt", "text/plain", b"hello world".to_vec())
            .build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("name=\"upload\"; filename=\"test.txt\""));
        assert!(body_str.contains("Content-Type: text/plain"));
        assert!(body_str.contains("\r\n\r\nhello world\r\n"));
    }

    #[test]
    fn test_mixed_fields() {
        let (body, ct) = Multipart::new()
            .text("name", "John")
            .file("avatar", "photo.jpg", "image/jpeg", vec![0xFF, 0xD8, 0xFF])
            .text("description", "A photo")
            .build();

        assert!(ct.starts_with("multipart/form-data; boundary="));

        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"name\""));
        assert!(body_str.contains("name=\"avatar\""));
        assert!(body_str.contains("name=\"description\""));
        // Should end with closing boundary
        assert!(body_str.ends_with("--\r\n"));
    }

    #[test]
    fn test_closing_boundary() {
        let mp = Multipart::new();
        let boundary = mp.boundary.clone();
        let (body, _) = mp.text("x", "y").build();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains(&format!("--{boundary}--")));
    }
}
