use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;

use bytes::Bytes;
use futures_util::Stream;

use crate::error::Error;

/// A stream of body chunks.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

/// The body of a request: bytes in memory, or a stream read while the request goes out.
///
/// Anything that converts into bytes converts into a body (`Vec<u8>`, [`Bytes`], `String`,
/// `&'static str`, `&'static [u8]`), and so does `Option<Vec<u8>>`, where `None` means no body.
///
/// A stream with a known length ([`Body::sized_stream`]) is sent with a `Content-Length`; without
/// one ([`Body::stream`]) it goes out as a chunked HTTP/1.1 body, or as DATA frames on HTTP/2 and
/// HTTP/3 without a `Content-Length`. The stream is read as fast as the connection takes it.
///
/// Bytes can be sent again: a retry, or a redirect that keeps the body, resends them. A stream is
/// read once: a retry only happens before it was first read, and a redirect other than 303 fails
/// (Fetch Standard, HTTP-redirect fetch step 11).
pub struct Body {
    kind: Kind,
}

enum Kind {
    /// No body.
    None,
    Bytes(Bytes),
    Stream {
        /// Taken when the request starts reading it.
        stream: Mutex<Option<ByteStream>>,
        length: Option<u64>,
    },
}

/// How the length of a body is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// No body at all.
    None,
    Known(u64),
    /// A stream of unknown length.
    Unknown,
}

impl Body {
    /// No body.
    #[must_use]
    pub fn empty() -> Self {
        Self { kind: Kind::None }
    }

    /// A body read from `stream`, of unknown length.
    pub fn stream<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    {
        Self::from_stream(Box::pin(stream), None)
    }

    /// A body of exactly `length` bytes read from `stream`. The request fails if the stream ends
    /// early or yields more.
    pub fn sized_stream<S>(stream: S, length: u64) -> Self
    where
        S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    {
        Self::from_stream(Box::pin(stream), Some(length))
    }

    pub fn from_stream(stream: ByteStream, length: Option<u64>) -> Self {
        Self {
            kind: Kind::Stream {
                stream: Mutex::new(Some(stream)),
                length,
            },
        }
    }

    /// The length of the body, if it is known up front.
    pub fn content_length(&self) -> Option<u64> {
        match self.length() {
            Length::Known(len) => Some(len),
            Length::None | Length::Unknown => None,
        }
    }

    /// Whether the body is read from a stream.
    pub fn is_stream(&self) -> bool {
        matches!(self.kind, Kind::Stream { .. })
    }

    pub fn length(&self) -> Length {
        match &self.kind {
            Kind::None => Length::None,
            Kind::Bytes(bytes) => Length::Known(bytes.len() as u64),
            Kind::Stream {
                length: Some(len), ..
            } => Length::Known(*len),
            Kind::Stream { length: None, .. } => Length::Unknown,
        }
    }

    /// The bytes of an in-memory body.
    pub fn bytes(&self) -> Option<&Bytes> {
        match &self.kind {
            Kind::Bytes(bytes) => Some(bytes),
            Kind::None | Kind::Stream { .. } => None,
        }
    }

    /// Whether the body can still be sent (again): always for bytes, for a stream only until it was
    /// taken.
    pub fn replayable(&self) -> bool {
        match &self.kind {
            Kind::None | Kind::Bytes(_) => true,
            Kind::Stream { stream, .. } => crate::util::lock_recover(stream).is_some(),
        }
    }

    /// Take the stream to send it; `None` for a body that is not a stream or was taken already.
    pub fn take_stream(&self) -> Option<ByteStream> {
        match &self.kind {
            Kind::Stream { stream, .. } => crate::util::lock_recover(stream).take(),
            Kind::None | Kind::Bytes(_) => None,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::None => f.write_str("Body::empty()"),
            Kind::Bytes(bytes) => write!(f, "Body({} bytes)", bytes.len()),
            Kind::Stream { length, .. } => write!(f, "Body::stream(length: {length:?})"),
        }
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self {
            kind: Kind::Bytes(bytes),
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes::from(bytes).into()
    }
}

impl From<String> for Body {
    fn from(text: String) -> Self {
        Bytes::from(text).into()
    }
}

impl From<&'static str> for Body {
    fn from(text: &'static str) -> Self {
        Bytes::from_static(text.as_bytes()).into()
    }
}

impl From<&'static [u8]> for Body {
    fn from(bytes: &'static [u8]) -> Self {
        Bytes::from_static(bytes).into()
    }
}

/// `None` is no body. The only `Option` conversion, so that a bare `None` argument needs no type
/// annotation.
impl From<Option<Vec<u8>>> for Body {
    fn from(bytes: Option<Vec<u8>>) -> Self {
        bytes.map_or_else(Self::empty, Self::from)
    }
}

/// The error for a stream body that is needed again after it was sent.
pub fn already_sent() -> Error {
    Error::Body("the request body stream was already sent".into(), None)
}

/// The error for a request whose body stream failed.
pub fn stream_error(e: io::Error) -> Error {
    let message = format!("request body stream failed: {e}");
    Error::Body(message, crate::error::boxed(e))
}

/// Checks that a stream yields the length it announced.
pub struct LengthCheck {
    expected: Option<u64>,
    seen: u64,
}

impl LengthCheck {
    pub fn new(expected: Option<u64>) -> Self {
        Self { expected, seen: 0 }
    }

    /// Account for the next chunk.
    pub fn chunk(&mut self, len: usize) -> Result<(), Error> {
        self.seen += len as u64;
        match self.expected {
            Some(expected) if self.seen > expected => Err(Error::Body(
                format!("request body stream yielded more than its length of {expected} bytes"),
                None,
            )),
            _ => Ok(()),
        }
    }

    /// The stream ended.
    pub fn end(&self) -> Result<u64, Error> {
        match self.expected {
            Some(expected) if self.seen != expected => Err(Error::Body(
                format!(
                    "request body stream ended after {} of {expected} bytes",
                    self.seen
                ),
                None,
            )),
            _ => Ok(self.seen),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(parts: &[&'static [u8]]) -> impl Stream<Item = Result<Bytes, io::Error>> + Send {
        futures_util::stream::iter(parts.iter().map(|p| Ok(Bytes::from_static(p))))
    }

    #[test]
    fn test_conversions_and_lengths() {
        assert_eq!(Body::from(None).length(), Length::None);
        assert_eq!(Body::from(Some(b"abc".to_vec())).length(), Length::Known(3));
        assert_eq!(Body::from("hi").content_length(), Some(2));
        assert_eq!(Body::from(Vec::new()).length(), Length::Known(0));
        assert_eq!(Body::stream(chunks(&[b"a"])).length(), Length::Unknown);
        assert_eq!(
            Body::sized_stream(chunks(&[b"a"]), 1).content_length(),
            Some(1)
        );
    }

    #[test]
    fn test_stream_is_replayable_until_taken() {
        let body = Body::stream(chunks(&[b"a"]));
        assert!(body.replayable());
        assert!(body.take_stream().is_some());
        assert!(!body.replayable());
        assert!(body.take_stream().is_none());
        assert!(Body::from("x").replayable());
    }

    #[test]
    fn test_length_check() {
        let mut check = LengthCheck::new(Some(3));
        check.chunk(2).unwrap();
        assert!(check.end().is_err());
        check.chunk(1).unwrap();
        assert_eq!(check.end().unwrap(), 3);
        assert!(check.chunk(1).is_err());
    }
}
