use boring2::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};

/// Brotli certificate decompressor for RFC 8879 `compress_certificate` extension.
///
/// Chrome advertises Brotli cert compression support. The client only needs
/// decompression — the server compresses certificates when both sides support it.
pub struct BrotliCertCompressor;

impl CertificateCompressor for BrotliCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}
