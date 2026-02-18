use boring2::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};

/// Brotli certificate decompressor for RFC 8879 `compress_certificate` extension.
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

/// Zlib certificate decompressor for RFC 8879 `compress_certificate` extension.
/// Firefox advertises Zlib cert compression support.
pub struct ZlibCertCompressor;

impl CertificateCompressor for ZlibCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use std::io::Read;
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}

/// Zstd certificate decompressor for RFC 8879 `compress_certificate` extension.
/// Firefox advertises Zstd cert compression support.
pub struct ZstdCertCompressor;

impl CertificateCompressor for ZstdCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use std::io::Read;
        let mut decoder = zstd::Decoder::new(input)?;
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}
