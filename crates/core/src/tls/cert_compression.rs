use btls::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};

/// Brotli certificate decompressor for RFC 8879 `compress_certificate` extension.
#[derive(Debug)]
pub struct BrotliCertCompressor;

impl CertificateCompressor for BrotliCertCompressor {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::BROTLI
    }

    fn compress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        // We only decompress (client-side). Compression stub for trait compliance.
        let _ = (input, output);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "compression not implemented",
        ))
    }

    fn decompress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut buf = Vec::new();
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), &mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}

/// Zlib certificate decompressor for RFC 8879 `compress_certificate` extension.
#[derive(Debug)]
pub struct ZlibCertCompressor;

impl CertificateCompressor for ZlibCertCompressor {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZLIB
    }

    fn compress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let _ = (input, output);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "compression not implemented",
        ))
    }

    fn decompress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        use std::io::Read;
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}

/// Zstd certificate decompressor for RFC 8879 `compress_certificate` extension.
#[derive(Debug)]
pub struct ZstdCertCompressor;

impl CertificateCompressor for ZstdCertCompressor {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZSTD
    }

    fn compress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let _ = (input, output);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "compression not implemented",
        ))
    }

    fn decompress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        use std::io::Read;
        let mut decoder = zstd::Decoder::new(input)?;
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}
