use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use boring2::asn1::Asn1Time;
use boring2::bn::{BigNum, MsbOption};
use boring2::hash::MessageDigest;
use boring2::pkey::{PKey, Private};
use boring2::rsa::Rsa;
use boring2::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use boring2::x509::{X509Name, X509};

use crate::error::Error;

/// Certificate authority for MITM proxy.
///
/// Generates or loads a CA certificate from disk, and signs leaf certificates
/// per domain on demand. Leaf certs are cached in memory.
pub struct CertAuthority {
    ca_key: PKey<Private>,
    ca_cert: X509,
    storage_dir: PathBuf,
    leaf_cache: Mutex<HashMap<String, (X509, PKey<Private>)>>,
}

impl CertAuthority {
    /// Load an existing CA from disk, or generate a new one and save it.
    ///
    /// Files: `koon-ca.pem` (certificate) and `koon-ca-key.pem` (private key).
    pub fn load_or_generate(storage_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&storage_dir).map_err(Error::Io)?;

        let cert_path = storage_dir.join("koon-ca.pem");
        let key_path = storage_dir.join("koon-ca-key.pem");

        let (ca_cert, ca_key) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read(&cert_path).map_err(Error::Io)?;
            let key_pem = std::fs::read(&key_path).map_err(Error::Io)?;

            let cert = X509::from_pem(&cert_pem)
                .map_err(|e| Error::Proxy(format!("Failed to load CA cert: {e}")))?;
            let key = PKey::private_key_from_pem(&key_pem)
                .map_err(|e| Error::Proxy(format!("Failed to load CA key: {e}")))?;

            (cert, key)
        } else {
            let (cert, key) = Self::generate_ca()?;

            let cert_pem = cert
                .to_pem()
                .map_err(|e| Error::Proxy(format!("Failed to encode CA cert: {e}")))?;
            let key_pem = key
                .private_key_to_pem_pkcs8()
                .map_err(|e| Error::Proxy(format!("Failed to encode CA key: {e}")))?;

            std::fs::write(&cert_path, &cert_pem).map_err(Error::Io)?;
            std::fs::write(&key_path, &key_pem).map_err(Error::Io)?;

            (cert, key)
        };

        Ok(CertAuthority {
            ca_key,
            ca_cert,
            storage_dir,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Path to the CA certificate PEM file.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join("koon-ca.pem")
    }

    /// CA certificate as PEM bytes (for installing in browsers/tools).
    pub fn ca_cert_pem(&self) -> Result<Vec<u8>, Error> {
        self.ca_cert
            .to_pem()
            .map_err(|e| Error::Proxy(format!("Failed to encode CA cert: {e}")))
    }

    /// Get or create a leaf certificate for the given domain.
    pub fn get_or_create_leaf(&self, domain: &str) -> Result<(X509, PKey<Private>), Error> {
        let mut cache = self.leaf_cache.lock().unwrap();
        if let Some(entry) = cache.get(domain) {
            return Ok(entry.clone());
        }

        let (cert, key) = self.sign_leaf(domain)?;
        cache.insert(domain.to_string(), (cert.clone(), key.clone()));
        Ok((cert, key))
    }

    /// Generate a new self-signed CA certificate.
    fn generate_ca() -> Result<(X509, PKey<Private>), Error> {
        let rsa = Rsa::generate(2048)
            .map_err(|e| Error::Proxy(format!("RSA key generation failed: {e}")))?;
        let key = PKey::from_rsa(rsa)
            .map_err(|e| Error::Proxy(format!("PKey creation failed: {e}")))?;

        let mut name_builder = X509Name::builder()
            .map_err(|e| Error::Proxy(format!("X509Name builder failed: {e}")))?;
        name_builder
            .append_entry_by_text("CN", "Koon MITM Proxy CA")
            .map_err(|e| Error::Proxy(format!("CN entry failed: {e}")))?;
        name_builder
            .append_entry_by_text("O", "Koon")
            .map_err(|e| Error::Proxy(format!("O entry failed: {e}")))?;
        let name = name_builder.build();

        let mut builder = X509::builder()
            .map_err(|e| Error::Proxy(format!("X509 builder failed: {e}")))?;
        builder
            .set_version(2)
            .map_err(|e| Error::Proxy(format!("set_version failed: {e}")))?;

        let serial = {
            let mut bn = BigNum::new()
                .map_err(|e| Error::Proxy(format!("BigNum::new failed: {e}")))?;
            bn.rand(128, MsbOption::MAYBE_ZERO, false)
                .map_err(|e| Error::Proxy(format!("BigNum::rand failed: {e}")))?;
            bn.to_asn1_integer()
                .map_err(|e| Error::Proxy(format!("to_asn1_integer failed: {e}")))?
        };
        builder
            .set_serial_number(&serial)
            .map_err(|e| Error::Proxy(format!("set_serial_number failed: {e}")))?;

        builder
            .set_subject_name(&name)
            .map_err(|e| Error::Proxy(format!("set_subject_name failed: {e}")))?;
        builder
            .set_issuer_name(&name)
            .map_err(|e| Error::Proxy(format!("set_issuer_name failed: {e}")))?;
        builder
            .set_pubkey(&key)
            .map_err(|e| Error::Proxy(format!("set_pubkey failed: {e}")))?;

        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| Error::Proxy(format!("Asn1Time not_before failed: {e}")))?;
        let not_after = Asn1Time::days_from_now(3650)
            .map_err(|e| Error::Proxy(format!("Asn1Time not_after failed: {e}")))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| Error::Proxy(format!("set_not_before failed: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| Error::Proxy(format!("set_not_after failed: {e}")))?;

        let bc = BasicConstraints::new().critical().ca().build()
            .map_err(|e| Error::Proxy(format!("BasicConstraints failed: {e}")))?;
        builder
            .append_extension(&bc)
            .map_err(|e| Error::Proxy(format!("append_extension CA failed: {e}")))?;

        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(|e| Error::Proxy(format!("KeyUsage failed: {e}")))?;
        builder
            .append_extension(&ku)
            .map_err(|e| Error::Proxy(format!("append_extension KeyUsage failed: {e}")))?;

        builder
            .sign(&key, MessageDigest::sha256())
            .map_err(|e| Error::Proxy(format!("CA signing failed: {e}")))?;

        Ok((builder.build(), key))
    }

    /// Sign a leaf certificate for a specific domain using the CA.
    fn sign_leaf(&self, domain: &str) -> Result<(X509, PKey<Private>), Error> {
        let rsa = Rsa::generate(2048)
            .map_err(|e| Error::Proxy(format!("Leaf RSA generation failed: {e}")))?;
        let key = PKey::from_rsa(rsa)
            .map_err(|e| Error::Proxy(format!("Leaf PKey creation failed: {e}")))?;

        let mut name_builder = X509Name::builder()
            .map_err(|e| Error::Proxy(format!("Leaf X509Name builder failed: {e}")))?;
        name_builder
            .append_entry_by_text("CN", domain)
            .map_err(|e| Error::Proxy(format!("Leaf CN entry failed: {e}")))?;
        let name = name_builder.build();

        let mut builder = X509::builder()
            .map_err(|e| Error::Proxy(format!("Leaf X509 builder failed: {e}")))?;
        builder
            .set_version(2)
            .map_err(|e| Error::Proxy(format!("Leaf set_version failed: {e}")))?;

        let serial = {
            let mut bn = BigNum::new()
                .map_err(|e| Error::Proxy(format!("Leaf BigNum::new failed: {e}")))?;
            bn.rand(128, MsbOption::MAYBE_ZERO, false)
                .map_err(|e| Error::Proxy(format!("Leaf BigNum::rand failed: {e}")))?;
            bn.to_asn1_integer()
                .map_err(|e| Error::Proxy(format!("Leaf to_asn1_integer failed: {e}")))?
        };
        builder
            .set_serial_number(&serial)
            .map_err(|e| Error::Proxy(format!("Leaf set_serial_number failed: {e}")))?;

        builder
            .set_subject_name(&name)
            .map_err(|e| Error::Proxy(format!("Leaf set_subject_name failed: {e}")))?;
        builder
            .set_issuer_name(self.ca_cert.subject_name())
            .map_err(|e| Error::Proxy(format!("Leaf set_issuer_name failed: {e}")))?;
        builder
            .set_pubkey(&key)
            .map_err(|e| Error::Proxy(format!("Leaf set_pubkey failed: {e}")))?;

        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| Error::Proxy(format!("Leaf not_before failed: {e}")))?;
        let not_after = Asn1Time::days_from_now(365)
            .map_err(|e| Error::Proxy(format!("Leaf not_after failed: {e}")))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| Error::Proxy(format!("Leaf set_not_before failed: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| Error::Proxy(format!("Leaf set_not_after failed: {e}")))?;

        let bc = BasicConstraints::new().build()
            .map_err(|e| Error::Proxy(format!("Leaf BasicConstraints failed: {e}")))?;
        builder
            .append_extension(&bc)
            .map_err(|e| Error::Proxy(format!("Leaf append BasicConstraints failed: {e}")))?;

        let san = SubjectAlternativeName::new()
            .dns(domain)
            .build(&builder.x509v3_context(Some(&self.ca_cert), None))
            .map_err(|e| Error::Proxy(format!("SAN build failed: {e}")))?;
        builder
            .append_extension(&san)
            .map_err(|e| Error::Proxy(format!("Leaf append SAN failed: {e}")))?;

        builder
            .sign(&self.ca_key, MessageDigest::sha256())
            .map_err(|e| Error::Proxy(format!("Leaf signing failed: {e}")))?;

        Ok((builder.build(), key))
    }
}
