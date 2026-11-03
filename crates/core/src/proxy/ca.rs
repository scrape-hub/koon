use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::util::GrowingLru;
use btls::asn1::{Asn1Time, Asn1TimeRef};
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::error::ErrorStack;
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::{PKey, Private};
use btls::rsa::Rsa;
use btls::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use btls::x509::{X509, X509Builder, X509Name, X509NameRef};

use crate::error::Error;

const MAX_CACHED_HOSTS: usize = 10_000;

const MAX_COMMON_NAME_LEN: usize = 64;

fn write_ca_key_pem(key_path: &Path, key_pem: &[u8]) -> Result<(), Error> {
    let dir = key_path
        .parent()
        .ok_or_else(|| Error::Proxy("CA key path has no parent directory".into(), None))?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_path = dir.join(format!(
        "koon-ca-key.pem.tmp.{}.{unique}",
        std::process::id()
    ));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(Error::Io)?;
        file.write_all(key_pem).map_err(Error::Io)?;
        file.sync_all().map_err(Error::Io)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, key_pem).map_err(Error::Io)?;
    }

    std::fs::rename(&tmp_path, key_path).map_err(Error::Io)?;
    Ok(())
}

pub struct CertAuthority {
    ca_key: PKey<Private>,
    ca_cert: X509,
    storage_dir: PathBuf,
    leaf_cache: Mutex<GrowingLru<String, (X509, PKey<Private>)>>,
}

impl CertAuthority {
    pub fn load_or_generate(storage_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&storage_dir).map_err(Error::Io)?;

        let cert_path = storage_dir.join("koon-ca.pem");
        let key_path = storage_dir.join("koon-ca-key.pem");

        let (ca_cert, ca_key) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read(&cert_path).map_err(Error::Io)?;
            let key_pem = std::fs::read(&key_path).map_err(Error::Io)?;

            let cert = X509::from_pem(&cert_pem).map_err(|e| {
                let message = format!("Failed to load CA cert: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;
            let key = PKey::private_key_from_pem(&key_pem).map_err(|e| {
                let message = format!("Failed to load CA key: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            if cert.subject_key_id().is_none() {
                return Err(Error::Proxy(
                    format!(
                        "The CA certificate {} has no subjectKeyIdentifier, which strict TLS \
                         clients require. Delete {} and {}; koon will generate a new CA next \
                         time, and it will need reinstalling in your clients.",
                        cert_path.display(),
                        cert_path.display(),
                        key_path.display()
                    ),
                    None,
                ));
            }

            (cert, key)
        } else {
            let (cert, key) = generate_ca().map_err(|e| {
                let message = format!("CA certificate generation failed: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            let cert_pem = cert.to_pem().map_err(|e| {
                let message = format!("Failed to encode CA cert: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;
            let key_pem = key.private_key_to_pem_pkcs8().map_err(|e| {
                let message = format!("Failed to encode CA key: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            std::fs::write(&cert_path, &cert_pem).map_err(Error::Io)?;
            write_ca_key_pem(&key_path, &key_pem)?;

            (cert, key)
        };

        Ok(Self {
            ca_key,
            ca_cert,
            storage_dir,
            leaf_cache: Mutex::new(GrowingLru::new(MAX_CACHED_HOSTS)),
        })
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join("koon-ca.pem")
    }

    pub fn ca_cert_pem(&self) -> Result<Vec<u8>, Error> {
        self.ca_cert.to_pem().map_err(|e| {
            let message = format!("Failed to encode CA cert: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        })
    }

    pub fn get_or_create_leaf(&self, host: &str) -> Result<(X509, PKey<Private>), Error> {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if let Some(entry) = crate::util::lock_recover(&self.leaf_cache).get(&host) {
            return Ok(entry.clone());
        }

        let (cert, key) = self.sign_leaf(&host).map_err(|e| {
            let message = format!("Leaf certificate for {host} failed: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        })?;

        let mut cache = crate::util::lock_recover(&self.leaf_cache);
        if let Some(existing) = cache.get(&host) {
            return Ok(existing.clone());
        }
        cache.put(host, (cert.clone(), key.clone()));
        Ok((cert, key))
    }

    fn sign_leaf(&self, host: &str) -> Result<(X509, PKey<Private>), ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;

        let mut name = X509Name::builder()?;
        let has_common_name = host.len() <= MAX_COMMON_NAME_LEN;
        if has_common_name {
            name.append_entry_by_text("CN", host)?;
        }
        let name = name.build();

        let (not_before, not_after) = validity(365)?;
        let mut builder = new_cert_builder(
            &name,
            self.ca_cert.subject_name(),
            &key,
            &not_before,
            &not_after,
        )?;
        let basic_constraints = BasicConstraints::new().build()?;
        builder.append_extension(&basic_constraints)?;
        let server_auth = ExtendedKeyUsage::new().server_auth().build()?;
        builder.append_extension(&server_auth)?;
        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(&self.ca_cert), None))?;
        builder.append_extension(&authority_key_id)?;

        let mut san = SubjectAlternativeName::new();
        if !has_common_name {
            san.critical();
        }
        if host.parse::<IpAddr>().is_ok() {
            san.ip(host);
        } else {
            san.dns(host);
        }
        let san = san.build(&builder.x509v3_context(Some(&self.ca_cert), None))?;
        builder.append_extension(&san)?;

        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        Ok((builder.build(), key))
    }
}

fn generate_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_text("CN", "Koon MITM Proxy CA")?;
    name.append_entry_by_text("O", "Koon")?;
    let name = name.build();

    let (not_before, not_after) = validity(3650)?;
    let cert = sign_ca(&name, &key, &not_before, &not_after)?;
    Ok((cert, key))
}

fn sign_ca(
    name: &X509NameRef,
    key: &PKey<Private>,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509, ErrorStack> {
    let mut builder = new_cert_builder(name, name, key, not_before, not_after)?;
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(&basic_constraints)?;
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    builder.append_extension(&key_usage)?;
    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(&subject_key_id)?;

    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}

fn validity(days: u32) -> Result<(Asn1Time, Asn1Time), ErrorStack> {
    Ok((Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(days)?))
}

fn new_cert_builder(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    key: &PKey<Private>,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509Builder, ErrorStack> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    builder.set_subject_name(subject)?;
    builder.set_issuer_name(issuer)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(not_before)?;
    builder.set_not_after(not_after)?;
    Ok(builder)
}
