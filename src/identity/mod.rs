extern crate ring;
extern crate rustls;
extern crate untrusted;

use self::ring::rand;
use self::ring::signature::EcdsaKeyPair;
use self::rustls::RootCertStore;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use std::{fmt, fs, io};

pub use self::ring::error::KeyRejected;

use convert::TryFrom;
use dns;

/// A DER-encoded X.509 certificate signing request.
#[derive(Clone, Debug)]
pub struct CSR(Arc<Vec<u8>>);

/// An endpoint's identity.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Name(Arc<dns::Name>);

#[derive(Clone, Debug)]
pub struct Key(Arc<EcdsaKeyPair>);

struct SigningKey(Arc<EcdsaKeyPair>);
struct Signer(Arc<EcdsaKeyPair>);

#[derive(Clone, Debug)]
pub struct TrustAnchors(Arc<RootCertStore>);

#[derive(Clone, Debug)]
pub struct TokenSource(Arc<String>);

#[derive(Clone, Debug)]
pub struct Crt {
    name: Name,
    expiry: SystemTime,
    chain: Vec<rustls::Certificate>,
}

#[derive(Clone)]
pub struct CrtKey {
    name: Name,
    expiry: SystemTime,
    key: rustls::sign::CertifiedKey,
}

#[derive(Clone, Debug)]
pub struct InvalidCrt(rustls::TLSError);

// These must be kept in sync:
static SIGNATURE_ALG_RING_SIGNING: &ring::signature::EcdsaSigningAlgorithm =
    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
const SIGNATURE_ALG_RUSTLS_SCHEME: rustls::SignatureScheme =
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
const SIGNATURE_ALG_RUSTLS_ALGORITHM: rustls::internal::msgs::enums::SignatureAlgorithm =
    rustls::internal::msgs::enums::SignatureAlgorithm::ECDSA;

// === impl CSR ===

impl CSR {
    pub fn from_der(der: Vec<u8>) -> Option<Self> {
        if der.is_empty() {
            return None;
        }

        Some(CSR(Arc::new(der)))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// === impl Key ===

impl Key {
    pub fn from_pkcs8(b: &[u8]) -> Result<Self, KeyRejected> {
        let i = untrusted::Input::from(b);
        let k = EcdsaKeyPair::from_pkcs8(SIGNATURE_ALG_RING_SIGNING, i)?;
        Ok(Key(Arc::new(k)))
    }
}

impl rustls::sign::SigningKey for SigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<rustls::sign::Signer>> {
        if offered.contains(&SIGNATURE_ALG_RUSTLS_SCHEME) {
            Some(Box::new(Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::internal::msgs::enums::SignatureAlgorithm {
        SIGNATURE_ALG_RUSTLS_ALGORITHM
    }
}

impl rustls::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::TLSError> {
        let rng = rand::SystemRandom::new();
        self.0
            .sign(&rng, untrusted::Input::from(message))
            .map(|signature| signature.as_ref().to_owned())
            .map_err(|ring::error::Unspecified| {
                rustls::TLSError::General("Signing Failed".to_owned())
            })
    }

    fn get_scheme(&self) -> rustls::SignatureScheme {
        SIGNATURE_ALG_RUSTLS_SCHEME
    }
}

// === impl Name ===

// impl From<dns::Name> for Name {
//     fn from(n: dns::Name) -> Self {
//         Name(Arc::new(n))
//     }
// }

impl Name {
    pub fn from_sni_hostname(hostname: &[u8]) -> Result<Self, dns::InvalidName> {
        if hostname.last() == Some(&b'.') {
            return Err(dns::InvalidName); // SNI hostnames are implicitly absolute.
        }

        dns::Name::try_from(hostname).map(|n| Name(Arc::new(n)))
    }

    pub fn as_dns_name_ref(&self) -> webpki::DNSNameRef {
        self.0.as_dns_name_ref()
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        (*self.0).as_ref()
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(&self.0, f)
    }
}

// === impl TrustAnchors ===

impl TokenSource {
    pub fn if_nonempty_file(p: String) -> io::Result<Self> {
        let ts = TokenSource(Arc::new(p));
        ts.load().map(|_| ts)
    }

    pub fn load(&self) -> io::Result<Vec<u8>> {
        let t = fs::read(self.0.as_str())?;

        if t.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other.into(),
                "token is empty",
            ));
        }

        Ok(t)
    }
}

// === impl TrustAnchors ===

impl TrustAnchors {
    pub fn from_pem(s: &str) -> Option<Self> {
        use std::io::Cursor;

        let mut roots = rustls::RootCertStore::empty();
        let (added, skipped) = roots.add_pem_file(&mut Cursor::new(s)).ok()?;
        if skipped != 0 {
            warn!("skipped {} trust anchors in trust anchors file", skipped);
        }
        if added == 0 {
            return None;
        }

        Some(TrustAnchors(Arc::new(roots)))
    }

    pub fn certify(&self, key: Key, crt: Crt) -> Result<CrtKey, InvalidCrt> {
        // Ensure the certificate is valid for the services we terminate for
        // TLS. This assumes that server cert validation does the same or
        // more validation than client cert validation.
        //
        // XXX: Rustls currently only provides access to a
        // `ServerCertVerifier` through
        // `rustls::ClientConfig::get_verifier()`.
        //
        // XXX: Once `rustls::ServerCertVerified` is exposed in Rustls's
        // safe API, use it to pass proof to CertResolver::new....
        //
        // TODO: Restrict accepted signatutre algorithms.
        static NO_OCSP: &'static [u8] = &[];
        rustls::ClientConfig::new()
            .get_verifier()
            .verify_server_cert(&self.0, &crt.chain, crt.name.as_dns_name_ref(), NO_OCSP)
            .map_err(InvalidCrt)?;

        let k = SigningKey(key.0.clone());
        Ok(CrtKey {
            name: crt.name,
            expiry: crt.expiry,
            key: rustls::sign::CertifiedKey::new(crt.chain, Arc::new(Box::new(k))),
        })
    }
}

// === CrtKey ===

impl Crt {
    pub fn new(name: Name, leaf: Vec<u8>, intermediates: Vec<Vec<u8>>, expiry: SystemTime) -> Self {
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(rustls::Certificate(leaf));
        chain.extend(intermediates.into_iter().map(rustls::Certificate));

        Self {
            name,
            chain,
            expiry,
        }
    }
}

// === CrtKey ===

impl CrtKey {
    fn resolve_(
        &self,
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        if !sigschemes.contains(&SIGNATURE_ALG_RUSTLS_SCHEME) {
            debug!("signature scheme not supported -> no certificate");
            return None;
        }

        Some(self.key.clone())
    }
}

impl rustls::ResolvesClientCert for CrtKey {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        // The proxy's server-side doesn't send the list of acceptable issuers so
        // don't bother looking at `_acceptable_issuers`.
        self.resolve_(sigschemes)
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::ResolvesServerCert for CrtKey {
    fn resolve(
        &self,
        server_name: Option<webpki::DNSNameRef>,
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        let server_name = if let Some(server_name) = server_name {
            server_name
        } else {
            debug!("no SNI -> no certificate");
            return None;
        };

        // Verify that our certificate is valid for the given SNI name.
        let c = (&self.key.cert)
            .first()
            .map(rustls::Certificate::as_ref)
            .unwrap_or(&[]); // An empty input will fail to parse.
        if let Err(err) = webpki::EndEntityCert::from(untrusted::Input::from(c))
            .and_then(|cert| cert.verify_is_valid_for_dns_name(server_name))
        {
            debug!(
                "our certificate is not valid for the SNI name -> no certificate: {:?}",
                err
            );
            return None;
        }

        self.resolve_(sigschemes)
    }
}

// === impl InvalidCrt ===

impl fmt::Display for InvalidCrt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for InvalidCrt {
    fn description(&self) -> &str {
        self.0.description()
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}
