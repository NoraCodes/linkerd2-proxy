// These crates are only used within the `tls` module.
extern crate rustls;
extern crate tokio_rustls;
extern crate untrusted;
extern crate webpki;

use self::tokio_rustls::{Accept, TlsAcceptor as Acceptor, TlsConnector as Connector};
use std::fmt;

use identity;

pub mod client;
mod conditional_accept;
mod connection;
mod io;
pub mod listen;

use self::io::TlsIo;

pub use self::connection::Connection;
pub use self::listen::Listen;
pub use self::rustls::TLSError as Error;

// ===== Remove this =====
pub type Status = ::Conditional<(), ReasonForNoIdentity>;

pub trait HasStatus {
    fn tls_status(&self) -> Status;
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ::Conditional::Some(()) => write!(f, "true"),
            ::Conditional::None(r) => fmt::Display::fmt(&r, f),
        }
    }
}

// ===== end =====

/// The ultimate goal of this to be able to say on the Identity Controller's
/// proxy that there is a TLS status on the server, but the peer of that
/// TLS connection did not provide its own peer identity. This model would
/// solve the following with:
///
/// TlsStatus::Some(
///     TlsState {
///         server_identity: identity::Name,
///         client_identity: None(ReasonForNoClientIdenityt::NotProvidedByClient)
///     }
/// )

pub type IdentityStatus<T> = ::Conditional<T, ReasonForNoIdentity>;

pub type PeerIdentity = ::Conditional<identity::Name, ReasonForNoPeerIdentity>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReasonForNoIdentity {
    Disabled,
    NoPeerIdentity(ReasonForNoPeerIdentity),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReasonForNoPeerIdentity {
    /// The connection is a loopback connection which does not need or support
    /// TLS.
    Loopback,

    /// The connection protocol is HTTP, but the request does not have an
    /// authority so we cannot extract the identity from it.
    NoAuthorityInHttpRequest,

    /// The connection protocol is not HTTP so we don't know anything about
    /// the destination besides its address.
    NotHttp,

    /// The destination service did not give us the identity, which is its way
    /// of telling us that we should not TLS for this endpoint.
    NotProvidedByServiceDiscovery,

    /// Identity was not provided by the client.
    NotProvidedByClient,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IdentityState {
    server_identity: identity::Name,
    client_identity: PeerIdentity,
}

pub trait HasIdentity {
    fn identity(&self) -> IdentityStatus<IdentityState>;
}

pub trait HasPeerIdentity {
    fn peer_identity(&self) -> PeerIdentity;
}

impl fmt::Display for ReasonForNoIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReasonForNoIdentity::Disabled => write!(f, "disabled"),
            ReasonForNoIdentity::NoPeerIdentity(r) => write!(f, "{}", r),
        }
    }
}

impl fmt::Display for ReasonForNoPeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReasonForNoPeerIdentity::Loopback => write!(f, "loopback"),
            ReasonForNoPeerIdentity::NoAuthorityInHttpRequest => {
                write!(f, "no_authority_in_http_request")
            }
            ReasonForNoPeerIdentity::NotHttp => write!(f, "not_http"),
            ReasonForNoPeerIdentity::NotProvidedByServiceDiscovery => {
                write!(f, "not_provided_by_service_discovery")
            }
            ReasonForNoPeerIdentity::NotProvidedByClient => write!(f, "not_provided_by_client"),
        }
    }
}
