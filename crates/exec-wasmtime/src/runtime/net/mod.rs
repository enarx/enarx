// SPDX-License-Identifier: Apache-2.0

//! Networking functionality for keeps

pub mod tls;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use cap_std::net::{TcpListener, TcpStream};
use enarx_config::{ConnectFile, ListenFile};
use once_cell::sync::Lazy;
use rustls::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::kx_group::{SECP256R1, SECP384R1, X25519};
use rustls::version::TLS13;
use rustls::{Certificate, PrivateKey, RootCertStore};
use wasi_common::file::FileCaps;
use wasi_common::WasiFile;
use zeroize::Zeroizing;

static DEFAULT_TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&TLS13];

static DEFAULT_TLS_KX_GROUPS: &[&rustls::SupportedKxGroup] = &[&X25519, &SECP384R1, &SECP256R1];

static DEFAULT_TLS_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
];

static LISTEN_CAPS: Lazy<FileCaps> = Lazy::new(|| {
    FileCaps::FILESTAT_GET | FileCaps::FDSTAT_SET_FLAGS | FileCaps::POLL_READWRITE | FileCaps::READ
});

static CONNECT_CAPS: Lazy<FileCaps> = Lazy::new(|| {
    FileCaps::FILESTAT_GET
        | FileCaps::FDSTAT_SET_FLAGS
        | FileCaps::POLL_READWRITE
        | FileCaps::READ
        | FileCaps::WRITE
});

pub fn listen_file(
    file: &ListenFile,
    certs: Vec<Certificate>,
    key: &Zeroizing<Vec<u8>>,
) -> Result<(Box<dyn WasiFile>, FileCaps)> {
    let (addr, port) = match file {
        ListenFile::Tcp { addr, port, .. } | ListenFile::Tls { addr, port, .. } => (addr, port),
    };
    let tcp = std::net::TcpListener::bind((addr.as_str(), *port))?;
    let tcp = TcpListener::from_std(tcp);
    tcp.set_nonblocking(true)
        .context("Error setting channel to nonblocking")?;
    let file = match file {
        ListenFile::Tcp { .. } => wasmtime_wasi::net::Socket::from(tcp).into(),
        ListenFile::Tls { .. } => {
            let cfg = rustls::ServerConfig::builder()
                .with_cipher_suites(DEFAULT_TLS_CIPHER_SUITES)
                .with_kx_groups(DEFAULT_TLS_KX_GROUPS)
                .with_protocol_versions(DEFAULT_TLS_PROTOCOL_VERSIONS)?
                .with_no_client_auth() // TODO: https://github.com/enarx/enarx/issues/1547
                .with_single_cert(certs, PrivateKey(key.deref().clone()))?;
            tls::Listener::new(tcp, Arc::new(cfg)).into()
        }
    };
    Ok((file, *LISTEN_CAPS))
}

pub fn connect_file(
    file: &ConnectFile,
    certs: Vec<Certificate>,
    key: &Zeroizing<Vec<u8>>,
) -> Result<(Box<dyn WasiFile>, FileCaps)> {
    let (host, port) = match &file {
        ConnectFile::Tcp { host, port, .. } | ConnectFile::Tls { host, port, .. } => (host, port),
    };
    let tcp = match (host.as_str(), *port) {
        ("localhost", port) => std::net::TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))),
        // TODO: Handle DNS in the keep
        // https://github.com/enarx/enarx/issues/1511
        addr => std::net::TcpStream::connect(addr),
    }
    .map(TcpStream::from_std)
    .context("failed to connect to endpoint")?;
    let file = match file {
        ConnectFile::Tcp { .. } => wasmtime_wasi::net::Socket::from(tcp).into(),
        ConnectFile::Tls { .. } => {
            let mut server_roots = RootCertStore::empty();
            server_roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));
            let cfg = rustls::ClientConfig::builder()
                .with_cipher_suites(DEFAULT_TLS_CIPHER_SUITES)
                .with_kx_groups(DEFAULT_TLS_KX_GROUPS)
                .with_protocol_versions(DEFAULT_TLS_PROTOCOL_VERSIONS)?
                .with_root_certificates(server_roots)
                .with_single_cert(certs, PrivateKey(key.deref().clone()))?;

            tls::Stream::connect(tcp, host, Arc::new(cfg))?.into()
        }
    };
    Ok((file, *CONNECT_CAPS))
}
