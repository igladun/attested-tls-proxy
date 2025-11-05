use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{
    rustls::{ClientConfig, ServerConfig},
    TlsAcceptor, TlsConnector,
};
use x509_parser::prelude::*;

/// The label used when exporting key material from a TLS session
const EXPORTER_LABEL: &[u8; 24] = b"EXPORTER-Channel-Binding";

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer {
    /// The certificate chain
    cert_chain: Vec<CertificateDer<'static>>,
    /// For accepting TLS connections
    acceptor: TlsAcceptor,
    /// The underlying TCP listener
    listener: TcpListener,
    /// The address of the target service we are proxying to
    target: SocketAddr,
    attestation_platform: MockAttestation,
}

impl ProxyServer {
    pub async fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        local: impl ToSocketAddrs,
        target: SocketAddr,
    ) -> Self {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain.clone(), key)
            .expect("Failed to create rustls server config");

        Self::new_with_tls_config(cert_chain, server_config.into(), local, target).await
    }

    /// Start with preconfigured TLS
    pub async fn new_with_tls_config(
        cert_chain: Vec<CertificateDer<'static>>,
        server_config: Arc<ServerConfig>,
        local: impl ToSocketAddrs,
        target: SocketAddr,
    ) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind(local).await.unwrap();

        Self {
            cert_chain,
            acceptor,
            listener,
            target,
            attestation_platform: MockAttestation,
        }
    }

    /// Accept an incoming connection
    pub async fn accept(&self) -> io::Result<()> {
        let (inbound, _client_addr) = self.listener.accept().await.unwrap();

        let acceptor = self.acceptor.clone();
        let target = self.target;
        let cert_chain = self.cert_chain.clone();
        let attestation_platform = self.attestation_platform.clone();
        tokio::spawn(async move {
            let mut tls_stream = acceptor.accept(inbound).await.unwrap();
            let (_io, server_connection) = tls_stream.get_ref();

            let mut exporter = [0u8; 32];
            server_connection
                .export_keying_material(
                    &mut exporter,
                    EXPORTER_LABEL,
                    None, // context
                )
                .unwrap();

            let attestation = attestation_platform.create_attestation(&cert_chain, exporter);
            let attestation_length_prefix = length_prefix(&attestation);

            tls_stream
                .write_all(&attestation_length_prefix)
                .await
                .unwrap();

            tls_stream
                .write_all(&attestation_platform.create_attestation(&cert_chain, exporter))
                .await
                .unwrap();

            let outbound = TcpStream::connect(target).await.unwrap();

            let (mut inbound_reader, mut inbound_writer) = tokio::io::split(tls_stream);
            let (mut outbound_reader, mut outbound_writer) = outbound.into_split();

            let client_to_server = tokio::io::copy(&mut inbound_reader, &mut outbound_writer);
            let server_to_client = tokio::io::copy(&mut outbound_reader, &mut inbound_writer);
            tokio::try_join!(client_to_server, server_to_client).unwrap();
        });

        Ok(())
    }
}

pub struct ProxyClient {
    connector: TlsConnector,
    listener: TcpListener,
    /// The address of the proxy server
    target: SocketAddr,
    /// The subject name of the proxy server
    target_name: ServerName<'static>,
    attestation_platform: MockAttestation,
}

impl ProxyClient {
    pub async fn new(
        address: impl ToSocketAddrs,
        server_address: SocketAddr,
        server_name: ServerName<'static>,
    ) -> Self {
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self::new_with_tls_config(client_config.into(), address, server_address, server_name).await
    }

    pub async fn new_with_tls_config(
        client_config: Arc<ClientConfig>,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        target_name: ServerName<'static>,
    ) -> Self {
        let listener = TcpListener::bind(local).await.unwrap();
        let connector = TlsConnector::from(client_config.clone());

        Self {
            connector,
            listener,
            target,
            target_name,
            attestation_platform: MockAttestation,
        }
    }

    pub async fn accept(&self) -> io::Result<()> {
        let (inbound, _client_addr) = self.listener.accept().await.unwrap();

        let connector = self.connector.clone();
        let target_name = self.target_name.clone();
        let target = self.target;
        let attestation_platform = self.attestation_platform.clone();

        tokio::spawn(async move {
            let out = TcpStream::connect(target).await.unwrap();
            let mut tls_stream = connector.connect(target_name, out).await.unwrap();

            let (_io, server_connection) = tls_stream.get_ref();

            let mut exporter = [0u8; 32];
            server_connection
                .export_keying_material(
                    &mut exporter,
                    EXPORTER_LABEL,
                    None, // context
                )
                .unwrap();

            let cert_chain = server_connection.peer_certificates().unwrap().to_owned();

            let mut length_bytes = [0; 4];
            tls_stream.read_exact(&mut length_bytes).await.unwrap();
            let length: usize = u32::from_be_bytes(length_bytes).try_into().unwrap();

            let mut buf = vec![0; length];
            tls_stream.read_exact(&mut buf).await.unwrap();

            if !attestation_platform.verify_attestation(buf, &cert_chain, exporter) {
                panic!("Cannot verify attestation");
            };

            let (mut inbound_reader, mut inbound_writer) = inbound.into_split();
            let (mut outbound_reader, mut outbound_writer) = tokio::io::split(tls_stream);

            let client_to_server = tokio::io::copy(&mut inbound_reader, &mut outbound_writer);
            let server_to_client = tokio::io::copy(&mut outbound_reader, &mut inbound_writer);
            tokio::try_join!(client_to_server, server_to_client).unwrap();
        });

        Ok(())
    }
}

pub trait AttestationPlatform {
    fn create_attestation(&self, cert_chain: &[CertificateDer<'_>], exporter: [u8; 32]) -> Vec<u8>;

    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> bool;
}

#[derive(Clone)]
struct MockAttestation;

impl AttestationPlatform for MockAttestation {
    /// Mocks creating an attestation
    fn create_attestation(&self, cert_chain: &[CertificateDer<'_>], exporter: [u8; 32]) -> Vec<u8> {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain).unwrap();
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);
        quote_input.to_vec()
    }

    /// Mocks verifying an attestation
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> bool {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain).unwrap();
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);

        input == quote_input
    }
}

fn length_prefix(input: &[u8]) -> [u8; 4] {
    let len = input.len() as u32;
    len.to_be_bytes()
}

/// Given a certificate chain, get the [Sha256] hash of the public key of the leaf certificate
fn get_pki_hash_from_certificate_chain(
    cert_chain: &[CertificateDer<'_>],
) -> Result<[u8; 32], AttestationError> {
    let leaf_certificate = cert_chain.first().ok_or(AttestationError::NoCertificate)?;
    let (_, cert) = parse_x509_certificate(leaf_certificate.as_ref())?;
    let public_key = &cert.tbs_certificate.subject_pki;
    let key_bytes = public_key.subject_public_key.as_ref();

    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    Ok(hasher.finalize().into())
}

/// An error when generating an attestation
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Certificate chain is empty")]
    NoCertificate,
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    use rcgen::generate_simple_self_signed;
    use std::{net::SocketAddr, sync::Arc};
    use tokio_rustls::rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    };

    /// Helper to generate a self-signed certificate for testing
    pub fn generate_certificate_chain(
        name: String,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let subject_alt_names = vec![name];
        let cert_key = generate_simple_self_signed(subject_alt_names)
            .expect("Failed to generate self-signed certificate");

        let certs = vec![CertificateDer::from(cert_key.cert)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert_key.signing_key.serialize_der(),
        ));
        (certs, key)
    }

    /// Helper to generate TLS configuration for testing
    ///
    /// For the server: A given self-signed certificate
    /// For the client: A root certificate store with the server's certificate
    pub fn generate_tls_config(
        certificate_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate_chain.clone(), key)
            .expect("Failed to create rustls server config");

        let mut root_store = RootCertStore::empty();
        root_store.add(certificate_chain[0].clone()).unwrap();

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        (Arc::new(server_config), Arc::new(client_config))
    }

    async fn example_http_service() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route("/", axum::routing::get(|| async { "foobar" }));

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        addr
    }

    async fn example_service() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut inbound, _client_addr) = listener.accept().await.unwrap();
                inbound.write_all(b"some data").await.unwrap();
            }
        });

        addr
    }

    #[tokio::test]
    async fn http_proxy() {
        let target_addr = example_http_service().await;
        let target_name = "name".to_string();

        let (cert_chain, private_key) = generate_certificate_chain(target_name.clone());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server =
            ProxyServer::new_with_tls_config(cert_chain, server_config, "127.0.0.1:0", target_addr)
                .await;
        let proxy_addr = proxy_server.listener.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            proxy_addr,
            target_name.try_into().unwrap(),
        )
        .await;
        let proxy_client_addr = proxy_client.listener.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr.to_string()))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert_eq!(res, "foobar");
    }

    #[tokio::test]
    async fn raw_tcp_proxy() {
        let target_addr = example_service().await;
        let target_name = "name".to_string();

        let (cert_chain, private_key) = generate_certificate_chain(target_name.clone());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server =
            ProxyServer::new_with_tls_config(cert_chain, server_config, "127.0.0.1:0", target_addr)
                .await;
        let proxy_server_addr = proxy_server.listener.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            proxy_server_addr,
            target_name.try_into().unwrap(),
        )
        .await;
        let proxy_client_addr = proxy_client.listener.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let mut out = TcpStream::connect(proxy_client_addr).await.unwrap();

        let mut buf = [0; 9];
        out.read(&mut buf).await.unwrap();

        assert_eq!(buf[..], b"some data"[..]);
    }
}
