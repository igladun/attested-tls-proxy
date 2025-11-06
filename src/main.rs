use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use attested_tls_proxy::{MockAttestation, NoAttestation, ProxyClient, ProxyServer, TlsCertAndKey};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Socket address to listen on
    #[arg(short, long)]
    address: SocketAddr,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        #[arg(short, long)]
        server_address: SocketAddr,
        #[arg(long)]
        server_name: String,
        /// The path to a PEM encoded private key for client authentication
        #[arg(long)]
        private_key: Option<PathBuf>,
        /// The path to a PEM encoded certificate chain for client authentication
        #[arg(long)]
        cert_chain: Option<PathBuf>,
    },
    /// Run a proxy server
    Server {
        /// Socket address of the target service to forward traffic to
        #[arg(short, long)]
        target_address: SocketAddr,
        /// The path to a PEM encoded private key
        #[arg(long)]
        private_key: PathBuf,
        /// The path to a PEM encoded certificate chain
        #[arg(long)]
        cert_chain: PathBuf,
        #[arg(long)]
        client_auth: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Client {
            server_name,
            server_address,
            private_key,
            cert_chain,
        } => {
            let tls_cert_and_chain = private_key
                .map(|private_key| load_tls_cert_and_key(cert_chain.unwrap(), private_key));

            let client = ProxyClient::new(
                tls_cert_and_chain,
                cli.address,
                server_address,
                server_name.try_into().unwrap(),
                NoAttestation,
                MockAttestation,
            )
            .await;

            loop {
                client.accept().await.unwrap();
            }
        }
        CliCommand::Server {
            target_address,
            private_key,
            cert_chain,
            client_auth,
        } => {
            let tls_cert_and_chain = load_tls_cert_and_key(cert_chain, private_key);
            let local_attestation = MockAttestation;
            let remote_attestation = NoAttestation;

            let server = ProxyServer::new(
                tls_cert_and_chain,
                cli.address,
                target_address,
                local_attestation,
                remote_attestation,
                client_auth,
            )
            .await;

            loop {
                server.accept().await.unwrap();
            }
        }
    }
}

fn load_tls_cert_and_key(cert_chain: PathBuf, private_key: PathBuf) -> TlsCertAndKey {
    let key = load_private_key_pem(private_key);
    let cert_chain = load_certs_pem(cert_chain).unwrap();
    TlsCertAndKey { key, cert_chain }
}

pub fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    Ok(
        rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
            .map(|res| res.unwrap())
            .collect(),
    )
}

pub fn load_private_key_pem(path: PathBuf) -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(File::open(path).unwrap());

    // Tries to read the key as PKCS#8, PKCS#1, or SEC1
    let pks8_key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .unwrap()
        .unwrap();

    PrivateKeyDer::Pkcs8(pks8_key)
}
