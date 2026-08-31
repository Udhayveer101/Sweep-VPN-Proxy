//! sweepbridge — server side of the Sweep VPN fallback rungs.
//!
//! Listens on TCP/443 (plain and TLS) and UDP/443 (QUIC) and relays the
//! WireGuard datagrams carried inside to the real WireGuard port on localhost.
//! Stream transports use a 2-byte big-endian length prefix per datagram, which
//! is exactly what `StreamTransport` in the client writes; QUIC datagrams map
//! one to one.
//!
//! The bridge is deliberately dumb: it authenticates nothing and decrypts
//! nothing. Authentication is WireGuard's, end to end, so a compromised bridge
//! cannot read or forge tunnel traffic — it can only refuse to carry it.

use anyhow::{Context, Result};
use sweepbridge::relay_stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use sweepbridge::MAX_FRAME;

#[derive(Clone)]
struct Config {
    wireguard: SocketAddr,
    tcp: Option<SocketAddr>,
    tls: Option<SocketAddr>,
    quic: Option<SocketAddr>,
    cert: Option<String>,
    key: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: sweepbridge --wireguard 127.0.0.1:51820 \\
       [--tcp 0.0.0.0:8443] [--tls 0.0.0.0:443 --cert fullchain.pem --key privkey.pem] \\
       [--quic 0.0.0.0:443 --cert fullchain.pem --key privkey.pem]"
    );
    std::process::exit(2)
}

fn parse_args() -> Config {
    let mut cfg = Config {
        wireguard: "127.0.0.1:51820".parse().unwrap(),
        tcp: None,
        tls: None,
        quic: None,
        cert: None,
        key: None,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--wireguard" => cfg.wireguard = value.unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()),
            "--tcp" => cfg.tcp = Some(value.unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage())),
            "--tls" => cfg.tls = Some(value.unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage())),
            "--quic" => cfg.quic = Some(value.unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage())),
            "--cert" => cfg.cert = value,
            "--key" => cfg.key = value,
            _ => usage(),
        }
        i += 2;
    }
    if cfg.tcp.is_none() && cfg.tls.is_none() && cfg.quic.is_none() {
        usage();
    }
    cfg
}

async fn serve_tcp(addr: SocketAddr, wireguard: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
    eprintln!("sweepbridge: TCP on {addr} -> {wireguard}");
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        tokio::spawn(async move {
            let _ = relay_stream(stream, wireguard).await;
        });
    }
}

async fn serve_tls(addr: SocketAddr, wireguard: SocketAddr, cert: &str, key: &str) -> Result<()> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .context("no private key in file")?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // Advertise h2 so the handshake looks like an ordinary HTTPS server.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
    eprintln!("sweepbridge: TLS on {addr} -> {wireguard}");
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(stream).await {
                let _ = relay_stream(tls, wireguard).await;
            }
        });
    }
}

async fn serve_quic(addr: SocketAddr, wireguard: SocketAddr, cert: &str, key: &str) -> Result<()> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .context("no private key in file")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let endpoint = quinn::Endpoint::server(quic_config, addr)?;
    eprintln!("sweepbridge: QUIC on {addr} -> {wireguard}");

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(connection) = connecting.await else { return };
            let bind: SocketAddr = if wireguard.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let Ok(udp) = UdpSocket::bind(bind).await else { return };
            if udp.connect(wireguard).await.is_err() {
                return;
            }
            let udp = Arc::new(udp);
            let down = {
                let udp = udp.clone();
                let connection = connection.clone();
                async move {
                    let mut buf = vec![0u8; MAX_FRAME];
                    loop {
                        let Ok(n) = udp.recv(&mut buf).await else { break };
                        if connection.send_datagram(buf[..n].to_vec().into()).is_err() {
                            break;
                        }
                    }
                }
            };
            let up = async move {
                while let Ok(datagram) = connection.read_datagram().await {
                    if udp.send(&datagram).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(up, down);
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = parse_args();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tasks = Vec::new();
    if let Some(addr) = cfg.tcp {
        let wg = cfg.wireguard;
        tasks.push(tokio::spawn(async move { serve_tcp(addr, wg).await }));
    }
    if let Some(addr) = cfg.tls {
        let (cert, key) = (cfg.cert.clone().unwrap_or_else(|| usage()), cfg.key.clone().unwrap_or_else(|| usage()));
        let wg = cfg.wireguard;
        tasks.push(tokio::spawn(async move { serve_tls(addr, wg, &cert, &key).await }));
    }
    if let Some(addr) = cfg.quic {
        let (cert, key) = (cfg.cert.clone().unwrap_or_else(|| usage()), cfg.key.clone().unwrap_or_else(|| usage()));
        let wg = cfg.wireguard;
        tasks.push(tokio::spawn(async move { serve_quic(addr, wg, &cert, &key).await }));
    }
    for task in tasks {
        task.await??;
    }
    Ok(())
}
