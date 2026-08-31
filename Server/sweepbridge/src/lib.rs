//! Reusable relay used by the sweepbridge binary and its tests.
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

pub const MAX_FRAME: usize = 65_535;

/// One client stream <-> one dedicated UDP socket toward wg0, so the WireGuard
/// server sees a normal per-peer source port.
pub async fn relay_stream<S>(stream: S, wireguard: SocketAddr) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let bind: SocketAddr = if wireguard.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let udp = Arc::new(UdpSocket::bind(bind).await?);
    udp.connect(wireguard).await?;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let up = {
        let udp = udp.clone();
        async move {
            let mut header = [0u8; 2];
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                reader.read_exact(&mut header).await?;
                let len = u16::from_be_bytes(header) as usize;
                if len == 0 || len > MAX_FRAME {
                    anyhow::bail!("bad frame length {len}");
                }
                reader.read_exact(&mut buf[..len]).await?;
                udp.send(&buf[..len]).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    let down = {
        let udp = udp.clone();
        async move {
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                let n = udp.recv(&mut buf).await?;
                if n == 0 || n > MAX_FRAME {
                    continue;
                }
                writer.write_all(&(n as u16).to_be_bytes()).await?;
                writer.write_all(&buf[..n]).await?;
                writer.flush().await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

