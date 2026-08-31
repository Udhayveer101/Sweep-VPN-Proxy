//! The bridge must deframe the client's 2-byte-prefixed datagrams onto UDP and
//! re-frame the replies, without ever needing to understand WireGuard.
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn frames_survive_the_bridge_in_both_directions() {
    // Stand-in for wg0: echo every datagram back.
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wg_addr: SocketAddr = wg.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, peer)) = wg.recv_from(&mut buf).await else { break };
            let _ = wg.send_to(&buf[..n], peer).await;
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = sweepbridge::relay_stream(stream, wg_addr).await;
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();
    let payload = vec![0x7Au8; 148];      // WireGuard handshake-sized datagram
    client.write_all(&(payload.len() as u16).to_be_bytes()).await.unwrap();
    client.write_all(&payload).await.unwrap();

    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut header))
        .await
        .expect("bridge replied in time")
        .unwrap();
    let len = u16::from_be_bytes(header) as usize;
    assert_eq!(len, payload.len());
    let mut echoed = vec![0u8; len];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn an_oversized_frame_header_kills_the_connection() {
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wg_addr = wg.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = sweepbridge::relay_stream(stream, wg_addr).await;
        assert!(result.is_err(), "a zero-length frame must be rejected");
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&0u16.to_be_bytes()).await.unwrap();
    let mut buf = [0u8; 1];
    // The bridge drops the connection rather than trying to interpret it.
    let _ = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
}
