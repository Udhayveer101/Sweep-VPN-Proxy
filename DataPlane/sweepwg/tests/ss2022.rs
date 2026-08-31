//! Verifies the Shadowsocks-2022 rung against a *real* stock `ssserver`
//! (shadowsocks-rust). If ssserver is not installed the test skips rather than
//! pretending to pass.
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use sweepwg::ss2022::*;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn tunnels_bytes_through_a_real_shadowsocks_2022_server() {
    if Command::new("ssserver").arg("--version").stdout(Stdio::null()).status().is_err() {
        eprintln!("skipping: ssserver not installed");
        return;
    }

    // A plain TCP echo server standing in for the WireGuard port on the VPS.
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in echo.incoming() {
            let mut s = stream.unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 32-byte PSK, base64 — the AEAD-2022 key format.
    let psk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let ss_port = free_port();
    let server = Server(
        Command::new("ssserver")
            .args([
                "-s", &format!("127.0.0.1:{ss_port}"),
                "-k", psk,
                "-m", "2022-blake3-aes-256-gcm",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ssserver"),
    );
    thread::sleep(Duration::from_millis(700));

    let mut handle: *mut SsTunnel = std::ptr::null_mut();
    let local_port = sweepss_start(
        CString::new("127.0.0.1").unwrap().as_ptr(),
        ss_port,
        CString::new(psk).unwrap().as_ptr(),
        CString::new("127.0.0.1").unwrap().as_ptr(),
        echo_port,
        &mut handle,
    );
    assert!(local_port > 0, "loopback tunnel failed to start");
    assert_eq!(sweepss_port(handle), local_port);
    thread::sleep(Duration::from_millis(300));

    let mut client = TcpStream::connect(("127.0.0.1", local_port)).expect("connect to tunnel");
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // A framed WireGuard-sized datagram.
    let payload = vec![0xABu8; 148];
    client.write_all(&payload).unwrap();

    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).expect("echo through the shadowsocks tunnel");
    assert_eq!(out, payload, "bytes survive the SS2022 round trip");

    sweepss_stop(handle);
    drop(server);
}
