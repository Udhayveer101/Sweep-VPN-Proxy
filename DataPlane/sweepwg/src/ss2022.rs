//! Shadowsocks-2022 client as a loopback TCP tunnel.
//!
//! Rung 5 needs an AEAD-2022 transport with no plaintext handshake for a DPI box
//! to fingerprint. Rather than re-implement the protocol (and its crypto), this
//! runs the upstream `shadowsocks` crate's client against a stock
//! `ssserver` and exposes it as a plain TCP listener on 127.0.0.1. The Swift
//! side then reuses the ordinary stream transport and framing.
//!
//! No cryptography is implemented here.

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyClientStream;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

pub struct SsTunnel {
    runtime: Runtime,
    port: u16,
}

fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

/// Start a loopback tunnel: everything written to 127.0.0.1:<returned port> is
/// carried inside a Shadowsocks-2022 connection to `server_host:server_port` and
/// delivered to `target_host:target_port` (the WireGuard port on the VPS).
/// Returns 0 on failure.
#[no_mangle]
pub extern "C" fn sweepss_start(
    server_host: *const c_char,
    server_port: u16,
    password_b64: *const c_char,
    target_host: *const c_char,
    target_port: u16,
    out: *mut *mut SsTunnel,
) -> u16 {
    let (Some(server_host), Some(password), Some(target_host)) =
        (cstr(server_host), cstr(password_b64), cstr(target_host))
    else {
        return 0;
    };

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    else {
        return 0;
    };

    let config = match ServerConfig::new(
        (server_host, server_port),
        password,
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    ) {
        Ok(c) => Arc::new(c),
        Err(_) => return 0,
    };
    let target = Address::DomainNameAddress(target_host, target_port);

    let listener = match runtime.block_on(TcpListener::bind("127.0.0.1:0")) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return 0,
    };

    let context = Context::new_shared(ServerType::Local);
    runtime.spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                break;
            };
            let context = context.clone();
            let config = config.clone();
            let target = target.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) =
                    ProxyClientStream::connect(context, &config, target).await
                {
                    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });

    let tunnel = Box::into_raw(Box::new(SsTunnel { runtime, port }));
    unsafe { *out = tunnel };
    port
}

#[no_mangle]
pub extern "C" fn sweepss_stop(t: *mut SsTunnel) {
    if !t.is_null() {
        let tunnel = unsafe { Box::from_raw(t) };
        tunnel.runtime.shutdown_background();
    }
}

#[no_mangle]
pub extern "C" fn sweepss_port(t: *mut SsTunnel) -> u16 {
    if t.is_null() {
        0
    } else {
        unsafe { (*t).port }
    }
}
