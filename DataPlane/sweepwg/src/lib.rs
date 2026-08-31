//! Minimal C ABI over boringtun's `Tunn` state machine.
//!
//! Deliberately thin: key handling, timers and packet framing stay in the Rust
//! crate that already implements WireGuard; Swift only moves bytes between the
//! NEPacketTunnelProvider's packetFlow / UDP socket and these calls.
//! No cryptography is implemented in this file.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::os::raw::{c_char, c_int};
use std::ffi::CStr;
use std::slice;

pub const SWEEPWG_DONE: c_int = 0;
pub const SWEEPWG_WRITE_TO_NETWORK: c_int = 1;
pub const SWEEPWG_WRITE_TO_TUNNEL_V4: c_int = 2;
pub const SWEEPWG_WRITE_TO_TUNNEL_V6: c_int = 3;
pub const SWEEPWG_ERROR: c_int = -1;

pub struct SweepTunnel {
    tun: Tunn,
}

fn key32(b64: *const c_char) -> Option<[u8; 32]> {
    if b64.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(b64) }.to_str().ok()?;
    let raw = STANDARD.decode(s).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

/// Create a tunnel. `preshared_key_b64` may be null; when present it is the
/// ML-KEM-768-derived hybrid PSK (see SweepVPNCore/PostQuantum.swift).
#[no_mangle]
pub extern "C" fn sweepwg_new(
    private_key_b64: *const c_char,
    peer_public_key_b64: *const c_char,
    preshared_key_b64: *const c_char,
    keepalive_seconds: u16,
    index: u32,
) -> *mut SweepTunnel {
    let (Some(sk), Some(pk)) = (key32(private_key_b64), key32(peer_public_key_b64)) else {
        return std::ptr::null_mut();
    };
    let psk = key32(preshared_key_b64);
    let keepalive = if keepalive_seconds == 0 { None } else { Some(keepalive_seconds) };
    let tun = Tunn::new(StaticSecret::from(sk), PublicKey::from(pk), psk, keepalive, index, None);
    Box::into_raw(Box::new(SweepTunnel { tun }))
}

#[no_mangle]
pub extern "C" fn sweepwg_free(t: *mut SweepTunnel) {
    if !t.is_null() {
        unsafe { drop(Box::from_raw(t)) };
    }
}

/// Replace the peer's preshared key (used for the post-quantum rekey) by
/// rebuilding the Tunn — boringtun has no in-place PSK setter.
#[no_mangle]
pub extern "C" fn sweepwg_set_psk(
    t: *mut SweepTunnel,
    private_key_b64: *const c_char,
    peer_public_key_b64: *const c_char,
    preshared_key_b64: *const c_char,
    keepalive_seconds: u16,
    index: u32,
) -> c_int {
    if t.is_null() {
        return SWEEPWG_ERROR;
    }
    let (Some(sk), Some(pk)) = (key32(private_key_b64), key32(peer_public_key_b64)) else {
        return SWEEPWG_ERROR;
    };
    let psk = key32(preshared_key_b64);
    let keepalive = if keepalive_seconds == 0 { None } else { Some(keepalive_seconds) };
    let tun = Tunn::new(StaticSecret::from(sk), PublicKey::from(pk), psk, keepalive, index, None);
    unsafe { (*t).tun = tun };
    SWEEPWG_DONE
}

fn map(res: TunnResult, out_len: *mut usize) -> c_int {
    match res {
        TunnResult::Done => SWEEPWG_DONE,
        TunnResult::Err(_) => SWEEPWG_ERROR,
        TunnResult::WriteToNetwork(b) => {
            unsafe { *out_len = b.len() };
            SWEEPWG_WRITE_TO_NETWORK
        }
        TunnResult::WriteToTunnelV4(b, _) => {
            unsafe { *out_len = b.len() };
            SWEEPWG_WRITE_TO_TUNNEL_V4
        }
        TunnResult::WriteToTunnelV6(b, _) => {
            unsafe { *out_len = b.len() };
            SWEEPWG_WRITE_TO_TUNNEL_V6
        }
    }
}

/// Plaintext IP packet -> encrypted transport packet in `dst`.
#[no_mangle]
pub extern "C" fn sweepwg_encapsulate(
    t: *mut SweepTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if t.is_null() || src.is_null() || dst.is_null() {
        return SWEEPWG_ERROR;
    }
    let src = unsafe { slice::from_raw_parts(src, src_len) };
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_cap) };
    let res = unsafe { (*t).tun.encapsulate(src, dst) };
    map(res, out_len)
}

/// Encrypted transport packet -> plaintext IP packet (or a handshake reply).
#[no_mangle]
pub extern "C" fn sweepwg_decapsulate(
    t: *mut SweepTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if t.is_null() || dst.is_null() {
        return SWEEPWG_ERROR;
    }
    let src = if src.is_null() || src_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(src, src_len) }
    };
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_cap) };
    let res = unsafe { (*t).tun.decapsulate(None, src, dst) };
    map(res, out_len)
}

/// Drive timers: handshake initiation, rekey, keepalive, expiry.
#[no_mangle]
pub extern "C" fn sweepwg_tick(
    t: *mut SweepTunnel,
    dst: *mut u8,
    dst_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if t.is_null() || dst.is_null() {
        return SWEEPWG_ERROR;
    }
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_cap) };
    let res = unsafe { (*t).tun.update_timers(dst) };
    map(res, out_len)
}

/// Force a handshake initiation (used on connect and after roaming).
#[no_mangle]
pub extern "C" fn sweepwg_force_handshake(
    t: *mut SweepTunnel,
    dst: *mut u8,
    dst_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if t.is_null() || dst.is_null() {
        return SWEEPWG_ERROR;
    }
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_cap) };
    let res = unsafe { (*t).tun.format_handshake_initiation(dst, true) };
    map(res, out_len)
}

/// Seconds since the last completed handshake, or -1 if none yet.
/// This is the signal the provider uses to decide "authenticated" — the
/// blackhole stays armed until it is >= 0.
#[no_mangle]
pub extern "C" fn sweepwg_seconds_since_handshake(t: *mut SweepTunnel) -> i64 {
    if t.is_null() {
        return -1;
    }
    match unsafe { (*t).tun.stats().0 } {
        Some(d) => d.as_secs() as i64,
        None => -1,
    }
}

/// tx/rx byte counters for the diagnostics view.
#[no_mangle]
pub extern "C" fn sweepwg_transfer(t: *mut SweepTunnel, tx: *mut u64, rx: *mut u64) -> c_int {
    if t.is_null() {
        return SWEEPWG_ERROR;
    }
    let stats = unsafe { (*t).tun.stats() };
    unsafe {
        *tx = stats.1 as u64;
        *rx = stats.2 as u64;
    }
    SWEEPWG_DONE
}
