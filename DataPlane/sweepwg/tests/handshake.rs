//! Proves the C ABI actually completes a real WireGuard handshake and carries
//! a data packet, by wiring two sweepwg tunnels back to back in-process.
use std::ffi::CString;
use sweepwg::*;

fn b64(k: &[u8; 32]) -> CString {
    use base64::{engine::general_purpose::STANDARD, Engine};
    CString::new(STANDARD.encode(k)).unwrap()
}

fn keypair() -> ([u8; 32], [u8; 32]) {
    use boringtun::x25519::{PublicKey, StaticSecret};
    use rand_core::OsRng;
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (sk.to_bytes(), pk.to_bytes())
}

struct Buf(Vec<u8>);
impl Buf {
    fn new() -> Self { Buf(vec![0u8; 2048]) }
}

#[test]
fn two_peers_complete_handshake_and_exchange_data() {
    let (a_sk, a_pk) = keypair();
    let (b_sk, b_pk) = keypair();
    let psk = [7u8; 32];

    let a = sweepwg_new(b64(&a_sk).as_ptr(), b64(&b_pk).as_ptr(), b64(&psk).as_ptr(), 25, 1);
    let b = sweepwg_new(b64(&b_sk).as_ptr(), b64(&a_pk).as_ptr(), b64(&psk).as_ptr(), 25, 2);
    assert!(!a.is_null() && !b.is_null());
    assert_eq!(sweepwg_seconds_since_handshake(a), -1, "no handshake yet");

    let mut out = Buf::new();
    let mut n = 0usize;

    // initiation A -> B
    let r = sweepwg_force_handshake(a, out.0.as_mut_ptr(), out.0.len(), &mut n);
    assert_eq!(r, SWEEPWG_WRITE_TO_NETWORK);
    let init = out.0[..n].to_vec();

    // response B -> A
    let mut out2 = Buf::new();
    let mut n2 = 0usize;
    let r = sweepwg_decapsulate(b, init.as_ptr(), init.len(), out2.0.as_mut_ptr(), out2.0.len(), &mut n2);
    assert_eq!(r, SWEEPWG_WRITE_TO_NETWORK);
    let resp = out2.0[..n2].to_vec();

    let mut out3 = Buf::new();
    let mut n3 = 0usize;
    let r = sweepwg_decapsulate(a, resp.as_ptr(), resp.len(), out3.0.as_mut_ptr(), out3.0.len(), &mut n3);
    assert!(r == SWEEPWG_DONE || r == SWEEPWG_WRITE_TO_NETWORK);
    assert!(sweepwg_seconds_since_handshake(a) >= 0, "A is authenticated");

    // A sends a real IPv4 packet through the tunnel; B must recover it verbatim.
    let packet: Vec<u8> = {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;                 // IPv4, IHL 5
        p[2] = 0; p[3] = 20;         // total length
        p[9] = 1;                    // ICMP
        p[12..16].copy_from_slice(&[10, 64, 0, 2]);
        p[16..20].copy_from_slice(&[10, 64, 0, 1]);
        p
    };
    let mut enc = Buf::new();
    let mut ne = 0usize;
    let r = sweepwg_encapsulate(a, packet.as_ptr(), packet.len(), enc.0.as_mut_ptr(), enc.0.len(), &mut ne);
    assert_eq!(r, SWEEPWG_WRITE_TO_NETWORK);
    let ct = enc.0[..ne].to_vec();
    assert_ne!(ct[..], packet[..], "traffic on the wire is not plaintext");

    let mut dec = Buf::new();
    let mut nd = 0usize;
    let r = sweepwg_decapsulate(b, ct.as_ptr(), ct.len(), dec.0.as_mut_ptr(), dec.0.len(), &mut nd);
    assert_eq!(r, SWEEPWG_WRITE_TO_TUNNEL_V4);
    assert_eq!(&dec.0[..nd], &packet[..], "plaintext survives the round trip");

    // A forged/corrupted transport packet must be rejected, never forwarded.
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    let mut junk = Buf::new();
    let mut nj = 0usize;
    let r = sweepwg_decapsulate(b, bad.as_ptr(), bad.len(), junk.0.as_mut_ptr(), junk.0.len(), &mut nj);
    assert_eq!(r, SWEEPWG_ERROR, "tampered packet is dropped");

    // Replaying an already-accepted packet must also be rejected.
    let mut rep = Buf::new();
    let mut nr = 0usize;
    let r = sweepwg_decapsulate(b, ct.as_ptr(), ct.len(), rep.0.as_mut_ptr(), rep.0.len(), &mut nr);
    assert_eq!(r, SWEEPWG_ERROR, "replayed packet is dropped");

    // Wrong PSK must not authenticate: rebuild B with a different PSK.
    let other = [9u8; 32];
    assert_eq!(
        sweepwg_set_psk(b, b64(&b_sk).as_ptr(), b64(&a_pk).as_ptr(), b64(&other).as_ptr(), 25, 2),
        SWEEPWG_DONE
    );
    let mut out4 = Buf::new();
    let mut n4 = 0usize;
    let r = sweepwg_force_handshake(a, out4.0.as_mut_ptr(), out4.0.len(), &mut n4);
    assert_eq!(r, SWEEPWG_WRITE_TO_NETWORK);
    let init2 = out4.0[..n4].to_vec();
    let mut out5 = Buf::new();
    let mut n5 = 0usize;
    // The PSK is mixed at the response stage, so B still answers; A must reject
    // that response and stay unauthenticated.
    let r = sweepwg_decapsulate(b, init2.as_ptr(), init2.len(), out5.0.as_mut_ptr(), out5.0.len(), &mut n5);
    assert_eq!(r, SWEEPWG_WRITE_TO_NETWORK);
    let resp2 = out5.0[..n5].to_vec();
    let mut out6 = Buf::new();
    let mut n6 = 0usize;
    let r = sweepwg_decapsulate(a, resp2.as_ptr(), resp2.len(), out6.0.as_mut_ptr(), out6.0.len(), &mut n6);
    assert_eq!(r, SWEEPWG_ERROR, "PSK mismatch fails the handshake");

    sweepwg_free(a);
    sweepwg_free(b);
}
