// C ABI over the OpenVPN 3 client library.
//
// Mirrors the shape of `DataPlane/sweepwg` (the boringtun shim): no protocol
// logic and no cryptography lives here, only the marshalling needed to reach a
// C++ library from Swift. OpenVPN 3 is the same core that ships in OpenVPN
// Connect, so the protocol work is theirs, not ours.
//
// How packets move: OpenVPN 3 wants a tun file descriptor. Inside a
// NEPacketTunnelProvider there is no such descriptor — there is `packetFlow`.
// So `tun_builder_establish()` hands OpenVPN 3 one end of a datagram
// socketpair and keeps the other; a pump thread turns that into the packet
// callbacks below. SOCK_DGRAM is deliberate: it preserves packet boundaries,
// which a stream socket would smear together.

#ifndef SWEEPOVPN_H
#define SWEEPOVPN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SweepOvpnClient SweepOvpnClient;

/// One plaintext IP packet arriving from the tunnel. `family` is AF_INET or
/// AF_INET6, which NEPacketTunnelProvider needs alongside the bytes; the utun
/// framing OpenVPN 3 uses internally is stripped before this is called.
typedef void (*sweep_ovpn_packet_cb)(void *ctx, const uint8_t *data, size_t len, int32_t family);

/// Connection lifecycle. `name` is OpenVPN 3's own event name — CONNECTED,
/// AUTH_FAILED, DISCONNECTED and so on — passed through unchanged rather than
/// remapped, so nothing is lost in translation on the way to the UI.
typedef void (*sweep_ovpn_event_cb)(void *ctx, const char *name, const char *info);

/// The tunnel settings the server pushed, as JSON, delivered once just before
/// the tunnel comes up. The client cannot know these in advance: an OpenVPN
/// relay assigns the address, resolvers and routes in its PUSH_REPLY.
///
///   {"mtu":1500,"remote":"61.6.43.75",
///    "addresses":[{"address":"10.211.1.57","prefix":32,"gateway":"10.211.1.58","ipv6":false}],
///    "dns":["10.211.254.254","8.8.8.8"],
///    "routes":[{"address":"0.0.0.0","prefix":0,"ipv6":false,"exclude":false}],
///    "redirectGateway":true}
typedef void (*sweep_ovpn_tun_cb)(void *ctx, const char *settings_json);

/// Log lines from the core, for the diagnostics ring buffer.
typedef void (*sweep_ovpn_log_cb)(void *ctx, const char *line);

/// Process-wide one-time init. Safe to call more than once.
void sweep_ovpn_init_process(void);

/// Build a client for a full `.ovpn` profile. Returns NULL if the profile does
/// not parse. Nothing connects until `sweep_ovpn_start`.
SweepOvpnClient *sweep_ovpn_new(const char *profile,
                                sweep_ovpn_packet_cb packet_cb,
                                sweep_ovpn_event_cb event_cb,
                                sweep_ovpn_tun_cb tun_cb,
                                sweep_ovpn_log_cb log_cb,
                                void *ctx);

/// Connect on a background thread. Returns 0 if the thread started.
/// Authentication is reported through the event callback, never here: a
/// started thread is not a connected tunnel.
int sweep_ovpn_start(SweepOvpnClient *client);

/// Hand one plaintext IP packet to the tunnel.
void sweep_ovpn_send(SweepOvpnClient *client, const uint8_t *data, size_t len);

/// Ask the session to stop; the event callback reports DISCONNECTED.
void sweep_ovpn_stop(SweepOvpnClient *client);

/// Tell the core the network changed, so it re-establishes rather than sitting
/// on a dead socket after a roam.
void sweep_ovpn_reconnect(SweepOvpnClient *client);

/// Cumulative byte counters for the UI.
void sweep_ovpn_stats(SweepOvpnClient *client, uint64_t *tx, uint64_t *rx);

/// Stops if still running, joins the thread, then frees.
void sweep_ovpn_free(SweepOvpnClient *client);

#ifdef __cplusplus
}
#endif

#endif /* SWEEPOVPN_H */
