// C ABI for the sweepwg WireGuard data plane (boringtun).
#ifndef SWEEPWG_H
#define SWEEPWG_H
#include <stdint.h>
#include <stddef.h>

#define SWEEPWG_DONE 0
#define SWEEPWG_WRITE_TO_NETWORK 1
#define SWEEPWG_WRITE_TO_TUNNEL_V4 2
#define SWEEPWG_WRITE_TO_TUNNEL_V6 3
#define SWEEPWG_ERROR -1

typedef struct SweepTunnel SweepTunnel;

SweepTunnel *sweepwg_new(const char *private_key_b64, const char *peer_public_key_b64,
                         const char *preshared_key_b64, uint16_t keepalive_seconds, uint32_t index);
void sweepwg_free(SweepTunnel *t);
int sweepwg_set_psk(SweepTunnel *t, const char *private_key_b64, const char *peer_public_key_b64,
                    const char *preshared_key_b64, uint16_t keepalive_seconds, uint32_t index);
int sweepwg_encapsulate(SweepTunnel *t, const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len);
int sweepwg_decapsulate(SweepTunnel *t, const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len);
int sweepwg_tick(SweepTunnel *t, uint8_t *dst, size_t dst_cap, size_t *out_len);
int sweepwg_force_handshake(SweepTunnel *t, uint8_t *dst, size_t dst_cap, size_t *out_len);
int64_t sweepwg_seconds_since_handshake(SweepTunnel *t);
int sweepwg_transfer(SweepTunnel *t, uint64_t *tx, uint64_t *rx);
#endif
