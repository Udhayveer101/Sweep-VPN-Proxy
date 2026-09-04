// End-to-end check for the shim, outside the app.
//
// Connects to a real relay, prints the pushed tun settings, then builds an
// actual IPv4/UDP DNS query, pushes it through the tunnel, and waits for the
// reply to come back out. A reply proves the whole path: encrypt, relay,
// decrypt, and the socketpair bridge in both directions. Anything less than
// that only proves the handshake, which we already knew worked.
//
//   ./harness relay.ovpn

#include "sweepovpn.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static SweepOvpnClient *g_client;
static char g_dns[64];
static char g_local[64];
static int g_got_reply;
static int g_sent;
static int g_replies;
static size_t build_packet(uint8_t *buf, const char *src, const char *dst);
static int g_probes;
static time_t g_last_reply;

/// Re-arms the same probe the CONNECTED path sends, so a soak run can tell
/// "still carrying packets" from "still nominally connected".
static void probe(void)
{
    if (!g_local[0] || !g_dns[0]) return;
    uint8_t pkt[128];
    const size_t n = build_packet(pkt, g_local, g_dns);
    g_probes++;
    sweep_ovpn_send(g_client, pkt, n);
}

static uint16_t checksum(const void *data, size_t len, uint32_t seed)
{
    const uint16_t *w = data;
    uint32_t sum = seed;
    while (len > 1) { sum += *w++; len -= 2; }
    if (len) sum += *(const uint8_t *)w;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/// Minimal A-query for example.com.
static size_t build_dns_query(uint8_t *out)
{
    static const uint8_t q[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
    memcpy(out, q, sizeof(q));
    return sizeof(q);
}

static size_t build_packet(uint8_t *buf, const char *src, const char *dst)
{
    uint8_t dns[64];
    const size_t dns_len = build_dns_query(dns);

    const size_t udp_len = 8 + dns_len;
    const size_t total = 20 + udp_len;
    memset(buf, 0, total);

    buf[0] = 0x45;                       // IPv4, IHL 5
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xFF);
    buf[4] = 0x1a; buf[5] = 0x2b;        // id
    buf[6] = 0x40;                       // don't fragment
    buf[8] = 64;                         // TTL
    buf[9] = 17;                         // UDP
    inet_pton(AF_INET, src, buf + 12);
    inet_pton(AF_INET, dst, buf + 16);
    const uint16_t ip_ck = checksum(buf, 20, 0);
    memcpy(buf + 10, &ip_ck, 2);

    uint8_t *udp = buf + 20;
    udp[0] = 0xC0; udp[1] = 0x00;        // sport 49152
    udp[2] = 0x00; udp[3] = 0x35;        // dport 53
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)(udp_len & 0xFF);
    memcpy(udp + 8, dns, dns_len);

    // UDP checksum over the pseudo-header.
    uint32_t sum = 0;
    const uint16_t *s = (const uint16_t *)(buf + 12);
    for (int i = 0; i < 4; i++) sum += s[i];       // src + dst
    sum += htons(17);
    sum += htons((uint16_t)udp_len);
    const uint16_t ck = checksum(udp, udp_len, sum);
    memcpy(udp + 6, &ck, 2);

    return total;
}

static void on_packet(void *ctx, const uint8_t *data, size_t len, int32_t family)
{
    (void)ctx; (void)family;
    if (len < 28 || (data[0] >> 4) != 4) return;
    char src[64];
    inet_ntop(AF_INET, data + 12, src, sizeof(src));
    const uint8_t proto = data[9];
    if (proto == 17) {
        const uint8_t *udp = data + ((data[0] & 0x0F) * 4);
        const uint16_t sport = (uint16_t)((udp[0] << 8) | udp[1]);
        if (sport == 53) {
            printf("  <-- DNS REPLY from %s, %zu bytes  ** DATA PLANE WORKS **\n", src, len);
            g_got_reply = 1;
            g_replies++;
            return;
        }
    }
    printf("  <-- inbound proto=%u from %s (%zu bytes)\n", proto, src, len);
}

static void on_tun(void *ctx, const char *json)
{
    (void)ctx;
    printf("TUN SETTINGS: %s\n", json);

    // Pull the assigned address and the first DNS server out of the JSON by
    // hand — the harness has no JSON library and only needs two fields.
    const char *a = strstr(json, "\"address\":\"");
    if (a) {
        a += 11;
        const char *e = strchr(a, '"');
        if (e && (size_t)(e - a) < sizeof(g_local)) {
            memcpy(g_local, a, (size_t)(e - a));
            g_local[e - a] = 0;
        }
    }
    const char *d = strstr(json, "\"dns\":[\"");
    if (d) {
        d += 8;
        const char *e = strchr(d, '"');
        if (e && (size_t)(e - d) < sizeof(g_dns)) {
            memcpy(g_dns, d, (size_t)(e - d));
            g_dns[e - d] = 0;
        }
    }
    // Some relays push an internal resolver that does not answer; SWEEP_DNS
    // aims the probe at a public one they also push, so a silent resolver is
    // not mistaken for a dead tunnel.
    const char *override = getenv("SWEEP_DNS");
    if (override && strlen(override) < sizeof(g_dns)) snprintf(g_dns, sizeof(g_dns), "%s", override);
    printf("  local=%s dns=%s\n", g_local, g_dns);
}

static void on_event(void *ctx, const char *name, const char *info)
{
    (void)ctx;
    printf("EVENT %s %s\n", name, info ? info : "");

    if (strcmp(name, "CONNECTED") == 0 && !g_sent) {
        g_sent = 1;
        if (!g_local[0] || !g_dns[0]) {
            printf("  (no pushed address/dns, cannot send a probe packet)\n");
            return;
        }
        uint8_t pkt[128];
        const size_t n = build_packet(pkt, g_local, g_dns);
        printf("  --> sending %zu-byte DNS query %s -> %s\n", n, g_local, g_dns);
        sweep_ovpn_send(g_client, pkt, n);
    }
}

static void on_log(void *ctx, const char *line)
{
    (void)ctx;
    // Quiet by default; the events carry what matters.
    if (getenv("SWEEP_VERBOSE")) printf("log: %s", line);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: harness profile.ovpn\n"); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *profile = malloc((size_t)size + 1);
    if (fread(profile, 1, (size_t)size, f) != (size_t)size) { perror("read"); return 2; }
    profile[size] = 0;
    fclose(f);

    g_client = sweep_ovpn_new(profile, on_packet, on_event, on_tun, on_log, NULL);
    if (!g_client) { fprintf(stderr, "profile did not parse\n"); return 1; }

    if (sweep_ovpn_start(g_client) != 0) { fprintf(stderr, "start failed\n"); return 1; }

    const char *soak = getenv("SWEEP_SOAK");
    if (soak) {
        // Soak mode: keep probing for N seconds and report the first gap. A
        // session that stays "connected" while replies stop is the failure we
        // are actually chasing, and only a repeated probe can see it.
        const int secs = atoi(soak);
        const time_t start = time(NULL);
        g_last_reply = start;
        int reported_gap = 0;
        for (int i = 0; i < secs; i++) {
            sleep(1);
            if (g_sent && (i % 2) == 0) probe();
            if (g_replies) g_last_reply = g_got_reply ? time(NULL) : g_last_reply;
            if (g_got_reply) { g_got_reply = 0; g_last_reply = time(NULL); }
            const long gap = (long)(time(NULL) - g_last_reply);
            if (gap >= 10 && !reported_gap) {
                printf("!! %lds elapsed: NO REPLY for %lds (probes=%d replies=%d)\n",
                       (long)(time(NULL) - start), gap, g_probes, g_replies);
                reported_gap = 1;
            }
            if (gap < 10) reported_gap = 0;
            if ((i % 15) == 0) {
                uint64_t tx = 0, rx = 0;
                sweep_ovpn_stats(g_client, &tx, &rx);
                printf("== %4lds  probes=%d replies=%d tun tx=%llu rx=%llu\n",
                       (long)(time(NULL) - start), g_probes, g_replies,
                       (unsigned long long)tx, (unsigned long long)rx);
                fflush(stdout);
            }
        }
        uint64_t tx = 0, rx = 0;
        sweep_ovpn_stats(g_client, &tx, &rx);
        printf("SOAK DONE probes=%d replies=%d tx=%llu rx=%llu\n",
               g_probes, g_replies, (unsigned long long)tx, (unsigned long long)rx);
        sweep_ovpn_stop(g_client);
        sleep(1);
        sweep_ovpn_free(g_client);
        free(profile);
        return g_replies > 0 ? 0 : 1;
    }

    for (int i = 0; i < 40 && !g_got_reply; i++) sleep(1);

    uint64_t tx = 0, rx = 0;
    sweep_ovpn_stats(g_client, &tx, &rx);
    printf("STATS tun tx=%llu rx=%llu\n", (unsigned long long)tx, (unsigned long long)rx);
    printf("RESULT: %s\n", g_got_reply ? "PASS - packets flow both ways" : "FAIL - no reply");

    sweep_ovpn_stop(g_client);
    sleep(1);
    sweep_ovpn_free(g_client);
    free(profile);
    return g_got_reply ? 0 : 1;
}
