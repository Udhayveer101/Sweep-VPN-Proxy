// Mirror for the VPN Gate public relay list.
//
// Indian residential ISPs (and plenty of corporate filters) block vpngate.net
// by category — the gateway returns its own 403 block page rather than the CSV,
// so the app never sees a relay list at all. This Worker fetches the list from
// Cloudflare's network and serves it from a *.workers.dev domain, which no
// category filter recognises.
//
// It is a dumb pipe: no logging, no auth, no state. Everyone who fetches gets
// the same public file VPN Gate already publishes to the world, so the Worker
// learns nothing about you that vpngate.net would not have learned directly.
//
//   npx wrangler deploy
//
// Then paste the deployed https://<name>.<subdomain>.workers.dev/ URL into
// "Mirror URL…" in the app's public-relay picker.

const UPSTREAM = "https://www.vpngate.net/api/iphone/";

// VPN Gate rotates relays constantly, but re-fetching a 1 MB CSV on every
// launch is wasteful; a few minutes of edge cache is the right trade.
const CACHE_SECONDS = 300;

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }

    const upstream = await fetch(UPSTREAM, {
      cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
      headers: { "user-agent": "sweep-vpn-relay-mirror" },
    });

    if (!upstream.ok) {
      return new Response(`upstream ${upstream.status}`, { status: 502 });
    }

    const body = await upstream.text();

    // Fail loudly rather than caching a block page or an error document as if
    // it were a relay list — the app checks the body parses, but a 502 here
    // gives a far clearer signal about where it broke.
    if (!body.includes("OpenVPN_ConfigData_Base64")) {
      return new Response("upstream did not return the VPN Gate CSV", { status: 502 });
    }

    return new Response(body, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": `public, max-age=${CACHE_SECONDS}`,
      },
    });
  },
};
