// TCP-over-WebSocket relay, so a blocked protocol can reach a blocked host.
//
// # Why this exists
//
// Measured on the target ISP (see the vault note): TCP connects to a VPN Gate
// relay on :443 succeed, but the moment OpenVPN's handshake bytes flow the
// connection is reset — the DPI fingerprints the protocol, not the port. Every
// free obfuscated transport is also dead there: the public obfs4 bridge IPs are
// blocklisted, snowflake's broker is reachable but its WebRTC data channel is
// not (UDP is blocked except :53), and meek stalls at 10%.
//
// The one thing that passes untouched is ordinary TLS to a CDN on :443. So the
// blocked bytes go inside that instead: the client opens a WebSocket to this
// Worker, names a target, and the Worker holds the raw TCP socket on its behalf.
// The ISP sees an HTTPS session to workers.dev. The OpenVPN handshake happens
// inside it, where there is nothing to fingerprint.
//
//   wss://<worker>.workers.dev/tcp?host=<ip>&port=<port>
//
// The first frame the client receives is a one-byte status: 0x01 connected,
// 0x00 failed. After that it is raw bidirectional bytes.
//
// # Limits worth knowing
//
// - Egress is restricted to the VPN Gate relay list, refreshed hourly, so this
//   is not an open proxy someone else can point at arbitrary hosts. An open
//   relay on your account is a liability, not a feature.
// - Cloudflare bills this as Worker CPU + duration. It is a personal tool; a
//   few concurrent tunnels are free-tier territory, a shared one is not.
// - Cloudflare terminates the TLS to the relay's *transport*, not the VPN's
//   payload — the OpenVPN session inside is still end-to-end to the relay, so
//   Cloudflare sees ciphertext, not your traffic.

import { connect } from "cloudflare:sockets";

const RELAY_LIST = "https://www.vpngate.net/api/iphone/";
const ALLOW_TTL_MS = 60 * 60 * 1000;

let allowCache = { at: 0, hosts: new Set() };

/// The set of IPs the relay list currently advertises. Refreshed lazily; on a
/// refresh failure the previous set is kept rather than falling open or shut.
async function allowedHosts() {
  if (Date.now() - allowCache.at < ALLOW_TTL_MS && allowCache.hosts.size) {
    return allowCache.hosts;
  }
  try {
    const res = await fetch(RELAY_LIST, {
      cf: { cacheTtl: 3600, cacheEverything: true },
      headers: { "user-agent": "sweep-vpn-tunnel" },
    });
    if (!res.ok) return allowCache.hosts;
    const text = await res.text();
    const hosts = new Set();
    for (const line of text.split("\n")) {
      const cols = line.split(",");
      // #HostName,IP,... — column 1 is the relay's address.
      if (cols.length > 14 && /^\d+\.\d+\.\d+\.\d+$/.test(cols[1])) hosts.add(cols[1]);
    }
    if (hosts.size) allowCache = { at: Date.now(), hosts };
  } catch {
    // keep whatever we had
  }
  return allowCache.hosts;
}

/// Pump the socket's bytes into the WebSocket until either end closes.
async function pumpToSocket(readable, ws) {
  const reader = readable.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      // A send on a closing socket throws; that is a normal end of tunnel.
      if (ws.readyState !== 1) break;
      // `value` is a view into a pooled buffer — sending it directly can put
      // the whole backing ArrayBuffer on the wire, corrupting the stream. Send
      // exactly the bytes this chunk covers.
      ws.send(value.buffer.byteLength === value.byteLength
        ? value.buffer
        : value.slice().buffer);
    }
  } catch {
    // fall through to close
  } finally {
    try { ws.close(1000, "eof"); } catch {}
  }
}

async function handleTunnel(request, ctx) {
  const url = new URL(request.url);
  const host = url.searchParams.get("host");
  const port = Number(url.searchParams.get("port"));

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return new Response("host and port required", { status: 400 });
  }
  const allowed = await allowedHosts();
  // An empty allow-list means the refresh has never succeeded. Refuse rather
  // than serve as an open relay while the list is unavailable.
  if (!allowed.has(host)) {
    return new Response("host is not a known VPN Gate relay", { status: 403 });
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  let socket;
  let writer;
  try {
    socket = connect({ hostname: host, port });
    await socket.opened;
    writer = socket.writable.getWriter();
    server.send(new Uint8Array([0x01]));
  } catch {
    try { server.send(new Uint8Array([0x00])); server.close(1011, "connect failed"); } catch {}
    return new Response(null, { status: 101, webSocket: client });
  }

  server.addEventListener("message", (event) => {
    const data = event.data;
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
    writer.write(bytes).catch(() => { try { server.close(1011, "write failed"); } catch {} });
  });

  const teardown = () => {
    try { writer.close(); } catch {}
    try { socket.close(); } catch {}
  };
  server.addEventListener("close", teardown);
  server.addEventListener("error", teardown);

  // The pump has to outlive this handler: once `fetch` returns, an unawaited
  // promise is not a reason to keep the invocation alive, and the relay's
  // replies were being dropped the moment the 101 went out.
  ctx.waitUntil(pumpToSocket(socket.readable, server));

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);



    if (url.pathname === "/tcp") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("expected a websocket upgrade", { status: 426 });
      }
      return handleTunnel(request, ctx);
    }

    // Anything else keeps serving the relay-list mirror, so one Worker covers
    // both the list fetch and the data path.
    const upstream = await fetch(RELAY_LIST, {
      cf: { cacheTtl: 300, cacheEverything: true },
      headers: { "user-agent": "sweep-vpn-relay-mirror" },
    });
    if (!upstream.ok) return new Response(`upstream ${upstream.status}`, { status: 502 });
    const body = await upstream.text();
    if (!body.includes("OpenVPN_ConfigData_Base64")) {
      return new Response("upstream did not return the VPN Gate CSV", { status: 502 });
    }
    return new Response(body, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      },
    });
  },
};
