// TCP-over-WebSocket relay, so a DPI-blocked protocol can reach its server.
//
// # The gap this exploits
//
// The network is behind a Sophos gateway running three engines (measured):
// Web Filtering matches Host header and TLS SNI (vpngate.net → 403 block page);
// App Control fingerprints plaintext protocol signatures and kills OpenVPN the
// instant its handshake hits the wire, port 443 included; SSL/TLS Inspection is
// OFF (google.com presents a genuine Google Trust Services cert, no MITM CA).
//
// So the gateway can read SNI and fingerprint plaintext, but cannot see inside
// TLS to a host it has not categorised. That is the hole: the blocked bytes go
// inside an ordinary-looking HTTPS session to workers.dev, where App Control
// has nothing to match. It is the same reason Psiphon and Hotspot Shield work
// here and a bare OpenVPN does not.
//
//   wss://<worker>.workers.dev/tcp?h=<host>&p=<port>&t=<token>
//
// The first frame the client receives is a one-byte status: 0x01 connected,
// 0x00 failed. After that it is raw bidirectional bytes.
//
// # Two things that will silently break this
//
// 1. The 101 must be returned *promptly*. Awaiting the allow-list fetch or
//    `socket.opened` before returning it makes the runtime kill the request
//    ("your Worker's code had hung and would never generate a response") and
//    the client sees a close with code 1005. All connect-and-pipe work belongs
//    after the response, inside waitUntil.
// 2. Chunks from `readable` are views into a pooled buffer. Sending one
//    directly can put the whole backing ArrayBuffer on the wire and corrupt the
//    stream, so each chunk is copied to exactly its own bytes.
//
// # Access
//
// `/tcp` requires TUNNEL_TOKEN (`wrangler secret put TUNNEL_TOKEN`) and egress
// is restricted to hosts on the current VPN Gate relay list. Without both this
// is an open proxy, and an open proxy on this account is how the account gets
// banned.

import { connect } from "cloudflare:sockets";

const RELAY_LIST = "https://www.vpngate.net/api/iphone/";
/// Deliberately the same 300 s the mirror route below serves the app, and the
/// same `cacheTtl`, so both routes read one edge-cached body. They used to be an
/// hour apart, and that hour was a bug with a signature: the user refreshes the
/// relay list, gets rows newer than this isolate's allow-list, and every one of
/// them comes back `1008 not a known relay` until the TTL rolls over. VPN Gate
/// rotates addresses within hours, so after a refresh that was most of the pool.
const ALLOW_TTL_MS = 5 * 60 * 1000;

let allowCache = { at: 0, hosts: new Set() };
/// One in-flight refresh shared by every concurrent dial. A burst of sixteen
/// relays failing the set must not become sixteen upstream fetches.
let allowInFlight = null;

function parseHosts(body) {
  const hosts = new Set();
  for (const line of body.split("\n")) {
    const cols = line.split(",");
    // #HostName,IP,... — column 1 is the relay's address.
    if (cols.length > 14 && /^\d+\.\d+\.\d+\.\d+$/.test(cols[1])) hosts.add(cols[1]);
  }
  return hosts;
}

/// Fetch the list and replace the cache. On failure the previous set is kept —
/// never falling open, never falling shut mid-session.
function refreshHosts() {
  if (allowInFlight) return allowInFlight;
  const run = (async () => {
    try {
      const res = await fetch(RELAY_LIST, {
        cf: { cacheTtl: 300, cacheEverything: true },
        headers: { "user-agent": "sweep-vpn-tunnel" },
      });
      if (res.ok) {
        const hosts = parseHosts(await res.text());
        if (hosts.size) allowCache = { at: Date.now(), hosts };
      }
    } catch {
      // keep whatever we had
    } finally {
      allowInFlight = null;
    }
    return allowCache.hosts;
  })();
  allowInFlight = run;
  return run;
}

/// IPs the relay list currently advertises.
async function allowedHosts() {
  if (Date.now() - allowCache.at < ALLOW_TTL_MS && allowCache.hosts.size) {
    return allowCache.hosts;
  }
  return refreshHosts();
}

/// A miss is not yet a refusal. The relay the client just picked may have been
/// published after this isolate last looked, so spend one forced refresh before
/// turning it away — otherwise a freshly-listed relay is unusable for the whole
/// TTL, which is the whole of what the client can see.
async function isAllowed(host) {
  const before = allowCache.at;
  if ((await allowedHosts()).has(host)) return true;
  // Only worth a second trip if the set we just missed against was not itself
  // freshly fetched.
  if (allowCache.at !== before) return false;
  return (await refreshHosts()).has(host);
}

/// Constant-time-ish compare, so the token cannot be recovered a byte at a time.
function tokenMatches(given, expected) {
  if (!expected || !given || given.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < given.length; i++) diff |= given.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/// Everything after the 101: verify, connect, and pipe until either side ends.
async function runTunnel(ws, host, port, token, expected) {
  const fail = (reason) => { try { ws.send(new Uint8Array([0x00])); ws.close(1008, reason); } catch {} };

  // Attach the message listener before anything is awaited. An accepted
  // WebSocket dispatches frames immediately and drops those that arrive with
  // no listener attached — the client sends its handshake the moment it sees
  // 0x01, which lands inside the connect await. Queue until the socket exists.
  let writer = null;
  const pending = [];
  ws.addEventListener("message", (event) => {
    // `event.data` is not always a plain ArrayBuffer here: a Blob or a typed
    // array both slip through `new Uint8Array(d)` as ZERO bytes, which silently
    // empties every packet and looks exactly like the far end never replying.
    const d = event.data;
    let bytes;
    if (typeof d === "string") bytes = new TextEncoder().encode(d);
    else if (d instanceof ArrayBuffer) bytes = new Uint8Array(d);
    else if (ArrayBuffer.isView(d)) bytes = new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
    else { queueBlob(d); return; }
    push(bytes);
  });

  const push = (bytes) => {
    if (!bytes.byteLength) return;
    if (!writer) { pending.push(bytes); return; }
    writer.write(bytes).catch(() => { try { ws.close(1011, "write failed"); } catch {} });
  };
  // A Blob has to be read asynchronously; keep the ordering by chaining.
  let blobChain = Promise.resolve();
  const queueBlob = (blob) => {
    blobChain = blobChain.then(async () => {
      try { push(new Uint8Array(await blob.arrayBuffer())); } catch {}
    });
  };

  if (!tokenMatches(token, expected)) return fail("forbidden");
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return fail("bad target");
  if (!(await isAllowed(host))) return fail("not a known relay");

  let socket;
  try {
    socket = connect({ hostname: host, port });
    await socket.opened;
    writer = socket.writable.getWriter();
    for (const b of pending) writer.write(b).catch(() => {});
    pending.length = 0;
    // Deliberately not logged. `console.log(host, port)` here wrote which relay
    // this user picked into Workers logs, and the read loop below logged a line
    // per chunk — between them, the relay choice and a byte-size/timing trace of
    // the session. That is precisely the metadata a VPN exists to not produce,
    // and it was being produced by the operator rather than the network.
    ws.send(new Uint8Array([0x01]));
  } catch {
    return fail("connect failed");
  }
  const teardown = () => {
    try { writer.close(); } catch {}
    try { socket.close(); } catch {}
  };
  ws.addEventListener("close", teardown);
  ws.addEventListener("error", teardown);

  const reader = socket.readable.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done || ws.readyState !== 1) break;
      // Copy exactly this chunk's bytes out of the pooled buffer.
      ws.send(value.buffer.byteLength === value.byteLength
        ? value.buffer
        : value.slice().buffer);
    }
  } catch {
    // fall through
  } finally {
    try { ws.close(1000, "eof"); } catch {}
    teardown();
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/tcp") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("expected a websocket upgrade", { status: 426 });
      }
      const [client, server] = Object.values(new WebSocketPair());
      server.accept();
      // Fire-and-forget, deliberately not `ctx.waitUntil`: an accepted
      // WebSocket already keeps the context alive, and handing waitUntil an
      // unbounded read loop trips the runtime's hang detector, which cancels
      // the request and closes the client's socket with code 1005.
      runTunnel(
        server,
        url.searchParams.get("h"),
        Number(url.searchParams.get("p")),
        url.searchParams.get("t"),
        env.TUNNEL_TOKEN,
      );
      return new Response(null, { status: 101, webSocket: client });
    }

    // Everything else mirrors the relay list, so one Worker covers both the
    // list fetch (which the gateway blocks by category) and the data path.
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
