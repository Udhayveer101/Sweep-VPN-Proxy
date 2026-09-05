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

/// The relay leg, owned by a Durable Object rather than by a request.
///
/// It used to be a fire-and-forget `runTunnel()` in the request handler, on the
/// theory that an accepted WebSocket keeps the context alive. It does not, not
/// reliably: the field log shows the stream ending every three to six seconds
/// with no close frame at all — not the `1000 "eof"` the read loop sends when
/// the *relay* hangs up, but the Cloudflare side being torn down mid-stream.
/// Every one of those cost a full OpenVPN renegotiation, which is what the user
/// experienced as the internet dying every few seconds.
///
/// A Durable Object holds its socket for its own lifetime, so the loop is no
/// longer something the runtime can reap. It also outlives any one client
/// connection, which buys the thing the old design could not have at any price:
/// when the client's leg drops, the relay's TCP session — and so the OpenVPN
/// session riding on it — stays up. The client redials the same session id and
/// re-attaches to the live socket. No renegotiation, no visible gap.
export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.ws = null;
    this.socket = null;
    this.writer = null;
    this.target = null;      // "host:port", so a reattach cannot be redirected
    this.dead = false;
    this.parked = [];        // relay -> client bytes with nowhere to go yet
    this.parkedBytes = 0;
    this.pending = [];       // client -> relay bytes that arrived before the writer
    this.blobChain = Promise.resolve();
  }

  /// How long a session survives with no client attached. Long enough to ride
  /// out a redial and a network blip, short enough that an abandoned session
  /// does not hold a relay socket open for the operator to answer for.
  static get graceMs() { return 30_000; }

  /// Past this, the client is not coming back fast enough to matter and the
  /// buffer is doing more harm than the reconnect it was protecting.
  static get maxParkedBytes() { return 512 * 1024; }

  async fetch(request) {
    const url = new URL(request.url);
    const host = url.searchParams.get("h");
    const port = Number(url.searchParams.get("p"));
    // `r=1` says the client is resuming, not starting. It matters because this
    // object can be evicted while parked, and a resumed session that quietly
    // opened a *fresh* relay socket would hand OpenVPN a stream it cannot pick
    // up — a corrupt session that only fails later, on a timeout. Refusing it
    // outright turns that into an immediate, honest handover.
    const resuming = url.searchParams.get("r") === "1";
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    // Same rule as before: return the 101 promptly. Everything else happens
    // after it, or the runtime kills the request as hung.
    this.attach(server, host, port, resuming);
    return new Response(null, { status: 101, webSocket: client });
  }

  attach(ws, host, port, resuming = false) {
    const target = `${host}:${port}`;
    if (this.dead) return this.refuse(ws, "session gone");
    if (resuming && !this.socket) return this.refuse(ws, "session gone");
    // A resumed session may only resume the relay it started on. The session id
    // is the client's to choose, and this is what stops a chosen id from being
    // a way to point someone else's live socket somewhere new.
    if (this.target && this.target !== target) return this.refuse(ws, "wrong target");

    // A redial that arrives while an older leg is still open replaces it; the
    // old one is hung up rather than left to leak.
    if (this.ws && this.ws !== ws) {
      const stale = this.ws;
      this.ws = null;
      try { stale.close(1000, "replaced"); } catch {}
    }
    this.ws = ws;
    ws.addEventListener("message", (event) => this.fromClient(event.data));
    ws.addEventListener("close", () => this.park(ws));
    ws.addEventListener("error", () => this.park(ws));

    if (this.socket) {
      // Reattach: the relay never noticed we were gone.
      this.state.storage.deleteAlarm();
      try {
        ws.send(new Uint8Array([0x01]));
      } catch { return; }
      this.flushParked();
      return;
    }
    this.target = target;
    this.open(host, port);
  }

  refuse(ws, reason) {
    try {
      ws.send(new Uint8Array([0x00]));
      ws.close(1008, reason);
    } catch {}
  }

  async open(host, port) {
    try {
      this.socket = connect({ hostname: host, port });
      await this.socket.opened;
      this.writer = this.socket.writable.getWriter();
      for (const b of this.pending) this.writer.write(b).catch(() => {});
      this.pending.length = 0;
      // Deliberately not logged. `console.log(host, port)` here wrote which relay
      // this user picked into Workers logs, and the read loop below logged a line
      // per chunk — between them, the relay choice and a byte-size/timing trace of
      // the session. That is precisely the metadata a VPN exists to not produce,
      // and it was being produced by the operator rather than the network.
      this.ws?.send(new Uint8Array([0x01]));
    } catch {
      this.socket = null;
      if (this.ws) this.refuse(this.ws, "connect failed");
      this.destroy();
      return;
    }
    this.pump();
  }

  /// Relay -> client. Keeps reading while no client is attached, so a reconnect
  /// finds the stream where it left off instead of a hole.
  async pump() {
    const reader = this.socket.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done || this.dead) break;
        // Chunks are views into a pooled buffer. Sending one directly can put
        // the whole backing ArrayBuffer on the wire and corrupt the stream, so
        // each chunk is copied to exactly its own bytes.
        const bytes = value.buffer.byteLength === value.byteLength
          ? value.buffer
          : value.slice().buffer;
        // A client leg that is on its way out still reports readyState 1, and
        // the send then throws. That throw used to escape into the loop's catch
        // and take `finally` -> destroy() with it, so a *client* blip killed the
        // relay's TCP session — the one thing this object exists to keep. The
        // field signature was exact: the client redials, re-attaches, and is
        // handed `1000 "eof"` a fraction of a second later, costing a full
        // OpenVPN renegotiation every few seconds. A failed send is a leg that
        // is gone, which is what `parked` is for.
        if (!this.sendOrPark(bytes)) break;
      }
    } catch {
      // fall through: the relay itself ended or errored
    } finally {
      try { this.ws?.close(1000, "eof"); } catch {}
      this.destroy();
    }
  }

  /// Relay bytes to the client if a leg is up, else hold them for the redial.
  /// False only when the hold-buffer is full, which is the one case where
  /// giving up beats waiting.
  sendOrPark(bytes) {
    if (this.ws && this.ws.readyState === 1) {
      try {
        this.ws.send(bytes);
        return true;
      } catch {
        // The leg is gone but its close event has not landed yet. Drop it here
        // so nothing else tries to use it, and park this chunk with the rest.
        this.park(this.ws);
      }
    }
    if (this.park_overflowed(bytes.byteLength)) return false;
    this.parked.push(bytes);
    return true;
  }

  park_overflowed(n) {
    this.parkedBytes += n;
    return this.parkedBytes > RelaySession.maxParkedBytes;
  }

  /// Hand the client everything the relay said while it was away, oldest
  /// first. Bytes are dropped from the queue only once they are actually on
  /// the wire: the old version cleared nothing on a mid-flush throw, so the
  /// chunks it *had* sent were replayed on the next attach — a duplicated span
  /// inside an OpenVPN stream, which the peer answers with NETWORK_EOF_ERROR
  /// or AUTH_FAILED rather than anything that names the real cause.
  flushParked() {
    while (this.parked.length) {
      const b = this.parked[0];
      try { this.ws.send(b); } catch { return; }
      this.parked.shift();
      this.parkedBytes -= b.byteLength;
    }
    this.parkedBytes = 0;
  }

  /// `event.data` is not always a plain ArrayBuffer here: a Blob or a typed
  /// array both slip through `new Uint8Array(d)` as ZERO bytes, which silently
  /// empties every packet and looks exactly like the far end never replying.
  fromClient(d) {
    if (typeof d === "string") return this.push(new TextEncoder().encode(d));
    if (d instanceof ArrayBuffer) return this.push(new Uint8Array(d));
    if (ArrayBuffer.isView(d)) {
      return this.push(new Uint8Array(d.buffer, d.byteOffset, d.byteLength));
    }
    // A Blob has to be read asynchronously; keep the ordering by chaining.
    this.blobChain = this.blobChain.then(async () => {
      try { this.push(new Uint8Array(await d.arrayBuffer())); } catch {}
    });
  }

  push(bytes) {
    if (!bytes.byteLength) return;
    if (!this.writer) { this.pending.push(bytes); return; }
    this.writer.write(bytes).catch(() => this.destroy());
  }

  /// The client went away. Keep the relay socket — that is the whole point —
  /// and give the client a window to come back before giving up on it.
  park(ws) {
    if (this.ws !== ws) return;   // a later attach already replaced this one
    this.ws = null;
    if (this.dead) return;
    this.state.storage.setAlarm(Date.now() + RelaySession.graceMs);
  }

  async alarm() {
    if (!this.ws) this.destroy();
  }

  destroy() {
    if (this.dead) return;
    this.dead = true;
    this.parked.length = 0;
    try { this.writer?.close(); } catch {}
    try { this.socket?.close(); } catch {}
    try { this.ws?.close(1000, "eof"); } catch {}
    this.state.storage.deleteAlarm();
  }
}

/// Refuse in the shape the client expects: a 101, the 0x00 status byte, then a
/// 1008 close. Answering with a plain HTTP error instead would leave the client
/// waiting on its status deadline for a verdict it could have had at once.
function refused(reason) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  try {
    server.send(new Uint8Array([0x00]));
    server.close(1008, reason);
  } catch {}
  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/tcp") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("expected a websocket upgrade", { status: 426 });
      }
      // The cheap, stateless checks stay out here: no point spinning up a
      // Durable Object for a request that has the wrong token.
      const host = url.searchParams.get("h");
      const port = Number(url.searchParams.get("p"));
      if (!tokenMatches(url.searchParams.get("t"), env.TUNNEL_TOKEN)) {
        return refused("forbidden");
      }
      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        return refused("bad target");
      }
      if (!(await isAllowed(host))) return refused("not a known relay");

      // `s` names the session. The client reuses it to re-attach to a live
      // relay socket after its own leg drops; a client that does not send one
      // gets a fresh, unresumable session.
      const session = url.searchParams.get("s") || crypto.randomUUID();
      const id = env.RELAY.idFromName(session);
      return env.RELAY.get(id).fetch(request);
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
