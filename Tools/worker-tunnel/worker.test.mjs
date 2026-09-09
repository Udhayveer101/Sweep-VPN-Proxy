// Self-check for the two paths that decide whether a client blip costs an
// OpenVPN renegotiation. Run: node worker.test.mjs
//
// `cloudflare:sockets` does not exist outside the runtime, so the module is
// loaded as source with that import stripped. Nothing here touches it.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const src = readFileSync(new URL("./worker.js", import.meta.url), "utf8")
  .replace(/^import \{ connect \} from "cloudflare:sockets";$/m, "const connect = () => {};");
const { RelaySession, isSafeDestination } = await import(
  "data:text/javascript;base64," + Buffer.from(src).toString("base64"));

const session = () => {
  const s = new RelaySession({ storage: { setAlarm() {}, deleteAlarm() {} } }, {});
  s.socket = {};   // a live relay, so destroy() is observable as a change
  return s;
};
const bytes = (n) => new Uint8Array(n).buffer;

// A send that throws is a client leg on its way out, not a reason to drop the
// relay. The bytes must be parked for the redial instead.
{
  const s = session();
  s.ws = { readyState: 1, send() { throw new Error("leg gone"); } };
  assert.equal(s.sendOrPark(bytes(10)), true, "a failed send must not end the pump");
  assert.equal(s.dead, false, "a client-side send failure must never kill the relay session");
  assert.equal(s.ws, null, "the dead leg must be dropped so nothing else uses it");
  assert.equal(s.parked.length, 1, "the chunk belongs in the hold buffer");
}

// Overflow is the one case where giving up beats waiting.
{
  const s = session();
  s.ws = null;
  assert.equal(s.sendOrPark(bytes(4 * 1024 * 1024 + 1)), false, "past the cap the pump stops");
}

// A flush that dies partway must not replay what it already sent: a duplicated
// span inside an OpenVPN stream is answered with AUTH_FAILED, not with anything
// that names the real cause.
{
  const s = session();
  s.ws = null;
  for (const n of [1, 2, 3]) s.sendOrPark(bytes(n));
  const sent = [];
  let allowed = 2;
  s.ws = { readyState: 1, send(b) { if (allowed-- <= 0) throw new Error("leg gone"); sent.push(b.byteLength); } };
  s.flushParked();
  assert.deepEqual(sent, [1, 2], "the flush stops where the leg died");
  assert.deepEqual(s.parked.map((b) => b.byteLength), [3], "only the unsent tail may be retried");

  allowed = 9;
  s.flushParked();
  assert.deepEqual(sent, [1, 2, 3], "the retry sends the tail once, and nothing twice");
  assert.equal(s.parkedBytes, 0);
}

// The destination policy for general-exit mode. The token is the gate; this is
// what keeps a leaked token from being worth much.
for (const [h, p] of [["example.com", 443], ["example.com", 80], ["1.1.1.1", 443]]) {
  assert.equal(isSafeDestination(h, p), true, `${h}:${p} is an ordinary public destination`);
}

// Private space through someone else's proxy is SSRF, not browsing.
for (const h of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                 "169.254.169.254", "0.0.0.0", "localhost", "[::1]", "::1"]) {
  assert.equal(isSafeDestination(h, 443), false, h);
}

// Mail submission ports are what an abuse report would name.
for (const p of [25, 465, 587, 2525]) {
  assert.equal(isSafeDestination("example.com", p), false, String(p));
}

assert.equal(isSafeDestination("example.com", 0), false, "port 0");
assert.equal(isSafeDestination("example.com", 70000), false, "port past 65535");

console.log("worker relay-session self-check: ok");
