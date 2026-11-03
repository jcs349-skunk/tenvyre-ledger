/*
 * tools/audit/timestamp.mjs — the two timestamps on each batch root (notes/AUDIT_PLAN_2026-11-02.md §3, row AU-2).
 * __FE_PR_AUDIT_AU2_V1__ (2026-11-03)
 *
 *   RFC 3161     a timestamping authority signs the root's time to the second, at once (the lock rule needs that).
 *                `tsRequest` builds the DER TimeStampReq (SHA-256 imprint = the root itself, a nonce, certReq), and
 *                `tsResponseOf` reads the reply's status and its genTime. The reply is kept whole as a .tsr, so
 *                `openssl ts -verify` (and AU-4's verifier) check the signature, not this file.
 *   OpenTimestamps  a calendar commits the root to Bitcoin within hours, so no one, the owner included, can backdate
 *                it. `otsFileOf` writes the standard detached .ots file: the magic header, version 1, SHA-256, the
 *                root, then the calendar's reply (two calendars' replies joined by a fork). The pending proof is
 *                upgraded once its Bitcoin anchor lands (a later step; the .ots stays valid meanwhile).
 *
 * `stampRoot` calls both through an injected `fetch`, so the tests never touch a real service, and returns each one's
 * bytes or its error: a failure is reported, never thrown, and the sweep keeps the batch sealed and tries again (AU6).
 * Node only.
 */
import { randomBytes } from "node:crypto";

/** The default services: free, no account (the plan's §9 "Costs"). */
export const TSA_URL = "https://freetsa.org/tsr";
export const OTS_CALENDARS = Object.freeze(["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]);

const derLen = (n) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const der = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
const SHA256_OID = Buffer.from("0609608648016503040201", "hex"); // OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1
const isRoot = (hex) => typeof hex === "string" && /^[0-9a-f]{64}$/.test(hex);

/** The DER TimeStampReq for a 32-byte root (RFC 3161 §2.4.1): version 1, the SHA-256 imprint, a nonce, certReq. */
export function tsRequest(rootHex, { nonce = randomBytes(8) } = {}) {
  if (!isRoot(rootHex)) throw new Error("audit: a root is 32 bytes of hex");
  const n = Buffer.from(nonce); n[0] &= 0x7f; // a positive INTEGER
  const algorithm = der(0x30, Buffer.concat([SHA256_OID, Buffer.from([0x05, 0x00])]));
  const imprint = der(0x30, Buffer.concat([algorithm, der(0x04, Buffer.from(rootHex, "hex"))]));
  return der(0x30, Buffer.concat([Buffer.from([0x02, 0x01, 0x01]), imprint, der(0x02, n), Buffer.from([0x01, 0x01, 0xff])]));
}

/** One DER element at `at`: its tag, where its body starts, and its length. */
function element(buf, at) {
  const tag = buf[at]; let len = buf[at + 1], start = at + 2;
  if (len & 0x80) { const k = len & 0x7f; if (k < 1 || k > 3) throw new Error("audit: an unexpected DER length"); len = 0; for (let i = 0; i < k; i++) len = (len << 8) | buf[start + i]; start += k; }
  if (start + len > buf.length) throw new Error("audit: a DER element runs past the reply");
  return { tag, start, len };
}

/**
 * A TimeStampResp's status (0 granted, 1 granted with mods; anything else refused) and genTime, read without trusting it:
 * the signature is checked by `openssl ts -verify` on the kept .tsr. genTime is the first GeneralizedTime in the token.
 */
export function tsResponseOf(bytes) {
  const buf = Buffer.from(bytes);
  const outer = element(buf, 0); if (outer.tag !== 0x30) throw new Error("audit: the reply is not a DER SEQUENCE");
  const info = element(buf, outer.start); if (info.tag !== 0x30) throw new Error("audit: no status in the reply");
  const st = element(buf, info.start); if (st.tag !== 0x02) throw new Error("audit: the status is not an INTEGER");
  const status = buf.readUIntBE(st.start, st.len);
  const granted = status === 0 || status === 1;
  let genTime = null;
  if (granted) {
    for (let i = info.start + info.len; i < buf.length - 17; i++) {
      if (buf[i] !== 0x18) continue;
      const len = buf[i + 1], s = buf.toString("latin1", i + 2, i + 2 + len);
      const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
      if (m) { genTime = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ? `.${m[7].slice(0, 3).padEnd(3, "0")}` : ""}Z`; break; }
    }
    if (!genTime) throw new Error("audit: a granted reply with no genTime");
  }
  return { status, granted, genTime };
}

/** The detached .ots file's fixed header (python-opentimestamps DetachedTimestampFile): magic, version 1, OpSHA256. */
export const OTS_HEADER = Buffer.concat([
  Buffer.from([0x00]), Buffer.from("OpenTimestamps", "latin1"), Buffer.from([0x00, 0x00]), Buffer.from("Proof", "latin1"),
  Buffer.from([0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]), Buffer.from([0x01]), Buffer.from([0x08]),
]);

/** The .ots file for a root from one or more calendars' replies (each a serialized timestamp on the root). */
export function otsFileOf(rootHex, replies) {
  if (!isRoot(rootHex)) throw new Error("audit: a root is 32 bytes of hex");
  if (!replies.length) throw new Error("audit: no calendar reply to write");
  const body = Buffer.concat(replies.map((r, i) => (i < replies.length - 1 ? Buffer.concat([Buffer.from([0xff]), Buffer.from(r)]) : Buffer.from(r))));
  return Buffer.concat([OTS_HEADER, Buffer.from(rootHex, "hex"), body]);
}

/**
 * Both timestamps for a root, through `fetch` (the global one by default). Never throws: each part comes back as
 * { ok: true, bytes, … } or { ok: false, error }, and the sweep keeps what failed for its next run.
 */
export async function stampRoot(rootHex, { fetch = globalThis.fetch, tsaUrl = TSA_URL, calendars = OTS_CALENDARS, timeoutMs = 20000 } = {}) {
  const call = async (url, init) => {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), timeoutMs);
    try { const r = await fetch(url, { ...init, signal: ctl.signal }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return Buffer.from(await r.arrayBuffer()); }
    finally { clearTimeout(t); }
  };
  let rfc3161;
  try {
    const bytes = await call(tsaUrl, { method: "POST", headers: { "Content-Type": "application/timestamp-query" }, body: tsRequest(rootHex) });
    const r = tsResponseOf(bytes);
    rfc3161 = r.granted ? { ok: true, bytes, genTime: r.genTime, tsa: tsaUrl } : { ok: false, error: `the authority refused it (status ${r.status})` };
  } catch (e) { rfc3161 = { ok: false, error: `RFC 3161: ${e.message}` }; }
  const replies = [], errors = [];
  for (const c of calendars) {
    try { replies.push(await call(`${c}/digest`, { method: "POST", headers: { Accept: "application/vnd.opentimestamps.v1", "Content-Type": "application/x-www-form-urlencoded" }, body: Buffer.from(rootHex, "hex") })); }
    catch (e) { errors.push(`${c}: ${e.message}`); }
  }
  const ots = replies.length ? { ok: true, bytes: otsFileOf(rootHex, replies), calendars: replies.length } : { ok: false, error: `OpenTimestamps: ${errors.join("; ")}` };
  return { rfc3161, ots };
}
