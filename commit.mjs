/*
 * tools/audit/commit.mjs — the audit's commitment: canonical records, salts, leaves, the Merkle root and its proofs,
 * the heartbeat, and verify (notes/AUDIT_PLAN_2026-11-02.md §3, row AU-1). __FE_PR_AUDIT_AU1_V1__ (2026-11-03)
 *
 * WHAT IT PROVES. A batch's root commits to every call in the batch, to their order and to how many there were. Given
 * a revealed record, its salt and its proof, anyone can recompute the leaf and walk it to the root; a changed byte,
 * a changed salt, a dropped or an added call breaks the walk. Timestamping the root (AU-2) then proves when.
 *
 * THE SHAPES (fixed here; the public verifier, AU-4, implements the same):
 *   record     a JSON object with `id` (a string), `class` (CLASSES) and `madeAt` (UTC ISO, ending "Z"). Anything else
 *              the record carries is committed too; numbers must be finite, and nothing may be undefined.
 *   canonical  the record as JSON with every object's keys sorted, no whitespace, UTF-8 (`canonical`)
 *   salt       32 random bytes, hex (`newSalt`), kept private until a reveal; it stops a guess by hashing every likely
 *              call (there are only so many players to start)
 *   leaf       sha256(0x00 ‖ salt ‖ canonical)
 *   node       sha256(0x01 ‖ left ‖ right), the tree split as RFC 9162 (Certificate Transparency) splits it: the left
 *              subtree holds the largest power of two below the count, so an odd leaf is never duplicated
 *   root       sha256(0x02 ‖ count as 8 bytes, big-endian ‖ tree head), so the count is committed with the calls.
 *              The tree head of no leaves is sha256(""): an empty sweep's root is the HEARTBEAT, so a skipped sweep
 *              shows as a gap. The plan's §3 says sha256(salt ‖ record); the 0x00/0x01/0x02 prefixes are added so a leaf
 *              can never pass for a node, or a node for a root (RFC 9162 §2.1.1).
 *   order      leaves in record-id order (`commitBatch` sorts); a duplicate id is refused
 *   proof      { index, count, path: [hex …] }, RFC 9162's inclusion proof; `verify` walks it with §2.1.3.2's algorithm
 *
 * Pure apart from `newSalt` (crypto randomness). Node only (`node:crypto`), so the sync repo's sweep and the verifier
 * can run byte copies of it.
 */
import { createHash, randomBytes } from "node:crypto";

export const CLASSES = Object.freeze(["odds", "rates", "projections", "calls", "campaign"]);
const LEAF = Buffer.from([0x00]), NODE = Buffer.from([0x01]), ROOT = Buffer.from([0x02]);
const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const hex = (b) => b.toString("hex");
const isHex = (s, bytes) => typeof s === "string" && s.length === bytes * 2 && /^[0-9a-f]+$/.test(s);

/** The record's canonical text: sorted keys, no whitespace. Throws on what JSON can't carry the same way twice. */
export function canonical(value) {
  const walk = (v, at) => {
    if (v === null || typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "number") { if (!Number.isFinite(v)) throw new Error(`audit: ${at} is not a finite number`); return JSON.stringify(v); }
    if (Array.isArray(v)) return `[${v.map((x, i) => walk(x, `${at}[${i}]`)).join(",")}]`;
    if (typeof v === "object") {
      return `{${Object.keys(v).sort().map((k) => {
        if (v[k] === undefined) throw new Error(`audit: ${at}.${k} is undefined`);
        return `${JSON.stringify(k)}:${walk(v[k], `${at}.${k}`)}`;
      }).join(",")}}`;
    }
    throw new Error(`audit: ${at} is a ${typeof v}, which a record can't carry`);
  };
  return walk(value, "record");
}

/** A record's checks before it is committed: its id, its class and a UTC time. Returns the problems, [] when none. */
export function recordProblems(r) {
  const out = [];
  if (!r || typeof r !== "object" || Array.isArray(r)) return ["audit: a record is an object"];
  if (typeof r.id !== "string" || !r.id) out.push("audit: a record needs a string id");
  if (!CLASSES.includes(r.class)) out.push(`audit: ${r.id}: class "${r.class}" is not one of ${CLASSES.join(", ")}`);
  if (typeof r.madeAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(r.madeAt) || Number.isNaN(Date.parse(r.madeAt)))
    out.push(`audit: ${r.id}: madeAt "${r.madeAt}" is not a UTC ISO time ending in Z`);
  return out;
}

/** 32 fresh random bytes, hex: one per record, kept private until its reveal. */
export const newSalt = () => hex(randomBytes(32));

/** A record's leaf: sha256(0x00 ‖ salt ‖ canonical record), hex. */
export function leafOf(record, salt) {
  if (!isHex(salt, 32)) throw new Error("audit: a salt is 32 bytes, as 64 hex characters");
  return hex(sha(LEAF, Buffer.from(salt, "hex"), Buffer.from(canonical(record), "utf8")));
}

/** RFC 9162's split: the largest power of two strictly below n (n ≥ 2). */
const splitOf = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** The tree head over leaf hashes (Buffers): sha256("") for none, the leaf itself for one. */
function headOf(leaves) {
  if (!leaves.length) return sha(Buffer.alloc(0));
  if (leaves.length === 1) return leaves[0];
  const k = splitOf(leaves.length);
  return sha(NODE, headOf(leaves.slice(0, k)), headOf(leaves.slice(k)));
}

/** The root that commits to the tree head and the count. */
const rootOf = (head, count) => { const n = Buffer.alloc(8); n.writeBigUInt64BE(BigInt(count)); return hex(sha(ROOT, n, head)); };

/** The root over leaf hashes (hex), in their given order. Pure. */
export const rootOfLeaves = (leaves) => rootOf(headOf(leaves.map((l) => Buffer.from(l, "hex"))), leaves.length);

/** The heartbeat: the root of a sweep with no new calls. */
export const HEARTBEAT = rootOfLeaves([]);

/** The inclusion proof for leaf `index` among `leaves` (Buffers): its sibling hashes, from the leaf up. */
function pathOf(index, leaves) {
  if (leaves.length <= 1) return [];
  const k = splitOf(leaves.length);
  return index < k
    ? [...pathOf(index, leaves.slice(0, k)), headOf(leaves.slice(k))]
    : [...pathOf(index - k, leaves.slice(k)), headOf(leaves.slice(0, k))];
}

/**
 * One sweep's batch: each record checked, salted and hashed, in id order, and the root over them all.
 * `saltOf(record)` supplies a salt (the default draws a fresh one). Throws on a bad record or a duplicate id.
 * Returns { root, count, entries: [{ id, salt, leaf, canonical, proof }] } — the entries stay private (the salts);
 * only the root and the count are published.
 */
export function commitBatch(records, { saltOf = newSalt } = {}) {
  const problems = records.flatMap(recordProblems);
  if (problems.length) throw new Error(problems.join("\n"));
  const sorted = [...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  for (let i = 1; i < sorted.length; i++) if (sorted[i].id === sorted[i - 1].id) throw new Error(`audit: the id "${sorted[i].id}" is in the batch twice`);
  const entries = sorted.map((r) => { const salt = saltOf(r); return { id: r.id, salt, leaf: leafOf(r, salt), canonical: canonical(r) }; });
  const leaves = entries.map((e) => Buffer.from(e.leaf, "hex"));
  entries.forEach((e, i) => { e.proof = { index: i, count: entries.length, path: pathOf(i, leaves).map(hex) }; });
  return { root: rootOf(headOf(leaves), entries.length), count: entries.length, entries };
}

/**
 * Verify one revealed record: its leaf from the record and salt, walked up its proof (RFC 9162 §2.1.3.2), must give
 * `root` for the proof's count. Returns { ok, problem }. Pure.
 */
export function verify(record, salt, proof, root) {
  try {
    if (!proof || !Number.isInteger(proof.index) || !Number.isInteger(proof.count) || !Array.isArray(proof.path)) return { ok: false, problem: "the proof is malformed" };
    if (!isHex(root, 32)) return { ok: false, problem: "the root is not 32 bytes of hex" };
    if (proof.index < 0 || proof.index >= proof.count) return { ok: false, problem: "the index is outside the batch" };
    if (proof.path.some((p) => !isHex(p, 32))) return { ok: false, problem: "a proof hash is not 32 bytes of hex" };
    let fn = proof.index, sn = proof.count - 1;
    let r = Buffer.from(leafOf(record, salt), "hex");
    for (const p of proof.path) {
      if (sn === 0) return { ok: false, problem: "the proof is longer than the batch allows" };
      const sib = Buffer.from(p, "hex");
      if (fn % 2 === 1 || fn === sn) {
        r = sha(NODE, sib, r);
        if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
      } else r = sha(NODE, r, sib);
      fn >>= 1; sn >>= 1;
    }
    if (sn !== 0) return { ok: false, problem: "the proof is shorter than the batch needs" };
    return rootOf(r, proof.count) === root ? { ok: true, problem: null } : { ok: false, problem: "the record does not reach the root" };
  } catch (e) {
    return { ok: false, problem: e.message };
  }
}
