#!/usr/bin/env node
/*
 * verify.mjs — check a TENVYRE call against its public root: it existed, unedited, by the time its timestamp says.
 * (FieldEdge notes/AUDIT_PLAN_2026-11-02.md §7, row AU-4.) __FE_PR_AUDIT_AU4_V1__ (2026-11-03)
 *
 * It ships in the public tenvyre-ledger repo beside commit.mjs and timestamp.mjs (byte copies of FieldEdge's
 * tools/audit/), with Node and no packages. Licence: the owner's choice, set before the repo is made public (plan §10).
 *
 *     node verify.mjs <reveal.json> [--ledger <dir>] [--tsa-ca <pem>] [--before <ISO time>] [--json]
 *
 * A reveal is { batch, record, salt, proof }. With the ledger's roots/<YYYY-MM>/<batch>.json (and its .tsr and .ots)
 * it checks, in order:
 *   1 the record    it is a well-formed call, and its leaf is sha256(0x00 ‖ salt ‖ canonical record)
 *   2 the proof     the leaf walks up its Merkle proof to the batch's published root, for the published count
 *   3 RFC 3161      the reply was granted, its imprint is that root, and its time is the one the ledger prints;
 *                   its signature through `openssl ts -verify` when OpenSSL and the authority's CA (--tsa-ca) are here
 *   4 Bitcoin       the .ots file is for that root; its Bitcoin anchor through the OpenTimestamps client (`ots verify`)
 *   5 the time      with --before, the RFC 3161 time is earlier (the lock rule, AU-3, supplies each game's first pitch)
 * A step it can't run here is printed "not checked", with the command that does it, and never counted as passed.
 * Exit 0: every step it ran passed. Exit 1: one failed.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { recordProblems, verify } from "./commit.mjs";
import { OTS_HEADER, tsResponseOf } from "./timestamp.mjs";

const PASS = "passed", FAIL = "failed", SKIP = "not checked";

/** Whether a command runs here (`openssl version`, `ots --version`). */
const available = (cmd, args) => { try { execFileSync(cmd, args, { stdio: "ignore" }); return true; } catch { return false; } };

/** The RFC 3161 signature through OpenSSL, against the authority's CA. Returns a step. */
export function opensslStep(tsrPath, root, caFile) {
  if (!caFile) return { step: "RFC 3161 signature", state: SKIP, detail: `give the authority's CA certificate: --tsa-ca <pem> (FreeTSA's is https://freetsa.org/files/cacert.pem), or run: openssl ts -verify -digest ${root} -in ${tsrPath} -CAfile <pem>` };
  if (!available("openssl", ["version"])) return { step: "RFC 3161 signature", state: SKIP, detail: `OpenSSL is not installed here; run: openssl ts -verify -digest ${root} -in ${tsrPath} -CAfile ${caFile}` };
  try {
    const out = execFileSync("openssl", ["ts", "-verify", "-digest", root, "-in", tsrPath, "-CAfile", caFile], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return /Verification: OK/.test(out) ? { step: "RFC 3161 signature", state: PASS, detail: "openssl ts -verify: OK" } : { step: "RFC 3161 signature", state: FAIL, detail: out.trim() };
  } catch (e) { return { step: "RFC 3161 signature", state: FAIL, detail: String((e.stdout || "") + (e.stderr || e.message)).trim().split("\n").pop() }; }
}

/** The Bitcoin anchor through the OpenTimestamps client, when it is installed. Returns a step. */
export function otsStep(otsPath) {
  if (!available("ots", ["--version"])) return { step: "Bitcoin anchor", state: SKIP, detail: `install the OpenTimestamps client (pip install opentimestamps-client) and run: ots verify ${otsPath}` };
  try { const out = execFileSync("ots", ["verify", otsPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); return { step: "Bitcoin anchor", state: PASS, detail: out.trim().split("\n").pop() }; }
  catch (e) {
    const msg = String((e.stdout || "") + (e.stderr || "")).trim();
    // a proof whose anchor hasn't landed yet is pending, not false
    return /pending/i.test(msg) ? { step: "Bitcoin anchor", state: SKIP, detail: `pending: the Bitcoin anchor hasn't landed yet (${msg.split("\n").pop()})` } : { step: "Bitcoin anchor", state: FAIL, detail: msg.split("\n").pop() };
  }
}

/**
 * The checks that need only Node (steps 1–5 above, without the two outside tools). Pure, given the bytes.
 * `rootDoc` is the ledger's roots/<month>/<batch>.json; `tsr` and `ots` its proofs (Buffers, or null when absent).
 */
export function verifyReveal(reveal, rootDoc, { tsr = null, ots = null, before = null } = {}) {
  const steps = [];
  const add = (step, ok, detail) => steps.push({ step, state: ok ? PASS : FAIL, detail });
  const problems = recordProblems(reveal.record);
  add("the record", !problems.length, problems.length ? problems.join("; ") : `${reveal.record.class} call ${reveal.record.id}, made ${reveal.record.madeAt}`);
  if (!rootDoc || rootDoc.id !== reveal.batch) { add("the proof", false, `no published root for batch ${reveal.batch}`); return steps; }
  const v = reveal.proof && reveal.proof.count === rootDoc.count ? verify(reveal.record, reveal.salt, reveal.proof, rootDoc.root) : { ok: false, problem: `the proof is for ${reveal.proof && reveal.proof.count} calls; the published batch has ${rootDoc.count}` };
  add("the proof", v.ok, v.ok ? `call ${reveal.proof.index + 1} of ${rootDoc.count} reaches root ${rootDoc.root.slice(0, 16)}…` : v.problem);
  if (!tsr) steps.push({ step: "RFC 3161 reply", state: SKIP, detail: "no .tsr beside the root" });
  else {
    let r; try { r = tsResponseOf(tsr); } catch (e) { r = { granted: false, error: e.message }; }
    const imprint = tsr.includes(Buffer.concat([Buffer.from([0x04, 0x20]), Buffer.from(rootDoc.root, "hex")]));
    const sameTime = rootDoc.rfc3161 && r.genTime === rootDoc.rfc3161.genTime;
    add("RFC 3161 reply", r.granted && imprint && sameTime,
      !r.granted ? `not a granted reply${r.error ? ` (${r.error})` : ""}` : !imprint ? "the reply is for another root" : !sameTime ? `the reply says ${r.genTime}, the ledger ${rootDoc.rfc3161 && rootDoc.rfc3161.genTime}` : `granted, for this root, at ${r.genTime}`);
  }
  if (!ots) steps.push({ step: "OpenTimestamps file", state: SKIP, detail: "no .ots beside the root" });
  else {
    const head = ots.subarray(0, OTS_HEADER.length).equals(OTS_HEADER), digest = ots.subarray(OTS_HEADER.length, OTS_HEADER.length + 32).toString("hex");
    add("OpenTimestamps file", head && digest === rootDoc.root, !head ? "not an OpenTimestamps proof" : digest !== rootDoc.root ? "the proof is for another root" : "a proof for this root");
  }
  if (before) {
    const t = rootDoc.rfc3161 && rootDoc.rfc3161.genTime;
    add("before", !!t && Date.parse(t) < Date.parse(before), t ? `timestamped ${t}; needed before ${before}` : "no RFC 3161 time to compare");
  }
  return steps;
}

/** Every step, the outside tools included, for a reveal file and a ledger checkout. */
export function verifyFiles(revealPath, { ledger = ".", tsaCa = null, before = null } = {}) {
  const reveal = JSON.parse(readFileSync(revealPath, "utf8"));
  const base = join(ledger, "roots", String(reveal.batch).slice(0, 7), String(reveal.batch));
  const read = (ext) => (existsSync(`${base}.${ext}`) ? readFileSync(`${base}.${ext}`) : null);
  const rootDoc = read("json") ? JSON.parse(read("json").toString("utf8")) : null;
  const steps = verifyReveal(reveal, rootDoc, { tsr: read("tsr"), ots: read("ots"), before });
  if (read("tsr") && steps.every((s) => s.state !== FAIL)) steps.splice(3, 0, opensslStep(`${base}.tsr`, rootDoc.root, tsaCa));
  if (read("ots") && steps.every((s) => s.state !== FAIL)) steps.push(otsStep(`${base}.ots`));
  return steps;
}

export const verdictOf = (steps) => (steps.some((s) => s.state === FAIL) ? "FAILED" : steps.some((s) => s.state === SKIP) ? "PASSED, with steps left to you" : "PASSED");

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
  const file = process.argv[2];
  if (!file || file.startsWith("--")) { console.error("usage: node verify.mjs <reveal.json> [--ledger <dir>] [--tsa-ca <pem>] [--before <ISO time>] [--json]"); process.exit(2); }
  const steps = verifyFiles(file, { ledger: arg("--ledger") || dirname(fileURLToPath(import.meta.url)), tsaCa: arg("--tsa-ca"), before: arg("--before") });
  if (process.argv.includes("--json")) console.log(JSON.stringify({ verdict: verdictOf(steps), steps }, null, 1));
  else { for (const s of steps) console.log(`${s.state.padEnd(11)} ${s.step}: ${s.detail}`); console.log(verdictOf(steps)); }
  process.exit(steps.some((s) => s.state === FAIL) ? 1 : 0);
}
