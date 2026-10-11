// AZRT-AUDITOR-1.0. A separate job with a separate key (AUDITOR_ED25519_PKCS8).
// Re-verifies the whole witness log (signatures, order, RFC 3161 tokens, Rekor entries), then
// checks that the live runtime still holds every head of the newest statement (append-only),
// and seals its own chained, signed check receipt in audits/log.jsonl. Never writes the runtime.
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { RUNTIME, ZERO, canonicalize, sha256, loadKey, sign, verify, readJsonl, getJson, keyFor } from "./lib.mjs";

const pinnedWitness = fs.readFileSync("keys/witness.pub", "utf8").trim();
const pinnedAuditor = fs.readFileSync("keys/auditor.pub", "utf8").trim();
const { key, pub } = loadKey("AUDITOR_ED25519_PKCS8");
if (pub !== pinnedAuditor) throw new Error("auditor secret does not match keys/auditor.pub");

const anchors = readJsonl("anchors/log.jsonl");
const findings = [];
let prev = ZERO;
let tsaOk = 0, rekorOk = 0;
for (const row of anchors) {
  const text = canonicalize(row.statement);
  const n = row.statement.n;
  if (sha256(text) !== row.statement_hash) findings.push({ n, code: "ANCHOR-MISMATCH", what: "statement hash" });
  if (row.statement.prev_statement_hash !== prev) findings.push({ n, code: "ANCHOR-ORDER-BREAK" });
  const wk = keyFor("witness", n);
  if (row.public_key !== wk || !verify(wk, text, row.sig)) findings.push({ n, code: "ANCHOR-SIG-BAD" });
  if (row.tsa && row.tsa.token) {
    try {
      fs.writeFileSync("/tmp/a.txt", text);
      execFileSync("openssl", ["ts", "-verify", "-data", "/tmp/a.txt", "-in", row.tsa.token, "-CAfile", "keys/freetsa-cacert.pem", "-untrusted", "keys/freetsa-tsa.crt"], { stdio: "pipe" });
      tsaOk++;
    } catch {
      findings.push({ n, code: "AUDIT-TSA-BAD" });
    }
  }
  if (row.rekor && row.rekor.uuid) {
    try {
      const j = await getJson(`https://rekor.sigstore.dev/api/v1/log/entries/${row.rekor.uuid}`);
      const entry = j[Object.keys(j)[0]];
      const body = JSON.parse(Buffer.from(entry.body, "base64").toString());
      if (body.spec.data.hash.value !== sha256(text)) findings.push({ n, code: "AUDIT-REKOR-MISMATCH" });
      else rekorOk++;
    } catch (err) {
      findings.push({ n, code: "AUDIT-REKOR-UNREACHABLE", detail: String(err.message).slice(0, 80) });
    }
  }
  prev = row.statement_hash;
}
// Live append-only check against the runtime (read-only GETs).
const latest = anchors[anchors.length - 1];
const live = [];
if (latest) {
  for (const head of latest.statement.heads.chains || []) {
    if (!head.seq || !head.h) continue;
    try {
      const r = await fetch(`${RUNTIME}/v1/anchor/row?c=${encodeURIComponent(head.c)}&seq=${head.seq}`);
      const j = await r.json();
      const ok = j.hash === head.h;
      live.push({ c: head.c, seq: head.seq, ok });
      if (!ok) findings.push({ n: latest.statement.n, code: "ANCHOR-MISMATCH", chain: head.c, seq: head.seq });
    } catch (err) {
      live.push({ c: head.c, seq: head.seq, ok: false, error: "unreachable" });
      findings.push({ code: "AUDIT-RUNTIME-UNREACHABLE", chain: head.c });
    }
  }
  for (const name of ["aznews", "4dmap"]) {
    const a = latest.statement.heads.stores && latest.statement.heads.stores[name];
    if (!a || !a.n) continue;
    try {
      const j = await getJson(`${RUNTIME}/v1/${name}/checkpoints?after=${a.n - 1}`);
      const cp = (j.checkpoints || []).find((x) => x.n === a.n);
      const ok = Boolean(cp && cp.cp_hash === a.cp_hash);
      live.push({ c: name, cp_n: a.n, ok });
      if (!ok) findings.push({ code: "ANCHOR-MISMATCH", store: name, cp_n: a.n });
    } catch {
      findings.push({ code: "AUDIT-RUNTIME-UNREACHABLE", store: name });
    }
  }
}
const audits = readJsonl("audits/log.jsonl");
const lastAudit = audits[audits.length - 1];
const statement = {
  spec: "AZRT-AUDITOR-1.0",
  n: audits.length + 1,
  prev_audit_hash: lastAudit ? lastAudit.statement_hash : ZERO,
  audited_at: new Date().toISOString(),
  witness_entries: anchors.length,
  witness_head: latest ? { n: latest.statement.n, statement_hash: latest.statement_hash } : null,
  tsa_verified: tsaOk,
  rekor_verified: rekorOk,
  live_checks: live,
  findings,
  verdict: anchors.length === 0 ? "AUDIT-EMPTY" : findings.length ? "AUDIT-FAIL" : "AUDIT-PASS",
  auditor: { repo: "AzielEliab/aziel-anchors", run_id: process.env.GITHUB_RUN_ID || null, key: "keys/auditor.pub" },
};
const text = canonicalize(statement);
fs.appendFileSync("audits/log.jsonl", JSON.stringify({ statement, statement_hash: sha256(text), public_key: pub, sig: sign(key, text) }) + "\n");
console.log(statement.verdict, JSON.stringify(findings).slice(0, 400));
