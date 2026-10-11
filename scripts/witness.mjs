// AZRT-ANCHOR-1.0 witness. Runs in GitHub Actions of AzielEliab/aziel-anchors only.
// Pulls aziel-runtime heads, signs a chained statement with WITNESS_ED25519_PKCS8 (Actions secret),
// gets an RFC 3161 token from freetsa.org and a Sigstore Rekor entry, appends anchors/log.jsonl.
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { RUNTIME, ZERO, canonicalize, sha256, loadKey, sign, readJsonl, getJson, rekorSubmit } from "./lib.mjs";

const LOG = "anchors/log.jsonl";
const pinned = fs.readFileSync("keys/witness.pub", "utf8").trim();
const { key, pub, pem } = loadKey("WITNESS_ED25519_PKCS8");
if (pub !== pinned) throw new Error("witness secret does not match keys/witness.pub");

const log = readJsonl(LOG);
const last = log[log.length - 1];
const heads = await getJson(`${RUNTIME}/v1/anchor/heads`);
// Independent second read of the checkpointed stores, straight from their own public ledgers.
const independent = {};
for (const name of ["aznews", "4dmap"]) {
  try {
    const led = await getJson(`${RUNTIME}/v1/${name}/ledger`);
    if (led.checkpoint_tip) independent[name] = { n: led.checkpoint_tip.n, cp_hash: led.checkpoint_tip.cp_hash, to_seq: led.checkpoint_tip.to_seq };
  } catch (err) {
    independent[name] = { error: String(err.message).slice(0, 120) };
  }
}
const sameHeads = last && canonicalize(last.statement.heads.chains) === canonicalize(heads.chains) && canonicalize(last.statement.heads.stores) === canonicalize(heads.stores);
if (sameHeads && process.env.FORCE !== "1") {
  console.log("heads unchanged since statement", last.statement.n, "- nothing to anchor");
  process.exit(0);
}
const statement = {
  spec: "AZRT-ANCHOR-1.0",
  n: log.length + 1,
  prev_statement_hash: last ? last.statement_hash : ZERO,
  observed_at: new Date().toISOString(),
  source: `${RUNTIME}/v1/anchor/heads`,
  // Additive (AZRT-ANCHOR-1.0 key-epoch update): the runtime's live GIT_SHA at the top level.
  // Statements before this field verify unchanged (canonical JSON of what was signed).
  git_sha: heads.git_sha || null,
  heads: { chains: heads.chains, stores: heads.stores, version: heads.version, git_sha: heads.git_sha, at: heads.at },
  independent,
  witness: { repo: "AzielEliab/aziel-anchors", run_id: process.env.GITHUB_RUN_ID || null, key: "keys/witness.pub" },
};
const text = canonicalize(statement);
const statement_hash = sha256(text);
const sig = sign(key, text);

let tsa = null;
try {
  fs.writeFileSync("/tmp/statement.txt", text);
  execFileSync("openssl", ["ts", "-query", "-data", "/tmp/statement.txt", "-sha256", "-cert", "-out", "/tmp/q.tsq"]);
  const res = await fetch("https://freetsa.org/tsr", { method: "POST", headers: { "content-type": "application/timestamp-query" }, body: fs.readFileSync("/tmp/q.tsq") });
  if (!res.ok) throw new Error("freetsa " + res.status);
  const path = `anchors/tsr/${statement.n}.tsr`;
  fs.writeFileSync(path, Buffer.from(await res.arrayBuffer()));
  const txt = execFileSync("openssl", ["ts", "-reply", "-in", path, "-text"]).toString();
  const m = txt.match(/Time stamp: (.+)/);
  tsa = { authority: "https://freetsa.org", rfc: 3161, token: path, gen_time: m ? m[1].trim() : null };
} catch (err) {
  console.log("TSA skipped:", err.message);
}
let rekor = null;
try {
  rekor = await rekorSubmit(pem, text, sig);
} catch (err) {
  console.log("Rekor skipped:", err.message);
}
const row = { statement, statement_hash, public_key: pub, sig, tsa, rekor };
fs.appendFileSync(LOG, JSON.stringify(row) + "\n");
console.log(`anchored n=${statement.n} ${statement_hash} chains=${heads.chains.length} tsa=${Boolean(tsa)} rekor=${rekor ? rekor.log_index : null}`);
