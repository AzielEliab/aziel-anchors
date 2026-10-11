// EXTERNAL-HEADS-1.0: the witness also anchors the godlock.uk ledger head and the corpus
// ACT-RECEIPT tip, read straight from their own public endpoints (not through the runtime).
// Fail closed: a head is recorded only when its source says it verified; anything else is
// recorded as { anchored: false, reason } so a statement never vouches for an unverified head.
const HEX64 = /^[0-9a-f]{64}$/;
const ZERO64 = "0".repeat(64);

export const GODLOCK_VERIFY = process.env.GODLOCK_ORIGIN ? `${process.env.GODLOCK_ORIGIN}/verify` : "https://godlock.uk/verify";
export const CORPUS_RECEIPTS = process.env.CORPUS_ORIGIN ? `${process.env.CORPUS_ORIGIN}/v1/receipts` : "https://www.azielcorpuslibrary.net/v1/receipts";

export function godlockHead(body) {
  if (!body || typeof body !== "object") return { anchored: false, reason: "no JSON from /verify" };
  if (body.ok !== true || body.status !== "VERIFIED") return { anchored: false, reason: `godlock /verify status ${body.status || "missing"}` };
  if (Array.isArray(body.errors) && body.errors.length) return { anchored: false, reason: "godlock /verify reported errors" };
  if (!HEX64.test(String(body.ledger_head || ""))) return { anchored: false, reason: "ledger_head is not 64-hex" };
  if (!Number.isInteger(body.ledger_entries) || body.ledger_entries < 1) return { anchored: false, reason: "ledger_entries missing" };
  return { anchored: true, source: GODLOCK_VERIFY, head: body.ledger_head, entries: body.ledger_entries, verified_utc: body.verified_utc || null };
}

export function corpusHead(body) {
  if (!body || typeof body !== "object") return { anchored: false, reason: "no JSON from /v1/receipts" };
  const tip = String(body.tip || "");
  if (!HEX64.test(tip)) return { anchored: false, reason: "tip is not 64-hex" };
  if (tip === ZERO64) return { anchored: false, reason: "corpus ACT-RECEIPT chain is empty (tip is all zeros)", lockset_tip: HEX64.test(String(body.lockset_tip || "")) ? body.lockset_tip : null };
  return { anchored: true, source: CORPUS_RECEIPTS, head: tip, lockset_tip: HEX64.test(String(body.lockset_tip || "")) ? body.lockset_tip : null };
}

/** JSON GET with Accept: application/json (godlock.uk serves HTML to browsers on /verify). */
export async function fetchJson(url) {
  const res = await fetch(url, { headers: { accept: "application/json", "user-agent": "aziel-anchors-witness" } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

export async function readExternalHeads(getJson = fetchJson) {
  const out = {};
  for (const [name, url, shape] of [["godlock", GODLOCK_VERIFY, godlockHead], ["corpus", CORPUS_RECEIPTS, corpusHead]]) {
    try {
      out[name] = shape(await getJson(url));
    } catch (err) {
      out[name] = { anchored: false, reason: "unreachable: " + String(err && err.message).slice(0, 120) };
    }
  }
  return out;
}
