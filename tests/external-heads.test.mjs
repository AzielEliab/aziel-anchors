// EXTERNAL-HEADS-1.0 tests: run with `node tests/external-heads.test.mjs`.
import assert from "node:assert/strict";
import { godlockHead, corpusHead, readExternalHeads } from "../scripts/external-heads.mjs";
const H = "d9c4f1b0c140f813735b5c80b13237381d0dd604176d50cacf29761bc5ac60d4";
let n = 0;
assert.deepEqual(godlockHead({ ok: true, status: "VERIFIED", errors: [], ledger_head: H, ledger_entries: 71 }).head, H); n++;
assert.equal(godlockHead({ ok: true, status: "BROKEN", errors: [], ledger_head: H, ledger_entries: 71 }).anchored, false); n++;
assert.equal(godlockHead({ ok: true, status: "VERIFIED", errors: ["x"], ledger_head: H, ledger_entries: 71 }).anchored, false); n++;
assert.equal(godlockHead({ ok: true, status: "VERIFIED", errors: [], ledger_head: "nothex", ledger_entries: 71 }).anchored, false); n++;
assert.equal(godlockHead(null).anchored, false); n++;
assert.equal(corpusHead({ tip: "0".repeat(64), lockset_tip: H }).anchored, false); n++;
assert.match(corpusHead({ tip: "0".repeat(64) }).reason, /empty/); n++;
assert.equal(corpusHead({ tip: H }).head, H); n++;
assert.equal(corpusHead({ tip: "abc" }).anchored, false); n++;
const ext = await readExternalHeads(async (url) => { if (url.includes("godlock")) throw new Error("down"); return { tip: H }; });
assert.equal(ext.godlock.anchored, false); assert.match(ext.godlock.reason, /unreachable/);
assert.equal(ext.corpus.anchored, true); n++;
console.log(`external-heads: ${n} passed`);
