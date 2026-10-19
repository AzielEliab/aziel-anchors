import assert from "node:assert/strict";
import { receiptKeyAlert, lastRecordedKey } from "../scripts/receipt-key-guard.mjs";
const A = { key_id: "ed25519:aa", public_key: "pa", retired: [] };
const B = { key_id: "ed25519:bb", public_key: "pb", retired: [] };
const Bret = { ...B, retired: [{ key_id: "ed25519:aa", until: "2026-10-19T00:00:00Z" }] };
const BretStr = { ...B, retired: ["ed25519:aa"] };
let n = 0; const t = (f) => { f(); n++; };
t(() => assert.equal(receiptKeyAlert(null, A), null));            // first provisioning
t(() => assert.equal(receiptKeyAlert(null, null), null));         // never had a key
t(() => assert.equal(receiptKeyAlert(A, A), null));               // unchanged
t(() => assert.equal(receiptKeyAlert(A, B).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(receiptKeyAlert(A, Bret), null));            // proper rotation (object entry)
t(() => assert.equal(receiptKeyAlert(A, BretStr), null));         // proper rotation (string entry)
t(() => assert.equal(receiptKeyAlert(A, { ...B, retired: [{ key_id: "ed25519:zz" }] }).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(receiptKeyAlert(A, null).code, "RECEIPT-KEY-DROPPED"));
t(() => assert.equal(receiptKeyAlert(A, { key_id: null }).code, "RECEIPT-KEY-DROPPED"));
t(() => assert.equal(receiptKeyAlert(A, {}).code, "RECEIPT-KEY-DROPPED"));
// last recorded key survives a later statement that predates the field or recorded null
const log = [{ statement: { receipt_key: A } }, { statement: {} }, { statement: { receipt_key: null } }];
t(() => assert.deepEqual(lastRecordedKey(log), A));
t(() => assert.equal(receiptKeyAlert(lastRecordedKey(log), B).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(lastRecordedKey([{ statement: { n: 1 } }]), null));
console.log(`ok receipt key guard: ${n} checks`);
