import assert from "node:assert/strict";
import { receiptKeyAlert, lastRecordedKey } from "../scripts/receipt-key-guard.mjs";
const PUB = "5hjGrDhtR5IFJqEY30smt8CyRKXIRMYdijU_IAT8iP8";
const A = { key_id: "ed25519:" + "a".repeat(64), public_key: PUB, retired: [] };
const B = { key_id: "ed25519:" + "b".repeat(64), public_key: PUB, retired: [] };
const Bret = { ...B, retired: [{ key_id: A.key_id, until: "2026-10-19T00:00:00Z" }] };
const BretStr = { ...B, retired: [A.key_id] };
let n = 0; const t = (f) => { f(); n++; };
t(() => assert.equal(receiptKeyAlert(null, A), null));            // first provisioning
t(() => assert.equal(receiptKeyAlert(null, null), null));         // never had a key
t(() => assert.equal(receiptKeyAlert(A, A), null));               // unchanged
t(() => assert.equal(receiptKeyAlert(A, B).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(receiptKeyAlert(A, Bret), null));            // proper rotation (object entry)
t(() => assert.equal(receiptKeyAlert(A, BretStr), null));         // proper rotation (string entry)
t(() => assert.equal(receiptKeyAlert(A, { ...B, retired: [{ key_id: "ed25519:" + "f".repeat(64) }] }).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(receiptKeyAlert(A, null).code, "RECEIPT-KEY-DROPPED"));
t(() => assert.equal(receiptKeyAlert(A, { key_id: null }).code, "RECEIPT-KEY-DROPPED"));
t(() => assert.equal(receiptKeyAlert(A, {}).code, "RECEIPT-KEY-DROPPED"));
// last recorded key survives a later statement that predates the field or recorded null
const log = [{ statement: { receipt_key: A } }, { statement: {} }, { statement: { receipt_key: null } }];
t(() => assert.deepEqual(lastRecordedKey(log), A));
t(() => assert.equal(receiptKeyAlert(lastRecordedKey(log), B).code, "RECEIPT-KEY-CHANGED-UNRETIRED"));
t(() => assert.equal(lastRecordedKey([{ statement: { n: 1 } }]), null));
// shape check on first appearance (first provisioning or a new key_id), fail closed
const M = "RECEIPT-KEY-MALFORMED";
t(() => assert.equal(receiptKeyAlert(null, { key_id: "ed25519:aa", public_key: PUB }).code, M));
t(() => assert.equal(receiptKeyAlert(null, { key_id: "ed25519:" + "A".repeat(64), public_key: PUB }).code, M));
t(() => assert.equal(receiptKeyAlert(null, { key_id: A.key_id, public_key: PUB + "=" }).code, M));
t(() => assert.equal(receiptKeyAlert(null, { key_id: A.key_id, public_key: "5hjGrDhtR5IFJqEY30smt8CyRKXIRMYdijU+IAT8iP8" }).code, M));
t(() => assert.equal(receiptKeyAlert(null, { key_id: A.key_id }).code, M));
t(() => assert.equal(receiptKeyAlert(null, {}).code, M));
t(() => assert.equal(receiptKeyAlert(A, { ...Bret, public_key: "short" }).code, M));
t(() => assert.equal(receiptKeyAlert(null, { spec: "AZRT-KEYS-1.0", key_id: "ed25519:78aa5564baffbda0fcf1dfc4a2d07f41d730062f2175a2eeb786236f7b576874", public_key: PUB, retired: [] }), null)); // live shape
console.log(`ok receipt key guard: ${n} checks`);
