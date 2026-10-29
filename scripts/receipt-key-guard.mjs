// AZRT-KEYS-1.0 guard for the witness. Compares the receipt key in the last signed statement with the one
// the runtime publishes now. Fails closed:
//   RECEIPT-KEY-DROPPED            a key was recorded before and now receipt_key (or its key_id) is null
//   RECEIPT-KEY-CHANGED-UNRETIRED  key_id changed and the old key_id is not listed in receipt_key.retired
//   RECEIPT-KEY-MALFORMED          a key appearing for the first time (first provisioning or a new key_id)
//                                  is not { key_id: "ed25519:<64 lowercase hex>", public_key: <43-char base64url> }
// First provisioning (no key recorded before) and an unchanged key pass. A rotation passes only when the
// runtime lists the old key as retired.
export function retiredIds(rk) {
  const out = new Set();
  for (const r of (rk && Array.isArray(rk.retired) ? rk.retired : [])) {
    if (typeof r === "string") out.add(r);
    else if (r && typeof r.key_id === "string") out.add(r.key_id);
  }
  return out;
}

const KEY_ID_RE = /^ed25519:[0-9a-f]{64}$/;
const PUB_RE = /^[A-Za-z0-9_-]{43}$/; // 32-byte Ed25519 public key, base64url, no padding
export function keyShapeOk(k) {
  if (!k || typeof k.key_id !== "string" || typeof k.public_key !== "string") return false;
  if (!KEY_ID_RE.test(k.key_id) || !PUB_RE.test(k.public_key)) return false;
  return Buffer.from(k.public_key, "base64url").length === 32;
}

export function receiptKeyAlert(prevKey, curKey) {
  const prevId = prevKey && typeof prevKey.key_id === "string" ? prevKey.key_id : null;
  const curId = curKey && typeof curKey.key_id === "string" ? curKey.key_id : null;
  if (!prevId) {
    if (!curKey) return null; // never had a key
    return keyShapeOk(curKey) ? null : { code: "RECEIPT-KEY-MALFORMED", from: null, to: curId };
  }
  if (!curId) return { code: "RECEIPT-KEY-DROPPED", from: prevId, to: null };
  if (curId === prevId) return null;
  if (!retiredIds(curKey).has(prevId)) return { code: "RECEIPT-KEY-CHANGED-UNRETIRED", from: prevId, to: curId };
  if (!keyShapeOk(curKey)) return { code: "RECEIPT-KEY-MALFORMED", from: prevId, to: curId };
  return null;
}

// The newest receipt key recorded anywhere in the log (older statements carry no receipt_key field).
export function lastRecordedKey(log) {
  for (let i = log.length - 1; i >= 0; i--) {
    const s = log[i] && log[i].statement;
    if (s && Object.prototype.hasOwnProperty.call(s, "receipt_key") && s.receipt_key) return s.receipt_key;
  }
  return null;
}
