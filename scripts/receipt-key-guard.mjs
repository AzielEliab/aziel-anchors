// AZRT-KEYS-1.0 guard for the witness. Compares the receipt key in the last signed statement with the one
// the runtime publishes now. Fails closed:
//   RECEIPT-KEY-DROPPED            a key was recorded before and now receipt_key (or its key_id) is null
//   RECEIPT-KEY-CHANGED-UNRETIRED  key_id changed and the old key_id is not listed in receipt_key.retired
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

export function receiptKeyAlert(prevKey, curKey) {
  const prevId = prevKey && typeof prevKey.key_id === "string" ? prevKey.key_id : null;
  const curId = curKey && typeof curKey.key_id === "string" ? curKey.key_id : null;
  if (!prevId) return null;
  if (!curId) return { code: "RECEIPT-KEY-DROPPED", from: prevId, to: null };
  if (curId === prevId) return null;
  if (!retiredIds(curKey).has(prevId)) return { code: "RECEIPT-KEY-CHANGED-UNRETIRED", from: prevId, to: curId };
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
