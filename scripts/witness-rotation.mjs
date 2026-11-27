// AZRT-WITNESS-ROTATION-1.0. A witness-key rotation is accepted only when BOTH signatures
// verify over the canonical rotation body: the OLD witness key (keys/witness.pub) and the
// operator root key. The root public key is pinned in keys/operator-root.json. No pin
// refuses the rotation, including a document that carries both signatures. The holder of
// the witness secret alone cannot rotate it. This module does not rewrite anchors/log.jsonl
// or keys/epochs.json. Cap-7 is not ICANN. Paid satellite stays HELD. No secret is read or written.
import fs from "node:fs";
import { canonicalize, verify } from "./lib.mjs";

export const ROTATION_SPEC = "AZRT-WITNESS-ROTATION-1.0";
const PUB_RE = /^[A-Za-z0-9_-]{43}$/;

export function pubOk(k) {
  if (typeof k !== "string" || !PUB_RE.test(k.trim())) return false;
  return Buffer.from(k.trim(), "base64url").length === 32;
}

/** Pinned root public key, or null when the repo has not configured one. */
export function loadPinnedRoot(path = "keys/operator-root.json") {
  try {
    const cfg = JSON.parse(fs.readFileSync(path, "utf8"));
    const key = cfg && typeof cfg.public_key === "string" ? cfg.public_key.trim() : "";
    return pubOk(key) ? key : null;
  } catch {
    return null;
  }
}

/** Bytes both signatures cover. Signature fields themselves are not part of the body. */
export function rotationBody(doc) {
  const body = {};
  for (const [k, v] of Object.entries(doc || {})) {
    if (k === "sig_old" || k === "sig_root") continue;
    body[k] = v;
  }
  return body;
}

/**
 * @returns {{ok:boolean, code:string, from_public_key?:string, to_public_key?:string}}
 * Codes: WITNESS-ROTATION-NO-ROOT, WITNESS-ROTATION-UNSIGNED, WITNESS-ROTATION-OLD-ONLY,
 * WITNESS-ROTATION-ROOT-ONLY, WITNESS-ROTATION-MALFORMED, WITNESS-ROTATION-OK.
 */
function sigOk(pub, text, sig) {
  if (!pubOk(pub) || typeof sig !== "string" || sig.length === 0) return false;
  try {
    return verify(pub, text, sig) === true;
  } catch {
    return false;
  }
}

export function verifyWitnessRotation(doc, { oldWitnessPub, rootPub } = {}) {
  if (!pubOk(rootPub)) return { ok: false, code: "WITNESS-ROTATION-NO-ROOT" };
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, code: "WITNESS-ROTATION-UNSIGNED" };
  const oldPub = typeof oldWitnessPub === "string" ? oldWitnessPub.trim() : "";
  const root = rootPub.trim();
  let text;
  try {
    text = canonicalize(rotationBody(doc));
  } catch {
    return { ok: false, code: "WITNESS-ROTATION-UNSIGNED" };
  }
  const oldOk = sigOk(oldPub, text, doc.sig_old);
  const rootOk = sigOk(root, text, doc.sig_root);
  if (!oldOk && !rootOk) return { ok: false, code: "WITNESS-ROTATION-UNSIGNED" };
  if (oldOk && !rootOk) return { ok: false, code: "WITNESS-ROTATION-OLD-ONLY" };
  if (!oldOk && rootOk) return { ok: false, code: "WITNESS-ROTATION-ROOT-ONLY" };
  const body = rotationBody(doc);
  if (body.spec !== ROTATION_SPEC || body.role !== "witness") return { ok: false, code: "WITNESS-ROTATION-MALFORMED" };
  if (!pubOk(body.from_public_key) || body.from_public_key !== oldPub) return { ok: false, code: "WITNESS-ROTATION-MALFORMED" };
  if (!pubOk(body.to_public_key) || body.to_public_key === body.from_public_key) return { ok: false, code: "WITNESS-ROTATION-MALFORMED" };
  return { ok: true, code: "WITNESS-ROTATION-OK", from_public_key: body.from_public_key, to_public_key: body.to_public_key };
}

export function parseAuthorization(authorization) {
  if (authorization == null || (typeof authorization === "string" && authorization.trim() === "")) return null;
  if (typeof authorization === "object") return authorization;
  try {
    return JSON.parse(authorization);
  } catch {
    return undefined;
  }
}

export function gateWitnessRotation({ rootPub, oldWitnessPub, authorization } = {}) {
  if (!pubOk(rootPub)) return { ok: false, code: "WITNESS-ROTATION-NO-ROOT" };
  const doc = parseAuthorization(authorization);
  if (doc == null || doc === undefined) return { ok: false, code: "WITNESS-ROTATION-UNSIGNED" };
  return verifyWitnessRotation(doc, { oldWitnessPub, rootPub });
}

/** The minted witness public key is the rotation only when it is the signed to_public_key. */
export function expectGeneratedWitness(rotationFile, authorization, { rootPub, oldWitnessPub } = {}) {
  const gated = gateWitnessRotation({ rootPub, oldWitnessPub, authorization });
  if (!gated.ok) return gated;
  let generated;
  try {
    const parsed = typeof rotationFile === "string" ? JSON.parse(fs.readFileSync(rotationFile, "utf8")) : rotationFile;
    generated = parsed && parsed.keys && parsed.keys.WITNESS_ED25519_PKCS8 && parsed.keys.WITNESS_ED25519_PKCS8.public_key;
  } catch {
    return { ok: false, code: "WITNESS-ROTATION-GENERATED-MISMATCH" };
  }
  if (generated !== gated.to_public_key) return { ok: false, code: "WITNESS-ROTATION-GENERATED-MISMATCH" };
  return gated;
}

function isDirectRun() {
  const arg = process.argv[1] || "";
  return arg.endsWith("/witness-rotation.mjs") || arg.endsWith("\\witness-rotation.mjs");
}

if (isDirectRun()) {
  const rootPub = loadPinnedRoot();
  const oldWitnessPub = fs.readFileSync("keys/witness.pub", "utf8").trim();
  const expectIdx = process.argv.indexOf("--expect-generated");
  const result = expectIdx >= 0
    ? expectGeneratedWitness(process.argv[expectIdx + 1], process.env.ROTATION_AUTHORIZATION, { rootPub, oldWitnessPub })
    : gateWitnessRotation({ rootPub, oldWitnessPub, authorization: process.env.ROTATION_AUTHORIZATION });
  if (!result.ok) {
    if (expectIdx >= 0 && process.argv[expectIdx + 1]) {
      try { fs.rmSync(process.argv[expectIdx + 1], { force: true }); } catch { /* ephemeral runner file */ }
    }
    console.error(result.code);
    process.exit(1);
  }
  console.log(result.code);
}
