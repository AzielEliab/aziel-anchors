// AZRT-WITNESS-ROTATION-1.0. Unsigned refused, old-key-only refused, both signatures accepted.
// No pinned root refuses the rotation. Run: node tests/witness-rotation.test.mjs
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalize, sign } from "../scripts/lib.mjs";
import {
  expectGeneratedWitness,
  gateWitnessRotation,
  loadPinnedRoot,
  rotationBody,
  verifyWitnessRotation,
} from "../scripts/witness-rotation.mjs";

function pair() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(12).toString("base64url");
  return { key: privateKey, pub };
}

const old = pair();
const root = pair();
const next = pair();
const body = {
  spec: "AZRT-WITNESS-ROTATION-1.0",
  role: "witness",
  from_public_key: old.pub,
  to_public_key: next.pub,
};
const text = canonicalize(body);
const signedBy = (who) => ({ ...body, ...who });
const ctx = { oldWitnessPub: old.pub, rootPub: root.pub };
let n = 0;
const t = (fn) => { fn(); n++; };

const unsigned = signedBy({});
t(() => assert.equal(verifyWitnessRotation(unsigned, ctx).ok, false));
t(() => assert.equal(verifyWitnessRotation(unsigned, ctx).code, "WITNESS-ROTATION-UNSIGNED"));
t(() => assert.equal(gateWitnessRotation({ ...ctx, authorization: "" }).code, "WITNESS-ROTATION-UNSIGNED"));
t(() => assert.equal(verifyWitnessRotation(null, ctx).code, "WITNESS-ROTATION-UNSIGNED"));

const oldOnly = signedBy({ sig_old: sign(old.key, text) });
t(() => assert.equal(verifyWitnessRotation(oldOnly, ctx).ok, false));
t(() => assert.equal(verifyWitnessRotation(oldOnly, ctx).code, "WITNESS-ROTATION-OLD-ONLY"));
const oldPlusBadRoot = signedBy({ sig_old: sign(old.key, text), sig_root: sign(next.key, text) });
t(() => assert.equal(verifyWitnessRotation(oldPlusBadRoot, ctx).code, "WITNESS-ROTATION-OLD-ONLY"));

const both = signedBy({ sig_old: sign(old.key, text), sig_root: sign(root.key, text) });
const accepted = verifyWitnessRotation(both, ctx);
t(() => assert.equal(accepted.ok, true));
t(() => assert.equal(accepted.code, "WITNESS-ROTATION-OK"));
t(() => assert.equal(accepted.from_public_key, old.pub));
t(() => assert.equal(accepted.to_public_key, next.pub));
t(() => assert.equal(gateWitnessRotation({ ...ctx, authorization: JSON.stringify(both) }).ok, true));

// The repo pin is null. Both signatures still refuse until an operator root is configured.
t(() => assert.equal(loadPinnedRoot(new URL("../keys/operator-root.json", import.meta.url)), null));
t(() => assert.equal(verifyWitnessRotation(both, { oldWitnessPub: old.pub, rootPub: null }).code, "WITNESS-ROTATION-NO-ROOT"));
t(() => assert.equal(verifyWitnessRotation(both, { oldWitnessPub: old.pub, rootPub: "" }).code, "WITNESS-ROTATION-NO-ROOT"));
t(() => assert.equal(verifyWitnessRotation(oldOnly, { oldWitnessPub: old.pub, rootPub: null }).code, "WITNESS-ROTATION-NO-ROOT"));

const rootOnly = signedBy({ sig_root: sign(root.key, text) });
t(() => assert.equal(verifyWitnessRotation(rootOnly, ctx).code, "WITNESS-ROTATION-ROOT-ONLY"));

const swapped = { ...both, from_public_key: next.pub };
t(() => assert.equal(verifyWitnessRotation(swapped, ctx).ok, false));

const minted = { keys: { WITNESS_ED25519_PKCS8: { public_key: next.pub } } };
t(() => assert.equal(expectGeneratedWitness(minted, both, ctx).ok, true));
const other = { keys: { WITNESS_ED25519_PKCS8: { public_key: pair().pub } } };
t(() => assert.equal(expectGeneratedWitness(other, both, ctx).code, "WITNESS-ROTATION-GENERATED-MISMATCH"));
t(() => assert.deepEqual(rotationBody(both), body));

t(() => {
  let stderr = "";
  let code = 0;
  try {
    execFileSync(process.execPath, ["scripts/witness-rotation.mjs"], {
      encoding: "utf8",
      env: { ...process.env, ROTATION_AUTHORIZATION: JSON.stringify(both) },
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    code = err.status;
    stderr = err.stderr.toString();
  }
  assert.equal(code, 1);
  assert.match(stderr, /WITNESS-ROTATION-NO-ROOT/);
});

console.log(`witness-rotation: ${n} passed`);
