// AZRT-BUILD-PROVENANCE-1.0. Self-reported git_sha and version_id stay self_consistent.
// CI provenance compares bundle_sha256 + git_sha. Cloudflare stays disabled with no token.
// Run: node tests/build-provenance.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import { buildChanged, buildOf } from "../scripts/build-identity.mjs";
import {
  assessBuildProvenance,
  checkCloudflareVersion,
  compareCiProvenance,
  loadCiAttestation,
  provenanceWarrantsAnchor,
  withProvenance,
} from "../scripts/build-provenance.mjs";

const SHA = "116c56c41cb35c9184fc22b30a0e97c1fd9c3ada";
const VID = "d6a14842-98ff-4c60-925f-606607a74012";
const DIGEST = "64c2601346ce313e6498b64da4efa957b32147535e9c01ea2d4125f480fca414";
const heads = {
  git_sha: SHA,
  build: { git_sha: SHA, version_id: VID },
  build_attest: { artifact_digest: DIGEST },
};
let n = 0;
const t = async (fn) => { await fn(); n++; };

const reported = { bundle_digest: DIGEST, git_sha: SHA, version_id: VID };
const attestation = { bundle_sha256: DIGEST, git_sha: SHA };

await t(async () => {
  const build = buildOf(heads);
  assert.equal(build.assurance.git_sha, "self_consistent");
  assert.equal(build.assurance.version_id, "self_consistent");
  assert.equal(JSON.stringify(build.assurance).includes("verified"), false);
});

await t(async () => {
  assert.equal(compareCiProvenance(reported, null).status, "not_checked");
  assert.equal(compareCiProvenance(reported, { malformed: true }).status, "malformed");
  assert.equal(compareCiProvenance(reported, { bundle_sha256: "abcd", git_sha: SHA }).status, "malformed");
  assert.equal(compareCiProvenance({ bundle_digest: null, git_sha: SHA }, attestation).status, "not_checked");
});

await t(async () => {
  const match = compareCiProvenance(reported, attestation);
  assert.equal(match.status, "match");
  assert.equal(match.bundle_match, true);
  assert.equal(match.git_match, true);
  const mismatch = compareCiProvenance(reported, { bundle_sha256: "ab".repeat(32), git_sha: SHA });
  assert.equal(mismatch.status, "mismatch");
  const gitMismatch = compareCiProvenance(reported, { bundle_sha256: DIGEST, git_sha: "a".repeat(40) });
  assert.equal(gitMismatch.status, "mismatch");
  assert.equal(gitMismatch.git_match, false);
});

await t(async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error("must not run"); };
  const off = await checkCloudflareVersion({ versionId: VID, env: {}, fetchImpl });
  assert.equal(off.enabled, false);
  assert.equal(off.status, "disabled");
  assert.equal(off.reason, "no read-only token");
  assert.equal(calls, 0);
});

await t(async () => {
  const token = "read-only-token-value";
  let seen = null;
  const fetchImpl = async (url, opts) => {
    seen = { url, authorization: opts.headers.authorization };
    return { ok: true, status: 200, json: async () => ({ success: true, result: { id: VID } }) };
  };
  const on = await checkCloudflareVersion({ versionId: VID, env: { CLOUDFLARE_READONLY_TOKEN: token }, fetchImpl });
  assert.equal(on.enabled, true);
  assert.equal(on.status, "match");
  assert.equal(on.version_id, VID);
  assert.match(seen.url, /\/workers\/scripts\/aziel-runtime\/versions\//);
  assert.equal(seen.authorization, `Bearer ${token}`);
  assert.equal(JSON.stringify(on).includes(token), false);
  const other = await checkCloudflareVersion({
    versionId: VID,
    env: { CLOUDFLARE_READONLY_TOKEN: token },
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ success: true, result: { id: "other-version" } }) }),
  });
  assert.equal(other.status, "mismatch");
});

await t(async () => {
  const assessed = await assessBuildProvenance(heads, { attestation, env: {} });
  const build = withProvenance(buildOf(heads), assessed);
  assert.equal(build.assurance.git_sha, "self_consistent");
  assert.equal(build.assurance.version_id, "self_consistent");
  assert.equal(build.provenance.ci.status, "match");
  assert.equal(build.provenance.bundle_digest, DIGEST);
  assert.equal(build.provenance.bundle_digest_source, "runtime_self_report");
  assert.equal(build.provenance.bundle_digest_status, "ci_match");
  assert.equal(build.provenance.cloudflare.enabled, false);
  assert.equal(JSON.stringify(build).includes("verified"), false);
  assert.equal(buildChanged({ build: { git_sha: SHA, version_id: VID } }, build), false);
});

await t(async () => {
  const quiet = await assessBuildProvenance(heads, { attestation: null, env: {} });
  const build = withProvenance(buildOf(heads), quiet);
  assert.equal(build.provenance.ci.status, "not_checked");
  assert.equal(build.provenance.bundle_digest_status, "self_consistent");
  assert.equal(provenanceWarrantsAnchor(null, build), false);
  assert.equal(provenanceWarrantsAnchor({ build: { git_sha: SHA, version_id: VID } }, build), false);
  const matched = withProvenance(buildOf(heads), await assessBuildProvenance(heads, { attestation, env: {} }));
  assert.equal(provenanceWarrantsAnchor(null, matched), true);
  assert.equal(provenanceWarrantsAnchor({ build: matched }, matched), false);
});

await t(async () => {
  assert.equal(await loadCiAttestation({}), null);
  const parsed = await loadCiAttestation({ CI_PROVENANCE_JSON: JSON.stringify(attestation) });
  assert.equal(parsed.bundle_sha256, DIGEST);
  assert.equal((await loadCiAttestation({ CI_PROVENANCE_JSON: "{" })).malformed, true);
  let called = 0;
  const fromUrl = await loadCiAttestation({ CI_PROVENANCE_URL: "https://ci.example/provenance.json" }, async () => {
    called++;
    return { ok: true, status: 200, text: async () => JSON.stringify(attestation) };
  });
  assert.equal(called, 1);
  assert.equal(fromUrl.git_sha, SHA);
});

await t(async () => {
  const witness = fs.readFileSync(new URL("../.github/workflows/witness.yml", import.meta.url), "utf8");
  const rotate = fs.readFileSync(new URL("../.github/workflows/rotate-keys.yml", import.meta.url), "utf8");
  assert.equal(witness.includes("CLOUDFLARE_READONLY_TOKEN"), false);
  assert.equal(witness.includes("CI_PROVENANCE_JSON"), false);
  assert.equal(rotate.includes("secrets."), false);
  assert.match(rotate, /witness-rotation\.mjs/);
});

console.log(`build-provenance: ${n} passed`);
