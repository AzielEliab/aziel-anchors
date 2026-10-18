// AZRT-BUILD-WITNESS-1.0 tests: run with `node tests/build-identity.test.mjs`.
import assert from "node:assert/strict";
import { buildOf, buildChanged, buildSource, statementBuild, isFlap, FLAP_WINDOW_MS } from "../scripts/build-identity.mjs";
const SHA = "3221bbe47c04873575957d4f6220133e65039111";
const VID = "38a05023-5835-4ce0-a203-a53fb11382e6";
let n = 0;
assert.deepEqual(buildOf({ git_sha: SHA, build: { git_sha: SHA, version_id: VID } }), { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: SHA, version_id: VID }); n++;
assert.deepEqual(buildOf({ git_sha: SHA }), { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: SHA, version_id: null }, "older runtime: git_sha only"); n++;
assert.equal(buildOf({ build: { git_sha: "nope" } }).git_sha, null, "never guessed"); n++;
assert.equal(buildOf(null).git_sha, null); n++;
assert.deepEqual(statementBuild({ git_sha: SHA }), { git_sha: SHA, version_id: null }); n++;
assert.equal(buildChanged({ git_sha: SHA, build: { git_sha: SHA, version_id: VID } }, buildOf({ build: { git_sha: SHA, version_id: VID } })), false); n++;
assert.equal(buildChanged({ git_sha: SHA, build: { git_sha: SHA, version_id: VID } }, buildOf({ build: { git_sha: SHA, version_id: "new" } })), true, "redeploy, same sha"); n++;
assert.equal(buildChanged({ git_sha: "a".repeat(40) }, buildOf({ git_sha: SHA })), true); n++;
assert.equal(buildChanged({ git_sha: SHA }, buildOf({ build: { git_sha: SHA, version_id: VID } })), true, "first statement with version_id"); n++;
assert.equal(buildChanged(null, buildOf({ git_sha: SHA })), true); n++;
const NOW = Date.parse("2026-10-13T20:00:00Z");
const st = (vid, minsAgo = 60) => ({ statement: { git_sha: SHA, observed_at: new Date(NOW - minsAgo * 60_000).toISOString(), build: { git_sha: SHA, version_id: vid } } });
const b = (vid) => buildOf({ build: { git_sha: SHA, version_id: vid } });
assert.equal(FLAP_WINDOW_MS, 15 * 60_000); n++;
assert.equal(isFlap([st("a", 30), st("b", 5)], b("a"), NOW), true, "A,B,A within 15 min of newest: flap, skip"); n++;
assert.equal(isFlap([st("a", 60), st("b", 20)], b("a"), NOW), false, "newest is 20 min old: anchor"); n++;
assert.equal(isFlap([st("c", 90), st("a", 60), st("b", 30), st("d", 5)], b("c"), NOW), false, "rollback to a version 3 statements back: anchor"); n++;
assert.equal(isFlap([st("a", 60), st("b", 30), st("c", 5)], b("a"), NOW), false, "rollback two back (not the one just before newest): anchor"); n++;
assert.equal(isFlap([st("b", 5)], b("a"), NOW), false, "one statement only: anchor"); n++;
assert.equal(isFlap([st("a", 30), st("b", 5)], buildOf({ git_sha: SHA }), NOW), false, "no version_id: never skipped"); n++;
assert.equal(isFlap([st("a", 30), { statement: { build: { version_id: "b" } } }], b("a"), NOW), false, "newest without observed_at: anchor"); n++;
// version_id null (statements 24-34): the runtime then live published no build object. Live 22ba95e does.
{
  const pre286 = { git_sha: "cbb350992c4ab7b9f204c92b409d144a42c31545", version: "2.0.0-rc1", chains: [] };
  assert.deepEqual(buildOf(pre286), { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: pre286.git_sha, version_id: null });
  assert.equal(buildSource(pre286).from, "heads.git_sha"); assert.match(buildSource(pre286).reason, /#286/); n++;
  const live = { git_sha: "22ba95e126410302ed85ebbdaaa314264de63f0a", build: { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: "22ba95e126410302ed85ebbdaaa314264de63f0a", version_id: "f50445ee-0fc3-42d8-9bfe-3cace58ab715" }, chains: [] };
  assert.equal(buildOf(live).version_id, "f50445ee-0fc3-42d8-9bfe-3cace58ab715");
  assert.deepEqual(buildSource(live), { from: "heads.build", version_id_published: true });
  // The first statement after the 22ba95e deploy is anchored even if no head moved (build changed vs n=34).
  const n34 = { git_sha: pre286.git_sha, build: { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: pre286.git_sha, version_id: null } };
  assert.equal(buildChanged(n34, buildOf(live)), true); n++;
  assert.equal(buildSource({ build: { git_sha: SHA, version_id: null } }).version_id_published, false);
  assert.equal(buildSource(null).from, "none"); n++;
}
console.log(`build-identity: ${n} passed`);
