// AZRT-BUILD-WITNESS-1.0 tests: run with `node tests/build-identity.test.mjs`.
import assert from "node:assert/strict";
import { buildOf, buildChanged, statementBuild } from "../scripts/build-identity.mjs";
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
console.log(`build-identity: ${n} passed`);
