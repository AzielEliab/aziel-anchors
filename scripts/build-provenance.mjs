// AZRT-BUILD-PROVENANCE-1.0. The witness records the runtime's git_sha and version_id as a
// self-report (assurance self_consistent). It does not label that copy verified.
// This module compares the runtime's reported bundle digest with a CI provenance attestation
// (bundle_sha256 + git_sha from an aziel-runtime CI artifact). A Cloudflare version read is
// a second, optional path and stays disabled unless CLOUDFLARE_READONLY_TOKEN is set.
// This module does not create that secret and does not put a token into the statement.
// Cap-7 is not ICANN. Paid satellite stays HELD. Remain-OFF is untouched.
import { canonicalize } from "./lib.mjs";
import { buildOf } from "./build-identity.mjs";

export const PROVENANCE_SPEC = "AZRT-BUILD-PROVENANCE-1.0";
export const CF_READONLY_TOKEN_ENV = "CLOUDFLARE_READONLY_TOKEN";
// Published in aziel-runtime wrangler.toml. Not a secret. Used only when the read-only token is set.
export const DEFAULT_CF_ACCOUNT_ID = "ac575a9b822bea2bed97d0ab73aed238";
export const DEFAULT_CF_SCRIPT = "aziel-runtime";

const HEX64 = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{7,40}$/;
const clean = (v) => (v == null || v === "" ? null : String(v).trim().toLowerCase() || null);

export function reportedBundleDigest(heads) {
  const raw = heads && heads.build_attest && heads.build_attest.artifact_digest;
  const digest = clean(raw);
  return digest && HEX64.test(digest) ? digest : null;
}

export function cloudflareCheckEnabled(env = process.env) {
  const token = env && typeof env[CF_READONLY_TOKEN_ENV] === "string" ? env[CF_READONLY_TOKEN_ENV].trim() : "";
  return Boolean(token);
}

/**
 * CI attestation shape: { bundle_sha256, git_sha }. Absent attestation is not_checked.
 * match requires the bundle digest and the git sha to both equal the runtime report.
 * The self-report is never upgraded to verified by this function.
 */
export function compareCiProvenance(reported, attestation) {
  if (!attestation) return { status: "not_checked", reason: "no CI provenance attestation" };
  if (attestation.malformed === true) return { status: "malformed", reason: "CI provenance JSON did not parse" };
  const bundle = clean(attestation.bundle_sha256);
  const git = clean(attestation.git_sha);
  if (!bundle || !HEX64.test(bundle) || !git || !SHA.test(git)) {
    return { status: "malformed", reason: "CI attestation needs bundle_sha256 and git_sha" };
  }
  if (!reported || !reported.bundle_digest) {
    return { status: "not_checked", reason: "runtime published no bundle digest", attestation_git_sha: git, bundle_sha256: bundle };
  }
  const bundleMatch = reported.bundle_digest === bundle;
  const gitMatch = Boolean(reported.git_sha) && reported.git_sha === git;
  const base = { bundle_sha256: bundle, git_sha: git, bundle_match: bundleMatch, git_match: gitMatch };
  if (bundleMatch && gitMatch) return { status: "match", ...base };
  return { status: "mismatch", ...base };
}

/**
 * Optional. Disabled when CLOUDFLARE_READONLY_TOKEN is unset: no request is made.
 * A match means the version API returned the same version id. It does not label version_id verified.
 */
export async function checkCloudflareVersion({ versionId, env = process.env, fetchImpl = fetch, accountId, scriptName } = {}) {
  if (!cloudflareCheckEnabled(env)) {
    return { enabled: false, status: "disabled", reason: "no read-only token" };
  }
  const account = (accountId || (env && env.CLOUDFLARE_ACCOUNT_ID) || DEFAULT_CF_ACCOUNT_ID).trim();
  const script = (scriptName || (env && env.CLOUDFLARE_WORKER_SCRIPT) || DEFAULT_CF_SCRIPT).trim();
  const reported = clean(versionId);
  if (!reported) return { enabled: true, status: "not_checked", reason: "runtime published no version_id" };
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account)}/workers/scripts/${encodeURIComponent(script)}/versions/${encodeURIComponent(reported)}`;
  try {
    const res = await fetchImpl(url, {
      headers: { authorization: `Bearer ${env[CF_READONLY_TOKEN_ENV].trim()}`, accept: "application/json", "user-agent": "aziel-anchors-witness" },
    });
    const body = await res.json();
    const id = clean(body && body.result && (body.result.id || body.result.version_id));
    if (!res.ok || !body || body.success !== true || !id) {
      return { enabled: true, status: "unavailable", http: res.status };
    }
    if (id === reported) return { enabled: true, status: "match", version_id: id };
    return { enabled: true, status: "mismatch", version_id: id, reported };
  } catch (err) {
    return { enabled: true, status: "unavailable", reason: String(err && err.message || err).slice(0, 120) };
  }
}

export function parseCiAttestationJson(raw) {
  if (raw == null || String(raw).trim() === "") return null;
  try {
    const doc = JSON.parse(String(raw));
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { malformed: true };
    return doc;
  } catch {
    return { malformed: true };
  }
}

/** Inline JSON wins. A URL is fetched only when CI_PROVENANCE_URL is set and no inline JSON is set. */
export async function loadCiAttestation(env = process.env, fetchImpl = fetch) {
  if (env && typeof env.CI_PROVENANCE_JSON === "string" && env.CI_PROVENANCE_JSON.trim()) {
    return parseCiAttestationJson(env.CI_PROVENANCE_JSON);
  }
  const url = env && typeof env.CI_PROVENANCE_URL === "string" ? env.CI_PROVENANCE_URL.trim() : "";
  if (!url) return null;
  try {
    const res = await fetchImpl(url, { headers: { accept: "application/json", "user-agent": "aziel-anchors-witness" } });
    if (!res.ok) return { malformed: true, reason: `CI provenance URL ${res.status}` };
    return parseCiAttestationJson(await res.text());
  } catch {
    return { malformed: true, reason: "CI provenance URL unreachable" };
  }
}

export async function assessBuildProvenance(heads, { attestation = null, env = process.env, fetchImpl = fetch } = {}) {
  const identity = buildOf(heads);
  const reported = {
    bundle_digest: reportedBundleDigest(heads),
    git_sha: identity.git_sha,
    version_id: identity.version_id,
  };
  const ci = compareCiProvenance(reported, attestation);
  const cloudflare = await checkCloudflareVersion({ versionId: identity.version_id, env, fetchImpl });
  return { bundle_digest: reported.bundle_digest, ci, cloudflare };
}

function bundleStatus(digest, ci) {
  if (!digest) return "absent";
  if (ci && ci.status === "match") return "ci_match";
  if (ci && ci.status === "mismatch") return "ci_mismatch";
  return "self_consistent";
}

/** Attach provenance beside the self-report. Does not change assurance.git_sha or assurance.version_id. */
export function withProvenance(build, assessed) {
  return {
    ...build,
    provenance: {
      spec: PROVENANCE_SPEC,
      bundle_digest: assessed.bundle_digest,
      bundle_digest_source: "runtime_self_report",
      bundle_digest_status: bundleStatus(assessed.bundle_digest, assessed.ci),
      ci: assessed.ci,
      cloudflare: assessed.cloudflare,
    },
  };
}

function independentNews(provenance) {
  if (!provenance) return false;
  const ci = provenance.ci && provenance.ci.status;
  if (ci === "match" || ci === "mismatch") return true;
  const cf = provenance.cloudflare;
  return Boolean(cf && cf.enabled && (cf.status === "match" || cf.status === "mismatch"));
}

/**
 * A not_checked self-report does not by itself open a new statement (historical rows have no
 * provenance field). A CI or Cloudflare match/mismatch does, so that result is signed.
 */
export function provenanceWarrantsAnchor(lastStatement, build) {
  const cur = build && build.provenance;
  if (!independentNews(cur)) return false;
  const prev = lastStatement && lastStatement.build && lastStatement.build.provenance;
  if (!prev) return true;
  return canonicalize(prev) !== canonicalize(cur);
}
