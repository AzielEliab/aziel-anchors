// AZRT-BUILD-WITNESS-1.0 (RIB-041, @TheNabeelKhan): the runtime build identity the witness signs
// next to the chain heads. Read from GET /v1/anchor/heads; null fields stay null (never guessed).
const SHA = /^[a-f0-9]{7,40}$/;
const clean = (v) => (v == null || v === "" ? null : String(v).trim().toLowerCase() || null);

export function buildOf(heads) {
  const b = heads && typeof heads.build === "object" && heads.build ? heads.build : {};
  const sha = clean(b.git_sha ?? (heads && heads.git_sha));
  return { spec: "AZRT-BUILD-WITNESS-1.0", git_sha: sha && SHA.test(sha) ? sha : null, version_id: clean(b.version_id) };
}

/** Build the previous statement witnessed (statements before this field: top-level git_sha only). */
export function statementBuild(statement) {
  if (!statement) return null;
  if (statement.build) return { git_sha: clean(statement.build.git_sha), version_id: clean(statement.build.version_id) };
  return { git_sha: clean(statement.git_sha), version_id: null };
}

/** True when the build moved since the last statement, so a redeploy is anchored even if heads did not move. */
export function buildChanged(lastStatement, build) {
  const prev = statementBuild(lastStatement);
  if (!prev) return Boolean(build && (build.git_sha || build.version_id));
  return prev.git_sha !== build.git_sha || prev.version_id !== build.version_id;
}

/**
 * Anti-flap (gradual deploys alternate versions): skip a BUILD-ONLY statement when this version_id
 * already appears in the last RECENT_VERSION_WINDOW statements. Heads changes always anchor.
 * Consequence: during a gradual rollout the newest statement may name the other version, so the
 * runtime's build check can report a mismatch on some isolates until the rollout settles.
 */
export const RECENT_VERSION_WINDOW = 5;
export function versionSeenRecently(log, build, window = RECENT_VERSION_WINDOW) {
  const vid = build && build.version_id;
  if (!vid) return false;
  return (log || []).slice(-window).some((row) => {
    const b = statementBuild(row && row.statement);
    return b && b.version_id === vid;
  });
}
