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
 * Anti-flap, real flaps only (gradual deploys alternating A/B/A). Skip a BUILD-ONLY statement only when
 * BOTH hold: the version_id equals the build of the statement just before the newest one (A, B, now A
 * again), AND the newest statement is less than FLAP_WINDOW_MS old. An honest rollback to any older
 * version, or an A->B->A after the newest statement has aged, is anchored. Heads changes always anchor.
 */
export const FLAP_WINDOW_MS = 15 * 60_000;
export function isFlap(log, build, now = Date.now()) {
  const vid = build && build.version_id;
  const rows = log || [];
  if (!vid || rows.length < 2) return false;
  const before = statementBuild(rows[rows.length - 2] && rows[rows.length - 2].statement);
  if (!before || before.version_id !== vid) return false;
  const seen = Date.parse(rows[rows.length - 1].statement && rows[rows.length - 1].statement.observed_at);
  return Number.isFinite(seen) && now - seen >= 0 && now - seen < FLAP_WINDOW_MS;
}
