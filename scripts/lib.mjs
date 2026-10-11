// Shared helpers. canonicalize() is byte-identical to aziel-runtime src/session-core.js.
import crypto from "node:crypto";
import fs from "node:fs";

export const RUNTIME = process.env.RUNTIME_ORIGIN || "https://aziel-runtime.vibelock.workers.dev";
export const ZERO = "0".repeat(64);

export function canonicalize(value) {
  if (value === undefined) return undefined;
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("cannot canonicalize non-finite number");
    return JSON.stringify(value);
  }
  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
  }
  throw new Error("cannot canonicalize " + t);
}

export const sha256 = (text) => crypto.createHash("sha256").update(text).digest("hex");

export function loadKey(envName) {
  const b64 = process.env[envName];
  if (!b64) throw new Error(`${envName} secret is not set`);
  const key = crypto.createPrivateKey({ key: Buffer.from(b64.trim(), "base64"), format: "der", type: "pkcs8" });
  const pub = crypto.createPublicKey(key).export({ type: "spki", format: "der" }).subarray(12).toString("base64url");
  return { key, pub, pem: crypto.createPublicKey(key).export({ type: "spki", format: "pem" }) };
}

export function sign(key, text) {
  return crypto.sign(null, Buffer.from(text), key).toString("base64url");
}

export function verify(pubB64url, text, sigB64url) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubB64url, "base64url")]);
  const pub = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  return crypto.verify(null, Buffer.from(text), pub, Buffer.from(sigB64url, "base64url"));
}

export function readJsonl(path) {
  if (!fs.existsSync(path)) return [];
  return fs.readFileSync(path, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

export async function getJson(url) {
  const res = await fetch(url, { headers: { "user-agent": "aziel-anchors-witness" } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

/** Sigstore Rekor (free public log): rekord entry over the exact signed bytes. */
export async function rekorSubmit(pem, text, sigB64url) {
  const body = {
    apiVersion: "0.0.1",
    kind: "rekord",
    spec: {
      signature: { format: "x509", content: Buffer.from(sigB64url, "base64url").toString("base64"), publicKey: { content: Buffer.from(pem).toString("base64") } },
      data: { content: Buffer.from(text).toString("base64") },
    },
  };
  const res = await fetch("https://rekor.sigstore.dev/api/v1/log/entries", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await res.json();
  if (res.status !== 201) throw new Error("rekor " + res.status + " " + JSON.stringify(j).slice(0, 200));
  const uuid = Object.keys(j)[0];
  return { uuid, log_index: j[uuid].logIndex, integrated_time: j[uuid].integratedTime, url: `https://search.sigstore.dev/?uuid=${uuid}` };
}

/** Key epochs: keys/epochs.json lists retired keys with the last n each one signed. Rows after
 *  every retired epoch must use the current pinned key (keys/<role>.pub). Append-only file. */
export function keyFor(role, n) {
  const cur = fs.readFileSync(`keys/${role}.pub`, "utf8").trim();
  if (!fs.existsSync("keys/epochs.json")) return cur;
  const ep = (JSON.parse(fs.readFileSync("keys/epochs.json", "utf8"))[role] || []).find((e) => n >= e.from_n && n <= e.through_n);
  return ep ? ep.public_key : cur;
}
