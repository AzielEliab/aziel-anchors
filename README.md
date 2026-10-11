# aziel-anchors

External witness and auditor for [aziel-runtime](https://github.com/AzielEliab/aziel-runtime) (specs `AZRT-ANCHOR-1.0`, `AZRT-AUDITOR-1.0`). Author: Aziel Eliab.

- `anchors/log.jsonl` — append-only, chained witness statements of the runtime's chain heads (`/v1/anchor/heads`) and checkpoint tips. Each statement is signed with Ed25519 (`keys/witness.pub`), timestamped by RFC 3161 (freetsa.org, token in `anchors/tsr/<n>.tsr`) and logged in Sigstore Rekor.
- `audits/log.jsonl` — append-only, chained audit receipts from a separate job with a separate key (`keys/auditor.pub`): re-verifies every witness signature, TSA token and Rekor entry, and checks the live runtime still holds every anchored head.

The private keys exist only as this repository's GitHub Actions secrets (`WITNESS_ED25519_PKCS8`, `AUDITOR_ED25519_PKCS8`). The runtime Worker has neither key and no write access here; it pins the public keys and only reads these logs. Fail closed: a missing, re-ordered, re-signed or mismatching statement is refused by the runtime's `GET /v1/anchor`.

Honest limits: the keys were generated on the operator's build machine, written straight into the Actions secrets, and the local copies were shredded; the repository owner can still rotate secrets or rewrite git history (Rekor and the RFC 3161 tokens are the parts the owner cannot rewrite). GitHub schedules are best-effort (gaps of more than 15 minutes happen).

Verify a statement yourself: recompute `sha256(canonical JSON of statement)`, check the Ed25519 signature with `keys/witness.pub`, then `openssl ts -verify -data <statement bytes> -in anchors/tsr/<n>.tsr -CAfile keys/freetsa-cacert.pem -untrusted keys/freetsa-tsa.crt`.
