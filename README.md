# Governed Evidence Pack — Sanitized Public Reference Sample (`evidence-pack.v1`)

> **Disclosure Label: Sanitized Reference Sample**  
> This repository contains a **sanitized public reference bundle** exported from deterministic test execution at Maestro commit `cf97c8ece0edca5516d148df5aefcad9704147b7`. All tenant metadata (`org-maestro-showcase`) and operator handles (`@operator-showcase`) are neutral showcase identifiers, and the pack is signed with an ephemeral Ed25519 keypair whose private key was discarded immediately after signing.

---

## Quick Verification (Zero Network, Zero Database, Zero External Packages)

Requires **Node.js >= 18**:

```sh
node verify.mjs
```

Expected output (exit code `0`):

```json
{
  "valid": true,
  "scope": "outcome",
  "verdict": "verified",
  "claimBoundary": "pilot-attested",
  "keyMatch": true,
  "digestMatch": true,
  "htmlShaMatch": true,
  "jsonOk": true,
  "htmlOk": true,
  "auditChainOk": true,
  "auditEntriesChecked": 3
}
```

### Independent File Integrity Check

```sh
sha256sum evidence-pack.html
# Expected: 98afd400d020a8b445ecf141126296278883a580637546547c4b28341700c1e8
```

### Tamper Detection Check

Modify any byte in `evidence-pack.json` or `evidence-pack.html` and re-run `node verify.mjs` — verification fails immediately (exit code `1`) on canonical SHA-256 digest, HTML digest, audit hash-chain, or Ed25519 signature checks.

---

## Verified Fingerprints in This Bundle

| Field | Value |
| --- | --- |
| **Schema Version** | `evidence-pack.v1` |
| **Scope / Outcome ID** | `outcome` / `O-SHOWCASE-SAMPLE-01` |
| **Verdict** | `verified` |
| **Claim Boundary** | `pilot-attested` *(not `deployed-verified` — live deployment proof remains pending)* |
| **Tested Commit SHA** | `cf97c8ece0edca5516d148df5aefcad9704147b7` |
| **Automated JUnit Input** | `25 pass, 0 fail, 304 expect()` across automated signing/redaction, HTML rendering, and compliance resolver checks plus human-attested `AC-03` |
| **JUnit Report SHA-256** | `1776f455f9128416c2f052ad2084537c18ba54065584691ab3efaf050d808ad4` |
| **Pack Payload SHA-256** | `5cbc51f60469a7755242a220e29a11de7067022f892df2fe87b547dbe3d5b464` |
| **HTML Digest SHA-256** | `98afd400d020a8b445ecf141126296278883a580637546547c4b28341700c1e8` |
| **Ed25519 Key ID** | `b12e28ed7f858180` *(ephemeral public key embedded in `signature.publicKeyPem`; private key discarded)* |
| **Audit Chain Events** | `3` contiguous SHA-256 hash-chained events (`seq: 1..3`) |
| **Export Safety Gate** | `passed` (`findingsCount: 0`, `syntheticAllowed: false`) |

---

## Files Included

- [`evidence-pack.json`](./evidence-pack.json) — Canonical `evidence-pack.v1` manifest with ratified solution contract, criteria matrix, out-of-band approval records, hash-chained audit slice, compliance crosswalks (`regulated-healthcare` and `soc2`), and Ed25519 signature envelope.
- [`evidence-pack.html`](./evidence-pack.html) — Self-contained, XSS-escaped inspection report cryptographically bound to `evidence-pack.json` via `signature.htmlSha256` and `signature.htmlSignatureBase64`.
- [`VERIFY.txt`](./VERIFY.txt) — Plain-text verification instructions shipped alongside every exported pack.
- [`verify.mjs`](./verify.mjs) — Standalone zero-dependency Node.js verifier checking key fingerprint, canonical JSON SHA-256, HTML digest, Ed25519 signatures, and audit hash chain continuity.

---

## Claim Boundary Notice

> **Technical Control Evidence Only — Not Certification.**  
> This bundle and its compliance crosswalks (`regulated-healthcare`, `soc2`) map verified technical engineering controls; they are not third-party HIPAA, SOC 2, or ISO compliance certifications, nor do they assert live production deployment (`claimBoundary: pilot-attested`).

## Related Public Links

- Architecture Field Note 06: https://aaronjbentley.vercel.app/field-notes/governed-evidence-delivery
- Mahoosuc Solutions: https://mahoosuc.ai
