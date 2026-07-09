# Trust profiles (v0.4)

A **trust profile** is a pluggable adapter that verifies one kind of trust root and
normalizes the outcome to a single downstream vocabulary: `ProofResult`. Heterogeneous
sources onboard through their own profile and emerge with a proof block that means the same
thing everywhere.

Every profile obeys the **cryptographic honesty rule**: `VERIFIED` is emitted only after a
real signature / DNS / Merkle check (and only with an `evidence_ref` — enforced at
construction). When verification cannot truly run, the profile returns `NOT_VERIFIED(reason)`
— never a fabricated pass. A real check that rejects returns `FAILED(reason)`.

Profiles live in `sm_bridge.trust.<name>` and require the `[trust]` extra (they import
cryptography / cbor2 / dnspython / dns-aid lazily). The spine (`ProofResult`, `TrustProfile`,
`TrustRegistry`) is core-safe.

```python
from sm_bridge.trust import TrustRegistry
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile
from sm_bridge.trust.ans_scitt import AnsScittProfile

registry = TrustRegistry([Ed25519AgentCardProfile(), AnsScittProfile()])
result = await registry.verify("ed25519-agentcard", subject, evidence)
```

| profile_id | Trust root | Evidence inputs | VERIFIED means | Failure modes | Correspondence |
|---|---|---|---|---|---|
| `ed25519-agentcard` | The signing key of the agent card | `{payload, signature_b64, public_key}` | ed25519 signature over the JCS-canonical card verifies | tampered payload, wrong key → FAILED; missing key → NOT_VERIFIED | implements the NANDA Index agent-card signing contract (JCS canonicalization + ed25519) |
| `ans-scitt` | An ANS transparency-log receipt | `{receipt, public_key}` | COSE_Sign1 ES256 verifies AND the RFC 9162 Merkle root reconstructs to the receipt's committed root | tampered payload/path, wrong key, detached payload, treeSize≤0 → FAILED | implements the ANS SCITT receipt contract (COSE_Sign1 + RFC 9162); guards degenerate treeSize-1 and producer-vs-issuer-key conflation |
| `ans-txt` | ANS `_ans` / `_ans-badge` DNS discovery records | `{host, vantages?, expected_url?}` | consistent, well-formed `_ans` records prove DNS control of the ANS records | split-horizon across vantages → FAILED; unreachable/absent → NOT_VERIFIED | implements the ANS `ANS_TXT` discovery profile. Asserts DNS control, not agent-receipt trust (that is `ans-scitt`) |
| `dns-aid` | DNS-AID (IETF draft-mozleywilliams) SVCB + DNSSEC + DANE | `{fqdn, verify_dane_cert?}` | a DNSSEC-authenticated SVCB record (+ DANE when requested) | DNSSEC bogus / bad SVCB / DANE mismatch → FAILED; unsigned zone / no record → NOT_VERIFIED | **consumes the upstream `dns-aid` PyPI package** (`dns_aid.core.validator.verify`) — thin adapter, never forked |
| `nanda-delegation` | A domainless `did:key` delegation chain | `{chain, signatures, status_tokens, provider_scopes, now?}` | every hop's JWS verifies, scopes contain (no escalation), windows nest, tokens fresh-ACTIVE | scope escalation, over-depth, expired/non-nested window, revoked ancestor, stale token, forged sig → FAILED | implements the delegation-chain model (scope containment, validity nesting, revocation) |

## The proof block

```python
class ProofResult(BaseModel):
    profile: str            # profile_id that produced this
    method: str             # e.g. "ed25519-jcs", "scitt-cose-merkle", "dns-aid-dnssec"
    status: ProofStatus     # VERIFIED | FAILED | NOT_VERIFIED
    verified_at: datetime
    evidence_ref: str | None # the artifact actually checked — MANDATORY when VERIFIED
    failure_reason: str | None
```

`ProofResult` is the typed value of `SmAgentFacts.proof`. A pre-v0.4 opaque `proof` dict is
accepted for back-compat but downgraded to `NOT_VERIFIED(legacy-unverified)` — a legacy
payload can never masquerade as verified.

## Adding a source

Write one adapter that satisfies the `TrustProfile` protocol (`profile_id` + `async verify`)
and register it. Consume an upstream library where a maintained one exists (as `dns-aid`
does); implement the published contract where only a specification exists. Never fork
upstream — keep a thin adapter.
