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
| `jws-catalog` | A signed AI-Catalog (ARD / Cisco AGNTCY discovery) | `{entries, signature (detached JWS), jwks \| public_key}` | ES256 detached JWS verifies over the JCS-canonical entries | tampered entry (catalog hijack), wrong key → FAILED; missing pieces → NOT_VERIFIED | implements the AI-Catalog signed-catalog contract (ES256 detached JWS over RFC 8785 entries) |
| `nanda-delegation` | A domainless `did:key` delegation chain | `{chain, signatures, status_tokens, provider_scopes, now?}` | every hop's **ES256 (P-256)** JWS verifies, scopes contain (no escalation), windows nest, tokens fresh-ACTIVE | scope escalation, over-depth, expired/non-nested window, revoked ancestor, stale token, forged sig → FAILED | implements the delegation-chain model over ES256/P-256 detached JWS (subjects/signers as PEM, DER, JWK, or `did:key` P-256) |
| `vaid-delegation` | A VAID delegation chain (Ed25519 kernel-signed) | `{leaf, chain, trust_config, requested_action?, now?}` + an injected `vaid_mint.revocation.RevocationCheck` | the upstream `vaid-a2a` verifier's full ordered check (signature, leaf expiry, `scope_boundary` readability, chain integrity/attenuation, requested-action scope, revocation) allows the request | forged signature, scope escalation, expired, unknown `scope_boundary` kind, issuer/trust-domain mismatch, revoked link → FAILED; no revocation source configured, or revocation genuinely indeterminate → NOT_VERIFIED | **consumes the upstream `vaid-a2a` PyPI package** (`vaid_a2a.verify_a2a_message`, which itself consumes `vaid-mint`); thin adapter, never forked |

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

## `vaid-delegation`: VAID delegation chains

`VaidDelegationProfile` (`sm_bridge.trust.vaid_delegation`) verifies a VAID delegation
chain carried under the VAID A2A extension
(https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md). It
requires the `[vaid]` extra (`pip install 'sm-bridge[vaid]'`), which pulls in `vaid-a2a`
and, transitively, `vaid-mint`.

```python
from vaid_mint.revocation import InMemoryRevocationList

from sm_bridge.trust.vaid_delegation import VaidDelegationProfile

# A durable RevocationCheck belongs here in production; InMemoryRevocationList is for
# tests and local development.
revocation = InMemoryRevocationList.assume_nothing_revoked()
profile = VaidDelegationProfile(revocation=revocation)

evidence = {
    "leaf": leaf_vaid_document,
    "chain": ancestor_vaid_documents,
    "trust_config": {"trustedIssuers": [{"trustDomain": "vaid.example", "kernelPublicKey": "..."}]},
    "requested_action": "data.acme.orders",
    "now": "2026-07-01T00:00:00Z",
}
result = await profile.verify(None, evidence)
```

The adapter does not reimplement signature, attenuation or revocation checking: it
builds the A2A `Message` metadata shape `vaid_a2a.verify_a2a_message` expects and
normalizes its `VerifyResult` into a `ProofResult`.

The revocation seam is injected at construction, never read from evidence, matching how
`vaid_a2a.verify_a2a_message` itself requires the seam to be wired: the check only
answers about a lineage it is handed, it never resolves or looks one up. If no
`RevocationCheck` is configured, `verify` returns `NOT_VERIFIED` every time, regardless
of how clean the rest of the chain is. A configured-but-empty store
(`InMemoryRevocationList()` / `.unavailable()`) is also `NOT_VERIFIED`, distinct from a
configured store that vouches for an empty revoked set
(`InMemoryRevocationList.assume_nothing_revoked()`), which can reach `VERIFIED`.

### What VAID proves that AgentFacts does not

An AgentFacts record is a self-asserted description of an agent. Nothing in the record
itself is cryptographically tied to whatever authority was supposed to have granted the
agent its capabilities; a registry that accepts AgentFacts at face value is trusting the
agent's own say-so. A VAID delegation chain is a signed lineage: every hop is a
credential issued by an identified kernel key, scoped and time-bounded, and every child's
scope, capabilities, tenant and validity window is checked to sit strictly inside its
parent's. Verifying a VAID chain proves not just "this agent claims capability X" but "an
identified authority granted X, and every re-delegation down to this agent only narrowed
it, never widened it." AgentFacts has no equivalent of that lineage check, and nothing in
it distinguishes an agent that was properly delegated authority from one that simply
wrote the claim into its own record.

### CLI

```sh
sm-bridge verify vaid --evidence vaid-evidence.json [--revocation-list revoked-ids.json]
```

Exit codes match every other profile: 0 VERIFIED, 1 FAILED, 2 NOT_VERIFIED. Omitting both
`--revocation-list` and an `evidence.revoked_vaid_ids` key leaves the revocation source
unconfigured, so the command always reports NOT_VERIFIED rather than a silent pass.

A runnable, fully offline example (no network, no package server) is in
`examples/demo4_vaid_delegation.py`.

## Adding a source

Write one adapter that satisfies the `TrustProfile` protocol (`profile_id` + `async verify`)
and register it. Consume an upstream library where a maintained one exists (as `dns-aid`
does); implement the published contract where only a specification exists. Never fork
upstream — keep a thin adapter.
