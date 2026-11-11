"""Demo 2 — ANS-grade trust for an identity with no domain of its own.

An individual or small business holds only a keypair (a `did:key`) — no domain to anchor on,
so DNS/ARD/ANS discovery cannot reach it. NANDA's distinct value is trust for exactly these
identities: a domain-holding, ANS-registered **provider** issues a scoped, time-bounded,
revocable **delegation** to the domainless subject. The delegation is a real ES256 (P-256)
detached JWS, verified by the `nanda-delegation` trust profile.

The demo proves, with real cryptography:
  1. an honest delegation VERIFIES (did:key → delegation → provider);
  2. **escalation is impossible** — a scope the provider does not hold is REJECTED;
  3. an **expired** delegation is REJECTED;
  4. a **revoked** delegation breaks the chain — REJECTED, not a silent pass — even
     when the subject's bundle still asserts ACTIVE (status is the verifier's view);
  5. a verifier with **no revocation view** of its own says NOT_VERIFIED, never VERIFIED.

Run offline, no external services:  python examples/demo2_domainless_delegation.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.delegation import NandaDelegationProfile, sign_credential, signer_pubkey_pem

NOW = 1_800_000_000  # fixed evaluation instant, for a deterministic demo
PROVIDER_KEY = ec.generate_private_key(ec.SECP256R1())          # the domain-holding provider
SUBJECT_DID = "did:key:zAliceDomainlessP256"                    # an identity with no domain
PROVIDER_SCOPES = ["mail"]                                      # what the provider actually holds


def _rfc3339(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _credential(delegation_id: str, scopes: list[str], *, issued: int, expires: int) -> dict:
    return {
        "delegationId": delegation_id,
        "schemaVersion": "DELEGATION-V1",
        "issuer": {"ansName": "provider.example", "agentId": "agent-provider", "did": "did:key:zProvider"},
        "subject": {"did": SUBJECT_DID},
        "scopes": scopes,
        "issuedAt": _rfc3339(issued),
        "expiresAt": _rfc3339(expires),
        "maxRedelegationDepth": 1,
        "parentDelegation": None,
    }


# The provider's revocation registry — the VERIFIER's view of each delegation's status.
# This is deliberately not part of the evidence bundle: a subject asserting its own
# delegation is ACTIVE is a claim, and the profile ignores such claims.
STATUS_REGISTRY: dict[str, dict] = {}


def _status_source(delegation_id: str) -> dict | None:
    return STATUS_REGISTRY.get(delegation_id)


def _issue(cred: dict, *, status: str = "ACTIVE") -> None:
    """The provider records the delegation's status in its own registry."""
    STATUS_REGISTRY[cred["delegationId"]] = {"status": status, "exp": NOW + 3600}


def _evidence(cred: dict) -> dict:
    """What the domainless subject hands a verifier: the chain and its signatures, nothing
    about its own revocation status and no clock of its choosing."""
    return {
        "chain": [cred],
        "signatures": {cred["delegationId"]: {
            "sig_b64": sign_credential(cred, PROVIDER_KEY),
            "signer_pubkey": signer_pubkey_pem(PROVIDER_KEY),
        }},
        "provider_scopes": PROVIDER_SCOPES,
        # Only honoured because the demo runs with the TEST-ONLY `trust_evidence_clock`,
        # so the fixed instant above is used instead of the wall clock.
        "now": NOW,
    }


def _rule(title: str) -> None:
    print(f"\n{'─' * 74}\n {title}\n{'─' * 74}")


async def main() -> bool:
    # `status_source` is the verifier's own revocation view; `trust_evidence_clock` pins the
    # offline fixture instant and is TEST ONLY — a real verifier never sets it.
    profile = NandaDelegationProfile(status_source=_status_source, trust_evidence_clock=True)

    _rule("Setup")
    print(f" provider holds scopes : {PROVIDER_SCOPES}   (domain-anchored, ANS-registered)")
    print(f" subject (no domain)   : {SUBJECT_DID}")

    _rule("1. Honest delegation — provider grants 'mail.send' to the domainless subject")
    honest = _credential("d-alice", ["mail.send"], issued=NOW - 100, expires=NOW + 10_000)
    _issue(honest)
    r1 = await profile.verify(None, _evidence(honest))
    print(f"   scopes granted : {honest['scopes']}  (⊆ provider's {PROVIDER_SCOPES})")
    print(f"   verdict        : {r1.status.value}  →  {r1.evidence_ref or r1.failure_reason}")
    print("   chain          : did:key subject → delegation (ES256/P-256, verified) → provider")

    _rule("2. Escalation attempt — subject asks for 'admin.write' the provider does NOT hold")
    escalate = _credential("d-escalate", ["admin.write"], issued=NOW - 100, expires=NOW + 10_000)
    _issue(escalate)
    r2 = await profile.verify(None, _evidence(escalate))
    print(f"   verdict        : {r2.status.value}  →  {r2.failure_reason}")

    _rule("3. Expired delegation — evaluated after expiresAt")
    expired = _credential("d-expired", ["mail.send"], issued=NOW - 10_000, expires=NOW - 100)
    _issue(expired)
    r3 = await profile.verify(None, _evidence(expired))
    print(f"   verdict        : {r3.status.value}  →  {r3.failure_reason}")

    _rule("4. Revoked delegation — the provider's registry reads REVOKED")
    revoked = _credential("d-revoked", ["mail.send"], issued=NOW - 100, expires=NOW + 10_000)
    _issue(revoked, status="REVOKED")
    bundle = _evidence(revoked)
    # The subject still swears it is ACTIVE. The profile ignores that: the verifier's
    # registry decides, and a verifier with no registry says NOT_VERIFIED, never VERIFIED.
    bundle["status_tokens"] = {"d-revoked": {"status": "ACTIVE", "exp": NOW + 3600}}
    r4 = await profile.verify(None, bundle)
    print(f"   verdict        : {r4.status.value}  →  {r4.failure_reason}")

    _rule("5. Same honest chain, but the verifier has no revocation view of its own")
    r5 = await NandaDelegationProfile(trust_evidence_clock=True).verify(None, _evidence(honest))
    print(f"   verdict        : {r5.status.value}  →  {r5.failure_reason}")

    ok = (
        r1.status is ProofStatus.VERIFIED
        and r2.status is ProofStatus.FAILED
        and r3.status is ProofStatus.FAILED
        and r4.status is ProofStatus.FAILED
        and r5.status is ProofStatus.NOT_VERIFIED
    )
    _rule("Result")
    print(" ✓ a domainless identity earned ANS-grade, scoped, revocable trust — and escalation,"
          if ok else " ✗ demo did not reach the expected state")
    print("   expiry, and revocation were each rejected with a verbatim reason.")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
