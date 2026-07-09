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
  4. a **revoked** delegation breaks the chain — REJECTED, not a silent pass.

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


def _evidence(cred: dict, *, status: str = "ACTIVE", token_exp: int = NOW + 3600, now: int = NOW) -> dict:
    return {
        "chain": [cred],
        "signatures": {cred["delegationId"]: {
            "sig_b64": sign_credential(cred, PROVIDER_KEY),
            "signer_pubkey": signer_pubkey_pem(PROVIDER_KEY),
        }},
        "status_tokens": {cred["delegationId"]: {"status": status, "exp": token_exp}},
        "provider_scopes": PROVIDER_SCOPES,
        "now": now,
    }


def _rule(title: str) -> None:
    print(f"\n{'─' * 74}\n {title}\n{'─' * 74}")


async def main() -> bool:
    profile = NandaDelegationProfile()

    _rule("Setup")
    print(f" provider holds scopes : {PROVIDER_SCOPES}   (domain-anchored, ANS-registered)")
    print(f" subject (no domain)   : {SUBJECT_DID}")

    _rule("1. Honest delegation — provider grants 'mail.send' to the domainless subject")
    honest = _credential("d-alice", ["mail.send"], issued=NOW - 100, expires=NOW + 10_000)
    r1 = await profile.verify(None, _evidence(honest))
    print(f"   scopes granted : {honest['scopes']}  (⊆ provider's {PROVIDER_SCOPES})")
    print(f"   verdict        : {r1.status.value}  →  {r1.evidence_ref or r1.failure_reason}")
    print("   chain          : did:key subject → delegation (ES256/P-256, verified) → provider")

    _rule("2. Escalation attempt — subject asks for 'admin.write' the provider does NOT hold")
    escalate = _credential("d-escalate", ["admin.write"], issued=NOW - 100, expires=NOW + 10_000)
    r2 = await profile.verify(None, _evidence(escalate))
    print(f"   verdict        : {r2.status.value}  →  {r2.failure_reason}")

    _rule("3. Expired delegation — evaluated after expiresAt")
    expired = _credential("d-expired", ["mail.send"], issued=NOW - 10_000, expires=NOW - 100)
    r3 = await profile.verify(None, _evidence(expired))
    print(f"   verdict        : {r3.status.value}  →  {r3.failure_reason}")

    _rule("4. Revoked delegation — the status token reads REVOKED")
    revoked = _credential("d-revoked", ["mail.send"], issued=NOW - 100, expires=NOW + 10_000)
    r4 = await profile.verify(None, _evidence(revoked, status="REVOKED"))
    print(f"   verdict        : {r4.status.value}  →  {r4.failure_reason}")

    ok = (
        r1.status is ProofStatus.VERIFIED
        and r2.status is ProofStatus.FAILED
        and r3.status is ProofStatus.FAILED
        and r4.status is ProofStatus.FAILED
    )
    _rule("Result")
    print(" ✓ a domainless identity earned ANS-grade, scoped, revocable trust — and escalation,"
          if ok else " ✗ demo did not reach the expected state")
    print("   expiry, and revocation were each rejected with a verbatim reason.")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
