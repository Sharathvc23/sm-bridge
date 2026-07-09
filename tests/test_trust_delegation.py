"""Red-team tests for the delegation-chain trust profile.

Every test mints **real** P-256 keys, signs credentials with them, and drives the
profile end-to-end. Honest chains must VERIFY; every attack (scope escalation, over-depth,
bad windows, revocation, stale token, forged signature) must be rejected as FAILED with a
reason that names the fault; missing evidence must be an honest NOT_VERIFIED — never a pass.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sm_bridge.trust.base import ProofStatus
from sm_bridge.trust.delegation import (
    NandaDelegationProfile,
    scope_covers,
    scope_subset,
    sign_credential,
    signer_pubkey_pem,
)

NOW = 1_800_000_000  # fixed evaluation instant (unix seconds)


def _rfc3339(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cred(
    delegation_id: str,
    subject_did: str,
    scopes: list[str],
    *,
    issued: int,
    expires: int,
    max_depth: int,
    parent: str | None,
    issuer_did: str = "did:key:zProvider",
) -> dict:
    return {
        "delegationId": delegation_id,
        "schemaVersion": "DELEGATION-V1",
        "issuer": {"ansName": "provider.ans", "agentId": "agent-provider", "did": issuer_did},
        "subject": {"did": subject_did},
        "scopes": scopes,
        "issuedAt": _rfc3339(issued),
        "expiresAt": _rfc3339(expires),
        "maxRedelegationDepth": max_depth,
        "parentDelegation": parent,
    }


def _sign(cred: dict, key: ec.EllipticCurvePrivateKey) -> dict:
    return {"sig_b64": sign_credential(cred, key), "signer_pubkey": signer_pubkey_pem(key)}


def _token(status: str = "ACTIVE", exp: int = NOW + 3600) -> dict:
    return {"status": status, "exp": exp}


async def _verify(evidence: dict):
    return await NandaDelegationProfile().verify(subject=None, evidence=evidence)


# --------------------------------------------------------------------------------------
# Pure scope logic — the label-boundary trap in particular
# --------------------------------------------------------------------------------------


def test_scope_covers_label_boundary():
    assert scope_covers("a.b", "a.b")  # exact
    assert scope_covers("a.b", "a.b.c")  # strict descendant
    assert not scope_covers("a.b", "a.bc")  # sibling label, NOT covered
    assert not scope_covers("a.b", "a.c")  # sibling
    assert not scope_covers("a.b.c", "a.b")  # ancestor is not covered by descendant


def test_scope_subset():
    ok, bad = scope_subset(["a.b.c", "a.b"], ["a"])
    assert ok and bad is None
    ok, bad = scope_subset(["a.b", "x.y"], ["a"])
    assert not ok and bad == "x.y"


# --------------------------------------------------------------------------------------
# 1. Honest chains — single hop and 2-hop — VERIFIED
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_honest_single_hop_verified():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send", "mail.read"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.VERIFIED, res.failure_reason
    assert res.evidence_ref == "deleg:d-root"
    assert res.method == "delegation-chain"


@pytest.mark.asyncio
async def test_honest_two_hop_verified():
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send", "mail.read"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["mail.send"],
        issued=NOW - 50, expires=NOW + 500, max_depth=1, parent="d-root",
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            "status_tokens": {"d-root": _token(), "d-child": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.VERIFIED, res.failure_reason
    assert res.evidence_ref == "deleg:d-root"


# --------------------------------------------------------------------------------------
# 2. Scope escalation — FAILED naming the offending scope
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_escalation_beyond_provider_failed():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["admin.write"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail"],  # provider cannot grant admin.write
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "scope escalation" in res.failure_reason
    assert "admin.write" in res.failure_reason


@pytest.mark.asyncio
async def test_sibling_scope_escalation_child_failed():
    # Child asks for "a.bc" while parent only holds "a.b" — the label-boundary attack.
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["a.b"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["a.bc"],
        issued=NOW - 50, expires=NOW + 500, max_depth=1, parent="d-root",
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            "status_tokens": {"d-root": _token(), "d-child": _token()},
            "provider_scopes": ["a"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "scope escalation" in res.failure_reason
    assert "a.bc" in res.failure_reason


# --------------------------------------------------------------------------------------
# 3. Depth exceeded — FAILED
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_depth_exceeded_failed():
    # Root permits max_depth=0 (no redelegation) yet a child is chained below it.
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=0, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["mail.send"],
        issued=NOW - 50, expires=NOW + 500, max_depth=0, parent="d-root",
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            "status_tokens": {"d-root": _token(), "d-child": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "redelegation depth exceeded" in res.failure_reason


# --------------------------------------------------------------------------------------
# 4. Bad validity windows — expired, and not nested — FAILED
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_window_failed():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 1000, expires=NOW - 500, max_depth=2, parent=None,  # already expired
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "validity window" in res.failure_reason


@pytest.mark.asyncio
async def test_window_not_nested_failed():
    # Child's window extends BEYOND the parent's — not nested.
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 200, max_depth=1, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["mail.send"],
        issued=NOW - 50, expires=NOW + 1000, max_depth=0, parent="d-root",  # expires after parent
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            "status_tokens": {"d-root": _token(), "d-child": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "not nested" in res.failure_reason


# --------------------------------------------------------------------------------------
# 5. Revoked ancestor — FAILED (chain broken)
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_ancestor_breaks_chain_failed():
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["mail.send"],
        issued=NOW - 50, expires=NOW + 500, max_depth=1, parent="d-root",
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            # ancestor revoked → whole chain broken even though child is fine
            "status_tokens": {"d-root": _token("REVOKED"), "d-child": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "revoked" in res.failure_reason
    assert "chain broken" in res.failure_reason


# --------------------------------------------------------------------------------------
# 6. Stale / missing status token — FAILED
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_status_token_failed():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {"d-root": _token(exp=NOW - 10)},  # exp in the past
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "stale status token" in res.failure_reason


@pytest.mark.asyncio
async def test_missing_status_token_failed():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {},  # no token at all
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "stale status token" in res.failure_reason


# --------------------------------------------------------------------------------------
# 7. Forged signature — tamper a credential after signing — FAILED
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forged_signature_failed():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    sig = _sign(root, key)  # sign the honest credential
    tampered = copy.deepcopy(root)
    tampered["scopes"] = ["mail.send", "admin.write"]  # add a scope AFTER signing
    res = await _verify(
        {
            "chain": [tampered],
            "signatures": {"d-root": sig},  # stale signature over the pre-tamper bytes
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail", "admin"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "forged signature" in res.failure_reason


@pytest.mark.asyncio
async def test_signature_by_wrong_key_failed():
    signer = ec.generate_private_key(ec.SECP256R1())
    attacker = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    # Signature made by `signer`, but the advertised pubkey is the attacker's.
    entry = {"sig_b64": sign_credential(root, signer), "signer_pubkey": signer_pubkey_pem(attacker)}
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": entry},
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "forged signature" in res.failure_reason


# --------------------------------------------------------------------------------------
# 8. Missing chain / evidence — NOT_VERIFIED (honest unknown, not a rejection)
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_chain_not_verified():
    res = await _verify({"signatures": {}, "provider_scopes": ["mail"]})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "chain" in res.failure_reason


@pytest.mark.asyncio
async def test_empty_chain_not_verified():
    res = await _verify({"chain": [], "signatures": {}, "provider_scopes": ["mail"]})
    assert res.status is ProofStatus.NOT_VERIFIED


@pytest.mark.asyncio
async def test_unsigned_hop_not_verified():
    # A hop with no signature material cannot be checked → honest unknown, not FAILED.
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {},  # present dict but no entry for d-root
            "status_tokens": {"d-root": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "signature material" in res.failure_reason


@pytest.mark.asyncio
async def test_missing_provider_scopes_not_verified():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    res = await _verify(
        {
            "chain": [root],
            "signatures": {"d-root": _sign(root, key)},
            "status_tokens": {"d-root": _token()},
            # no provider_scopes → cannot anchor issuance coverage
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "provider_scopes" in res.failure_reason


# --------------------------------------------------------------------------------------
# Sanity: a broken parentDelegation pointer is rejected
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broken_linkage_failed():
    k_root = ec.generate_private_key(ec.SECP256R1())
    k_child = ec.generate_private_key(ec.SECP256R1())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    child = _cred(
        "d-child", "did:key:zBob", ["mail.send"],
        issued=NOW - 50, expires=NOW + 500, max_depth=1, parent="d-WRONG",  # bad pointer
    )
    res = await _verify(
        {
            "chain": [root, child],
            "signatures": {"d-root": _sign(root, k_root), "d-child": _sign(child, k_child)},
            "status_tokens": {"d-root": _token(), "d-child": _token()},
            "provider_scopes": ["mail"],
            "now": NOW,
        }
    )
    assert res.status is ProofStatus.FAILED
    assert "linkage broken" in res.failure_reason
