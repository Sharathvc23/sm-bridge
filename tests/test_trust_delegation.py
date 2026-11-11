"""Red-team tests for the delegation-chain trust profile.

Every test mints **real** P-256 keys, signs credentials with them, and drives the
profile end-to-end. Honest chains must VERIFY; every attack (scope escalation, over-depth,
bad windows, revocation, stale token, forged signature) must be rejected as FAILED with a
reason that names the fault; missing evidence must be an honest NOT_VERIFIED — never a pass.

The evaluation instant and the revocation view are the **verifier's**: tests pin ``NOW``
through ``trust_evidence_clock=True`` (the test-only flag) and hand the status tokens to
the profile as its ``status_source``. Until 0.11.0 both were read from the evidence the
subject supplied, so a revoked or expired delegate could assert ACTIVE and pick its own
clock — the "self-asserted status" section below pins that this is now rejected.
"""

from __future__ import annotations

import copy
import time
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


async def _verify(evidence: dict, *, status_source=None, trust_evidence_clock: bool = True):
    """Drive the profile the way a verifier does.

    The test bundles still carry ``status_tokens`` (they are what a subject would hand
    over); the *verifier* view is derived from them here via ``status_source`` unless the
    test supplies its own. ``now`` in the bundle is honoured only because the test-only
    clock flag is on.
    """
    if status_source is None:
        tokens = evidence.get("status_tokens") or {}

        def status_source(did: str):  # noqa: E306 - closure over the test's tokens
            return tokens.get(did)

    profile = NandaDelegationProfile(
        status_source=status_source, trust_evidence_clock=trust_evidence_clock
    )
    return await profile.verify(subject=None, evidence=evidence)


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
# 9. Self-asserted status and clock — the subject does not get to grade itself
# --------------------------------------------------------------------------------------


def _honest_root_bundle(key: ec.EllipticCurvePrivateKey, **over) -> dict:
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=NOW - 100, expires=NOW + 1000, max_depth=2, parent=None,
    )
    bundle = {
        "chain": [root],
        "signatures": {"d-root": _sign(root, key)},
        "status_tokens": {"d-root": _token()},
        "provider_scopes": ["mail"],
        "now": NOW,
    }
    bundle.update(over)
    return bundle


@pytest.mark.asyncio
async def test_evidence_status_tokens_are_a_claim_not_a_check():
    # A valid chain whose only ACTIVE assertion comes from the subject's own bundle.
    key = ec.generate_private_key(ec.SECP256R1())
    profile = NandaDelegationProfile(trust_evidence_clock=True)  # no status_source
    res = await profile.verify(None, _honest_root_bundle(key))
    assert res.status is ProofStatus.NOT_VERIFIED
    assert res.failure_reason.startswith("status_unverified")
    assert "ignored as a self-assertion" in res.failure_reason


@pytest.mark.asyncio
async def test_no_status_source_and_no_claim_is_still_status_unverified():
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = _honest_root_bundle(key)
    del bundle["status_tokens"]
    res = await NandaDelegationProfile(trust_evidence_clock=True).verify(None, bundle)
    assert res.status is ProofStatus.NOT_VERIFIED
    assert res.failure_reason.startswith("status_unverified")
    assert "self-assertion" not in res.failure_reason


@pytest.mark.asyncio
async def test_revoked_at_the_verifier_beats_active_in_the_evidence():
    # The bundle says ACTIVE; the verifier's own source says REVOKED. REVOKED wins.
    key = ec.generate_private_key(ec.SECP256R1())
    res = await _verify(
        _honest_root_bundle(key),
        status_source=lambda did: _token("REVOKED"),
    )
    assert res.status is ProofStatus.FAILED
    assert "revoked" in res.failure_reason


@pytest.mark.asyncio
async def test_verifier_source_with_no_token_for_the_hop_is_failed_not_passed():
    key = ec.generate_private_key(ec.SECP256R1())
    res = await _verify(_honest_root_bundle(key), status_source=lambda did: None)
    assert res.status is ProofStatus.FAILED
    assert "stale status token: no status token for d-root" in res.failure_reason


@pytest.mark.asyncio
async def test_async_status_source_is_awaited():
    key = ec.generate_private_key(ec.SECP256R1())

    async def source(did: str):
        return _token()

    res = await _verify(_honest_root_bundle(key), status_source=source)
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


@pytest.mark.asyncio
async def test_status_source_returning_garbage_is_a_programming_error():
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(TypeError, match="status_source must return"):
        await _verify(_honest_root_bundle(key), status_source=lambda did: "ACTIVE")


@pytest.mark.asyncio
async def test_rule_violations_are_failed_even_without_a_status_source():
    # A scope escalation is a rejection whatever the revocation state; the missing
    # status source must not soften it into an "unknown".
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = _honest_root_bundle(key, provider_scopes=["calendar"])
    res = await NandaDelegationProfile(trust_evidence_clock=True).verify(None, bundle)
    assert res.status is ProofStatus.FAILED
    assert "scope escalation" in res.failure_reason


@pytest.mark.asyncio
async def test_evidence_now_is_ignored_by_default():
    # The credential is valid at the bundle's `now` (a fixed instant in 2027) but long
    # expired at the wall clock; by default the wall clock decides.
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = _honest_root_bundle(key)
    # Make the credential already expired at wall-clock time but valid at bundle `now`.
    past = int(time.time()) - 10_000
    bundle["chain"][0]["issuedAt"] = _rfc3339(past - 100)
    bundle["chain"][0]["expiresAt"] = _rfc3339(past)
    bundle["signatures"]["d-root"] = _sign(bundle["chain"][0], key)
    bundle["now"] = past - 50  # the subject claims "judge me back then"
    bundle["status_tokens"]["d-root"] = _token(exp=int(time.time()) + 3600)

    tokens = bundle["status_tokens"]
    strict = NandaDelegationProfile(status_source=lambda did: tokens.get(did))
    res = await strict.verify(None, bundle)
    assert res.status is ProofStatus.FAILED
    assert "validity window" in res.failure_reason

    # Only the explicit, test-only flag lets the bundle's clock in.
    lenient = NandaDelegationProfile(
        status_source=lambda did: tokens.get(did), trust_evidence_clock=True
    )
    res = await lenient.verify(None, bundle)
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


@pytest.mark.asyncio
async def test_default_clock_is_utc_wall_clock():
    # A credential valid now at the wall clock verifies with no `now` in the bundle.
    key = ec.generate_private_key(ec.SECP256R1())
    wall = int(time.time())
    root = _cred(
        "d-root", "did:key:zAlice", ["mail.send"],
        issued=wall - 100, expires=wall + 1000, max_depth=2, parent=None,
    )
    bundle = {
        "chain": [root],
        "signatures": {"d-root": _sign(root, key)},
        "provider_scopes": ["mail"],
    }
    profile = NandaDelegationProfile(status_source=lambda did: _token(exp=wall + 3600))
    res = await profile.verify(None, bundle)
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


def test_trust_evidence_clock_defaults_off():
    assert NandaDelegationProfile()._trust_evidence_clock is False
    assert NandaDelegationProfile()._status_source is None


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
