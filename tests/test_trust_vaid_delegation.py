"""VAID delegation-chain adapter. Run against the published vaid-a2a conformance
vectors (vendored inside the installed ``vaid-a2a`` wheel, never copied here) plus the
honesty-rule cases this profile adds on top of the upstream verdict.
"""

from __future__ import annotations

import os

import pytest
from vaid_a2a.conformance import load_vector, vector_names
from vaid_mint.revocation import InMemoryRevocationList, RevocationStatus

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.vaid_delegation import VaidDelegationProfile, VaidRevocationSource

# name -> what this vector exercises, for readable test ids.
_COVERED = {
    "01-valid-two-hop-chain.json": "valid",
    "02-child-scope-wider-than-parent.json": "scope widening",
    "03-expired-leaf.json": "expired",
    "04-revoked-middle-link.json": "revoked",
    "06-unknown-root-key.json": "untrusted signer",
    "13-unknown-scope-kind-future-compat.json": "unknown scope kind",
}


def _revocation_for(revoked_ids: list[str]) -> InMemoryRevocationList:
    store = InMemoryRevocationList()
    if not revoked_ids:
        return InMemoryRevocationList.assume_nothing_revoked()
    for vaid_id in revoked_ids:
        store.revoke(vaid_id)
    return store


def _evidence_for(vector: dict) -> dict:
    return {
        "leaf": vector["inputs"]["leaf"],
        "chain": vector["inputs"]["chain"],
        "trust_config": vector["trust_config"],
        "requested_action": vector.get("requested_action"),
        "now": vector["verification_time"],
    }


@pytest.mark.parametrize("name", sorted(_COVERED), ids=lambda n: _COVERED[n])
@pytest.mark.asyncio
async def test_vector_matches_published_expectation(name: str) -> None:
    vector = load_vector(name)
    profile = VaidDelegationProfile(revocation=_revocation_for(vector["revoked_vaid_ids"]))
    result = await profile.verify(None, _evidence_for(vector))

    if vector["expected_result"] == "pass":
        assert result.status is ProofStatus.VERIFIED, result.failure_reason
        assert result.evidence_ref
    else:
        assert result.status is ProofStatus.FAILED, (
            f"vector {name} expects a denial but got {result.status}"
        )
        assert vector["expected_error_code"] in result.failure_reason


@pytest.mark.asyncio
async def test_every_bundled_vaid_a2a_vector_matches_its_published_verdict() -> None:
    """Not just the six named above: every vector vaid-a2a ships must agree, so a future
    vaid-a2a release that adds a vector is covered automatically rather than silently
    skipped."""
    names = vector_names()
    assert len(names) >= 14
    for name in names:
        vector = load_vector(name)
        profile = VaidDelegationProfile(revocation=_revocation_for(vector["revoked_vaid_ids"]))
        result = await profile.verify(None, _evidence_for(vector))
        expect_pass = vector["expected_result"] == "pass"
        got_pass = result.status is ProofStatus.VERIFIED
        assert got_pass is expect_pass, (
            f"{name}: expected {'VERIFIED' if expect_pass else 'FAILED'}, "
            f"got {result.status} ({result.failure_reason})"
        )


@pytest.mark.asyncio
async def test_revoked_vector_is_failed_not_merely_not_verified() -> None:
    # The task's own distinguishing case: a correctly configured revocation source that
    # has this vector's link revoked must FAIL the chain, not shrug with NOT_VERIFIED.
    vector = load_vector("04-revoked-middle-link.json")
    profile = VaidDelegationProfile(revocation=_revocation_for(vector["revoked_vaid_ids"]))
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.FAILED
    assert "revoked" in result.failure_reason


@pytest.mark.asyncio
async def test_no_revocation_source_is_not_verified_never_a_pass() -> None:
    # Even a chain that would otherwise pass every other check must not be reported
    # VERIFIED when the revocation seam was never wired up.
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=None)
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "revocation" in result.failure_reason
    assert result.evidence_ref is None


@pytest.mark.asyncio
async def test_revocation_unavailable_is_not_verified_fails_closed() -> None:
    # A configured-but-empty (absent) revocation store is UNAVAILABLE, distinct from
    # "configured and vouching for nothing"; the chain must still not pass.
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=InMemoryRevocationList.unavailable())
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.NOT_VERIFIED


@pytest.mark.asyncio
async def test_missing_leaf_is_not_verified() -> None:
    profile = VaidDelegationProfile(revocation=InMemoryRevocationList.assume_nothing_revoked())
    result = await profile.verify(None, {"trust_config": {"trustedIssuers": []}})
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "leaf" in result.failure_reason


@pytest.mark.asyncio
async def test_missing_trust_config_is_not_verified() -> None:
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=InMemoryRevocationList.assume_nothing_revoked())
    result = await profile.verify(None, {"leaf": vector["inputs"]["leaf"]})
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "trust_config" in result.failure_reason


# ----- VaidRevocationSource: the injected protocol, not a concrete list type ---------

class _StubRevocation:
    """A hand-rolled VaidRevocationSource, never importing vaid_mint's concrete
    InMemoryRevocationList, to prove the protocol -- not that one implementation -- is
    the contract."""

    def __init__(self, status: RevocationStatus) -> None:
        self._status = status

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        return self._status


def test_stub_revocation_source_satisfies_the_protocol() -> None:
    assert isinstance(_StubRevocation(RevocationStatus.NOT_REVOKED), VaidRevocationSource)


@pytest.mark.asyncio
async def test_protocol_stub_reporting_revoked_fails() -> None:
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=_StubRevocation(RevocationStatus.REVOKED))
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.FAILED
    assert "revoked" in result.failure_reason


@pytest.mark.asyncio
async def test_protocol_stub_reporting_not_revoked_passes() -> None:
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=_StubRevocation(RevocationStatus.NOT_REVOKED))
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.VERIFIED, result.failure_reason


@pytest.mark.asyncio
async def test_no_revocation_source_injected_is_not_verified() -> None:
    # Restated against the protocol directly: no VaidRevocationSource at all, not merely
    # an unavailable one, is NOT_VERIFIED even on an otherwise-clean chain.
    vector = load_vector("01-valid-two-hop-chain.json")
    profile = VaidDelegationProfile(revocation=None)
    result = await profile.verify(None, _evidence_for(vector))
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "revocation" in result.failure_reason


@pytest.mark.asyncio
async def test_profile_reads_no_config_env_var_has_no_effect() -> None:
    # The profile verifies only what it is handed: construction + evidence. Setting an
    # environment variable that names every input this profile could plausibly read from
    # config must change nothing about the verdict.
    vector = load_vector("01-valid-two-hop-chain.json")
    evidence = _evidence_for(vector)
    profile = VaidDelegationProfile(revocation=_StubRevocation(RevocationStatus.NOT_REVOKED))

    baseline = await profile.verify(None, evidence)

    env_keys = [
        "VAID_REVOCATION_LIST",
        "VAID_TRUST_CONFIG",
        "VAID_TRUSTED_ISSUERS",
        "SM_BRIDGE_VAID_CONFIG",
        "SM_BRIDGE_CONFIG",
    ]
    previous = {k: os.environ.get(k) for k in env_keys}
    try:
        for k in env_keys:
            os.environ[k] = "/nonexistent/should-never-be-read.json"
        with_env = await profile.verify(None, evidence)
    finally:
        for k, v in previous.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    assert with_env.status is baseline.status is ProofStatus.VERIFIED
    assert with_env.evidence_ref == baseline.evidence_ref
