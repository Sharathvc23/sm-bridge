"""Phase 1 spine tests — ProofResult honesty, legacy downgrade, registry dispatch."""

from __future__ import annotations

import pytest

from sm_bridge.models import SmAgentFacts
from sm_bridge.trust import ProofResult, ProofStatus, TrustRegistry
from sm_bridge.trust.base import (
    is_registered_method,
    register_verification_method,
    verification_methods,
)

register_verification_method("stub")  # the fake profile below is visibly a stub


def _facts(**over):
    base = {
        "id": "agent-1",
        "agent_name": "Agent One",
        "label": "test",
        "description": "d",
        "version": "1.0.0",
        "provider": {"name": "P", "url": "https://p.example"},
        "endpoints": {"static": ["https://a.example/mcp"]},
        "capabilities": {"modalities": ["text"]},
        "skills": [{"id": "s1", "name": "Skill", "description": "a skill"}],
    }
    base.update(over)
    return SmAgentFacts.model_validate(base)


# ----- honesty rule ------------------------------------------------------------------

def test_verified_requires_evidence_ref():
    with pytest.raises(ValueError, match="honesty"):
        ProofResult(profile="p", method="m", status=ProofStatus.VERIFIED, evidence_ref=None)
    with pytest.raises(ValueError, match="honesty"):
        ProofResult(profile="p", method="m", status=ProofStatus.VERIFIED, evidence_ref="   ")


def test_verified_constructor_ok_with_evidence():
    r = ProofResult.verified(profile="ed25519-agentcard", method="ed25519-jcs", evidence_ref="sig:abcd")
    assert r.status is ProofStatus.VERIFIED
    assert r.evidence_ref == "sig:abcd"


def test_failed_and_not_verified_require_reason():
    with pytest.raises(ValueError, match="failure_reason"):
        ProofResult(profile="p", method="m", status=ProofStatus.FAILED)
    with pytest.raises(ValueError, match="failure_reason"):
        ProofResult(profile="p", method="m", status=ProofStatus.NOT_VERIFIED)
    assert ProofResult.failed(profile="p", method="m", reason="forged sig").failure_reason == "forged sig"
    assert ProofResult.not_verified(profile="p", method="m", reason="no dns").status is ProofStatus.NOT_VERIFIED


# ----- registered verification methods -----------------------------------------------


def test_verified_requires_a_registered_method():
    with pytest.raises(ValueError, match="not a registered method"):
        ProofResult.verified(profile="p", method="totally-made-up", evidence_ref="ev:1")
    with pytest.raises(ValueError, match="not a registered method"):
        ProofResult(profile="p", method="m", status=ProofStatus.VERIFIED, evidence_ref="ev:1")


def test_failed_and_not_verified_do_not_need_a_registered_method():
    # Honest rejections and unknowns may name whatever ran (or did not run).
    assert ProofResult.failed(profile="p", method="anything", reason="r").method == "anything"
    assert ProofResult.not_verified(profile="p", method="dispatch", reason="r").method == "dispatch"


def test_registering_a_method_is_explicit_and_visible():
    assert not is_registered_method("test-only-method")
    assert register_verification_method("test-only-method") == "test-only-method"
    assert is_registered_method("test-only-method")
    assert "test-only-method" in verification_methods()
    r = ProofResult.verified(profile="p", method="test-only-method", evidence_ref="ev:1")
    assert r.status is ProofStatus.VERIFIED
    with pytest.raises(ValueError, match="non-empty"):
        register_verification_method("  ")


def test_every_in_tree_profile_method_is_registered():
    from sm_bridge.trust import (
        ans_scitt,
        ans_txt,
        delegation,
        dns_aid,
        ed25519_agentcard,
        jws_catalog,
    )

    expected = {
        ed25519_agentcard._METHOD,
        ans_scitt._METHOD,
        jws_catalog._METHOD,
        delegation.NandaDelegationProfile._METHOD,
        "ans-txt-control",  # ans_txt sets it inline in verify()
        "dns-aid-dnssec",  # dns_aid sets it inline in verify()
        "dns-aid-dnssec+dane",  # ...and suffixes it when DANE was requested and held
    }
    assert ans_txt.profile_id == "ans-txt" and dns_aid.profile_id == "dns-aid"
    assert expected <= verification_methods()


def test_an_inbound_verified_naming_an_unknown_method_is_downgraded_not_laundered():
    # A peer (or a hand-written record) claims VERIFIED via a check this registry has
    # no profile for. Rejecting it would let one record wedge a federation pull;
    # keeping it would launder a claim. It is downgraded to an honest NOT_VERIFIED.
    facts = _facts(
        proof={
            "profile": "their-profile",
            "method": "their-check",
            "status": "VERIFIED",
            "evidence_ref": "ev:theirs",
        }
    )
    assert isinstance(facts.proof, ProofResult)
    assert facts.proof.status is ProofStatus.NOT_VERIFIED
    assert facts.proof.method == "their-check"
    assert facts.proof.profile == "their-profile"
    assert "unregistered-method" in facts.proof.failure_reason


# ----- schema round-trip -------------------------------------------------------------

def test_proofresult_roundtrips_through_agentfacts():
    proof = ProofResult.verified(profile="ans-scitt", method="scitt-cose-merkle", evidence_ref="receipt:xyz")
    facts = _facts(proof=proof)
    dumped = facts.model_dump()
    reloaded = SmAgentFacts.model_validate(dumped)
    assert isinstance(reloaded.proof, ProofResult)
    assert reloaded.proof.status is ProofStatus.VERIFIED
    assert reloaded.proof.evidence_ref == "receipt:xyz"


# ----- legacy downgrade --------------------------------------------------------------

def test_legacy_opaque_dict_downgrades_to_not_verified():
    # A pre-v0.4 opaque proof (the old _build_proof shape) must NOT be trusted.
    facts = _facts(proof={"method": "sha256", "digest": "deadbeef", "registry_id": "r"})
    assert isinstance(facts.proof, ProofResult)
    assert facts.proof.status is ProofStatus.NOT_VERIFIED
    assert "legacy-unverified" in (facts.proof.failure_reason or "")


def test_none_proof_stays_none():
    assert _facts().proof is None


# ----- registry dispatch -------------------------------------------------------------

class _StubProfile:
    profile_id = "stub"

    async def verify(self, subject, evidence):
        if evidence.get("good"):
            return ProofResult.verified(profile=self.profile_id, method="stub", evidence_ref="ev:1")
        return ProofResult.failed(profile=self.profile_id, method="stub", reason="stub-reject")


@pytest.mark.asyncio
async def test_registry_dispatch_hits_profile():
    reg = TrustRegistry([_StubProfile()])
    assert reg.profile_ids() == ["stub"]
    ok = await reg.verify("stub", _facts(), {"good": True})
    assert ok.status is ProofStatus.VERIFIED
    bad = await reg.verify("stub", _facts(), {"good": False})
    assert bad.status is ProofStatus.FAILED


@pytest.mark.asyncio
async def test_registry_unknown_profile_is_not_verified_not_crash():
    reg = TrustRegistry()
    r = await reg.verify("nope", _facts(), {})
    assert r.status is ProofStatus.NOT_VERIFIED
    assert "no trust profile registered" in (r.failure_reason or "")


def test_registry_rejects_profile_without_id():
    class Bad:
        profile_id = ""

        async def verify(self, subject, evidence):  # pragma: no cover
            ...

    with pytest.raises(ValueError, match="profile_id"):
        TrustRegistry([Bad()])
