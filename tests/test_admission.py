"""Onboarding admission — an entry-mode source is verified ONCE at join and its proof is
stamped into the entry. Resolution stays delegated (never re-verified). This is the
switchboard (index) vs onboarding-tool (bridge) split made concrete.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge.onboarding import AdmissionError, ANSEntryConverter
from sm_bridge.router import SmBridge
from sm_bridge.trust import ProofResult, ProofStatus, TrustRegistry


class _AttestationProfile:
    """Stand-in for a real admission verifier (ans-scitt/ans-txt): VERIFIED iff evidence
    carries a well-formed attestation for the entry."""

    profile_id = "ans-scitt"

    async def verify(self, subject, evidence):
        if evidence.get("attestation") == "valid":
            return ProofResult.verified(profile=self.profile_id, method="admission", evidence_ref="att:ok")
        return ProofResult.failed(profile=self.profile_id, method="admission", reason="attestation invalid")


def _conv(evidence):
    return ANSEntryConverter(
        registry_name="acme-ans", resolver_endpoint="https://ans.acme.example",
        tl_checkpoint="acme\n9\nROOT\n", root_keys=["acme+deadbeef+KEY"],
        admission_evidence=evidence,
    )


@pytest.mark.asyncio
async def test_valid_attestation_stamps_verified_entry():
    conv = _conv({"attestation": "valid"})
    reg = TrustRegistry([_AttestationProfile()])
    proof = await conv.admit(reg)
    assert proof.status is ProofStatus.VERIFIED
    # and the stamped proof shows up in the entry the index will serve
    assert conv.to_entry().proof.status is ProofStatus.VERIFIED


@pytest.mark.asyncio
async def test_no_evidence_joins_unattested_not_verified():
    conv = _conv(None)
    proof = await conv.admit(TrustRegistry([_AttestationProfile()]))
    assert proof.status is ProofStatus.NOT_VERIFIED
    assert "unattested" in proof.failure_reason


@pytest.mark.asyncio
async def test_require_verified_rejects_bad_attestation():
    conv = _conv({"attestation": "forged"})
    with pytest.raises(AdmissionError, match="failed admission"):
        await conv.admit(TrustRegistry([_AttestationProfile()]), require_verified=True)


@pytest.mark.asyncio
async def test_bridge_admit_entries_stamps_all_and_serves_proof():
    conv = _conv({"attestation": "valid"})
    bridge = SmBridge(
        registry_id="quilt", provider_name="Q", provider_url="https://q.example",
        trust_registry=TrustRegistry([_AttestationProfile()]), entries=[conv],
    )
    await bridge.admit_entries()

    app = FastAPI()
    app.include_router(bridge.router)
    body = TestClient(app).get("/nanda/registries/acme-ans").json()
    assert body["proof"]["status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_resolution_still_delegates_after_admission():
    # Admission verifies once; resolving an agent under the entry still returns a delegation
    # pointer — the index never re-verifies live records.
    conv = _conv({"attestation": "valid"})
    bridge = SmBridge(
        registry_id="quilt", provider_name="Q", provider_url="https://q.example",
        trust_registry=TrustRegistry([_AttestationProfile()]), entries=[conv],
    )
    await bridge.admit_entries()
    app = FastAPI()
    app.include_router(bridge.router)
    r = TestClient(app).get("/nanda/registries/acme-ans/resolve", params={"agent": "urn:a:1"})
    assert r.json()["kind"] == "delegation"  # delegated, not a verified mirror
