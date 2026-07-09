"""Phase 1 — /nanda/resolve carries a normalized proof block via the injected registry."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge.converter import SimpleAgent, SimpleAgentConverter
from sm_bridge.router import SmBridge
from sm_bridge.trust import ProofResult, TrustRegistry


class _EvidenceConverter(SimpleAgentConverter):
    """A converter that can supply verification evidence for the resolve seam."""

    def trust_evidence(self, agent):  # noqa: D401 - hook
        return ("stub-profile", {"ok": True})


class _StubProfile:
    profile_id = "stub-profile"

    async def verify(self, subject, evidence):
        if evidence.get("ok"):
            return ProofResult.verified(profile=self.profile_id, method="stub", evidence_ref="ev:resolve")
        return ProofResult.failed(profile=self.profile_id, method="stub", reason="no")


def _client(with_trust: bool) -> TestClient:
    conv = _EvidenceConverter(
        registry_id="r", provider_name="P", provider_url="https://p.example", base_url="https://p.example"
    )
    conv.register(SimpleAgent(id="a1", name="A1", description="d", public=True))
    reg = TrustRegistry([_StubProfile()]) if with_trust else None
    bridge = SmBridge(
        registry_id="r", provider_name="P", provider_url="https://p.example", converter=conv, trust_registry=reg
    )
    app = FastAPI()
    app.include_router(bridge.router)
    app.include_router(bridge.wellknown_router)
    return TestClient(app)


def test_resolve_carries_verified_proof_when_registry_present():
    r = _client(with_trust=True).get("/nanda/resolve", params={"agent": "a1"})
    assert r.status_code == 200
    proof = r.json()["proof"]
    assert proof["status"] == "VERIFIED"
    assert proof["profile"] == "stub-profile"
    assert proof["evidence_ref"] == "ev:resolve"


def test_resolve_without_registry_still_resolves():
    # No trust registry → agent still resolves; proof reflects the converter (legacy dict
    # downgraded to NOT_VERIFIED), never a fabricated pass.
    r = _client(with_trust=False).get("/nanda/resolve", params={"agent": "a1"})
    assert r.status_code == 200
    proof = r.json()["proof"]
    assert proof is None or proof["status"] == "NOT_VERIFIED"


def test_wellknown_unchanged():
    r = _client(with_trust=True).get("/.well-known/nanda.json")
    assert r.status_code == 200
    body = r.json()
    assert "index_url" in body and "capabilities" in body
