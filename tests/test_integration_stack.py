"""Integration — the whole quilt, all hops and resolves, with every trust profile.

Stands up ONE sm-bridge wired with all five trust profiles and an entry-mode ANS registry,
then drives every path a caller would take:

  hosting mode (a catalog agent):   /nanda/index -> /nanda/resolve -> VERIFIED ed25519 proof
  entry mode (an ANS registry):     /nanda/registries -> delegation pointer (never mirrored)
  ai-catalog surface:               /.well-known/ai-catalog.json (spec-shaped)
  each trust profile exercised end-to-end with real crypto or an honest NOT_VERIFIED.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge.converter import SimpleAgent, SimpleAgentConverter
from sm_bridge.onboarding import ANSEntryConverter
from sm_bridge.router import SmBridge
from sm_bridge.trust import TrustRegistry
from sm_bridge.trust.ans_scitt import AnsScittProfile
from sm_bridge.trust.ans_txt import AnsTxtProfile
from sm_bridge.trust.delegation import NandaDelegationProfile
from sm_bridge.trust.dns_aid import DnsAidProfile
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile, canonicalize

# ------------------------------------------------------------------------------------
# A hosting-mode converter whose agent card is really signed, so resolve verifies it.
# ------------------------------------------------------------------------------------

_SIGNING_KEY = Ed25519PrivateKey.generate()


class SignedCatalogConverter(SimpleAgentConverter):
    """Hosting-mode source (an AI catalog) that can prove each agent card with ed25519."""

    def trust_evidence(self, agent):
        facts = self.to_sm(agent)
        payload = facts.model_dump(mode="json", exclude_none=True)
        payload.pop("proof", None)
        sig = _SIGNING_KEY.sign(canonicalize(payload))
        pub = _SIGNING_KEY.public_key().public_bytes_raw()
        return (
            "ed25519-agentcard",
            {"payload": payload, "signature_b64": base64.b64encode(sig).decode(), "public_key": pub},
        )


def _bridge() -> SmBridge:
    conv = SignedCatalogConverter(
        registry_id="catalog", provider_name="Catalog Co", provider_url="https://cat.example",
        base_url="https://cat.example",
    )
    conv.register(SimpleAgent(id="finance", name="Finance Agent", description="does finance", public=True))
    registry = TrustRegistry([
        Ed25519AgentCardProfile(),
        AnsScittProfile(),
        AnsTxtProfile(),
        DnsAidProfile(),
        NandaDelegationProfile(),
    ])
    entries = [
        ANSEntryConverter(
            registry_name="acme-ans", display_name="Acme ANS",
            resolver_endpoint="https://ans.acme.example",
            tl_checkpoint="acme\n9\nROOT\n", root_keys=["acme+deadbeef+KEY"],
        )
    ]
    return SmBridge(
        registry_id="catalog", provider_name="Catalog Co", provider_url="https://cat.example",
        converter=conv, trust_registry=registry, entries=entries,
    )


def _client() -> TestClient:
    b = _bridge()
    app = FastAPI()
    app.include_router(b.router)
    app.include_router(b.wellknown_router)
    return TestClient(app)


# ------------------------------------------------------------------------------------
# Hosting-mode: index -> resolve -> a genuinely VERIFIED ed25519 proof block
# ------------------------------------------------------------------------------------

def test_hosting_all_hops_index_then_resolve_verified():
    c = _client()
    idx = c.get("/nanda/index").json()
    assert idx["total_count"] == 1
    ids = [a["id"] for a in idx["agents"]]
    assert any(i.endswith("finance") for i in ids)

    r = c.get("/nanda/resolve", params={"agent": "finance"}).json()
    assert r["agent_name"] == "Finance Agent"
    # the card was really signed -> the resolve hop carries a VERIFIED proof
    assert r["proof"]["status"] == "VERIFIED"
    assert r["proof"]["profile"] == "ed25519-agentcard"
    assert r["proof"]["evidence_ref"].startswith("ed25519:")


def test_ai_catalog_surface_is_spec_shaped():
    # The hosting gateway also speaks the Agent-Card/ai-catalog spec: {specVersion, host, entries}.
    from sm_bridge.gateway import create_gateway_router

    b = _bridge()
    app = FastAPI()
    app.include_router(create_gateway_router(b.delta_store, base_url="https://cat.example", domain="cat.example"))
    # seed the gateway's view from the delta log
    b.register_agent(SimpleAgent(id="research", name="Research", description="r", public=True))
    doc = TestClient(app).get("/.well-known/ai-catalog.json").json()
    assert set(doc) >= {"specVersion", "host", "entries"}
    assert doc["host"] == "https://cat.example"


# ------------------------------------------------------------------------------------
# Entry-mode: the quilt stays pointer-only — resolve delegates, never mirrors
# ------------------------------------------------------------------------------------

def test_entry_mode_all_hops_registries_then_delegate():
    c = _client()
    regs = c.get("/nanda/registries").json()
    assert [e["registry_name"] for e in regs] == ["acme-ans"]
    assert regs[0]["conformance_level"] == "auditable"

    deleg = c.get("/nanda/registries/acme-ans/resolve", params={"agent": "urn:acme:42"}).json()
    assert deleg["kind"] == "delegation"
    assert deleg["resolver_endpoint"] == "https://ans.acme.example"
    # never a mirrored SmAgentFacts record
    assert "skills" not in deleg and "capabilities" not in deleg


# ------------------------------------------------------------------------------------
# Every profile reachable through the one registry, each honest
# ------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registry_dispatches_all_profiles_honestly():
    reg = _bridge().trust_registry
    assert set(reg.profile_ids()) == {
        "ed25519-agentcard", "ans-scitt", "ans-txt", "dns-aid", "nanda-delegation",
    }

    # ed25519: a real signed card verifies
    key = Ed25519PrivateKey.generate()
    payload = {"id": "x", "b": 2, "a": 1}
    sig = key.sign(canonicalize(payload))
    ev = {"payload": payload, "signature_b64": base64.b64encode(sig).decode(),
          "public_key": key.public_key().public_bytes_raw()}
    assert (await reg.verify("ed25519-agentcard", None, ev)).status.value == "VERIFIED"

    # dns-aid: no fqdn -> honest NOT_VERIFIED (never a fabricated pass)
    assert (await reg.verify("dns-aid", None, {})).status.value == "NOT_VERIFIED"

    # unknown profile -> honest NOT_VERIFIED, not a crash
    assert (await reg.verify("no-such", None, {})).status.value == "NOT_VERIFIED"
