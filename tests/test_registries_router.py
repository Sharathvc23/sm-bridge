"""Phase 3 router surface — /nanda/registries list, get, and entry-mode delegation."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge.onboarding import ANSEntryConverter
from sm_bridge.router import SmBridge


def _client() -> TestClient:
    entries = [
        ANSEntryConverter(
            registry_name="acme-ans",
            display_name="Acme ANS",
            resolver_endpoint="https://ans.acme.example",
            tl_checkpoint="acme\n5\nROOT\n",
            root_keys=["acme+deadbeef+KEY"],
        ),
        ANSEntryConverter(registry_name="bare", resolver_endpoint="https://bare.example"),
    ]
    bridge = SmBridge(
        registry_id="r", provider_name="P", provider_url="https://p.example", entries=entries
    )
    app = FastAPI()
    app.include_router(bridge.router)
    return TestClient(app)


def test_registries_list():
    r = _client().get("/nanda/registries")
    assert r.status_code == 200
    names = {e["registry_name"] for e in r.json()}
    assert names == {"acme-ans", "bare"}


def test_registry_get_conformance_level():
    body = _client().get("/nanda/registries/acme-ans").json()
    assert body["conformance_level"] == "auditable"  # has checkpoint + keys
    assert body["trust_profile"] == "ans-scitt"
    assert _client().get("/nanda/registries/bare").json()["conformance_level"] == "basic"


def test_registry_unknown_404():
    assert _client().get("/nanda/registries/nope").status_code == 404


def test_entry_mode_resolve_delegates_not_mirrors():
    r = _client().get("/nanda/registries/acme-ans/resolve", params={"agent": "urn:agent:9"})
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "delegation"
    assert body["resolver_endpoint"] == "https://ans.acme.example"
    assert body["agent"] == "urn:agent:9"
    # a delegation pointer, never a mirrored SmAgentFacts record
    assert "skills" not in body and "capabilities" not in body
