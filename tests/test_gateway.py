"""Tests for the AI-Catalog gateway (border layer)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge import (
    DeltaStore,
    SmAgentFacts,
    SmAuthentication,
    SmCapabilities,
    SmEndpoints,
    SmProvider,
    SmSkill,
    create_gateway_router,
)

BASE_URL = "https://reg.example.com"
DOMAIN = "example.com"
RUNTIME = "https://runtime.example.com"


def _facts(slug: str = "planner") -> SmAgentFacts:
    return SmAgentFacts(
        id=f"did:web:{DOMAIN}:agents:{slug}",
        handle=SmAgentFacts.create_handle("example", "agents", slug),
        agent_name=f"Agent {slug}",
        label=slug,
        description="An agent.",
        version="1.0.0",
        provider=SmProvider(name="Example", url="https://example.com"),
        endpoints=SmEndpoints(static=[RUNTIME]),
        capabilities=SmCapabilities(
            modalities=["text"], skills=["plan"], authentication=SmAuthentication(methods=["ed25519"])
        ),
        skills=[SmSkill(id="plan", description="Plan something")],
    )


def _client(store: DeltaStore) -> TestClient:
    app = FastAPI()
    app.include_router(create_gateway_router(store, base_url=BASE_URL, domain=DOMAIN))
    return TestClient(app)


def test_ai_catalog_lists_upserted_agent() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    client = _client(store)

    res = client.get("/.well-known/ai-catalog.json")
    assert res.status_code == 200
    body = res.json()
    assert body["specVersion"] == "1.0"
    assert len(body["entries"]) == 1
    entry = body["entries"][0]
    assert entry["identifier"] == "planner"
    assert entry["mediaType"] == "application/a2a-agent-card+json"
    assert entry["url"] == f"{BASE_URL}/cards/planner.json"


def test_catalog_entry_is_a_pointer() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    res = _client(store).get("/agents/planner")
    assert res.status_code == 200
    entry = res.json()
    assert entry["identifier"] == "planner"
    assert entry["url"] == f"{BASE_URL}/cards/planner.json"
    assert entry["displayName"] == "Agent planner"


def test_a2a_card_leaf_points_at_runtime_and_carries_agentfacts() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    res = _client(store).get("/cards/planner.json")
    assert res.status_code == 200
    card = res.json()
    assert card["url"] == RUNTIME
    assert card["authentication"]["schemes"] == ["ed25519"]
    assert card["_meta"]["identifier"] == f"urn:ai:domain:{DOMAIN}:agent:planner"
    # native facts ride along on the same response
    assert card["_meta"]["agentfacts"]["agent_name"] == "Agent planner"


def test_unknown_agent_404() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    client = _client(store)
    assert client.get("/agents/ghost").status_code == 404
    assert client.get("/cards/ghost.json").status_code == 404


def test_delete_delta_removes_agent_from_catalog() -> None:
    """Federation-fed: a delete delta drops the agent from the live catalog."""
    store = DeltaStore()
    facts = _facts("planner")
    store.add("upsert", facts)
    client = _client(store)
    assert client.get("/agents/planner").status_code == 200

    store.add("delete", facts)
    assert client.get("/agents/planner").status_code == 404
    assert client.get("/.well-known/ai-catalog.json").json()["entries"] == []


def test_later_upsert_wins() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    updated = _facts("planner")
    updated.description = "Updated description."
    store.add("upsert", updated)

    card = _client(store).get("/cards/planner.json").json()
    assert card["description"] == "Updated description."
