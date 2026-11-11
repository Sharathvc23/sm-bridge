"""Tests for the AI Catalog gateway."""

from __future__ import annotations

from datetime import datetime, timezone

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
from sm_bridge.gateway import to_a2a_card, to_catalog_entry

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
    # The legacy top-level endpoint is kept and agrees with the v1.0 interface.
    assert card["url"] == RUNTIME
    assert card["supportedInterfaces"][0]["url"] == RUNTIME
    # An AIR URN. This asserted `urn:ai:domain:...` until that form turned out to
    # be one the Index refuses; see tests/test_index_fanout.py.
    assert card["_meta"]["identifier"] == f"urn:air:{DOMAIN}:agent:planner"
    # native facts ride along on the same response
    assert card["_meta"]["agentfacts"]["agent_name"] == "Agent planner"


# ── A2A v1.0 card shape ──────────────────────────────────────────────────────
#
# The card used to be an A2A v0.2-era document: a top-level `url` only, an
# `authentication: {schemes}` block the protocol dropped in v0.3, no
# `defaultInputModes`/`defaultOutputModes`, skills without `id`/`tags` and no
# protocol version. The NANDA Index v2 rejected it. The assertions below pin the
# v1.0 shape (A2A spec §4.4.1 AgentCard, §4.4.5 AgentSkill, §4.4.6 AgentInterface).


def _card(facts: SmAgentFacts | None = None) -> dict:
    store = DeltaStore()
    store.add("upsert", facts or _facts("planner"))
    return _client(store).get("/cards/planner.json").json()


def test_card_is_a2a_v1_0() -> None:
    card = _card()
    assert card["protocolVersion"] == "1.0"
    assert card["supportedInterfaces"] == [
        {"url": RUNTIME, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ]
    assert card["name"] == "Agent planner"
    assert card["description"] == "An agent."
    assert card["version"] == "1.0.0"
    assert card["capabilities"] == {"streaming": False}
    assert card["provider"] == {"organization": "Example", "url": "https://example.com"}
    # `authentication` was removed from the AgentCard in A2A v0.3; it must not come back.
    assert "authentication" not in card


def test_card_security_is_derived_from_the_declared_auth_methods() -> None:
    card = _card()
    assert card["securitySchemes"] == {
        "ed25519": {
            "type": "ed25519",
            "description": card["securitySchemes"]["ed25519"]["description"],
        }
    }
    assert "no lossless equivalent" in card["securitySchemes"]["ed25519"]["description"]
    assert card["securityRequirements"] == [{"ed25519": []}]


def test_card_renders_a_lossless_a2a_scheme_when_one_exists() -> None:
    facts = _facts("planner")
    facts.capabilities.authentication = SmAuthentication(
        methods=["jwt", "oauth2"], requiredScopes=["agents:read"]
    )
    card = _card(facts)
    assert card["securitySchemes"]["jwt"] == {
        "type": "http", "scheme": "bearer", "bearerFormat": "JWT"
    }
    assert card["securitySchemes"]["oauth2"]["type"] == "oauth2"
    # Alternatives, in the declared order, each carrying the agent's required scopes.
    assert card["securityRequirements"] == [
        {"jwt": ["agents:read"]}, {"oauth2": ["agents:read"]}
    ]


def test_an_agent_declaring_no_auth_has_no_schemes_and_no_requirements() -> None:
    facts = _facts("planner")
    facts.capabilities.authentication = SmAuthentication(methods=["none"])
    card = _card(facts)
    assert card["securitySchemes"] == {}
    assert card["securityRequirements"] == []


def test_card_skills_carry_id_name_description_and_nonempty_tags() -> None:
    card = _card()
    assert card["skills"] == [
        {
            "id": "plan",
            "name": "plan",
            "description": "Plan something",
            "tags": ["plan"],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain"],
        }
    ]


def test_skill_name_comes_from_the_source_when_it_sent_one() -> None:
    facts = _facts("planner")
    facts.skills = [
        SmSkill.model_validate({"id": "plan", "name": "Planner", "description": "Plan something"})
    ]
    assert _card(facts)["skills"][0]["name"] == "Planner"


def test_skill_tags_fall_back_to_general_when_no_capability_skills_are_declared() -> None:
    facts = _facts("planner")
    facts.capabilities.skills = []
    card = _card(facts)
    assert card["skills"][0]["tags"] == ["general"]


def test_default_modes_are_the_union_of_the_skills_modes_as_media_types() -> None:
    facts = _facts("planner")
    facts.skills = [
        SmSkill(id="plan", description="d", inputModes=["text", "image"], outputModes=["json"]),
        SmSkill(id="draw", description="d", inputModes=["text"], outputModes=["image/png"]),
    ]
    card = _card(facts)
    assert card["defaultInputModes"] == ["text/plain", "image/*"]
    assert card["defaultOutputModes"] == ["application/json", "image/png"]
    assert card["skills"][1]["outputModes"] == ["image/png"]


def test_default_modes_fall_back_to_text_plain_when_skills_declare_none() -> None:
    facts = _facts("planner")
    facts.skills = [SmSkill(id="plan", description="d", inputModes=[], outputModes=[])]
    card = _card(facts)
    assert card["defaultInputModes"] == ["text/plain"]
    assert card["defaultOutputModes"] == ["text/plain"]


def test_model_dump_emits_meta_under_its_wire_name_by_default() -> None:
    card = to_a2a_card(_facts("planner"), "planner", DOMAIN, BASE_URL)
    dumped = card.model_dump()
    assert "_meta" in dumped and "meta" not in dumped
    assert dumped["_meta"]["identifier"] == f"urn:air:{DOMAIN}:agent:planner"
    assert '"_meta"' in card.model_dump_json()
    # The router's JSON and a hand-rolled dump are the same document.
    assert card.model_dump(mode="json") == _card()


def test_the_v1_0_card_satisfies_the_index_card_check() -> None:
    """A Python rendering of the NANDA Index v2 A2A card check.

    Source: ``server/src/services/cardValidation.ts`` in ``projnanda/nanda-index-v2``,
    whose rule text is also served in the Index's OpenAPI description
    (``https://api.nandaindex.org/docs/json``): "A2A (application/a2a-agent-card+json):
    supportedInterfaces must be a nonempty array whose entries have nonempty
    protocolBinding and protocolVersion strings and an absolute URL without embedded
    credentials. Core JSONRPC, GRPC, and HTTP+JSON bindings require HTTP(S) URLs. When
    supportedInterfaces is absent, a legacy HTTP(S) url is required. capabilities must
    be an object; defaultInputModes and defaultOutputModes must be nonempty arrays of
    nonempty strings. skills must be an array (possibly empty); each skill requires
    nonempty id, name, description and a tags array of nonempty strings."
    Checked 2026-11-11.
    """
    card = _card()

    def text(v: object) -> bool:
        return isinstance(v, str) and v.strip() != ""

    def strings(v: object) -> bool:
        return isinstance(v, list) and len(v) > 0 and all(text(x) for x in v)

    def http_url(v: object) -> bool:
        from urllib.parse import urlparse

        if not isinstance(v, str):
            return False
        u = urlparse(v)
        return u.scheme in ("http", "https") and not u.username and not u.password

    issues = [f for f in ("name", "description", "version") if not text(card.get(f))]
    interfaces = card.get("supportedInterfaces")
    if interfaces is not None:
        endpoint = (
            isinstance(interfaces, list)
            and len(interfaces) > 0
            and all(
                isinstance(i, dict)
                and text(i.get("protocolBinding"))
                and text(i.get("protocolVersion"))
                and http_url(i.get("url"))
                for i in interfaces
            )
        )
    else:
        endpoint = http_url(card.get("url"))
    if not endpoint:
        issues.append("supportedInterfaces")
    if not isinstance(card.get("capabilities"), dict):
        issues.append("capabilities")
    if not strings(card.get("defaultInputModes")):
        issues.append("defaultInputModes")
    if not strings(card.get("defaultOutputModes")):
        issues.append("defaultOutputModes")
    skills = card.get("skills")
    if not (
        isinstance(skills, list)
        and all(
            isinstance(s, dict)
            and text(s.get("id"))
            and text(s.get("name"))
            and text(s.get("description"))
            and isinstance(s.get("tags"), list)
            and all(text(t) for t in s["tags"])
            for s in skills
        )
    ):
        issues.append("skills")
    assert issues == []
    # And the legacy fallback the Index applies when `supportedInterfaces` is absent
    # would also pass on this card.
    assert http_url(card["url"])


def test_catalog_entry_url_has_no_double_slash_when_base_url_ends_with_one() -> None:
    entry = to_catalog_entry(_facts("planner"), "planner", BASE_URL + "/")
    assert entry.url == f"{BASE_URL}/cards/planner.json"
    card = to_a2a_card(_facts("planner"), "planner", DOMAIN, BASE_URL + "/")
    assert card.meta["publicUrl"] == f"{BASE_URL}/cards/planner.json"


def test_catalog_entry_updated_at_is_serialization_time() -> None:
    before = datetime.now(timezone.utc)
    entry = to_catalog_entry(_facts("planner"), "planner", BASE_URL)
    after = datetime.now(timezone.utc)
    assert before <= datetime.fromisoformat(entry.updatedAt) <= after


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
