"""
Extended / adversarial tests for sm-bridge

# ── Step 1: Assumption Audit ──────────────────────────────────────────
# A1. _parse_agent_identifier handles empty strings gracefully.
# A2. _parse_agent_identifier handles malformed DIDs ("did:" only).
# A3. Handle strings without "/" still return something meaningful.
# A4. Unregister records a "delete" delta.
# A5. add_tool appends to the bridge tools list.
# A6. PersistentDeltaStore._persist and _load_since are called.
# A7. Concurrent DeltaStore.add calls produce monotonic sequences.

# ── Step 2: Gap Analysis ─────────────────────────────────────────────
# G1. No test for empty-string identifier parsing.
# G2. No test for malformed DID ("did:" with no segments).
# G3. No test for handle without slash ("@registry:noslash").
# G4. No concurrency test for DeltaStore.
# G5. No test verifying add_tool makes tool visible in bridge.tools.

# ── Step 3: Break It List ────────────────────────────────────────────
# B1. Empty string to _parse_agent_identifier — should not crash.
# B2. "did:" alone — should return last segment (empty string).
# B3. "@registry:noslash" — no "/" means fall through to strip "@".
# B4. Concurrent adds from multiple threads — seqs must be monotonic.
# B5. PersistentDeltaStore hooks must be invoked on add / since.
"""

import threading

import pytest
from fastapi import HTTPException

from sm_bridge import (
    DeltaStore,
    SmAgentFacts,
    SmBridge,
    SimpleAgent,
    SimpleAgentConverter,
)
from sm_bridge.models import SmTool
from sm_bridge.router import _parse_agent_identifier, create_sm_router
from sm_bridge.store import PersistentDeltaStore

from .conftest import (
    TEST_BASE_URL,
    TEST_PROVIDER_NAME,
    TEST_PROVIDER_URL,
    TEST_REGISTRY_ID,
)

# ── helpers ───────────────────────────────────────────────────────────


def _make_agent_facts(agent_id: str = "agent-1") -> SmAgentFacts:
    converter = SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        base_url=TEST_BASE_URL,
    )
    agent = SimpleAgent(
        id=agent_id,
        name=f"Agent {agent_id}",
        description="Test agent",
        labels=["chat"],
    )
    return converter.to_sm(agent)


def _build_router(converter=None, delta_store=None, tools=None):
    converter = converter or SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        base_url=TEST_BASE_URL,
    )
    delta_store = delta_store or DeltaStore()
    router = create_sm_router(
        converter=converter,
        delta_store=delta_store,
        registry_id=TEST_REGISTRY_ID,
        base_url=TEST_BASE_URL,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        tools=tools,
        namespaces=["did:web:provider.test:*"],
    )
    return router, converter, delta_store


# =====================================================================
# Boundary tests — identifier parsing edge cases
# =====================================================================


class TestParseIdentifierBoundary:
    """Boundary and edge-case tests for _parse_agent_identifier."""

    def test_parse_identifier_empty_string(self):
        """Empty string input should not crash; returns empty string."""
        result = _parse_agent_identifier("", TEST_REGISTRY_ID)
        assert result == ""

    def test_parse_identifier_malformed_did(self):
        """'did:' with no further segments returns the last split part."""
        result = _parse_agent_identifier("did:", TEST_REGISTRY_ID)
        # "did:".split(":") == ["did", ""] → last element is ""
        assert result == ""

    def test_parse_identifier_handle_no_slash(self):
        """'@registry:noslash' has no '/' so falls to strip-@ path."""
        result = _parse_agent_identifier("@registry:noslash", TEST_REGISTRY_ID)
        # No "/" in value → returns value[1:] == "registry:noslash"
        assert result == "registry:noslash"


# =====================================================================
# Failure / sad-path tests
# =====================================================================


class TestRouterFailures:
    """Router error-path tests."""

    def test_resolve_not_found_and_not_public(self):
        router, converter, _ = _build_router()
        private_agent = SimpleAgent(
            id="private", name="Private", description="priv", public=False, namespace="ns"
        )
        converter.register(private_agent)

        resolve_route = next(r for r in router.routes if r.path.endswith("/resolve"))

        with pytest.raises(HTTPException) as missing:
            resolve_route.endpoint(agent="missing")
        assert missing.value.status_code == 404

        handle = f"@{TEST_REGISTRY_ID}:ns/private"
        with pytest.raises(HTTPException) as forbidden:
            resolve_route.endpoint(agent=handle)
        assert forbidden.value.status_code == 403


# =====================================================================
# Integration / lifecycle tests
# =====================================================================


class TestLifecycle:
    """Register → unregister lifecycle and tool management."""

    def test_register_agent_then_unregister(self, bridge):
        """Register then unregister — delta store records upsert then delete."""
        agent = SimpleAgent(id="lifecycle", name="Lifecycle Agent", description="test")
        bridge.register_agent(agent)

        assert len(bridge.delta_store) == 1
        assert bridge.delta_store.since(0)[0].action == "upsert"

        bridge.unregister_agent(agent.id)

        assert len(bridge.delta_store) == 2
        assert bridge.delta_store.since(1)[0].action == "delete"
        assert bridge.converter.get_agent(agent.id) is None

    def test_bridge_add_tool_appears_in_tools(self, bridge):
        """add_tool makes the tool visible in bridge.tools."""
        tool = SmTool(
            tool_id="new-tool",
            description="A new tool",
            endpoint="https://tools.test/new",
        )
        bridge.add_tool(tool)

        assert len(bridge.tools) == 1
        assert bridge.tools[0].tool_id == "new-tool"
        assert bridge.wellknown.tools_url is not None


# =====================================================================
# Concurrency tests
# =====================================================================


class TestConcurrency:
    """Thread-safety tests for DeltaStore."""

    def test_concurrent_delta_store_adds(self, delta_store):
        """Adds from multiple threads produce monotonically increasing seqs."""
        num_threads = 10
        adds_per_thread = 20
        facts = _make_agent_facts("concurrent")

        results: list[int] = []
        lock = threading.Lock()

        def worker():
            for _ in range(adds_per_thread):
                delta = delta_store.add("upsert", facts)
                with lock:
                    results.append(delta.seq)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == num_threads * adds_per_thread
        # All sequence numbers must be unique
        assert len(set(results)) == len(results)
        # When sorted, they should be 1..N
        assert sorted(results) == list(range(1, num_threads * adds_per_thread + 1))


# =====================================================================
# PersistentDeltaStore hook tests
# =====================================================================


class DummyPersistentStore(PersistentDeltaStore):
    def __init__(self):
        super().__init__(max_deltas=10)
        self.persisted: list = []
        self.loaded: list = []
        self._load_returns: list[list] = []

    def _persist(self, delta):
        self.persisted.append(delta)
        return super()._persist(delta)

    def _load_since(self, seq: int):
        self.loaded.append(seq)
        if self._load_returns:
            return self._load_returns.pop(0)
        return super()._load_since(seq)


class TestPersistentDeltaStore:
    """Tests for PersistentDeltaStore hooks."""

    def test_persistent_delta_store_hooks_called(self):
        """_persist called on add; _load_since called on since."""
        store = DummyPersistentStore()
        facts = _make_agent_facts("persistent")

        delta = store.add("upsert", facts)

        # _persist was called
        assert len(store.persisted) == 1
        assert store.persisted[0].seq == delta.seq

        # _load_since is called when since() is invoked
        store._load_returns.append([delta])
        result = store.since(0)
        assert result == [delta]
        assert 0 in store.loaded

    def test_persistent_delta_store_paths(self):
        """Existing test: fallback to in-memory when _load_since returns []."""
        store = DummyPersistentStore()
        facts = _make_agent_facts("persistent")

        delta = store.add("upsert", facts)
        assert store.persisted == [delta]

        store._load_returns.append([delta])
        assert store.since(0) == [delta]

        assert store.since(delta.seq) == []


# =====================================================================
# Happy-path tests (existing, kept last per R1-R10 ordering)
# =====================================================================


def test_converter_skills_and_unregister_and_get():
    converter = SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
    )
    agent = SimpleAgent(
        id="agent-skills",
        name="Skillful Agent",
        description="Has skills",
        skills=[
            {
                "id": "dict-skill",
                "description": "dict based",
                "inputModes": ["text"],
                "outputModes": ["text"],
            },
            "string-skill",
        ],
        endpoints={"primary": "https://api.test.com/agent-skills"},
    )
    converter.register(agent)
    facts = converter.to_sm(agent)

    assert [s.id for s in facts.skills] == ["dict-skill", "string-skill"]
    assert facts.endpoints.static == ["https://api.test.com/agent-skills"]

    converter.unregister(agent.id)
    assert converter.get_agent(agent.id) is None


def test_converter_ext_metadata_dynamic_and_proof():
    converter = SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
    )
    agent = SimpleAgent(
        id="agent-meta",
        name="Meta Agent",
        description="Has metadata",
        public=False,
        classification="internal",
        card_template="card-v1",
        metadata={
            "certification": {"fedramp": "pending"},
            "telemetry": {"latency_ms": 50},
        },
        endpoints={"primary": "https://api.test.com/meta"},
        dynamic_endpoints=["https://edge.test.com/meta"],
    )

    facts = converter.to_sm(agent)

    assert facts.endpoints.dynamic == ["https://edge.test.com/meta"]
    meta = facts.metadata["x_test_registry"]
    assert meta["public"] is False
    assert meta["classification"] == "internal"
    assert meta["card_template"] == "card-v1"
    assert meta["certification"]["fedramp"] == "pending"
    assert meta["telemetry"]["latency_ms"] == 50
    assert any(entry["key"] == "primary" for entry in meta["endpoints_extended"])
    assert any(entry["key"] == "dynamic_0" for entry in meta["endpoints_extended"])
    assert facts.proof["method"] == "sha256"


def test_delta_store_pruning_get_and_clear():
    store = DeltaStore(max_deltas=2)
    facts = _make_agent_facts("prune-me")

    first = store.add("upsert", facts)
    store.add("upsert", facts)
    third = store.add("upsert", facts)

    assert len(store) == 2
    assert store.get(first.seq) is None
    assert store.get(third.seq).seq == third.seq
    assert store.current_seq == third.seq
    assert store.next_seq == third.seq + 1

    store.clear()
    assert len(store) == 0
    assert store.current_seq == 0
    assert store.next_seq == 1


def test_index_filters_private_and_lists_public():
    router, converter, _ = _build_router()
    public_agent = SimpleAgent(id="public", name="Public", description="pub", labels=["chat"])
    private_agent = SimpleAgent(id="private", name="Private", description="priv", public=False)
    converter.register(public_agent)
    converter.register(private_agent)

    index_route = next(r for r in router.routes if r.path.endswith("/index"))
    data = index_route.endpoint(limit=100, offset=0).model_dump()

    assert data["total_count"] == 1
    assert data["agents"][0]["id"].endswith("public")


def test_resolve_success_returns_agentfacts():
    router, converter, _ = _build_router()
    agent = SimpleAgent(id="good", name="Good Agent", description="ok", labels=["chat"])
    converter.register(agent)

    resolve_route = next(r for r in router.routes if r.path.endswith("/resolve"))
    facts = resolve_route.endpoint(agent="good")

    assert facts.agent_name == "Good Agent"
    assert facts.handle.endswith("/good")


def test_deltas_endpoint_returns_changes_and_next_seq():
    router, converter, delta_store = _build_router()
    agent = SimpleAgent(id="delta-agent", name="Delta Agent", description="desc")
    converter.register(agent)
    delta_store.add("upsert", converter.to_sm(agent))

    deltas_route = next(r for r in router.routes if r.path.endswith("/deltas"))
    body = deltas_route.endpoint(since=0).model_dump()

    assert len(body["deltas"]) == 1
    assert body["next_seq"] == delta_store.next_seq


def test_tools_and_wellknown_routes():
    tools = [
        SmTool(
            tool_id="t1",
            description="Tool 1",
            endpoint="https://tools.test/t1",
            params=["x"],
            version="v1",
        )
    ]
    router, _, _ = _build_router(tools=tools)

    tools_route = next(r for r in router.routes if r.path.endswith("/tools"))
    tools_resp = tools_route.endpoint().model_dump()
    assert tools_resp["tools"][0]["tool_id"] == "t1"

    wellknown_route = next(r for r in router.routes if "well-known" in r.path)
    wellknown = wellknown_route.endpoint().model_dump()
    assert wellknown["tools_url"] is not None
    assert "mcp-tools" in wellknown["capabilities"]


def test_parse_agent_identifier_variants():
    assert _parse_agent_identifier("@registry/agent", TEST_REGISTRY_ID) == "agent"
    assert _parse_agent_identifier("@registry", TEST_REGISTRY_ID) == "registry"
    assert (
        _parse_agent_identifier("did:web:example.com:agents:ns:agent", TEST_REGISTRY_ID) == "agent"
    )
    assert _parse_agent_identifier("ns:agent", TEST_REGISTRY_ID) == "agent"
    assert _parse_agent_identifier("plain-agent", TEST_REGISTRY_ID) == "plain-agent"


def test_bridge_unregister_records_delete_and_add_tool():
    bridge = SmBridge(
        registry_id="bridge-test",
        provider_name="Bridge",
        provider_url="https://bridge.test",
    )
    agent = SimpleAgent(id="bridge-agent", name="Bridge Agent", description="desc")
    bridge.register_agent(agent)
    assert len(bridge.delta_store) == 1

    bridge.unregister_agent(agent.id)
    assert len(bridge.delta_store) == 2
    assert bridge.delta_store.since(1)[0].action == "delete"
    assert bridge.converter.get_agent(agent.id) is None

    tool = SmTool(tool_id="bridge-tool", description="Tool", endpoint="https://tool.test")
    bridge.add_tool(tool)
    assert len(bridge.tools) == 1
    assert bridge.wellknown.tools_url is not None


def test_bridge_accepts_custom_converter_branch():
    custom_converter = SimpleAgentConverter(
        registry_id="custom-registry",
        provider_name="Custom",
        provider_url="https://custom.test",
    )
    custom_store = DeltaStore()
    bridge = SmBridge(
        registry_id="custom-registry",
        provider_name="Custom",
        provider_url="https://custom.test",
        converter=custom_converter,
        delta_store=custom_store,
    )
    assert bridge.converter is custom_converter
    assert bridge.delta_store is custom_store
