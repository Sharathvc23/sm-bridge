"""
Tests for sm-bridge

# ── Step 1: Assumption Audit ──────────────────────────────────────────
# A1. SimpleAgentConverter.get_agent returns None for unknown IDs.
# A2. DeltaStore.since(0) returns ALL deltas (boundary).
# A3. DeltaStore pruning fires only when len > max_deltas.
# A4. SmAgentFacts.create_handle always produces "@registry:ns/id".
# A5. An agent with no skills gets a single default skill.
# A6. Skills passed as dicts or strings are both accepted.
# A7. Private agents are excluded from is_public.

# ── Step 2: Gap Analysis ─────────────────────────────────────────────
# G1. ZERO pytest.raises in this file — no error-state coverage.
# G2. No boundary tests for DeltaStore.since or pruning at exact max.
# G3. No test for get_agent returning None (nonexistent agent).
# G4. No test for handle format correctness.
# G5. No tests for different skill input types (dict vs str vs empty).

# ── Step 3: Break It List ────────────────────────────────────────────
# B1. since(999999) on a small store — should return [].
# B2. Pruning at exactly max_deltas — nothing should be pruned.
# B3. Pruning at max_deltas + 1 — oldest delta pruned.
# B4. Private agent not visible via is_public.
# B5. Empty skills list produces a default skill.
"""

from sm_bridge import (
    DeltaStore,
    SmAgentFacts,
    SmBridge,
    SmCapabilities,
    SmEndpoints,
    SmProvider,
    SmSkill,
    SmWellKnown,
    SimpleAgent,
    SimpleAgentConverter,
)

from .conftest import (
    TEST_BASE_URL,
    TEST_PROVIDER_NAME,
    TEST_PROVIDER_URL,
    TEST_REGISTRY_ID,
)

# ── helpers ───────────────────────────────────────────────────────────


def _make_facts(agent_id: str = "test-agent") -> SmAgentFacts:
    """Build minimal SmAgentFacts for store tests."""
    return SmAgentFacts(
        id=f"did:web:example.com:agents:{agent_id}",
        handle=f"@test/{agent_id}",
        agent_name=f"Agent {agent_id}",
        label="test",
        description="A test agent",
        version="1.0.0",
        provider=SmProvider(name="Test", url="https://test.com"),
        endpoints=SmEndpoints(static=[]),
        capabilities=SmCapabilities(modalities=[]),
        skills=[],
    )


# =====================================================================
# Boundary tests
# =====================================================================


class TestDeltaStoreBoundary:
    """Boundary and edge-case tests for DeltaStore."""

    def test_delta_store_since_zero_returns_all(self, delta_store):
        """since=0 must return every delta in the store."""
        facts = _make_facts()
        delta_store.add("upsert", facts)
        delta_store.add("upsert", facts)
        delta_store.add("delete", facts)

        result = delta_store.since(0)
        assert len(result) == 3

    def test_delta_store_since_future_returns_empty(self, delta_store):
        """since=999999 on a small store returns an empty list."""
        facts = _make_facts()
        delta_store.add("upsert", facts)

        result = delta_store.since(999999)
        assert result == []

    def test_delta_store_pruning_at_exactly_max(self):
        """When exactly max_deltas items exist, none are pruned."""
        max_deltas = 3
        store = DeltaStore(max_deltas=max_deltas)
        facts = _make_facts()

        for _ in range(max_deltas):
            store.add("upsert", facts)

        assert len(store) == max_deltas

    def test_delta_store_pruning_at_max_plus_one(self):
        """Adding one more than max_deltas prunes the oldest."""
        max_deltas = 3
        store = DeltaStore(max_deltas=max_deltas)
        facts = _make_facts()

        for _ in range(max_deltas + 1):
            store.add("upsert", facts)

        assert len(store) == max_deltas
        # The first delta (seq=1) should have been pruned
        assert store.get(1) is None


# =====================================================================
# Failure / sad-path tests
# =====================================================================


class TestConverterFailures:
    """Failure and sad-path tests for SimpleAgentConverter."""

    def test_resolve_nonexistent_agent_returns_none(self, converter):
        """get_agent for an unregistered ID must return None."""
        assert converter.get_agent("does-not-exist") is None

    def test_simple_agent_converter_private_agent_excluded(self, converter):
        """is_public returns False for a private agent."""
        agent = SimpleAgent(
            id="private-agent",
            name="Private",
            description="Should not be public",
            public=False,
        )
        assert converter.is_public(agent) is False


class TestSkillVariants:
    """Tests for different skill input types."""

    def test_agent_facts_with_empty_skills(self, converter):
        """Agent with no skills gets a single default SmSkill."""
        agent = SimpleAgent(
            id="no-skills",
            name="No Skills Agent",
            description="Has no skills",
        )
        facts = converter.to_sm(agent)

        assert len(facts.skills) == 1
        assert facts.skills[0].id == f"urn:{TEST_REGISTRY_ID}:agent"

    def test_agent_facts_with_dict_skills(self, converter):
        """Skills passed as dicts with id/description are converted."""
        agent = SimpleAgent(
            id="dict-skills",
            name="Dict Skills Agent",
            description="Has dict skills",
            skills=[
                {"id": "skill-a", "description": "First skill"},
                {"id": "skill-b", "description": "Second skill"},
            ],
        )
        facts = converter.to_sm(agent)

        assert len(facts.skills) == 2
        assert [s.id for s in facts.skills] == ["skill-a", "skill-b"]

    def test_agent_facts_with_string_skills(self, converter):
        """Skills passed as plain strings are converted."""
        agent = SimpleAgent(
            id="str-skills",
            name="String Skills Agent",
            description="Has string skills",
            skills=["summarize", "translate"],
        )
        facts = converter.to_sm(agent)

        assert len(facts.skills) == 2
        assert [s.id for s in facts.skills] == ["summarize", "translate"]


class TestHandleFormat:
    """Tests for NANDA handle creation."""

    def test_nanda_agent_facts_create_handle_format(self):
        """Verify handle format is '@registry:namespace/id'."""
        handle = SmAgentFacts.create_handle(
            registry="my-registry",
            namespace="prod",
            agent_id="my-agent",
        )
        assert handle.startswith("@")
        assert ":" in handle
        assert "/" in handle
        assert handle == "@my-registry:prod/my-agent"


# =====================================================================
# Happy-path tests (existing, kept last per R1-R10 ordering)
# =====================================================================


class TestModels:
    """Test NANDA model definitions."""

    def test_create_agent_facts(self):
        """Test creating a basic SmAgentFacts instance."""
        facts = SmAgentFacts(
            id="did:web:example.com:agents:test",
            handle="@test/agent",
            agent_name="Test Agent",
            label="test",
            description="A test agent",
            version="1.0.0",
            provider=SmProvider(name="Test", url="https://test.com"),
            endpoints=SmEndpoints(static=["https://test.com/agent"]),
            capabilities=SmCapabilities(modalities=["text"]),
            skills=[SmSkill(id="test-skill", description="A test skill")],
        )

        assert facts.id == "did:web:example.com:agents:test"
        assert facts.handle == "@test/agent"
        assert facts.agent_name == "Test Agent"
        assert len(facts.skills) == 1

    def test_create_handle(self):
        """Test handle creation helper."""
        handle = SmAgentFacts.create_handle(
            registry="my-registry", namespace="prod", agent_id="my-agent"
        )
        assert handle == "@my-registry:prod/my-agent"

    def test_well_known(self):
        """Test well-known document creation."""
        doc = SmWellKnown(
            registry_id="test-registry",
            registry_did="did:web:test.com",
            namespaces=["did:web:test.com:*"],
            index_url="https://test.com/nanda/index",
            resolve_url="https://test.com/nanda/resolve",
            deltas_url="https://test.com/nanda/deltas",
            provider=SmProvider(name="Test", url="https://test.com"),
        )

        assert doc.registry_id == "test-registry"
        assert "agentfacts" in doc.capabilities


class TestDeltaStore:
    """Test delta store functionality."""

    def test_add_delta(self):
        """Test adding a delta."""
        store = DeltaStore()

        facts = _make_facts()
        delta = store.add("upsert", facts)

        assert delta.seq == 1
        assert delta.action == "upsert"
        assert delta.agent.id == facts.id

    def test_since(self):
        """Test getting deltas since a sequence number."""
        store = DeltaStore()

        facts = _make_facts()

        store.add("upsert", facts)
        store.add("upsert", facts)
        store.add("upsert", facts)

        deltas = store.since(1)
        assert len(deltas) == 2

        deltas = store.since(0)
        assert len(deltas) == 3

    def test_next_seq(self):
        """Test sequence number tracking."""
        store = DeltaStore()

        assert store.next_seq == 1

        facts = _make_facts()
        store.add("upsert", facts)
        assert store.next_seq == 2


class TestConverter:
    """Test agent converter."""

    def test_simple_agent_converter(self):
        """Test SimpleAgentConverter."""
        converter = SimpleAgentConverter(
            registry_id=TEST_REGISTRY_ID,
            provider_name=TEST_PROVIDER_NAME,
            provider_url=TEST_PROVIDER_URL,
            base_url=TEST_BASE_URL,
        )

        agent = SimpleAgent(
            id="my-agent",
            name="My Agent",
            description="A test agent",
            namespace="prod",
            labels=["chat", "assistant"],
        )

        converter.register(agent)

        facts = converter.to_sm(agent)

        assert "did:" in facts.id
        assert facts.handle == "@test-registry:prod/my-agent"
        assert facts.agent_name == "My Agent"
        assert facts.provider.name == TEST_PROVIDER_NAME
        assert "chat" in facts.capabilities.modalities

    def test_list_agents(self):
        """Test listing agents."""
        converter = SimpleAgentConverter(
            registry_id=TEST_REGISTRY_ID,
            provider_name="Test",
            provider_url="https://test.com",
        )

        converter.register(SimpleAgent(id="agent-1", name="Agent 1", description="First"))
        converter.register(SimpleAgent(id="agent-2", name="Agent 2", description="Second"))

        agents = list(converter.list_agents(limit=10, offset=0))
        assert len(agents) == 2


class TestSmBridge:
    """Test high-level SmBridge."""

    def test_bridge_creation(self):
        """Test creating a SmBridge."""
        bridge = SmBridge(
            registry_id=TEST_REGISTRY_ID,
            provider_name="Test",
            provider_url="https://test.com",
        )

        assert bridge.registry_id == TEST_REGISTRY_ID
        assert bridge.router is not None

    def test_register_agent(self):
        """Test registering an agent via bridge."""
        bridge = SmBridge(
            registry_id=TEST_REGISTRY_ID,
            provider_name="Test",
            provider_url="https://test.com",
        )

        facts = bridge.register_agent(
            SimpleAgent(
                id="my-agent",
                name="My Agent",
                description="Test",
            )
        )

        assert facts.handle == "@test-registry:default/my-agent"

        # Should have recorded a delta
        deltas = bridge.delta_store.since(0)
        assert len(deltas) == 1
        assert deltas[0].action == "upsert"

    def test_wellknown(self):
        """Test well-known document generation."""
        bridge = SmBridge(
            registry_id=TEST_REGISTRY_ID,
            provider_name="Test",
            provider_url="https://test.com",
            base_url=TEST_BASE_URL,
        )

        wellknown = bridge.wellknown

        assert wellknown.registry_id == TEST_REGISTRY_ID
        assert f"{TEST_BASE_URL}/nanda/index" == wellknown.index_url
