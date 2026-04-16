"""
NANDA Bridge Router

FastAPI router implementing standard NANDA endpoints.

Provides:
- /nanda/index - List all public agents
- /nanda/resolve - Resolve a single agent
- /nanda/deltas - Get change feed for sync
- /nanda/tools - List available MCP tools
- /.well-known/nanda.json - Registry discovery
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from .converter import AgentConverter, SimpleAgentConverter
from .models import (
    SmAgentFacts,
    SmAgentFactsDeltaResponse,
    SmAgentFactsIndexResponse,
    SmProvider,
    SmTool,
    SmToolsResponse,
    SmWellKnown,
)
from .store import DeltaStore


def create_sm_router(
    converter: AgentConverter,
    delta_store: DeltaStore,
    registry_id: str,
    base_url: str,
    provider_name: str,
    provider_url: str,
    tools: list[SmTool] | None = None,
    namespaces: list[str] | None = None,
    prefix: str = "/nanda",
) -> tuple[APIRouter, APIRouter]:
    """Create FastAPI routers with NANDA endpoints.

    Args:
        converter: Agent converter implementing the AgentConverter protocol
        delta_store: Delta store for tracking changes
        registry_id: Unique registry identifier
        base_url: Base URL where this registry is hosted
        provider_name: Human-readable provider name
        provider_url: Provider website URL
        tools: Optional list of MCP tools to advertise
        namespaces: DID namespaces this registry manages
        prefix: URL prefix for endpoints (default: "/nanda")

    Returns:
        Tuple of (nanda_router, wellknown_router). The wellknown_router
        must be mounted without a prefix so /.well-known/nanda.json is
        served at the domain root per RFC 8615.

    Usage:
        from fastapi import FastAPI
        from sm_bridge import create_sm_router, SimpleAgentConverter, DeltaStore

        converter = SimpleAgentConverter(
            registry_id="my-registry",
            provider_name="My Company",
            provider_url="https://example.com"
        )
        delta_store = DeltaStore()

        nanda_router, wellknown_router = create_sm_router(
            converter=converter,
            delta_store=delta_store,
            registry_id="my-registry",
            base_url="https://registry.example.com",
            provider_name="My Company",
            provider_url="https://example.com"
        )

        app = FastAPI()
        app.include_router(nanda_router)
        app.include_router(wellknown_router)
    """
    router = APIRouter(prefix=prefix, tags=["nanda"])
    wellknown_router = APIRouter(tags=["nanda-discovery"])

    tools = tools or []
    namespaces = namespaces or [f"did:web:{provider_url.replace('https://', '')}:*"]

    @router.get("/index", response_model=SmAgentFactsIndexResponse)
    def sm_index(
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> SmAgentFactsIndexResponse:
        """List all public agents in NANDA AgentFacts format.

        This endpoint returns all publicly visible agents in the registry,
        formatted according to the NANDA AgentFacts specification.
        """
        agents: list[SmAgentFacts] = []

        for agent in converter.list_agents(limit=limit, offset=offset):
            if converter.is_public(agent):
                agents.append(converter.to_sm(agent))

        # total_count must reflect all public agents, not just this page
        total = sum(1 for a in converter.list_agents(limit=10_000, offset=0) if converter.is_public(a))

        return SmAgentFactsIndexResponse(
            generated_at=datetime.now(timezone.utc),
            registry_id=registry_id,
            agents=agents,
            total_count=total,
        )

    @router.get("/resolve", response_model=SmAgentFacts)
    def sm_resolve(
        agent: str = Query(..., description="Agent ID, DID, or handle"),
    ) -> SmAgentFacts:
        """Resolve a single agent by ID.

        Accepts:
        - Agent ID (e.g., "my-agent")
        - DID (e.g., "did:web:example.com:agents:my-agent")
        - Handle (e.g., "@myregistry/my-agent")
        """
        # Parse the agent identifier
        agent_id = _parse_agent_identifier(agent, registry_id)

        # Look up the agent
        internal_agent = converter.get_agent(agent_id)

        if internal_agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")

        if not converter.is_public(internal_agent):
            raise HTTPException(status_code=403, detail="Agent is not public")

        return converter.to_sm(internal_agent)

    @router.get("/deltas", response_model=SmAgentFactsDeltaResponse)
    def sm_deltas(
        since: int = Query(0, ge=0, description="Sequence number to start from"),
    ) -> SmAgentFactsDeltaResponse:
        """Get agent changes since a sequence number.

        Used for incremental sync between registries.
        Poll this endpoint with the next_seq value to get new changes.
        """
        deltas = delta_store.since(since)

        return SmAgentFactsDeltaResponse(
            registry_id=registry_id,
            generated_at=datetime.now(timezone.utc),
            deltas=deltas,
            next_seq=delta_store.next_seq,
        )

    @router.get("/tools", response_model=SmToolsResponse)
    def sm_tools_endpoint() -> SmToolsResponse:
        """List available MCP tools.

        Returns tools that agents in this registry can use.
        """
        return SmToolsResponse(
            registry_id=registry_id,
            tools=tools,
        )

    # Well-known endpoint — mounted on a separate unprefixed router
    # so it serves at /.well-known/nanda.json per RFC 8615.
    @wellknown_router.get("/.well-known/nanda.json", response_model=SmWellKnown)
    def sm_wellknown() -> SmWellKnown:
        """NANDA registry discovery document.

        Other registries use this to discover and federate with this registry.
        """
        return SmWellKnown(
            registry_id=registry_id,
            registry_did=f"did:web:{base_url.replace('https://', '').replace('http://', '')}",
            namespaces=namespaces,
            index_url=f"{base_url}{prefix}/index",
            resolve_url=f"{base_url}{prefix}/resolve",
            deltas_url=f"{base_url}{prefix}/deltas",
            tools_url=f"{base_url}{prefix}/tools" if tools else None,
            provider=SmProvider(
                name=provider_name,
                url=provider_url,
            ),
            capabilities=["agentfacts", "deltas"] + (["mcp-tools"] if tools else []),
        )

    return router, wellknown_router


def _parse_agent_identifier(value: str, registry_id: str) -> str:
    """Parse various agent identifier formats to a simple ID.

    Handles:
    - Simple ID: "my-agent" -> "my-agent"
    - DID: "did:web:example.com:agents:my-agent" -> "my-agent"
    - Handle: "@myregistry/my-agent" -> "my-agent"
    - Namespaced: "namespace:my-agent" -> "my-agent"
    """
    # Handle format: @registry/agent or @registry:namespace/agent
    if value.startswith("@"):
        # @registry/agent
        if "/" in value:
            return value.split("/")[-1]
        return value[1:]  # Remove @ prefix

    # DID format: did:method:...
    if value.startswith("did:"):
        parts = value.split(":")
        # Last part is typically the agent ID
        return parts[-1]

    # Namespaced format: namespace:agent
    if ":" in value and not value.startswith("did:"):
        return value.split(":")[-1]

    # Simple ID
    return value


class SmBridge:
    """High-level NANDA bridge for easy integration.

    Combines converter, delta store, and router into a single object.

    Usage:
        from fastapi import FastAPI
        from sm_bridge import SmBridge

        bridge = SmBridge(
            registry_id="my-registry",
            provider_name="My Company",
            provider_url="https://example.com",
            base_url="https://registry.example.com"
        )

        # Register agents
        bridge.register_agent(SimpleAgent(
            id="my-agent",
            name="My Agent",
            description="Does things"
        ))

        # Mount both routers
        app = FastAPI()
        app.include_router(bridge.router)             # /nanda/* endpoints
        app.include_router(bridge.wellknown_router)    # /.well-known/nanda.json
    """

    def __init__(
        self,
        registry_id: str,
        provider_name: str,
        provider_url: str,
        base_url: str | None = None,
        converter: AgentConverter | None = None,
        delta_store: DeltaStore | None = None,
        tools: list[SmTool] | None = None,
        namespaces: list[str] | None = None,
    ):
        """Initialize the NANDA bridge.

        Args:
            registry_id: Unique registry identifier
            provider_name: Human-readable provider name
            provider_url: Provider website URL
            base_url: Base URL where registry is hosted (defaults to provider_url)
            converter: Custom converter (defaults to SimpleAgentConverter)
            delta_store: Custom delta store (defaults to in-memory DeltaStore)
            tools: MCP tools to advertise
            namespaces: DID namespaces managed by this registry
        """
        self.registry_id = registry_id
        self.provider_name = provider_name
        self.provider_url = provider_url
        self.base_url = base_url or provider_url

        # Create or use provided converter
        if converter is not None:
            self.converter = converter
        else:
            self.converter = SimpleAgentConverter(
                registry_id=registry_id,
                provider_name=provider_name,
                provider_url=provider_url,
                base_url=self.base_url,
            )

        # Create or use provided delta store (do not truthiness-check because DeltaStore is falsy when empty)
        self.delta_store = delta_store if delta_store is not None else DeltaStore()

        # Store tools
        self.tools = tools or []

        # Create routers — main NANDA router + separate well-known router
        self.router, self.wellknown_router = create_sm_router(
            converter=self.converter,
            delta_store=self.delta_store,
            registry_id=registry_id,
            base_url=self.base_url,
            provider_name=provider_name,
            provider_url=provider_url,
            tools=self.tools,
            namespaces=namespaces,
        )

    def register_agent(self, agent: Any) -> SmAgentFacts:
        """Register an agent and record a delta.

        Args:
            agent: Agent to register (SimpleAgent or your custom type)

        Returns:
            SM AgentFacts for the registered agent
        """
        # If using SimpleAgentConverter, register directly
        if isinstance(self.converter, SimpleAgentConverter):
            self.converter.register(agent)

        # Convert to NANDA format
        sm_facts = self.converter.to_sm(agent)

        # Record delta
        if self.converter.is_public(agent):
            self.delta_store.add("upsert", sm_facts)

        return sm_facts

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent and record a delete delta.

        Args:
            agent_id: ID of agent to unregister
        """
        # Get agent before deletion for delta
        agent = self.converter.get_agent(agent_id)

        if agent is not None:
            sm_facts = self.converter.to_sm(agent)

            # If using SimpleAgentConverter, unregister directly
            if isinstance(self.converter, SimpleAgentConverter):
                self.converter.unregister(agent_id)

            # Record delete delta
            if self.converter.is_public(agent):
                self.delta_store.add("delete", sm_facts)

    def add_tool(self, tool: SmTool) -> None:
        """Add an MCP tool to advertise."""
        self.tools.append(tool)

    @property
    def wellknown(self) -> SmWellKnown:
        """Get the well-known discovery document."""
        return SmWellKnown(
            registry_id=self.registry_id,
            registry_did=f"did:web:{self.base_url.replace('https://', '').replace('http://', '')}",
            namespaces=[f"did:web:{self.provider_url.replace('https://', '')}:*"],
            index_url=f"{self.base_url}/nanda/index",
            resolve_url=f"{self.base_url}/nanda/resolve",
            deltas_url=f"{self.base_url}/nanda/deltas",
            tools_url=f"{self.base_url}/nanda/tools" if self.tools else None,
            provider=SmProvider(
                name=self.provider_name,
                url=self.provider_url,
            ),
            capabilities=["agentfacts", "deltas"] + (["mcp-tools"] if self.tools else []),
        )
