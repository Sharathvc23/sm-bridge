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
from .onboarding import DelegationResolution, EntryModeConverter, RegistryEntry
from .store import DeltaStore
from .trust.base import TrustRegistry


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
    trust_registry: TrustRegistry | None = None,
    entries: list[EntryModeConverter] | None = None,
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
        total = sum(
            1 for a in converter.list_agents(limit=10_000, offset=0) if converter.is_public(a)
        )

        return SmAgentFactsIndexResponse(
            generated_at=datetime.now(timezone.utc),
            registry_id=registry_id,
            agents=agents,
            total_count=total,
        )

    @router.get("/resolve", response_model=SmAgentFacts)
    async def sm_resolve(
        agent: str = Query(..., description="Agent ID, DID, or handle"),
    ) -> SmAgentFacts:
        """Resolve a single agent by ID.

        Accepts:
        - Agent ID (e.g., "my-agent")
        - DID (e.g., "did:web:example.com:agents:my-agent")
        - Handle (e.g., "@myregistry/my-agent")

        When a `TrustRegistry` is injected and the converter can supply verification
        evidence for the agent (`trust_evidence(agent) -> (profile_id, evidence)`), the
        resolved facts carry a normalized `ProofResult`. Absent a registry or evidence, the
        proof block reflects whatever the converter produced (honest NOT_VERIFIED for an
        unverified source) — never a fabricated pass.
        """
        # Parse the agent identifier
        agent_id = _parse_agent_identifier(agent, registry_id, provider_url)
        if agent_id is None:
            raise HTTPException(
                status_code=400,
                detail="Agent identifier is not scoped to this registry",
            )

        # Look up the agent
        internal_agent = converter.get_agent(agent_id)

        if internal_agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")

        if not converter.is_public(internal_agent):
            raise HTTPException(status_code=403, detail="Agent is not public")

        facts = converter.to_sm(internal_agent)

        # Attach a normalized proof block when a trust profile can verify this agent.
        if trust_registry is not None:
            evidence_hook = getattr(converter, "trust_evidence", None)
            if callable(evidence_hook):
                supplied = evidence_hook(internal_agent)
                if supplied is not None:
                    profile_id, evidence = supplied
                    facts.proof = await trust_registry.verify(profile_id, facts, evidence)

        return facts

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

    # ----- entry-mode: the quilt of registries ------------------------------------
    # Registry-scale sources onboard as ONE RegistryEntry each; resolution is delegated
    # back to their own resolver, never mirrored here.
    _entry_by_name: dict[str, EntryModeConverter] = {}
    for _conv in entries or []:
        _entry_by_name[_conv.to_entry().registry_name] = _conv

    @router.get("/registries", response_model=list[RegistryEntry])
    def sm_registries() -> list[RegistryEntry]:
        """List the registry-scale sources stitched into this quilt (pointer entries)."""
        return [c.to_entry() for c in _entry_by_name.values()]

    @router.get("/registries/{name}", response_model=RegistryEntry)
    def sm_registry(name: str) -> RegistryEntry:
        """One registry entry (+ its proof, if any)."""
        conv = _entry_by_name.get(name)
        if conv is None:
            raise HTTPException(status_code=404, detail="Registry not found")
        return conv.to_entry()

    @router.get("/registries/{name}/resolve", response_model=DelegationResolution)
    def sm_registry_resolve(
        name: str, agent: str = Query(..., description="Agent identifier to resolve at the source")
    ) -> DelegationResolution:
        """Resolve an agent under an entry-mode registry: returns a delegation pointer to the
        source's resolver — this bridge never mirrors an entry-mode record."""
        conv = _entry_by_name.get(name)
        if conv is None:
            raise HTTPException(status_code=404, detail="Registry not found")
        return conv.delegate(agent)

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


def _did_authority(provider_url: str) -> str:
    """The host part of a provider URL, as it appears in a `did:web`."""
    authority = provider_url.split("://", 1)[-1]
    return authority.rstrip("/")


#: Scheme and NID of an ARD domain-anchored resource identifier (AIR URN), the form
#: the NANDA Index keys every entry on. Matched case-insensitively: RFC 8141 defines
#: both as case-insensitive, and the Index normalises them to lower case.
_AIR_URN_PREFIX = "urn:air:"


def _publisher_fqdn(provider_url: str) -> str:
    """This registry's publisher FQDN, as it appears in an AIR URN.

    An AIR URN's publisher segment is a bare FQDN — the Index validates it as one
    and the registrant proves control of it by DNS TXT challenge. So unlike
    `_did_authority`, which reproduces whatever a `did:web` carries, this drops any
    port and path from the provider URL and lower-cases the result: those cannot
    appear in the segment being compared, and leaving them in would fail to anchor
    an identifier that is in fact ours.
    """
    authority = provider_url.split("://", 1)[-1]
    return authority.split("/", 1)[0].split(":", 1)[0].lower()


def _parse_agent_identifier(value: str, registry_id: str, provider_url: str) -> str | None:
    """Reduce an identifier to a local agent id, or None if it is not ours.

    This registry answers about agents it holds, and attaches its own proof block
    to the answer. So an identifier that explicitly names a *different* registry
    must not be reduced to a bare id and looked up here — that answers for a
    subject we were not asked about, under our own attestation.

    Returns None when the identifier names another authority, when it names one
    we cannot recognise, or when it is empty. The caller MUST turn that into a
    400, never a 404: a 404 is a positive claim that the agent is absent, and a
    corroborator comparing registries would read it as this registry asserting
    something about another registry's namespace.

    Handled:
    - `agent`                                    -> `agent`
    - `@this-registry[:ns]/agent`                -> `agent`
    - `@agent`                                   -> `agent`   (names no scope)
    - `did:web:<our-host>:...:agent`             -> `agent`
    - `urn:air:<our-fqdn>:<ns...>:agent`         -> `agent`   (the Index's own form)
    - `@other-registry/agent`                    -> None
    - `did:web:other.example:...:agent`          -> None
    - `urn:air:other.example:<ns...>:agent`      -> None      (another publisher)
    - `urn:...`                                  -> None      (foreign by construction)

    Anything else is returned whole. A colon is NOT evidence of a namespace: the
    previous rule split on any colon and took the last segment, which could not
    distinguish a local id from another registry's URN or DID.
    """
    if not value:
        return None

    # Handle — the registry is named explicitly, so it can be checked.
    if value.startswith("@"):
        body = value[1:]
        if "/" in body:
            scope, _, agent = body.partition("/")
            if scope.split(":", 1)[0] != registry_id:
                return None
            return agent or None
        return body or None

    # DID — the authority is part of the identifier. Only our own did:web.
    if value.startswith("did:"):
        local_prefix = f"did:web:{_did_authority(provider_url)}:"
        if not value.startswith(local_prefix):
            return None
        return value[len(local_prefix) :].split(":")[-1] or None

    # AIR URN — an ARD domain-anchored resource identifier:
    #
    #     urn:air:<publisher-FQDN>:<namespace...>:<short-name>
    #
    # The NANDA Index keys every entry on one of these, and the publisher FQDN is
    # the ownership anchor: the registrant proves control of it by DNS TXT challenge
    # before the Index will issue an identifier under it. So an AIR URN naming our
    # own FQDN names US — exactly as a `did:web` under our host does — and refusing
    # it means refusing this registry's own canonical identifier.
    #
    # The Index's `resolve` returns the short-name alone, so a consumer that only
    # ever sees that output is unaffected. One holding the canonical identifier (the
    # key every index record carries) is not, and resolving it is this library's job
    # rather than each consumer's: a registry onboarded through the bridge should not
    # have to patch its own adapter when the Index changes how it names things.
    lowered = value.lower()
    if lowered.startswith(_AIR_URN_PREFIX):
        domain, _, path = value[len(_AIR_URN_PREFIX) :].partition(":")
        if domain.lower() != _publisher_fqdn(provider_url):
            return None
        # `<namespace...>:<short-name>` — at least one namespace segment and a name,
        # the same minimum the Index enforces. The namespace may have more than one
        # segment; the short name is the last.
        segments = path.split(":")
        if len(segments) < 2:
            return None
        return segments[-1] or None

    # Every other URN names an authority we are not.
    if lowered.startswith("urn:"):
        return None

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
        trust_registry: TrustRegistry | None = None,
        entries: list[EntryModeConverter] | None = None,
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

        # Trust registry (optional) — profile_id -> TrustProfile for normalized proofs.
        self.trust_registry = trust_registry

        # Entry-mode registries (optional) — one RegistryEntry per registry-scale source.
        self.entries = entries or []

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
            trust_registry=self.trust_registry,
            entries=self.entries,
        )

    async def admit_entries(self, *, require_verified: bool = False) -> list[RegistryEntry]:
        """Verify every entry-mode source at onboarding and stamp each entry's proof.

        Uses this bridge's ``trust_registry``. With ``require_verified=True`` a source that
        fails admission raises ``AdmissionError`` and does not join. Call once after wiring
        (or admit converters individually before constructing the bridge).
        """
        if self.trust_registry is None:
            return [c.to_entry() for c in self.entries]
        admitted: list[RegistryEntry] = []
        for conv in self.entries:
            admit = getattr(conv, "admit", None)
            if callable(admit):
                await admit(self.trust_registry, require_verified=require_verified)
            admitted.append(conv.to_entry())
        return admitted

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
