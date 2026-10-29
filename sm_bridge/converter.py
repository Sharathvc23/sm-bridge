"""
NANDA Agent Converter

Abstract interface for converting your registry's internal agent model
to NANDA AgentFacts format.

Implement the AgentConverter protocol to integrate with your registry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .models import (
    SmAdaptiveResolver,
    SmAgentFacts,
    SmAuthentication,
    SmCapabilities,
    SmCertification,
    SmEndpoints,
    SmEvaluations,
    SmProvider,
    SmSkill,
    SmTelemetry,
)
from .trust.base import ProofResult


@dataclass
class SimpleAgent:
    """Simple agent data structure for basic use cases.

    If your registry doesn't have a complex internal model, you can
    use SimpleAgent directly with the SimpleAgentConverter.

    For complex registries, implement the AgentConverter protocol
    with your own internal types.
    """

    # Required
    id: str  # Unique identifier (will be converted to DID)
    name: str
    description: str

    # Optional - basic
    namespace: str = "default"
    version: str = "1.0.0"
    labels: list[str] = field(default_factory=list)
    skills: list[dict[str, Any]] = field(default_factory=list)
    endpoints: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    public: bool = True

    # Optional - extended
    classification: str | None = None
    card_template: str | None = None
    dynamic_endpoints: list[str] = field(default_factory=list)

    # Optional - adaptive resolver
    adaptive_resolver_url: str | None = None
    adaptive_resolver_policies: list[str] = field(default_factory=list)

    # Optional - capabilities
    streaming: bool = False
    batch: bool = False
    auth_methods: list[str] = field(default_factory=lambda: ["did-auth"])
    required_scopes: list[str] | None = None

    # Optional - certification (production NANDA). None means the source made no
    # certification claim, and none is emitted — a default here would have this
    # bridge assert something on the source's behalf.
    certification_level: str | None = None
    certification_issuer: str | None = None
    attestations: list[str] = field(default_factory=list)

    # Optional - evaluations
    performance_score: float | None = None
    availability_90d: str | None = None
    audit_trail: str | None = None

    # Optional - telemetry
    telemetry_enabled: bool = False
    telemetry_retention: str | None = None
    telemetry_sampling: float | None = None


@runtime_checkable
class AgentConverter(Protocol):
    """Protocol for converting internal agents to NANDA format.

    Implement this protocol to integrate your registry with NANDA.

    Example:
        class MyRegistryConverter:
            def __init__(self, registry_id: str, provider_name: str, provider_url: str):
                self.registry_id = registry_id
                self.provider_name = provider_name
                self.provider_url = provider_url

            def to_sm(self, agent: MyInternalAgent) -> SmAgentFacts:
                return SmAgentFacts(
                    id=f"did:web:myregistry.com:agents:{agent.id}",
                    handle=f"@myregistry/{agent.id}",
                    agent_name=agent.display_name,
                    # ... etc
                )

            def list_agents(self, limit: int, offset: int) -> Iterator[MyInternalAgent]:
                return self.repository.list_all(limit, offset)

            def get_agent(self, agent_id: str) -> MyInternalAgent | None:
                return self.repository.get(agent_id)

            def is_public(self, agent: MyInternalAgent) -> bool:
                return agent.visibility == "public"
    """

    def to_sm(self, agent: Any) -> SmAgentFacts:
        """Convert an internal agent to NANDA AgentFacts format."""
        ...

    def list_agents(self, limit: int, offset: int) -> Iterator[Any]:
        """List agents from your registry."""
        ...

    def get_agent(self, agent_id: str) -> Any | None:
        """Get a specific agent by ID."""
        ...

    def is_public(self, agent: Any) -> bool:
        """Check if an agent should be publicly visible."""
        ...


class SimpleAgentConverter:
    """Basic converter for SimpleAgent instances.

    Use this if you don't have a complex internal agent model.

    Usage:
        converter = SimpleAgentConverter(
            registry_id="my-registry",
            provider_name="My Company",
            provider_url="https://example.com",
            base_url="https://registry.example.com"
        )

        agent = SimpleAgent(
            id="my-agent",
            name="My Agent",
            description="Does things"
        )

        sm_facts = converter.to_sm(agent)
    """

    def __init__(
        self,
        registry_id: str,
        provider_name: str,
        provider_url: str,
        base_url: str | None = None,
        did_method: str = "web",
    ):
        """Initialize the converter.

        Args:
            registry_id: Unique identifier for your registry
            provider_name: Human-readable provider name
            provider_url: Provider website URL
            base_url: Base URL for agent endpoints
            did_method: DID method to use (default: "web")
        """
        self.registry_id = registry_id
        self.provider_name = provider_name
        self.provider_url = provider_url
        self.base_url = base_url or provider_url
        self.did_method = did_method

        # In-memory agent storage for simple use cases
        self._agents: dict[str, SimpleAgent] = {}

    def register(self, agent: SimpleAgent) -> None:
        """Register an agent (simple in-memory storage)."""
        self._agents[agent.id] = agent

    def unregister(self, agent_id: str) -> None:
        """Unregister an agent."""
        self._agents.pop(agent_id, None)

    def to_sm(self, agent: SimpleAgent) -> SmAgentFacts:
        """Convert a SimpleAgent to NANDA AgentFacts format."""
        # What the source said, versus what this bridge supplied. A mandatory
        # frame fills fields the source does not have and drops fields it has no
        # slot for; unrecorded, both are indistinguishable from source claims.
        invented: list[str] = []
        defaulted: list[str] = []
        dropped: list[str] = []

        # Build DID. The source supplied a bare id; the DID is built by munging
        # the provider URL, so it is ours, not theirs.
        did = self._build_did(agent)
        invented.append("id")

        # Build handle
        handle = SmAgentFacts.create_handle(
            registry=self.registry_id, namespace=agent.namespace, agent_id=agent.id
        )

        # Build provider
        provider = SmProvider(
            name=self.provider_name,
            url=self.provider_url,
            did=f"did:{self.did_method}:{self.provider_url.replace('https://', '').replace('http://', '')}",
        )
        invented.append("provider.did")

        # Build endpoints
        static_urls = list(agent.endpoints.values()) if agent.endpoints else []
        if self.base_url and not static_urls:
            # The endpoint is the field corroboration compares. Synthesising one
            # and serving it unmarked lets two registries agree on an address no
            # source ever asserted.
            static_urls = [f"{self.base_url}/agents/{agent.id}"]
            invented.append("endpoints.static")
        dynamic_urls = list(agent.dynamic_endpoints)

        # Build adaptive resolver if configured
        adaptive_resolver = None
        if agent.adaptive_resolver_url:
            adaptive_resolver = SmAdaptiveResolver(
                url=agent.adaptive_resolver_url,
                policies=agent.adaptive_resolver_policies
                or ["capability_negotiation", "load_balancing"],
            )

        endpoints = SmEndpoints(
            static=static_urls,
            dynamic=dynamic_urls,
            adaptive_resolver=adaptive_resolver,
        )

        # Build extended endpoint metadata for x_<registry>
        endpoints_extended: list[dict[str, Any]] = []
        if agent.endpoints:
            for key, url in agent.endpoints.items():
                endpoints_extended.append(
                    {
                        "url": url,
                        "protocol": "https" if str(url).startswith("https") else "http",
                        "description": key.replace("_", " ").title(),
                        "key": key,
                    }
                )
        for idx, url in enumerate(dynamic_urls):
            endpoints_extended.append(
                {
                    "url": url,
                    "protocol": "https" if str(url).startswith("https") else "http",
                    "description": "Dynamic Endpoint",
                    "key": f"dynamic_{idx}",
                }
            )

        # Build authentication
        authentication = SmAuthentication(
            methods=agent.auth_methods,
            requiredScopes=agent.required_scopes,
        )

        # Build skill identifiers for capabilities.skills
        skill_ids: list[str] = []
        for skill_data in agent.skills:
            if isinstance(skill_data, dict):
                skill_ids.append(str(skill_data.get("id", skill_data.get("name", "unknown"))))
            elif isinstance(skill_data, str):
                skill_ids.append(skill_data)

        # Build capabilities (production NANDA format)
        capabilities = SmCapabilities(
            modalities=list(agent.labels),
            skills=skill_ids,
            authentication=authentication,
            streaming=agent.streaming,
            batch=agent.batch,
        )

        # Build detailed skills. `SmSkill` reads seven keys; anything else the
        # source sent has no slot in the frame and is recorded as dropped.
        _SKILL_KEYS = {
            "id",
            "name",
            "description",
            "inputModes",
            "outputModes",
            "supportedLanguages",
            "latencyBudgetMs",
            "maxTokens",
        }
        skills = []
        for idx, skill_data in enumerate(agent.skills):
            if isinstance(skill_data, dict):
                if "description" not in skill_data:
                    defaulted.append(f"skills[{idx}].description")
                if "id" not in skill_data and "name" not in skill_data:
                    defaulted.append(f"skills[{idx}].id")
                dropped.extend(
                    f"skills[{idx}].{k}" for k in sorted(set(skill_data) - _SKILL_KEYS)
                )
                skills.append(
                    SmSkill(
                        id=str(skill_data.get("id", skill_data.get("name", "unknown"))),
                        description=skill_data.get("description", ""),
                        inputModes=skill_data.get("inputModes", ["text"]),
                        outputModes=skill_data.get("outputModes", ["text"]),
                        supportedLanguages=skill_data.get("supportedLanguages"),
                        latencyBudgetMs=skill_data.get("latencyBudgetMs"),
                        maxTokens=skill_data.get("maxTokens"),
                    )
                )
            elif isinstance(skill_data, str):
                skills.append(SmSkill(id=skill_data, description=skill_data))

        # NANDA requires minItems:1, so a source with no skills cannot be
        # represented without one. The placeholder stays, but it is recorded in
        # `provenance.invented` below so a consumer can tell it apart from a
        # skill the source actually declared.
        if not skills:
            invented.append("skills")
            skills.append(
                SmSkill(
                    id=f"urn:{self.registry_id}:agent",
                    description=f"No skills declared by {self.provider_name}; placeholder for schema validity",
                )
            )

        # Build certification only if the source declared one. A default level
        # would emit a trust claim the source never made, indistinguishable in
        # the output from one it did.
        certification = None
        if agent.certification_level is not None:
            certification = SmCertification(
                level=agent.certification_level,
                issuer=agent.certification_issuer or self.provider_name,
                attestations=agent.attestations,
            )

        # Build evaluations if any metrics provided
        evaluations = None
        if agent.performance_score is not None or agent.availability_90d or agent.audit_trail:
            evaluations = SmEvaluations(
                performanceScore=agent.performance_score,
                availability90d=agent.availability_90d,
                auditTrail=agent.audit_trail,
            )

        # Build telemetry if enabled
        telemetry = None
        if agent.telemetry_enabled:
            telemetry = SmTelemetry(
                enabled=True,
                retention=agent.telemetry_retention,
                sampling=agent.telemetry_sampling,
            )

        # NANDA requires `label`. With no labels the namespace is repurposed as
        # one, which is a category claim the source did not make.
        if agent.labels:
            label = agent.labels[0]
        else:
            label = agent.namespace
            defaulted.append("label")

        # Build metadata with registry extensions
        metadata = {
            f"x_{self.registry_id.replace('-', '_')}": {
                "namespace": agent.namespace,
                "original_id": agent.id,
                "public": agent.public,
                "classification": agent.classification,
                "card_template": agent.card_template,
                "endpoints_extended": endpoints_extended,
                **agent.metadata,
                # After the spread on purpose: this is the bridge's statement
                # about its own output, and a source must not be able to hide it.
                "provenance": {
                    "invented": invented,
                    "defaulted": defaulted,
                    "dropped": dropped,
                },
            }
        }

        # `synthesized` was this bridge's own marker until 0.9.0 removed it in
        # favour of `provenance.invented`. Removing it is not enough: the source's
        # metadata is spread into the same block, so a source supplying its own
        # `synthesized` would land exactly where our marker used to be, and a
        # consumer still reading the 0.7.0 field would read a source-controlled
        # value believing it was ours. The field is therefore absent rather than
        # merely unwritten — a lagging reader gets nothing, which it can detect,
        # instead of a plausible claim it cannot.
        metadata[f"x_{self.registry_id.replace('-', '_')}"].pop("synthesized", None)

        proof = self._build_proof(agent)

        return SmAgentFacts(
            id=did,
            handle=handle,
            agent_name=agent.name,
            label=label,
            description=agent.description,
            version=agent.version,
            provider=provider,
            endpoints=endpoints,
            capabilities=capabilities,
            skills=skills,
            certification=certification,
            evaluations=evaluations,
            telemetry=telemetry,
            metadata=metadata,
            proof=proof,
        )

    def list_agents(self, limit: int = 100, offset: int = 0) -> Iterator[SimpleAgent]:
        """List registered agents."""
        agents = list(self._agents.values())
        yield from agents[offset : offset + limit]

    def get_agent(self, agent_id: str) -> SimpleAgent | None:
        """Get a specific agent by ID."""
        return self._agents.get(agent_id)

    def is_public(self, agent: SimpleAgent) -> bool:
        """Check if an agent is public."""
        return agent.public

    def _build_did(self, agent: SimpleAgent) -> str:
        """Build a DID for the agent."""
        domain = self.provider_url.replace("https://", "").replace("http://", "")
        return f"did:{self.did_method}:{domain}:agents:{agent.namespace}:{agent.id}"

    def _build_proof(self, agent: SimpleAgent) -> ProofResult:
        """The simple in-memory converter holds no cryptographic evidence for an agent, so it
        emits an explicit unverified proof rather than a fabricated one. A real source wires a
        TrustProfile (ed25519-agentcard, ans-scitt, …) via the resolve-time evidence hook."""
        return ProofResult.legacy()


class AbstractAgentConverter(ABC):  # pragma: no cover - interface helpers only
    """Abstract base class for custom converters.

    Extend this class if you prefer inheritance over the Protocol pattern.

    Example:
        class MyConverter(AbstractAgentConverter):
            def __init__(self, db_connection):
                super().__init__(
                    registry_id="my-registry",
                    provider_name="My Company",
                    provider_url="https://example.com"
                )
                self.db = db_connection

            def to_sm(self, agent: MyAgent) -> SmAgentFacts:
                # Custom conversion logic
                pass

            def list_agents(self, limit: int, offset: int) -> Iterator[MyAgent]:
                return self.db.query_agents(limit, offset)

            def get_agent(self, agent_id: str) -> MyAgent | None:
                return self.db.get_agent(agent_id)

            def is_public(self, agent: MyAgent) -> bool:
                return agent.status == "published"
    """

    def __init__(
        self,
        registry_id: str,
        provider_name: str,
        provider_url: str,
        base_url: str | None = None,
    ):
        self.registry_id = registry_id
        self.provider_name = provider_name
        self.provider_url = provider_url
        self.base_url = base_url or provider_url

    @abstractmethod
    def to_sm(self, agent: Any) -> SmAgentFacts:
        """Convert an internal agent to NANDA format."""
        pass

    @abstractmethod
    def list_agents(self, limit: int, offset: int) -> Iterator[Any]:
        """List agents from your registry."""
        pass

    @abstractmethod
    def get_agent(self, agent_id: str) -> Any | None:
        """Get a specific agent by ID."""
        pass

    @abstractmethod
    def is_public(self, agent: Any) -> bool:
        """Check if an agent should be publicly visible."""
        pass

    def build_provider(self) -> SmProvider:
        """Build the provider block."""
        return SmProvider(
            name=self.provider_name,
            url=self.provider_url,
        )

    def build_handle(self, namespace: str, agent_id: str) -> str:
        """Build a NANDA handle."""
        return SmAgentFacts.create_handle(
            registry=self.registry_id, namespace=namespace, agent_id=agent_id
        )
