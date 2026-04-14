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

    # Optional - certification (production NANDA)
    certification_level: str = "self-declared"
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
        # Build DID
        did = self._build_did(agent)

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

        # Build endpoints
        static_urls = list(agent.endpoints.values()) if agent.endpoints else []
        if self.base_url and not static_urls:
            static_urls = [f"{self.base_url}/agents/{agent.id}"]
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

        # Build detailed skills
        skills = []
        for skill_data in agent.skills:
            if isinstance(skill_data, dict):
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

        # Default skill if none specified
        if not skills:
            skills.append(
                SmSkill(
                    id=f"urn:{self.registry_id}:agent", description=f"{self.provider_name} agent"
                )
            )

        # Build certification (production NANDA)
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
            }
        }

        proof = self._build_proof(agent)

        return SmAgentFacts(
            id=did,
            handle=handle,
            agent_name=agent.name,
            label=agent.labels[0] if agent.labels else agent.namespace,
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

    def _build_proof(self, agent: SimpleAgent) -> dict[str, Any]:
        """Create a lightweight, non-secret proof placeholder."""
        import hashlib

        payload = f"{agent.id}:{agent.namespace}:{agent.version}:{self.registry_id}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return {
            "method": "sha256",
            "digest": digest,
            "registry_id": self.registry_id,
        }


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
