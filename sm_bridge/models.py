"""
NANDA AgentFacts Models

Pydantic models implementing the NANDA AgentFacts specification.
See: https://github.com/projnanda/agentfacts-format


"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SmProvider(BaseModel):
    """NANDA provider object identifying the organization running the agent.

    Required fields per NANDA spec: name, url
    Optional: did (decentralized identifier for the provider)
    """

    name: str = Field(..., description="Human-readable provider name")
    url: str = Field(..., description="Provider's website URL")
    did: str | None = Field(None, description="Provider's DID (e.g., did:web:example.com)")


class SmAdaptiveResolver(BaseModel):
    """NANDA adaptive resolver for dynamic endpoint resolution.

    Supports capability negotiation, load balancing, and geo-routing.
    """

    url: str = Field(..., description="Resolver endpoint URL")
    policies: list[str] = Field(
        default_factory=list,
        description="Resolution policies (e.g., 'capability_negotiation', 'load_balancing', 'geo')",
    )


class SmEndpoints(BaseModel):
    """NANDA endpoints object specifying how to reach the agent.

    Supports static endpoints, dynamic/rotating endpoints, and adaptive resolution.
    """

    static: list[str] = Field(default_factory=list, description="Static endpoint URLs")
    dynamic: list[str] = Field(default_factory=list, description="Dynamic/load-balanced URLs")
    adaptive_resolver: SmAdaptiveResolver | None = Field(
        None, description="Adaptive resolver for dynamic capability-based routing"
    )


class SmAuthentication(BaseModel):
    """NANDA authentication object specifying supported auth methods.

    Common methods: "did-auth", "oauth2", "api-key", "jwt", "none"
    """

    methods: list[str] = Field(
        default_factory=lambda: ["did-auth"], description="Supported authentication methods"
    )
    requiredScopes: list[str] | None = Field(
        None, description="Required OAuth scopes if using oauth2"
    )


class SmCapabilities(BaseModel):
    """NANDA capabilities object describing what the agent can do.

    Modalities are high-level capability categories (e.g., "text", "image", "audio").
    Skills are simple string identifiers for specific capabilities.
    Authentication specifies how clients should authenticate.
    """

    modalities: list[str] = Field(default_factory=list, description="Capability modalities")
    skills: list[str] = Field(default_factory=list, description="Skill identifiers")
    authentication: SmAuthentication = Field(
        default_factory=lambda: SmAuthentication(), description="Authentication requirements"
    )
    streaming: bool = Field(default=False, description="Supports streaming responses")
    batch: bool = Field(default=False, description="Supports batch processing")


class SmSkill(BaseModel):
    """NANDA skill object describing a specific agent capability.

    Skills are more granular than modalities - they describe specific
    functions the agent can perform with detailed metadata.

    Required fields: id, description
    """

    id: str = Field(..., description="Unique skill identifier (e.g., 'urn:nanda:cap:summarize:v1')")
    description: str = Field(..., description="Human-readable skill description")
    inputModes: list[str] = Field(
        default_factory=lambda: ["text"], description="Accepted input types"
    )
    outputModes: list[str] = Field(
        default_factory=lambda: ["text"], description="Produced output types"
    )

    # Optional extended fields
    version: str | None = Field(None, description="Skill version")
    parameters: dict[str, Any] | None = Field(None, description="Skill parameters schema")
    supportedLanguages: list[str] | None = Field(None, description="Supported languages")
    latencyBudgetMs: int | None = Field(None, description="Expected latency in milliseconds")
    maxTokens: int | None = Field(None, description="Maximum token limit")


class SmCertification(BaseModel):
    """NANDA certification block for trust verification.

    Levels: "self-declared", "verified", "audited"

    """

    level: str = Field(
        ..., description="Certification level: 'self-declared', 'verified', 'audited'"
    )
    issuer: str | None = Field(None, description="Certification issuer (e.g., 'NANDA')")
    attestations: list[str] = Field(
        default_factory=list,
        description="Attestation claims (e.g., 'privacy_compliant', 'security_audited')",
    )
    issuanceDate: datetime | None = Field(None, description="When certification was issued")
    expirationDate: datetime | None = Field(None, description="When certification expires")


class SmEvaluations(BaseModel):
    """NANDA evaluations block for performance metrics.

    Contains audit trails and third-party verification records.
    """

    performanceScore: float | None = Field(None, description="Performance score (e.g., 4.8)")
    availability90d: str | None = Field(None, description="90-day availability (e.g., '99.95%')")
    lastAudited: datetime | None = Field(None, description="Last audit timestamp")
    auditTrail: str | None = Field(None, description="Audit trail reference (e.g., IPFS hash)")
    auditorID: str | None = Field(None, description="Auditor identifier")


class SmTelemetry(BaseModel):
    """NANDA telemetry block for observability configuration.

    Defines monitoring and metrics collection settings.
    """

    enabled: bool = Field(default=False, description="Telemetry enabled")
    retention: str | None = Field(None, description="Data retention period (e.g., '30d')")
    sampling: float | None = Field(None, description="Sampling rate (e.g., 0.1 for 10%)")
    metrics: dict[str, Any] | None = Field(
        None,
        description="Real-time metrics (latency_p95_ms, throughput_rps, error_rate, availability)",
    )


class SmAgentFacts(BaseModel):
    """NANDA-compliant AgentFacts schema.

    This is the core data structure for agent metadata in the NANDA ecosystem.
    Implements the projnanda/agentfacts-format specification as deployed
    on list39.org and join39.org.

    Required fields: id, agent_name, description, version, provider,
                     endpoints, capabilities

    The metadata field can contain registry-specific extensions using
    the x_<registry_name> convention (e.g., x_my_registry, x_acme).
    """

    # Identity
    id: str = Field(..., description="Agent's unique identifier (UUID or DID)")
    handle: str | None = Field(
        None, description="NANDA handle (e.g., '@registry:namespace/agent-name')"
    )

    # Basic info
    agent_name: str = Field(..., description="Human-readable agent name")
    label: str | None = Field(None, description="Short label/category")
    description: str = Field(..., description="Agent description")
    version: str = Field(..., description="Agent version (semver recommended)")

    # Provider
    provider: SmProvider = Field(..., description="Provider information")

    # Connectivity
    endpoints: SmEndpoints = Field(..., description="Agent endpoints")

    # Capabilities
    capabilities: SmCapabilities = Field(..., description="Agent capabilities")
    skills: list[SmSkill] = Field(default_factory=list, description="Detailed skill definitions")

    # Trust & Verification (production NANDA fields)
    certification: SmCertification | None = Field(None, description="Trust certification")
    evaluations: SmEvaluations | None = Field(None, description="Performance evaluations")
    telemetry: SmTelemetry | None = Field(None, description="Observability configuration")

    # Extensions
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Registry-specific extensions (use x_<registry> prefix)"
    )

    # Optional proof / attestation
    proof: dict[str, Any] | None = Field(
        None, description="Optional attestation payload (e.g., hash/signature metadata)"
    )

    @classmethod
    def create_handle(cls, registry: str, namespace: str, agent_id: str) -> str:
        """Create a NANDA handle from components.

        Args:
            registry: Registry identifier (e.g., "my-registry")
            namespace: Agent namespace (e.g., "agents")
            agent_id: Agent identifier (e.g., "summarizer")

        Returns:
            NANDA handle (e.g., "@my-registry:agents/summarizer")
        """
        return f"@{registry}:{namespace}/{agent_id}"


class SmAgentFactsIndexResponse(BaseModel):
    """Response model for NANDA index endpoint.

    Returns a list of all public agents in the registry.
    """

    generated_at: datetime = Field(..., description="Timestamp when index was generated")
    registry_id: str = Field(..., description="Registry identifier")
    agents: list[SmAgentFacts] = Field(..., description="List of agents")

    # Optional signature for registry attestation
    signature: dict[str, Any] | None = Field(None, description="Registry signature")

    # Pagination
    total_count: int | None = Field(None, description="Total number of agents")
    next_cursor: str | None = Field(None, description="Cursor for next page")


class SmAgentFactsDelta(BaseModel):
    """Single delta entry representing an agent change.

    Used for incremental sync between registries.
    """

    seq: int = Field(..., description="Sequence number (monotonically increasing)")
    action: str = Field(..., description="Action type: 'upsert', 'delete', 'revoke'")
    recorded_at: datetime = Field(..., description="When the change was recorded")
    agent: SmAgentFacts = Field(..., description="Agent data (for upsert)")

    # Optional signature for delta attestation
    signature: dict[str, Any] | None = Field(None, description="Delta signature")


class SmAgentFactsDeltaResponse(BaseModel):
    """Response model for NANDA deltas endpoint.

    Returns changes since a given sequence number for incremental sync.
    """

    registry_id: str = Field(..., description="Registry identifier")
    generated_at: datetime = Field(..., description="Response timestamp")
    deltas: list[SmAgentFactsDelta] = Field(..., description="List of changes")
    next_seq: int = Field(..., description="Next sequence number to query")


class SmWellKnown(BaseModel):
    """NANDA registry discovery document.

    Served at /.well-known/nanda.json for registry discovery.
    """

    registry_id: str = Field(..., description="Unique registry identifier")
    registry_did: str = Field(..., description="Registry's DID")
    namespaces: list[str] = Field(..., description="DID namespaces this registry manages")

    # Endpoint URLs
    index_url: str = Field(..., description="URL for /nanda/index endpoint")
    resolve_url: str = Field(..., description="URL for /nanda/resolve endpoint")
    deltas_url: str = Field(..., description="URL for /nanda/deltas endpoint")

    # Optional endpoints
    tools_url: str | None = Field(None, description="URL for /nanda/tools endpoint")
    a2a_send_url: str | None = Field(None, description="URL for A2A messaging")

    # Provider info
    provider: SmProvider = Field(..., description="Registry provider")

    # Capabilities
    capabilities: list[str] = Field(
        default_factory=lambda: ["agentfacts", "deltas"], description="Supported NANDA capabilities"
    )

    # Federation
    peers: list[str] | None = Field(None, description="Peer registry URLs for Quilt federation")


class SmTool(BaseModel):
    """NANDA MCP tool descriptor.

    Describes a tool that agents in this registry can use.
    """

    tool_id: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Tool description")
    endpoint: str = Field(..., description="Tool endpoint URL")
    params: list[str] = Field(default_factory=list, description="Parameter names")
    version: str = Field(default="v1", description="Tool version")


class SmToolsResponse(BaseModel):
    """Response model for NANDA tools endpoint."""

    registry_id: str = Field(..., description="Registry identifier")
    tools: list[SmTool] = Field(..., description="Available tools")


class SmA2AMessage(BaseModel):
    """NANDA A2A (Agent-to-Agent) message envelope.

    Used for direct messaging between agents.
    """

    message_id: str = Field(..., description="Unique message identifier")
    sender: str = Field(..., description="Sender agent DID or handle")
    recipient: str = Field(..., description="Recipient agent DID or handle")
    content: str = Field(..., description="Message content")
    content_type: str = Field(default="text/plain", description="Content MIME type")
    timestamp: datetime = Field(..., description="Message timestamp")

    # Optional signature for authenticity
    signature: dict[str, Any] | None = Field(None, description="Sender's signature")

    # Optional reply reference
    in_reply_to: str | None = Field(None, description="Message ID this is replying to")
