"""
SM Bridge - A Python library for building NANDA-compatible agent registries.

NANDA (Network of AI Agents in Decentralized Architecture) is MIT Media Lab's
protocol for federated AI agent discovery and communication.

This library provides:
- Pydantic models matching the NANDA AgentFacts schema
- FastAPI router with standard NANDA endpoints
- Simple delta store for change tracking
- Abstract interfaces for custom registry integration

Usage:
    from sm_bridge import SmBridge, SmAgentFacts

    bridge = SmBridge(
        registry_id="my-registry",
        provider_name="My Company",
        provider_url="https://example.com"
    )

    app = FastAPI()
    app.include_router(bridge.router)
    app.include_router(bridge.wellknown_router)

See https://github.com/projnanda for the official NANDA specification.
"""

from .converter import AbstractAgentConverter, AgentConverter, SimpleAgent, SimpleAgentConverter
from .federation import FederationPoller, PullResult, pull_deltas
from .gateway import (
    A2AAgentCard,
    CatalogDocument,
    CatalogEntry,
    create_gateway_router,
    current_facts,
    default_slug,
)
from .models import (
    SmA2AMessage,
    SmAdaptiveResolver,
    SmAgentFacts,
    SmAgentFactsDelta,
    SmAgentFactsDeltaResponse,
    SmAgentFactsIndexResponse,
    SmAuthentication,
    SmCapabilities,
    SmCertification,
    SmEndpoints,
    SmEvaluations,
    SmProvider,
    SmSkill,
    SmTelemetry,
    SmTool,
    SmToolsResponse,
    SmWellKnown,
)
from .onboarding import (
    AdmissionError,
    ANSEntryConverter,
    DelegationResolution,
    EntryModeConverter,
    RegistryEntry,
    normalize_reliability_receipts,
)
from .router import SmBridge, create_sm_router
from .store import DeltaStore, PersistentDeltaStore
from .switchboard import Switchboard, SwitchboardResult
from .trust import ProofResult, ProofStatus, TrustProfile, TrustRegistry

# Trust-profile ADAPTERS live in sm_bridge.trust.<name> and require the [trust] extra —
# import them from their submodules (e.g. from sm_bridge.trust.ans_scitt import AnsScittProfile)
# so a core-only install never imports cryptography/cbor2/dnspython.

__version__ = "0.4.1"
__all__ = [
    # Core Models
    "SmAgentFacts",
    "SmProvider",
    "SmEndpoints",
    "SmAdaptiveResolver",
    "SmAuthentication",
    "SmCapabilities",
    "SmSkill",
    # Trust & Verification Models
    "SmCertification",
    "SmEvaluations",
    "SmTelemetry",
    # Response Models
    "SmAgentFactsIndexResponse",
    "SmAgentFactsDelta",
    "SmAgentFactsDeltaResponse",
    "SmWellKnown",
    # Tool Models
    "SmTool",
    "SmToolsResponse",
    # Messaging
    "SmA2AMessage",
    # Store
    "DeltaStore",
    "PersistentDeltaStore",
    # Converter
    "AbstractAgentConverter",
    "AgentConverter",
    "SimpleAgent",
    "SimpleAgentConverter",
    # Router
    "create_sm_router",
    "SmBridge",
    # AI Catalog gateway
    "create_gateway_router",
    "current_facts",
    "default_slug",
    "CatalogEntry",
    "CatalogDocument",
    "A2AAgentCard",
    # Federation sync client
    "pull_deltas",
    "PullResult",
    "FederationPoller",
    # Trust spine (v0.4) — normalized proof block + verifier plugin seam
    "ProofResult",
    "ProofStatus",
    "TrustProfile",
    "TrustRegistry",
    # Onboarding (v0.4) — entry mode (quilt-safe) vs hosting mode
    "RegistryEntry",
    "EntryModeConverter",
    "ANSEntryConverter",
    "AdmissionError",
    "DelegationResolution",
    "normalize_reliability_receipts",
    # Switchboard (v0.4) — cross-registry resolve, uniform response
    "Switchboard",
    "SwitchboardResult",
]
