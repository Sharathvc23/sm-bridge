"""
SM Bridge - A Python library for building NANDA-compatible agent registries.

NANDA (Network of AI Agents in Decentralized Architecture) is MIT Media Lab's
protocol for federated AI agent discovery and communication.

This library provides:
- Pydantic models matching the NANDA AgentFacts schema (list39.org compatible)
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

See https://github.com/projnanda for the official NANDA specification.
"""

from .converter import AbstractAgentConverter, AgentConverter, SimpleAgent, SimpleAgentConverter
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
from .router import SmBridge, create_sm_router
from .store import DeltaStore, PersistentDeltaStore

__version__ = "0.3.0"
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
]
