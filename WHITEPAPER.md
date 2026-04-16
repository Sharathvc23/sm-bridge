# SM Bridge: Reference Implementation for Agent Registry Endpoints

**Authors:** StellarMinds ([stellarminds.ai](https://stellarminds.ai))
**Date:** April 2026
**Version:** 0.3.0

## Abstract

`sm-bridge` is a Python library that provides a complete server-side implementation for NANDA-compatible agent registry endpoints. It solves the adoption barrier facing new registry operators by packaging 16 Pydantic models, 5 HTTP endpoints, a thread-safe delta store, and a protocol-based converter into a single drop-in library. The library supports three levels of adoption complexity, from a one-line facade to full custom converter implementations. The implementation depends only on FastAPI and Pydantic as its runtime dependencies.

## Problem

Federated AI agent discovery requires that participating registries expose standardized HTTP APIs. Implementing these endpoints from scratch requires understanding the AgentFacts schema, the Quilt delta-sync protocol, DID-based identity, and registry discovery conventions — a significant adoption barrier for new registry operators. Building these for each registry creates duplicated effort and risks schema divergence across implementations. The NANDA ecosystem needs a reference implementation that lowers the barrier for new registries while ensuring schema compliance through runtime validation, and supports progressive adoption from simple demos to production deployments.

## What It Does

- Provides 16 Pydantic models implementing the full NANDA AgentFacts specification covering identity, capabilities, trust, telemetry, and messaging
- Exposes 5 standard endpoints: `/nanda/index`, `/nanda/resolve`, `/nanda/deltas`, `/nanda/tools`, `/.well-known/nanda.json`
- Tracks changes via a thread-safe delta store with monotonic sequencing and configurable retention pruning (default 10,000 deltas)
- Defines an `AgentConverter` protocol (`@runtime_checkable`) for integration with arbitrary internal registry data models without inheritance
- Constructs three identity formats: `did:web:` DIDs, `@registry:namespace/agent` handles, and SHA-256 proof digests
- Supports 3-tier adoption: drop-in via `SmBridge` facade, protocol-based via `AgentConverter`, inheritance-based via `AbstractAgentConverter`
- Parses agent identifiers in any format (DID, handle, namespaced, plain) for the resolve endpoint with priority-ordered format detection
- Advertises MCP tools via `/nanda/tools` and supports A2A message envelopes for inter-agent communication

## Architecture

```
┌─────────────────────────────────────────────────┐
│            SmBridge (router.py)                  │  High-level facade
├─────────────────────────────────────────────────┤
│       FastAPI Router (router.py)                 │  5 NANDA endpoints
├──────────────────┬──────────────────────────────┤
│ DeltaStore        │  AgentConverter              │  Change tracking / Integration
│ (store.py)        │  (converter.py)              │
├──────────────────┴──────────────────────────────┤
│         Pydantic Models (models.py)              │  16 NANDA types
└─────────────────────────────────────────────────┘
```

Each module has a single responsibility: models define the schema, the converter translates internal types to NANDA types, the store tracks changes with monotonic sequence numbers, and the router exposes HTTP endpoints with pagination and multi-format identifier parsing.

The 16 models are organized into five groups:

| Group | Models | Purpose |
|-------|--------|---------|
| Core | AgentFacts, Provider, Endpoints, Capabilities, Skill, etc. | Agent identity, connectivity, capabilities |
| Trust | Certification, Evaluations, Telemetry | Trust verification, performance metrics |
| Response | IndexResponse, Delta, DeltaResponse | API response envelopes |
| Discovery | WellKnown | Registry discovery document |
| Interop | Tool, ToolsResponse, A2AMessage | MCP tools, agent-to-agent messaging |

The five endpoints serve distinct federation roles:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/nanda/index` | GET | List all public agents with pagination (limit 1-500, offset >= 0) |
| `/nanda/resolve` | GET | Resolve a single agent by ID, DID, or handle (404/403 aware) |
| `/nanda/deltas` | GET | Get changes since a sequence number for incremental sync |
| `/nanda/tools` | GET | List available MCP tools for tool-use agents |
| `/.well-known/nanda.json` | GET | Registry discovery document with identity, endpoints, and peers |

The library constructs three forms of agent identity: `did:web:{domain}:agents:{namespace}:{id}` for W3C-compliant decentralized identifiers, `@{registry}:{namespace}/{agent}` for human-readable NANDA handles, and `sha256:{digest}` for lightweight proof digests. The `_parse_agent_identifier()` function reverses all three formats plus plain IDs and namespaced identifiers, enabling the resolve endpoint to accept any format.

## Key Design Decisions

- **Pydantic for runtime validation:** Serialized output is guaranteed to match the AgentFacts specification at the type level, catching schema drift before it reaches the network. This is stronger than documentation-level compliance because validation happens on every response. Pydantic also provides automatic OpenAPI schema generation when combined with FastAPI, giving registry operators interactive API documentation for free.

- **Protocol-based converter (no inheritance coupling):** Any class implementing four methods (`to_nanda`, `list_agents`, `get_agent`, `is_public`) satisfies the `@runtime_checkable` `AgentConverter` protocol. This follows structural subtyping rather than nominal subtyping, allowing integration with arbitrary internal data models without subclassing or importing any base class. The protocol is verified at runtime via `isinstance()`.

- **Thread-safe delta store with monotonic sequencing:** Enables Quilt-compatible incremental federation sync where peer registries poll for changes since their last known sequence number. All operations acquire a `threading.Lock()` before accessing the internal delta list and sequence counter. Configurable retention pruning (default 10,000 deltas) bounds memory via list slicing while preserving the most recent history. A `PersistentDeltaStore` base class provides `_persist()` and `_load_since()` hooks for database-backed implementations.

- **3-tier adoption model (progressive complexity):** Simple registries use the `SmBridge` facade with `SimpleAgent` for zero-effort setup — register agents and include the router. Medium-complexity registries implement the `AgentConverter` protocol with their existing data models, gaining full control over the conversion logic. Complex registries extend `AbstractAgentConverter` for built-in helper methods (`build_provider`, `build_handle`, `build_did`). Each tier adds power without requiring the complexity of the tier above.

## Ecosystem Integration

The package exports 21 symbols organized across four categories: core models (AgentFacts, Provider, Endpoints, Capabilities, etc.), response models (IndexResponse, Delta, DeltaResponse, WellKnown), tools and messaging (Tool, ToolsResponse, A2AMessage), and infrastructure (DeltaStore, AgentConverter, SimpleAgent, SimpleAgentConverter, create_sm_router, SmBridge).

The `sm-bridge` package occupies the transport layer in the NANDA ecosystem, serving as the HTTP interface through which all model metadata reaches federated peers.

| Package | Role | Question Answered |
|---------|------|-------------------|
| `nanda-model-provenance` | Identity metadata | Where did this model come from? |
| `nanda-model-card` | Metadata schema | What is this model? |
| `nanda-model-integrity-layer` | Integrity verification | Does metadata meet policy? |
| `nanda-model-governance` | Cryptographic governance | Has this model been approved? |
| **`sm-bridge`** | **Transport layer** | **How is it exposed to the network?** |

Model provenance flows into the bridge through `SmAgentFacts.metadata` under vendor extension keys (`x_model_provenance`, `x_model_integrity`). The integrity layer's `attach_to_agent_facts()` function injects both provenance and integrity metadata into agent records, which the bridge then serves through its index and resolve endpoints to discovering peers.

A complete federation workflow proceeds as follows:

1. **Registration** — A registry operator creates a `SmBridge`, registers agents, and deploys the FastAPI application.
2. **Discovery** — A peer registry fetches `/.well-known/nanda.json` to discover endpoint URLs, provider identity, and supported capabilities.
3. **Initial sync** — The peer calls `/nanda/index` to retrieve all public agents with pagination.
4. **Incremental sync** — The peer polls `/nanda/deltas?since={last_seq}` to receive only changes since the last sync.
5. **Resolution** — End users or agents call `/nanda/resolve?agent={id}` to retrieve a specific agent's full metadata.

The governance layer's `approval_to_integrity_facts()` function converts cryptographic approvals into metadata that becomes discoverable through bridge endpoints, enabling consuming registries to filter agents by governance status.

## References

1. NANDA Protocol. "Network of AI Agents in Decentralized Architecture." https://projectnanda.org
2. NANDA Quilt. "Quilt of Registries and Verified AgentFacts." https://github.com/aidecentralized/NANDA-Quilt-of-Registries-and-Verified-AgentFacts
3. Google. "Agent-to-Agent (A2A) Protocol." https://github.com/google/A2A
4. W3C. "Decentralized Identifiers (DIDs) v1.0." W3C Recommendation, July 2022. https://www.w3.org/TR/did-core/

---

*First published: 2026-04-15 | Last modified: 2026-04-15*

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
