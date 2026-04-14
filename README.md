# SM Bridge

A Python library for building NANDA-compatible AI agent registries.

**[NANDA](https://projectnanda.org)** (Network of AI Agents in Decentralized Architecture) is the protocol for federated AI agent discovery and communication. This library provides the primitives needed to make your agent registry interoperable with the NANDA ecosystem.

## Features

- **NANDA AgentFacts Models** - Pydantic models implementing the [projnanda/agentfacts-format](https://github.com/projnanda) specification
- **FastAPI Router** - Drop-in endpoints for `/nanda/index`, `/nanda/resolve`, `/nanda/deltas`
- **Delta Store** - Change tracking for registry synchronization
- **Converter Interface** - Abstract pattern for integrating with your existing registry

## Installation

```bash
pip install git+https://github.com/Sharathvc23/sm-bridge.git
```

Or install from source:

```bash
git clone https://github.com/Sharathvc23/sm-bridge
cd sm-bridge
pip install -e .
```

## Quick Start

### Basic Usage

```python
from fastapi import FastAPI
from sm_bridge import SmBridge, SimpleAgent

# Create the bridge
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
    description="An agent that does things",
    namespace="production",
    labels=["chat", "tool-use"],
    skills=[
        {"id": "summarize", "description": "Summarizes text"},
        {"id": "translate", "description": "Translates between languages"}
    ]
))

# Mount the router
app = FastAPI()
app.include_router(bridge.router)
```

This gives you:

- `GET /nanda/index` - List all public agents
- `GET /nanda/resolve?agent=my-agent` - Resolve a single agent
- `GET /nanda/deltas?since=0` - Get changes for sync
- `GET /nanda/.well-known/nanda.json` - Registry discovery

### Custom Registry Integration

For existing registries with their own data models:

```python
from sm_bridge import (
    AbstractAgentConverter,
    SmAgentFacts,
    SmProvider,
    SmEndpoints,
    SmCapabilities,
    SmSkill,
    DeltaStore,
    create_sm_router,
)
from typing import Iterator

class MyRegistryConverter(AbstractAgentConverter):
    def __init__(self, db_connection):
        super().__init__(
            registry_id="my-registry",
            provider_name="My Company",
            provider_url="https://example.com"
        )
        self.db = db_connection
    
    def to_sm(self, agent) -> SmAgentFacts:
        return SmAgentFacts(
            id=f"did:web:example.com:agents:{agent.id}",
            handle=self.build_handle(agent.namespace, agent.id),
            agent_name=agent.display_name,
            label=agent.category,
            description=agent.description,
            version=agent.version,
            provider=self.build_provider(),
            endpoints=SmEndpoints(static=[agent.endpoint_url]),
            capabilities=SmCapabilities(modalities=agent.capabilities),
            skills=[SmSkill(id=s.id, description=s.desc) for s in agent.skills],
            metadata={
                "x_my_registry": {
                    "internal_id": agent.internal_id,
                    "created_at": agent.created_at.isoformat(),
                }
            }
        )
    
    def list_agents(self, limit: int, offset: int) -> Iterator:
        return self.db.query_agents(limit=limit, offset=offset)
    
    def get_agent(self, agent_id: str):
        return self.db.get_agent(agent_id)
    
    def is_public(self, agent) -> bool:
        return agent.visibility == "public"

# Create router with custom converter
converter = MyRegistryConverter(db_connection)
delta_store = DeltaStore()

router = create_sm_router(
    converter=converter,
    delta_store=delta_store,
    registry_id="my-registry",
    base_url="https://registry.example.com",
    provider_name="My Company",
    provider_url="https://example.com"
)

app = FastAPI()
app.include_router(router)
```

## Models

### SmAgentFacts

The core data structure for agent metadata:

```python
from sm_bridge import SmAgentFacts

facts = SmAgentFacts(
    id="did:web:example.com:agents:my-agent",
    handle="@my-registry:production/my-agent",
    agent_name="My Agent",
    label="assistant",
    description="An AI assistant",
    version="1.0.0",
    provider=SmProvider(
        name="My Company",
        url="https://example.com"
    ),
    endpoints=SmEndpoints(
        static=["https://api.example.com/agents/my-agent"]
    ),
    capabilities=SmCapabilities(
        modalities=["text", "tool-use"],
        authentication=SmAuthentication(methods=["did-auth"])
    ),
    skills=[
        SmSkill(
            id="urn:my-registry:cap:summarize:v1",
            description="Summarizes long documents",
            inputModes=["text"],
            outputModes=["text"]
        )
    ],
    metadata={
        "x_my_registry": {
            "custom_field": "custom_value"
        }
    }
)
```

### Handle Format

NANDA handles follow the format `@registry:namespace/agent-id`:

```python
handle = SmAgentFacts.create_handle(
    registry="my-registry",
    namespace="production", 
    agent_id="my-agent"
)
# Returns: "@my-registry:production/my-agent"
```

## Delta Store

Track changes for registry synchronization:

```python
from sm_bridge import DeltaStore, SmAgentFacts

store = DeltaStore()

# Record an agent creation/update
delta = store.add("upsert", agent_facts)
print(f"Recorded delta with seq={delta.seq}")

# Get all changes since seq 0
deltas = store.since(0)

# Get next sequence number for polling
next_seq = store.next_seq
```

For production, extend `PersistentDeltaStore` to persist to a database:

```python
from sm_bridge import PersistentDeltaStore

class PostgresDeltaStore(PersistentDeltaStore):
    def __init__(self, dsn: str):
        super().__init__()
        self.conn = psycopg2.connect(dsn)
    
    def _persist(self, delta):
        # INSERT INTO nanda_deltas ...
        pass
    
    def _load_since(self, seq):
        # SELECT * FROM nanda_deltas WHERE seq > ...
        pass
```

## MCP Tools

Advertise MCP tools that agents can use:

```python
from sm_bridge import SmBridge, SmTool

bridge = SmBridge(
    registry_id="my-registry",
    provider_name="My Company",
    provider_url="https://example.com",
    tools=[
        SmTool(
            tool_id="search",
            description="Search the web",
            endpoint="https://api.example.com/mcp/search",
            params=["query", "limit"]
        ),
        SmTool(
            tool_id="calculate",
            description="Perform calculations",
            endpoint="https://api.example.com/mcp/calculate",
            params=["expression"]
        )
    ]
)
```

## Registry Discovery

The library automatically serves `/.well-known/nanda.json` for registry discovery:

```json
{
  "registry_id": "my-registry",
  "registry_did": "did:web:registry.example.com",
  "namespaces": ["did:web:example.com:*"],
  "index_url": "https://registry.example.com/nanda/index",
  "resolve_url": "https://registry.example.com/nanda/resolve",
  "deltas_url": "https://registry.example.com/nanda/deltas",
  "tools_url": "https://registry.example.com/nanda/tools",
  "provider": {
    "name": "My Company",
    "url": "https://example.com"
  },
  "capabilities": ["agentfacts", "deltas", "mcp-tools"]
}
```

## Federating with NANDA

To join the NANDA network:

1. Deploy your registry with the NANDA bridge endpoints
2. Ensure `/.well-known/nanda.json` is accessible
3. Contact the MIT NANDA team to register as a federated peer
4. (Optional) Implement Quilt-compatible sync or gossip mechanisms for real-time or near-real-time federation

## Related Packages

| Package | Question it answers |
|---------|-------------------|
| [`sm-model-provenance`](https://github.com/Sharathvc23/sm-model-provenance) | "Where did this model come from?" (identity, versioning, provider, NANDA serialization) |
| [`sm-model-card`](https://github.com/Sharathvc23/sm-model-card) | "What is this model?" (unified metadata schema — type, status, risk level, metrics, weights hash) |
| [`sm-model-integrity-layer`](https://github.com/Sharathvc23/sm-model-integrity-layer) | "Does this model's metadata meet policy?" (rule-based checks) |
| [`sm-model-governance`](https://github.com/Sharathvc23/sm-model-governance) | "Has this model been cryptographically approved for deployment?" (approval flow with signatures, quorum, scoping, revocation) |
| `sm-bridge` (this package) | "How do I expose this to the NANDA network?" (FastAPI router, AgentFacts models, delta sync) |


## License

MIT

---

*Developed by [stellarminds.ai](https://stellarminds.ai) — Research Contribution to [Project NANDA](https://projectnanda.org)*
