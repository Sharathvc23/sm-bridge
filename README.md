# sm-bridge

[![PyPI](https://img.shields.io/pypi/v/sm-bridge.svg)](https://pypi.org/project/sm-bridge/)
[![Python](https://img.shields.io/pypi/pyversions/sm-bridge.svg)](https://pypi.org/project/sm-bridge/)
[![License](https://img.shields.io/pypi/l/sm-bridge.svg)](./LICENSE)

**The universal on-ramp to the NANDA agent-internet.**

sm-bridge lets any agent source — your own registry, an AI catalog, an ANS registry, or a
single domainless agent — join the [NANDA](https://projectnanda.org) Index through one small
library, and emerge carrying a **normalized, cryptographically verifiable proof of trust**.
The Index stays a *quilt of registries* (one entry per registry, never one per agent); the
bridge is how you get onto it.

The core is just FastAPI + Pydantic. Verification and transparency-log features live in
optional extras, so you only pull cryptography when you use it.

## What it does

- **Onboard** any source to the quilt. A registry-scale source (like ANS, with its own
  resolver) joins as **one entry** and resolution is delegated back to it — the bridge never
  mirrors its agents. A source with **no registry of its own** (a catalog, a `did:key` agent)
  is hosted locally.
- **Verify** each source with a pluggable **trust profile** and normalize the result to one
  proof block: `VERIFIED` / `FAILED` / `NOT_VERIFIED`. Every `VERIFIED` is a real signature,
  DNS, or Merkle check — absent live infrastructure you get an honest `NOT_VERIFIED(reason)`,
  never a mocked pass.
- **Serve** the NANDA discovery surfaces as drop-in FastAPI routers: `/nanda/index`,
  `/nanda/resolve`, `/nanda/deltas`, `/.well-known/nanda.json`, plus an AI-Catalog gateway.

Trust profiles today: `ed25519-agentcard`, `ans-scitt` (ANS SCITT receipts),
`ans-txt` (ANS DNS discovery), `dns-aid` (SVCB + DNSSEC + DANE), `jws-catalog` (signed
AI-Catalog), and `nanda-delegation` (did:key delegation chains). See
[`docs/trust-profiles.md`](docs/trust-profiles.md).

## Install

```bash
pip install sm-bridge                 # core: FastAPI routers, models, delta sync
pip install "sm-bridge[trust]"        # + verification adapters (ed25519/SCITT/DNS-AID/JWS/delegation)
pip install "sm-bridge[trust,tlog]"   # + RFC 6962 transparency log & conformance self-test
```

Requires Python 3.11+.

## Onboard and verify

```python
from sm_bridge import SmBridge, SimpleAgent, SimpleAgentConverter, ANSEntryConverter, TrustRegistry
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile
from sm_bridge.trust.ans_scitt import AnsScittProfile

# A source with no registry of its own → hosted locally.
conv = SimpleAgentConverter(registry_id="quilt", provider_name="Q", provider_url="https://q.example")
conv.register(SimpleAgent(id="finance", name="Finance Agent", description="does finance"))

bridge = SmBridge(
    registry_id="quilt", provider_name="Q", provider_url="https://q.example",
    converter=conv,
    trust_registry=TrustRegistry([Ed25519AgentCardProfile(), AnsScittProfile()]),
    # A registry-scale source (ANS) → one entry, resolution delegated back to it.
    entries=[ANSEntryConverter(registry_name="acme-ans", resolver_endpoint="https://ans.acme.example")],
)

# GET /nanda/resolve?agent=finance          → agent facts + a normalized proof block
# GET /nanda/registries/acme-ans/resolve    → a delegation pointer (the quilt never mirrors ANS's agents)
```

### Command line

The same verification is available from the terminal (`[trust]` extra):

```bash
sm-bridge verify ans-scitt   --receipt receipt.cbor --root-keys root-keys.txt
sm-bridge verify jws-catalog --catalog ai-catalog.json --signature sig.jws --jwks jwks.json
sm-bridge verify agent-card  --card card.json --signature-b64 <b64> --pubkey key.pem
sm-bridge verify dns-aid     --fqdn agent.example.com [--dane]
sm-bridge verify delegation  --evidence delegation-bundle.json
```

Exit code `0` = VERIFIED, `1` = FAILED, `2` = NOT_VERIFIED.

### Runnable demos

Two offline, self-contained scenarios (see [`examples/`](examples/)):

```bash
python examples/demo1_switchboard.py            # one query → an ANS registry (delegated) + a non-ANS catalog (verified)
python examples/demo2_domainless_delegation.py  # a domainless did:key earns scoped, revocable delegation
```

## Serve a NANDA-compatible registry

If you just want to expose your own agents on NANDA, mount the routers and register agents:

```python
from fastapi import FastAPI
from sm_bridge import SmBridge, SimpleAgent

bridge = SmBridge(
    registry_id="my-registry",
    provider_name="My Company",
    provider_url="https://example.com",
    base_url="https://registry.example.com",
)

bridge.register_agent(SimpleAgent(
    id="my-agent",
    name="My Agent",
    description="An agent that does things",
    namespace="production",
    labels=["chat", "tool-use"],
    skills=[
        {"id": "summarize", "description": "Summarizes text"},
        {"id": "translate", "description": "Translates between languages"},
    ],
))

app = FastAPI()
app.include_router(bridge.router)            # /nanda/* endpoints
app.include_router(bridge.wellknown_router)  # /.well-known/nanda.json (RFC 8615)
```

You get:

- `GET /nanda/index` — list public agents (with a correct `total_count` for pagination)
- `GET /nanda/resolve?agent=my-agent` — resolve a single agent
- `GET /nanda/deltas?since=0` — change feed for synchronization
- `GET /.well-known/nanda.json` — registry discovery document

### Integrate an existing registry

Implement the converter protocol to expose your own data model, without copying agents into
a second store:

```python
from typing import Iterator

from sm_bridge import (
    AbstractAgentConverter, SmAgentFacts, SmEndpoints, SmCapabilities, SmSkill,
    DeltaStore, create_sm_router,
)


class MyRegistryConverter(AbstractAgentConverter):
    def __init__(self, db):
        super().__init__(registry_id="my-registry", provider_name="My Company",
                         provider_url="https://example.com")
        self.db = db

    def to_sm(self, agent) -> SmAgentFacts:
        return SmAgentFacts(
            id=f"did:web:example.com:agents:{agent.id}",
            handle=self.build_handle(agent.namespace, agent.id),
            agent_name=agent.display_name, label=agent.category,
            description=agent.description, version=agent.version,
            provider=self.build_provider(),
            endpoints=SmEndpoints(static=[agent.endpoint_url]),
            capabilities=SmCapabilities(modalities=agent.capabilities),
            skills=[SmSkill(id=s.id, description=s.desc) for s in agent.skills],
        )

    def list_agents(self, limit: int, offset: int) -> Iterator:
        return self.db.query_agents(limit=limit, offset=offset)

    def get_agent(self, agent_id: str):
        return self.db.get_agent(agent_id)

    def is_public(self, agent) -> bool:
        return agent.visibility == "public"
```

To attach real verification at resolve time, add a `trust_evidence(agent) -> (profile_id,
evidence)` method to your converter and inject a `TrustRegistry` — the resolved facts then
carry a `ProofResult`.

## Delta sync & AI-Catalog gateway

- **Delta store** — `DeltaStore` tracks upserts/deletes with a monotonic cursor for
  registry-to-registry synchronization; subclass `PersistentDeltaStore` to back it with a
  database. The default HTTP sync transport is the `[federation]` extra.
- **AI-Catalog gateway** — `create_gateway_router(delta_store, base_url=..., domain=...)`
  serves `/.well-known/ai-catalog.json`, `/agents/{slug}`, and A2A `/cards/{slug}.json`
  alongside the `/nanda/*` router.

## Transparency log & conformance

The `[tlog]` extra adds an RFC 6962 Merkle tree over the delta log, a signed checkpoint, and
inclusion/consistency proofs, plus a conformance self-test (`sm_bridge.conformance`) that
verifies the checkpoint signature, recomputes the root, checks append-only growth, and
detects tampering.

## Verifiable Agent Feed (`[feed]`)

The `[feed]` extra projects the delta log as a signed, hash-chained
[Verifiable Agent Feed](https://github.com/Sharathvc23/sm-feed) — **alongside** `/nanda/deltas`,
not replacing it. `sm_bridge.feed.build_delta_feed(deltas, identity, ...)` returns a signed
`feed-page` a peer subscribes to with `?since=<cursor>`; `read_delta_feed(page)` verifies it for
**authenticity and completeness** (no dropped or reordered delta) and returns the verified
records. Where `/nanda/deltas` asks a puller to trust the server for completeness, the feed lets
a subscriber prove it. The extra is opt-in; the core never imports `sm-feed`.

## Documentation

- [`docs/trust-profiles.md`](docs/trust-profiles.md) — the trust profiles and the proof block.
- [`docs/quilt-onboarding.md`](docs/quilt-onboarding.md) — entry mode vs hosting mode, and
  verify-at-admission.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes.

## Related packages

Part of the `sm-*` trust stack:

| Package | Role |
|---|---|
| `sm-bridge` (this package) | Onboard any agent source to the NANDA Index, with a normalized verifiable proof of trust |
| [`sm-arp`](https://github.com/Sharathvc23/sm-arp) | Agency Receipt Protocol — signed receipts for what an agent did |
| [`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) | Signed, offline-verifiable conformance badges |

## License

MIT

---

*Aligned with [Project NANDA](https://projectnanda.org). Built by [Stellarminds.ai](https://stellarminds.ai).*
