"""
NANDA AI-Catalog gateway (border layer).

sm-bridge's native surface (``/nanda/*``, AgentFacts) is the *list39* lineage.
The current MIT reference index (``nanda-index-v2``) instead resolves through the
**AI-Catalog** convention: a ``hosting_path=registry`` org is dereferenced via
``GET {registry_url}/agents/{id}`` -> ``CatalogEntry`` -> an **A2A AgentCard** leaf.

This module is the optional border node that makes a sm-bridge registry reachable
from that index without touching the core: it reads the registry's **current
state folded from the DeltaStore** (so it tracks whatever the federation syncs in)
and translates each ``SmAgentFacts`` into the AI-Catalog + A2A-card shapes.

Mount it *alongside* ``create_sm_router`` — the ``/nanda/*`` surface stays as-is::

    from fastapi import FastAPI
    from sm_bridge import DeltaStore, create_gateway_router

    app = FastAPI()
    app.include_router(
        create_gateway_router(delta_store, base_url="https://reg.example.com",
                              domain="example.com")
    )

Now ``GET /.well-known/ai-catalog.json``, ``GET /agents/{slug}`` and
``GET /cards/{slug}.json`` are served, and the registry can be registered into
``nanda-index-v2`` as ``hosting_path=registry`` with ``registry_url`` = ``base_url``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .models import SmAgentFacts
from .store import DeltaStore

A2A_CARD_MEDIA_TYPE = "application/a2a-agent-card+json"


# ── AI-Catalog wire models (match spec.aicatalog.org / nanda-registry) ──
class CatalogEntry(BaseModel):
    """A single AI-Catalog entry — a *pointer* to an agent card."""

    identifier: str
    displayName: str
    mediaType: str = A2A_CARD_MEDIA_TYPE
    url: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    version: str | None = None
    updatedAt: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CatalogDocument(BaseModel):
    """The aggregate AI-Catalog served at ``/.well-known/ai-catalog.json``."""

    specVersion: str = "1.0"
    entries: list[CatalogEntry]


class A2AAgentCard(BaseModel):
    """A2A AgentCard leaf — ``url`` is the runtime endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str | None = None
    url: str
    version: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    authentication: dict[str, Any] = Field(default_factory=dict)
    skills: list[dict[str, Any]] = Field(default_factory=list)
    provider: dict[str, Any] | None = None
    meta: dict[str, Any] = Field(default_factory=dict, alias="_meta")


# ── federation feed: fold the delta log into the current agent set ──
def default_slug(facts: SmAgentFacts) -> str:
    """Derive the catalog slug from a handle (``@reg:ns/slug``) or the DID tail."""
    if facts.handle and "/" in facts.handle:
        return facts.handle.rsplit("/", 1)[-1]
    return facts.id.rsplit(":", 1)[-1]


def current_facts(
    delta_store: DeltaStore, slug_of: Callable[[SmAgentFacts], str]
) -> dict[str, SmAgentFacts]:
    """Replay the DeltaStore into the live agent set (upsert adds, delete/revoke removes).

    This is what makes the gateway *federation-fed*: as peers sync deltas in via the
    Quilt ``/nanda/deltas`` surface, the catalog reflects them with no extra wiring.
    """
    state: dict[str, SmAgentFacts] = {}
    for delta in delta_store.since(0):
        slug = slug_of(delta.agent)
        if delta.action == "upsert":
            state[slug] = delta.agent
        else:  # "delete" | "revoke"
            state.pop(slug, None)
    return state


# ── translators: SmAgentFacts -> AI-Catalog / A2A card ──
def to_catalog_entry(facts: SmAgentFacts, slug: str, base_url: str) -> CatalogEntry:
    return CatalogEntry(
        identifier=slug,
        displayName=facts.agent_name,
        mediaType=A2A_CARD_MEDIA_TYPE,
        url=f"{base_url}/cards/{slug}.json",
        description=facts.description,
        tags=list(facts.capabilities.skills),
        version=facts.version,
        updatedAt=datetime.now(timezone.utc).isoformat(),
        metadata={"ttl_seconds": 3600, "status": "active"},
    )


def to_a2a_card(facts: SmAgentFacts, slug: str, domain: str, base_url: str) -> A2AAgentCard:
    runtime = facts.endpoints.static[0] if facts.endpoints.static else ""
    return A2AAgentCard(
        name=facts.agent_name,
        description=facts.description,
        url=runtime,
        version=facts.version,
        capabilities={"streaming": facts.capabilities.streaming, "pushNotifications": False},
        authentication={"schemes": list(facts.capabilities.authentication.methods)},
        skills=[{"name": s.id, "description": s.description} for s in facts.skills],
        provider={"organization": facts.provider.name, "url": facts.provider.url},
        meta={
            "identifier": f"urn:ai:domain:{domain}:agent:{slug}",
            "publicUrl": f"{base_url}/cards/{slug}.json",
            "hostedBy": "sm-nanda-gateway",
            # native facts ride along: NANDA clients read the card, sm-bridge-aware
            # clients pull the full AgentFacts from the same response.
            "agentfacts": facts.model_dump(mode="json"),
        },
    )


def create_gateway_router(
    delta_store: DeltaStore,
    base_url: str,
    domain: str,
    *,
    slug_of: Callable[[SmAgentFacts], str] | None = None,
    prefix: str = "",
) -> APIRouter:
    """Create the AI-Catalog border router for a sm-bridge registry.

    Args:
        delta_store: the registry's DeltaStore (the federation-synced state).
        base_url: public URL where this gateway is reachable (``registry_url`` in the Index).
        domain: org domain used in the agent ``urn`` (``urn:ai:domain:<domain>:agent:<slug>``).
        slug_of: how to derive the catalog slug from facts (default: handle/DID tail).
        prefix: optional URL prefix.

    Returns:
        An ``APIRouter`` serving ``/.well-known/ai-catalog.json``, ``/agents/{slug}``
        and ``/cards/{slug}.json``.
    """
    slug_fn = slug_of or default_slug
    base = base_url.rstrip("/")
    router = APIRouter(prefix=prefix, tags=["nanda-ai-catalog"])

    @router.get("/.well-known/ai-catalog.json", response_model=CatalogDocument)
    def ai_catalog() -> CatalogDocument:
        agents = current_facts(delta_store, slug_fn)
        return CatalogDocument(
            entries=[to_catalog_entry(f, slug, base) for slug, f in agents.items()]
        )

    @router.get("/agents/{slug}", response_model=CatalogEntry)
    def get_agent(slug: str) -> CatalogEntry:
        facts = current_facts(delta_store, slug_fn).get(slug)
        if facts is None:
            raise HTTPException(status_code=404, detail=f"agent '{slug}' not found")
        return to_catalog_entry(facts, slug, base)

    @router.get("/cards/{slug}.json", response_model=A2AAgentCard)
    def get_card(slug: str) -> A2AAgentCard:
        facts = current_facts(delta_store, slug_fn).get(slug)
        if facts is None:
            raise HTTPException(status_code=404, detail=f"agent '{slug}' not found")
        return to_a2a_card(facts, slug, domain, base)

    return router
