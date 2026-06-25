"""
AI Catalog gateway.

Serves the AI Catalog discovery endpoints for the agents in a ``DeltaStore``::

    GET /.well-known/ai-catalog.json   -> CatalogDocument
    GET /agents/{slug}                 -> CatalogEntry
    GET /cards/{slug}.json             -> A2A AgentCard

Each ``SmAgentFacts`` record is translated into a ``CatalogEntry`` (a pointer to
the agent's card) and an A2A ``AgentCard`` whose ``url`` is the agent's runtime.
The full ``SmAgentFacts`` is also included on the card under ``_meta`` for clients
that want it.

Mount it alongside ``create_sm_router``; the two surfaces are independent::

    from fastapi import FastAPI
    from sm_bridge import DeltaStore, create_gateway_router

    app = FastAPI()
    app.include_router(
        create_gateway_router(delta_store, base_url="https://reg.example.com",
                              domain="example.com")
    )
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


# ── AI Catalog wire models ──
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


def default_slug(facts: SmAgentFacts) -> str:
    """Derive the catalog slug from a handle (``@reg:ns/slug``) or the DID tail."""
    if facts.handle and "/" in facts.handle:
        return facts.handle.rsplit("/", 1)[-1]
    return facts.id.rsplit(":", 1)[-1]


def current_facts(
    delta_store: DeltaStore, slug_of: Callable[[SmAgentFacts], str]
) -> dict[str, SmAgentFacts]:
    """Replay the delta log into the current agent set (upsert adds, delete/revoke removes).

    The catalog reflects the store's current state, so it stays current as deltas arrive.
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
            "hostedBy": "sm-bridge",
            # full AgentFacts, for clients that want more than the card
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
    """Create the AI Catalog router for a registry's agents.

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
