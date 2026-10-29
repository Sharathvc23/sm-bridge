"""
AI Catalog gateway.

Serves the AI Catalog discovery endpoints for the agents in a ``DeltaStore``::

    GET /.well-known/ai-catalog.json   -> CatalogDocument
    GET /agents/search?q=<query>       -> CatalogDocument (the Index's fan-out hop)
    GET /agents/{slug}                 -> CatalogEntry
    GET /cards/{slug}.json             -> A2A AgentCard

``/agents/search`` is the one path the NANDA Index fetches from a registrant. An
entry whose ``media_type`` is the enterprise catalog type is expanded by the Index
at query time with ``GET <registry_url>/agents/search?q=...``; a registry that does
not answer it is recorded as unreachable and contributes nothing to the Index's
search, however complete its catalog. ``registry_url`` is this gateway's
``base_url``.

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

from fastapi import APIRouter, HTTPException, Query
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
    host: str | None = None  # ai-catalog spec (Agent-Card/ai-catalog): the catalog's host
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
    """The current agent set (upsert adds, delete/revoke removes).

    Built from the store's per-agent snapshot rather than a replay of the whole
    log, so it costs one entry per agent and does not grow with history. The log
    is append-only (`DeltaStore`), and a full replay would grow without bound.
    """
    state: dict[str, SmAgentFacts] = {}
    for delta in delta_store.snapshot():
        slug = slug_of(delta.agent)
        if delta.action == "upsert":
            state[slug] = delta.agent
        else:  # "delete" | "revoke"
            state.pop(slug, None)
    return state


def _matches(entry: CatalogEntry, query: str) -> bool:
    """Whether `entry` satisfies a free-text catalog query.

    Only fields the entry actually carries are searched, so a match can always be
    explained by something the source declared. An empty query matches everything:
    the caller asked to narrow by nothing.
    """
    q = query.strip().lower()
    if not q:
        return True
    haystack = [entry.displayName, entry.description or "", entry.identifier, *entry.tags]
    return any(q in field.lower() for field in haystack)


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
        # No ttl_seconds and no status. A hardcoded one-hour TTL is a caching
        # contract nothing here honors — nothing invalidates at 3600s and the
        # value was identical for a DNSSEC-anchored agent and an unverified one.
        # "status": "active" is a liveness claim derived from nothing.
        metadata={},
    )


def _runtime_url(facts: SmAgentFacts) -> str:
    """The address a caller should use, preferring the most specific declared.

    `static[0] if static else ""` emitted a card with an empty `url` for an agent
    that is reachable, just not statically — NANDA's `dynamic` and
    `adaptive_resolver` are exactly that case, and both were dropped.
    """
    if facts.endpoints.static:
        return facts.endpoints.static[0]
    if facts.endpoints.dynamic:
        return facts.endpoints.dynamic[0]
    if facts.endpoints.adaptive_resolver is not None:
        return facts.endpoints.adaptive_resolver.url
    return ""


def to_a2a_card(facts: SmAgentFacts, slug: str, domain: str, base_url: str) -> A2AAgentCard:
    runtime = _runtime_url(facts)
    return A2AAgentCard(
        name=facts.agent_name,
        description=facts.description,
        url=runtime,
        version=facts.version,
        # Only capabilities the source declared. `"pushNotifications": False` was
        # an invented negative claim: the source never said it lacked them.
        capabilities={"streaming": facts.capabilities.streaming},
        authentication={"schemes": list(facts.capabilities.authentication.methods)},
        skills=[{"name": s.id, "description": s.description} for s in facts.skills],
        provider={"organization": facts.provider.name, "url": facts.provider.url},
        meta={
            # An ARD domain-anchored resource identifier (AIR URN), the form the
            # NANDA Index keys entries on. The previous `urn:ai:domain:<domain>:...`
            # is refused by the Index outright, so a card carrying it named this
            # agent with a string nothing upstream would accept. The publisher
            # domain is lower-cased because the Index normalises it that way and an
            # identifier that differs only in case is a different string here.
            "identifier": f"urn:air:{domain.lower()}:agent:{slug}",
            "publicUrl": f"{base_url}/cards/{slug}.json",
            "hostedBy": "sm-bridge",
            # full AgentFacts, for clients that want more than the card
            "agentfacts": facts.model_dump(mode="json"),
        },
    )


#: A registry's own rule for who may be *enumerated* on the public catalog surfaces.
#: Takes the agent's slug and its facts; returns False to withhold it.
ListingPredicate = Callable[[str, SmAgentFacts], bool]


def create_gateway_router(
    delta_store: DeltaStore,
    base_url: str,
    domain: str,
    *,
    slug_of: Callable[[SmAgentFacts], str] | None = None,
    prefix: str = "",
    is_listed: ListingPredicate | None = None,
) -> APIRouter:
    """Create the AI Catalog router for a registry's agents.

    Args:
        delta_store: the registry's DeltaStore (the federation-synced state).
        base_url: public URL where this gateway is reachable (``registry_url`` in the Index).
        domain: publisher FQDN used in the agent's AIR URN (``urn:air:<domain>:agent:<slug>``).
        slug_of: how to derive the catalog slug from facts (default: handle/DID tail).
        prefix: optional URL prefix.
        is_listed: the registry's own rule for who may be **enumerated** on the public
            catalog surfaces — ``(slug, facts) -> bool``. Default: everything in the
            store is listed. See the note below on what it does and does not gate.

    Returns:
        An ``APIRouter`` serving ``/.well-known/ai-catalog.json``, ``/agents/search``,
        ``/agents/{slug}`` and ``/cards/{slug}.json``.

    **What ``is_listed`` gates, and why not everything.**

    It gates the two **enumerating** surfaces — the catalog document and the Index's
    fan-out search — with one predicate, so they cannot disagree about who is
    discoverable. A registry whose index and search answered with different agent sets
    would be publishing two incompatible claims about itself.

    It deliberately does **not** gate ``/agents/{slug}`` or ``/cards/{slug}.json``.
    Those answer about an agent the caller already named, and neither available
    behaviour is honest: a ``403`` discloses that the agent exists while refusing it,
    and a ``404`` is a positive claim of absence about an agent this registry is in fact
    holding — which a corroborator would read as a false omission. Worse, an entry
    published on the Index resolves through exactly this path, so gating it would
    ``404`` the Index's own resolution hop for an agent that is legitimately registered.

    So the boundary is: **withheld from the listing, still resolvable by name.** If your
    registry needs an agent to be unreachable rather than merely unlisted, keep it out
    of the ``DeltaStore`` — absence from the store is the only honest way to say an
    agent is not here.
    """
    slug_fn = slug_of or default_slug
    listed = is_listed or (lambda _slug, _facts: True)
    base = base_url.rstrip("/")
    router = APIRouter(prefix=prefix, tags=["nanda-ai-catalog"])

    def listed_entries() -> list[CatalogEntry]:
        """The entries both enumerating surfaces publish — one rule, computed once.

        The catalog document and the Index's fan-out answer from this, so a registry
        cannot end up publishing two different claims about who it lists.
        """
        agents = current_facts(delta_store, slug_fn)
        return [
            to_catalog_entry(f, slug, base) for slug, f in agents.items() if listed(slug, f)
        ]

    @router.get("/.well-known/ai-catalog.json", response_model=CatalogDocument)
    def ai_catalog() -> CatalogDocument:
        return CatalogDocument(host=base, entries=listed_entries())

    # MUST be registered before `/agents/{slug}`: FastAPI matches in registration
    # order, so the parameterised route would otherwise capture "search" as a slug
    # and answer the Index's fan-out with a 404 for an agent of that name.
    @router.get("/agents/search", response_model=CatalogDocument)
    def search_agents(q: str = Query("", description="Free-text query")) -> CatalogDocument:
        """The NANDA Index's fan-out hop — `GET <registry_url>/agents/search?q=...`.

        Returns the same entries as `/.well-known/ai-catalog.json`, narrowed to those
        matching `q`. The Index reads `entries` and takes a bounded slice, so this
        answers with the whole catalog shape rather than a bespoke result envelope.

        Matching is a case-insensitive substring over the fields an entry actually
        declares — name, description, tags and identifier. It is deliberately not a
        relevance ranking: the Index ranks across registries itself, and a score
        invented here would compete with that while meaning something different for
        every registry.
        """
        return CatalogDocument(
            host=base, entries=[e for e in listed_entries() if _matches(e, q)]
        )

    # `is_listed` is deliberately NOT applied here or to the card below: these answer
    # about an agent the caller already named, and the Index's own resolution hop comes
    # through this path for a legitimately registered entry. See create_gateway_router.
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
