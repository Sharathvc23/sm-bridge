"""
AI Catalog gateway.

Serves the AI Catalog discovery endpoints for the agents in a ``DeltaStore``::

    GET /.well-known/ai-catalog.json   -> CatalogDocument
    GET /agents/search?q=<query>       -> CatalogDocument (the Index's fan-out hop)
    GET /agents/{slug}                 -> CatalogEntry
    GET /cards/{slug}.json             -> A2A AgentCard (A2A v1.0 shape)

``/agents/search`` is the one path the NANDA Index fetches from a registrant. An
entry whose ``media_type`` is the enterprise catalog type is expanded by the Index
at query time with ``GET <registry_url>/agents/search?q=...``; a registry that does
not answer it is recorded as unreachable and contributes nothing to the Index's
search, however complete its catalog. ``registry_url`` is this gateway's
``base_url``.

Each ``SmAgentFacts`` record is translated into a ``CatalogEntry`` (a pointer to
the agent's card) and an A2A ``AgentCard``. The card follows the **A2A v1.0**
AgentCard (spec §4.4.1): the runtime is declared in ``supportedInterfaces`` (§4.4.6,
``url`` + ``protocolBinding`` + ``protocolVersion``), authentication in
``securitySchemes`` / ``securityRequirements``, media types in
``defaultInputModes`` / ``defaultOutputModes``, and every skill carries ``id``,
``name``, ``description`` and ``tags`` (§4.4.5). These are exactly the fields the
NANDA Index v2 checks when it fetches a registrant's card
(``server/src/services/cardValidation.ts``): nonempty ``name``/``description``/
``version``, a nonempty ``supportedInterfaces`` (or a legacy HTTP(S) ``url`` when it
is absent), an object ``capabilities``, nonempty ``defaultInputModes`` /
``defaultOutputModes``, and skills each with nonempty ``id``/``name``/``description``
and a ``tags`` array. The legacy top-level ``url`` is kept alongside
``supportedInterfaces`` for pre-v1.0 readers. The full ``SmAgentFacts`` is also
included on the card under ``_meta`` for clients that want it.

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

from .models import SmAgentFacts, SmSkill
from .store import DeltaStore

A2A_CARD_MEDIA_TYPE = "application/a2a-agent-card+json"

#: The A2A protocol version the card declares — top-level and on every interface.
A2A_PROTOCOL_VERSION = "1.0"

#: The binding the gateway advertises for an agent's runtime endpoint. The NANDA
#: facts carry a URL and nothing about the wire protocol spoken at it; JSON-RPC is the
#: A2A core binding, and the Index requires an HTTP(S) URL for it.
A2A_DEFAULT_BINDING = "JSONRPC"

#: What a card declares when its skills name no media type at all.
DEFAULT_MEDIA_TYPES = ["text/plain"]

#: NANDA skill ``inputModes`` / ``outputModes`` are modality names ("text", "image");
#: A2A modes are media types. These are the lossless renderings; anything already
#: containing a ``/`` is a media type and passes through, and anything else is kept
#: verbatim rather than guessed at.
_MODALITY_MEDIA_TYPES: dict[str, str] = {
    "text": "text/plain",
    "json": "application/json",
    "image": "image/*",
    "audio": "audio/*",
    "video": "video/*",
}

#: NANDA authentication methods with a lossless A2A ``SecurityScheme`` rendering. Any
#: other method is carried under its own name with ``type`` set to the method verbatim,
#: so a reader sees exactly what the source declared rather than a guessed scheme.
_SECURITY_SCHEMES: dict[str, dict[str, Any]] = {
    "jwt": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
    "bearer": {"type": "http", "scheme": "bearer"},
    "basic": {"type": "http", "scheme": "basic"},
    "mtls": {"type": "mutualTLS"},
    "mutual-tls": {"type": "mutualTLS"},
}

#: Methods that mean "no authentication" — they produce no scheme and no requirement.
_NO_AUTH_METHODS = frozenset({"none", "open", "public"})


# ── AI Catalog wire models ──
class CatalogEntry(BaseModel):
    """A single AI-Catalog entry — a *pointer* to an agent card.

    ``updatedAt`` is the time the entry was **serialized**, not the time the agent's
    record last changed. The facts carry no modification timestamp, and the gateway
    does not invent one; a consumer wanting the record's own history has the delta
    log (``/nanda/deltas``), whose ``recorded_at`` is a real event time.
    """

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


class A2AAgentInterface(BaseModel):
    """A2A v1.0 ``AgentInterface`` (§4.4.6) — one way to reach the agent."""

    url: str
    protocolBinding: str = A2A_DEFAULT_BINDING
    protocolVersion: str = A2A_PROTOCOL_VERSION


class A2AAgentSkill(BaseModel):
    """A2A v1.0 ``AgentSkill`` (§4.4.5). ``id``/``name``/``description``/``tags`` are
    required by the spec and checked by the Index; ``tags`` is never empty here."""

    id: str
    name: str
    description: str
    tags: list[str]
    inputModes: list[str] = Field(default_factory=list)
    outputModes: list[str] = Field(default_factory=list)


class A2AAgentCard(BaseModel):
    """A2A v1.0 ``AgentCard`` (§4.4.1), plus two compatibility fields.

    ``url`` is the pre-v1.0 top-level runtime endpoint; the Index falls back to it only
    when ``supportedInterfaces`` is absent, and older readers know nothing else. It is
    always equal to ``supportedInterfaces[0].url``. ``_meta`` is the gateway's own
    extension carrying the AIR URN identifier and the full ``SmAgentFacts``.

    ``model_dump()`` / ``model_dump_json()`` emit ``_meta`` under its wire name by
    default, so a hand-rolled dump is the same document the router serves.
    """

    model_config = ConfigDict(populate_by_name=True)

    protocolVersion: str = A2A_PROTOCOL_VERSION
    name: str
    description: str
    url: str
    supportedInterfaces: list[A2AAgentInterface] = Field(min_length=1)
    version: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    securitySchemes: dict[str, dict[str, Any]] = Field(default_factory=dict)
    securityRequirements: list[dict[str, list[str]]] = Field(default_factory=list)
    defaultInputModes: list[str] = Field(min_length=1)
    defaultOutputModes: list[str] = Field(min_length=1)
    skills: list[A2AAgentSkill] = Field(default_factory=list)
    provider: dict[str, Any] | None = None
    meta: dict[str, Any] = Field(default_factory=dict, alias="_meta")

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("by_alias", True)
        return super().model_dump(*args, **kwargs)

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        kwargs.setdefault("by_alias", True)
        return super().model_dump_json(*args, **kwargs)


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
    base = base_url.rstrip("/")
    return CatalogEntry(
        identifier=slug,
        displayName=facts.agent_name,
        mediaType=A2A_CARD_MEDIA_TYPE,
        url=f"{base}/cards/{slug}.json",
        description=facts.description,
        tags=list(facts.capabilities.skills),
        version=facts.version,
        # Serialization time, by construction — see CatalogEntry.
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


def _media_types(modes: list[str]) -> list[str]:
    """Render NANDA modality names as A2A media types, de-duplicated, order kept."""
    out: list[str] = []
    for mode in modes:
        rendered = mode if "/" in mode else _MODALITY_MEDIA_TYPES.get(mode, mode)
        if rendered and rendered not in out:
            out.append(rendered)
    return out


def _default_modes(skills: list[SmSkill], attr: str) -> list[str]:
    """The union of the skills' modes, or ``text/plain`` when they declare none."""
    union: list[str] = []
    for skill in skills:
        for rendered in _media_types(list(getattr(skill, attr))):
            if rendered not in union:
                union.append(rendered)
    return union or list(DEFAULT_MEDIA_TYPES)


def _skill_name(skill: SmSkill) -> str:
    """A skill's display name: the source's ``name`` extra when it sent one, else the id."""
    extra = skill.model_extra or {}
    name = extra.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return skill.id


def _skill_tags(facts: SmAgentFacts) -> list[str]:
    """Skill tags: the agent's declared capability skill identifiers, or ``general``.

    A2A requires ``tags`` on every skill and the Index checks it is an array; a
    non-empty list is emitted so a strict reader never sees a skill with no tags.
    ``general`` is the one value here the source did not say.
    """
    tags = [t for t in facts.capabilities.skills if t.strip()]
    return tags or ["general"]


def _to_a2a_skill(skill: SmSkill, tags: list[str]) -> A2AAgentSkill:
    return A2AAgentSkill(
        id=skill.id,
        name=_skill_name(skill),
        description=skill.description,
        tags=list(tags),
        inputModes=_media_types(list(skill.inputModes)),
        outputModes=_media_types(list(skill.outputModes)),
    )


def _security(facts: SmAgentFacts) -> tuple[dict[str, dict[str, Any]], list[dict[str, list[str]]]]:
    """``securitySchemes`` + ``securityRequirements`` from the declared auth methods.

    Each method becomes one named scheme and one alternative requirement (A2A's
    ``securityRequirements`` is a list of alternatives — any one satisfies). A method
    with a lossless A2A rendering gets it; any other is carried under its own name
    with ``type`` set to the method verbatim. ``requiredScopes`` attach to every
    requirement because the facts scope them to the agent, not to a method. A method
    meaning "no authentication" produces nothing.
    """
    auth = facts.capabilities.authentication
    scopes = list(auth.requiredScopes or [])
    schemes: dict[str, dict[str, Any]] = {}
    requirements: list[dict[str, list[str]]] = []
    for method in auth.methods:
        key = method.strip()
        if not key or key.lower() in _NO_AUTH_METHODS:
            continue
        scheme = _SECURITY_SCHEMES.get(key.lower())
        if scheme is None:
            scheme = {
                "type": key,
                "description": (
                    f"NANDA authentication method {key!r}, carried verbatim: the A2A "
                    "SecurityScheme vocabulary has no lossless equivalent. See "
                    "_meta.agentfacts.capabilities.authentication."
                ),
            }
        schemes[key] = dict(scheme)
        requirements.append({key: scopes})
    return schemes, requirements


def to_a2a_card(facts: SmAgentFacts, slug: str, domain: str, base_url: str) -> A2AAgentCard:
    """Translate facts into an A2A v1.0 AgentCard the NANDA Index v2 accepts.

    Every field the Index's card check requires is populated from the facts; the only
    values present that the source did not declare are the ``JSONRPC`` binding (the
    facts carry a URL, not a wire protocol), ``text/plain`` when no skill names a
    media type, and the ``general`` tag when the agent lists no capability skills.
    """
    runtime = _runtime_url(facts)
    base = base_url.rstrip("/")
    tags = _skill_tags(facts)
    schemes, requirements = _security(facts)
    return A2AAgentCard(
        protocolVersion=A2A_PROTOCOL_VERSION,
        name=facts.agent_name,
        description=facts.description,
        # Legacy top-level endpoint, kept for pre-v1.0 readers; the Index reads it
        # only when `supportedInterfaces` is absent.
        url=runtime,
        supportedInterfaces=[
            A2AAgentInterface(
                url=runtime,
                protocolBinding=A2A_DEFAULT_BINDING,
                protocolVersion=A2A_PROTOCOL_VERSION,
            )
        ],
        version=facts.version,
        # Only capabilities the source declared. `"pushNotifications": False` was
        # an invented negative claim: the source never said it lacked them.
        capabilities={"streaming": facts.capabilities.streaming},
        securitySchemes=schemes,
        securityRequirements=requirements,
        defaultInputModes=_default_modes(facts.skills, "inputModes"),
        defaultOutputModes=_default_modes(facts.skills, "outputModes"),
        skills=[_to_a2a_skill(s, tags) for s in facts.skills],
        provider={"organization": facts.provider.name, "url": facts.provider.url},
        meta={
            # An ARD domain-anchored resource identifier (AIR URN), the form the
            # NANDA Index keys entries on. The previous `urn:ai:domain:<domain>:...`
            # is refused by the Index outright, so a card carrying it named this
            # agent with a string nothing upstream would accept. The publisher
            # domain is lower-cased because the Index normalises it that way and an
            # identifier that differs only in case is a different string here.
            "identifier": f"urn:air:{domain.lower()}:agent:{slug}",
            "publicUrl": f"{base}/cards/{slug}.json",
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
