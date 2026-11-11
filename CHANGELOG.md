# Changelog

## [0.11.0] — 2026-11-11

### Changed — BREAKING

- **The A2A card at `/cards/{slug}.json` is an A2A v1.0 AgentCard.** It was an A2A
  v0.2-era document — a top-level `url` only, an `authentication: {schemes}` block the
  protocol removed in v0.3, no `defaultInputModes`/`defaultOutputModes`, skills with
  neither `id` nor `tags`, and no protocol version — and the NANDA Index v2's card check
  (`server/src/services/cardValidation.ts`) rejected it on every one of those points. The
  card now carries `protocolVersion: "1.0"`, `supportedInterfaces: [{url, protocolBinding:
  "JSONRPC", protocolVersion: "1.0"}]`, `securitySchemes` + `securityRequirements` derived
  from `capabilities.authentication.methods` (methods with a lossless A2A rendering get
  it; others are carried verbatim; `none` yields nothing), `defaultInputModes` /
  `defaultOutputModes` (the union of the skills' modes rendered as media types, falling
  back to `text/plain`), and skills each with `id`, `name` (the source's `name` extra or
  the id), `description`, non-empty `tags` (`capabilities.skills` or `general`),
  `inputModes` and `outputModes`. The legacy top-level `url` is kept for pre-v1.0 readers
  (the Index falls back to it only when `supportedInterfaces` is absent), and `_meta` is
  unchanged. `A2AAgentCard.model_dump()` / `model_dump_json()` emit `_meta` under its
  wire name by default, so a hand-rolled dump is the document the router serves.
  **Migration:** readers of `card["authentication"]["schemes"]` should read
  `card["securitySchemes"]` / `card["securityRequirements"]`; readers of
  `card["skills"][i]["name"]` now get the display name and should read `["id"]` for the
  identifier. A test runs a Python rendering of the Index's own check against the card.

- **`ans-txt` returns `VERIFIED` only from DNSSEC-validated answers.** It returned
  `VERIFIED` from a plain TXT lookup, which proves nothing about who controls the zone
  and contradicted the README's "every VERIFIED is a real signature, DNS, or Merkle
  check". The resolver seam now reports `DnsAnswer(records, authenticated)`; the default
  dnspython resolver requests DNSSEC (EDNS DO + AD) and reports the response's AD bit.
  Every load-bearing record (`_ans`, `_ans-badge`, at every vantage) must be
  authenticated, else the verdict is `NOT_VERIFIED` with reason `dnssec_not_validated`
  naming what was not. A resolver returning a bare `list[str]` is still accepted and
  treated as unauthenticated, so a seam that says nothing about DNSSEC can never produce
  a pass. Split-horizon and expected-url mismatch stay `FAILED`, decided before the gate.
  **Migration:** a deployment whose resolver does not validate DNSSEC will now see
  `NOT_VERIFIED` where it saw `VERIFIED`; that is the honest verdict for what it checked.

- **`nanda-delegation` uses the verifier's clock and revocation view.** The profile read
  `now` and `status_tokens` from the evidence bundle — the thing the subject under
  verification hands over — so a revoked or expired delegate could assert `ACTIVE`, pick
  the instant it was judged at, and be `VERIFIED`. `now` is now the verifier's UTC wall
  clock; an evidence-supplied `now` is ignored unless the profile is built with
  `trust_evidence_clock=True`, which is **test-only** (it pins offline fixtures) and
  defaults off. Evidence-supplied `status_tokens` are the subject's claim and are
  ignored; rule 5 is checked against a verifier-side `status_source`
  (`delegationId -> token | None`, sync or async) passed to
  `NandaDelegationProfile(status_source=...)`. Without one, a chain that passes every
  other check is `NOT_VERIFIED (status_unverified)`. Structural violations stay `FAILED`
  regardless. `sm-bridge verify delegation` gains `--status-source <json>` and
  `--trust-evidence-clock`; without a status source it exits `2`.
  **Migration:** pass your revocation view as `status_source`; drop `now` and
  `status_tokens` from bundles you produce (they are ignored).

- **A `VERIFIED` must name a registered verification method.** `ProofResult.verified()`
  accepted any non-empty strings, so the honesty invariant guarded only against a missing
  `evidence_ref`. The in-tree methods are pre-registered in core; a third-party profile
  calls `sm_bridge.trust.base.register_verification_method()` once. `FAILED` and
  `NOT_VERIFIED` are unrestricted. An inbound record claiming `VERIFIED` via a method this
  registry does not implement is downgraded on parse to `NOT_VERIFIED
  (unregistered-method)` rather than rejected (one record must not wedge a federation
  pull) or kept (laundering). The `trust/base.py` docstring now says plainly that
  construction is a shape check, not a guard that the check ran — that guarantee is each
  profile's, pinned by its tests.

- **The `integrity`, `governance`, `card` and `provenance` extras are gone, and `[all]`
  installs.** All four named `sm-model-*` packages that are not on PyPI, and `[all]`
  included them, so `pip install "sm-bridge[all]"` failed outright. `[all]` is now the
  union of the published extras: federation, trust, tlog, feed. The `Python :: 3.10`
  classifier is also removed; the package requires 3.11.

### Added

- **`cursor_mode="inclusive"` on `pull_deltas` and `FederationPoller`** (#30, unreleased
  until now). A peer using inclusive `since` and `next_seq = last + 1` caused the
  polling helper to replay its final entry forever. The exclusive default is unchanged;
  inclusive pages must report exactly the derived cursor, including unchanged empty
  pages, and both modes reject malformed or out-of-order rows and complete agent
  validation and proof re-verification before any store write. See
  [`docs/delta-cursors.md`](docs/delta-cursors.md) for the compatibility and recovery
  limits (no atomic import, no durable cursor; a store error can partially apply a page).

- **`FederationPoller.last_error`.** `_run` swallowed every exception with `pass`, so a
  peer that was down or serving malformed pages looked like a catalog that had stopped
  changing. A failed tick is now logged at `WARNING` under `sm_bridge.federation` with
  the traceback and kept on `last_error` until a later tick succeeds. The loop still
  retries.

- `A2AAgentInterface` and `A2AAgentSkill` are exported from `sm_bridge`.

### Fixed

- `to_catalog_entry` and `to_a2a_card` strip a trailing slash from `base_url`, so a
  `base_url` ending in `/` no longer yields `//cards/...` URLs.

### Documentation

- `CatalogEntry.updatedAt` is documented as the time the entry was **serialized**, not the
  time the record last changed; the facts carry no modification time and the gateway does
  not invent one (the delta log's `recorded_at` is the real event time).
- The quilt invariant ("one entry per registry, never one per agent") is stated as what
  it is: structural in entry mode, a **convention** in hosting mode. The README and
  `docs/quilt-onboarding.md` said the types enforced it; the per-agent `AgentConverter`
  seam cannot tell a catalog from a flattened registry.
- `docs/nanda-index-onboarding.md` lists the card fields the Index checks and where that
  rule text lives.

## [0.10.0] — 2026-10-29

### Added

- **`create_gateway_router(..., is_listed=...)` — a registry's own rule for who may be
  enumerated.** The gateway published everything in the `DeltaStore`, with no way to
  express "this agent exists but has not consented to be listed". A registry with such a
  rule therefore could not use the gateway at all, and hand-wrote the whole Index-facing
  surface instead — then had to keep its catalog, its feed and its re-seed agreeing with
  each other by hand. That is a gap in this library, not a quirk of the registry that hit
  it.

  `is_listed` is `(slug, facts) -> bool`, and it gates the two **enumerating** surfaces —
  `/.well-known/ai-catalog.json` and `/agents/search` — from a single computation, so a
  registry cannot publish two different claims about who it lists. Default `None` lists
  everything in the store, which is the previous behaviour exactly.

  It deliberately does **not** gate `/agents/{slug}` or `/cards/{slug}.json`. Those answer
  about an agent the caller already named, and neither available behaviour is honest: a
  `403` discloses the agent while refusing it, and a `404` is a positive claim of absence
  about an agent this registry is holding — which a corroborator reads as a false
  omission. The Index's own resolution hop for a legitimately registered entry also comes
  through that path, so gating it would `404` the Index against an agent that is properly
  listed on it.

  The boundary is therefore **withheld from the listing, still resolvable by name**, and
  it is pinned by a test rather than left to be discovered. A registry that needs an agent
  to be unreachable rather than unlisted should keep it out of the `DeltaStore`: absence
  from the store is the only honest way to say an agent is not here.

## [0.9.0] — 2026-10-29

### Removed — BREAKING

- **The deprecated `synthesized` extension field is gone**, as 0.8.0 said it would be in
  this release. `provenance.invented` carries the same fact and carries it for every
  field, not just `skills`.

  Removing it was not sufficient on its own, and the second half matters more than the
  first. The source's own metadata is spread into the same extension block, and the old
  marker was written *after* that spread precisely so a source could not shadow the
  bridge's statement about its own output. Delete the write and that protection goes with
  it: a source supplying `"synthesized": [...]` would land exactly where our marker used
  to be, and a consumer still reading the 0.7.0 field would read a **source-controlled**
  value believing it was ours.

  So the field is now actively absent rather than merely unwritten — a source cannot
  reoccupy it. A lagging reader gets nothing, which it can detect, instead of a plausible
  claim it cannot. Pinned by
  `test_a_source_cannot_reoccupy_the_removed_synthesized_field`.

  **Migration:** read `metadata[<ext>]["provenance"]["invented"]` and check for
  `"skills"`.

### Documentation

- **[`docs/nanda-index-onboarding.md`](docs/nanda-index-onboarding.md)** — the end-to-end
  path for getting an org listed on the NANDA Index: the `hosting_path` → media-type →
  routing table, what `registry_url` must point at, how the AIR URN identifier is derived
  (and the two older forms the Index refuses), the two paths the Index fetches from a
  registrant, and the `match: "publisher"` trap that makes a `200` from the Index's resolve
  not a claim about the agent you asked for. Points at
  [nandaindex.org](https://nandaindex.org) as the authoritative, current spec — what the
  Index expects is a moving target, and this page is the thing to fix when the two disagree.

  Written because the library serves the Index but never said what the Index expects, so
  the information lived in whichever consumer had most recently been broken by it. It also
  states plainly that **the bridge serves and does not register** — registration needs an
  account, a role and a DNS challenge, none of which belong in a registry library.

### Added

- **`GET /agents/search?q=...` on the AI-Catalog gateway — the NANDA Index's fan-out
  hop.** This is the one path the Index fetches from a registrant: an entry registered
  with the enterprise catalog media type is expanded at query time via
  `GET <registry_url>/agents/search?q=...`, and a registry that does not answer is
  recorded as **unreachable** and contributes nothing to the Index's search, however
  complete its catalog. A bridge-backed registry was in that position: the gateway
  served the catalog, the per-agent entry and the A2A card, but not the only path the
  Index actually calls.

  The response is a `CatalogDocument`, which already matched the Index's wire shape
  exactly — `{specVersion, entries}` with camelCase `identifier` / `displayName` /
  `mediaType` / `url` / `description` / `tags` / `version` / `updatedAt` / `metadata`.
  So this is a route, not a remodel, and it answers with the same entries as
  `/.well-known/ai-catalog.json`, narrowed by `q`.

  Matching is a case-insensitive substring over the fields an entry actually declares
  (name, description, tags, identifier), so a match can always be explained by
  something the source said. It is deliberately **not** a relevance ranking: the Index
  ranks across registries itself, and a score invented per registry would compete with
  that while meaning something different in each one.

  Two behaviours worth knowing, both pinned by tests:
  - A query matching nothing is a `200` with no entries, not an error. "Asked, nothing
    matched" and "unreachable" are different claims, and only the registry can tell
    them apart.
  - The route is registered **before** `/agents/{slug}`, so an agent whose slug is
    literally `search` is shadowed on that path. It remains in the catalog and remains
    a fan-out candidate.

### Fixed

- **The A2A card no longer names its agent with an identifier the Index refuses.**
  `to_a2a_card` put `urn:ai:domain:<domain>:agent:<slug>` in the card's `_meta`. The
  Index rejects that form outright, so every card the gateway served carried a
  self-identifier nothing upstream would accept. It is now the AIR URN
  `urn:air:<domain>:agent:<slug>`, with the publisher domain lower-cased as the Index
  normalises it — an identifier differing only in case is a different string
  downstream.

  **Breaking** for anything reading `_meta.identifier`, which is why it is called out
  rather than filed as a detail. The old value was not usable with the Index it named.

- **An AIR URN anchored to this registry's own domain now resolves against it.**
  The NANDA Index keys every entry on an ARD domain-anchored resource identifier —
  `urn:air:<publisher-FQDN>:<namespace...>:<short-name>` — and the publisher FQDN is
  the ownership anchor: the registrant proves control of it by DNS TXT challenge
  before the Index will issue an identifier under it.

  `0.7.0` refused every `urn:` as naming "a foreign authority by construction".
  That is true of a URN whose namespace carries its own authority, and it stays
  refused; it is not true of an AIR URN naming the FQDN we are. The bridge was
  rejecting, with a `400`, the one identifier the Index holds for its own agents.

  An AIR URN is now anchored the same way a `did:web` already was — publisher FQDN
  compared against `provider_url`, reduced to the short name when it matches, `None`
  (and so a `400`) when it names another publisher. Every other URN is unchanged.

  The Index's own `resolve` returns the short name alone, so a consumer that reads
  only that output was never affected; one holding the canonical identifier was. A
  registry onboarded through this library should not have to patch its own adapter
  when the Index changes how it names things — absorbing that is what the bridge is
  for.

  Two details, both deliberate:
  - The FQDN comparison drops any port and path from `provider_url` and lower-cases
    the result, because neither can appear in the segment being compared. This is
    `_publisher_fqdn`, kept separate from `_did_authority`, which must keep
    reproducing whatever a `did:web` carries.
  - The `urn:` scheme and the `air` NID are matched case-insensitively, per RFC 8141
    and as the Index normalises them. A URN in some other case previously fell
    through to be treated as a local agent id; it is now refused with the rest.

## [0.8.0] — 2026-08-27

### Changed — BREAKING

- **The delta log is append-only. Nothing an agent does is deleted.**
  `DeltaStore` pruned to `max_deltas=10000`, dropping the OLDEST deltas, while
  `current_facts` rebuilt the catalog by replaying from zero. An agent whose only
  `upsert` had aged out disappeared from the catalog — no error, no gap, and no
  way to tell it had ever been there.

  An agent's history is evidence. A registry that silently forgets what it served
  cannot be audited for what it served, which is the whole property this package
  is meant to support.

  `max_deltas` is deprecated. Passing it raises a `DeprecationWarning` and has no
  effect; accepting the argument and silently ignoring it would be its own lie.

- **`DeltaStore.snapshot()`** returns the most recent delta per agent, in
  sequence order, and `current_facts` uses it instead of replaying the log. A
  complete log must not make the read path grow with history. `delete` and
  `revoke` are kept in the snapshot — a removal is a fact about the agent, not
  the absence of one, and dropping it would resurrect the agent on the next
  rebuild.

  A subclass that persists deltas MUST override `snapshot()`; the default reads
  the in-memory index.


### Changed

- **A converted record now says what the source supplied and what this bridge
  did.** `to_sm` declares a total conversion, and it is lossy in both directions:
  a mandatory frame fills fields the source does not have, and drops fields it
  has no slot for. Neither was visible in the output, so a consumer could not
  tell a synthesised endpoint from a declared one.

  The extension block gains `provenance`, with three lists:

  - `invented` — `id` and `provider.did` (both munged from the provider URL),
    `endpoints.static` when the source declared none, `skills` when it declared
    none
  - `defaulted` — `label` when taken from the namespace, `skills[n].description`
    and `skills[n].id` when absent
  - `dropped` — skill keys the frame has no slot for

  `endpoints.static` matters most: it is the field corroboration compares.
  Synthesising an endpoint and serving it unmarked lets two registries agree on
  an address no source ever asserted — and self-corroboration cannot catch that,
  because two instances of one converter invent identically. The converter has to
  declare it because nothing downstream can infer it.

  Written after the source's own `metadata` is merged, so a source cannot rewrite
  the record of what we did.

- **`synthesized` is deprecated** in favour of `provenance.invented`. It shipped
  in 0.7.0 and is kept as an alias for one release; removed in 0.9.0.

- **The gateway stops inventing.** An A2A card for an agent reachable only via
  `dynamic` or `adaptive_resolver` had `url: ""`; it now falls back through both.
  `"pushNotifications": False` is gone — the source never said it lacked them.
  Catalog entries no longer carry `ttl_seconds: 3600` or `status: "active"`: a
  hardcoded TTL is a caching contract nothing honors, and the status was derived
  from nothing.

  **Still invented, and not fixed here:** `CatalogEntry.updatedAt` is the moment
  of serialization, not of modification. Fixing it needs a real modification time
  threaded in, which changes the signature.

### Added

- **This bridge is now swept by the corroboration stack in CI**
  (`tests/test_corroborates_itself.py`). Two instances serving the same agents
  must corroborate to `AGREE`; a divergence means this registry is
  misrepresenting its own data.

  Every fault fixed in 0.7.0 was this registry doing something the Quilt exists
  to detect — answering for an identifier scoped elsewhere, dropping fields from
  a peer's record, emitting claims the source never made. Pointing the auditor at
  ourselves turns that from a coincidence into a regression net.

  Verified by reverting each fix: the registry-scope check and the 400-not-404
  decision are both caught. `extra="allow"` is **not** — two instances of the
  same code truncate identically and agree. That boundary is pinned by
  `test_identical_invention_is_invisible_to_self_corroboration`, so the file is
  not read as stronger than it is.

  `sm-divergence` is a **dev** dependency. Nothing in `sm_bridge` imports it: this
  package is a registry, a thing the stack audits, and depending on it at runtime
  would invert that.

## [0.7.0] — 2026-08-27

Four fixes, all of the same shape: this bridge asserted things the source never
said. Three are breaking. **Upgrade is recommended for every deployment** — one
of these is a security fix.

Read the entries below before upgrading; two of them change what your registry
emits, and one changes which requests it answers.

### Fixed — claims the source never made

- **No certification block unless the source declared one.** `SimpleAgent.certification_level`
  defaulted to `"self-declared"`, so every converted agent carried a certification
  block naming this provider as issuer — including agents that never certified
  anything. The default is now `None` and no block is emitted without one.

  **Breaking** for anyone relying on the old default. The old behaviour asserted a
  trust claim on the source's behalf, indistinguishable in the output from one it
  actually made.

- **A placeholder skill is marked as synthesized.** NANDA requires `minItems: 1`,
  so a source with no skills cannot be represented without one. The placeholder
  stays — removing it would make the record schema-invalid — but the extension
  block now carries `"synthesized": ["skills"]` so a consumer can tell it from a
  skill the source declared, and the placeholder's description says what it is.

  The marker is written *after* the source's own `metadata` is merged, so a source
  cannot supply its own `synthesized` key to hide the fact.

- **`conformance_level` is computed, not asserted.** `ANSEntryConverter.to_entry`
  set `auditable` whenever a checkpoint and root keys were both non-empty strings.
  The field's own docstring says "Computed, not asserted", and
  `conformance.conformance_level` — the real predicate — was never called.

  `to_entry` now calls it. Presence of a checkpoint is not evidence that the
  checkpoint *verifies*; that needs a live check this converter does not perform.
  So the default is `basic`, and a caller that has actually verified passes
  `to_entry(checkpoint_verifies=True)`.

  **Breaking:** entries that previously reported `auditable` on presence alone now
  report `basic` until something verifies them.

### Fixed

- **A federated record keeps fields this model does not declare.** `pull_deltas`
  validates a peer's record into `SmAgentFacts` and stores it, and the gateway
  re-serves what was stored. Pydantic's default is `extra="ignore"`, so every
  undeclared field a peer sent was dropped silently — and we then re-served a
  truncated version of another registry's record as though it were complete,
  with nothing recording that anything had been lost.

  The AgentFacts record tree now inherits `SmRecord`, which sets
  `extra="allow"`. Unknown fields survive validation and round-trip through
  `model_dump`, at both the top level and inside nested objects such as `skills`.

  This is not a licence for this bridge to invent fields: our own converter
  populates only declared ones, so a record we build carries no extras, and a
  test pins that.

  The response wrappers (`SmAgentFactsIndexResponse`, `SmAgentFactsDelta`,
  `SmAgentFactsDeltaResponse`, `SmWellKnown`, `SmTool`, `SmToolsResponse`,
  `SmA2AMessage`) deliberately stay strict — they are our own output, and
  accepting undeclared fields there would let junk into our responses unnoticed.
  A test pins that boundary too.

### Fixed — security

- **An identifier naming another registry no longer resolves against this one.**
  `GET /nanda/resolve` reduced any identifier to a bare id and looked it up
  locally, so `@other-registry:ns/foo` and `did:web:other.example:agents:foo`
  both returned *this* registry's `foo`, carrying *this* registry's `proof`
  block. The caller had no way to tell the scope was ignored. `registry_id` was
  passed to the parser and never read.

  `_parse_agent_identifier` now takes `provider_url` as well and returns `None`
  for an identifier that names an authority we are not. A handle's registry is
  compared against `registry_id`; a `did:web` must be under this provider's host;
  a `urn:` names a foreign authority by construction and is refused.

  **Rejection is `400`, deliberately not `404`.** A `404` is a positive claim
  that the agent is absent. A corroborator comparing registries would read it as
  this registry asserting something about another registry's namespace, and could
  raise a false omission finding against it. A `400` carries no claim.

  Behaviour changes, both intended:
  - `ns:agent` is no longer split to `agent`. A colon is not evidence of a
    namespace — the old rule could not tell a local id from another registry's
    URN or DID, which is what made the flaw reachable.
  - `_parse_agent_identifier` is private, but its signature and return type
    changed (`str` to `str | None`, third argument added).

- **`[feed]` extra now requires `sm-feed>=0.2.0`.** `0.1.x` is incompatible with
  partial pages: `sm-feed` split the page wire version because relaxing the head
  constraint changed its verification contract. Complete pages still declare
  `feed-page/0.1` and a `0.1.x` subscriber verifies them unchanged; partial pages
  declare `feed-page/0.2`.
- **`read_delta_feed` accepts `expected_head`** and passes it to
  `sm_feed.verify_page`. This is the whole of sm-feed's rewind defence (SPEC §5
  rule 6): without it a registry can serve a validly signed head behind the history
  the puller already holds and the rewind is accepted. Optional for compatibility,
  and the docstring says plainly that it should always be passed.
- `read_delta_feed`'s fourth return value is now sm-feed's cursor object —
  `{seq, entry_hash, head, complete_to_head}`. `entry_hash` is still the next
  `expected_prev_hash`, so the existing idiom is unchanged; `head` is what to pass
  back as `expected_head`, and `complete_to_head` is `False` when the registry
  served a bounded prefix of a long backlog.
- Documentation links to the Verifiable Agent Feed now point at the published
  specification (https://verifeed.ai) instead of a repository that is not public.

## [0.6.0] — Verifiable Agent Feed extra

- **`[feed]` extra (additive, non-breaking):** `sm_bridge.feed.build_delta_feed` projects the
  delta log as a signed, hash-chained Verifiable Agent Feed (`sm-feed`); `read_delta_feed`
  verifies a page for authenticity + completeness and returns the verified deltas. Served
  **alongside** `/nanda/deltas` — no change to the existing endpoint, the delta store, or any
  core import. Opt in with `pip install 'sm-bridge[feed]'`.
- Fixed `sm_bridge.__version__` (was pinned at `0.4.1`) to track the release.

## [0.5.0] — authenticated delegated binding write

- Release the registry-side write surface merged in #4: `BindingStore`,
  `RequestAuthenticator`, and `create_binding_write_router` — a delegate applies an
  authenticated, signed binding change through it. These were on `main` but not in a
  published release; 0.5.0 puts them on PyPI (consumed by nanda-connect).

## [0.4.1] — docs

- README rewritten to lead with what the bridge is and does (commercial + OSS tone); removed a
  dead `agentfacts-format` link and trimmed the reference sections into the docs. No code changes.

## [0.4.0] — universal registry onboarding + verification

The v0.4 line turns sm-bridge from a NANDA publication layer into the **universal on-ramp for
the NANDA Index quilt**: any source onboards through one library and emerges with a
normalized, verifiable proof block, while the Index stays strictly pointer-only.

### Added

- **Trust-profile spine** (`sm_bridge.trust`): `ProofResult` (VERIFIED / FAILED /
  NOT_VERIFIED, with the cryptographic-honesty invariant enforced at construction — no
  VERIFIED without a real `evidence_ref`), the `TrustProfile` protocol, and `TrustRegistry`.
- **Six trust-profile adapters** (`[trust]` extra, lazy crypto imports):
  - `ed25519-agentcard` — the NANDA Index agent-card signing contract (JCS + ed25519).
  - `ans-scitt` — the ANS SCITT receipt contract (COSE_Sign1 + RFC 9162 Merkle + issuer binding).
  - `ans-txt` — the ANS `ANS_TXT` DNS discovery profile (split-horizon aware).
  - `dns-aid` — **consumes the upstream `dns-aid` package** (SVCB + DNSSEC + DANE).
  - `jws-catalog` — signed AI-Catalog verification (ES256 detached JWS over the JCS entries;
    catalog-hijack detection).
  - `nanda-delegation` — did:key delegation chains over **ES256 / P-256** detached JWS
    (scope containment, freshness, revocation).
- **Cross-registry switchboard** (`sm_bridge.switchboard`): one resolve surfaces agents from
  heterogeneous registries through a uniform result — entry-mode registries delegate,
  hosting-mode registries resolve locally with a verified proof. One entry per registry.
- **`sm-bridge verify` CLI**: verify a receipt / signed catalog / agent card / DNS-AID record /
  delegation from the terminal (exit 0 = VERIFIED, 1 = FAILED, 2 = NOT_VERIFIED).
- **Runnable demos** (`examples/`): the cross-registry switchboard and domainless-delegation
  scenarios, offline and self-contained.
- **Bidirectional ANS interop, verified against the real reference binaries**: a receipt sm-bridge
  produces is accepted by `ans-verify`, and a receipt the real `ans-tl` transparency log produces
  is verified by the `ans-scitt` profile (baked in as a fixture that runs without a Go toolchain).
- **Dual onboarding modes** (`sm_bridge.onboarding`): `RegistryEntry`, the `EntryModeConverter`
  protocol (no agent-iteration — quilt invariant enforced structurally), `ANSEntryConverter`,
  and `/nanda/registries` + entry-mode delegation-resolve router surface. `reliability_receipts`
  pass-through (attester identity mandatory, no grading).
- **Transparency-log extra** (`[tlog]`): RFC 6962 Merkle over the delta log, signed checkpoint,
  inclusion + consistency proofs (refused below treeSize 3), and `sm_bridge.conformance` — the
  Demo 3 auditor self-test (checkpoint signature, root recomputation, append-only, tamper
  detection). Computed `conformanceLevel`.
- ai-catalog spec alignment: `/.well-known/ai-catalog.json` now emits `{specVersion, host,
  entries}` per the Agent-Card/ai-catalog standard.

### Changed

- `SmAgentFacts.proof` is now a typed `ProofResult | None`. A pre-v0.4 opaque `proof` dict is
  accepted for back-compat but **downgraded to `NOT_VERIFIED(legacy-unverified)`** — it can no
  longer masquerade as verified. `SimpleAgentConverter` emits `ProofResult.legacy()` (it holds
  no cryptographic evidence) rather than a fabricated sha256 placeholder.
- `/nanda/resolve` is now `async` and carries a normalized proof block when a `TrustRegistry`
  is injected and the converter supplies `trust_evidence`.

### Compatibility

- The FastAPI + pydantic core never imports a crypto library (verified in CI); all verifiers
  live in `[trust]` / `[tlog]` and import lazily.
- All v0.3.x endpoints and shapes are preserved. The 51 pre-v0.4 tests pass unchanged except
  one that asserted the old opaque-proof shape (updated to the honest downgrade).

## [0.3.1]

NANDA AgentFacts converter, registry endpoints (`/nanda/*`), AI-Catalog + A2A gateway,
Quilt-style deltas, federation sync.
