# Getting listed on the NANDA Index

This is the end-to-end path for an org that wants to be discoverable through the
NANDA Index: what you register, what the Index then expects you to serve, and which
half of that this library gives you.

The short version: **sm-bridge serves; it does not register.** Registration is a few
authenticated calls you make once. Serving is what the bridge is for, and the Index
only ever fetches two things from you.

> **For the current specification, see [nandaindex.org](https://nandaindex.org).** This
> page describes what the Index expects of a registry as of this release, which is a
> moving target — the identifier scheme and the media-type vocabulary have both changed
> once already. Where the two disagree, nandaindex.org is authoritative and this page is
> the thing to fix.

## 1. Register your entry

Registration is an authenticated flow against the Index (create the org, raise a DNS
TXT challenge, verify the domain). The bridge deliberately has no client for it:
it needs an account, a role, and a challenge you satisfy in your own DNS, none of
which a registry library should hold.

What matters here is the two fields that decide how the Index treats you afterwards.

### `hosting_path` — how the Index routes you

Send a hosting path and let the Index derive the rest. It owns `resolutionRole` and
`preferredDiscovery`; a record that asserts them by hand is asserting values the Index
will derive anyway.

| `hosting_path` | Media type you get | How the Index treats you |
|---|---|---|
| `registry` | `application/ai-catalog+json` | **Fanned out** — your registry is queried live at search time. This is the path for an org with many agents. |
| `smb` | `application/a2a-agent-card+json` | One agent, synthesised from your record. No call to you. |
| `dns-svcb` | `application/a2a-agent-card+json` | One agent, discovered through your DNS SVCB record. |
| `personal` | `application/a2a-agent-card+json` | One agent for a domain-less individual, anchored to the card host. |

A fifth shape exists that you do not register into: `application/vnd.ans-registry+json`,
the Agent Name Service pointer-only type. The Index points at an ANS instance and never
resolves into it. That is the entry mode this library models with `RegistryEntry` and
`ANSEntryConverter` — see [`quilt-onboarding.md`](quilt-onboarding.md).

### `registry_url` — where the Index comes back to

For `hosting_path=registry`, this is the base URL of your **AI-Catalog gateway**: the
`base_url` you pass to `create_gateway_router`. The Index appends paths to it, so it
must be the gateway's root, not a specific endpoint.

Only orgs with a `registry_url` are eligible for the Index's agentic search at all.

### Your identifier

The Index keys every entry on an ARD domain-anchored resource identifier (AIR URN):

```
urn:air:<publisher-FQDN>:<namespace...>:<short-name>
```

The publisher FQDN is the domain you proved control of, which is what makes the
identifier yours. **Send no identifier and let the Index derive it** — for
`hosting_path=registry` it derives `urn:air:<your-domain>:catalog:root`. If you do send
one it must be anchored to the domain you are registering, or it is refused.

Two older forms are refused outright and are worth knowing because they turn up in
pre-ARD code: `urn:ai:domain:<domain>:...` (a different URN namespace), and any
identifier anchored to a domain you have not proven.

Put your own conventions under `extensions`, keyed by a reverse-DNS namespace
(`org.projectnanda`). Flat metadata keys alongside the record are dropped — silently,
on an otherwise successful write — so a write that returns `201` is not by itself proof
your convention landed.

## 2. Serve what the Index fetches

Mount the gateway, and the two things the Index asks for are already answered:

```python
from fastapi import FastAPI
from sm_bridge import DeltaStore, create_gateway_router

app = FastAPI()
app.include_router(
    create_gateway_router(
        delta_store,
        base_url="https://registry.example.com",   # == registry_url at the Index
        domain="example.com",                      # your proven publisher FQDN
    )
)
```

### `GET /agents/search?q=...` — the fan-out hop

This is the **only** path the Index fetches from a registrant. An entry registered with
`application/ai-catalog+json` is expanded at query time by fetching it, and the Index
reads `entries` off the response.

A registry that does not answer is recorded as **unreachable** and contributes nothing
to the Index's search, however complete its catalog. There is no error surfaced to you
when this happens: your org is simply absent from results. If you are serving a
hand-rolled registry hop rather than this gateway, check that this exact path answers —
a route like `GET /agents/{id}` will match `search` as an id and 404.

A query that matches nothing is a `200` with no entries, which is a different answer
from being unreachable: the first says you were asked and had nothing, the second is a
claim about your registry.

### `GET /agents/{slug}` and `GET /cards/{slug}.json` — the walk

A resolver that found your `registry_url` in the Index walks it: your catalog entry,
then the A2A card at `CatalogEntry.url`. The gateway serves both, plus
`/.well-known/ai-catalog.json` for consumers that want the whole catalog.

## 3. What arrives when someone resolves you

The Index's `/api/v1/resolve?locator=<air-urn>` returns `{locator, identifier, match,
index_record}`, and hands the next hop **`identifier` — the short name alone**, not the
full URN. For an org-level locator that is `root`, from
`urn:air:<your-domain>:catalog:root`.

So your registry must answer to the short name. The bridge's `/nanda/resolve` accepts
both: a bare short name, and the full AIR URN anchored to your own domain (reduced to
the short name). An AIR URN naming a *different* publisher is rejected with a `400` —
never a `404`, because a `404` is a positive claim of absence and a corroborator would
read it as this registry asserting something about another publisher's namespace.

One trap worth knowing on the consuming side: `match` can be `publisher`, meaning the
Index had no entry for that exact identifier and returned the publisher's catalog entry
instead. **A `200` is therefore not proof the answer is about the agent you asked for.**
Check `match`, and look the short name up inside the catalog rather than treating the
record as the agent's.

## 4. Trust, separately

Getting listed makes you reachable. It says nothing about whether anything you serve is
verifiable. That is the other half of this library — a trust profile per source,
normalised to one proof block — and it is independent of everything above. See
[`trust-profiles.md`](trust-profiles.md).

---

The Index's own contract is specified at [nandaindex.org](https://nandaindex.org); check
there first if something here does not match what the Index does.
