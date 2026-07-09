# Quilt onboarding — entry mode vs hosting mode

The NANDA Index is the **switchboard**: a pointer-only quilt that stitches together many
independent registries, never a database that swallows their agents. sm-bridge is the
**onboarding tool** anyone uses to join the index. It onboards a source through one of two
modes, deliberately different in *shape* so the quilt invariant is enforced structurally.

## Verify at admission, delegate at resolution

Verification is an **onboarding-time** concern, not a resolution-time one. When a
registry-scale source joins, the bridge verifies its attestation **once** (`admit`) and
stamps the result into the entry's `proof`; the index then holds the pointer and **delegates
resolution back to the source**. The index never re-verifies a source's live records — the
source serves and verifies its own. Resolving an agent under an entry returns a delegation
pointer, not a verified mirror.

```python
conv = ANSEntryConverter(registry_name="acme-ans", resolver_endpoint="https://ans.acme.example",
                         trust_profile="ans-scitt", admission_evidence={...})
bridge = SmBridge(..., trust_registry=registry, entries=[conv])
await bridge.admit_entries(require_verified=True)   # verify once at join; refuse if unattested
```

## Decision table

| If the source… | Use | It becomes | Resolution |
|---|---|---|---|
| runs its own registry / resolver (ANS ~140K agents, ARD, another NANDA registry) | **Entry mode** | exactly **one** `RegistryEntry` (pointer + TL checkpoint + root keys) | delegated back to the source's `resolver_endpoint` — never mirrored here |
| has **no registry of its own** (an AI catalog, a domainless `did:key` operator, a small operator) | **Hosting mode** | per-agent `SmAgentFacts` via an `AgentConverter` | resolved locally by this bridge |

The rule in one line: **never per-agent-flatten a source that has its own registry.** Doing
so would turn the quilt into a monolith and put you on the hook for 140K records you don't
own.

## Why entry mode can't cheat

`EntryModeConverter` has **no `list_agents` / `get_agent` / `to_sm`** — only `to_entry()` and
`delegate(agent)`. There is no API on this path to enumerate or import a source's agents, so
bulk import isn't merely disallowed, it's *unrepresentable*. The invariant is enforced by the
type, not by a runtime check you could forget.

```python
from sm_bridge import ANSEntryConverter, SmBridge

ans = ANSEntryConverter(
    registry_name="acme-ans",
    resolver_endpoint="https://ans.acme.example",
    tl_checkpoint="…c2sp signed note…",
    root_keys=["acme-tl+deadbeef+…"],
    trust_profile="ans-scitt",
)
bridge = SmBridge(registry_id="quilt", provider_name="Q", provider_url="https://q.example",
                  entries=[ans])
```

- `GET /nanda/registries` → the list of pointer entries.
- `GET /nanda/registries/acme-ans` → the entry (+ its computed `conformance_level`).
- `GET /nanda/registries/acme-ans/resolve?agent=…` → a **delegation document** pointing at
  `resolver_endpoint`. The caller follows it to the source and verifies the returned card
  with the entry's `trust_profile` (e.g. `ans-scitt`).

## Hosting mode

Hosting mode is the existing `AgentConverter` seam. To attach real verification at resolve
time, implement `trust_evidence(agent) -> (profile_id, evidence)` on your converter; the
bridge verifies via the injected `TrustRegistry` and the resolved facts carry the
`ProofResult`. sm-bridge also speaks the [Agent-Card/ai-catalog](https://ai-catalog.io) spec
(`{specVersion, host, entries}`) at `/.well-known/ai-catalog.json` for catalog consumers.

## `reliability_receipts` (store-and-display, no grading)

Hosting-mode sources may pass through an `x_reliability_receipts` array. Each receipt **must**
carry an attester identity (`attester` / `attester_id` / `attester_did`); sm-bridge validates
that field is present and echoes the array. It does **not** score, rank, or weigh receipts —
grading is a consumer policy, not the bridge's.
