# Changelog

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
