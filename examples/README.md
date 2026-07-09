# Examples

Runnable, offline demos of the two scenarios NANDA is uniquely positioned to serve — the
cross-registry switchboard, and trust for an identity with no domain of its own. Each mints
its own keys in-process and needs no external services.

```bash
pip install "sm-bridge[trust]"
python examples/demo1_switchboard.py
python examples/demo2_domainless_delegation.py
```

## Demo 1 — the cross-registry switchboard (`demo1_switchboard.py`)

One resolve surfaces an agent from an ANS registry and an agent from a non-ANS catalog
through the *same* switchboard, with a uniform response. The switchboard holds **one entry
per registry, never one per agent**:

- the ANS registry resolves by **delegation** (a pointer to ANS's own resolver — the
  switchboard reads nothing on its behalf, and never lists ANS's agents);
- the non-ANS catalog is **hosted** and resolves locally with a real verified proof.

## Demo 2 — ANS-grade trust for a domainless identity (`demo2_domainless_delegation.py`)

An identity with only a `did:key` — no domain to anchor on — earns scoped, time-bounded,
revocable trust via an **ES256 (P-256) delegation** from a domain-holding, ANS-registered
provider. The demo verifies an honest delegation and then shows, with real cryptography, that
**escalation, expiry, and revocation are each rejected** with a verbatim reason.
