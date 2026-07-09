"""Demo 1 — NANDA as the cross-registry switchboard.

One resolve surfaces an agent from an ANS registry and an agent from a non-ANS catalog
through the *same* switchboard, with a uniform response — and the switchboard holds one
entry per registry, never a roster of every agent.

  - The ANS registry (GoDaddy-scale) resolves by **delegation**: the switchboard returns a
    pointer to ANS's own resolver and reads nothing on its behalf. ANS serves and verifies
    its ~140k agents itself; they are never listed in the switchboard.
  - The non-ANS catalog has no registry of its own, so the switchboard **hosts** it and
    attaches a real, verified proof.

Run offline, no external services:  python examples/demo1_switchboard.py
"""

from __future__ import annotations

import asyncio
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_bridge import (
    ANSEntryConverter,
    SimpleAgent,
    SimpleAgentConverter,
    Switchboard,
    TrustRegistry,
)
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile, canonicalize

_CATALOG_KEY = Ed25519PrivateKey.generate()


def _rule(title: str) -> None:
    print(f"\n{'─' * 74}\n {title}\n{'─' * 74}")


class SignedCatalogConverter(SimpleAgentConverter):
    """A non-ANS AI catalog whose agent cards are really signed (ed25519)."""

    def trust_evidence(self, agent):
        facts = self.to_sm(agent)
        payload = facts.model_dump(mode="json", exclude_none=True)
        payload.pop("proof", None)
        sig = _CATALOG_KEY.sign(canonicalize(payload))
        return (
            "ed25519-agentcard",
            {
                "payload": payload,
                "signature_b64": base64.b64encode(sig).decode(),
                "public_key": _CATALOG_KEY.public_key().public_bytes_raw(),
            },
        )


def build_switchboard() -> Switchboard:
    sb = Switchboard(trust_registry=TrustRegistry([Ed25519AgentCardProfile()]))

    # Registry 1 — an ANS registry. One entry; its ~140k agents resolve on ANS's side.
    sb.add_registry(
        ANSEntryConverter(
            registry_name="godaddy-ans",
            display_name="GoDaddy ANS",
            resolver_endpoint="https://ans.godaddy.example",
            trust_profile="ans-scitt",
        )
    )

    # Registry 2 — a non-ANS AI catalog with no registry of its own → hosted.
    catalog = SignedCatalogConverter(
        registry_id="acme-catalog", provider_name="Acme",
        provider_url="https://acme.example", base_url="https://acme.example",
    )
    catalog.register(
        SimpleAgent(id="finance", name="Finance Agent", description="Handles invoices and payments", public=True)
    )
    sb.add_hosting("acme-catalog", catalog)
    return sb


async def main() -> bool:
    sb = build_switchboard()

    _rule("The switchboard — one entry per registry (never one per agent)")
    print(" registries on the switchboard:", sb.registry_names())
    for entry in sb.registries():
        print(f"   • {entry.registry_name}: pointer → {entry.resolver_endpoint} "
              f"(entry-mode; agents resolve on the source's side)")

    _rule("Query 1 — an ANS-registered agent  →  DELEGATED")
    ans = await sb.resolve("godaddy-ans", "urn:ai:godaddy:agent-42")
    print(f" kind      : {ans.kind}")
    print(f" pointer   : {ans.delegation.resolver_endpoint}  (follow this to ANS; the switchboard read nothing)")
    print(f" mirrored? : {ans.agent is None} → the switchboard never lists ANS's agents")

    _rule("Query 2 — a non-ANS catalog agent  →  HOSTED + VERIFIED")
    cat = await sb.resolve("acme-catalog", "finance")
    print(f" kind      : {cat.kind}")
    print(f" agent     : {cat.agent.agent_name} — {cat.agent.description}")
    print(f" proof     : {cat.proof.status.value} via {cat.proof.profile}  (evidence: {cat.proof.evidence_ref})")

    ok = (
        ans.kind == "delegated" and ans.agent is None
        and cat.kind == "hosted" and cat.proof.status.value == "VERIFIED"
    )
    _rule("Result")
    print(" ✓ one query surfaced two heterogeneous registries through one switchboard:"
          if ok else " ✗ demo did not reach the expected state")
    print("   ANS delegated (pointer-only), the non-ANS catalog resolved locally with a verified proof.")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
