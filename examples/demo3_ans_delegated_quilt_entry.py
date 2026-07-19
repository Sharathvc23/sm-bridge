"""Demo 3 — an ANS registry joins the quilt as exactly ONE entry.

The narrowest possible proof of the quilt's core invariant, isolated from
demo1_switchboard.py's broader two-registry story: a registry-scale source
(ANS, GoDaddy-scale — ~140k agents) onboards to the switchboard as a single
pointer, and resolving any agent under it returns a DELEGATION, never a
mirrored record.

This is structural, not a runtime check: ``ANSEntryConverter`` implements
``EntryModeConverter``, whose protocol has no ``list_agents``/``get_agent``/
``to_sm`` method at all — there is no code path through which this converter
could bulk-import ANS's agent catalog into the quilt, even by accident.

Also shows the honesty rule at admission: with no admission evidence
supplied, the entry is stamped NOT_VERIFIED rather than a mocked pass — an
unattested source can still join the quilt (registries are pointers, not
identities), but it says so.

Run offline, no external services:  python examples/demo3_ans_delegated_quilt_entry.py
"""

from __future__ import annotations

import asyncio

from sm_bridge import ANSEntryConverter, Switchboard, TrustRegistry
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile


def _rule(title: str) -> None:
    print(f"\n{'─' * 74}\n {title}\n{'─' * 74}")


def build_switchboard() -> tuple[Switchboard, ANSEntryConverter, TrustRegistry]:
    trust_registry = TrustRegistry([Ed25519AgentCardProfile()])
    sb = Switchboard(trust_registry=trust_registry)
    ans_entry = ANSEntryConverter(
        registry_name="acme-ans",
        display_name="Acme ANS Registry",
        resolver_endpoint="https://ans.acme.example",
        trust_profile="ans-scitt",
    )
    sb.add_registry(ans_entry)
    return sb, ans_entry, trust_registry


async def main() -> bool:
    sb, ans_entry, trust_registry = build_switchboard()

    _rule("The quilt holds ONE entry for ANS — never a roster of its agents")
    names = sb.registry_names()
    print(f" registry_names(): {names}")
    entry = sb.registries()[0]
    print(f" entry.registry_name    : {entry.registry_name}")
    print(f" entry.display_name     : {entry.display_name}")
    print(f" entry.resolver_endpoint: {entry.resolver_endpoint}")
    print(f" entry.trust_profile    : {entry.trust_profile}")
    print(f" entry.conformance_level: {entry.conformance_level}  (no tl_checkpoint/root_keys supplied)")

    _rule("Admission — no evidence supplied, so it joins honestly unattested")
    proof = await ans_entry.admit(trust_registry)
    print(f" proof.status: {proof.status.value}  (never a mocked pass — NOT_VERIFIED, stated plainly)")
    print(f" reason      : {proof.failure_reason}")

    _rule("Resolve an ANS-registered agent  →  DELEGATED, not mirrored")
    result = await sb.resolve("acme-ans", "urn:ai:domain:acme.example:agent:concierge")
    print(f" kind      : {result.kind}")
    print(f" pointer   : {result.delegation.resolver_endpoint}  (follow this to ANS; the quilt read nothing)")
    print(f" agent     : {result.agent}  (facts field — None: the quilt never fetched or stored a record)")
    print(f" note      : {result.delegation.note}")

    ok = (
        names == ["acme-ans"]
        and result.kind == "delegated"
        and result.agent is None
        and result.delegation.resolver_endpoint == "https://ans.acme.example"
    )
    _rule("Result")
    print(" ✓ ANS joined as exactly one quilt entry; resolution delegates back to it, unmirrored."
          if ok else " ✗ demo did not reach the expected state")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
