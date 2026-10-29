"""Demo 4 - verifying a VAID delegation chain through sm-bridge's trust spine.

Loads two of the VAID A2A extension's own published conformance vectors (bundled
inside the installed vaid-a2a wheel, no network and no repo checkout needed) and
runs them through VaidDelegationProfile: one chain that verifies cleanly, and the
same chain again with its middle link revoked.

Also shows the honesty rule this profile enforces on top of the upstream verdict:
with no revocation source configured at all, the clean chain is reported
NOT_VERIFIED, never a silent pass.

The revocation source is a constructor-injected VaidRevocationSource protocol, not a
concrete list type: the final section wires in a hand-rolled implementation (not
vaid-mint's InMemoryRevocationList) to show that any object shaped like the protocol
is accepted, not just the one bundled implementation.

Requires the [vaid] extra:  pip install 'sm-bridge[vaid]'
Run offline, no external services:  python examples/demo4_vaid_delegation.py
"""

from __future__ import annotations

import asyncio

from vaid_a2a.conformance import load_vector
from vaid_mint.revocation import InMemoryRevocationList, RevocationStatus

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.vaid_delegation import VaidDelegationProfile, VaidRevocationSource


class DemoRevocationSource:
    """A from-scratch VaidRevocationSource, independent of vaid-mint's own
    InMemoryRevocationList, to show that the protocol -- not that one class -- is the
    contract a production revocation backend needs to satisfy."""

    def __init__(self, revoked: set[str]) -> None:
        self._revoked = revoked

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        return (
            RevocationStatus.REVOKED
            if any(vaid_id in self._revoked for vaid_id in lineage)
            else RevocationStatus.NOT_REVOKED
        )


def _rule(title: str) -> None:
    print(f"\n{'-' * 74}\n {title}\n{'-' * 74}")


def _evidence_for(vector: dict) -> dict:
    return {
        "leaf": vector["inputs"]["leaf"],
        "chain": vector["inputs"]["chain"],
        "trust_config": vector["trust_config"],
        "requested_action": vector.get("requested_action"),
        "now": vector["verification_time"],
    }


async def main() -> bool:
    valid_vector = load_vector("01-valid-two-hop-chain.json")
    revoked_vector = load_vector("04-revoked-middle-link.json")

    _rule("A clean two-hop chain, verified with a revocation source wired up")
    clean_profile = VaidDelegationProfile(revocation=InMemoryRevocationList.assume_nothing_revoked())
    verified = await clean_profile.verify(None, _evidence_for(valid_vector))
    print(f" status       : {verified.status.value}")
    print(f" method       : {verified.method}")
    print(f" evidence_ref : {verified.evidence_ref}")
    assert verified.status is ProofStatus.VERIFIED

    _rule("The same shape of chain, with its middle link revoked")
    revocation = InMemoryRevocationList()
    for vaid_id in revoked_vector["revoked_vaid_ids"]:
        revocation.revoke(vaid_id)
    revoked_profile = VaidDelegationProfile(revocation=revocation)
    failed = await revoked_profile.verify(None, _evidence_for(revoked_vector))
    print(f" status         : {failed.status.value}")
    print(f" failure_reason : {failed.failure_reason}")
    assert failed.status is ProofStatus.FAILED  # a real rejection, not a shrug

    _rule("The honesty rule: no revocation source configured is NEVER a pass")
    unconfigured_profile = VaidDelegationProfile(revocation=None)
    not_verified = await unconfigured_profile.verify(None, _evidence_for(valid_vector))
    print(f" status         : {not_verified.status.value}")
    print(f" failure_reason : {not_verified.failure_reason}")
    assert not_verified.status is ProofStatus.NOT_VERIFIED

    _rule("A revocation source that is a protocol, not a concrete list type")
    own_revocation_source: VaidRevocationSource = DemoRevocationSource(revoked=set())
    custom_profile = VaidDelegationProfile(revocation=own_revocation_source)
    custom_verified = await custom_profile.verify(None, _evidence_for(valid_vector))
    print(f" status       : {custom_verified.status.value}")
    print(f" method       : {custom_verified.method}")
    assert custom_verified.status is ProofStatus.VERIFIED

    print("\nAll four outcomes matched the honesty rule.")
    return True


if __name__ == "__main__":
    ok = asyncio.run(main())
    raise SystemExit(0 if ok else 1)
