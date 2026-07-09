"""Demo 1 — one query surfaces an ANS-registered agent and a non-ANS one through the same
switchboard. ANS resolves by delegation (the switchboard reads nothing on its behalf); the
non-ANS catalog resolves locally with a real verified proof. One entry per registry.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_bridge.converter import SimpleAgent, SimpleAgentConverter
from sm_bridge.onboarding import ANSEntryConverter
from sm_bridge.switchboard import Switchboard
from sm_bridge.trust import ProofStatus, TrustRegistry
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile, canonicalize

_KEY = Ed25519PrivateKey.generate()


class _SignedCatalog(SimpleAgentConverter):
    """A non-ANS source (an AI catalog) whose cards are really signed."""

    def trust_evidence(self, agent):
        facts = self.to_sm(agent)
        payload = facts.model_dump(mode="json", exclude_none=True)
        payload.pop("proof", None)
        sig = _KEY.sign(canonicalize(payload))
        return ("ed25519-agentcard",
                {"payload": payload, "signature_b64": base64.b64encode(sig).decode(),
                 "public_key": _KEY.public_key().public_bytes_raw()})


def _switchboard() -> Switchboard:
    sb = Switchboard(trust_registry=TrustRegistry([Ed25519AgentCardProfile()]))
    # registry 1: GoDaddy ANS — one entry, resolves ~140k agents on its own side
    sb.add_registry(ANSEntryConverter(registry_name="godaddy-ans",
                                      resolver_endpoint="https://ans.godaddy.example"))
    # registry 2: a non-ANS catalog the bridge hosts
    cat = _SignedCatalog(registry_id="acme-catalog", provider_name="Acme",
                         provider_url="https://acme.example", base_url="https://acme.example")
    cat.register(SimpleAgent(id="finance", name="Finance Agent", description="does finance", public=True))
    sb.add_hosting("acme-catalog", cat)
    return sb


def test_switchboard_lists_one_entry_per_registry():
    sb = _switchboard()
    assert sb.registry_names() == ["acme-catalog", "godaddy-ans"]
    # only the entry-mode (registry-scale) source appears as a quilt pointer entry
    assert [e.registry_name for e in sb.registries()] == ["godaddy-ans"]


@pytest.mark.asyncio
async def test_one_query_surfaces_ans_delegated_and_nonans_verified():
    sb = _switchboard()

    # ANS agent → delegation pointer; the switchboard reads nothing on ANS's behalf
    ans = await sb.resolve("godaddy-ans", "urn:ai:godaddy:agent-42")
    assert ans.kind == "delegated"
    assert ans.delegation.resolver_endpoint == "https://ans.godaddy.example"
    assert ans.agent is None  # never mirrored

    # non-ANS catalog agent → resolved locally with a genuinely VERIFIED proof
    cat = await sb.resolve("acme-catalog", "finance")
    assert cat.kind == "hosted"
    assert cat.agent.agent_name == "Finance Agent"
    assert cat.proof.status is ProofStatus.VERIFIED
    assert cat.proof.profile == "ed25519-agentcard"


@pytest.mark.asyncio
async def test_unknown_registry_raises():
    with pytest.raises(KeyError):
        await _switchboard().resolve("no-such", "x")
