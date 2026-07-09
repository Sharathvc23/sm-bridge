"""Adversarial: a federated peer cannot launder a proof claim into this registry.

The delta-sync path must never re-serve a peer's `proof` as this registry's own
verification. By default an inbound proof is downgraded to NOT_VERIFIED; a peer must be
explicitly trusted, or the record re-verified locally, to carry anything stronger.
"""

from __future__ import annotations

from sm_bridge.federation import pull_deltas
from sm_bridge.store import DeltaStore
from sm_bridge.trust import ProofResult, ProofStatus


def _delta_with_proof(proof: dict | None) -> dict:
    agent = {
        "id": "peer-agent",
        "agent_name": "Peer Agent",
        "label": "x",
        "description": "d",
        "version": "1.0.0",
        "provider": {"name": "Peer", "url": "https://peer.example"},
        "endpoints": {"static": ["https://peer.example/a"]},
        "capabilities": {"modalities": ["text"]},
        "skills": [{"id": "s", "name": "S", "description": "s"}],
    }
    if proof is not None:
        agent["proof"] = proof
    return {"seq": 1, "action": "upsert", "agent": agent}


def _fetch(deltas):
    def _f(url):
        return {"deltas": deltas}

    return _f


# The core attack: a hostile peer asserts VERIFIED to get its record trusted.
_FORGED_VERIFIED = {
    "profile": "ed25519-agentcard",
    "method": "ed25519-jcs",
    "status": "VERIFIED",
    "evidence_ref": "ed25519:totally-made-up",
}


def test_peer_verified_claim_is_downgraded_by_default():
    store = DeltaStore()
    pull_deltas("https://peer.example", store, fetch=_fetch([_delta_with_proof(_FORGED_VERIFIED)]))
    ingested = store.get(1).agent
    # the peer said VERIFIED; we did not verify it → it must NOT be VERIFIED in our store
    assert ingested.proof.status is ProofStatus.NOT_VERIFIED
    assert ingested.proof.profile == "federation"
    assert "not re-verified" in ingested.proof.failure_reason


def test_trust_peer_proof_optin_keeps_claim():
    store = DeltaStore()
    pull_deltas(
        "https://peer.example", store,
        fetch=_fetch([_delta_with_proof(_FORGED_VERIFIED)]), trust_peer_proof=True,
    )
    # explicit operator opt-in to trust this peer → claim retained
    assert store.get(1).agent.proof.status is ProofStatus.VERIFIED


def test_local_reverify_wins():
    store = DeltaStore()

    def reverify(agent, delta):
        return ProofResult.failed(profile="ed25519-agentcard", method="ed25519-jcs",
                                  reason="local re-verification rejected the forged signature")

    pull_deltas(
        "https://peer.example", store,
        fetch=_fetch([_delta_with_proof(_FORGED_VERIFIED)]), reverify=reverify,
    )
    proof = store.get(1).agent.proof
    assert proof.status is ProofStatus.FAILED
    assert "rejected the forged signature" in proof.failure_reason


def test_legacy_peer_dict_also_downgraded():
    # a peer sending a pre-v0.4 opaque proof dict is likewise not trusted
    store = DeltaStore()
    pull_deltas("https://peer.example", store,
                fetch=_fetch([_delta_with_proof({"method": "sha256", "digest": "x"})]))
    assert store.get(1).agent.proof.status is ProofStatus.NOT_VERIFIED
