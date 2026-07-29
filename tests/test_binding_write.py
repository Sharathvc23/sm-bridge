"""Wiring tests for the authenticated delegated-write endpoint.

Crypto-free: the authorizer and authenticator are fakes, so these exercise only
what the registry owns — routing, verdict→HTTP mapping, the replay guard, the
RFC 6962 log growing, and state application. Real Ed25519 + grant/authority
verification live behind the injected seams and are tested by their provider.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge import (
    BindingStore,
    WriteVerdict,
    create_binding_write_router,
)
from sm_bridge.binding_write import canonical_log_entry
from sm_bridge.tlog import MerkleLog, leaf_hash, root_from_inclusion


class FakeAuthenticator:
    def authenticate(self, payload: bytes, store_did: str, signature: str) -> bool:
        return signature == "valid"


class FakeAuthorizer:
    def __init__(self, verdict: WriteVerdict):
        self.verdict = verdict

    def authorize(self, grant, request, issued_at, store_did):
        return self.verdict


def _client(authorizer, store=None, log=None):
    app = FastAPI()
    router = create_binding_write_router(
        authorizer=authorizer, authenticator=FakeAuthenticator(), store=store, log=log,
    )
    app.include_router(router)
    return TestClient(app)


def _body(signature="valid", nonce="n1", subject="john@hotmail.com", **over):
    b = {
        "grant": {"grant_id": "dat:did:key:zOwner:abcd"},
        "op": "binding.update_target",
        "subject": subject,
        "fields": {"agent_card_url": "https://cards.acme-store.example/john"},
        "target_host": "cards.acme-store.example",
        "agent_role": "personal-assistant",
        "issued_at": "2026-07-28T12:00:00Z",
        "nonce": nonce,
        "store_did": "did:key:zStore",
        "store_signature": signature,
    }
    b.update(over)
    return b


def test_satisfied_write_applied_and_logged():
    store, log = BindingStore(), MerkleLog(origin="sm-bridge/bindings")
    client = _client(FakeAuthorizer(WriteVerdict("SATISFIED")), store, log)
    r = client.post("/bindings/write", json=_body())
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "applied"
    assert data["binding"]["fields"]["agent_card_url"].endswith("/john")
    assert data["binding"]["lifecycle_state"] == "active"
    assert data["log"]["tree_size"] == 1 and data["log"]["leaf_index"] == 0
    assert log.size == 1
    assert store.get("john@hotmail.com")["version"] == 1


def test_bad_store_signature_401():
    client = _client(FakeAuthorizer(WriteVerdict("SATISFIED")))
    r = client.post("/bindings/write", json=_body(signature="forged"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "store_signature_invalid"


def test_violated_403():
    client = _client(FakeAuthorizer(WriteVerdict("VIOLATED", "field_out_of_scope")))
    r = client.post("/bindings/write", json=_body())
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "field_out_of_scope"


def test_indeterminate_409():
    client = _client(FakeAuthorizer(WriteVerdict("INDETERMINATE", "o1_not_established")))
    r = client.post("/bindings/write", json=_body())
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "o1_not_established"


def test_nonce_replay_rejected_and_not_logged():
    store, log = BindingStore(), MerkleLog(origin="sm-bridge/bindings")
    client = _client(FakeAuthorizer(WriteVerdict("SATISFIED")), store, log)
    assert client.post("/bindings/write", json=_body(nonce="dup")).status_code == 200
    r = client.post("/bindings/write", json=_body(nonce="dup"))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "nonce_replayed"
    assert log.size == 1  # the replay left no leaf


def test_merkle_log_inclusion_proof_round_trips():
    store, log = BindingStore(), MerkleLog(origin="sm-bridge/bindings")
    client = _client(FakeAuthorizer(WriteVerdict("SATISFIED")), store, log)
    # Three distinct writes → tree big enough (>=3) for RFC 6962 proofs.
    for i in range(3):
        r = client.post("/bindings/write",
                        json=_body(nonce=f"n{i}", subject=f"user{i}@example.com"))
        assert r.status_code == 200
    size = log.size
    assert size == 3
    # Reconstruct leaf 0 and verify its inclusion against the current root.
    entry0 = canonical_log_entry({
        "op": "binding.update_target", "subject": "user0@example.com",
        "fields": ["agent_card_url"], "store_did": "did:key:zStore",
        "grant_id": "dat:did:key:zOwner:abcd", "issued_at": "2026-07-28T12:00:00Z",
        "nonce": "n0", "version": 1,
    })
    proof = log.inclusion_proof(0)
    assert root_from_inclusion(leaf_hash(entry0), 0, size, proof) == log.root()
