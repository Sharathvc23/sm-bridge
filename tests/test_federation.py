"""Tests for the federation sync client (pull_deltas + FederationPoller).

A fake ``fetch`` mimics a real peer's ``/nanda/deltas?since=`` semantics
(only ``seq > since`` is returned) so no network or httpx is required.
"""

from __future__ import annotations

import time
from typing import Any

from sm_bridge import (
    DeltaStore,
    FederationPoller,
    SmAgentFacts,
    SmAuthentication,
    SmCapabilities,
    SmEndpoints,
    SmProvider,
    SmSkill,
    current_facts,
    default_slug,
    pull_deltas,
)


def _facts(slug: str) -> SmAgentFacts:
    return SmAgentFacts(
        id=f"did:web:example.com:agents:{slug}",
        handle=SmAgentFacts.create_handle("peer", "agents", slug),
        agent_name=f"Agent {slug}",
        label=slug,
        description="An agent.",
        version="1.0.0",
        provider=SmProvider(name="Peer", url="https://peer.example"),
        endpoints=SmEndpoints(static=["https://runtime.example"]),
        capabilities=SmCapabilities(
            modalities=["text"], skills=["x"], authentication=SmAuthentication(methods=["ed25519"])
        ),
        skills=[SmSkill(id="x", description="do x")],
    )


def _delta(seq: int, action: str, slug: str) -> dict[str, Any]:
    return {
        "seq": seq,
        "action": action,
        "recorded_at": "2026-06-24T00:00:00+00:00",
        "agent": _facts(slug).model_dump(mode="json"),
        "signature": None,
    }


def _peer_fetch(log: list[dict[str, Any]]):
    """Return a fetch() that serves `log` with real `seq > since` filtering."""

    def fetch(url: str) -> dict[str, Any]:
        since = int(url.rsplit("since=", 1)[1])
        deltas = [d for d in log if d["seq"] > since]
        nxt = max((d["seq"] for d in log), default=since) + 1
        return {
            "registry_id": "peer",
            "generated_at": "2026-06-24T00:00:00+00:00",
            "deltas": deltas,
            "next_seq": nxt,
        }

    return fetch


def test_pull_applies_upserts_and_returns_cursor() -> None:
    store = DeltaStore()
    log = [_delta(1, "upsert", "navigator")]
    res = pull_deltas("https://peer.example", store, 0, fetch=_peer_fetch(log))
    assert res.applied == 1
    assert res.cursor == 1
    assert "navigator" in current_facts(store, default_slug)


def test_pull_is_incremental_by_cursor() -> None:
    store = DeltaStore()
    log = [_delta(1, "upsert", "navigator")]
    fetch = _peer_fetch(log)

    first = pull_deltas("https://peer.example", store, 0, fetch=fetch)
    assert first.applied == 1

    # nothing new since cursor -> no re-application
    second = pull_deltas("https://peer.example", store, first.cursor, fetch=fetch)
    assert second.applied == 0
    assert second.cursor == first.cursor


def test_pull_propagates_delete() -> None:
    store = DeltaStore()
    log = [_delta(1, "upsert", "navigator"), _delta(2, "delete", "navigator")]
    res = pull_deltas("https://peer.example", store, 0, fetch=_peer_fetch(log))
    assert res.applied == 2
    assert res.cursor == 2
    assert "navigator" not in current_facts(store, default_slug)


def test_poller_sync_once_advances_cursor() -> None:
    store = DeltaStore()
    log = [_delta(1, "upsert", "navigator")]
    poller = FederationPoller("https://peer.example", store, fetch=_peer_fetch(log))

    r1 = poller.sync_once()
    assert r1.applied == 1 and poller.since == 1
    # second pass: peer grows by one
    log.append(_delta(2, "upsert", "scheduler"))
    r2 = poller.sync_once()
    assert r2.applied == 1 and poller.since == 2
    assert {"navigator", "scheduler"} <= set(current_facts(store, default_slug))


def test_poller_thread_start_stop() -> None:
    store = DeltaStore()
    log = [_delta(1, "upsert", "navigator")]
    poller = FederationPoller(
        "https://peer.example", store, interval=0.01, fetch=_peer_fetch(log)
    )
    poller.start()
    try:
        deadline = time.time() + 2.0
        while "navigator" not in current_facts(store, default_slug) and time.time() < deadline:
            time.sleep(0.02)
        assert "navigator" in current_facts(store, default_slug)
    finally:
        poller.stop()
    assert poller._thread is None
