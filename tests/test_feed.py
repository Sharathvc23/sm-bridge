"""The delta log projected as a signed sm-feed (`[feed]` extra): build, subscribe,
verify completeness, detect a tamper. Additive — `/nanda/deltas` is untouched."""

from __future__ import annotations

import copy

import pytest

pytest.importorskip("sm_feed")

from sm_arp import Identity  # noqa: E402

from sm_bridge import DeltaStore  # noqa: E402
from sm_bridge.feed import DELTA_FEED_TYPE, build_delta_feed, read_delta_feed  # noqa: E402
from sm_bridge.models import (  # noqa: E402
    SmAgentFacts,
    SmAuthentication,
    SmCapabilities,
    SmEndpoints,
    SmProvider,
    SmSkill,
)

AT = "2026-06-24T00:00:00+00:00"


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


def _store(n: int) -> DeltaStore:
    store = DeltaStore()
    for i in range(n):
        store.add("upsert", _facts(f"a{i}"))
    return store


def test_build_then_read_yields_verified_deltas():
    page = build_delta_feed(_store(3).since(0), Identity.generate(), generated_at=AT)
    ok, reason, deltas, head = read_delta_feed(page, expected_prev_hash=None)
    assert ok, reason
    assert [d["action"] for d in deltas] == ["upsert"] * 3
    assert [d["registry_seq"] for d in deltas] == [1, 2, 3]
    assert all(d["type"] == DELTA_FEED_TYPE for d in deltas)
    assert head["seq"] == 2


def test_incremental_read_from_cursor():
    store = _store(2)
    idn = Identity.generate()
    _, _, _, head = read_delta_feed(build_delta_feed(store.since(0), idn, generated_at=AT))
    store.add("delete", _facts("a2"))
    page = build_delta_feed(store.since(0), idn, generated_at=AT, since=head["seq"])
    ok, reason, deltas, _ = read_delta_feed(page, expected_prev_hash=head["entry_hash"])
    assert ok and len(deltas) == 1 and deltas[0]["action"] == "delete"


def test_tampered_page_yields_no_deltas():
    idn = Identity.generate()
    page = build_delta_feed(_store(3).since(0), idn, generated_at=AT)
    page["entries"][1]["payload"]["action"] = "revoke"  # tamper a signed entry
    ok, reason, deltas, head = read_delta_feed(page, expected_prev_hash=None)
    assert not ok and deltas == [] and head is None


def test_projection_is_deterministic():
    # Same deltas + same identity ⇒ byte-identical feed, so ?since is stable.
    idn = Identity.from_seed(b"\x07" * 32)
    deltas = _store(3).since(0)
    a = build_delta_feed(deltas, idn, generated_at=AT)
    b = build_delta_feed(copy.deepcopy(deltas), idn, generated_at=AT)
    assert a["entries"] == b["entries"] and a["head"] == b["head"]
