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


def test_expected_head_is_passed_through_and_catches_a_rewind():
    """sm-feed's rewind defence only runs when the puller supplies the head it
    pinned (SPEC §5 rule 6). Before 0.2.0 this argument did not exist and a
    registry could serve a validly signed head behind the history the puller
    already held. This pins the passthrough."""
    from sm_feed import build_signed_head

    idn = Identity.from_seed(b"\x09" * 32)
    store = _store(4)
    page = build_delta_feed(store.since(0), idn, generated_at=AT)
    ok, reason, _, cursor = read_delta_feed(page, expected_prev_hash=None)
    assert ok, reason

    # The registry now serves an empty page whose signed head sits behind the one
    # the puller already accepted.
    behind = page["entries"][1]
    rewound = {
        "version": "feed-page/0.1",
        "feed_id": page["feed_id"],
        "since": cursor["seq"],
        "entries": [],
        "head": build_signed_head(
            idn, seq=behind["seq"], entry_hash=behind["entry_hash"], generated_at=AT
        ),
    }

    ok, reason, deltas, _ = read_delta_feed(
        rewound, expected_prev_hash=cursor["entry_hash"], expected_head=cursor["head"]
    )
    assert not ok and deltas == []
    assert "rewind" in reason, reason

    # Omitting expected_head keeps the pre-0.2.0 behaviour: the rewind is accepted.
    ok, _, _, _ = read_delta_feed(rewound, expected_prev_hash=cursor["entry_hash"])
    assert ok, "documents why passing expected_head is not optional in practice"


def test_projection_is_deterministic():
    # Same deltas + same identity ⇒ byte-identical feed, so ?since is stable.
    idn = Identity.from_seed(b"\x07" * 32)
    deltas = _store(3).since(0)
    a = build_delta_feed(deltas, idn, generated_at=AT)
    b = build_delta_feed(copy.deepcopy(deltas), idn, generated_at=AT)
    assert a["entries"] == b["entries"] and a["head"] == b["head"]
