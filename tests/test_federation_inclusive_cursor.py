"""Inclusive next-sequence peers must neither replay nor skip retained entries."""

from copy import deepcopy
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge import DeltaStore, FederationPoller, create_sm_router, pull_deltas

from .test_federation import _delta


def test_inclusive_polling_drains_short_pages_then_observes_new_entry() -> None:
    log = [_delta(i, "upsert", str(i)) for i in range(1, 4)]
    requested = []

    def fetch(url: str) -> dict[str, Any]:
        since = int(url.rsplit("=", 1)[1])
        requested.append(since)
        page = [entry for entry in log if entry["seq"] >= since][:1]
        return {"deltas": page, "next_seq": page[-1]["seq"] + 1 if page else since}

    store = DeltaStore()
    poller = FederationPoller("https://peer.example", store, fetch=fetch, cursor_mode="inclusive")
    results = [poller.sync_once() for _ in range(4)]
    assert [result.applied for result in results] == [1, 1, 1, 0]
    assert [result.cursor for result in results] == [2, 3, 4, 4]
    log.append(_delta(4, "delete", "1"))
    assert poller.sync_once().cursor == 5
    assert poller.sync_once().applied == 0
    assert requested == [0, 2, 3, 4, 4, 5]
    assert len(store) == 4
    assert [entry.action for entry in store.since(0)] == ["upsert"] * 3 + ["delete"]


@pytest.mark.parametrize("next_seq", [None, True, "3", 0, 1, 2, 4, 100])
def test_bad_inclusive_cursor_refused_before_any_store_write(next_seq: Any) -> None:
    store = DeltaStore()
    page = {"deltas": [_delta(1, "upsert", "a"), _delta(2, "upsert", "b")]}
    if next_seq is not None:
        page["next_seq"] = next_seq
    with pytest.raises(ValueError):
        pull_deltas("https://peer.example", store, fetch=lambda _: page, cursor_mode="inclusive")
    assert len(store) == 0


@pytest.mark.parametrize("next_seq", [0, 2, True, "1"])
def test_empty_page_cannot_advance_or_rewind(next_seq: Any) -> None:
    with pytest.raises(ValueError):
        pull_deltas(
            "https://peer.example",
            DeltaStore(),
            1,
            fetch=lambda _: {"deltas": [], "next_seq": next_seq},
            cursor_mode="inclusive",
        )


@pytest.mark.parametrize("mode", ["exclusive", "inclusive"])
@pytest.mark.parametrize("bad", ["duplicate", "reverse", "boolean", "string", "action", "agent"])
def test_malformed_later_row_does_not_partially_apply(mode: str, bad: str) -> None:
    rows = [_delta(2, "upsert", "a"), _delta(3, "upsert", "b")]
    if bad in {"duplicate", "reverse", "boolean", "string"}:
        rows[1]["seq"] = {"duplicate": 2, "reverse": 1, "boolean": True, "string": "3"}[bad]
    elif bad == "action":
        rows[1]["action"] = "invented"
    else:
        rows[1]["agent"] = {}
    page = {"deltas": rows, "next_seq": 4}
    original = deepcopy(page)
    store = DeltaStore()
    with pytest.raises(ValueError):
        pull_deltas("https://peer.example", store, 1, fetch=lambda _: page, cursor_mode=mode)
    assert len(store) == 0
    assert page == original


@pytest.mark.parametrize("since", [-1, True, "0"])
def test_invalid_cursor_rejected_before_fetch(since: Any) -> None:
    def fetch(_: str) -> dict[str, Any]:
        pytest.fail("invalid cursor must not dispatch")

    with pytest.raises(ValueError):
        pull_deltas("https://peer.example", DeltaStore(), since, fetch=fetch)


def test_unknown_mode_rejected_before_fetch() -> None:
    def fetch(_: str) -> dict[str, Any]:
        pytest.fail("invalid cursor mode must not dispatch")

    with pytest.raises(ValueError):
        pull_deltas("https://peer.example", DeltaStore(), fetch=fetch, cursor_mode="guess")


def test_reverification_failure_before_any_store_write() -> None:
    store = DeltaStore()

    def reverify(agent: Any, delta: dict[str, Any]) -> None:
        if delta["seq"] == 2:
            raise ValueError("verification failed")

    with pytest.raises(ValueError):
        pull_deltas(
            "https://peer.example",
            store,
            cursor_mode="inclusive",
            reverify=reverify,
            fetch=lambda _: {
                "deltas": [_delta(1, "upsert", "a"), _delta(2, "upsert", "b")],
                "next_seq": 3,
            },
        )
    assert len(store) == 0


def test_default_mode_remains_compatible_with_real_router(converter: Any) -> None:
    source = DeltaStore()
    from .test_federation import _facts

    source.add("upsert", _facts("first"))
    app = FastAPI()
    router, _ = create_sm_router(
        converter, source, "peer", "https://peer.example", "Peer", "https://peer.example"
    )
    app.include_router(router)
    with TestClient(app) as client:

        def fetch(url: str) -> dict[str, Any]:
            response = client.get(url)
            response.raise_for_status()
            return response.json()

        sink = DeltaStore()
        poller = FederationPoller("https://peer.example", sink, fetch=fetch)
        assert poller.sync_once().cursor == 1
        assert poller.sync_once().applied == 0
        source.add("upsert", _facts("second"))
        assert poller.sync_once().cursor == 2
        assert len(sink) == 2


@pytest.mark.parametrize(
    "page", [{}, {"deltas": None}, {"deltas": {}}, {"deltas": [None]}, {"deltas": []}]
)
def test_bad_inclusive_page_leaves_poller_cursor_and_sink_unchanged(page: Any) -> None:
    sink = DeltaStore()
    poller = FederationPoller(
        "https://peer.example", sink, since=5, cursor_mode="inclusive", fetch=lambda _: page
    )
    with pytest.raises(ValueError):
        poller.sync_once()
    assert poller.since == 5 and len(sink) == 0


@pytest.mark.parametrize("mode", ["exclusive", "inclusive"])
def test_pre_cursor_entry_cannot_be_replayed(mode: Any) -> None:
    store = DeltaStore()
    with pytest.raises(ValueError):
        pull_deltas(
            "https://peer.example",
            store,
            5,
            cursor_mode=mode,
            fetch=lambda _: {"deltas": [_delta(4, "upsert", "old")], "next_seq": 5},
        )
    assert len(store) == 0
