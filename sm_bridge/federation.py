"""
NANDA federation sync client (Quilt pull).

A registry exposes its change log at ``GET /nanda/deltas?since=<seq>`` (see
``create_sm_router``). ``pull_deltas`` is the other half: it fetches a peer's
deltas since a cursor and applies them into a local :class:`~sm_bridge.DeltaStore`,
so a border/aggregator node tracks whatever the mesh syncs in.

The default transport uses ``httpx`` (an optional extra: ``pip install
'sm-bridge[federation]'``). Pass your own ``fetch`` callable to use a different
client or to test without a network::

    from sm_bridge import DeltaStore, pull_deltas

    store = DeltaStore()
    cursor = 0
    cursor = pull_deltas("https://peer.example", store, cursor).cursor  # repeat on a timer
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import SmAgentFacts
from .store import DeltaStore

Fetch = Callable[[str], dict[str, Any]]


@dataclass(frozen=True)
class PullResult:
    """Outcome of one :func:`pull_deltas` call."""

    applied: int
    cursor: int


def _httpx_fetch(timeout: float) -> Fetch:
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "pull_deltas needs httpx for its default transport. "
            "Install it with: pip install 'sm-bridge[federation]' "
            "(or pass your own `fetch` callable)."
        ) from exc

    def _get(url: str) -> dict[str, Any]:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        return body

    return _get


def pull_deltas(
    peer_url: str,
    store: DeltaStore,
    since: int = 0,
    *,
    fetch: Fetch | None = None,
    timeout: float = 10.0,
) -> PullResult:
    """Pull a peer's deltas since ``since`` and apply them into ``store``.

    Args:
        peer_url: base URL of the peer registry (its ``/nanda/deltas`` is appended).
        store: local DeltaStore to apply the peer's changes into.
        since: peer sequence cursor — only deltas with ``seq > since`` are returned.
        fetch: transport ``(url) -> json dict``; defaults to an httpx GET.
        timeout: request timeout for the default transport.

    Returns:
        :class:`PullResult` with the number applied and the new cursor (the highest
        peer ``seq`` seen, or ``since`` unchanged when nothing was returned).
    """
    do_fetch = fetch or _httpx_fetch(timeout)
    url = f"{peer_url.rstrip('/')}/nanda/deltas?since={since}"
    data = do_fetch(url)

    cursor = since
    applied = 0
    for delta in data.get("deltas", []):
        agent = SmAgentFacts.model_validate(delta["agent"])
        store.add(str(delta["action"]), agent)
        cursor = max(cursor, int(delta["seq"]))
        applied += 1
    return PullResult(applied=applied, cursor=cursor)


class FederationPoller:
    """Background poller that repeatedly :func:`pull_deltas` from one peer.

    Thread-based and resilient — transient peer errors are swallowed so the loop
    keeps running. The cursor advances across iterations.

    Usage::

        poller = FederationPoller("https://peer.example", store, interval=30.0)
        poller.start()
        ...
        poller.stop()
    """

    def __init__(
        self,
        peer_url: str,
        store: DeltaStore,
        *,
        interval: float = 30.0,
        since: int = 0,
        fetch: Fetch | None = None,
    ) -> None:
        self.peer_url = peer_url
        self.store = store
        self.interval = interval
        self.since = since
        self._fetch = fetch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def sync_once(self) -> PullResult:
        """Run a single pull and advance the cursor."""
        result = pull_deltas(self.peer_url, self.store, self.since, fetch=self._fetch)
        self.since = result.cursor
        return result

    def start(self) -> None:
        """Start the background poll loop (no-op if already running)."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sync_once()
            except Exception:
                # A poller must survive a flaky/unreachable peer; retry next tick.
                pass
            self._stop.wait(self.interval)

    def stop(self, timeout: float | None = 5.0) -> None:
        """Signal the loop to stop and join the thread."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
