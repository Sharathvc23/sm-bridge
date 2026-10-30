"""
Delta sync client.

A registry exposes its change log at ``GET /nanda/deltas?since=<seq>`` (see
``create_sm_router``). ``pull_deltas`` fetches a peer's deltas since a cursor and
applies the upserts and deletes into a local :class:`~sm_bridge.DeltaStore`.
``FederationPoller`` runs it on a background thread.

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
from typing import Any, Literal

from .models import SmAgentFacts
from .store import DeltaStore
from .trust.base import ProofResult

Fetch = Callable[[str], dict[str, Any]]
# A caller-supplied local re-verifier: given the inbound agent + its raw delta, return a
# ProofResult this registry actually computed (or None to fall through to the safe default).
Reverify = Callable[[SmAgentFacts, dict[str, Any]], "ProofResult | None"]
CursorMode = Literal["exclusive", "inclusive"]


def _resolve_inbound_proof(
    agent: SmAgentFacts,
    delta: dict[str, Any],
    reverify: Reverify | None,
    trust_peer_proof: bool,
) -> ProofResult | None:
    """Decide the proof for an ingested delta.

    A peer's ``proof`` is the peer's *claim*, not something this registry verified — so by
    default it is NOT propagated as-is (that would launder an unverified VERIFIED into our
    index). Order: a caller-supplied local ``reverify`` wins; else, if the operator has
    explicitly chosen to trust this peer, keep the peer's proof; else downgrade to an honest
    NOT_VERIFIED.
    """
    if reverify is not None:
        result = reverify(agent, delta)
        if result is not None:
            return result
    if trust_peer_proof:
        return agent.proof
    return ProofResult.not_verified(
        profile="federation",
        method="federation-ingest",
        reason="proof asserted by a federated peer; not re-verified by this registry",
    )


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
    reverify: Reverify | None = None,
    trust_peer_proof: bool = False,
    cursor_mode: CursorMode = "exclusive",
) -> PullResult:
    """Pull a peer's deltas since ``since`` and apply them into ``store``.

    Args:
        peer_url: base URL of the peer registry (its ``/nanda/deltas`` is appended).
        store: local DeltaStore to apply the peer's changes into.
        since: peer sequence cursor; its meaning is selected by ``cursor_mode``.
        cursor_mode: ``exclusive`` (default) requests ``seq > since`` and returns
            the last received sequence. ``inclusive`` requests ``seq >= since``
            and requires ``next_seq`` to equal the last received sequence plus
            one, or the unchanged input cursor for an empty page. Select this
            from the peer's documented contract; never infer it from one page.
        fetch: transport ``(url) -> json dict``; defaults to an httpx GET.
        timeout: request timeout for the default transport.
        reverify: optional local re-verifier ``(agent, delta) -> ProofResult | None``.
            When it returns a ProofResult, that (locally computed) proof is stored. Use this
            to re-verify a peer's record against transported evidence.
        trust_peer_proof: opt-in to keep a peer's ``proof`` claim verbatim. Default ``False``
            — a peer's proof is downgraded to NOT_VERIFIED so a federated ``VERIFIED`` claim
            is never laundered into this registry. Only enable for a peer you fully trust.

    Returns:
        :class:`PullResult` with the number applied and the new cursor, suitable
        for the next call using the same mode. A short page is not necessarily
        the end of the feed. Page validation and local re-verification finish
        before any writes. Store writes are not atomic: a store failure can leave
        a partial page applied, and durable recovery needs a transactional sink.
    """
    if type(since) is not int or since < 0:
        raise ValueError("since must be a nonnegative integer")
    if cursor_mode not in ("exclusive", "inclusive"):
        raise ValueError("unsupported cursor mode")
    do_fetch = fetch or _httpx_fetch(timeout)
    url = f"{peer_url.rstrip('/')}/nanda/deltas?since={since}"
    data = do_fetch(url)

    if not isinstance(data, dict) or not isinstance(data.get("deltas"), list):
        raise ValueError("invalid delta page")
    cursor = since
    previous = since if cursor_mode == "exclusive" else since - 1
    prepared: list[tuple[dict[str, Any], SmAgentFacts]] = []
    for delta in data["deltas"]:
        if not isinstance(delta, dict):
            raise ValueError("invalid delta row")
        seq = delta.get("seq")
        if type(seq) is not int or seq <= previous:
            raise ValueError("delta sequences must increase within the requested range")
        if delta.get("action") not in ("upsert", "delete", "revoke"):
            raise ValueError("invalid delta action")
        agent = SmAgentFacts.model_validate(delta["agent"])
        prepared.append((delta, agent))
        previous = seq
        cursor = seq + 1 if cursor_mode == "inclusive" else seq
    if cursor_mode == "inclusive":
        next_seq = data.get("next_seq")
        if type(next_seq) is not int or next_seq != cursor:
            raise ValueError("next_seq does not match the returned page")
    for delta, agent in prepared:
        # Never re-serve a peer's proof claim as our own verification.
        agent.proof = _resolve_inbound_proof(agent, delta, reverify, trust_peer_proof)
    for delta, agent in prepared:
        store.add(delta["action"], agent)
    return PullResult(applied=len(prepared), cursor=cursor)


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
        reverify: Reverify | None = None,
        trust_peer_proof: bool = False,
        cursor_mode: CursorMode = "exclusive",
    ) -> None:
        self.peer_url = peer_url
        self.store = store
        self.interval = interval
        self.since = since
        self._fetch = fetch
        self._reverify = reverify
        self._trust_peer_proof = trust_peer_proof
        self._cursor_mode = cursor_mode
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def sync_once(self) -> PullResult:
        """Run a single pull and advance the cursor."""
        result = pull_deltas(
            self.peer_url,
            self.store,
            self.since,
            fetch=self._fetch,
            reverify=self._reverify,
            trust_peer_proof=self._trust_peer_proof,
            cursor_mode=self._cursor_mode,
        )
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
