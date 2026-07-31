"""Delta-feed extra (`[feed]`) — project the registry delta log as a Verifiable
Agent Feed (`sm-feed`).

Additive to `GET /nanda/deltas`. That endpoint sequences records, but a puller
must trust the server that it received every delta, in order, unaltered. This
projects the same deltas into an `sm-feed`: a signed, hash-chained, cursor-based
feed a subscriber can verify for **authenticity and completeness** (no dropped or
reordered delta) with :func:`read_delta_feed`. Nothing here changes `/nanda/deltas`
or the delta store; the `[feed]` extra is opt-in and the core never imports
`sm-feed` (mirrors the `[tlog]` extra).

Determinism: Ed25519 signing (RFC 8032) and JCS hashing are deterministic, so
rebuilding the feed from the same ordered deltas and the same registry identity
yields byte-identical entries. A subscriber's `?since=<cursor>` is therefore
stable across calls without the registry persisting the feed itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import SmAgentFactsDelta

if TYPE_CHECKING:
    from sm_arp import Identity  # provided transitively by the `[feed]` extra (sm-feed → sm-arp)

# Payload discriminator for a registry delta carried as one sm-feed entry.
DELTA_FEED_TYPE = "sm-bridge/delta/0.1"


def _require_sm_feed() -> Any:
    try:
        import sm_feed
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "build_delta_feed / read_delta_feed need sm-feed. "
            "Install it with: pip install 'sm-bridge[feed]'."
        ) from exc
    return sm_feed


def build_delta_feed(
    deltas: list[SmAgentFactsDelta],
    identity: Identity,
    *,
    generated_at: str,
    since: int | None = None,
) -> dict[str, Any]:
    """Project an ordered list of registry deltas into a signed `sm-feed` page.

    Each delta becomes one signed, hash-chained feed entry whose payload carries
    the registry ``action``, the registry ``seq`` (as ``registry_seq``), and the
    agent record. ``identity`` is the registry's ``sm_arp.Identity`` — the feed's
    signer. ``since`` is the **sm-feed** cursor (0-based feed ``seq``) the
    subscriber last held; ``None`` returns from genesis. ``generated_at`` stamps
    the signed head.
    """
    sm_feed = _require_sm_feed()
    log = sm_feed.FeedLog(identity)
    for d in sorted(deltas, key=lambda x: x.seq):
        payload = {
            "type": DELTA_FEED_TYPE,
            "registry_seq": d.seq,
            "action": d.action,
            "agent": d.agent.model_dump(mode="json"),
        }
        log.append(payload, issued_at=d.recorded_at.isoformat())
    return dict(log.page(cursor=since, generated_at=generated_at))


def read_delta_feed(
    page: dict[str, Any], *, expected_prev_hash: str | None = None
) -> tuple[bool, str, list[dict[str, Any]], dict[str, Any] | None]:
    """Verify a delta-feed page and return ``(ok, reason, deltas, new_head)``.

    ``ok`` is the result of ``sm_feed.verify_page`` — the page's entries must be
    authentic and a complete run from ``expected_prev_hash``. ``deltas`` are the
    verified ``sm-bridge/delta/0.1`` payloads; empty on any verification failure,
    so a peer never applies an unverified delta. ``new_head`` is the cursor anchor
    to persist for the next pull.
    """
    sm_feed = _require_sm_feed()
    ok, reason, head = sm_feed.verify_page(page, expected_prev_hash=expected_prev_hash)
    if not ok:
        return False, reason, [], None
    deltas = [
        e["payload"]
        for e in page["entries"]
        if isinstance(e.get("payload"), dict) and e["payload"].get("type") == DELTA_FEED_TYPE
    ]
    return True, "ok", deltas, head
