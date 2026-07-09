"""DNS-AID trust profile — domain-anchored ANS discovery records.

Ports the *proven* verification logic of the `nanda-ans-quilt` switchboard
(`src/adapters/dnsaid.ts` + `src/routes/divergence.ts`) into a `TrustProfile`.

What this profile actually proves — and what it does NOT
--------------------------------------------------------
DNS-AID publishes an agent's ANS coordinates under records the domain operator
controls:

    _ans.<host>        TXT   v=ans1; version=…; p=…; mode=direct; url=…
    _ans-badge.<host>  TXT   v=ans-badge1; version=…; url=<TL badge URL>
    <host>             SVCB(64)/HTTPS(65)   RFC 9460 endpoints

The badge URL embeds a transparency-log ``agentId`` UUID — that is the *bridge*
from DNS to the SCITT receipt chain, but verifying the receipt is mechanism 3's
job, not this profile's.

So the strongest honest claim a green DNS-AID check can make is **DNS CONTROL of
the domain's ANS records**: whoever answered these queries controls what the
domain advertises. That is why a consistent, well-formed result returns
``VERIFIED`` with ``method="ans-txt-control"`` — the evidence_ref pins the exact
records checked. It is deliberately *not* a claim that the agent behind the
badge is receipt-verified; agent trust requires the badge → transparency-log →
SCITT chain, which is out of scope here.

Honesty rule (from `trust/base.py`): when DNS is unreachable, times out, or the
records are simply absent/malformed, this profile returns ``NOT_VERIFIED`` with a
reason — never ``FAILED`` (which is an adversarial rejection) and never a
fabricated ``VERIFIED``. The one adversarial rejection this profile does make is
**split-horizon DNS**: when two or more vantages disagree on the advertised
endpoint set, that divergence is affirmative evidence of tampering →
``FAILED`` (mirrors the two-vantage endpoint diff in `routes/divergence.ts`).

Resolver seam
-------------
`__init__(self, resolver=None)` takes an injectable callable so tests never touch
the network. The callable is either ``(qname, rdtype) -> list[str]`` or, to
support per-vantage queries, ``(qname, rdtype, vantage) -> list[str]`` — the
arity is detected once and the extra argument is passed only when accepted. The
default resolver imports `dnspython` lazily (mirrors the repo's lazy-import
pattern) so a core-only install never pays for the `[trust]` extra.
"""

from __future__ import annotations

import hashlib
import inspect
import re
from collections.abc import Callable
from typing import Any, NamedTuple

from sm_bridge.trust.base import ProofResult

profile_id = "ans-txt"

# Match the switchboard's 2 s per-lookup budget (adapters/dnsaid.ts).
_DNS_TIMEOUT_S = 2.0

# A DNS-AID badge URL embeds the transparency-log agentId as a UUID (the TS
# adapter pulls it from `/v1/agents/<uuid>`); we accept the UUID anywhere in the
# badge URL so the exact path layout can evolve without breaking the bridge.
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# A conservative FQDN: 2+ dot-separated labels, each 1-63 chars of
# [A-Za-z0-9-] with no leading/trailing hyphen, total <= 253, optional root dot.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+"
    r"\.?$"
)


def _is_valid_fqdn(host: Any) -> bool:
    return isinstance(host, str) and bool(_FQDN_RE.match(host))


def _default_resolver(qname: str, rdtype: str, vantage: str | None = None) -> list[str]:
    """dnspython-backed resolver. Imported lazily so core installs stay light.

    `vantage` is an optional ``ip[:port]`` nameserver spec; when given, the query
    is directed at that authoritative server (multi-vantage split-horizon probe).
    Errors (timeout, NXDOMAIN, NoAnswer, no nameservers) propagate to the caller,
    which turns them into an honest NOT_VERIFIED.
    """
    import dns.resolver  # lazy: only when actually resolving over the network

    resolver = dns.resolver.Resolver(configure=vantage is None)
    if vantage is not None:
        ns_host, _, ns_port = vantage.partition(":")
        resolver.nameservers = [ns_host]
        if ns_port:
            resolver.port = int(ns_port)
    resolver.timeout = _DNS_TIMEOUT_S
    resolver.lifetime = _DNS_TIMEOUT_S

    answer = resolver.resolve(qname, rdtype)
    out: list[str] = []
    for rdata in answer:
        if rdtype.upper() == "TXT":
            # TXT rdata is a list of byte chunks; concatenate then decode.
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        else:
            out.append(rdata.to_text())
    return out


def _parse_kv(txt: str) -> dict[str, str]:
    """Parse a ``k=v; k=v; …`` TXT payload (the ANS record convention)."""
    out: dict[str, str] = {}
    for part in txt.split(";"):
        eq = part.find("=")
        if eq == -1:
            continue
        out[part[:eq].strip()] = part[eq + 1 :].strip()
    return out


def _find_kv(txts: list[str], expected_v: str) -> dict[str, str] | None:
    """First parsed TXT record whose ``v=`` tag matches, else None."""
    for txt in txts:
        kv = _parse_kv(txt)
        if kv.get("v") == expected_v:
            return kv
    return None


class _View(NamedTuple):
    """One vantage's parsed, well-formed view of a host's ANS records."""

    vantage: str
    url: str
    endpoints: tuple[str, ...]
    badge_url: str
    agent_id: str


class AnsTxtProfile:
    """Verifies DNS control of a domain's ANS (`_ans` / `_ans-badge`) records.

    See the module docstring for the exact trust claim: a green result asserts
    ``ans-txt-control`` (domain control of the ANS records), not agent-receipt
    trust — that requires the badge SCITT chain (mechanism 3).
    """

    profile_id = "ans-txt"

    def __init__(self, resolver: Callable[..., list[str]] | None = None) -> None:
        self._resolver: Callable[..., list[str]] = resolver or _default_resolver
        # Detect whether the resolver accepts a third `vantage` argument so a
        # simple 2-arg fake and a vantage-aware fake both work through one seam.
        try:
            params = inspect.signature(self._resolver).parameters.values()
            self._accepts_vantage = len(list(params)) >= 3 or any(
                p.kind is inspect.Parameter.VAR_POSITIONAL for p in params
            )
        except (TypeError, ValueError):
            self._accepts_vantage = False

    def _query(self, qname: str, rdtype: str, vantage: str | None) -> list[str]:
        if self._accepts_vantage:
            return self._resolver(qname, rdtype, vantage)
        return self._resolver(qname, rdtype)

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        method = "ans-txt-control"

        host = evidence.get("host") if isinstance(evidence, dict) else None
        if not _is_valid_fqdn(host):
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=method,
                reason=f"malformed host in evidence (need an FQDN): {host!r}",
            )
        assert isinstance(host, str)  # narrowed by _is_valid_fqdn

        vantages = evidence.get("vantages")
        if vantages is None:
            vantages = [None]  # single default-resolver vantage
        elif not isinstance(vantages, list) or not vantages:
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=method,
                reason="evidence 'vantages' must be a non-empty list of nameserver ip[:port]",
            )

        expected_url = evidence.get("expected_url")

        views: list[_View] = []
        for vantage in vantages:
            label = vantage if vantage else "default"

            # --- _ans.<host> TXT (v=ans1) --------------------------------------
            try:
                ans_txt = self._query(f"_ans.{host}", "TXT", vantage)
            except Exception as exc:  # timeout / NXDOMAIN / no nameservers
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=f"DNS unreachable/absent: _ans.{host} @ {label}: {exc}",
                )
            ans_kv = _find_kv(ans_txt, "ans1")
            if ans_kv is None:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=(
                        f"DNS records absent: no _ans.{host} TXT with v=ans1 "
                        f"@ {label}"
                    ),
                )
            url = ans_kv.get("url")
            if not url:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=f"_ans.{host} record has no url= field @ {label}",
                )

            # --- _ans-badge.<host> TXT (v=ans-badge1) --------------------------
            try:
                badge_txt = self._query(f"_ans-badge.{host}", "TXT", vantage)
            except Exception as exc:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=f"DNS unreachable/absent: _ans-badge.{host} @ {label}: {exc}",
                )
            badge_kv = _find_kv(badge_txt, "ans-badge1")
            if badge_kv is None:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=(
                        f"missing or malformed _ans-badge.{host} TXT "
                        f"(need v=ans-badge1) @ {label}"
                    ),
                )
            badge_url = badge_kv.get("url")
            if not badge_url:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=f"_ans-badge.{host} record has no url= field @ {label}",
                )
            uuid_match = _UUID_RE.search(badge_url)
            if uuid_match is None:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason=(
                        f"_ans-badge.{host} url does not embed a transparency-log "
                        f"agentId UUID @ {label}: {badge_url}"
                    ),
                )
            agent_id = uuid_match.group(0)

            # --- <host> SVCB(64)/HTTPS(65) — optional, informational ----------
            svcb: list[str] = []
            for rr in ("SVCB", "HTTPS"):
                try:
                    svcb.extend(self._query(host, rr, vantage))
                except Exception:
                    # Absent/unsupported SVCB is normal; it never blocks a
                    # verdict — the _ans/_ans-badge pair is the load-bearing part.
                    pass

            endpoints = tuple(sorted({url, *svcb}))
            views.append(
                _View(
                    vantage=label,
                    url=url,
                    endpoints=endpoints,
                    badge_url=badge_url,
                    agent_id=agent_id,
                )
            )

        # --- expected-url mismatch = tamper evidence (real check ran, lost) ----
        if expected_url is not None:
            mismatched = [v for v in views if v.url != expected_url]
            if mismatched:
                detail = ", ".join(f"{v.vantage}->{v.url}" for v in mismatched)
                return ProofResult.failed(
                    profile=self.profile_id,
                    method=method,
                    reason=(
                        f"advertised _ans url does not match expected "
                        f"{expected_url!r}: {detail}"
                    ),
                )

        # --- split-horizon: vantages disagree on the endpoint set → FAILED -----
        if len(views) > 1:
            distinct = {v.endpoints for v in views}
            if len(distinct) > 1:
                detail = "; ".join(f"{v.vantage}={list(v.endpoints)}" for v in views)
                return ProofResult.failed(
                    profile=self.profile_id,
                    method=method,
                    reason=f"split-horizon DNS: vantage endpoints diverge: {detail}",
                )

        # --- consistent, well-formed → DNS control proven ----------------------
        primary = views[0]
        record_blob = "|".join(
            [
                f"host={host}",
                "ans_urls=" + ",".join(sorted({v.url for v in views})),
                "endpoints=" + ",".join(primary.endpoints),
                f"badge={primary.badge_url}",
                f"agentId={primary.agent_id}",
                "vantages=" + ",".join(v.vantage for v in views),
            ]
        )
        digest = hashlib.sha256(record_blob.encode("utf-8")).hexdigest()[:12]
        return ProofResult.verified(
            profile=self.profile_id,
            method=method,
            evidence_ref=f"dns:{host}:{digest}",
        )


__all__ = ["AnsTxtProfile", "profile_id"]
