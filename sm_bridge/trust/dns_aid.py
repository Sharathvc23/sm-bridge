"""DNS-AID trust profile — thin adapter over the upstream ``dns-aid`` package.

This is the **real** DNS-AID (IETF draft-mozleywilliams-dnsop-dnsaid): DNS discovery via
SVCB records with DNSSEC chain validation and optional DANE/TLSA certificate binding. It is
distinct from ANS's ``_ans`` TXT discovery (see ``ans_txt.py``) — a different mechanism the
demo conflated under one name.

Per the "consume upstream, thin adapter, never fork" discipline, this profile does not
reimplement DNS-AID: it delegates to ``dns_aid.core.validator.verify`` (the maintained IETF
reference implementation) and normalizes its ``VerifyResult`` into a ``ProofResult``.

Honesty rule: ``VERIFIED`` is emitted only when the upstream check reports a
**DNSSEC-validated** record (a real cryptographic authentication of the DNS answer). A record
that exists but is not DNSSEC-authenticated is ``NOT_VERIFIED`` (present but unauthenticated),
never a pass. A DNSSEC-bogus answer is ``FAILED``. The ``dns-aid`` package is an optional
``[trust]`` dependency; if it is not installed, verify returns ``NOT_VERIFIED``.
"""

from __future__ import annotations

import re
from typing import Any

from sm_bridge.trust.base import ProofResult

profile_id = "dns-aid"

_FQDN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$")


def _default_verifier() -> Any:  # pragma: no cover - exercised only with the package installed
    """Lazily import the upstream verifier so a core-only install never pays for it."""
    from dns_aid.core.validator import verify as _verify

    return _verify


class DnsAidProfile:
    """Verify a DNS-AID record by delegating to the upstream ``dns-aid`` package.

    ``__init__(verifier=...)`` accepts an async callable ``(fqdn, *, verify_dane_cert) ->
    VerifyResult`` so tests can inject a fake without network; the default lazily loads the
    real ``dns_aid.core.validator.verify``.
    """

    profile_id = "dns-aid"

    def __init__(self, verifier: Any | None = None) -> None:
        self._verifier = verifier

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        method = "dns-aid-dnssec"
        fqdn = (evidence or {}).get("fqdn")
        if not isinstance(fqdn, str) or not _FQDN_RE.match(fqdn):
            return ProofResult.not_verified(
                profile=self.profile_id, method=method, reason="evidence.fqdn missing or malformed"
            )
        want_dane = bool((evidence or {}).get("verify_dane_cert", False))

        verifier = self._verifier
        if verifier is None:
            try:
                verifier = _default_verifier()
            except ImportError:
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=method,
                    reason="dns-aid package not installed (pip install 'sm-bridge[trust]')",
                )

        try:
            result = await verifier(fqdn, verify_dane_cert=want_dane)
        except Exception as e:  # network/timeout/resolver error — cannot verify, not a rejection
            return ProofResult.not_verified(
                profile=self.profile_id, method=method, reason=f"dns-aid verify could not run: {e}"
            )

        record_exists = bool(getattr(result, "record_exists", False))
        svcb_valid = bool(getattr(result, "svcb_valid", False))
        dnssec_valid = bool(getattr(result, "dnssec_valid", False))
        dane_valid = getattr(result, "dane_valid", None)

        if not record_exists:
            return ProofResult.not_verified(
                profile=self.profile_id, method=method, reason=f"no DNS-AID record for {fqdn}"
            )

        # A DNSSEC-bogus answer is an adversarial rejection; an unsigned/insecure zone is
        # simply unauthenticated (cannot verify), not a rejection.
        dnssec_note = str(getattr(result, "dnssec_note", "") or "")
        if not dnssec_valid:
            if "bogus" in dnssec_note.lower():
                return ProofResult.failed(
                    profile=self.profile_id,
                    method=method,
                    reason=f"DNSSEC validation failed (bogus) for {fqdn}: {dnssec_note}",
                    evidence_ref=f"dns-aid:{fqdn}",
                )
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=method,
                reason=f"DNS-AID record present but not DNSSEC-authenticated for {fqdn} "
                f"(unsigned/insecure zone): {dnssec_note or 'no DNSSEC'}",
            )

        if not svcb_valid:
            return ProofResult.failed(
                profile=self.profile_id,
                method=method,
                reason=f"DNSSEC-valid but SVCB record invalid for {fqdn}",
                evidence_ref=f"dns-aid:{fqdn}",
            )

        if want_dane and dane_valid is False:
            return ProofResult.failed(
                profile=self.profile_id,
                method=method,
                reason=f"DANE/TLSA certificate binding failed for {fqdn}",
                evidence_ref=f"dns-aid:{fqdn}",
            )

        # Real DNSSEC-authenticated SVCB record (+ DANE when requested) → VERIFIED.
        suffix = "+dane" if (want_dane and dane_valid) else ""
        return ProofResult.verified(
            profile=self.profile_id,
            method=method + suffix,
            evidence_ref=f"dns-aid:{fqdn}:dnssec{suffix}",
        )


__all__ = ["DnsAidProfile", "profile_id"]
