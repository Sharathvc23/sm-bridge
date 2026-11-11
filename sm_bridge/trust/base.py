"""Trust-profile spine — the normalized proof block and the verifier plugin seam.

A `TrustProfile` is a pluggable adapter that verifies one kind of trust root (ed25519
agent-card, ANS/SCITT, DNS-AID, delegation, …) and normalizes the outcome to a single
downstream vocabulary: `ProofResult`. Heterogeneous sources onboard through their own
profile and emerge with a proof block that means the same thing everywhere.

This module is **core-safe**: it imports only pydantic + stdlib, never a `[trust]` extra.
Individual profiles under this package import cryptography/dnspython/cbor2 lazily and are
only importable when the extra is installed — mirroring the repo's lazy-httpx pattern.

Cryptographic honesty rule (enforced at construction): a `ProofResult` may carry
``status == VERIFIED`` only when it also carries a non-empty ``evidence_ref`` describing
the concrete artifact that was checked **and** a ``method`` naming a registered
verification method (see :func:`register_verification_method`). `ProofResult.verified()`
is the blessed way to build a VERIFIED result and raises if either is violated. When
verification cannot truly run (no live infra, unreachable DNS, absent key), a profile
returns ``not_verified(reason)`` — never a fabricated VERIFIED.

**What construction does and does not guard.** The invariant catches the mistakes a
validator can see: a VERIFIED with no evidence, or one naming a method no profile here
implements (a typo, a stub, a peer's vocabulary). It cannot tell whether the named check
actually ran — any code that can call ``ProofResult.verified`` can also call
``register_verification_method`` first. The guarantee that a VERIFIED means a real
signature, DNS or Merkle check is made by the *profiles* (each builds its VERIFIED only
after its check passed, and the tests under ``tests/test_trust_*.py`` pin that), not by
this type. Read a ``ProofResult`` as a profile's statement, and trust it exactly as far
as you trust the profile that produced it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, model_validator

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sm_bridge.models import SmAgentFacts


class ProofStatus(str, Enum):
    """Outcome of a trust-profile verification.

    - ``VERIFIED``    — a real signature / DNS / Merkle check passed. Requires evidence.
    - ``FAILED``      — a real check ran and the subject failed it (forgery, tamper,
                        escalation, expiry). This is an adversarial *rejection*.
    - ``NOT_VERIFIED``— verification could not be performed (no evidence supplied, live
                        infra absent, legacy unverified data). NOT a pass and NOT a
                        rejection — an honest "unknown".
    """

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# The verification methods a VERIFIED result may name. Seeded with the methods the
# in-tree profiles implement; a third-party profile registers its own before it
# emits a VERIFIED. Kept here (core-safe) rather than in the profiles so the check
# does not need the `[trust]` extra to run.
_VERIFICATION_METHODS: set[str] = {
    "ed25519-jcs",  # ed25519_agentcard
    "scitt-cose-merkle",  # ans_scitt
    "ans-txt-control",  # ans_txt
    "dns-aid-dnssec",  # dns_aid
    "dns-aid-dnssec+dane",  # dns_aid, when DANE/TLSA binding was requested and held
    "es256-jws-catalog",  # jws_catalog
    "delegation-chain",  # delegation
}


def register_verification_method(method: str) -> str:
    """Register ``method`` as a name a VERIFIED ``ProofResult`` may carry.

    A trust profile outside this package calls this once (at import time) with the
    name of the concrete check it implements, before it emits a VERIFIED. Registration
    is not an attestation — see the module docstring — it only makes the name known so
    an unregistered string is rejected as a mistake rather than accepted as a check.
    Returns ``method`` so it can be used inline: ``_METHOD = register_verification_method(...)``.
    """
    if not isinstance(method, str) or not method.strip():
        raise ValueError("verification method must be a non-empty string")
    _VERIFICATION_METHODS.add(method)
    return method


def verification_methods() -> frozenset[str]:
    """The registered verification method names (a snapshot)."""
    return frozenset(_VERIFICATION_METHODS)


def is_registered_method(method: str) -> bool:
    return method in _VERIFICATION_METHODS


class ProofResult(BaseModel):
    """Normalized proof block — the one downstream vocabulary every profile produces.

    Build these via the classmethods (`verified` / `failed` / `not_verified`), never by
    hand, so the honesty invariant is enforced at construction.
    """

    profile: str = Field(..., description="profile_id of the TrustProfile that produced this")
    method: str = Field(
        ..., description="Concrete verification method, e.g. 'ed25519-jcs', 'scitt-cose-merkle'"
    )
    status: ProofStatus = Field(..., description="VERIFIED / FAILED / NOT_VERIFIED")
    verified_at: datetime = Field(default_factory=_utcnow, description="When this result was produced (UTC)")
    evidence_ref: str | None = Field(
        None,
        description="Reference to the artifact actually checked (receipt id, signature "
        "digest, DNS record, checkpoint root). MANDATORY when status is VERIFIED.",
    )
    failure_reason: str | None = Field(
        None, description="Why the check failed or could not run (set for FAILED / NOT_VERIFIED)"
    )

    @model_validator(mode="after")
    def _enforce_honesty(self) -> ProofResult:
        # The load-bearing invariant: no VERIFIED without a concrete evidence reference.
        if self.status is ProofStatus.VERIFIED and not (self.evidence_ref and self.evidence_ref.strip()):
            raise ValueError(
                "cryptographic honesty violation: ProofResult.status=VERIFIED requires a "
                "non-empty evidence_ref (the artifact that was actually checked)"
            )
        # ...and no VERIFIED naming a check nothing here implements.
        if self.status is ProofStatus.VERIFIED and not is_registered_method(self.method):
            raise ValueError(
                "cryptographic honesty violation: ProofResult.status=VERIFIED names "
                f"verification method {self.method!r}, which is not a registered method "
                f"(registered: {sorted(_VERIFICATION_METHODS)}); call "
                "register_verification_method() for a real check, never for a stub"
            )
        if self.status is not ProofStatus.VERIFIED and self.failure_reason is None:
            # FAILED / NOT_VERIFIED must say why — silence is not allowed.
            raise ValueError(
                f"ProofResult.status={self.status.value} requires a failure_reason"
            )
        return self

    # ----- blessed constructors -----------------------------------------------------

    @classmethod
    def verified(cls, *, profile: str, method: str, evidence_ref: str) -> ProofResult:
        """A real check passed. `evidence_ref` is mandatory and must be non-empty, and
        `method` must be a registered verification method.

        This is a constructor, not a guard: it checks the shape of the claim, not that
        the check ran. See the module docstring.
        """
        return cls(
            profile=profile,
            method=method,
            status=ProofStatus.VERIFIED,
            evidence_ref=evidence_ref,
        )

    @classmethod
    def failed(cls, *, profile: str, method: str, reason: str, evidence_ref: str | None = None) -> ProofResult:
        """A real check ran and the subject was rejected. `reason` is the verbatim cause."""
        return cls(
            profile=profile,
            method=method,
            status=ProofStatus.FAILED,
            evidence_ref=evidence_ref,
            failure_reason=reason,
        )

    @classmethod
    def not_verified(cls, *, profile: str, method: str, reason: str) -> ProofResult:
        """Verification could not be performed (honest unknown)."""
        return cls(
            profile=profile,
            method=method,
            status=ProofStatus.NOT_VERIFIED,
            failure_reason=reason,
        )

    @classmethod
    def legacy(cls) -> ProofResult:
        """Downgrade an opaque pre-v0.4 `proof` dict — it was never verified."""
        return cls.not_verified(
            profile="legacy",
            method="opaque-dict",
            reason="legacy-unverified: pre-v0.4 proof payload carried no verifiable evidence",
        )


@runtime_checkable
class TrustProfile(Protocol):
    """A pluggable verifier for one trust root.

    Implementations live under `sm_bridge/trust/` in the `[trust]` extra and import their
    crypto lazily. `verify` MUST honor the honesty rule: return a VERIFIED `ProofResult`
    only after a real check (via `ProofResult.verified`), else `failed`/`not_verified`.
    """

    profile_id: str

    async def verify(self, subject: SmAgentFacts | Any, evidence: dict[str, Any]) -> ProofResult:
        """Verify `subject` against `evidence`; return a normalized `ProofResult`."""
        ...


class TrustRegistry:
    """Maps ``profile_id -> TrustProfile``. Injected into SmBridge so `/nanda/resolve`
    can attach a normalized proof block per agent.

    Dispatch is explicit: an unknown profile_id yields an honest NOT_VERIFIED, never a
    silent pass or a crash.
    """

    def __init__(self, profiles: list[TrustProfile] | None = None) -> None:
        self._profiles: dict[str, TrustProfile] = {}
        for p in profiles or []:
            self.register(p)

    def register(self, profile: TrustProfile) -> None:
        pid = getattr(profile, "profile_id", None)
        if not pid or not isinstance(pid, str):
            raise ValueError("TrustProfile must expose a non-empty string profile_id")
        self._profiles[pid] = profile

    def get(self, profile_id: str) -> TrustProfile | None:
        return self._profiles.get(profile_id)

    def profile_ids(self) -> list[str]:
        return sorted(self._profiles)

    async def verify(
        self, profile_id: str, subject: SmAgentFacts | Any, evidence: dict[str, Any]
    ) -> ProofResult:
        """Dispatch to the named profile; unknown profile → honest NOT_VERIFIED."""
        profile = self._profiles.get(profile_id)
        if profile is None:
            return ProofResult.not_verified(
                profile=profile_id,
                method="dispatch",
                reason=f"no trust profile registered for '{profile_id}'",
            )
        return await profile.verify(subject, evidence)


__all__ = [
    "ProofStatus",
    "ProofResult",
    "TrustProfile",
    "TrustRegistry",
    "is_registered_method",
    "register_verification_method",
    "verification_methods",
]
