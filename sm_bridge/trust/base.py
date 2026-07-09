"""Trust-profile spine — the normalized proof block and the verifier plugin seam.

A `TrustProfile` is a pluggable adapter that verifies one kind of trust root (ed25519
agent-card, ANS/SCITT, DNS-AID, delegation, …) and normalizes the outcome to a single
downstream vocabulary: `ProofResult`. Heterogeneous sources onboard through their own
profile and emerge with a proof block that means the same thing everywhere.

This module is **core-safe**: it imports only pydantic + stdlib, never a `[trust]` extra.
Individual profiles under this package import cryptography/dnspython/cbor2 lazily and are
only importable when the extra is installed — mirroring the repo's lazy-httpx pattern.

Cryptographic honesty rule (enforced, not merely documented): a `ProofResult` may carry
``status == VERIFIED`` only when it also carries a non-empty ``evidence_ref`` describing
the concrete artifact that was checked. `ProofResult.verified()` is the only blessed way to
build a VERIFIED result and it raises if that invariant is violated, so a profile cannot
emit a mocked pass. When verification cannot truly run (no live infra, unreachable DNS,
absent key), a profile returns ``not_verified(reason)`` — never a fabricated VERIFIED.
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
        if self.status is not ProofStatus.VERIFIED and self.failure_reason is None:
            # FAILED / NOT_VERIFIED must say why — silence is not allowed.
            raise ValueError(
                f"ProofResult.status={self.status.value} requires a failure_reason"
            )
        return self

    # ----- blessed constructors -----------------------------------------------------

    @classmethod
    def verified(cls, *, profile: str, method: str, evidence_ref: str) -> ProofResult:
        """A real check passed. `evidence_ref` is mandatory and must be non-empty."""
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


__all__ = ["ProofStatus", "ProofResult", "TrustProfile", "TrustRegistry"]
