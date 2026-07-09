"""Dual onboarding modes — quilt compliance made structural.

Two ways a source joins the quilt, deliberately different in *shape*:

- **Entry mode** — a registry-scale source (ANS ~140K agents, ARD) onboards as exactly ONE
  ``RegistryEntry``: a pointer + its transparency-log checkpoint + verification keys.
  Resolution is delegated back to the source's ``resolver_endpoint``. The
  ``EntryModeConverter`` protocol has **no agent-iteration method** — so it is structurally
  impossible to bulk-import a registry's agent catalog through this path. The quilt
  invariant (Index stays pointer-only) is enforced by the type, not a runtime check.

- **Hosting mode** — the existing ``AgentConverter`` path (``converter.py``), for sources
  that have **no registry of their own**: AI catalogs, a domainless ``did:key`` operator, a
  small operator. Those get per-agent hosting because there is nothing to delegate to.

Choosing: if the source already runs a registry/resolver, use entry mode. If it does not,
use hosting mode. Never per-agent-flatten a source that has its own registry.

Verification is an **admission** concern. The bridge (the onboarding tool) verifies a source
once at join via ``admit`` and stamps ``RegistryEntry.proof``; the index (the switchboard)
then holds the pointer and delegates resolution — it never re-verifies a source's live
records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator

from sm_bridge.trust.base import ProofResult, ProofStatus, TrustRegistry


class AdmissionError(Exception):
    """A registry-scale source failed admission verification at onboarding."""


class RegistryEntry(BaseModel):
    """One quilt entry for a registry-scale source (the Demo 3 auditor schema).

    Pointer-only: it names where to resolve (``resolver_endpoint``) and pins the trust
    material to audit the source (``tl_checkpoint``, ``root_keys``) — it never contains the
    source's agents.
    """

    registry_name: str = Field(..., description="Stable machine name, e.g. 'acme-ans'")
    display_name: str | None = Field(None, description="Human-readable registry name")
    resolver_endpoint: str = Field(
        ..., description="Where agent resolution is delegated (the source's own resolver)"
    )
    media_type: str | None = Field(
        None, description="Media type the resolver serves (e.g. application/a2a-agent-card+json)"
    )
    tl_checkpoint: str | None = Field(
        None, description="Pinned transparency-log signed checkpoint (C2SP note), if auditable"
    )
    root_keys: list[str] = Field(
        default_factory=list, description="TL verification-line(s) / root keys for offline audit"
    )
    last_audited: datetime | None = Field(None, description="When the auditor last verified this entry")
    conformance_level: str = Field(
        "basic",
        description="Computed, not asserted: 'basic' (schema-valid) / 'auditable' (tlog live) "
        "/ 'witnessed' (reserved). See sm_bridge.conformance.",
    )
    trust_profile: str | None = Field(
        None, description="profile_id used to verify agents resolved under this registry"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="discovery/fanout/tags/ra/tl…")
    proof: ProofResult | None = Field(None, description="Normalized proof over the entry itself")

    @field_validator("conformance_level")
    @classmethod
    def _known_level(cls, v: str) -> str:
        if v not in {"basic", "auditable", "witnessed"}:
            raise ValueError(f"conformance_level must be basic/auditable/witnessed, got {v!r}")
        return v


class DelegationResolution(BaseModel):
    """What an entry-mode resolve returns: a pointer to the source's resolver, NOT a record.

    The Index never mirrors an entry-mode agent's facts; it tells the caller where to go.
    """

    kind: str = Field("delegation", frozen=True)
    registry_name: str
    resolver_endpoint: str
    agent: str = Field(..., description="The requested agent identifier, passed through")
    media_type: str | None = None
    note: str = Field(
        "resolution delegated to the source registry; this bridge does not mirror entry-mode records"
    )


@runtime_checkable
class EntryModeConverter(Protocol):
    """Source registry → exactly ONE ``RegistryEntry``.

    Note what is ABSENT: there is no ``list_agents`` / ``get_agent`` / ``to_sm``. An
    entry-mode source cannot have its agents enumerated or imported through this seam — the
    quilt's pointer-only invariant is enforced structurally. To resolve an agent under an
    entry-mode registry, call ``delegate`` and follow the returned pointer.
    """

    def to_entry(self) -> RegistryEntry:
        """Produce the single quilt entry for this source (carrying its admission proof)."""
        ...

    def delegate(self, agent: str) -> DelegationResolution:
        """Return a delegation pointer for resolving ``agent`` at the source's resolver."""
        ...

    async def admit(
        self, trust_registry: TrustRegistry, *, require_verified: bool = False
    ) -> ProofResult:
        """Verify the source's attestation ONCE at onboarding and stamp the entry's proof.

        This is the switchboard/bridge split made concrete: the bridge (onboarding tool)
        verifies a source at admission time; the index (switchboard) then holds the pointer
        and delegates resolution back to the source — it never re-verifies live records.
        """
        ...


class ANSEntryConverter:
    """Example entry-mode converter: an ANS registry becomes ONE quilt entry.

    Deliberately exposes no way to iterate ANS's agents — it holds only the pointer +
    checkpoint + keys. Bulk-importing ANS's ~140K agents is not merely disallowed, it is
    unrepresentable on this path.
    """

    def __init__(
        self,
        *,
        registry_name: str,
        resolver_endpoint: str,
        display_name: str | None = None,
        tl_checkpoint: str | None = None,
        root_keys: list[str] | None = None,
        media_type: str = "application/scitt-receipt+cose",
        trust_profile: str = "ans-scitt",
        metadata: dict[str, Any] | None = None,
        admission_evidence: dict[str, Any] | None = None,
    ) -> None:
        self._registry_name = registry_name
        self._resolver_endpoint = resolver_endpoint.rstrip("/")
        self._display_name = display_name
        self._tl_checkpoint = tl_checkpoint
        self._root_keys = root_keys or []
        self._media_type = media_type
        self._trust_profile = trust_profile
        self._metadata = metadata or {}
        # Evidence proving the source controls this registry (e.g. a signed attestation /
        # receipt over the entry's identity). Verified ONCE at admission by `admit`.
        self._admission_evidence = admission_evidence
        self._proof: ProofResult | None = None

    def to_entry(self) -> RegistryEntry:
        return RegistryEntry(
            registry_name=self._registry_name,
            display_name=self._display_name,
            resolver_endpoint=self._resolver_endpoint,
            media_type=self._media_type,
            tl_checkpoint=self._tl_checkpoint,
            root_keys=self._root_keys,
            conformance_level="auditable" if self._tl_checkpoint and self._root_keys else "basic",
            trust_profile=self._trust_profile,
            metadata=self._metadata,
            proof=self._proof,
        )

    async def admit(
        self, trust_registry: TrustRegistry, *, require_verified: bool = False
    ) -> ProofResult:
        """Verify the source's attestation once and stamp the entry's proof.

        With no admission evidence, the entry is stamped NOT_VERIFIED (honest — it joined
        unattested). With ``require_verified=True``, a non-VERIFIED outcome raises
        :class:`AdmissionError` so the source cannot join the index unattested.
        """
        if self._trust_profile and self._admission_evidence is not None:
            proof = await trust_registry.verify(
                self._trust_profile, self.to_entry(), self._admission_evidence
            )
        else:
            proof = ProofResult.not_verified(
                profile=self._trust_profile or "entry",
                method="admission",
                reason="no admission evidence supplied; source joined unattested",
            )
        if require_verified and proof.status is not ProofStatus.VERIFIED:
            raise AdmissionError(
                f"registry '{self._registry_name}' failed admission verification: "
                f"{proof.failure_reason}"
            )
        self._proof = proof
        return proof

    def delegate(self, agent: str) -> DelegationResolution:
        return DelegationResolution(
            registry_name=self._registry_name,
            resolver_endpoint=self._resolver_endpoint,
            agent=agent,
            media_type=self._media_type,
        )


def normalize_reliability_receipts(raw: Any) -> list[dict[str, Any]]:
    """Validate an ``x_reliability_receipts`` pass-through: store-and-display, no grading.

    Each receipt MUST carry a non-empty attester identity (``attester`` / ``attester_id`` /
    ``attester_did``). sm-bridge does not score, rank, or weigh these — it only enforces the
    attester-identity field is present and echoes them back. Malformed receipts are dropped
    (not silently trusted).
    """
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        attester = item.get("attester") or item.get("attester_id") or item.get("attester_did")
        if isinstance(attester, str) and attester.strip():
            out.append(item)
    return out


__all__ = [
    "RegistryEntry",
    "DelegationResolution",
    "EntryModeConverter",
    "ANSEntryConverter",
    "AdmissionError",
    "normalize_reliability_receipts",
]
