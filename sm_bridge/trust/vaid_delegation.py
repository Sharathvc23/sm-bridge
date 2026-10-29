"""VAID delegation-chain trust profile. A thin adapter over the upstream ``vaid-a2a``
reference verifier (https://github.com/solara-associates/vaid, ``docs/a2a/v1/extension.md``).

Per the "consume upstream, thin adapter, never fork" discipline this profile does not
reimplement signature, attenuation or revocation checking: it builds the A2A ``Message``
shape ``vaid_a2a.verify_a2a_message`` expects from this profile's own evidence shape and
normalizes its ``VerifyResult`` into a ``ProofResult``.

What VAID proves that AgentFacts does not: an AgentFacts record is a self-asserted
description of an agent. Nothing in it is cryptographically tied to the authority that
is supposed to have granted the agent its capabilities. A VAID delegation chain is a
signed lineage: each hop is a credential issued by a specific kernel key, scoped and
time-bounded, and every child's scope/capabilities/tenant/window is checked to sit strictly
inside its parent's. Verifying a VAID chain proves not just "this agent says X" but "an
identified authority granted X, and every re-delegation down to this agent only narrowed
it, never widened it." AgentFacts has no equivalent of that lineage check.

Honesty contract (matches the other profiles in this package):
  * VERIFIED only after the upstream verifier's full ordered check (signature, leaf
    expiry, scope_boundary readability, chain integrity/attenuation, requested-action
    scope, revocation) allows the request.
  * A real adversarial rejection (forged signature, scope escalation, expired credential,
    revoked link, unknown scope_boundary kind, issuer/trust-domain mismatch) -> FAILED.
  * Missing evidence, an unconfigured revocation source, or an incomplete lineage
    (revocation genuinely "could not be determined") -> NOT_VERIFIED. Never a fabricated
    pass.

Requires the ``[vaid]`` extra (``vaid-a2a``, which pulls in ``vaid-mint``). Core never
imports this module.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from sm_bridge.trust.base import ProofResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    from vaid_mint.revocation import RevocationStatus

profile_id = "vaid-delegation"
_METHOD = "vaid-a2a-ext-v1"


@runtime_checkable
class VaidRevocationSource(Protocol):
    """The revocation seam this profile accepts at construction. A protocol, not a
    concrete list type: any object shaped like this satisfies it, so a durable backend
    drops in later without this module changing. ``InMemoryRevocationList`` (the CLI's
    ``--revocation-list`` flag) is one implementation of this seam, never the contract
    itself.

    Mirrors ``vaid_mint.revocation.RevocationCheck`` exactly (method name and the
    three-state return), so every object that already satisfies vaid-mint's own seam
    satisfies this one with no adapter. That is a deliberate choice over a boolean
    ``is_revoked(lineage) -> bool`` shape: vaid-mint replaced a boolean revocation seam
    with this three-state one specifically because a bool cannot distinguish "checked,
    and clean" from "the backing store could not be consulted" -- collapsing the second
    case into the first is exactly the silent-pass failure mode this package's honesty
    contract exists to prevent. A caller is free to wrap a simpler boolean check into
    this shape (mapping "unknown" to ``UNAVAILABLE``, never to ``NOT_REVOKED``), but this
    profile does not accept the lossy shape directly.
    """

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        """Report revocation for an already-assembled, ordered lineage (root first,
        leaf last). ``REVOKED`` if any id in ``lineage`` is revoked, ``NOT_REVOKED`` if
        the store was consulted and none are, ``UNAVAILABLE`` if the store could not be
        consulted -- never collapse the last case into the second."""
        ...


def _parse_when(value: Any) -> datetime | None:
    """Accept an RFC 3339 string (as the VAID conformance vectors use) or a unix
    timestamp (int/float); ``None`` defers to the upstream verifier's own wall clock."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise TypeError(f"evidence.now: unsupported type {type(value).__name__}")


class VaidDelegationProfile:
    """Trust profile: verify a VAID delegation chain carried under the A2A extension.

    Evidence shape (all keys under ``evidence``)::

        {
          "leaf": <VAID document dict>,            # the credential being exercised
          "chain": [<VAID document dict>, ...],    # presented ancestors, any order
          "trust_config": {"trustedIssuers": [{"trustDomain": ..., "kernelPublicKey": ...}]},
          "requested_action": <str> | None,         # the action/resource being asked for
          "now": <RFC3339 str> | <unix seconds> | None,
        }

    The revocation seam is injected at construction (``revocation=...``) as a
    :class:`VaidRevocationSource`, never read from evidence and never read from config of
    any kind: a caller wires it once, the same way the upstream extension requires
    (``vaid_a2a.verify_a2a_message``'s ``revocation`` parameter is never resolved by the
    verifier itself). If no revocation source is configured, every call returns an honest
    ``NOT_VERIFIED``, never a pass that silently skipped the revocation check.
    """

    profile_id = profile_id

    def __init__(self, revocation: VaidRevocationSource | None = None) -> None:
        self._revocation = revocation

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        if self._revocation is None:
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=_METHOD,
                reason="no revocation source configured for vaid-delegation; inject a "
                "VaidRevocationSource (e.g. vaid_mint.revocation.InMemoryRevocationList) "
                "before verifying, never a pass with revocation silently skipped",
            )

        try:
            from vaid_a2a import (
                METADATA_CHAIN_KEY,
                METADATA_VAID_KEY,
                TrustedIssuersConfigError,
                VerifyCode,
                verify_a2a_message,
            )
        except ImportError:
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=_METHOD,
                reason="vaid-a2a package not installed (pip install 'sm-bridge[vaid]')",
            )

        leaf = (evidence or {}).get("leaf")
        if not isinstance(leaf, dict) or not leaf:
            return ProofResult.not_verified(
                profile=self.profile_id, method=_METHOD, reason="no VAID leaf document supplied"
            )
        chain = (evidence or {}).get("chain") or []
        if not isinstance(chain, list) or not all(isinstance(d, dict) for d in chain):
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=_METHOD,
                reason="evidence.chain is present but is not a list of VAID document objects",
            )
        trust_config = (evidence or {}).get("trust_config")
        if not isinstance(trust_config, dict):
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=_METHOD,
                reason="no trust_config.trustedIssuers supplied to anchor the leaf's issuer",
            )
        requested_action = (evidence or {}).get("requested_action")

        try:
            now = _parse_when((evidence or {}).get("now"))
        except (TypeError, ValueError) as exc:
            return ProofResult.not_verified(
                profile=self.profile_id, method=_METHOD, reason=f"malformed evidence.now: {exc}"
            )

        message = {"metadata": {METADATA_VAID_KEY: leaf, METADATA_CHAIN_KEY: chain}}

        try:
            result = verify_a2a_message(
                message,
                trust_config=trust_config,
                revocation=self._revocation,
                requested_action=requested_action,
                now=now,
                require_vaid=True,
            )
        except TrustedIssuersConfigError as exc:
            return ProofResult.not_verified(
                profile=self.profile_id, method=_METHOD, reason=f"malformed trust_config: {exc}"
            )

        vaid_id = leaf.get("vaid_id", "?")

        if result.code is VerifyCode.ALLOWED:
            return ProofResult.verified(
                profile=self.profile_id, method=_METHOD, evidence_ref=f"vaid:{vaid_id}"
            )
        if not result.code.is_determined_denial:
            # NO_VAID (shouldn't occur with require_vaid=True) / INDETERMINATE: the
            # upstream verifier's own "could not tell" state. Not a rejection.
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=_METHOD,
                reason=f"{result.code.value}: {result.reason}",
            )
        return ProofResult.failed(
            profile=self.profile_id,
            method=_METHOD,
            reason=f"{result.code.value}: {result.reason}",
            evidence_ref=f"vaid:{vaid_id}",
        )


__all__ = ["VaidDelegationProfile", "VaidRevocationSource", "profile_id"]
