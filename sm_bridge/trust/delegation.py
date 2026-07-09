"""Delegation-chain trust profile — a port of the ``nanda-ans-quilt`` Demo 4 mechanism.

This adapter verifies a *domainless* delegation chain: a `DELEGATION-V1` credential is
issued by an ANS-registered provider to a `did:key` subject, and may be re-delegated down
a chain of subjects. A chain is trustworthy only when every hop is cryptographically
signed **and** the pure delegation-safety rules hold (scope containment, monotonicity,
depth, nested validity windows, freshness, revocation).

Port map: `sm_bridge.trust.delegation` ← ``internal/delegation/{credential,scopes,validate}.go``
plus the status-token freshness gate from ``cmd/delegation-cli/verifychain.go``. See
``docs/demo-verifiers.tmp.md`` (Mechanism 4).

Signature primitive — a deliberate, documented deviation from the demo
--------------------------------------------------------------------
The demo signs delegation credentials with **ES256** (ECDSA P-256, detached JWS, IEEE
P1363 ``r||s``) and derives the subject ``did:key`` with multicodec ``0x1200`` (``zDnae…``).
This port uses **Ed25519 (EdDSA)** instead, for three reasons that keep the adapter
self-contained without weakening the honesty guarantee:

  1. Ed25519 signatures are fixed 64-byte blobs — no ``r||s`` ↔ DER conversion, so there
     is no place for an encoding bug to hide a forged-but-accepted signature.
  2. `cryptography`'s ``Ed25519PrivateKey``/``Ed25519PublicKey`` need no curve/hash
     plumbing, so the tests can mint real keys and real signatures with zero ceremony.
  3. The signature check here is *real crypto over the JCS bytes*: tampering any credential
     field changes its RFC 8785 canonicalization, changes the JWS signing input, and the
     Ed25519 verification fails. That is exactly the property the ES256 path guarantees.

The wire shape is a **compact JWS**: signing input ``b64url(JCS(header)) . b64url(JCS(cred))``,
signature = Ed25519 over that input. If/when this profile is pointed at the live demo,
swap :func:`_verify_signature` / :func:`sign_credential` for the P-256 detached-JWS pair
and the credential schema, scope rules, and :class:`ValidateChain` port below are unchanged.

Requires the ``[trust]`` extra (``cryptography``). Core never imports this module.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sm_bridge.trust.base import ProofResult

SCHEMA_VERSION = "DELEGATION-V1"

# Fixed protected header for the compact JWS. Signer and verifier both canonicalize this
# with JCS, so the signing input is symmetric and reproducible from the credential alone.
_JWS_HEADER: dict[str, str] = {"alg": "EdDSA", "typ": "delegation+jws"}


# --------------------------------------------------------------------------------------
# RFC 8785 (JCS) canonicalization
# --------------------------------------------------------------------------------------
# Credentials only carry strings, ints, null, arrays of strings, and nested objects, so
# the number-formatting minefield of RFC 8785 §3.2.2.3 never fires. We still sort object
# keys by UTF-16 code unit (§3.2.3) — comparing the utf-16-be encodings orders surrogate
# pairs correctly — so the port stays faithful even for non-ASCII keys.


def jcs_canonical(value: Any) -> bytes:
    """Serialize ``value`` to RFC 8785 canonical JSON bytes (UTF-8, no whitespace)."""
    return _ser(value).encode("utf-8")


def _ser(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # No floats in DELEGATION-V1; reject rather than emit a non-canonical number.
        raise TypeError("JCS: floating-point values are not part of the delegation schema")
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: str(kv[0]).encode("utf-16-be"))
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + _ser(val) for k, val in items) + "}"
    raise TypeError(f"JCS: unsupported type {type(v).__name__}")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------------------
# Scope containment — port of internal/delegation/scopes.go
# --------------------------------------------------------------------------------------


def scope_covers(s: str, t: str) -> bool:
    """Does scope ``s`` cover ``t`` under the dotted-hierarchy model?

    ``t == s`` (exact), or ``t`` is a strict descendant of ``s`` (``t`` starts with
    ``s + "."``). The label boundary is respected: ``"a.b"`` covers ``"a.b.c"`` but NOT
    ``"a.bc"`` (sibling label), and an ancestor never covers its descendant's scope.
    """
    return t == s or t.startswith(s + ".")


def scope_subset(child_scopes: list[str], parent_scopes: list[str]) -> tuple[bool, str | None]:
    """Is every child scope covered by some parent scope?

    Returns ``(True, None)`` on success, or ``(False, first_uncovered_scope)`` on the
    first child scope no parent covers.
    """
    for c in child_scopes:
        if not any(scope_covers(p, c) for p in parent_scopes):
            return False, c
    return True, None


# --------------------------------------------------------------------------------------
# Signing helpers — real Ed25519 over the JCS bytes (used by producers and tests)
# --------------------------------------------------------------------------------------


def _signing_input(credential: dict[str, Any]) -> bytes:
    header_b64 = _b64url(jcs_canonical(_JWS_HEADER))
    payload_b64 = _b64url(jcs_canonical(credential))
    return f"{header_b64}.{payload_b64}".encode("ascii")


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """Base64 of the raw 32-byte Ed25519 public key — the ``signer_pubkey`` wire value."""
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign_credential(credential: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Sign ``credential`` (JCS-canonicalized, compact JWS input) → base64 signature."""
    sig = private_key.sign(_signing_input(credential))
    return base64.b64encode(sig).decode("ascii")


def _verify_signature(credential: dict[str, Any], sig_b64: str, signer_pubkey_b64: str) -> bool:
    """Real Ed25519 verification of ``sig_b64`` over ``JCS(credential)``.

    Returns False on any signature failure or malformed key/signature bytes — an
    ``InvalidSignature`` here is the *result of the check*, not a swallowed error.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(signer_pubkey_b64))
        pub.verify(base64.b64decode(sig_b64), _signing_input(credential))
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------------------
# Window parsing
# --------------------------------------------------------------------------------------


def _parse_rfc3339(value: str) -> datetime:
    # Python 3.10's fromisoformat does not accept a trailing 'Z'; normalize it.
    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _window(cred: dict[str, Any]) -> tuple[datetime, datetime]:
    issued = _parse_rfc3339(cred["issuedAt"])
    expires = _parse_rfc3339(cred["expiresAt"])
    return issued, expires


class _ChainError(Exception):
    """Internal signal carrying a verbatim rule-failure reason for :meth:`verify`."""


def _validate_structure(cred: dict[str, Any]) -> None:
    if not cred.get("delegationId"):
        raise _ChainError("malformed credential: delegationId empty")
    if cred.get("schemaVersion") != SCHEMA_VERSION:
        raise _ChainError(
            f"malformed credential: schemaVersion {cred.get('schemaVersion')!r} (want {SCHEMA_VERSION!r})"
        )
    if not cred.get("subject", {}).get("did"):
        raise _ChainError("malformed credential: subject.did empty")
    if not cred.get("scopes"):
        raise _ChainError("malformed credential: scopes empty")
    if int(cred.get("maxRedelegationDepth", 0)) < 0:
        raise _ChainError("malformed credential: maxRedelegationDepth negative")
    try:
        issued, expires = _window(cred)
    except (KeyError, ValueError) as exc:
        raise _ChainError(f"malformed credential: bad validity window ({exc})") from exc
    if not expires > issued:
        raise _ChainError("malformed credential: expiresAt not after issuedAt")


def _validate_chain(
    chain: list[dict[str, Any]],
    provider_scopes: list[str],
    status_tokens: dict[str, dict[str, Any]],
    now: datetime,
    now_ts: float,
) -> None:
    """Port of ``delegation.ValidateChain`` (rules 1-5) + the status-token freshness gate.

    ``chain`` is ROOT-FIRST: ``chain[0]`` is the provider-issued root credential and
    ``chain[-1]`` is the credential being exercised. Raises :class:`_ChainError` with a
    verbatim reason on the first violated rule; returns None only for a fully honest chain.
    """
    for i, cred in enumerate(chain):
        _validate_structure(cred)
        did = cred["delegationId"]

        # Linkage — root has no parent; every other hop points at its predecessor.
        parent_ptr = cred.get("parentDelegation")
        if i == 0:
            if parent_ptr is not None:
                raise _ChainError(
                    f"chain parentDelegation linkage broken: root credential {did} has parentDelegation {parent_ptr!r}"
                )
        else:
            prev_id = chain[i - 1]["delegationId"]
            if parent_ptr != prev_id:
                raise _ChainError(
                    f"chain parentDelegation linkage broken: credential {did} does not point at parent {prev_id}"
                )

        # Rule 5 (revocation) + freshness — a fresh ACTIVE status token is required per hop.
        tok = status_tokens.get(did)
        if tok is None:
            raise _ChainError(f"stale status token: no status token for {did}")
        status = tok.get("status")
        if status == "REVOKED":
            raise _ChainError(f"revoked credential in chain: {did} (chain broken)")
        if status != "ACTIVE":
            raise _ChainError(f"stale status token: {did} status {status!r} is not ACTIVE")
        exp = tok.get("exp")
        if exp is None or float(exp) < now_ts:
            raise _ChainError(
                f"stale status token: {did} exp {exp} < now {int(now_ts)}"
            )

        # Rule 4b — inside its own window at `now`.
        issued, expires = _window(cred)
        if now < issued or not now < expires:
            raise _ChainError(
                f"credential outside its validity window at evaluation time: {did} "
                f"(window {cred['issuedAt']} .. {cred['expiresAt']}, now {now.isoformat()})"
            )

        # Rule 3 — redelegations below credential i must fit its budget.
        below = len(chain) - 1 - i
        max_depth = int(cred.get("maxRedelegationDepth", 0))
        if below > max_depth:
            raise _ChainError(
                f"redelegation depth exceeded: credential {did} allows depth {max_depth} "
                f"but has {below} redelegation(s) below it"
            )

        if i == 0:
            # Rule 1 — issuance coverage: root scopes ⊆ provider scopes.
            ok, uncovered = scope_subset(cred["scopes"], provider_scopes)
            if not ok:
                raise _ChainError(
                    f"scope escalation: {uncovered!r} not covered by provider scopes"
                )
            continue

        parent = chain[i - 1]

        # Rule 2 — monotone scopes (child ⊆ parent).
        ok, uncovered = scope_subset(cred["scopes"], parent["scopes"])
        if not ok:
            raise _ChainError(
                f"scope escalation: {uncovered!r} of {did} not covered by parent "
                f"{parent['delegationId']} scopes"
            )

        # Rule 4a — nested windows (child window ⊆ parent window).
        p_issued, p_expires = _window(parent)
        if issued < p_issued or expires > p_expires:
            raise _ChainError(
                f"child validity window not nested in parent window: {did} "
                f"[{cred['issuedAt']}, {cred['expiresAt']}] not inside parent "
                f"{parent['delegationId']} [{parent['issuedAt']}, {parent['expiresAt']}]"
            )


class NandaDelegationProfile:
    """Trust profile: verify a DELEGATION-V1 chain end-to-end.

    Evidence shape (all keys under ``evidence``)::

        {
          "chain": [<credential dict>, ...],          # ROOT-FIRST: chain[0] = root
          "signatures": {delegationId: {"sig_b64": ..., "signer_pubkey": ...}},
          "status_tokens": {delegationId: {"status": "ACTIVE"|"REVOKED", "exp": <unix>}},
          "provider_scopes": [<scope>, ...],          # the root issuer's own capabilities
          "now": <unix seconds>,                      # optional; defaults to wall clock
        }

    HONESTY CONTRACT:
      * VERIFIED only after (a) a real Ed25519 signature check passes for every credential
        AND (b) every ValidateChain rule + per-hop fresh ACTIVE status token holds.
      * A stale/absent status token, a revoked hop, a rule violation, or a forged
        signature → FAILED (with the verbatim reason).
      * Missing chain / signatures / provider_scopes, or an unsigned hop we cannot check
        → NOT_VERIFIED (an honest "unknown", never a fabricated pass).
    """

    profile_id = "nanda-delegation"
    _METHOD = "delegation-chain"

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        # ---- (0) evidence presence — can we even attempt a check? -------------------
        chain = evidence.get("chain")
        if not isinstance(chain, list) or not chain:
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=self._METHOD,
                reason="no delegation chain supplied",
            )
        signatures = evidence.get("signatures")
        if not isinstance(signatures, dict):
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=self._METHOD,
                reason="no signatures supplied for delegation chain",
            )
        provider_scopes = evidence.get("provider_scopes")
        if not isinstance(provider_scopes, list):
            return ProofResult.not_verified(
                profile=self.profile_id,
                method=self._METHOD,
                reason="no provider_scopes supplied to anchor issuance coverage",
            )
        status_tokens = evidence.get("status_tokens")
        if not isinstance(status_tokens, dict):
            status_tokens = {}
        now_ts = float(evidence["now"]) if "now" in evidence else time.time()
        now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)

        # ---- (1) real signature check for every credential --------------------------
        for cred in chain:
            if not isinstance(cred, dict) or not cred.get("delegationId"):
                return ProofResult.failed(
                    profile=self.profile_id,
                    method=self._METHOD,
                    reason="malformed credential: delegationId empty",
                )
            did = cred["delegationId"]
            sig_entry = signatures.get(did)
            if not isinstance(sig_entry, dict) or "sig_b64" not in sig_entry or "signer_pubkey" not in sig_entry:
                # Cannot run crypto on this hop → honest unknown, not a rejection.
                return ProofResult.not_verified(
                    profile=self.profile_id,
                    method=self._METHOD,
                    reason=f"no signature material for credential {did}",
                )
            if not _verify_signature(cred, sig_entry["sig_b64"], sig_entry["signer_pubkey"]):
                return ProofResult.failed(
                    profile=self.profile_id,
                    method=self._METHOD,
                    reason=f"forged signature: JWS verification failed for credential {did}",
                )

        # ---- (2 + 3) ValidateChain rules + status-token freshness -------------------
        try:
            _validate_chain(chain, provider_scopes, status_tokens, now_dt, now_ts)
        except _ChainError as exc:
            return ProofResult.failed(
                profile=self.profile_id,
                method=self._METHOD,
                reason=str(exc),
            )

        root_id = chain[0]["delegationId"]
        return ProofResult.verified(
            profile=self.profile_id,
            method=self._METHOD,
            evidence_ref=f"deleg:{root_id}",
        )


__all__ = [
    "NandaDelegationProfile",
    "SCHEMA_VERSION",
    "jcs_canonical",
    "scope_covers",
    "scope_subset",
    "sign_credential",
    "public_key_b64",
]
