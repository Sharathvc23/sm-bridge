"""ed25519 agent-card trust profile.

A direct, byte-for-byte port of `nanda-index-v2/server/src/services/signing.ts`
(`canonicalize` + `verifyAgentCardSignature`, algorithm ``ed25519``). The NANDA Index
signs its own pointer / agent-card records with ed25519 over a canonical-JSON (JCS-family)
projection of the card; this profile verifies that signature and normalizes the outcome to
the spine's :class:`~sm_bridge.trust.base.ProofResult`.

Honesty rule (see ``base.py``): a ``VERIFIED`` result is emitted **only** after a real
ed25519 signature check passes over the canonical bytes. A signature that runs and is
rejected → ``FAILED``; anything that prevents the check from running at all (missing
payload / signature / key, malformed key or base64, non-canonicalizable payload) →
``NOT_VERIFIED``. Never a fabricated pass.

Canonicalization contract (must match signing.ts byte-for-byte):
  - ``null`` / booleans → ``null`` / ``true`` / ``false``
  - numbers → ``JSON.stringify`` rules; non-finite values are rejected
  - strings → ``JSON.stringify`` escaping, UTF-8, non-ASCII left raw
  - arrays → insertion order preserved
  - objects → keys sorted, ``"k":canonical(v)`` joined by ``,`` with no whitespace

The ``signature`` field is stripped from the card before canonicalizing — a signature must
never sign over itself (mirrors ``verifyAgentCardSignature``'s ``{ signature: _strip }``).

This module lives under the ``[trust]`` extra, so importing ``cryptography`` at module top
is intentional and safe — a core-only install never imports this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from sm_bridge.trust.base import ProofResult

_PROFILE_ID = "ed25519-agentcard"
_METHOD = "ed25519-jcs"
_SIGNATURE_FIELD = "signature"


# --------------------------------------------------------------------------------------
# Canonicalization — byte-for-byte port of signing.ts `canonicalize`
# --------------------------------------------------------------------------------------


def _format_number(value: int | float) -> str:
    """Serialize a number per JS ``JSON.stringify`` (rejecting non-finite values).

    ``bool`` is handled by the caller before this runs (it is an ``int`` subclass), so the
    integer branch only ever sees real integers. Integer-valued floats drop the trailing
    ``.0`` exactly as V8 does (``JSON.stringify(1.0) === "1"``).
    """
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise ValueError("canonicalize: non-finite numbers are not representable")
    if value.is_integer():
        return str(int(value))
    return repr(value)


def _canonical_str(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_number(value)
    if isinstance(value, str):
        # JSON.stringify string escaping == json.dumps(..., ensure_ascii=False):
        # escapes ", \\ and control chars; leaves non-ASCII raw; does not escape "/".
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_str(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"canonicalize: object keys must be strings, got {type(key).__name__}"
                )
        keys = sorted(value.keys())
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + _canonical_str(value[key])
                for key in keys
            )
            + "}"
        )
    raise TypeError(f"canonicalize: unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the canonical-JSON byte sequence for ``value`` (the signing input).

    Two implementations producing the same record MUST produce the same bytes — this is
    the cross-implementation contract with ``signing.ts``.
    """
    return _canonical_str(value).encode("utf-8")


# --------------------------------------------------------------------------------------
# Public-key loading — PEM (SPKI) or raw 32-byte ed25519
# --------------------------------------------------------------------------------------


def _load_ed25519_public_key(public_key: Any) -> Ed25519PublicKey:
    """Coerce ``public_key`` to an :class:`Ed25519PublicKey` or raise.

    Accepts an already-loaded key, a PEM string / bytes, or a raw 32-byte ed25519 key.
    A PEM that decodes to a non-ed25519 key is rejected — we will only ever ed25519-verify.
    """
    if isinstance(public_key, Ed25519PublicKey):
        return public_key

    if isinstance(public_key, str):
        key = load_pem_public_key(public_key.encode("utf-8"))
    elif isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
        if raw.lstrip().startswith(b"-----BEGIN"):
            key = load_pem_public_key(raw)
        elif len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
        else:
            raise ValueError(
                f"raw ed25519 public key must be 32 bytes, got {len(raw)}"
            )
    else:
        raise TypeError(f"unsupported public_key type {type(public_key).__name__}")

    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(
            f"expected an ed25519 public key, got {type(key).__name__}"
        )
    return key


# --------------------------------------------------------------------------------------
# The profile
# --------------------------------------------------------------------------------------


class Ed25519AgentCardProfile:
    """Verifies a NANDA-Index ed25519 agent-card signature.

    ``evidence`` shape::

        {
            "payload": <dict>,       # the agent card (may still carry its "signature")
            "signature_b64": <str>,  # base64 ed25519 signature over the canonical card
            "public_key": <PEM str | PEM bytes | raw 32-byte key | Ed25519PublicKey>,
        }
    """

    profile_id: str = _PROFILE_ID

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        payload = evidence.get("payload")
        signature_b64 = evidence.get("signature_b64")
        public_key = evidence.get("public_key")

        # ----- honest NOT_VERIFIED: the check cannot even be attempted -----------------
        if not isinstance(payload, dict):
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason="no agent-card payload supplied in evidence['payload']",
            )
        if not isinstance(signature_b64, str) or not signature_b64:
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason="no signature supplied in evidence['signature_b64']",
            )
        if public_key is None:
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason="no public key supplied in evidence['public_key']",
            )

        try:
            pubkey = _load_ed25519_public_key(public_key)
        except (ValueError, TypeError) as exc:
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason=f"unusable ed25519 public key: {exc}",
            )

        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason=f"signature is not valid base64: {exc}",
            )

        # Strip the signature field before canonicalizing — a signature never signs itself.
        card = {k: v for k, v in payload.items() if k != _SIGNATURE_FIELD}
        try:
            message = canonicalize(card)
        except (TypeError, ValueError) as exc:
            return ProofResult.not_verified(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason=f"agent-card payload is not canonicalizable: {exc}",
            )

        evidence_ref = f"ed25519:{hashlib.sha256(signature).hexdigest()[:16]}"

        # ----- the real check ---------------------------------------------------------
        try:
            pubkey.verify(signature, message)
        except InvalidSignature:
            return ProofResult.failed(
                profile=_PROFILE_ID,
                method=_METHOD,
                reason="ed25519 signature verification failed",
                evidence_ref=evidence_ref,
            )

        return ProofResult.verified(
            profile=_PROFILE_ID,
            method=_METHOD,
            evidence_ref=evidence_ref,
        )


__all__ = ["Ed25519AgentCardProfile", "canonicalize"]
