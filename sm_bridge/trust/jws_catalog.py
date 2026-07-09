"""AI-Catalog trust profile — verify an ARD-style signed catalog (ES256 detached JWS).

The AI-Catalog discovery method (per-domain ``/.well-known/ai-catalog.json``) lists the
agents under a domain. A *signed* catalog carries a detached JWS over the RFC 8785 (JCS)
canonicalization of its ``entries``, with the verification key published via JWKS. This
profile verifies that signature so a **catalog hijack** — an entry's endpoint swapped while
the old signature is left in place — is detected: the tampered entries no longer match the
signature, and the result is FAILED.

Honesty rule: VERIFIED only after a real ES256 signature check over the canonical entries.
Requires the ``[trust]`` extra; imports crypto lazily.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sm_bridge.trust._es256_jws import b64url_decode, verify_es256
from sm_bridge.trust.base import ProofResult
from sm_bridge.trust.ed25519_agentcard import canonicalize

_PROFILE = "jws-catalog"
_METHOD = "es256-jws-catalog"


class JwsCatalogProfile:
    """Verify a signed AI-Catalog's entries with an ES256 detached JWS + JWKS."""

    profile_id = "jws-catalog"

    async def verify(self, subject: Any, evidence: dict[str, Any]) -> ProofResult:
        entries = (evidence or {}).get("entries")
        signature = (evidence or {}).get("signature")  # detached compact JWS: header..sig
        if entries is None or not isinstance(signature, str):
            return ProofResult.not_verified(
                profile=_PROFILE, method=_METHOD,
                reason="evidence must carry 'entries' and a detached-JWS 'signature'",
            )

        # Split the detached compact JWS: <header>.<empty payload>.<sig>
        parts = signature.split(".")
        if len(parts) != 3 or parts[1] != "":
            return ProofResult.not_verified(
                profile=_PROFILE, method=_METHOD,
                reason="signature is not a detached compact JWS (header..sig)",
            )
        header_b64, _, sig_b64url = parts

        try:
            header = json.loads(b64url_decode(header_b64))
        except Exception:  # noqa: BLE001
            return ProofResult.not_verified(profile=_PROFILE, method=_METHOD, reason="unparseable JWS header")
        if header.get("alg") != "ES256":
            return ProofResult.not_verified(
                profile=_PROFILE, method=_METHOD, reason=f"unsupported JWS alg {header.get('alg')!r}, want ES256"
            )
        if "crit" in header:
            return ProofResult.failed(profile=_PROFILE, method=_METHOD, reason="unsupported 'crit' header parameter")

        key = self._select_key(evidence, header.get("kid"))
        if key is None:
            return ProofResult.not_verified(
                profile=_PROFILE, method=_METHOD, reason="no verification key (provide 'public_key' or a 'jwks')"
            )

        try:
            canonical = canonicalize(entries)
        except Exception as e:  # noqa: BLE001
            return ProofResult.not_verified(profile=_PROFILE, method=_METHOD, reason=f"entries not canonicalizable: {e}")

        if verify_es256(header_b64, canonical, sig_b64url, key):
            digest = hashlib.sha256(canonical).hexdigest()[:16]
            return ProofResult.verified(profile=_PROFILE, method=_METHOD, evidence_ref=f"jws-catalog:{digest}")
        return ProofResult.failed(
            profile=_PROFILE, method=_METHOD,
            reason="catalog signature does not verify over the entries (tampered catalog or wrong key)",
        )

    @staticmethod
    def _select_key(evidence: dict[str, Any], kid: str | None) -> Any:
        if evidence.get("public_key") is not None:
            return evidence["public_key"]
        jwks = evidence.get("jwks")
        if isinstance(jwks, dict):
            keys = jwks.get("keys") or []
            if kid is not None:
                for k in keys:
                    if isinstance(k, dict) and k.get("kid") == kid:
                        return k
            return keys[0] if keys else None
        return None


__all__ = ["JwsCatalogProfile"]
