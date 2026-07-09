"""Red-team tests for the ed25519 agent-card trust profile.

Every positive assertion runs a *real* ed25519 signature check via ``cryptography`` — no
mocks. The canonicalization is proven byte-equal to the authority
(``nanda-index-v2 signing.ts``) with a hand-computed fixture, so a drift in either side
breaks the build rather than silently passing a forged card.
"""

from __future__ import annotations

import base64
import math

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile, canonicalize

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _keypair() -> tuple[Ed25519PrivateKey, str, bytes]:
    """Return (private key, public-key PEM, raw 32-byte public key)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pem, raw


def _sign_card(priv: Ed25519PrivateKey, card: dict) -> str:
    """Sign the canonical bytes of ``card`` (without any signature field)."""
    body = {k: v for k, v in card.items() if k != "signature"}
    sig = priv.sign(canonicalize(body))
    return base64.b64encode(sig).decode("ascii")


def _card() -> dict:
    return {
        "id": "did:nanda:agent-1",
        "name": "Agent One",
        "version": 1,
        "provider": {"url": "https://p.example", "name": "P"},
        "skills": ["chat", "search"],
        "endpoints": {"static": ["https://a.example/mcp"]},
    }


# --------------------------------------------------------------------------------------
# 1. Valid signature -> VERIFIED with evidence_ref
# --------------------------------------------------------------------------------------


async def test_valid_signature_verifies():
    priv, pem, _ = _keypair()
    card = _card()
    sig_b64 = _sign_card(priv, card)
    signed = dict(card, signature=sig_b64)

    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": signed, "signature_b64": sig_b64, "public_key": pem}
    )

    assert result.status is ProofStatus.VERIFIED
    assert result.evidence_ref and result.evidence_ref.startswith("ed25519:")
    assert result.profile == "ed25519-agentcard"


async def test_valid_signature_with_raw_public_key():
    priv, _, raw = _keypair()
    card = _card()
    sig_b64 = _sign_card(priv, card)

    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": card, "signature_b64": sig_b64, "public_key": raw}
    )

    assert result.status is ProofStatus.VERIFIED


async def test_signature_field_is_stripped_not_signed():
    # The signature must not sign over itself: a bogus `signature` value inside the
    # payload must not change the verification outcome (it is stripped before canon).
    priv, pem, _ = _keypair()
    card = _card()
    sig_b64 = _sign_card(priv, card)
    signed = dict(card, signature="ZZZZ-not-the-real-signature")

    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": signed, "signature_b64": sig_b64, "public_key": pem}
    )

    assert result.status is ProofStatus.VERIFIED


# --------------------------------------------------------------------------------------
# 2. Tampered payload -> FAILED (reason mentions signature)
# --------------------------------------------------------------------------------------


async def test_tampered_payload_fails():
    priv, pem, _ = _keypair()
    card = _card()
    sig_b64 = _sign_card(priv, card)
    # Flip a field AFTER signing.
    tampered = dict(card, id="did:nanda:agent-EVIL", signature=sig_b64)

    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": tampered, "signature_b64": sig_b64, "public_key": pem}
    )

    assert result.status is ProofStatus.FAILED
    assert "signature" in (result.failure_reason or "").lower()


# --------------------------------------------------------------------------------------
# 3. Wrong key (sign with A, verify with B) -> FAILED
# --------------------------------------------------------------------------------------


async def test_wrong_key_fails():
    signer, _, _ = _keypair()
    _, other_pem, _ = _keypair()
    card = _card()
    sig_b64 = _sign_card(signer, card)

    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": card, "signature_b64": sig_b64, "public_key": other_pem}
    )

    assert result.status is ProofStatus.FAILED
    assert "signature" in (result.failure_reason or "").lower()


# --------------------------------------------------------------------------------------
# 4. Canonicalization is byte-equal to signing.ts (cross-impl vector)
# --------------------------------------------------------------------------------------


def test_canonical_form_matches_signing_ts_fixture():
    # Out-of-order keys + nested object + array + unicode + bool + number.
    fixture = {
        "b": 1,
        "a": "x",
        "nested": {"z": True, "y": [3, 2, 1]},
        "u": "héllo",
        "arr": ["b", "a"],
    }
    # Computed BY HAND from signing.ts rules:
    #   top keys sorted -> a, arr, b, nested, u
    #   nested keys sorted -> y, z ; arrays keep order ; é left raw (UTF-8) ; no whitespace
    expected = (
        '{"a":"x","arr":["b","a"],"b":1,"nested":{"y":[3,2,1],"z":true},"u":"héllo"}'
    )
    assert canonicalize(fixture) == expected.encode("utf-8")


def test_canonical_primitive_rules():
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(1) == b"1"
    assert canonicalize(2.5) == b"2.5"
    # Integer-valued float drops the trailing .0, matching JSON.stringify(2.0) === "2".
    assert canonicalize(2.0) == b"2"
    assert canonicalize([]) == b"[]"
    assert canonicalize({}) == b"{}"


def test_canonical_string_escaping_matches_json_stringify():
    # ", \\ and control chars escaped; "/" and non-ASCII left raw.
    assert canonicalize('a"b\n\\c/') == b'"a\\"b\\n\\\\c/"'


def test_canonical_rejects_non_finite_numbers():
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize(math.inf)
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize(math.nan)


# --------------------------------------------------------------------------------------
# 5. Missing evidence -> NOT_VERIFIED (an honest unknown, never FAILED)
# --------------------------------------------------------------------------------------


async def test_missing_signature_is_not_verified():
    _, pem, _ = _keypair()
    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": _card(), "public_key": pem}
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "signature" in (result.failure_reason or "").lower()


async def test_missing_public_key_is_not_verified():
    priv, _, _ = _keypair()
    card = _card()
    result = await Ed25519AgentCardProfile().verify(
        None, {"payload": card, "signature_b64": _sign_card(priv, card)}
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "public key" in (result.failure_reason or "").lower()


async def test_missing_payload_is_not_verified():
    _, pem, _ = _keypair()
    result = await Ed25519AgentCardProfile().verify(
        None, {"signature_b64": "AAAA", "public_key": pem}
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "payload" in (result.failure_reason or "").lower()


async def test_malformed_base64_signature_is_not_verified():
    _, pem, _ = _keypair()
    result = await Ed25519AgentCardProfile().verify(
        None,
        {"payload": _card(), "signature_b64": "!!! not base64 !!!", "public_key": pem},
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "base64" in (result.failure_reason or "").lower()


async def test_unusable_public_key_is_not_verified():
    priv, _, _ = _keypair()
    card = _card()
    result = await Ed25519AgentCardProfile().verify(
        None,
        {
            "payload": card,
            "signature_b64": _sign_card(priv, card),
            "public_key": b"\x00\x01\x02",  # not 32 bytes, not PEM
        },
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "public key" in (result.failure_reason or "").lower()
