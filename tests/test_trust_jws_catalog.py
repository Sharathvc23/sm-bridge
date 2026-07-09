"""AI-Catalog signed-catalog verification (ES256 detached JWS) — the catalog-hijack guard."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sm_bridge.trust import ProofStatus
from sm_bridge.trust._es256_jws import sign_es256
from sm_bridge.trust.ed25519_agentcard import canonicalize
from sm_bridge.trust.jws_catalog import JwsCatalogProfile

_ENTRIES = [
    {"identifier": "urn:example:finance", "url": "https://acme.com/agents/finance.json", "tags": ["finance"]},
    {"identifier": "urn:example:research", "url": "https://acme.com/agents/research.json"},
]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign_catalog(entries, priv, *, kid="k1") -> str:
    header_b64 = _b64url(json.dumps({"alg": "ES256", "kid": kid}, separators=(",", ":")).encode())
    sig = sign_es256(header_b64, canonicalize(entries), priv)
    return f"{header_b64}..{sig}"  # detached compact JWS


def _pem(priv):
    return priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.asyncio
async def test_valid_signed_catalog_verifies():
    priv = ec.generate_private_key(ec.SECP256R1())
    sig = _sign_catalog(_ENTRIES, priv)
    out = await JwsCatalogProfile().verify(None, {"entries": _ENTRIES, "signature": sig, "public_key": _pem(priv)})
    assert out.status is ProofStatus.VERIFIED
    assert out.evidence_ref.startswith("jws-catalog:")


@pytest.mark.asyncio
async def test_catalog_hijack_tampered_entry_fails():
    # An entry's endpoint is swapped while the old signature is left in place → FAILED.
    priv = ec.generate_private_key(ec.SECP256R1())
    sig = _sign_catalog(_ENTRIES, priv)
    hijacked = [dict(_ENTRIES[0], url="https://evil.example/finance.json"), _ENTRIES[1]]
    out = await JwsCatalogProfile().verify(None, {"entries": hijacked, "signature": sig, "public_key": _pem(priv)})
    assert out.status is ProofStatus.FAILED
    assert "tampered" in out.failure_reason


@pytest.mark.asyncio
async def test_wrong_key_fails():
    priv, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    sig = _sign_catalog(_ENTRIES, priv)
    out = await JwsCatalogProfile().verify(None, {"entries": _ENTRIES, "signature": sig, "public_key": _pem(other)})
    assert out.status is ProofStatus.FAILED


@pytest.mark.asyncio
async def test_jwks_key_selection_by_kid():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "k1",
           "x": _b64url(nums.x.to_bytes(32, "big")), "y": _b64url(nums.y.to_bytes(32, "big"))}
    sig = _sign_catalog(_ENTRIES, priv, kid="k1")
    out = await JwsCatalogProfile().verify(None, {"entries": _ENTRIES, "signature": sig, "jwks": {"keys": [jwk]}})
    assert out.status is ProofStatus.VERIFIED


@pytest.mark.asyncio
async def test_missing_pieces_are_not_verified():
    p = JwsCatalogProfile()
    assert (await p.verify(None, {})).status is ProofStatus.NOT_VERIFIED
    assert (await p.verify(None, {"entries": _ENTRIES, "signature": "not-a-jws"})).status is ProofStatus.NOT_VERIFIED
    # no key supplied
    priv = ec.generate_private_key(ec.SECP256R1())
    sig = _sign_catalog(_ENTRIES, priv)
    assert (await p.verify(None, {"entries": _ENTRIES, "signature": sig})).status is ProofStatus.NOT_VERIFIED
