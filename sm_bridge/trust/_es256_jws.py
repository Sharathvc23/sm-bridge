"""Shared ES256 (ECDSA P-256) detached-JWS primitives.

The demo's delegation credentials (``nanda-delegation``) and its ARD signed catalog
(``jws-catalog``) both authenticate with an ES256 detached JWS: the signing input is
``b64url(header) . b64url(payload)`` (RFC 7515 App. F detached — the payload is base64url in
the signing input, omitted only on the wire), and the signature is a 64-byte IEEE P1363
``r||s`` blob. This module holds the sign/verify pair and P-256 public-key loading (PEM, DER,
JWK, or a ``did:key`` P-256 identifier) so both profiles verify byte-compatibly with the demo.

Requires the ``[trust]`` extra (``cryptography``); imported lazily by the profiles.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_ec_p256_public(key: Any) -> EllipticCurvePublicKey:
    """Load an ECDSA P-256 public key from PEM/DER bytes, a PEM str, a JWK dict, a
    ``did:key`` P-256 string, or an existing key object. Raises ValueError otherwise."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key,
        load_pem_public_key,
    )

    loaded: Any
    if isinstance(key, ec.EllipticCurvePublicKey):
        loaded = key
    elif isinstance(key, dict):  # JWK
        loaded = _p256_from_jwk(key)
    elif isinstance(key, str) and key.startswith("did:key:"):
        loaded = _p256_from_did_key(key)
    elif isinstance(key, str):
        loaded = load_pem_public_key(key.encode("utf-8"))
    elif isinstance(key, (bytes, bytearray)):
        raw = bytes(key)
        loaded = load_pem_public_key(raw) if raw.lstrip().startswith(b"-----BEGIN") else load_der_public_key(raw)
    else:
        raise ValueError(f"unsupported public key type: {type(key).__name__}")

    if not isinstance(loaded, ec.EllipticCurvePublicKey):
        raise ValueError("public key is not an ECDSA key")
    if loaded.curve.name != "secp256r1":
        raise ValueError(f"public key curve is {loaded.curve.name}, want secp256r1 (P-256)")
    return loaded


def _p256_from_jwk(jwk: dict[str, Any]) -> EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.asymmetric import ec

    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("JWK is not an EC P-256 key")
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _p256_from_did_key(did: str) -> EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.asymmetric import ec

    # did:key:z<base58btc(multicodec 0x1200 || compressed SEC1 point)>
    ident = did.removeprefix("did:key:")
    if not ident.startswith("z"):
        raise ValueError("did:key must be base58btc (z-prefixed)")
    decoded = _b58decode(ident[1:])
    if decoded[:2] != b"\x80\x24":  # multicodec p256-pub = 0x1200 varint
        raise ValueError("did:key is not a P-256 key (multicodec != 0x1200)")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded[2:])


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + _B58.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def signing_input(header_b64: str, payload_canonical: bytes) -> bytes:
    """RFC 7515 detached signing input: ``header_b64 . b64url(payload)``."""
    return header_b64.encode("ascii") + b"." + b64url(payload_canonical).encode("ascii")


def sign_es256(header_b64: str, payload_canonical: bytes, private_key: Any) -> str:
    """Sign the detached input; return the 64-byte P1363 signature as base64url. (Producers/tests.)"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der = private_key.sign(signing_input(header_b64, payload_canonical), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_es256(header_b64: str, payload_canonical: bytes, sig_b64url: str, public_key: Any) -> bool:
    """Verify a P1363 ES256 signature over the detached input. False on any failure."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        raw = b64url_decode(sig_b64url)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pub = load_ec_p256_public(public_key)
        pub.verify(der, signing_input(header_b64, payload_canonical), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, Exception):  # noqa: BLE001 - any failure = not verified
        return False


__all__ = [
    "b64url",
    "b64url_decode",
    "load_ec_p256_public",
    "signing_input",
    "sign_es256",
    "verify_es256",
]
