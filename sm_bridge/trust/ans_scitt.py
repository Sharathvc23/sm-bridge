"""ANS / SCITT trust profile — verifies a transparency-log COSE_Sign1 receipt.

This adapter implements the ANS transparency-log receipt verifier in Python. Given a
SCITT-style COSE_Sign1 receipt and the transparency-log producer's ECDSA P-256
public key, it proves three things — and only these three:

1. the receipt's attached event payload hashes to an RFC 9162 leaf,
2. the inclusion proof in the receipt's VDP walks to the asserted Merkle root, and
3. the receipt was signed (ES256) by the supplied public key.

Honesty rule (spine invariant): a ``VERIFIED`` ``ProofResult`` is emitted only after a
*real* COSE signature check AND a *real* Merkle-root reconstruction that matches the
receipt's claimed root. There is no mock pass — a receipt that cannot even be parsed
returns ``not_verified``; a receipt that parses but fails a check returns ``failed``.

------------------------------------------------------------------------------------
PRODUCER KEY vs ISSUER IDENTITY — read before extending (bug class ii).
------------------------------------------------------------------------------------
The key this profile verifies against is the transparency log's **producer / receipt
signing key** (the single ECDSA P-256 key the ANS TL advertises at ``/root-keys``). A
VERIFIED result here means "this receipt was really signed by that log and its event is
really in that log's tree" — it says **nothing** about *who the issuer of the underlying
agent event is*.

Issuer-identity binding is a **separate concern** in ANS: ``VerifiedIdentity`` carries no
public-key field at all (ANS-0 §6.2 "key transience"); the keys that prove an issuer's
control live only inside sealed ``IDENTITY_VERIFIED`` / ``IDENTITY_UPDATED`` TL events as
``ProvenKey = {verificationMethod, signedProof(JWS)}``. A producer key must never be used
to attest an issuer, and a proven DID key must never be treated as a producer key. This
profile therefore deliberately reports ``method='scitt-cose-merkle'`` and an
``evidence_ref`` of the form ``scitt:<root16>`` — "receipt verified", never
"issuer verified".

------------------------------------------------------------------------------------
Wire fidelity: the reader/writer follow the ANS SCITT receipt field layout and encode the
protected header + ``Sig_structure`` as core-deterministic CBOR. The signed ``Sig_structure``
is a plain array (no map-ordering ambiguity), so its bytes are stable across implementations.
End-to-end interoperability against the ANS reference verifier is tracked as a follow-up.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from sm_bridge.trust.base import ProofResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sm_bridge.models import SmAgentFacts

_PROFILE_ID = "ans-scitt"
_METHOD = "scitt-cose-merkle"

# COSE / SCITT wire labels (per the ANS SCITT receipt contract).
_LABEL_VDP = 396  # unprotected: Verifiable Data Structure Proofs
_VDP_TREE_SIZE = -1
_VDP_LEAF_INDEX = -2
_VDP_HASH_PATH = -3
_VDP_ROOT_HASH = -4

_SHA256_SIZE = 32
_COSE_SIGN1_TAG = 18
_P1363_SIG_LEN = 64  # ES256 raw r||s, 32 bytes each


# --------------------------------------------------------------------------------------
# RFC 9162 Merkle math — kept INDEPENDENT from any proof-generation helper on purpose,
# so a generator bug can't hide behind a shared round-trip.
# --------------------------------------------------------------------------------------

def rfc9162_leaf_hash(entry: bytes) -> bytes:
    """RFC 6962 §2.1 / RFC 9162 leaf hash: SHA-256(0x00 || entry)."""
    return hashlib.sha256(b"\x00" + entry).digest()


def _hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 9162 interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def rfc9162_root_from_proof(
    leaf_hash: bytes, leaf_index: int, tree_size: int, path: list[bytes]
) -> bytes:
    """Reconstruct the Merkle root from an inclusion proof (RFC 9162 §2.1.3.2).

    Implements the RFC 9162 proof walk independently of any tree/proof *builder* — it only
    consumes a leaf hash, its position, the tree size, and the sibling path, and walks upward.

    Raises ``ValueError`` on the structural rejections the reference enforces:
    ``tree_size == 0``, ``leaf_index >= tree_size``, a path element of wrong length, or a
    path that is too short to reach the root.
    """
    if tree_size == 0:
        raise ValueError("tree size is zero")
    if leaf_index >= tree_size:
        raise ValueError(f"leaf index {leaf_index} >= tree size {tree_size}")
    if leaf_index < 0:
        raise ValueError(f"leaf index {leaf_index} is negative")

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash

    for p in path:
        if len(p) != _SHA256_SIZE:
            raise ValueError(f"path element wrong length: {len(p)}")
        if fn & 1 == 1 or fn == sn:
            r = _hash_children(p, r)
            while fn != 0 and fn & 1 == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _hash_children(r, p)
        fn >>= 1
        sn >>= 1

    if fn != 0:
        raise ValueError("proof path too short")
    return r


# --------------------------------------------------------------------------------------
# COSE_Sign1 parsing — faithful to the ANS SCITT receipt field layout.
# --------------------------------------------------------------------------------------

class _ReceiptParseError(Exception):
    """Receipt bytes are missing/unparseable/structurally not a COSE_Sign1 receipt."""


class _ParsedReceipt:
    __slots__ = ("protected_bytes", "unprotected", "payload", "signature")

    def __init__(
        self,
        protected_bytes: bytes,
        unprotected: Mapping[Any, Any],
        payload: bytes | None,
        signature: bytes,
    ) -> None:
        self.protected_bytes = protected_bytes
        self.unprotected = unprotected
        self.payload = payload
        self.signature = signature


def _parse_cose_sign1(data: Any) -> _ParsedReceipt:
    """Parse tag-18-wrapped or bare 4-array COSE_Sign1 into its fields.

    Matches the reference's permissive parser: accepts either the CBOR tag-18 form or an
    untagged 4-element array. Does NOT re-encode the protected header — the original
    protected byte string is preserved verbatim for the Sig_structure (as the reference
    does), so signature verification never depends on our own encoder's canonicality.
    """
    import cbor2  # lazy — [trust] extra

    if not isinstance(data, (bytes, bytearray)):
        raise _ReceiptParseError(f"receipt must be CBOR bytes, got {type(data).__name__}")
    try:
        obj = cbor2.loads(bytes(data))
    except Exception as exc:  # noqa: BLE001 - normalize any cbor2 decode failure
        raise _ReceiptParseError(f"receipt is not valid CBOR: {exc}") from exc

    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != _COSE_SIGN1_TAG:
            raise _ReceiptParseError(f"unexpected CBOR tag {obj.tag}, want {_COSE_SIGN1_TAG}")
        arr = obj.value
    else:
        arr = obj

    # cbor2 decodes a tag's content as a tuple and a top-level array as a list; accept both.
    if not isinstance(arr, (list, tuple)) or len(arr) != 4:
        raise _ReceiptParseError("COSE_Sign1 must be a 4-element array")

    protected, unprotected, payload, signature = arr

    if not isinstance(protected, (bytes, bytearray)):
        raise _ReceiptParseError("protected header must be a byte string")
    # cbor2 yields a frozendict (not a plain dict) for maps nested inside a CBOR tag.
    if not isinstance(unprotected, Mapping):
        raise _ReceiptParseError("unprotected header must be a map")
    # payload: attached byte string, or None for detached (rejected downstream).
    if payload is not None and not isinstance(payload, (bytes, bytearray)):
        raise _ReceiptParseError("payload must be a byte string or null")
    if not isinstance(signature, (bytes, bytearray)):
        raise _ReceiptParseError("signature must be a byte string")

    return _ParsedReceipt(
        protected_bytes=bytes(protected),
        unprotected=unprotected,
        payload=None if payload is None else bytes(payload),
        signature=bytes(signature),
    )


class _ProofFields:
    __slots__ = ("tree_size", "leaf_index", "path", "root_hash")

    def __init__(self, tree_size: int, leaf_index: int, path: list[bytes], root_hash: bytes) -> None:
        self.tree_size = tree_size
        self.leaf_index = leaf_index
        self.path = path
        self.root_hash = root_hash


def _extract_inclusion_proof(unprotected: Mapping[Any, Any]) -> _ProofFields:
    """Pull the VDP (label 396) inclusion proof out of the unprotected header."""
    if _LABEL_VDP not in unprotected:
        raise _ReceiptParseError(f"unprotected header missing VDP (label {_LABEL_VDP})")
    vdp = unprotected[_LABEL_VDP]
    if not isinstance(vdp, Mapping):
        raise _ReceiptParseError("VDP is not a map")

    if _VDP_TREE_SIZE not in vdp:
        raise _ReceiptParseError("VDP missing treeSize")
    if _VDP_LEAF_INDEX not in vdp:
        raise _ReceiptParseError("VDP missing leafIndex")
    if _VDP_HASH_PATH not in vdp:
        raise _ReceiptParseError("VDP missing hashPath")
    if _VDP_ROOT_HASH not in vdp:
        raise _ReceiptParseError("VDP missing rootHash")

    tree_size = vdp[_VDP_TREE_SIZE]
    leaf_index = vdp[_VDP_LEAF_INDEX]
    raw_path = vdp[_VDP_HASH_PATH]
    root_hash = vdp[_VDP_ROOT_HASH]

    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        raise _ReceiptParseError("VDP treeSize is not an integer")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise _ReceiptParseError("VDP leafIndex is not an integer")
    if not isinstance(raw_path, (list, tuple)):
        raise _ReceiptParseError("VDP hashPath is not an array")
    path: list[bytes] = []
    for i, e in enumerate(raw_path):
        if not isinstance(e, (bytes, bytearray)):
            raise _ReceiptParseError(f"VDP hashPath element {i} is not bytes")
        path.append(bytes(e))
    if not isinstance(root_hash, (bytes, bytearray)):
        raise _ReceiptParseError("VDP rootHash is not bytes")

    return _ProofFields(tree_size, leaf_index, path, bytes(root_hash))


# --------------------------------------------------------------------------------------
# Signature verification — ES256 over the COSE Sig_structure.
# --------------------------------------------------------------------------------------

def _load_public_key(pub: Any) -> Any:
    """Load a PEM or DER ECDSA P-256 public key. Returns the cryptography key object.

    Raises ``ValueError`` if the key cannot be loaded or is not an EC P-256 key — a
    caller configuration problem, surfaced by the profile as NOT_VERIFIED (can't run the
    check), never as a silent pass.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key,
        load_pem_public_key,
    )

    key: Any
    if isinstance(pub, ec.EllipticCurvePublicKey):
        key = pub
    elif isinstance(pub, str):
        key = load_pem_public_key(pub.encode("utf-8"))
    elif isinstance(pub, (bytes, bytearray)):
        raw = bytes(pub)
        if raw.lstrip().startswith(b"-----BEGIN"):
            key = load_pem_public_key(raw)
        else:
            key = load_der_public_key(raw)
    else:
        raise ValueError(f"public_key must be PEM/DER bytes or str, got {type(pub).__name__}")

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("public_key is not an ECDSA key")
    if key.curve.name != "secp256r1":
        raise ValueError(f"public_key curve is {key.curve.name}, want secp256r1 (P-256)")
    return key


def spki_kid(public_key: Any) -> bytes:
    """C2SP 4-byte opaque key hash used as the COSE ``kid``: SHA-256(SPKI-DER)[0:4].

    Mirrors ``crypto.SPKIKeyHash4`` in the reference. Informational on the verify path
    (the reference verifier trusts the caller-supplied key and the ES256 check is what
    actually binds the receipt to the key); exposed for receipt construction and
    diagnostics.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:4]


def _sig_structure_bytes(protected_bytes: bytes, payload: bytes) -> bytes:
    """core-deterministic CBOR of Sig_structure = ["Signature1", protected, h'', payload].

    The protected byte string is reused verbatim from the parsed receipt (never
    re-encoded), and ``external_aad`` is the empty byte string ``h''`` — present, not
    absent — exactly as /the ANS reference verifier build it. As a 4-element array with no map
    keys, its canonical encoding is unambiguous, so these bytes equal Go's CoreDet output.
    """
    import cbor2

    return cbor2.dumps(["Signature1", protected_bytes, b"", payload], canonical=True)


def _verify_es256(public_key: Any, protected_bytes: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify the ES256 signature over the Sig_structure. Returns True iff valid.

    The 64-byte IEEE P1363 raw ``r||s`` signature is converted to DER via
    ``encode_dss_signature`` before handing it to ``public_key.verify``. cryptography's
    ``ECDSA(SHA256())`` hashes the message internally — equivalent to the reference's
    ``ecdsa.Verify(pub, SHA256(sigStructure), r, s)``.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(signature) != _P1363_SIG_LEN:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_sig = encode_dss_signature(r, s)
    msg = _sig_structure_bytes(protected_bytes, payload)
    try:
        public_key.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


# --------------------------------------------------------------------------------------
# The trust profile.
# --------------------------------------------------------------------------------------

class AnsScittProfile:
    """Verifier for ANS SCITT COSE_Sign1 transparency-log receipts.

    ``evidence`` shape::

        {
            "receipt": <bytes>,      # the COSE_Sign1 receipt (tag 18 or bare 4-array)
            "public_key": <bytes|str>,  # PEM or DER ECDSA P-256 *producer* key
        }

    Outcome mapping:

    - fully valid (Merkle root reconstructs AND ES256 signature checks) → ``verified``
      with ``evidence_ref='scitt:<first-16-hex-of-root>'``;
    - a present receipt that fails a real check (Merkle mismatch, bad/short signature,
      detached payload, ``treeSize==0``, ``leafIndex>=treeSize``, wrong path length) →
      ``failed`` with the verbatim cause;
    - missing evidence, unparseable receipt, or an unusable public key → ``not_verified``.

    A VERIFIED result attests **receipt verification only** (the TL producer key signed a
    receipt whose event is in the log). It does NOT attest issuer identity — see the
    module docstring for the producer-key vs issuer-key separation.
    """

    profile_id = _PROFILE_ID

    async def verify(
        self, subject: SmAgentFacts | Any, evidence: dict[str, Any]
    ) -> ProofResult:
        del subject  # not used: this profile verifies the receipt, not agent-card fields

        if not isinstance(evidence, dict):
            return self._not_verified("evidence must be a dict with 'receipt' and 'public_key'")
        receipt = evidence.get("receipt")
        pub = evidence.get("public_key")
        if receipt is None:
            return self._not_verified("no receipt supplied in evidence")
        if pub is None:
            return self._not_verified("no public_key supplied in evidence")

        # --- load the producer key (config problem -> honest NOT_VERIFIED) -----------
        try:
            public_key = _load_public_key(pub)
        except Exception as exc:  # noqa: BLE001 - normalize key-load failure
            return self._not_verified(f"cannot load public_key: {exc}")

        # --- parse the receipt (unparseable -> honest NOT_VERIFIED) ------------------
        try:
            parsed = _parse_cose_sign1(receipt)
        except _ReceiptParseError as exc:
            return self._not_verified(f"unparseable receipt: {exc}")

        # --- detached payload is a real rejection ------------------------------------
        if parsed.payload is None or len(parsed.payload) == 0:
            return self._failed("detached payloads not supported: payload must be attached")

        # --- extract the inclusion proof (missing VDP -> honest NOT_VERIFIED) --------
        try:
            proof = _extract_inclusion_proof(parsed.unprotected)
        except _ReceiptParseError as exc:
            return self._not_verified(f"receipt has no usable inclusion proof: {exc}")

        if len(proof.root_hash) != _SHA256_SIZE:
            return self._failed(f"invalid root hash length {len(proof.root_hash)}")

        # --- REAL Merkle-root reconstruction -----------------------------------------
        leaf_hash = rfc9162_leaf_hash(parsed.payload)
        try:
            computed_root = rfc9162_root_from_proof(
                leaf_hash, proof.leaf_index, proof.tree_size, proof.path
            )
        except ValueError as exc:
            return self._failed(f"inclusion proof walk failed: {exc}")

        if computed_root != proof.root_hash:
            return self._failed("computed root does not match proof root")

        # --- REAL ES256 signature check ----------------------------------------------
        if len(parsed.signature) != _P1363_SIG_LEN:
            return self._failed(f"invalid ES256 signature length {len(parsed.signature)}")
        if not _verify_es256(public_key, parsed.protected_bytes, parsed.payload, parsed.signature):
            return self._failed("ECDSA signature invalid")

        # Both the Merkle reconstruction and the signature passed — a real VERIFIED.
        # evidence_ref/method reflect "receipt verified", never "issuer verified".
        return ProofResult.verified(
            profile=_PROFILE_ID,
            method=_METHOD,
            evidence_ref=f"scitt:{proof.root_hash.hex()[:16]}",
        )

    @staticmethod
    def _failed(reason: str) -> ProofResult:
        return ProofResult.failed(profile=_PROFILE_ID, method=_METHOD, reason=reason)

    @staticmethod
    def _not_verified(reason: str) -> ProofResult:
        return ProofResult.not_verified(profile=_PROFILE_ID, method=_METHOD, reason=reason)


__all__ = [
    "AnsScittProfile",
    "rfc9162_leaf_hash",
    "rfc9162_root_from_proof",
    "spki_kid",
]
