"""ANS / SCITT trust-profile tests.

Fixtures are generated in-test (no live ANS transparency log required): we build a real
ECDSA P-256 key, a real RFC 6962/9162 Merkle tree of >= 3 leaves
(``SHA-256(0x00||leaf)`` / ``SHA-256(0x01||L||R)``), craft a genuine COSE_Sign1 receipt
(protected header + VDP per the ANS SCITT receipt layout, ES256
signature in IEEE P1363 raw form), and assert VERIFIED. Then we red-team every check.

The in-test inclusion-proof *generator* (``_inclusion_path`` / ``_mth``) is deliberately a
separate implementation from the profile's ``rfc9162_root_from_proof`` *walk* — a shared
helper could let a generator bug and a verifier bug cancel out. The generator follows
RFC 6962 §2.1.3.1 PATH(m, D); the verifier follows §2.1.3.2.

Byte-compat note: the receipt bytes are produced with the same field layout and
core-deterministic CBOR (cbor2 ``canonical=True``, which matches Go's ``CoreDetEncOptions``
key ordering for these headers) the real ANS TL emits. The signed ``Sig_structure`` is a
plain array, so its bytes equal Go's byte-for-byte. Running the actual ``ans-verify``
binary against these fixtures is a follow-up (Go toolchain absent here).
"""

from __future__ import annotations

import hashlib

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_scitt import (
    AnsScittProfile,
    rfc9162_leaf_hash,
    rfc9162_root_from_proof,
    spki_kid,
)

# COSE / SCITT wire labels (mirror constants.go).
LABEL_ALG = 1
LABEL_KID = 4
LABEL_VDS = 395
LABEL_CWT = 15
CWT_ISS = 1
CWT_IAT = 6
LABEL_VDP = 396
VDP_TREE_SIZE = -1
VDP_LEAF_INDEX = -2
VDP_HASH_PATH = -3
VDP_ROOT_HASH = -4
ALG_ES256 = -7
VDS_RFC9162 = 1
COSE_SIGN1_TAG = 18


# ======================================================================================
# In-test Merkle generator (RFC 6962 §2.1.3.1) — INDEPENDENT of the verifier's walk.
# ======================================================================================

def _leaf(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def _mth(entries: list[bytes]) -> bytes:
    """Merkle Tree Hash of a list of raw entries (RFC 6962 §2.1.1)."""
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf(entries[0])
    k = _largest_pow2_below(n)
    return _node(_mth(entries[:k]), _mth(entries[k:]))


def _inclusion_path(m: int, entries: list[bytes]) -> list[bytes]:
    """Audit path for leaf m among entries (RFC 6962 §2.1.3.1 PATH(m, D))."""
    n = len(entries)
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return _inclusion_path(m, entries[:k]) + [_mth(entries[k:])]
    return _inclusion_path(m - k, entries[k:]) + [_mth(entries[:k])]


# ======================================================================================
# In-test receipt builder — same field layout / core-det CBOR the real TL emits.
# ======================================================================================

def _build_protected(kid: bytes, iss: str = "example.ans.log", iat: int = 1_700_000_000) -> bytes:
    return cbor2.dumps(
        {
            LABEL_ALG: ALG_ES256,
            LABEL_KID: kid,
            LABEL_VDS: VDS_RFC9162,
            LABEL_CWT: {CWT_ISS: iss, CWT_IAT: iat},
        },
        canonical=True,
    )


def _p1363_sign(priv: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign `message` with ES256, returning a 64-byte IEEE P1363 raw r||s signature."""
    from cryptography.hazmat.primitives import hashes

    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _build_receipt(
    priv: ec.EllipticCurvePrivateKey,
    payload: bytes,
    tree_size: int,
    leaf_index: int,
    path: list[bytes],
    root_hash: bytes,
    *,
    sign_key: ec.EllipticCurvePrivateKey | None = None,
    detached: bool = False,
    protected_override: bytes | None = None,
    tag: bool = True,
) -> bytes:
    """Assemble a COSE_Sign1 receipt. `sign_key` defaults to `priv` (the honest signer)."""
    pub = priv.public_key()
    kid = spki_kid(pub)
    protected = protected_override if protected_override is not None else _build_protected(kid)

    vdp = {
        VDP_TREE_SIZE: tree_size,
        VDP_LEAF_INDEX: leaf_index,
        VDP_HASH_PATH: path,
        VDP_ROOT_HASH: root_hash,
    }
    unprotected = {LABEL_VDP: vdp}

    signer = sign_key if sign_key is not None else priv
    sig_struct = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    sig = _p1363_sign(signer, sig_struct)

    cose_payload = None if detached else payload
    arr = [protected, unprotected, cose_payload, sig]
    if tag:
        return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, arr), canonical=True)
    return cbor2.dumps(arr, canonical=True)


class _Tree:
    """A generated Merkle tree + a valid receipt for one chosen leaf."""

    def __init__(self, priv: ec.EllipticCurvePrivateKey, entries: list[bytes], index: int) -> None:
        self.priv = priv
        self.entries = entries
        self.index = index
        self.payload = entries[index]
        self.tree_size = len(entries)
        self.path = _inclusion_path(index, entries)
        self.root = _mth(entries)

    def receipt(self, **over) -> bytes:
        params = {
            "priv": self.priv,
            "payload": self.payload,
            "tree_size": self.tree_size,
            "leaf_index": self.index,
            "path": list(self.path),
            "root_hash": self.root,
        }
        params.update(over)
        return _build_receipt(**params)


@pytest.fixture()
def keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
def pubkey_pem(keypair: ec.EllipticCurvePrivateKey) -> bytes:
    return keypair.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture()
def tree(keypair: ec.EllipticCurvePrivateKey) -> _Tree:
    # >= 3 leaves for the happy path (per the mandate: no degenerate single-leaf happy case).
    entries = [f"event-{i}".encode() for i in range(5)]
    return _Tree(keypair, entries, index=2)


def _profile() -> AnsScittProfile:
    return AnsScittProfile()


# ======================================================================================
# Merkle math sanity — generator and verifier must agree on a real tree.
# ======================================================================================

def test_generator_and_verifier_agree_on_root():
    entries = [f"e{i}".encode() for i in range(7)]
    root = _mth(entries)
    for i in range(len(entries)):
        path = _inclusion_path(i, entries)
        walked = rfc9162_root_from_proof(_leaf(entries[i]), i, len(entries), path)
        assert walked == root, f"leaf {i} did not reconstruct the root"


def test_leaf_hash_matches_rfc6962():
    assert rfc9162_leaf_hash(b"abc") == hashlib.sha256(b"\x00abc").digest()


def test_walk_rejects_tree_size_zero():
    with pytest.raises(ValueError, match="tree size is zero"):
        rfc9162_root_from_proof(_leaf(b"x"), 0, 0, [])


def test_walk_rejects_leaf_index_out_of_range():
    with pytest.raises(ValueError, match="leaf index"):
        rfc9162_root_from_proof(_leaf(b"x"), 3, 3, [])


def test_walk_rejects_wrong_length_path_element():
    entries = [b"a", b"b", b"c"]
    path = _inclusion_path(0, entries)
    path[0] = path[0][:-1]  # 31 bytes
    with pytest.raises(ValueError, match="wrong length"):
        rfc9162_root_from_proof(_leaf(entries[0]), 0, len(entries), path)


def test_walk_rejects_short_path():
    # Leaf 3 in a size-4 tree needs a 2-element path; truncating it leaves fn != 0 at the
    # end of the walk, which is exactly the "proof path too short" rejection (RFC 9162).
    entries = [b"a", b"b", b"c", b"d"]
    path = _inclusion_path(3, entries)
    assert len(path) == 2
    with pytest.raises(ValueError, match="too short"):
        rfc9162_root_from_proof(_leaf(entries[3]), 3, len(entries), path[:-1])


# ======================================================================================
# Happy path — real signature + real Merkle reconstruction → VERIFIED.
# ======================================================================================

async def test_happy_path_verified(tree: _Tree, pubkey_pem: bytes):
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": pubkey_pem})
    assert res.status is ProofStatus.VERIFIED, res.failure_reason
    assert res.evidence_ref == f"scitt:{tree.root.hex()[:16]}"
    assert res.profile == "ans-scitt"
    assert res.method == "scitt-cose-merkle"


async def test_happy_path_accepts_der_public_key(tree: _Tree, keypair):
    der = keypair.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": der})
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


async def test_happy_path_accepts_pem_str(tree: _Tree, pubkey_pem: bytes):
    res = await _profile().verify(
        None, {"receipt": tree.receipt(), "public_key": pubkey_pem.decode()}
    )
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


async def test_happy_path_untagged_array_form(tree: _Tree, pubkey_pem: bytes):
    receipt = tree.receipt(tag=False)
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


async def test_verify_verifies_receipt_not_issuer_identity(tree: _Tree, pubkey_pem: bytes):
    """Bug class ii: a pass attests the RECEIPT (producer-key signature), never the issuer.

    evidence_ref/method must say "receipt verified" (scitt / cose-merkle), and must NOT
    claim issuer identity. ANS issuer keys live only in sealed IDENTITY_* events; a
    producer key can never attest an issuer.
    """
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": pubkey_pem})
    assert res.status is ProofStatus.VERIFIED
    assert res.evidence_ref.startswith("scitt:")
    assert "issuer" not in res.method.lower()
    assert "issuer" not in (res.evidence_ref or "").lower()
    assert "identity" not in res.method.lower()


# ======================================================================================
# Red team — every failure mode.
# ======================================================================================

async def test_tampered_payload_fails(tree: _Tree, keypair, pubkey_pem: bytes):
    # Sign over a different payload than the one whose leaf is in the tree.
    forged = _build_receipt(
        priv=keypair,
        payload=b"tampered-event",
        tree_size=tree.tree_size,
        leaf_index=tree.index,
        path=list(tree.path),
        root_hash=tree.root,
    )
    res = await _profile().verify(None, {"receipt": forged, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "root does not match" in (res.failure_reason or "")


async def test_wrong_key_fails(tree: _Tree):
    # Merkle proof is valid, but verify against a DIFFERENT public key → signature fails.
    other = ec.generate_private_key(ec.SECP256R1())
    other_pem = other.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": other_pem})
    assert res.status is ProofStatus.FAILED
    assert "signature invalid" in (res.failure_reason or "")


async def test_tampered_merkle_path_fails(tree: _Tree, pubkey_pem: bytes):
    bad_path = list(tree.path)
    flipped = bytearray(bad_path[0])
    flipped[0] ^= 0xFF
    bad_path[0] = bytes(flipped)
    res = await _profile().verify(
        None, {"receipt": tree.receipt(path=bad_path), "public_key": pubkey_pem}
    )
    assert res.status is ProofStatus.FAILED
    assert "root does not match" in (res.failure_reason or "")


async def test_tree_size_zero_fails(tree: _Tree, pubkey_pem: bytes):
    receipt = tree.receipt(tree_size=0, leaf_index=0, path=[])
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "tree size is zero" in (res.failure_reason or "")


async def test_leaf_index_out_of_range_fails(tree: _Tree, pubkey_pem: bytes):
    receipt = tree.receipt(leaf_index=tree.tree_size + 1)
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "leaf index" in (res.failure_reason or "")


async def test_detached_payload_fails(tree: _Tree, pubkey_pem: bytes):
    receipt = tree.receipt(detached=True)
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "detached" in (res.failure_reason or "")


async def test_short_signature_fails(tree: _Tree, keypair, pubkey_pem: bytes):
    # Build a valid receipt, then truncate the signature to 63 bytes.
    receipt = tree.receipt()
    tag = cbor2.loads(receipt)
    arr = list(tag.value)  # cbor2 decodes tag content as a tuple
    arr[3] = arr[3][:-1]
    broken = cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, arr), canonical=True)
    res = await _profile().verify(None, {"receipt": broken, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "signature length" in (res.failure_reason or "")


# ----- The degenerate treeSize==1 forgery (bug class i) -------------------------------

async def test_degenerate_single_leaf_forgery_fails_signature(keypair, pubkey_pem: bytes):
    """A forged treeSize=1/leafIndex=0/empty-path/root==leafHash receipt passes an
    ISOLATED Merkle walk — so the signature is the only thing standing between it and a
    false VERIFIED. Signed by an attacker key, verified against the real key → FAILED.
    """
    payload = b"forged-single-leaf-event"
    leaf = _leaf(payload)
    # Sanity: this receipt's Merkle walk trivially reconstructs (root == leafHash).
    assert rfc9162_root_from_proof(leaf, 0, 1, []) == leaf

    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = _build_receipt(
        priv=keypair,          # kid advertises the real key...
        payload=payload,
        tree_size=1,
        leaf_index=0,
        path=[],
        root_hash=leaf,        # forged root == leaf hash: passes isolated walk
        sign_key=attacker,     # ...but actually signed by the attacker
    )
    res = await _profile().verify(None, {"receipt": forged, "public_key": pubkey_pem})
    assert res.status is ProofStatus.FAILED
    assert "signature invalid" in (res.failure_reason or "")


async def test_degenerate_single_leaf_honestly_signed_still_verifies(keypair, pubkey_pem: bytes):
    """Control: the same single-leaf shape, honestly signed by the real key, VERIFIES —
    proving the previous test failed on the signature, not on the tree shape itself.
    """
    payload = b"honest-single-leaf-event"
    leaf = _leaf(payload)
    receipt = _build_receipt(
        priv=keypair, payload=payload, tree_size=1, leaf_index=0, path=[], root_hash=leaf
    )
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.VERIFIED, res.failure_reason


# ======================================================================================
# NOT_VERIFIED — can't even run the check (honest unknown, not a rejection).
# ======================================================================================

async def test_missing_receipt_not_verified(pubkey_pem: bytes):
    res = await _profile().verify(None, {"public_key": pubkey_pem})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "no receipt" in (res.failure_reason or "")


async def test_missing_public_key_not_verified(tree: _Tree):
    res = await _profile().verify(None, {"receipt": tree.receipt()})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "no public_key" in (res.failure_reason or "")


async def test_unparseable_receipt_not_verified(pubkey_pem: bytes):
    res = await _profile().verify(None, {"receipt": b"\xff\xff not cbor", "public_key": pubkey_pem})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "unparseable" in (res.failure_reason or "")


async def test_receipt_missing_vdp_not_verified(keypair, pubkey_pem: bytes):
    # A COSE_Sign1 with an empty unprotected header (no VDP label 396).
    payload = b"event"
    protected = _build_protected(spki_kid(keypair.public_key()))
    sig = _p1363_sign(keypair, cbor2.dumps(["Signature1", protected, b"", payload], canonical=True))
    receipt = cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, sig]), canonical=True)
    res = await _profile().verify(None, {"receipt": receipt, "public_key": pubkey_pem})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "inclusion proof" in (res.failure_reason or "")


async def test_bad_public_key_not_verified(tree: _Tree):
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": b"not a key"})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "public_key" in (res.failure_reason or "")


async def test_wrong_curve_key_not_verified(tree: _Tree):
    p384 = ec.generate_private_key(ec.SECP384R1())
    pem = p384.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    res = await _profile().verify(None, {"receipt": tree.receipt(), "public_key": pem})
    assert res.status is ProofStatus.NOT_VERIFIED
    assert "secp256r1" in (res.failure_reason or "") or "P-256" in (res.failure_reason or "")


async def test_non_dict_evidence_not_verified():
    res = await _profile().verify(None, [])  # type: ignore[arg-type]
    assert res.status is ProofStatus.NOT_VERIFIED


# ======================================================================================
# kid helper — matches the reference SPKIKeyHash4 shape.
# ======================================================================================

def test_spki_kid_is_sha256_spki_first4(keypair):
    pub = keypair.public_key()
    der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert spki_kid(pub) == hashlib.sha256(der).digest()[:4]
    assert len(spki_kid(pub)) == 4


def test_profile_id_is_stable():
    assert AnsScittProfile.profile_id == "ans-scitt"
    assert AnsScittProfile().profile_id == "ans-scitt"
