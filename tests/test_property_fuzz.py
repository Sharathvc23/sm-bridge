"""Property-based + fuzz + DoS tests for the verification-critical paths.

Enumerated tests prove the documented cases; these prove invariants over *randomized* input
and that hostile/oversized input degrades safely (NOT_VERIFIED / FAILED, never a crash and
never a spurious VERIFIED).
"""

from __future__ import annotations

import asyncio
import hashlib

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_scitt import (
    AnsScittProfile,
    rfc9162_root_from_proof,
)
from sm_bridge.trust.delegation import NandaDelegationProfile
from sm_bridge.trust.ed25519_agentcard import canonicalize


def _run(coro):
    return asyncio.run(coro)


# ============================ Merkle proof — properties =================================

def _leaf(e: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + e).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _mth(es):
    if len(es) == 1:
        return _leaf(es[0])
    k = 1
    while (k << 1) < len(es):
        k <<= 1
    return _node(_mth(es[:k]), _mth(es[k:]))


def _path(m, es):
    if len(es) == 1:
        return []
    k = 1
    while (k << 1) < len(es):
        k <<= 1
    return _path(m, es[:k]) + [_mth(es[k:])] if m < k else _path(m - k, es[k:]) + [_mth(es[:k])]


@given(n=st.integers(min_value=1, max_value=64), seed=st.integers(0, 2**32))
def test_honest_inclusion_proof_always_reconstructs_root(n, seed):
    entries = [f"e-{seed}-{i}".encode() for i in range(n)]
    root = _mth(entries)
    for m in range(n):
        got = rfc9162_root_from_proof(_leaf(entries[m]), m, n, _path(m, entries))
        assert got == root


@given(n=st.integers(min_value=2, max_value=48), tamper=st.integers(0, 2**16))
def test_tampered_leaf_never_reconstructs_root(n, tamper):
    entries = [f"x-{i}".encode() for i in range(n)]
    root = _mth(entries)
    m = tamper % n
    forged = bytes(b ^ 0xFF for b in _leaf(entries[m]))
    got = rfc9162_root_from_proof(forged, m, n, _path(m, entries))
    assert got != root  # a forged leaf cannot walk to the genuine root


# ============================ canonicalize — properties ================================

_json_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(-1000, 1000), st.text(max_size=12)
)
_json_objs = st.dictionaries(st.text(min_size=1, max_size=8), _json_scalars, max_size=6)


@given(obj=_json_objs)
def test_canonicalize_is_key_order_independent(obj):
    # Re-inserting the same keys in reverse order must not change the canonical bytes.
    shuffled = dict(reversed(list(obj.items())))
    assert canonicalize(obj) == canonicalize(shuffled)


@given(obj=_json_objs)
def test_canonicalize_is_deterministic_and_utf8(obj):
    a = canonicalize(obj)
    assert a == canonicalize(obj)
    assert isinstance(a, bytes)


# ============================ scope containment — properties ============================

@given(
    prefix=st.lists(st.sampled_from(["a", "b", "c"]), min_size=1, max_size=4),
    extra=st.lists(st.sampled_from(["x", "y"]), min_size=1, max_size=3),
)
def test_child_scope_under_parent_is_covered_sibling_is_not(prefix, extra):
    from sm_bridge.trust.delegation import scope_covers

    parent = ".".join(prefix)
    child = parent + "." + ".".join(extra)
    assert scope_covers(parent, child)          # a.b covers a.b.x
    assert scope_covers(parent, parent)         # reflexive
    assert not scope_covers(parent + "z", child)  # label-boundary: a.bz does NOT cover a.b.x


# ============================ COSE fuzz — never crash, never spurious pass ==============

@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(blob=st.binary(min_size=0, max_size=300))
def test_ans_scitt_fuzz_random_bytes_never_crash_never_verified(blob):
    key = Ed25519PrivateKey.generate().public_key()  # wrong key type on purpose
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    out = _run(AnsScittProfile().verify(None, {"receipt": blob, "public_key": pem}))
    assert out.status is not ProofStatus.VERIFIED  # random bytes can never verify


@given(depth=st.integers(min_value=1, max_value=40))
def test_ans_scitt_deeply_nested_cbor_bomb_degrades_safely(depth):
    # A deeply-nested CBOR structure must not crash the parser — it degrades to an honest
    # non-VERIFIED result.
    bomb = b"\x00"
    for _ in range(depth):
        bomb = cbor2.dumps([bomb])
    out = _run(AnsScittProfile().verify(None, {"receipt": bomb, "public_key": b"x"}))
    assert out.status is not ProofStatus.VERIFIED


# ============================ DoS guards ===============================================

def test_ans_scitt_oversized_receipt_rejected():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    huge = b"\x00" * (256 * 1024 + 1)
    out = _run(AnsScittProfile().verify(None, {"receipt": huge, "public_key": pem}))
    assert out.status is ProofStatus.NOT_VERIFIED
    assert "cap" in (out.failure_reason or "")


def test_ans_scitt_overlong_merkle_path_rejected():
    import pytest

    with pytest.raises(ValueError, match="DoS guard"):
        rfc9162_root_from_proof(_leaf(b"a"), 0, 2, [b"\x00" * 32] * 100)


def test_delegation_overlong_chain_rejected():
    chain = [{"delegationId": f"d{i}"} for i in range(65)]
    out = _run(NandaDelegationProfile().verify(
        None, {"chain": chain, "signatures": {}, "provider_scopes": ["a"]}
    ))
    assert out.status is ProofStatus.FAILED
    assert "exceeds cap" in out.failure_reason
