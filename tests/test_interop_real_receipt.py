"""Interop (baked fixture) — a receipt produced by the real ANS transparency log is
verified by our Python ans-scitt adapter.

The fixture in ``tests/fixtures/ans/`` was emitted by the actual ``ans-tl`` reference server
(a live AGENT_REGISTERED event) together with its ``/root-keys`` line. Unlike the live
``ans-verify`` interop test, this needs no Go toolchain — it proves the "real Go produces →
our Python verifies" direction anywhere the suite runs.
"""

from __future__ import annotations

import asyncio
import base64
import pathlib

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_scitt import AnsScittProfile

_FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "ans"


def _spki_from_root_keys() -> bytes:
    line = (_FIX / "real_tl_root-keys.txt").read_text().strip().splitlines()[0]
    _origin, _keyhash, blob = line.split("+", 2)
    raw = base64.b64decode(blob)
    assert raw[0] == 0x02, "root-keys algorithm byte should be 0x02 (ECDSA P-256)"
    return raw[1:]  # the SubjectPublicKeyInfo DER


def test_real_ans_tl_receipt_verifies():
    receipt = (_FIX / "real_tl_receipt.cbor").read_bytes()
    out = asyncio.run(AnsScittProfile().verify(None, {"receipt": receipt, "public_key": _spki_from_root_keys()}))
    assert out.status is ProofStatus.VERIFIED, out.failure_reason
    assert out.method == "scitt-cose-merkle"


def test_tampered_real_receipt_is_rejected():
    receipt = bytearray((_FIX / "real_tl_receipt.cbor").read_bytes())
    receipt[len(receipt) // 2] ^= 0x01  # flip one byte
    out = asyncio.run(AnsScittProfile().verify(None, {"receipt": bytes(receipt), "public_key": _spki_from_root_keys()}))
    assert out.status is not ProofStatus.VERIFIED
