"""Phase 4 — RFC 6962 Merkle log, signed checkpoint, and the Demo 3 conformance self-test."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_bridge import conformance
from sm_bridge.tlog import MerkleLog, root_from_inclusion, root_keys_line


def _log(n: int) -> MerkleLog:
    log = MerkleLog(origin="test/tlog")
    for i in range(n):
        log.append(f"record-{i}".encode())
    return log


def test_inclusion_proof_reconstructs_root():
    log = _log(7)
    root = log.root()
    for i in range(log.size):
        proof = log.inclusion_proof(i)
        assert root_from_inclusion(log.leaf_at(i), i, log.size, proof) == root


def test_inclusion_proof_rejects_tampered_leaf():
    log = _log(7)
    proof = log.inclusion_proof(3)
    forged = b"\x00" * 32
    assert root_from_inclusion(forged, 3, log.size, proof) != log.root()


def test_proofs_refused_below_min_size():
    # Degenerate 1- and 2-leaf trees must not serve proofs.
    for n in (1, 2):
        with pytest.raises(ValueError, match="degenerate|treeSize"):
            _log(n).inclusion_proof(0)


def test_checkpoint_sign_and_verify():
    log = _log(5)
    sk = Ed25519PrivateKey.generate()
    cp = log.sign_checkpoint(sk)
    assert MerkleLog.verify_checkpoint(cp, sk.public_key())
    # tamper the signed root → verification fails
    cp.root_b64 = "AAAA" + cp.root_b64[4:]
    assert not MerkleLog.verify_checkpoint(cp, sk.public_key())


def test_root_keys_line_shape():
    sk = Ed25519PrivateKey.generate()
    line = root_keys_line("test/tlog", sk.public_key())
    origin, kid, blob = line.split("+", 2)  # base64 blob may itself contain '+'
    assert origin == "test/tlog"
    assert len(kid) == 8


# ----- the Demo 3 auditor, including the tamper beat --------------------------------

def test_conformance_audit_passes_clean_log():
    log = _log(6)
    sk = Ed25519PrivateKey.generate()
    cp = log.sign_checkpoint(sk)
    report = conformance.audit(log, cp, sk.public_key())
    assert report.passed, report.summary()


def test_conformance_append_only_holds_then_grows():
    log = _log(4)
    sk = Ed25519PrivateKey.generate()
    pinned = log.sign_checkpoint(sk)
    for i in range(3):
        log.append(f"more-{i}".encode())
    cp = log.sign_checkpoint(sk)
    report = conformance.audit(log, cp, sk.public_key(), pinned=pinned)
    assert report.passed, report.summary()


def test_conformance_catches_tamper():
    # Flip one stored leaf after signing — root recomputation must report DIVERGENT.
    log = _log(6)
    sk = Ed25519PrivateKey.generate()
    cp = log.sign_checkpoint(sk)  # signs the honest root
    log._leaves[2] = b"\xff" * 32  # noqa: SLF001 - simulate on-disk tamper
    report = conformance.audit(log, cp, sk.public_key())
    assert not report.passed
    recompute = next(c for c in report.checks if c.name == "root-recomputation")
    assert not recompute.ok
    assert "DIVERGENT" in recompute.detail


def test_conformance_level_computed():
    assert conformance.conformance_level(has_live_tlog=True, checkpoint_verifies=True) == "auditable"
    assert conformance.conformance_level(has_live_tlog=False, checkpoint_verifies=False) == "basic"
    assert conformance.conformance_level(has_live_tlog=True, checkpoint_verifies=False) == "basic"
