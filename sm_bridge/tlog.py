"""Transparency-log extra (`[tlog]`) — RFC 6962 Merkle over the delta log + a signed
checkpoint, so a registry stood up with sm-bridge can pass its own Demo 3 auditor.

The delta log (`store.DeltaStore`) sequences records but carries no tamper-evidence. This
module builds an RFC 6962 Merkle tree over the record bytes, signs a checkpoint, and serves
inclusion + consistency proofs — turning "sequenced" into "auditable".

RFC 6962 hashing (matches the ANS/demo convention): leaf = SHA-256(0x00 || entry),
interior = SHA-256(0x01 || left || right). Proofs are refused until treeSize >= 3 (a
degenerate 1- or 2-leaf tree gives trivial/self-referential proofs — the exact class the
Demo 3 / ans-verify guards reject).

Signing uses Ed25519 (via `cryptography`, the `[tlog]` extra). The checkpoint mirrors the
sumdb-note idea (origin, size, base64 root) with a detached signature; the format is
documented here and is sm-bridge's own, not a claim of byte-compat with ans-tl's C2SP note.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

_LEAF = b"\x00"
_INTERIOR = b"\x01"


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(_LEAF + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_INTERIOR + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 MTH over a list of leaf hashes (empty tree = SHA-256 of empty string)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    # largest power of two < n
    k = 1
    while k << 1 < n:
        k <<= 1
    return _node_hash(_merkle_root(leaves[:k]), _merkle_root(leaves[k:]))


def _inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 inclusion proof for leaf index m in a tree of the given leaves."""
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k << 1 < n:
        k <<= 1
    if m < k:
        return _inclusion_proof(leaves[:k], m) + [_merkle_root(leaves[k:])]
    return _inclusion_proof(leaves[k:], m - k) + [_merkle_root(leaves[:k])]


def root_from_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes]) -> bytes:
    """Reconstruct the root from a leaf + inclusion proof (RFC 6962 §2.1.1).

    Independent of proof *generation* — a generator bug cannot round-trip through this.
    """
    if size <= 0 or index < 0 or index >= size:
        raise ValueError("invalid index/size for inclusion proof")
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if len(p) != 32:
            raise ValueError("proof element must be 32 bytes")
        if fn == sn or (fn & 1):
            r = _node_hash(p, r)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("proof too short for tree size")
    return r


def _consistency_proof(leaves: list[bytes], m: int, n: int) -> list[bytes]:
    """RFC 6962 consistency proof between sizes m (old) and n (new)."""
    if m <= 0 or m > n:
        return []
    return _subproof(m, leaves[:n], True)


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [_merkle_root(leaves)]
    k = 1
    while k << 1 < n:
        k <<= 1
    if m <= k:
        return _subproof(m, leaves[:k], b) + [_merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_merkle_root(leaves[:k])]


@dataclass
class Checkpoint:
    """A signed commitment to the log's state at a given size."""

    origin: str
    size: int
    root_b64: str
    signature_b64: str

    def note_body(self) -> str:
        return f"{self.origin}\n{self.size}\n{self.root_b64}\n"

    def signed_bytes(self) -> bytes:
        return self.note_body().encode("utf-8")


@dataclass
class MerkleLog:
    """RFC 6962 Merkle tree over appended record bytes, with a signable checkpoint.

    Append-only: `append` only extends. Proofs require size >= `min_proof_size` (default 3).
    """

    origin: str = "sm-bridge/tlog"
    min_proof_size: int = 3
    _leaves: list[bytes] = field(default_factory=list)
    _entries: list[bytes] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, entry: bytes) -> int:
        self._entries.append(entry)
        self._leaves.append(leaf_hash(entry))
        return self.size

    def root(self) -> bytes:
        return _merkle_root(self._leaves)

    def root_b64(self) -> str:
        return base64.b64encode(self.root()).decode()

    def _guard_proofs(self) -> None:
        if self.size < self.min_proof_size:
            raise ValueError(
                f"refusing to serve proofs at treeSize={self.size} (< {self.min_proof_size}); "
                "a degenerate tree yields trivial/self-referential proofs"
            )

    def inclusion_proof(self, index: int) -> list[bytes]:
        self._guard_proofs()
        if not (0 <= index < self.size):
            raise ValueError("index out of range")
        return _inclusion_proof(self._leaves, index)

    def consistency_proof(self, old_size: int) -> list[bytes]:
        self._guard_proofs()
        return _consistency_proof(self._leaves, old_size, self.size)

    def leaf_at(self, index: int) -> bytes:
        return self._leaves[index]

    # ----- checkpoint signing (Ed25519, [tlog] extra) -------------------------------

    def sign_checkpoint(self, private_key: Ed25519PrivateKey) -> Checkpoint:
        cp = Checkpoint(origin=self.origin, size=self.size, root_b64=self.root_b64(), signature_b64="")
        sig = private_key.sign(cp.signed_bytes())
        cp.signature_b64 = base64.b64encode(sig).decode()
        return cp

    @staticmethod
    def verify_checkpoint(cp: Checkpoint, public_key: Ed25519PublicKey) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            public_key.verify(base64.b64decode(cp.signature_b64), cp.signed_bytes())
            return True
        except (InvalidSignature, ValueError):
            return False


def root_keys_line(origin: str, public_key: Ed25519PublicKey) -> str:
    """A `/root-keys`-style verification line: `<origin>+<8hex keyhash>+<b64(0x01||raw)>`.

    0x01 = ed25519 (mirrors ANS notekey algorithm-byte convention; ANS uses 0x02 for P-256).
    """
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    kid = hashlib.sha256(raw).digest()[:4].hex()
    blob = base64.b64encode(b"\x01" + raw).decode()
    return f"{origin}+{kid}+{blob}"


__all__ = [
    "leaf_hash",
    "root_from_inclusion",
    "Checkpoint",
    "MerkleLog",
    "root_keys_line",
]
