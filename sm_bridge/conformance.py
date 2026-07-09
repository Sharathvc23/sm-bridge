"""Conformance self-test — run the Demo 3 auditor's checks against a local `MerkleLog`.

Three cryptographic checks, mirroring the demo/ans-verify auditor:
1. **Checkpoint signature** verifies against the pinned root key.
2. **Root recomputation** — the log's own leaves reproduce the signed checkpoint root
   (published data must reproduce the signed claim).
3. **Append-only** — the root at a previously pinned size, recomputed from today's leaves,
   equals the pinned root (the old tree is a prefix of the new; history only grew).

Plus the tamper beat: flip one stored leaf and check #2 must now report divergence.

`conformance_level(entry, log)` computes (not asserts) the level: `basic` (schema-valid),
`auditable` (a live tlog whose checkpoint verifies), `witnessed` (reserved — cosigning is
not built).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sm_bridge.tlog import Checkpoint, MerkleLog, _merkle_root

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


@dataclass
class ConformanceReport:
    checks: list[CheckResult]

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)

    def summary(self) -> str:
        return "\n".join(f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}" for c in self.checks)


def audit(
    log: MerkleLog,
    checkpoint: Checkpoint,
    public_key: Ed25519PublicKey,
    pinned: Checkpoint | None = None,
) -> ConformanceReport:
    """Run the auditor. `pinned` is an earlier checkpoint for the append-only check."""
    checks: list[CheckResult] = []

    # 1. checkpoint signature
    sig_ok = MerkleLog.verify_checkpoint(checkpoint, public_key)
    checks.append(CheckResult("checkpoint-signature", sig_ok,
                              "verifies against root key" if sig_ok else "signature INVALID"))

    # 2. root recomputation — the live leaves must reproduce the signed root
    live_root_b64 = log.root_b64()
    root_ok = (live_root_b64 == checkpoint.root_b64) and (log.size == checkpoint.size)
    checks.append(CheckResult(
        "root-recomputation", root_ok,
        "recomputed root matches signed checkpoint" if root_ok
        else f"DIVERGENT: live {live_root_b64[:16]}…/{log.size} vs signed {checkpoint.root_b64[:16]}…/{checkpoint.size}",
    ))

    # 3. append-only vs a pinned earlier checkpoint
    if pinned is not None:
        recomputed = base64.b64encode(_merkle_root(log._leaves[: pinned.size])).decode()  # noqa: SLF001
        grew_ok = (pinned.size <= log.size) and (recomputed == pinned.root_b64)
        checks.append(CheckResult(
            "append-only", grew_ok,
            "old tree is a prefix of the new (history only grew)" if grew_ok
            else "APPEND-ONLY VIOLATION: prior tree is not a prefix of the current log",
        ))

    return ConformanceReport(checks)


def conformance_level(has_live_tlog: bool, checkpoint_verifies: bool) -> str:
    """Compute the level. Witnessed (cosigning) is reserved, not built."""
    if has_live_tlog and checkpoint_verifies:
        return "auditable"
    return "basic"


__all__ = ["CheckResult", "ConformanceReport", "audit", "conformance_level"]
