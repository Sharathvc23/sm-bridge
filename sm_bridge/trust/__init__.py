"""sm-bridge trust profiles — normalized verification for heterogeneous trust roots.

The spine (`ProofResult`, `TrustProfile`, `TrustRegistry`) is core-safe and always
importable. The individual profile adapters (ed25519 agent-card, ANS/SCITT, DNS-AID,
delegation) require the `[trust]` extra and import their crypto lazily — import them from
their own submodules so a core-only install never pays for cryptography/dnspython/cbor2.
"""

from __future__ import annotations

from sm_bridge.trust.base import (
    ProofResult,
    ProofStatus,
    TrustProfile,
    TrustRegistry,
)

__all__ = ["ProofResult", "ProofStatus", "TrustProfile", "TrustRegistry"]
