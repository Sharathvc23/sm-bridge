"""Cross-registry switchboard — one query, heterogeneous registries, uniform response.

This is the NANDA-as-switchboard value (Demo 1): a single resolve surfaces agents from
registries of different kinds through one uniform ``SwitchboardResult``, without the
switchboard ever holding a per-agent roster.

- An **entry-mode** registry (a registry-scale source like ANS) resolves by **delegation**:
  the switchboard returns a pointer to the source's resolver; the source serves and verifies
  its own agents. The switchboard reads nothing on its behalf.
- A **hosting-mode** registry (a source with no registry of its own — a catalog, a
  domainless agent) resolves **locally**, with a normalized proof attached.

One entry per registry, never one per agent — the quilt invariant. This layer is core-safe
(pydantic + stdlib); any verification runs through an injected ``TrustRegistry``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sm_bridge.models import SmAgentFacts
from sm_bridge.onboarding import DelegationResolution, EntryModeConverter, RegistryEntry
from sm_bridge.trust.base import ProofResult, TrustRegistry


@dataclass
class SwitchboardResult:
    """A uniform result across registry kinds."""

    registry: str
    kind: str  # "delegated" (entry mode) | "hosted" (hosting mode)
    delegation: DelegationResolution | None = None
    agent: SmAgentFacts | None = None
    proof: ProofResult | None = None


@dataclass
class _Hosting:
    converter: Any  # an AgentConverter, optionally with trust_evidence(agent)


class Switchboard:
    """Holds one entry per registry and answers a resolve uniformly across kinds."""

    def __init__(self, trust_registry: TrustRegistry | None = None) -> None:
        self._entry: dict[str, EntryModeConverter] = {}
        self._hosting: dict[str, _Hosting] = {}
        self._trust = trust_registry

    def add_registry(self, converter: EntryModeConverter) -> None:
        """Add an entry-mode (registry-scale) source — resolves by delegation."""
        self._entry[converter.to_entry().registry_name] = converter

    def add_hosting(self, registry_name: str, converter: Any) -> None:
        """Add a hosting-mode source (no registry of its own) — resolves locally + verified."""
        self._hosting[registry_name] = _Hosting(converter=converter)

    def registries(self) -> list[RegistryEntry]:
        """The quilt: one pointer entry per registry (entry-mode sources)."""
        return [c.to_entry() for c in self._entry.values()]

    def registry_names(self) -> list[str]:
        return sorted([*self._entry, *self._hosting])

    async def resolve(self, registry: str, agent: str) -> SwitchboardResult:
        """Resolve ``agent`` under ``registry`` — delegate (entry) or host+verify (hosting)."""
        if registry in self._entry:
            return SwitchboardResult(
                registry=registry, kind="delegated", delegation=self._entry[registry].delegate(agent)
            )
        if registry in self._hosting:
            conv = self._hosting[registry].converter
            internal = conv.get_agent(agent)
            if internal is None or not conv.is_public(internal):
                raise KeyError(f"agent '{agent}' not found in hosting registry '{registry}'")
            facts = conv.to_sm(internal)
            proof = facts.proof
            hook = getattr(conv, "trust_evidence", None)
            if self._trust is not None and callable(hook):
                supplied = hook(internal)
                if supplied is not None:
                    profile_id, evidence = supplied
                    proof = await self._trust.verify(profile_id, facts, evidence)
            return SwitchboardResult(registry=registry, kind="hosted", agent=facts, proof=proof)
        raise KeyError(f"no registry '{registry}' on this switchboard")


__all__ = ["Switchboard", "SwitchboardResult"]
