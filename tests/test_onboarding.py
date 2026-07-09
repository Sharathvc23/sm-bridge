"""Phase 3 — dual onboarding modes: entry vs hosting, quilt invariant, delegation."""

from __future__ import annotations

import pytest

from sm_bridge.onboarding import (
    ANSEntryConverter,
    DelegationResolution,
    EntryModeConverter,
    RegistryEntry,
    normalize_reliability_receipts,
)


def test_ans_entry_produces_single_entry_and_is_auditable_with_tl():
    conv = ANSEntryConverter(
        registry_name="acme-ans",
        display_name="Acme ANS",
        resolver_endpoint="https://ans.acme.example/",
        tl_checkpoint="acme-tl\n7\nBASE64ROOT\n",
        root_keys=["acme-tl+deadbeef+BASE64KEY"],
    )
    entry = conv.to_entry()
    assert isinstance(entry, RegistryEntry)
    assert entry.registry_name == "acme-ans"
    assert entry.resolver_endpoint == "https://ans.acme.example"  # trailing slash stripped
    assert entry.conformance_level == "auditable"  # has checkpoint + keys
    assert entry.trust_profile == "ans-scitt"


def test_ans_entry_basic_without_tl():
    conv = ANSEntryConverter(registry_name="bare", resolver_endpoint="https://x.example")
    assert conv.to_entry().conformance_level == "basic"


def test_entry_mode_delegates_never_mirrors():
    conv = ANSEntryConverter(registry_name="acme-ans", resolver_endpoint="https://ans.acme.example")
    res = conv.delegate("urn:agent:123")
    assert isinstance(res, DelegationResolution)
    assert res.kind == "delegation"
    assert res.resolver_endpoint == "https://ans.acme.example"
    assert res.agent == "urn:agent:123"


def test_entry_mode_has_no_agent_iteration_api():
    # The quilt invariant, enforced structurally: entry-mode converters expose no way to
    # enumerate or fetch a source's agents.
    conv = ANSEntryConverter(registry_name="acme-ans", resolver_endpoint="https://ans.acme.example")
    for forbidden in ("list_agents", "get_agent", "to_sm"):
        assert not hasattr(conv, forbidden), f"entry-mode must not expose {forbidden}"


def test_ansentryconverter_satisfies_entrymode_protocol():
    conv = ANSEntryConverter(registry_name="r", resolver_endpoint="https://x.example")
    assert isinstance(conv, EntryModeConverter)


def test_registry_entry_rejects_unknown_conformance_level():
    with pytest.raises(ValueError, match="conformance_level"):
        RegistryEntry(registry_name="r", resolver_endpoint="https://x", conformance_level="platinum")


def test_reliability_receipts_require_attester_identity():
    raw = [
        {"attester": "did:key:zAlice", "claim": "99.9% uptime"},
        {"claim": "no attester"},  # dropped
        {"attester_did": "did:web:bob.example", "claim": "ok"},
        "not-a-dict",  # dropped
        {"attester": "   ", "claim": "blank attester"},  # dropped
    ]
    out = normalize_reliability_receipts(raw)
    assert len(out) == 2
    assert all(
        (r.get("attester") or r.get("attester_id") or r.get("attester_did", "")).strip() for r in out
    )


def test_reliability_receipts_non_list_is_empty():
    assert normalize_reliability_receipts(None) == []
    assert normalize_reliability_receipts({"a": 1}) == []
