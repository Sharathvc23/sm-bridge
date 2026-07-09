"""Red-team tests for the DNS-AID trust profile.

All DNS is injected through the resolver seam — no real network. The suite
exercises the profile's honest verdicts: VERIFIED only for genuine, consistent
DNS control; FAILED only for affirmative tamper evidence (split-horizon,
expected-url mismatch); NOT_VERIFIED for every "cannot tell" case (unreachable
DNS, absent/malformed records, bad input).
"""

from __future__ import annotations

import pytest

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_txt import AnsTxtProfile

HOST = "agent.example.com"
AGENT_ID = "11111111-1111-4111-8111-111111111111"
GOOD_URL = "https://agent.example/mcp"
BADGE_URL = f"https://tl.example/v1/agents/{AGENT_ID}"


def _ans_txt(url: str) -> str:
    return f"v=ans1; version=1.0.0; p=mcp; mode=direct; url={url}"


def _badge_txt(url: str) -> str:
    return f"v=ans-badge1; version=1.0.0; url={url}"


def _good_records(url: str = GOOD_URL, badge: str = BADGE_URL) -> dict:
    return {
        f"_ans.{HOST}": {"TXT": [_ans_txt(url)]},
        f"_ans-badge.{HOST}": {"TXT": [_badge_txt(badge)]},
    }


def _resolver(records: dict):
    """2-arg fake: single (default) vantage, keyed by qname/rdtype."""

    def resolve(qname: str, rdtype: str) -> list[str]:
        return list(records.get(qname, {}).get(rdtype.upper(), []))

    return resolve


def _vantage_resolver(by_vantage: dict):
    """3-arg fake: per-vantage records so split-horizon can be simulated."""

    def resolve(qname: str, rdtype: str, vantage=None) -> list[str]:
        recs = by_vantage[vantage]
        return list(recs.get(qname, {}).get(rdtype.upper(), []))

    return resolve


# --- 1. consistent records → VERIFIED (ans-txt-control) ------------------------


async def test_consistent_single_vantage_verified():
    profile = AnsTxtProfile(resolver=_resolver(_good_records()))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.VERIFIED
    assert result.profile == "ans-txt"
    assert result.method == "ans-txt-control"
    assert result.evidence_ref is not None
    assert result.evidence_ref.startswith(f"dns:{HOST}:")


async def test_two_vantages_agree_verified():
    recs = _good_records()
    by = {"10.0.0.1:53": recs, "10.0.0.2:53": recs}
    profile = AnsTxtProfile(resolver=_vantage_resolver(by))

    result = await profile.verify(
        None, {"host": HOST, "vantages": ["10.0.0.1:53", "10.0.0.2:53"]}
    )
    assert result.status is ProofStatus.VERIFIED
    assert result.method == "ans-txt-control"
    assert result.evidence_ref is not None


async def test_verified_when_expected_url_matches():
    profile = AnsTxtProfile(resolver=_resolver(_good_records()))
    result = await profile.verify(None, {"host": HOST, "expected_url": GOOD_URL})
    assert result.status is ProofStatus.VERIFIED


# --- 2. two vantages disagree on url → FAILED (split-horizon) ------------------


async def test_two_vantages_split_horizon_failed():
    by = {
        "10.0.0.1:53": _good_records(url="https://good.example/mcp"),
        "10.0.0.2:53": _good_records(url="https://evil.example/mcp"),
    }
    profile = AnsTxtProfile(resolver=_vantage_resolver(by))

    result = await profile.verify(
        None, {"host": HOST, "vantages": ["10.0.0.1:53", "10.0.0.2:53"]}
    )
    assert result.status is ProofStatus.FAILED
    assert result.failure_reason is not None
    assert "split-horizon" in result.failure_reason
    # The reason must name the divergent values, not just assert divergence.
    assert "good.example" in result.failure_reason
    assert "evil.example" in result.failure_reason


async def test_expected_url_mismatch_failed():
    profile = AnsTxtProfile(resolver=_resolver(_good_records(url="https://tampered/x")))
    result = await profile.verify(None, {"host": HOST, "expected_url": GOOD_URL})

    assert result.status is ProofStatus.FAILED
    assert result.failure_reason is not None
    assert "tampered" in result.failure_reason


# --- 3. resolver raises (timeout / NXDOMAIN) → NOT_VERIFIED --------------------


async def test_resolver_timeout_not_verified():
    def resolver(qname, rdtype):
        raise TimeoutError("no response from nameserver within 2s")

    profile = AnsTxtProfile(resolver=resolver)
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert result.failure_reason is not None
    assert "DNS" in result.failure_reason


async def test_resolver_nxdomain_not_verified():
    class NXDOMAIN(Exception):
        pass

    def resolver(qname, rdtype):
        raise NXDOMAIN(f"{qname} does not exist")

    profile = AnsTxtProfile(resolver=resolver)
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert "DNS" in (result.failure_reason or "")


# --- 4. missing _ans-badge or malformed v= tag → NOT_VERIFIED -----------------


async def test_missing_badge_not_verified():
    records = {f"_ans.{HOST}": {"TXT": [_ans_txt(GOOD_URL)]}}  # no badge record
    profile = AnsTxtProfile(resolver=_resolver(records))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert "_ans-badge" in (result.failure_reason or "")


async def test_malformed_badge_v_tag_not_verified():
    records = {
        f"_ans.{HOST}": {"TXT": [_ans_txt(GOOD_URL)]},
        # wrong v= tag: not the required ans-badge1
        f"_ans-badge.{HOST}": {"TXT": [f"v=ans-badgeX; url={BADGE_URL}"]},
    }
    profile = AnsTxtProfile(resolver=_resolver(records))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED


async def test_missing_ans_record_not_verified():
    records = {f"_ans-badge.{HOST}": {"TXT": [_badge_txt(BADGE_URL)]}}  # no _ans
    profile = AnsTxtProfile(resolver=_resolver(records))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert "DNS records absent" in (result.failure_reason or "")


async def test_badge_without_agent_id_not_verified():
    records = {
        f"_ans.{HOST}": {"TXT": [_ans_txt(GOOD_URL)]},
        f"_ans-badge.{HOST}": {"TXT": [_badge_txt("https://tl.example/badge/no-uuid")]},
    }
    profile = AnsTxtProfile(resolver=_resolver(records))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert "agentId" in (result.failure_reason or "")


# --- 5. malformed host in evidence → NOT_VERIFIED -----------------------------


@pytest.mark.parametrize(
    "bad_host",
    ["", "not a host", "no-dot", "http://x.example/y", "..", "-lead.example", 123, None],
)
async def test_malformed_host_not_verified(bad_host):
    # Resolver should never even be consulted; make it explode if it is.
    def resolver(qname, rdtype):  # pragma: no cover - must not be called
        raise AssertionError("resolver invoked for a malformed host")

    profile = AnsTxtProfile(resolver=resolver)
    result = await profile.verify(None, {"host": bad_host})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert "malformed host" in (result.failure_reason or "")


async def test_evidence_without_host_not_verified():
    profile = AnsTxtProfile(resolver=_resolver(_good_records()))
    result = await profile.verify(None, {})
    assert result.status is ProofStatus.NOT_VERIFIED


async def test_empty_vantages_list_not_verified():
    profile = AnsTxtProfile(resolver=_resolver(_good_records()))
    result = await profile.verify(None, {"host": HOST, "vantages": []})
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "vantages" in (result.failure_reason or "")


# --- profile identity ---------------------------------------------------------


def test_profile_id_matches_spine_contract():
    assert AnsTxtProfile.profile_id == "ans-txt"
    assert AnsTxtProfile(resolver=_resolver({})).profile_id == "ans-txt"
