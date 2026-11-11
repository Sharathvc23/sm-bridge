"""Red-team tests for the DNS-AID trust profile.

All DNS is injected through the resolver seam — no real network. The suite
exercises the profile's honest verdicts: VERIFIED only for genuine, consistent,
**DNSSEC-validated** DNS control; FAILED only for affirmative tamper evidence
(split-horizon, expected-url mismatch); NOT_VERIFIED for every "cannot tell" case
(unreachable DNS, absent/malformed records, bad input, and records nothing
authenticated — ``dnssec_not_validated``).
"""

from __future__ import annotations

import pytest

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_txt import AnsTxtProfile, DnsAnswer, _default_resolver

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


def _resolver(records: dict, *, authenticated: bool = True):
    """2-arg fake: single (default) vantage, keyed by qname/rdtype.

    Answers are DNSSEC-validated (AD set) by default so the happy paths below
    exercise the whole check; ``authenticated=False`` models a resolver that
    returned the same bytes without validating them.
    """

    def resolve(qname: str, rdtype: str) -> DnsAnswer:
        return DnsAnswer(list(records.get(qname, {}).get(rdtype.upper(), [])), authenticated)

    return resolve


def _plain_resolver(records: dict):
    """A resolver that says nothing about DNSSEC — returns bare record lists."""

    def resolve(qname: str, rdtype: str) -> list[str]:
        return list(records.get(qname, {}).get(rdtype.upper(), []))

    return resolve


def _vantage_resolver(by_vantage: dict, *, authenticated: bool = True):
    """3-arg fake: per-vantage records so split-horizon can be simulated."""

    def resolve(qname: str, rdtype: str, vantage=None) -> DnsAnswer:
        recs = by_vantage[vantage]
        return DnsAnswer(list(recs.get(qname, {}).get(rdtype.upper(), [])), authenticated)

    return resolve


# --- 0. the DNSSEC gate: unvalidated records are a claim, not a check ----------


async def test_unvalidated_records_are_not_verified():
    # Same records as the VERIFIED case, but the resolver did not set AD.
    profile = AnsTxtProfile(resolver=_resolver(_good_records(), authenticated=False))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert result.failure_reason is not None
    assert result.failure_reason.startswith("dnssec_not_validated")
    assert f"_ans.{HOST}" in result.failure_reason
    assert f"_ans-badge.{HOST}" in result.failure_reason


async def test_a_resolver_returning_bare_lists_cannot_produce_verified():
    # The pre-0.11 seam: a list[str] with no DNSSEC statement. It used to VERIFY.
    profile = AnsTxtProfile(resolver=_plain_resolver(_good_records()))
    result = await profile.verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    assert (result.failure_reason or "").startswith("dnssec_not_validated")


async def test_one_unvalidated_record_is_enough_to_withhold_verified():
    # `_ans` validated, `_ans-badge` not: the badge is load-bearing, so no pass.
    recs = _good_records()

    def resolve(qname: str, rdtype: str) -> DnsAnswer:
        return DnsAnswer(
            list(recs.get(qname, {}).get(rdtype.upper(), [])),
            authenticated=not qname.startswith("_ans-badge."),
        )

    result = await AnsTxtProfile(resolver=resolve).verify(None, {"host": HOST})

    assert result.status is ProofStatus.NOT_VERIFIED
    reason = result.failure_reason or ""
    assert reason.startswith("dnssec_not_validated")
    assert f"_ans-badge.{HOST}" in reason
    assert f"_ans.{HOST}," not in reason  # the validated record is not blamed


async def test_one_unvalidated_vantage_is_enough_to_withhold_verified():
    recs = _good_records()
    by = {"10.0.0.1:53": recs, "10.0.0.2:53": recs}

    def resolve(qname: str, rdtype: str, vantage=None) -> DnsAnswer:
        return DnsAnswer(
            list(by[vantage].get(qname, {}).get(rdtype.upper(), [])),
            authenticated=vantage == "10.0.0.1:53",
        )

    result = await AnsTxtProfile(resolver=resolve).verify(
        None, {"host": HOST, "vantages": ["10.0.0.1:53", "10.0.0.2:53"]}
    )
    assert result.status is ProofStatus.NOT_VERIFIED
    assert "10.0.0.2:53" in (result.failure_reason or "")
    assert "10.0.0.1:53" not in (result.failure_reason or "")


async def test_tamper_evidence_is_failed_even_when_unvalidated():
    # Divergent records are evidence against the subject whether or not anything
    # authenticated them; the DNSSEC gate must not soften a FAILED into "unknown".
    by = {
        "10.0.0.1:53": _good_records(url="https://good.example/mcp"),
        "10.0.0.2:53": _good_records(url="https://evil.example/mcp"),
    }
    profile = AnsTxtProfile(resolver=_vantage_resolver(by, authenticated=False))
    result = await profile.verify(
        None, {"host": HOST, "vantages": ["10.0.0.1:53", "10.0.0.2:53"]}
    )
    assert result.status is ProofStatus.FAILED

    profile = AnsTxtProfile(
        resolver=_resolver(_good_records(url="https://tampered/x"), authenticated=False)
    )
    result = await profile.verify(None, {"host": HOST, "expected_url": GOOD_URL})
    assert result.status is ProofStatus.FAILED


def test_default_resolver_requests_dnssec_and_reports_the_ad_bit(monkeypatch):
    """The real seam: DO + AD are requested, and `authenticated` is the response's AD bit."""
    import dns.flags
    import dns.resolver

    captured: dict = {}

    class _Rdata:
        strings = [b"v=ans1; url=", b"https://x.example"]

    class _Response:
        def __init__(self, flags):
            self.flags = flags

    class _Answer(list):
        def __init__(self, flags):
            super().__init__([_Rdata()])
            self.response = _Response(flags)

    class _FakeResolver:
        def __init__(self, configure=True):
            captured["configure"] = configure
            self.flags = None
            self.nameservers = []
            self.port = 53

        def use_edns(self, edns, ednsflags, payload):
            captured["edns"] = (edns, ednsflags, payload)

        def set_flags(self, flags):
            captured["flags"] = flags

        def resolve(self, qname, rdtype):
            captured["q"] = (qname, rdtype)
            return _Answer(captured["respond_with"])

    monkeypatch.setattr(dns.resolver, "Resolver", _FakeResolver)

    captured["respond_with"] = dns.flags.QR | dns.flags.RD | dns.flags.RA | dns.flags.AD
    ans = _default_resolver(f"_ans.{HOST}", "TXT")
    assert ans == DnsAnswer(["v=ans1; url=https://x.example"], True)
    assert captured["edns"][1] & dns.flags.DO
    assert captured["flags"] & dns.flags.AD

    captured["respond_with"] = dns.flags.QR | dns.flags.RD | dns.flags.RA  # no AD
    ans = _default_resolver(f"_ans.{HOST}", "TXT", "10.0.0.1:5353")
    assert ans.authenticated is False
    assert captured["configure"] is False


# --- 1. consistent, DNSSEC-validated records → VERIFIED (ans-txt-control) -------


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
