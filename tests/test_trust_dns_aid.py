"""DNS-AID adapter — normalizes the upstream dns-aid VerifyResult, honesty-rule correct.

Uses an injected async fake verifier (no network). A tiny stand-in mirrors the fields the
adapter reads from dns_aid.core.models.VerifyResult.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.dns_aid import DnsAidProfile


@dataclass
class FakeVerifyResult:
    fqdn: str
    record_exists: bool = False
    svcb_valid: bool = False
    dnssec_valid: bool = False
    dane_valid: bool | None = None
    dnssec_note: str = ""


def _verifier(result: FakeVerifyResult):
    async def _v(fqdn, *, verify_dane_cert=False):
        return result

    return _v


@pytest.mark.asyncio
async def test_dnssec_valid_svcb_record_is_verified():
    r = FakeVerifyResult("chat.example.com", record_exists=True, svcb_valid=True, dnssec_valid=True)
    out = await DnsAidProfile(verifier=_verifier(r)).verify(None, {"fqdn": "chat.example.com"})
    assert out.status is ProofStatus.VERIFIED
    assert out.evidence_ref == "dns-aid:chat.example.com:dnssec"


@pytest.mark.asyncio
async def test_dane_requested_and_valid_marks_evidence():
    r = FakeVerifyResult("a.example.com", record_exists=True, svcb_valid=True, dnssec_valid=True, dane_valid=True)
    out = await DnsAidProfile(verifier=_verifier(r)).verify(
        None, {"fqdn": "a.example.com", "verify_dane_cert": True}
    )
    assert out.status is ProofStatus.VERIFIED
    assert out.evidence_ref.endswith("+dane")


@pytest.mark.asyncio
async def test_no_record_is_not_verified():
    r = FakeVerifyResult("nope.example.com", record_exists=False)
    out = await DnsAidProfile(verifier=_verifier(r)).verify(None, {"fqdn": "nope.example.com"})
    assert out.status is ProofStatus.NOT_VERIFIED
    assert "no DNS-AID record" in out.failure_reason


@pytest.mark.asyncio
async def test_record_without_dnssec_is_not_verified_not_pass():
    # Present but unsigned zone → unauthenticated → NOT_VERIFIED, never VERIFIED.
    r = FakeVerifyResult("x.example.com", record_exists=True, svcb_valid=True, dnssec_valid=False, dnssec_note="insecure")
    out = await DnsAidProfile(verifier=_verifier(r)).verify(None, {"fqdn": "x.example.com"})
    assert out.status is ProofStatus.NOT_VERIFIED
    assert "not DNSSEC-authenticated" in out.failure_reason


@pytest.mark.asyncio
async def test_dnssec_bogus_is_failed():
    r = FakeVerifyResult("bad.example.com", record_exists=True, svcb_valid=True, dnssec_valid=False, dnssec_note="BOGUS: signature expired")
    out = await DnsAidProfile(verifier=_verifier(r)).verify(None, {"fqdn": "bad.example.com"})
    assert out.status is ProofStatus.FAILED
    assert "bogus" in out.failure_reason.lower()


@pytest.mark.asyncio
async def test_dnssec_valid_but_svcb_invalid_is_failed():
    r = FakeVerifyResult("s.example.com", record_exists=True, svcb_valid=False, dnssec_valid=True)
    out = await DnsAidProfile(verifier=_verifier(r)).verify(None, {"fqdn": "s.example.com"})
    assert out.status is ProofStatus.FAILED
    assert "SVCB" in out.failure_reason


@pytest.mark.asyncio
async def test_dane_requested_but_fails_is_failed():
    r = FakeVerifyResult("d.example.com", record_exists=True, svcb_valid=True, dnssec_valid=True, dane_valid=False)
    out = await DnsAidProfile(verifier=_verifier(r)).verify(
        None, {"fqdn": "d.example.com", "verify_dane_cert": True}
    )
    assert out.status is ProofStatus.FAILED
    assert "DANE" in out.failure_reason


@pytest.mark.asyncio
async def test_malformed_fqdn_is_not_verified():
    out = await DnsAidProfile(verifier=_verifier(FakeVerifyResult("x"))).verify(None, {"fqdn": "not a domain"})
    assert out.status is ProofStatus.NOT_VERIFIED
    out2 = await DnsAidProfile(verifier=_verifier(FakeVerifyResult("x"))).verify(None, {})
    assert out2.status is ProofStatus.NOT_VERIFIED


@pytest.mark.asyncio
async def test_verifier_raises_is_not_verified():
    async def _boom(fqdn, *, verify_dane_cert=False):
        raise TimeoutError("resolver down")

    out = await DnsAidProfile(verifier=_boom).verify(None, {"fqdn": "chat.example.com"})
    assert out.status is ProofStatus.NOT_VERIFIED
    assert "could not run" in out.failure_reason


@pytest.mark.asyncio
async def test_real_package_importable_and_wired():
    # Integration-ish: the real dns_aid package imports and the default verifier resolves.
    from sm_bridge.trust.dns_aid import _default_verifier

    v = _default_verifier()
    assert callable(v)
