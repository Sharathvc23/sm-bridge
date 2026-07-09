"""``sm-bridge`` command-line interface — verify a trust artifact from the terminal.

Offline verification is the whole point of the trust layer, so the CLI mirrors the ergonomics
of tools like ``ans-verify``: point it at a receipt / signed catalog / agent card / delegation
and it prints an honest verdict.

    sm-bridge verify ans-scitt   --receipt receipt.cbor --root-keys root-keys.txt
    sm-bridge verify jws-catalog --catalog ai-catalog.json --signature sig.jws --jwks jwks.json
    sm-bridge verify agent-card  --card card.json --signature-b64 <b64> --pubkey key.pem
    sm-bridge verify dns-aid     --fqdn agent.example.com [--dane]
    sm-bridge verify delegation  --evidence delegation-bundle.json

Exit code: 0 = VERIFIED, 1 = FAILED, 2 = NOT_VERIFIED, 64 = usage error. The verification
adapters live in the ``[trust]`` extra; install with ``pip install 'sm-bridge[trust]'``.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from pathlib import Path
from typing import Any

_EXIT = {"VERIFIED": 0, "FAILED": 1, "NOT_VERIFIED": 2}


def _die(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 64


def _need_trust() -> str | None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return "the verification adapters need the [trust] extra — pip install 'sm-bridge[trust]'"
    return None


def _spki_from_root_keys(path: Path) -> bytes:
    """Parse a `/root-keys` verification line → the SubjectPublicKeyInfo DER bytes."""
    line = path.read_text().strip().splitlines()[0]
    _origin, _keyhash, blob = line.split("+", 2)
    raw = base64.b64decode(blob)
    if raw[:1] != b"\x02":
        raise ValueError("root-keys algorithm byte is not 0x02 (ECDSA P-256)")
    return raw[1:]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _report(result: Any) -> int:
    print(f"profile      : {result.profile}")
    print(f"status       : {result.status.value}")
    print(f"method       : {result.method}")
    if result.evidence_ref:
        print(f"evidence_ref : {result.evidence_ref}")
    if result.failure_reason:
        print(f"reason       : {result.failure_reason}")
    return _EXIT.get(result.status.value, 1)


# ----- per-profile handlers ----------------------------------------------------------

def _verify_ans_scitt(args: argparse.Namespace) -> int:
    from sm_bridge.trust.ans_scitt import AnsScittProfile

    if args.root_keys:
        pub: Any = _spki_from_root_keys(Path(args.root_keys))
    elif args.pubkey:
        pub = Path(args.pubkey).read_bytes()
    else:
        return _die("provide --root-keys or --pubkey")
    receipt = Path(args.receipt).read_bytes()
    return _report(_run(AnsScittProfile().verify(None, {"receipt": receipt, "public_key": pub})))


def _verify_jws_catalog(args: argparse.Namespace) -> int:
    from sm_bridge.trust.jws_catalog import JwsCatalogProfile

    catalog = json.loads(Path(args.catalog).read_text())
    entries = catalog.get("entries", catalog)  # accept a bare entries array too
    sig = Path(args.signature).read_text().strip() if Path(args.signature).exists() else args.signature
    evidence: dict[str, Any] = {"entries": entries, "signature": sig}
    if args.jwks:
        evidence["jwks"] = json.loads(Path(args.jwks).read_text())
    elif args.pubkey:
        evidence["public_key"] = Path(args.pubkey).read_bytes()
    else:
        return _die("provide --jwks or --pubkey")
    return _report(_run(JwsCatalogProfile().verify(None, evidence)))


def _verify_agent_card(args: argparse.Namespace) -> int:
    from sm_bridge.trust.ed25519_agentcard import Ed25519AgentCardProfile

    payload = json.loads(Path(args.card).read_text())
    sig_b64 = Path(args.signature_b64).read_text().strip() if Path(args.signature_b64).exists() else args.signature_b64
    evidence = {"payload": payload, "signature_b64": sig_b64, "public_key": Path(args.pubkey).read_bytes()}
    return _report(_run(Ed25519AgentCardProfile().verify(None, evidence)))


def _verify_dns_aid(args: argparse.Namespace) -> int:
    from sm_bridge.trust.dns_aid import DnsAidProfile

    evidence = {"fqdn": args.fqdn, "verify_dane_cert": bool(args.dane)}
    return _report(_run(DnsAidProfile().verify(None, evidence)))


def _verify_delegation(args: argparse.Namespace) -> int:
    from sm_bridge.trust.delegation import NandaDelegationProfile

    evidence = json.loads(Path(args.evidence).read_text())
    return _report(_run(NandaDelegationProfile().verify(None, evidence)))


# ----- parser ------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sm-bridge", description="NANDA quilt onboarding + verification")
    sub = p.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a trust artifact")
    vsub = verify.add_subparsers(dest="profile", required=True)

    a = vsub.add_parser("ans-scitt", help="verify an ANS SCITT transparency-log receipt")
    a.add_argument("--receipt", required=True, help="path to the COSE_Sign1 receipt (CBOR)")
    a.add_argument("--root-keys", help="path to the log's /root-keys verification line")
    a.add_argument("--pubkey", help="path to the TL's P-256 public key (PEM/DER)")
    a.set_defaults(func=_verify_ans_scitt)

    j = vsub.add_parser("jws-catalog", help="verify a signed AI-Catalog (ES256 detached JWS)")
    j.add_argument("--catalog", required=True, help="path to the ai-catalog.json (its entries are verified)")
    j.add_argument("--signature", required=True, help="detached compact JWS (string or path)")
    j.add_argument("--jwks", help="path to the JWKS")
    j.add_argument("--pubkey", help="path to the signing public key (PEM/DER)")
    j.set_defaults(func=_verify_jws_catalog)

    c = vsub.add_parser("agent-card", help="verify an ed25519-signed NANDA agent card")
    c.add_argument("--card", required=True, help="path to the agent-card JSON payload")
    c.add_argument("--signature-b64", required=True, help="base64 signature (string or path)")
    c.add_argument("--pubkey", required=True, help="path to the ed25519 public key (PEM/raw)")
    c.set_defaults(func=_verify_agent_card)

    d = vsub.add_parser("dns-aid", help="verify a DNS-AID record (SVCB + DNSSEC + DANE)")
    d.add_argument("--fqdn", required=True, help="agent FQDN, e.g. chat.example.com")
    d.add_argument("--dane", action="store_true", help="also perform DANE/TLSA certificate matching")
    d.set_defaults(func=_verify_dns_aid)

    g = vsub.add_parser("delegation", help="verify a did:key delegation chain")
    g.add_argument("--evidence", required=True, help="path to the delegation evidence bundle (JSON)")
    g.set_defaults(func=_verify_delegation)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    missing = _need_trust()
    if missing:
        return _die(missing)
    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        return _die(f"file not found: {e.filename}")
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        return _die(f"bad input: {e}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
