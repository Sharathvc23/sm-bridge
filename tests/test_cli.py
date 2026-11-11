"""CLI — `sm-bridge verify` drives each profile and returns the right exit code.

Exit codes: 0 = VERIFIED, 1 = FAILED, 2 = NOT_VERIFIED.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_bridge.cli import main
from sm_bridge.trust.ed25519_agentcard import canonicalize

_FIX = __import__("pathlib").Path(__file__).resolve().parent / "fixtures" / "ans"


def test_ans_scitt_real_receipt_verified(capsys):
    rc = main([
        "verify", "ans-scitt",
        "--receipt", str(_FIX / "real_tl_receipt.cbor"),
        "--root-keys", str(_FIX / "real_tl_root-keys.txt"),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "status       : VERIFIED" in out


def test_ans_scitt_tampered_fails(tmp_path, capsys):
    receipt = bytearray((_FIX / "real_tl_receipt.cbor").read_bytes())
    receipt[len(receipt) // 2] ^= 0x01
    bad = tmp_path / "bad.cbor"
    bad.write_bytes(bytes(receipt))
    rc = main(["verify", "ans-scitt", "--receipt", str(bad), "--root-keys", str(_FIX / "real_tl_root-keys.txt")])
    assert rc == 1  # FAILED
    assert "FAILED" in capsys.readouterr().out


def test_agent_card_verified(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    payload = {"id": "a", "b": 2}
    card = tmp_path / "card.json"
    card.write_text(json.dumps(payload))
    sig = tmp_path / "sig.b64"
    sig.write_text(base64.b64encode(key.sign(canonicalize(payload))).decode())
    pub = tmp_path / "key.raw"
    pub.write_bytes(key.public_key().public_bytes_raw())
    rc = main(["verify", "agent-card", "--card", str(card), "--signature-b64", str(sig), "--pubkey", str(pub)])
    assert rc == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_jws_catalog_hijack_fails(tmp_path, capsys):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from sm_bridge.trust._es256_jws import sign_es256

    priv = ec.generate_private_key(ec.SECP256R1())
    entries = [{"identifier": "urn:a", "url": "https://a.example"}]
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "ES256"}).encode()).rstrip(b"=").decode()
    jws = f"{header_b64}..{sign_es256(header_b64, canonicalize(entries), priv)}"
    # tamper the catalog after signing → hijack
    catalog = tmp_path / "cat.json"
    catalog.write_text(json.dumps({"entries": [{"identifier": "urn:a", "url": "https://evil.example"}]}))
    sig = tmp_path / "sig.jws"
    sig.write_text(jws)
    pub = tmp_path / "k.pem"
    pub.write_bytes(priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    rc = main(["verify", "jws-catalog", "--catalog", str(catalog), "--signature", str(sig), "--pubkey", str(pub)])
    assert rc == 1
    assert "FAILED" in capsys.readouterr().out


def _delegation_bundle(tmp_path, *, expires_in: int = 1000):
    from cryptography.hazmat.primitives.asymmetric import ec

    from sm_bridge.trust.delegation import sign_credential, signer_pubkey_pem

    now = int(__import__("time").time())
    fmt = lambda ts: __import__("datetime").datetime.fromtimestamp(  # noqa: E731
        ts, tz=__import__("datetime").timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    key = ec.generate_private_key(ec.SECP256R1())
    cred = {
        "delegationId": "d-root",
        "schemaVersion": "DELEGATION-V1",
        "issuer": {"ansName": "p.ans", "agentId": "p", "did": "did:key:zP"},
        "subject": {"did": "did:key:zS"},
        "scopes": ["mail.send"],
        "issuedAt": fmt(now - 100),
        "expiresAt": fmt(now + expires_in),
        "maxRedelegationDepth": 0,
        "parentDelegation": None,
    }
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({
        "chain": [cred],
        "signatures": {"d-root": {"sig_b64": sign_credential(cred, key), "signer_pubkey": signer_pubkey_pem(key)}},
        # The subject's own claim — the CLI must not take it as the verifier's view.
        "status_tokens": {"d-root": {"status": "ACTIVE", "exp": now + 3600}},
        "provider_scopes": ["mail"],
    }))
    return bundle, now


def test_delegation_without_a_status_source_is_not_verified(tmp_path, capsys):
    bundle, _ = _delegation_bundle(tmp_path)
    rc = main(["verify", "delegation", "--evidence", str(bundle)])
    out = capsys.readouterr().out
    assert rc == 2  # NOT_VERIFIED
    assert "status_unverified" in out


def test_delegation_with_the_verifiers_status_source_is_verified(tmp_path, capsys):
    bundle, now = _delegation_bundle(tmp_path)
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"d-root": {"status": "ACTIVE", "exp": now + 3600}}))
    rc = main(["verify", "delegation", "--evidence", str(bundle), "--status-source", str(status)])
    assert rc == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_delegation_revoked_at_the_verifier_fails_despite_the_bundles_active(tmp_path, capsys):
    bundle, now = _delegation_bundle(tmp_path)
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"d-root": {"status": "REVOKED", "exp": now + 3600}}))
    rc = main(["verify", "delegation", "--evidence", str(bundle), "--status-source", str(status)])
    assert rc == 1
    assert "revoked" in capsys.readouterr().out


def test_delegation_status_source_must_be_an_object(tmp_path, capsys):
    bundle, _ = _delegation_bundle(tmp_path)
    status = tmp_path / "status.json"
    status.write_text("[]")
    rc = main(["verify", "delegation", "--evidence", str(bundle), "--status-source", str(status)])
    assert rc == 64
    assert "--status-source" in capsys.readouterr().err


def test_dns_aid_absent_is_not_verified(capsys):
    rc = main(["verify", "dns-aid", "--fqdn", "no-such.invalid-cli-check.example"])
    assert rc == 2  # NOT_VERIFIED
    assert "NOT_VERIFIED" in capsys.readouterr().out


def test_missing_key_is_usage_error(capsys):
    rc = main(["verify", "ans-scitt", "--receipt", str(_FIX / "real_tl_receipt.cbor")])
    assert rc == 64
    assert "error" in capsys.readouterr().err
