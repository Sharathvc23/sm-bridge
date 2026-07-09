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


def test_dns_aid_absent_is_not_verified(capsys):
    rc = main(["verify", "dns-aid", "--fqdn", "no-such.invalid-cli-check.example"])
    assert rc == 2  # NOT_VERIFIED
    assert "NOT_VERIFIED" in capsys.readouterr().out


def test_missing_key_is_usage_error(capsys):
    rc = main(["verify", "ans-scitt", "--receipt", str(_FIX / "real_tl_receipt.cbor")])
    assert rc == 64
    assert "error" in capsys.readouterr().err
