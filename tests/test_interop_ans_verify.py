"""Interop: a receipt produced with sm-bridge's wire layout is accepted by the *real*
GoDaddy ``ans-verify`` binary — and both engines agree on acceptance AND rejection.

This is the cross-implementation proof that ``ans_scitt`` matches the ANS wire contract, not
just its own fixtures. It runs only when an ``ans-verify`` binary is available (built from the
ANS repo); set ``ANS_VERIFY_BIN`` or put ``ans-verify`` on PATH. Otherwise it skips.

The mock transparency log serves only the two endpoints ``ans-verify`` needs for a
single-agent verify: ``/root-keys`` and ``/v1/agents/{id}/receipt``. The status-token and
badge cross-checks are best-effort in the binary (non-fatal), so a 404 there is fine.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import os
import shutil
import socket
import subprocess
import threading

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sm_bridge.trust import ProofStatus
from sm_bridge.trust.ans_scitt import AnsScittProfile

_ANS_VERIFY = os.environ.get("ANS_VERIFY_BIN") or shutil.which("ans-verify")
pytestmark = pytest.mark.skipif(
    not (_ANS_VERIFY and os.path.exists(_ANS_VERIFY)),
    reason="ans-verify binary not available (set ANS_VERIFY_BIN to run the interop check)",
)

_AGENT_ID = "12345678-1234-1234-1234-123456789abc"
_ORIGIN = "example.ans.log"

# --- RFC 6962 Merkle + COSE receipt builder (same wire layout the ANS TL emits) ----------

def _leaf(e: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + e).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _k(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def _mth(es: list[bytes]) -> bytes:
    if len(es) == 1:
        return _leaf(es[0])
    k = _k(len(es))
    return _node(_mth(es[:k]), _mth(es[k:]))


def _path(m: int, es: list[bytes]) -> list[bytes]:
    if len(es) == 1:
        return []
    k = _k(len(es))
    return _path(m, es[:k]) + [_mth(es[k:])] if m < k else _path(m - k, es[k:]) + [_mth(es[:k])]


def _spki(pub) -> bytes:
    return pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _kid(pub) -> bytes:
    return hashlib.sha256(_spki(pub)).digest()[:4]


def _receipt(priv, entries, index, *, tamper=False) -> bytes:
    pub = priv.public_key()
    payload = entries[index]
    protected = cbor2.dumps(
        {1: -7, 4: _kid(pub), 395: 1, 15: {1: _ORIGIN, 6: 1_700_000_000}}, canonical=True
    )
    vdp = {-1: len(entries), -2: index, -3: _path(index, entries), -4: _mth(entries)}
    sig_struct = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    der = priv.sign(sig_struct, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    cose_payload = (payload[:-1] + bytes([payload[-1] ^ 0x01])) if tamper else payload
    arr = [protected, {396: vdp}, cose_payload, sig]
    return cbor2.dumps(cbor2.CBORTag(18, arr), canonical=True)


def _root_keys_line(pub) -> bytes:
    spki = _spki(pub)
    keyhash_hex = format(int.from_bytes(hashlib.sha256(spki).digest()[:4], "big"), "08x")
    blob = base64.b64encode(b"\x02" + spki).decode()
    return f"{_ORIGIN}+{keyhash_hex}+{blob}\n".encode()


# --- a tiny mock ANS transparency log ----------------------------------------------------

def _serve(root_keys: bytes, receipt: bytes):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/root-keys":
                body, ct = root_keys, "text/plain; charset=utf-8"
            elif self.path == f"/v1/agents/{_AGENT_ID}/receipt":
                body, ct = receipt, "application/scitt-receipt+cose"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    httpd = http.server.HTTPServer(("127.0.0.1", port), H)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _run_ans_verify(port: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_ANS_VERIFY, "-url", f"http://127.0.0.1:{port}", "-agent", _AGENT_ID],
        capture_output=True, text=True, timeout=30,
    )


def _py_verify(receipt: bytes, pub) -> ProofStatus:
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    out = asyncio.run(AnsScittProfile().verify(None, {"receipt": receipt, "public_key": pem}))
    return out.status


def test_real_ans_verify_accepts_our_receipt_and_python_agrees():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    entries = [f"event-{i}".encode() for i in range(5)]
    receipt = _receipt(priv, entries, 2)

    httpd, port = _serve(_root_keys_line(pub), receipt)
    try:
        proc = _run_ans_verify(port)
    finally:
        httpd.shutdown()

    assert proc.returncode == 0, f"ans-verify rejected our receipt:\n{proc.stdout}\n{proc.stderr}"
    assert "VERIFIED" in proc.stdout, proc.stdout
    # both engines agree on acceptance
    assert _py_verify(receipt, pub) is ProofStatus.VERIFIED


def test_real_ans_verify_rejects_a_tampered_receipt_and_python_agrees():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    entries = [f"event-{i}".encode() for i in range(5)]
    forged = _receipt(priv, entries, 2, tamper=True)

    httpd, port = _serve(_root_keys_line(pub), forged)
    try:
        proc = _run_ans_verify(port)
    finally:
        httpd.shutdown()

    assert proc.returncode != 0, f"ans-verify wrongly accepted a tampered receipt:\n{proc.stdout}"
    # both engines agree on rejection
    assert _py_verify(forged, pub) is not ProofStatus.VERIFIED
