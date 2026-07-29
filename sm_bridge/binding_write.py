"""Authenticated delegated writes to a registry binding.

The read/onboarding side lets a caller *discover* or *delegate* a binding. This
module adds the missing half: a delegate writing a binding **under a scoped
grant**, without the registry ever holding the owner's credentials.

The registry stays out of two businesses it should not be in:

  - **Crypto / policy.** How a grant is verified (and how the caller's request is
    authenticated) are *injected* — ``WriteAuthorizer`` and ``RequestAuthenticator``
    are protocols, not implementations. This module ships no signature library and
    no grant model; a caller provides them. Mirrors how ``AgentConverter`` /
    ``slug_of`` are injected elsewhere.

  - **Trusting the caller's word.** A write applies only when the request is
    authenticated as coming from the named delegate **and** the injected authorizer
    returns ``SATISFIED``. An ``INDETERMINATE`` verdict (e.g. a revocation or
    authority check that could not be resolved) is a 409, never an implicit apply.

Every applied write is appended to the RFC 6962 Merkle transparency log
(:class:`sm_bridge.tlog.MerkleLog`) — the same append-only structure the Demo 3
auditor checks — so the change is independently provable after the fact.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .tlog import MerkleLog

# Three-valued verdict vocabulary the injected authorizer speaks (matching the
# sm-dat/sm-provision trust stack), kept as bare strings so this module needs no
# dependency on it.
SATISFIED = "SATISFIED"
VIOLATED = "VIOLATED"
INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class WriteVerdict:
    """The result an injected :class:`WriteAuthorizer` returns."""
    status: str            # SATISFIED | VIOLATED | INDETERMINATE
    reason: str = "ok"
    detail: str = ""


@runtime_checkable
class WriteAuthorizer(Protocol):
    """Decides whether a grant authorizes one binding write. Injected — the
    registry does not know the grant model (or the authority-evidence model)."""

    def authorize(
        self, grant: dict[str, Any], request: dict[str, Any],
        issued_at: str, store_did: str,
    ) -> WriteVerdict: ...


@runtime_checkable
class RequestAuthenticator(Protocol):
    """Proves the caller controls ``store_did`` via a detached signature over the
    canonical request bytes. Injected — the registry does no crypto."""

    def authenticate(self, payload: bytes, store_did: str, signature: str) -> bool: ...


def canonical_payload(
    *, grant_id: str, op: str, subject: str, fields: dict[str, Any],
    target_host: str | None, agent_role: str | None, issued_at: str, nonce: str,
) -> bytes:
    """Deterministic bytes the delegate signs and the registry re-derives. Both
    sides MUST compute this identically, so it is the one canonical form."""
    payload = {
        "grant_id": grant_id, "op": op, "subject": subject, "fields": fields,
        "target_host": target_host, "agent_role": agent_role,
        "issued_at": issued_at, "nonce": nonce,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_log_entry(record: dict[str, Any]) -> bytes:
    """The leaf bytes appended to the Merkle log for an applied write. Exposed so
    an auditor can recompute a leaf and check its inclusion proof."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


class BindingStore:
    """In-memory current-state store: ``subject -> binding record``. The audit
    trail lives in the Merkle log; this holds only latest state. Subclass to
    persist. Intentionally no ``__len__`` — a falsy-when-empty store trips
    ``x or Default()`` defaults."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, dict[str, Any]] = {}

    def get(self, subject: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._records.get(subject)
            return dict(r) if r is not None else None

    def apply(self, *, op: str, subject: str, fields: dict[str, Any],
              target_host: str | None, agent_role: str | None) -> dict[str, Any]:
        with self._lock:
            rec = self._records.get(subject) or {
                "subject": subject, "version": 0, "lifecycle_state": "active", "fields": {},
            }
            rec = {**rec, "fields": {**rec["fields"], **fields}, "version": rec["version"] + 1}
            if target_host is not None:
                rec["target_host"] = target_host
            if agent_role is not None:
                rec["agent_role"] = agent_role
            if op == "binding.suspend":
                rec["lifecycle_state"] = "suspended"
            elif op == "binding.revoke":
                rec["lifecycle_state"] = "revoked"
            else:  # create / update_target
                rec["lifecycle_state"] = "active"
            self._records[subject] = rec
            return dict(rec)


class BindingWriteRequest(BaseModel):
    """The body a delegate POSTs to write a binding."""
    grant: dict[str, Any]
    op: str
    subject: str
    fields: dict[str, Any] = Field(default_factory=dict)
    target_host: str | None = None
    agent_role: str | None = None
    issued_at: str
    nonce: str
    store_did: str
    store_signature: str


def create_binding_write_router(
    *,
    authorizer: WriteAuthorizer,
    authenticator: RequestAuthenticator,
    store: BindingStore | None = None,
    log: MerkleLog | None = None,
    prefix: str = "",
) -> APIRouter:
    """A router exposing ``POST {prefix}/bindings/write``. Both an ``authorizer``
    and an ``authenticator`` are REQUIRED — there is no insecure default, so a
    misconfiguration cannot silently accept unauthenticated writes."""
    store = store if store is not None else BindingStore()
    log = log if log is not None else MerkleLog(origin="sm-bridge/bindings")
    seen_nonces: set[tuple[str, str]] = set()
    lock = threading.Lock()

    router = APIRouter(prefix=prefix, tags=["nanda-binding-write"])
    router.binding_store = store   # type: ignore[attr-defined]
    router.merkle_log = log        # type: ignore[attr-defined]

    @router.post("/bindings/write")
    def write_binding(body: BindingWriteRequest) -> dict[str, Any]:
        grant_id = body.grant.get("grant_id")

        # 1. Authenticate the caller as the named delegate over the exact write.
        payload = canonical_payload(
            grant_id=grant_id or "", op=body.op, subject=body.subject,
            fields=body.fields, target_host=body.target_host,
            agent_role=body.agent_role, issued_at=body.issued_at, nonce=body.nonce,
        )
        if not authenticator.authenticate(payload, body.store_did, body.store_signature):
            raise HTTPException(status_code=401, detail={"reason": "store_signature_invalid"})

        # 2. Replay guard — a (store, nonce) pair is single-use.
        key = (body.store_did, body.nonce)
        with lock:
            if key in seen_nonces:
                raise HTTPException(status_code=409, detail={"reason": "nonce_replayed"})
            seen_nonces.add(key)

        # 3. Authorize via the injected verifier (grant + field-scope + O1).
        write_request = {
            "category": body.op,
            "binding": {
                "subject": body.subject,
                "fields": sorted(body.fields.keys()),
                "target_host": body.target_host,
                "agent_role": body.agent_role,
            },
        }
        verdict = authorizer.authorize(body.grant, write_request, body.issued_at, body.store_did)
        if verdict.status == VIOLATED:
            raise HTTPException(status_code=403,
                                detail={"reason": verdict.reason, "detail": verdict.detail})
        if verdict.status == INDETERMINATE:
            raise HTTPException(status_code=409,
                                detail={"reason": verdict.reason, "detail": verdict.detail})
        if verdict.status != SATISFIED:
            raise HTTPException(status_code=500,
                                detail={"reason": "unknown_verdict", "detail": verdict.status})

        # 4. Apply, then commit to the RFC 6962 Merkle transparency log.
        record = store.apply(op=body.op, subject=body.subject, fields=body.fields,
                             target_host=body.target_host, agent_role=body.agent_role)
        entry = {
            "op": body.op, "subject": body.subject, "fields": sorted(body.fields.keys()),
            "store_did": body.store_did, "grant_id": grant_id,
            "issued_at": body.issued_at, "nonce": body.nonce, "version": record["version"],
        }
        size = log.append(canonical_log_entry(entry))
        return {
            "status": "applied",
            "binding": record,
            "log": {"leaf_index": size - 1, "tree_size": size, "root_b64": log.root_b64()},
        }

    return router
