"""An identifier scoped to another registry must not resolve against this one.

`/resolve` answers about agents THIS registry holds, and attaches this
registry's proof block to the answer. Reducing `@other-registry:ns/foo` to `foo`
and looking it up locally means answering for a subject we were not asked about,
under our own attestation.

Rejection is 400, never 404. A 404 is read by a corroborator as a positive claim
of absence, which would make this registry appear to assert something about
another registry's namespace and could raise a false `omission` finding against
it. 400 carries no claim.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge.router import _parse_agent_identifier, create_sm_router

from .conftest import TEST_PROVIDER_URL, TEST_REGISTRY_ID


def _parse(value: str) -> str | None:
    return _parse_agent_identifier(value, TEST_REGISTRY_ID, TEST_PROVIDER_URL)


class TestOwnScopeIsStripped:
    def test_handle_naming_this_registry(self) -> None:
        assert _parse(f"@{TEST_REGISTRY_ID}/agent") == "agent"

    def test_handle_with_namespace_naming_this_registry(self) -> None:
        assert _parse(f"@{TEST_REGISTRY_ID}:ns/agent") == "agent"

    def test_did_web_under_this_provider(self) -> None:
        assert _parse("did:web:test.com:agents:default:agent") == "agent"

    def test_bare_handle_has_no_scope_to_check(self) -> None:
        assert _parse("@agent") == "agent"


class TestForeignScopeIsRejected:
    def test_handle_naming_another_registry(self) -> None:
        assert _parse("@other-registry/agent") is None

    def test_namespaced_handle_naming_another_registry(self) -> None:
        assert _parse("@other-registry:ns/agent") is None

    def test_did_web_under_another_provider(self) -> None:
        assert _parse("did:web:other.example:agents:agent") is None

    def test_urn_names_a_foreign_authority_by_construction(self) -> None:
        assert _parse("urn:ai:domain:acme.example:agent:concierge") is None

    def test_unknown_did_method(self) -> None:
        assert _parse("did:key:z6MkExample") is None

    def test_empty_identifier(self) -> None:
        assert _parse("") is None


class TestAirUrnIsAnchoredToThePublisherFqdn:
    """`urn:air:<publisher-FQDN>:<ns...>:<short-name>` — the Index's own key.

    The publisher FQDN is proven by DNS TXT challenge before the Index issues an
    identifier under it, so it anchors the identifier exactly as a `did:web`'s host
    does. Refusing every `urn:` meant refusing this registry's own identifier.
    """

    def test_air_urn_under_our_fqdn_reduces_to_the_short_name(self) -> None:
        assert _parse("urn:air:test.com:agent:agent-1") == "agent-1"

    def test_org_level_catalog_entry(self) -> None:
        # The shape a bridge-backed org carries on the Index; resolve arrives as
        # the short name "root", which a 404 here broke end to end.
        assert _parse("urn:air:test.com:catalog:root") == "root"

    def test_multi_segment_namespace_keeps_only_the_last_segment(self) -> None:
        assert _parse("urn:air:test.com:agent:retail:order") == "order"

    def test_scheme_and_nid_are_case_insensitive(self) -> None:
        # RFC 8141: both are case-insensitive. The Index lower-cases them.
        assert _parse("URN:AIR:TEST.COM:agent:agent-1") == "agent-1"

    def test_port_and_path_on_the_provider_url_still_anchor(self) -> None:
        # Neither can appear in the FQDN segment being compared.
        assert (
            _parse_agent_identifier(
                "urn:air:test.com:agent:agent-1", TEST_REGISTRY_ID, "https://test.com:8443/registry"
            )
            == "agent-1"
        )

    def test_air_urn_under_another_publisher_is_rejected(self) -> None:
        assert _parse("urn:air:other.example:agent:agent-1") is None

    def test_personal_card_host_anchor_is_another_publisher_to_us(self) -> None:
        # A domain-less individual is anchored to their card host, not to us.
        assert _parse("urn:air:host39.org:personal:someone@example.com") is None

    def test_the_card_host_itself_anchors_its_own_personal_identifiers(self) -> None:
        assert (
            _parse_agent_identifier(
                "urn:air:host39.org:personal:someone@example.com",
                TEST_REGISTRY_ID,
                "https://host39.org",
            )
            == "someone@example.com"
        )

    def test_a_namespace_without_a_short_name_is_not_an_identifier(self) -> None:
        # The minimum the Index enforces: at least one namespace segment and a name.
        assert _parse("urn:air:test.com:agent") is None

    def test_empty_short_name(self) -> None:
        assert _parse("urn:air:test.com:agent:") is None

    def test_bare_prefix(self) -> None:
        assert _parse("urn:air:") is None

    def test_a_different_urn_namespace_is_still_foreign(self) -> None:
        # `urn:ai:` is not `urn:air:` — and the Index refuses it too.
        assert _parse("urn:ai:domain:test.com:agent:agent-1") is None

    def test_a_foreign_urn_is_refused_whatever_its_case(self) -> None:
        assert _parse("URN:AI:domain:test.com:agent:agent-1") is None


class TestUnscopedIdentifiersArePassedThrough:
    def test_plain_id(self) -> None:
        assert _parse("plain-agent") == "plain-agent"

    def test_a_colon_is_not_evidence_of_a_namespace(self) -> None:
        # The old rule split any colon and took the last part, which could not
        # tell a local id from another registry's URN. An unrecognised format is
        # the id, whole.
        assert _parse("ns:agent") == "ns:agent"


@pytest.fixture
def client() -> TestClient:
    from sm_bridge import DeltaStore, SimpleAgent, SimpleAgentConverter

    from .conftest import TEST_BASE_URL, TEST_PROVIDER_NAME

    converter = SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        base_url=TEST_BASE_URL,
    )
    converter.register(SimpleAgent(id="agent-1", name="Agent 1", description="Test agent"))
    router, wellknown = create_sm_router(
        converter=converter,
        delta_store=DeltaStore(),
        registry_id=TEST_REGISTRY_ID,
        base_url=TEST_BASE_URL,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
    )
    app = FastAPI()
    app.include_router(router)
    app.include_router(wellknown)
    return TestClient(app)


def test_resolve_serves_its_own_agent(client: TestClient) -> None:
    assert client.get("/nanda/resolve", params={"agent": "agent-1"}).status_code == 200


def test_resolve_serves_its_own_agent_by_air_urn(client: TestClient) -> None:
    # The identifier the Index holds for this agent, resolved against the registry
    # that owns it. Before this was anchored, the blanket `urn:` refusal made this
    # a 400 — the bridge rejecting its own canonical identifier.
    r = client.get("/nanda/resolve", params={"agent": "urn:air:test.com:agent:agent-1"})
    assert r.status_code == 200


def test_resolve_rejects_another_publishers_air_urn_with_400(client: TestClient) -> None:
    # Anchoring must not become a way in: another publisher's identifier would
    # otherwise be answered with THIS registry's agent under THIS registry's proof.
    r = client.get("/nanda/resolve", params={"agent": "urn:air:other.example:agent:agent-1"})
    assert r.status_code == 400
    assert "registry" in r.json()["detail"].lower()


def test_resolve_rejects_a_foreign_identifier_with_400(client: TestClient) -> None:
    # Today this returns 200 with THIS registry's agent-1 and this registry's
    # proof block, for an identifier that names a different registry.
    r = client.get("/nanda/resolve", params={"agent": "@other-registry:ns/agent-1"})
    assert r.status_code == 400
    assert "registry" in r.json()["detail"].lower()
