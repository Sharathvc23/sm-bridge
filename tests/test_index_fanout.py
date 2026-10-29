"""The NANDA Index's fan-out hop — `GET <registry_url>/agents/search?q=...`.

This is the ONE path the Index fetches from a registrant. An entry registered with
the enterprise catalog media type is expanded at query time by fetching it; the
Index reads `entries` off the response and takes a bounded slice. A registry that
does not answer is recorded as unreachable and contributes nothing to the Index's
search, however complete its catalog — so these tests encode the upstream contract
rather than this library's preferences, and a change that breaks one of them breaks
discovery for every registry built on the bridge.

The contract, from the Index's own fan-out service:

  * the document is accepted when `entries` is an array (`specVersion` is sent and
    carried, but the Index does not gate on it)
  * an entry declares `identifier`, `displayName`, `mediaType`, `url`, and
    optionally `description`, `tags`, `version`, `updatedAt`, `metadata` — camelCase

A `200` with zero entries is a different answer from a timeout: the first says this
registry was asked and had nothing, the second gets the org recorded as unreachable.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sm_bridge import DeltaStore, create_gateway_router

from .test_gateway import BASE_URL, DOMAIN, _facts

#: What the Index requires of every entry it reads out of the fan-out response.
REQUIRED_ENTRY_KEYS = {"identifier", "displayName", "mediaType", "url"}
#: Everything else the Index declares for an entry. Nothing outside the union is read.
OPTIONAL_ENTRY_KEYS = {"description", "tags", "version", "updatedAt", "metadata"}


def _client(store: DeltaStore) -> TestClient:
    app = FastAPI()
    app.include_router(create_gateway_router(store, base_url=BASE_URL, domain=DOMAIN))
    return TestClient(app)


def test_the_index_fanout_url_is_answered() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))

    res = _client(store).get("/agents/search", params={"q": "plan"})

    assert res.status_code == 200


def test_the_response_is_a_document_the_index_accepts() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))

    body = _client(store).get("/agents/search", params={"q": "plan"}).json()

    # The Index's acceptance test is exactly this: `entries` is an array.
    assert isinstance(body["entries"], list)
    assert body["specVersion"] == "1.0"


def test_every_entry_carries_the_fields_the_index_reads() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))

    entries = _client(store).get("/agents/search", params={"q": "plan"}).json()["entries"]

    assert entries, "a matching agent must produce a candidate"
    for entry in entries:
        assert REQUIRED_ENTRY_KEYS <= set(entry)
        # Nothing outside the Index's vocabulary: a key it does not read is a field
        # this registry would be asserting into a fan-out result for no consumer.
        assert set(entry) <= REQUIRED_ENTRY_KEYS | OPTIONAL_ENTRY_KEYS


def test_no_match_is_an_empty_document_not_an_error() -> None:
    # A 200 with no entries says "asked, nothing matched". Anything else gets this
    # org recorded as unreachable, which is a claim about the registry, not the query.
    store = DeltaStore()
    store.add("upsert", _facts("planner"))

    res = _client(store).get("/agents/search", params={"q": "nothing-matches-this"})

    assert res.status_code == 200
    assert res.json()["entries"] == []


def test_search_is_not_captured_as_an_agent_slug() -> None:
    # Route-order regression: `/agents/{slug}` registered first would answer the
    # Index's fan-out with a 404 for an agent named "search".
    store = DeltaStore()
    store.add("upsert", _facts("planner"))

    body = _client(store).get("/agents/search", params={"q": "plan"}).json()

    assert "entries" in body


def test_an_agent_whose_slug_is_search_is_shadowed() -> None:
    # The boundary of the rule above, pinned rather than discovered: the fan-out
    # path wins, so an agent named "search" is not reachable at /agents/search.
    # It is still in the catalog and still a candidate in the fan-out.
    store = DeltaStore()
    store.add("upsert", _facts("search"))

    body = _client(store).get("/agents/search").json()

    assert "entries" in body
    assert [e["identifier"] for e in body["entries"]] == ["search"]


class TestMatching:
    def test_matches_the_display_name(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        body = _client(store).get("/agents/search", params={"q": "Agent planner"}).json()
        assert len(body["entries"]) == 1

    def test_matches_a_declared_tag(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        body = _client(store).get("/agents/search", params={"q": "plan"}).json()
        assert len(body["entries"]) == 1

    def test_matches_the_description(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        body = _client(store).get("/agents/search", params={"q": "an agent."}).json()
        assert len(body["entries"]) == 1

    def test_is_case_insensitive(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        body = _client(store).get("/agents/search", params={"q": "PLANNER"}).json()
        assert len(body["entries"]) == 1

    def test_an_absent_query_narrows_by_nothing(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        store.add("upsert", _facts("reporter"))
        body = _client(store).get("/agents/search").json()
        assert len(body["entries"]) == 2


def test_search_and_the_catalog_answer_with_the_same_agents() -> None:
    # One source of truth. If these could disagree, the Index would see a set of
    # agents that no other consumer of this registry can.
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    store.add("upsert", _facts("reporter"))
    client = _client(store)

    catalog = client.get("/.well-known/ai-catalog.json").json()["entries"]
    searched = client.get("/agents/search").json()["entries"]

    # `updatedAt` is excluded because it is the moment of serialization, not of
    # modification — a known residual recorded in 0.8.0 — so two requests differ
    # there by construction. Comparing it would pin the defect instead of the claim.
    def without_timestamp(entries: list[dict[str, object]]) -> list[dict[str, object]]:
        return [{k: v for k, v in e.items() if k != "updatedAt"} for e in entries]

    assert without_timestamp(searched) == without_timestamp(catalog)


def test_a_removed_agent_is_not_a_fanout_candidate() -> None:
    store = DeltaStore()
    store.add("upsert", _facts("planner"))
    store.add("delete", _facts("planner"))

    body = _client(store).get("/agents/search", params={"q": "plan"}).json()

    assert body["entries"] == []


class TestCardIdentifier:
    def test_the_card_names_the_agent_with_an_air_urn(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))

        card = _client(store).get("/cards/planner.json").json()

        assert card["_meta"]["identifier"] == f"urn:air:{DOMAIN}:agent:planner"

    def test_the_card_no_longer_carries_an_identifier_the_index_refuses(self) -> None:
        store = DeltaStore()
        store.add("upsert", _facts("planner"))

        card = _client(store).get("/cards/planner.json").json()

        assert not card["_meta"]["identifier"].startswith("urn:ai:domain:")

    def test_the_publisher_domain_is_normalised(self) -> None:
        # The Index lower-cases the publisher domain, so an identifier differing
        # only in case is a different string to everything downstream.
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        app = FastAPI()
        app.include_router(create_gateway_router(store, base_url=BASE_URL, domain="Example.COM"))

        card = TestClient(app).get("/cards/planner.json").json()

        assert card["_meta"]["identifier"] == "urn:air:example.com:agent:planner"


class TestListingPredicate:
    """`is_listed` — a registry's own rule for who may be enumerated.

    Orrery hand-wrote its entire Index-facing surface because this library could not
    express consent gating, and then had to keep its index, delta feed and re-seed
    agreeing by hand. The predicate exists so the next registry in that position can
    use the library instead.
    """

    @staticmethod
    def _store() -> DeltaStore:
        store = DeltaStore()
        store.add("upsert", _facts("consented"))
        store.add("upsert", _facts("withheld"))
        return store

    @staticmethod
    def _listed_client(store: DeltaStore) -> TestClient:
        app = FastAPI()
        app.include_router(
            create_gateway_router(
                store,
                base_url=BASE_URL,
                domain=DOMAIN,
                is_listed=lambda slug, _facts: slug != "withheld",
            )
        )
        return TestClient(app)

    def test_the_catalog_omits_an_unlisted_agent(self) -> None:
        body = self._listed_client(self._store()).get("/.well-known/ai-catalog.json").json()
        assert [e["identifier"] for e in body["entries"]] == ["consented"]

    def test_the_index_fanout_omits_an_unlisted_agent(self) -> None:
        body = self._listed_client(self._store()).get("/agents/search").json()
        assert [e["identifier"] for e in body["entries"]] == ["consented"]

    def test_both_enumerating_surfaces_agree(self) -> None:
        # The property that matters: a registry must not publish two different
        # claims about who it lists.
        client = self._listed_client(self._store())
        catalog = {e["identifier"] for e in client.get("/.well-known/ai-catalog.json").json()["entries"]}
        searched = {e["identifier"] for e in client.get("/agents/search").json()["entries"]}
        assert catalog == searched

    def test_an_unlisted_agent_is_still_resolvable_by_name(self) -> None:
        # Deliberate, and the boundary is pinned rather than left to be discovered.
        # A 403 would disclose the agent while refusing it; a 404 would be a positive
        # claim of absence about an agent this registry holds — which a corroborator
        # reads as a false omission — and the Index's own resolution hop for a
        # legitimately registered entry comes through this path.
        client = self._listed_client(self._store())
        assert client.get("/agents/withheld").status_code == 200
        assert client.get("/cards/withheld.json").status_code == 200

    def test_no_predicate_lists_everything(self) -> None:
        # The default must be the pre-existing behaviour, or this is a breaking change.
        body = _client(self._store()).get("/.well-known/ai-catalog.json").json()
        assert {e["identifier"] for e in body["entries"]} == {"consented", "withheld"}

    def test_the_predicate_sees_the_facts_not_only_the_slug(self) -> None:
        # A real consent rule reads the record, not just its name.
        store = DeltaStore()
        store.add("upsert", _facts("planner"))
        app = FastAPI()
        app.include_router(
            create_gateway_router(
                store,
                base_url=BASE_URL,
                domain=DOMAIN,
                is_listed=lambda _slug, facts: facts.agent_name != "Agent planner",
            )
        )
        assert TestClient(app).get("/agents/search").json()["entries"] == []
