"""
Shared fixtures for sm-bridge tests.

Centralises object construction so tests stay DRY and magic values
live in one place.
"""

import pytest

from sm_bridge import (
    DeltaStore,
    SmBridge,
    SimpleAgent,
    SimpleAgentConverter,
)

# ---------------------------------------------------------------------------
# Common test constants (no magic values scattered across test files)
# ---------------------------------------------------------------------------
TEST_REGISTRY_ID = "test-registry"
TEST_PROVIDER_NAME = "Test Provider"
TEST_PROVIDER_URL = "https://test.com"
TEST_BASE_URL = "https://registry.test.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def simple_agent() -> SimpleAgent:
    """Return a SimpleAgent with consistent, reusable test data."""
    return SimpleAgent(
        id="fixture-agent",
        name="Fixture Agent",
        description="Agent created by the simple_agent fixture",
        namespace="default",
        labels=["chat", "assistant"],
    )


@pytest.fixture()
def bridge() -> SmBridge:
    """Return a fully configured SmBridge ready for testing."""
    return SmBridge(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        base_url=TEST_BASE_URL,
    )


@pytest.fixture()
def delta_store() -> DeltaStore:
    """Return a fresh, empty DeltaStore."""
    return DeltaStore()


@pytest.fixture()
def converter() -> SimpleAgentConverter:
    """Return a SimpleAgentConverter with standard test settings."""
    return SimpleAgentConverter(
        registry_id=TEST_REGISTRY_ID,
        provider_name=TEST_PROVIDER_NAME,
        provider_url=TEST_PROVIDER_URL,
        base_url=TEST_BASE_URL,
    )
