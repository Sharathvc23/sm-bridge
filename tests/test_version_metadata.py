"""``__version__`` must equal the installed distribution version.

A literal is a second copy of pyproject's ``version`` with nothing comparing
them. That is not a hypothetical shape in this org: sm-provision 0.1.0 shipped
``__version__ == "0.0.1"`` against correct dist metadata, and sm-authority 0.1.0
shipped the same wrong value from the same template. sm-bridge 0.6.0 then
"fixed" its version by correcting the *value* — its wheel still carried a
literal, so it was set to drift again at the next bump.

sm-bridge was correct at the time of this change. That is the point: correct-today
is exactly the state these were all in right before they drifted, so the guard
below asserts on the *duplication* rather than on the value.
"""

from __future__ import annotations

import re
from importlib.metadata import version as dist_version
from pathlib import Path

import pytest
import tomllib

import sm_bridge


def test_dunder_version_equals_installed_distribution_version() -> None:
    assert sm_bridge.__version__ == dist_version("sm-bridge")


def test_dunder_version_is_not_the_uninstalled_sentinel() -> None:
    # The source-tree fallback must never reach an installed environment; if it
    # does, every consumer's version check silently reads a placeholder.
    assert sm_bridge.__version__ != "0.0.0.dev0"


def test_module_source_declares_no_version_literal() -> None:
    """The regression guard proper.

    Equality above passes the moment someone re-adds a literal that happens to
    match today, and only fails after the next bump has already drifted. This
    fails on the duplication itself, so the shape is rejected while it is still
    correct.
    """
    src = Path(sm_bridge.__file__).read_text(encoding="utf-8")
    literals = re.findall(r'^__version__\s*=\s*["\']', src, flags=re.MULTILINE)
    assert not literals, (
        "__version__ must be derived from distribution metadata, not assigned a "
        "literal — a literal is a second copy of pyproject's version and drifts."
    )


def test_pyproject_remains_the_single_declared_source() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.exists():  # installed-only test run
        pytest.skip("source checkout not present")
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert declared == dist_version("sm-bridge"), (
        "pyproject declares the version; a mismatch here means the installed "
        "wheel was built from a different tree than this checkout."
    )
