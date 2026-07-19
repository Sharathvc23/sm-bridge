"""Smoke tests — the runnable Demo 1 and Demo 2 scenarios complete successfully."""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib

_EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLES / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_demo1_switchboard_runs():
    assert asyncio.run(_load("demo1_switchboard").main()) is True


def test_demo2_domainless_delegation_runs():
    assert asyncio.run(_load("demo2_domainless_delegation").main()) is True


def test_demo3_ans_delegated_quilt_entry_runs():
    assert asyncio.run(_load("demo3_ans_delegated_quilt_entry").main()) is True
