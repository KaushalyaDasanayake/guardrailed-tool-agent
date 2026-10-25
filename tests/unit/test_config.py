"""Unit tests for configuration loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardagent.config import load_config


def test_load_default_config():
    cfg = load_config()
    assert cfg["agent"]["name"] == "guardagent"
    assert cfg["agent"]["max_iterations"] >= 1
    assert "security" in cfg
    assert "audit" in cfg


def test_config_missing_file(tmp_path: Path):
    non_existent = tmp_path / "missing.yaml"
    with pytest.raises(FileNotFoundError):
        load_config(non_existent)
