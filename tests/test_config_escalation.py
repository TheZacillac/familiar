"""Config helpers for two-tier model escalation."""

import pytest

from familiar import config


class TestFastModelId:
    """fast_model_id returns model.fast, falling back to model.default."""

    def test_returns_fast_when_set(self):
        config.reload()
        config._cfg["model"]["fast"] = "ollama:gemma4:e4b"
        assert config.fast_model_id() == "ollama:gemma4:e4b"

    def test_falls_back_to_default(self):
        config.reload()
        config._cfg["model"].pop("fast", None)
        config._cfg["model"]["default"] = "ollama:fallback:latest"
        assert config.fast_model_id() == "ollama:fallback:latest"

    def test_falls_back_to_hardcoded(self):
        config.reload()
        config._cfg["model"].pop("fast", None)
        config._cfg["model"].pop("default", None)
        result = config.fast_model_id()
        assert "ollama:" in result  # hardcoded default


class TestPowerModelId:
    """power_model_id returns model.power or None."""

    def test_returns_power_when_set(self):
        config.reload()
        config._cfg["model"]["power"] = "ollama:gemma4:31b"
        assert config.power_model_id() == "ollama:gemma4:31b"

    def test_returns_none_when_not_set(self):
        config.reload()
        config._cfg["model"].pop("power", None)
        assert config.power_model_id() is None


class TestModelKwargsParameterized:
    """model_kwargs accepts an optional model_id argument."""

    def test_ollama_model_gets_base_url(self):
        config.reload()
        config._cfg["model"]["ollama"] = {"base_url": "http://test:11434"}
        kwargs = config.model_kwargs("ollama:gemma4:e4b")
        assert kwargs["base_url"] == "http://test:11434"

    def test_non_ollama_model_gets_empty(self):
        config.reload()
        kwargs = config.model_kwargs("anthropic:claude-sonnet-4-20250514")
        assert kwargs == {}

    def test_default_uses_fast_model(self):
        config.reload()
        config._cfg["model"]["fast"] = "ollama:gemma4:e4b"
        config._cfg["model"]["ollama"] = {"base_url": "http://test:11434"}
        kwargs = config.model_kwargs()
        assert kwargs["base_url"] == "http://test:11434"


class TestEnvOverrideFastPower:
    """Environment variables override fast/power config."""

    def test_familiar_model_fast_override(self, monkeypatch):
        monkeypatch.setenv("FAMILIAR_MODEL_FAST", "ollama:tiny:latest")
        config.reload()
        assert config.fast_model_id() == "ollama:tiny:latest"

    def test_familiar_model_power_override(self, monkeypatch):
        monkeypatch.setenv("FAMILIAR_MODEL_POWER", "anthropic:claude-sonnet-4-20250514")
        config.reload()
        assert config.power_model_id() == "anthropic:claude-sonnet-4-20250514"
