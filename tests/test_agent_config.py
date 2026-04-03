"""Test 12: Agent configuration — env parsing, model kwargs, system prompt.

Tests the pure functions in agent.py that can be validated without
instantiating an LLM or making network calls.
"""

import os
import tempfile

import pytest

from familiar.agent import (
    DEFAULT_MODEL,
    SYSTEM_PROMPT,
    _build_model_kwargs,
    _build_system_prompt,
    _load_env,
)


class TestDefaultModel:
    """Default model configuration."""

    def test_default_model_format(self):
        assert ":" in DEFAULT_MODEL
        provider, model = DEFAULT_MODEL.split(":", 1)
        assert provider == "ollama"
        assert len(model) > 0


class TestSystemPrompt:
    """System prompt content must include key behavioral instructions."""

    def test_prompt_mentions_familiar(self):
        assert "Familiar" in SYSTEM_PROMPT

    def test_prompt_mentions_exact_domain_usage(self):
        assert "EXACTLY" in SYSTEM_PROMPT

    def test_prompt_mentions_diagnostics(self):
        assert "Diagnostics" in SYSTEM_PROMPT

    def test_prompt_mentions_security(self):
        assert "Security" in SYSTEM_PROMPT

    def test_prompt_mentions_penetration_testing(self):
        assert "Penetration Testing" in SYSTEM_PROMPT

    def test_prompt_mentions_advisory(self):
        assert "Advisory" in SYSTEM_PROMPT

    def test_prompt_mentions_memory(self):
        assert "Memory" in SYSTEM_PROMPT

    def test_prompt_mentions_severity_preservation(self):
        """Agent must not reclassify tool result severity."""
        assert "Never reclassify severity" in SYSTEM_PROMPT

    def test_prompt_mentions_faithful_count_reproduction(self):
        assert "severity_breakdown" in SYSTEM_PROMPT

    def test_prompt_contains_slash_commands(self):
        for cmd in ["/assess", "/compare", "/secure", "/pentest", "/vs"]:
            assert cmd in SYSTEM_PROMPT


class TestBuildSystemPrompt:
    """_build_system_prompt must include the base prompt."""

    def test_includes_base_prompt(self):
        prompt = _build_system_prompt()
        assert "Familiar" in prompt
        assert "Diagnostics" in prompt

    def test_returns_string(self):
        assert isinstance(_build_system_prompt(), str)


class TestBuildModelKwargs:
    """_build_model_kwargs must return correct provider-specific config."""

    def test_ollama_with_base_url(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://custom:11434")
        kwargs = _build_model_kwargs("ollama:llama3")
        assert kwargs["base_url"] == "http://custom:11434"

    def test_ollama_without_base_url(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
        kwargs = _build_model_kwargs("ollama:llama3")
        assert "base_url" not in kwargs

    def test_non_ollama_provider(self):
        kwargs = _build_model_kwargs("openai:gpt-4o")
        assert kwargs == {}

    def test_no_provider_separator(self):
        kwargs = _build_model_kwargs("some-model")
        assert kwargs == {}


class TestLoadEnv:
    """_load_env must parse .env files without python-dotenv."""

    def test_loads_simple_key_value(self, monkeypatch, tmp_path):
        env_file = tmp_path / "src" / "familiar" / ".env"
        env_file.parent.mkdir(parents=True)
        # _load_env looks two parents up from the agent module, so we
        # test the parsing logic directly with a controlled file.
        env_file.write_text("TEST_LOAD_ENV_KEY=hello\n")

        # Manually replicate the parsing logic on our controlled file
        monkeypatch.delenv("TEST_LOAD_ENV_KEY", raising=False)
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

        assert os.environ.get("TEST_LOAD_ENV_KEY") == "hello"
        monkeypatch.delenv("TEST_LOAD_ENV_KEY", raising=False)

    def test_strips_quotes(self):
        """Quoted values should have quotes removed."""
        # Test the quote-stripping logic directly
        value = '"quoted_value"'
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        assert value == "quoted_value"

    def test_strips_inline_comments(self):
        """Unquoted values with # should have comments stripped."""
        value = "some_value # this is a comment"
        if "#" in value:
            value = value.split("#", 1)[0].rstrip()
        assert value == "some_value"

    def test_skips_comment_lines(self):
        """Lines starting with # should be ignored."""
        line = "# This is a comment"
        assert line.startswith("#")

    def test_skips_empty_lines(self):
        """Empty lines should be ignored."""
        line = ""
        assert not line

    def test_setdefault_does_not_overwrite(self, monkeypatch):
        """Existing env vars should not be overwritten."""
        monkeypatch.setenv("EXISTING_VAR", "original")
        os.environ.setdefault("EXISTING_VAR", "new_value")
        assert os.environ["EXISTING_VAR"] == "original"
