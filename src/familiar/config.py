"""Configuration management for Familiar.

Loads settings from ``~/.familiar/config.toml`` with sensible defaults.
Environment variables override config file values for backward compatibility.
"""

import os
import tomllib
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "model": {
        "default": "ollama:nemotron-3-nano:latest",
        "ollama": {
            "base_url": "http://localhost:11434",
        },
    },
    "storage": {
        "data_dir": "~/.familiar",
        "db_name": "familiar.db",
        "export_dir": "~/.familiar/exports",
    },
    "agent": {
        "max_workers": 12,
    },
    "tracing": {
        "enabled": False,
        "api_key": "",
        "project": "familiar",
    },
    "theme": {
        "info": "#8caaee",
        "warning": "#e5c890",
        "error": "#e78284",
        "success": "#a6d189",
        "prompt": "bold #a6d189",
        "title": "bold #ca9ee6",
        "border": "#babbf1",
        "muted": "#a5adce",
        "spinner": "#81c8be",
        "accent": "#f4b8e4",
        "peach": "#ef9f76",
        "sky": "#99d1db",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _resolve_path(raw: str) -> Path:
    """Expand ``~`` and env vars, then resolve to an absolute path."""
    return Path(os.path.expandvars(os.path.expanduser(raw))).resolve()


def _config_path() -> Path:
    """Return the path to the user's config file."""
    env = os.environ.get("FAMILIAR_CONFIG")
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".familiar" / "config.toml"


def _load_file() -> dict:
    """Read and parse the TOML config file, returning ``{}`` if absent."""
    path = _config_path()
    if not path.is_file():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def _apply_env_overrides(cfg: dict) -> dict:
    """Let environment variables override config values for backward compat."""
    if val := os.environ.get("FAMILIAR_MODEL"):
        cfg.setdefault("model", {})["default"] = val
    if val := os.environ.get("OLLAMA_BASE_URL"):
        cfg.setdefault("model", {}).setdefault("ollama", {})["base_url"] = val
    if val := os.environ.get("FAMILIAR_DATA_DIR"):
        cfg.setdefault("storage", {})["data_dir"] = val
    if val := os.environ.get("FAMILIAR_DB_NAME"):
        cfg.setdefault("storage", {})["db_name"] = val
    if val := os.environ.get("FAMILIAR_EXPORT_DIR"):
        cfg.setdefault("storage", {})["export_dir"] = val
    if val := os.environ.get("FAMILIAR_MAX_WORKERS"):
        cfg.setdefault("agent", {})["max_workers"] = int(val)

    # Tracing env vars (LangSmith convention)
    tracing_val = os.environ.get("LANGSMITH_TRACING")
    if tracing_val is not None:
        cfg.setdefault("tracing", {})["enabled"] = tracing_val.lower() in ("true", "1", "yes")
    if val := os.environ.get("LANGSMITH_API_KEY"):
        cfg.setdefault("tracing", {})["api_key"] = val
    if val := os.environ.get("LANGSMITH_PROJECT"):
        cfg.setdefault("tracing", {})["project"] = val

    return cfg


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_cfg: dict | None = None


def load() -> dict:
    """Load configuration (file + env overrides), cached after first call."""
    global _cfg
    if _cfg is None:
        file_cfg = _load_file()
        merged = _deep_merge(DEFAULTS, file_cfg)
        _cfg = _apply_env_overrides(merged)
    return _cfg


def reload() -> dict:
    """Force-reload configuration from disk and environment."""
    global _cfg
    _cfg = None
    return load()


def get(section: str, key: str | None = None, default=None):
    """Convenience accessor.

    ``get("model", "default")`` → ``"ollama:nemotron-3-nano:latest"``
    ``get("theme")`` → full theme dict
    """
    cfg = load()
    data = cfg.get(section, {})
    if key is None:
        return data if data else default
    return data.get(key, default)


# --- Derived helpers used by multiple modules ---


def data_dir() -> Path:
    """Resolved data directory (``~/.familiar`` by default)."""
    path = _resolve_path(get("storage", "data_dir", "~/.familiar"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    """Full path to the SQLite database."""
    return data_dir() / get("storage", "db_name", "familiar.db")


def export_dir() -> Path:
    """Resolved export directory, created on first access."""
    path = _resolve_path(get("storage", "export_dir", "~/.familiar/exports"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def model_id() -> str:
    """The configured LLM model identifier (``provider:model``)."""
    return get("model", "default", "ollama:nemotron-3-nano:latest")


def model_kwargs() -> dict:
    """Provider-specific kwargs derived from config."""
    mid = model_id()
    kwargs = {}
    provider = mid.split(":")[0] if ":" in mid else None
    if provider == "ollama":
        base_url = get("model", key=None, default={}).get("ollama", {}).get("base_url")
        if base_url:
            kwargs["base_url"] = base_url
    return kwargs


def max_workers() -> int:
    """Thread pool size for parallel calls."""
    return get("agent", "max_workers", 12)


def theme_dict() -> dict:
    """Return the theme mapping for Rich."""
    return get("theme", default={})
