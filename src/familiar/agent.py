"""LangGraph Deep Agent with configurable LLM provider."""

import os

from langchain.chat_models import init_chat_model
from deepagents import create_deep_agent

from .tools import ALL_TOOLS

DEFAULT_MODEL = "ollama:nemotron-3-nano:latest"


def _load_env():
    """Load .env file if present, without requiring python-dotenv."""
    env_path = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, ".env")
    env_path = os.path.normpath(env_path)
    if not os.path.isfile(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and value:
                os.environ.setdefault(key, value)


_load_env()

SYSTEM_PROMPT = (
    "You are Familiar, a domain name intelligence assistant. "
    "You help users investigate domains, DNS records, WHOIS/RDAP data, "
    "TLD information, and domain industry terminology. "
    "Use your tools to look up real data rather than guessing. "
    "Be concise and direct in your responses."
)


def _build_model_kwargs(model_id: str) -> dict:
    """Build provider-specific kwargs from environment variables."""
    kwargs = {}
    provider = model_id.split(":")[0] if ":" in model_id else None

    if provider == "ollama":
        base_url = os.environ.get("OLLAMA_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url

    return kwargs


def build_agent():
    """Construct and return the LangGraph Deep Agent."""
    model_id = os.environ.get("FAMILIAR_MODEL", DEFAULT_MODEL)

    model = init_chat_model(
        model=model_id,
        **_build_model_kwargs(model_id),
    )

    agent = create_deep_agent(
        model=model,
        tools=ALL_TOOLS,
        system_prompt=SYSTEM_PROMPT,
    )

    return agent
