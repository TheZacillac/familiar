"""LangGraph ReAct agent wired to Ollama and tower tools."""

import os

from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from .tools import ALL_TOOLS


def _load_env():
    """Load .env file if present, without requiring python-dotenv."""
    env_path = os.path.join(os.path.dirname(__file__), os.pardir, ".env")
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


def build_agent():
    """Construct and return the LangGraph ReAct agent."""
    model = ChatOllama(
        model=os.environ.get("OLLAMA_MODEL", "qwen2.5:latest"),
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
    )

    agent = create_react_agent(
        model=model,
        tools=ALL_TOOLS,
        prompt=SYSTEM_PROMPT,
    )

    return agent
