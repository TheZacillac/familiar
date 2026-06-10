"""Claude Agent SDK adapter for Familiar.

Mirrors `agent.py` (the LangChain Deep Agent build) but powers the agent with
Anthropic's Claude Agent SDK instead. Reuses the existing tool implementations
in `familiar.tools` by wrapping each LangChain `@tool` function as an in-process
MCP tool — no per-tool reimplementation.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool

from . import config
from .agent import _build_system_prompt, _configure_tracing, _load_env
from .tools import ALL_TOOLS

MCP_SERVER_NAME = "familiar"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"

# Built-in Claude Code tools that we explicitly do not want Familiar to use.
# Familiar is a domain-intelligence agent, not a coding assistant — its only
# tool surface should be the MCP tools we register below.
_DISALLOWED_BUILTINS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "NotebookEdit",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Task",
    "TodoWrite",
)


def _to_json_schema(args_schema) -> dict[str, Any]:
    """Extract a JSON Schema dict from a LangChain tool's args_schema.

    Handles both Pydantic v1 (.schema()) and v2 (.model_json_schema()).
    """
    if args_schema is None:
        return {"type": "object", "properties": {}}
    if hasattr(args_schema, "model_json_schema"):
        try:
            return args_schema.model_json_schema()
        except Exception:
            pass
    if hasattr(args_schema, "schema"):
        try:
            return args_schema.schema()
        except Exception:
            pass
    return {"type": "object", "properties": {}}


def _wrap_lc_tool(lc_tool):
    """Wrap a LangChain `@tool`-decorated function as a Claude Agent SDK tool."""
    name = lc_tool.name
    description = (lc_tool.description or "").strip() or name
    schema = _to_json_schema(lc_tool.args_schema)

    @tool(name, description, schema)
    async def _handler(args: dict[str, Any]) -> dict[str, Any]:
        try:
            # LangChain tools are sync and may do blocking I/O — run off-loop.
            result = await asyncio.to_thread(lc_tool.invoke, args)
        except Exception as e:
            return {
                "content": [
                    {"type": "text", "text": json.dumps({"error": str(e)})}
                ],
                "is_error": True,
            }
        if not isinstance(result, str):
            try:
                result = json.dumps(result, default=str)
            except Exception:
                result = str(result)
        return {"content": [{"type": "text", "text": result}]}

    return _handler


def build_mcp_server():
    """Create the in-process MCP server hosting all Familiar tools."""
    sdk_tools = [_wrap_lc_tool(t) for t in ALL_TOOLS]
    return create_sdk_mcp_server(
        name=MCP_SERVER_NAME,
        version="0.1.0",
        tools=sdk_tools,
    )


def _claude_model_id() -> str:
    """Resolve the Claude model id from env / config, with a sensible default."""
    env_val = os.environ.get("FAMILIAR_CLAUDE_MODEL")
    if env_val:
        return env_val
    cfg_val = config.get("model", "claude_model", None)
    if cfg_val:
        return cfg_val
    return DEFAULT_CLAUDE_MODEL


def build_options(system_prompt: str | None = None) -> ClaudeAgentOptions:
    """Construct a `ClaudeAgentOptions` ready to drive `query()` / `ClaudeSDKClient`."""
    server = build_mcp_server()
    return ClaudeAgentOptions(
        system_prompt=system_prompt if system_prompt is not None else _build_system_prompt(),
        mcp_servers={MCP_SERVER_NAME: server},
        allowed_tools=[f"mcp__{MCP_SERVER_NAME}__*"],
        disallowed_tools=list(_DISALLOWED_BUILTINS),
        permission_mode="bypassPermissions",
        model=_claude_model_id(),
    )


def bootstrap() -> ClaudeAgentOptions:
    """Load `.env` + config + tracing and return ready-to-use options."""
    _load_env()
    config.load()
    _configure_tracing()
    return build_options()


__all__ = [
    "DEFAULT_CLAUDE_MODEL",
    "MCP_SERVER_NAME",
    "bootstrap",
    "build_mcp_server",
    "build_options",
]
