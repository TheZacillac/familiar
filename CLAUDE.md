# CLAUDE.md - Familiar

Familiar is a conversational AI agent for domain intelligence, powered by LangChain's Deep Agents framework and LangGraph. It provides a natural language interface to Seer (domain diagnostics) and Tome (reference data).

---

## Architecture

```
familiar/
├── pyproject.toml
├── .env                     # Local environment config (gitignored)
├── .env.example             # Environment template
└── src/familiar/
    ├── __init__.py           # Version: 0.1.0
    ├── cli.py                # CLI entry point (REPL + single-query)
    ├── agent.py              # LangGraph Deep Agent builder
    └── tools/
        ├── __init__.py       # Exports ALL_TOOLS (34 total: seer + tome + advisor + memory)
        ├── seer_tools.py     # 13 Seer tools (LangChain @tool wrappers)
        ├── tome_tools.py     # 6 Tome tools (LangChain @tool wrappers)
        ├── advisor_tools.py  # 6 Advisory tools (appraise, acquire, suggest, audit, competitive, migrate)
        └── memory_tools.py   # 9 Memory tools (domain notebook, watchlist, explanation mode)
```

---

## How It Works

### Agent Construction Flow (agent.py)

1. **`_load_env()`** — reads `.env` manually (no python-dotenv dependency), sets env vars with `setdefault`
2. **`_load_skill_docs()`** — uses `scrolls` to discover and load SKILL.md + reference docs for each skill
3. **`_build_system_prompt()`** — base prompt ("You are Familiar, a domain name intelligence assistant...") + merged skill documentation
4. **`_build_model_kwargs()`** — extracts provider from `FAMILIAR_MODEL`, builds provider-specific kwargs
5. **`build_agent()`** — uses `langchain_core.chat_models.init_chat_model()` + `deepagents.create_deep_agent()` with all tools and system prompt

### Agent Invocation

```python
agent.invoke({"messages": [{"role": "user", "content": query}]})
```

Deep Agents handles planning, tool selection, sub-agent delegation, and response synthesis.

---

## CLI (cli.py)

**Entry point:** `familiar` (or `familiar "query"`)

- **Interactive mode** (no args): REPL with Rich-styled markdown output, Catppuccin Mocha theme
- **Single-query mode** (with arg): executes one query, prints response, exits

Commands in REPL: type query, `quit`/`exit` to leave, Ctrl+C/Ctrl+D handled gracefully.

### UI Theme

Catppuccin Mocha palette with Rich library:
- Markdown rendering for responses
- Styled panels with borders and colors
- Custom color mapping: info (blue), warning (yellow), error (red), success (green), prompt (mauve), etc.

---

## Tools (34 total)

All wrapped with `@langchain_core.tools.tool`, return JSON strings.

### Seer Tools (13) — `seer_tools.py`

**Single:** `seer_lookup`, `seer_whois`, `seer_rdap_domain`, `seer_rdap_ip`, `seer_rdap_asn`, `seer_dig`, `seer_propagation`, `seer_status`

**Bulk (max 100 domains):** `seer_bulk_lookup`, `seer_bulk_whois`, `seer_bulk_dig`, `seer_bulk_status`, `seer_bulk_propagation`

### Tome Tools (6) — `tome_tools.py`

`tome_tld_lookup`, `tome_tld_search`, `tome_record_lookup`, `tome_record_search`, `tome_glossary_lookup`, `tome_glossary_search`

### Advisor Tools (6) — `advisor_tools.py`

`appraise_domain`, `plan_acquisition`, `suggest_domains`, `audit_portfolio`, `competitive_intel`, `migration_preflight`

### Memory Tools (9) — `memory_tools.py`

**Domain notebook:** `remember_domain`, `recall_domain`, `recall_all_domains`

**Watchlist:** `watchlist_add`, `watchlist_remove`, `watchlist_list`, `watchlist_check`

**Preferences:** `set_explanation_mode`, `get_explanation_mode`

---

## Configuration

### Environment Variables (.env)

| Variable | Default | Purpose |
|----------|---------|---------|
| `FAMILIAR_MODEL` | `ollama:nemotron-3-nano:latest` | LLM in `provider:model` format |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `GOOGLE_API_KEY` | — | Google Gemini API key |
| `LANGSMITH_TRACING` | `false` | Enable LangSmith observability |
| `LANGSMITH_API_KEY` | — | LangSmith auth key |
| `LANGSMITH_PROJECT` | `familiar` | LangSmith project name |

### Supported LLM Providers

Format: `provider:model`

- `ollama:nemotron-3-nano:latest` (local, default)
- `openai:gpt-4o`
- `anthropic:claude-sonnet-4-20250514`
- `google_genai:gemini-2.5-pro`

Uses LangChain's `init_chat_model()` for provider abstraction.

---

## Dependencies

**Core:**
- `deepagents>=0.4` — LangChain agent framework (planning, delegation)
- `rich>=13.0` — Terminal UI with markdown rendering
- `scrolls>=0.1.0` — Skill documentation loader
- `seer>=0.10.2` — PyO3 domain intelligence bindings
- `tome>=0.1.0` — PyO3 reference data bindings

**Optional LLM providers:**
- `ollama`: `langchain-ollama>=0.3`
- `openai`: `langchain-openai>=0.3`
- `anthropic`: `langchain-anthropic>=0.3`
- `google`: `langchain-google-genai>=4.0`
- `tracing`: `langsmith>=0.3`

**Requires Python 3.11+**

---

## Setup

```bash
# Create venv
python3 -m venv .venv && source .venv/bin/activate

# Install build tools and sibling projects
pip install maturin
pip install -e ../seer/seer-py -e ../tome/tome-py -e ../scrolls

# Install familiar with an LLM provider
pip install -e ".[ollama]"    # or [openai], [anthropic], [google], [all]

# Configure
cp .env.example .env
# Edit .env to set FAMILIAR_MODEL and API keys

# For Ollama: pull a model
ollama pull nemotron-3-nano:latest
```

---

## Key Implementation Details

- `.env` parsed manually line-by-line (no python-dotenv dependency)
- Scrolls documentation loaded once at startup, merged into system prompt
- Pydantic V1 deprecation warnings are filtered
- Tool results returned as JSON strings for LLM consumption
- REPL handles EOF/KeyboardInterrupt gracefully

---

## Extending

- **Add tools:** Create new file in `src/familiar/tools/`, add to `ALL_TOOLS` in `__init__.py`
- **Change LLM:** Set `FAMILIAR_MODEL` env var — no code changes needed
- **Customize prompt:** Modify `_build_system_prompt()` in `agent.py`
- **Adjust theme:** Edit `CATPPUCCIN` dict in `cli.py`
