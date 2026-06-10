# CLAUDE.md - Familiar

Familiar is a conversational AI agent for domain intelligence, powered by LangChain's Deep Agents framework and LangGraph. It provides a natural language interface to Seer (domain diagnostics) and Tome (reference data).

---

## Architecture

```
familiar/
├── pyproject.toml
├── config.default.toml          # Default config — copy to ~/.familiar/config.toml
├── .env                         # Local environment overrides (gitignored)
├── .env.example                 # Environment template
├── .github/workflows/ci.yml     # CI: ruff + pytest (builds sibling PyO3 deps)
└── src/familiar/
    ├── __init__.py               # Version: 0.1.0
    ├── config.py                 # TOML config loader (~/.familiar/config.toml)
    ├── cli.py                    # CLI entry point (REPL + single-query + escalation routing)
    ├── cli_claude.py             # Alternative CLI on claude-agent-sdk
    ├── cli_common.py             # Engine-agnostic CLI primitives (slash commands, handlers)
    ├── agent.py                  # LangGraph Deep Agent builder (fast + power tiers)
    ├── agent_claude.py           # claude-agent-sdk agent builder
    ├── memory.py                 # SQLite persistence (domain notebook, watchlist, prefs)
    ├── findings.py               # Finding severity ordering/counting
    ├── seer_shape.py             # Anti-corruption layer over seer record shapes
    ├── email_auth.py             # Shared SPF/DMARC record parsers
    ├── utils.py                  # Shared utilities (safe_call, parallel_calls, try_ssl)
    └── tools/
        ├── __init__.py           # Exports ALL_TOOLS (76 total)
        ├── seer_tools.py         # 25 Seer tools (LangChain @tool wrappers)
        ├── tome_tools.py         # 10 Tome tools (LangChain @tool wrappers)
        ├── advisor_tools.py      # 12 Advisory tools (6 strategic + 6 composite)
        ├── pentest_tools.py      # 7 Pentest tools (security scanning composites)
        ├── security_tools.py     # 5 Security tools (DNSBL, AXFR, MTA-STS, DANE, fingerprint)
        ├── memory_tools.py       # 16 Memory + snapshot + workflow tools
        └── escalation_tools.py   # 1 Escalation tool (fast → power handoff)
```

---

## How It Works

### Agent Construction Flow (agent.py)

1. **`_load_env()`** — reads `.env` manually (no python-dotenv dependency), sets env vars with `setdefault`
2. **`_load_skill_docs()`** — uses `scrolls` to discover and load skill docs (cached per level; `agent.skill_docs_level` controls depth, default `minimal`)
3. **`_build_system_prompt()`** — base prompt ("You are Familiar...") + merged skill documentation
4. **`config.model_kwargs()`** — derives provider-specific kwargs (e.g. Ollama base_url) from the configured model id
5. **`build_agent()`** — `init_chat_model()` + `deepagents.create_deep_agent()` with all tools and system prompt, using the fast-tier model
6. **`build_power_agent()`** — same construction with the power-tier model and the `escalate` tool removed; the CLI invokes it when the fast model's `escalate` call appears in the stream (see `_run_power` in cli.py)

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

## Tools (76 total)

All wrapped with `@langchain_core.tools.tool`, return JSON strings. Seer surface tracks `seer>=0.25.0`. Record-shape access goes through `src/familiar/seer_shape.py` — never reach into seer record dicts directly.

### Seer Tools (25) — `seer_tools.py`

**Single (17):** `seer_lookup`, `seer_info`, `seer_whois`, `seer_rdap`, `seer_rdap_domain`, `seer_rdap_ip`, `seer_rdap_asn`, `seer_dig`, `seer_propagation`, `seer_status`, `seer_availability`, `seer_subdomains`, `seer_ssl`, `seer_dnssec`, `seer_dns_compare`, `seer_dns_follow`, `seer_diff`

**Bulk (8, max 100 domains):** `seer_bulk_lookup`, `seer_bulk_info`, `seer_bulk_whois`, `seer_bulk_dig`, `seer_bulk_status`, `seer_bulk_propagation`, `seer_bulk_ssl`, `seer_bulk_availability`

### Tome Tools (10) — `tome_tools.py`

`tome_tld_lookup`, `tome_tld_search`, `tome_tld_overview`, `tome_tld_list_by_type`, `tome_tld_count`, `tome_record_lookup`, `tome_record_search`, `tome_record_by_status`, `tome_glossary_lookup`, `tome_glossary_search`

### Strategic Advisor Tools (6) — `advisor_tools.py`

`appraise_domain`, `plan_acquisition`, `suggest_domains`, `audit_portfolio`, `competitive_intel`, `migration_preflight`

### Composite Advisor Tools (6) — `advisor_tools.py`

`security_audit`, `brand_protection_scan`, `dns_health_check`, `domain_timeline`, `expiration_alert`, `compare_security`

### Pentest Tools (7) — `pentest_tools.py`

`subdomain_takeover_scan`, `http_security_scan`, `email_security_audit`, `ssl_deep_scan`, `dns_zone_security`, `infrastructure_recon`, `exposure_report`

### Security Tools (5) — `security_tools.py`

`domain_reputation_check` (DNSBL), `zone_transfer_test` (AXFR), `mta_sts_check`, `dane_tlsa_check`, `website_fingerprint`

### Memory Tools (9) — `memory_tools.py`

**Domain notebook:** `remember_domain`, `recall_domain`, `recall_all_domains`

**Watchlist:** `watchlist_add`, `watchlist_remove`, `watchlist_list`, `watchlist_check`

**Preferences:** `set_explanation_mode`, `get_explanation_mode`

### Snapshot Tools (3) — `memory_tools.py`

`snapshot_domain`, `diff_snapshots`, `list_domain_snapshots`

### Workflow Tools (4) — `memory_tools.py`

`tag_search`, `create_report`, `compare_domains`, `session_summary`

### Escalation Tools (1) — `escalation_tools.py`

`escalate` (delegate to a heavier-weight reasoning model)

---

## Configuration

### Config file (`~/.familiar/config.toml`)

Primary configuration via TOML. Copy `config.default.toml` to `~/.familiar/config.toml` and edit. See `config.default.toml` for all options with comments. Override the config file path with `FAMILIAR_CONFIG` env var.

Sections: `[model]`, `[model.ollama]`, `[storage]`, `[agent]`, `[tracing]`, `[theme]`

### Environment Variables

Env vars override config file values for backward compatibility.

| Variable | Config equivalent | Default | Purpose |
|----------|-------------------|---------|---------|
| `FAMILIAR_MODEL` | `model.default` | `ollama:nemotron-3-nano:latest` | LLM in `provider:model` format |
| `FAMILIAR_MODEL_FAST` | `model.fast` | — | Fast-tier model (falls back to `model.default`) |
| `FAMILIAR_MODEL_POWER` | `model.power` | — | Power-tier model for `escalate` handoffs |
| `OLLAMA_BASE_URL` | `model.ollama.base_url` | `http://localhost:11434` | Ollama server URL |
| `FAMILIAR_DATA_DIR` | `storage.data_dir` | `~/.familiar` | Base data directory |
| `FAMILIAR_DB_NAME` | `storage.db_name` | `familiar.db` | SQLite database filename |
| `FAMILIAR_EXPORT_DIR` | `storage.export_dir` | `~/.familiar/exports` | Export output directory |
| `FAMILIAR_MAX_WORKERS` | `agent.max_workers` | `32` | Parallel thread pool size |
| `OPENAI_API_KEY` | — | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | — | Anthropic API key |
| `GOOGLE_API_KEY` | — | — | Google Gemini API key |
| `LANGSMITH_TRACING` | `tracing.enabled` | `false` | Enable LangSmith observability |
| `LANGSMITH_API_KEY` | `tracing.api_key` | — | LangSmith auth key |
| `LANGSMITH_PROJECT` | `tracing.project` | `familiar` | LangSmith project name |

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
- `seer>=0.24.0` — PyO3 domain intelligence bindings
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
