# Familiar

AI agent for domain intelligence, powered by [Deep Agents](https://github.com/langchain-ai/deepagents), LangGraph, and Ollama.

Familiar wraps the domain tools from [Tower](../tower/) — giving you a conversational interface to investigate domains, DNS records, WHOIS/RDAP data, TLD information, and domain industry terminology. Built on LangChain's Deep Agents framework for planning, subagent delegation, and context management over long-running tasks.

## Setup

Requires [Ollama](https://ollama.com/) running locally with a model pulled:

```bash
ollama pull nemotron-3-nano:latest
```

Install the project (seer and tome are built from sibling Rust/PyO3 projects):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
pip install -e ../seer/seer-py -e ../tome/tome-py
pip install -e .
```

Copy `.env.example` to `.env` and adjust if needed:

```bash
cp .env.example .env
```

## Usage

Interactive mode:

```bash
familiar
```

Single query:

```bash
familiar "who owns google.com"
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_MODEL` | `nemotron-3-nano:latest` | Ollama model to use (must support tool calling) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |

## Observability (optional)

Agent runs can be traced via [LangSmith](https://smith.langchain.com/). Install the optional dependency:

```bash
pip install -e ".[tracing]"
```

Then enable tracing in `.env`:

| Variable | Default | Description |
|---|---|---|
| `LANGSMITH_TRACING` | `false` | Set to `true` to enable LangSmith tracing |
| `LANGSMITH_API_KEY` | | Your LangSmith API key |
| `LANGSMITH_PROJECT` | `familiar` | LangSmith project name |

Traces include every LLM call, tool invocation, and agent step. Tracing is disabled by default and requires both the extra install and a valid API key.

## Tools

### Seer — Domain Intelligence

| Tool | Description |
|---|---|
| `seer_lookup` | Smart RDAP-first lookup with WHOIS fallback |
| `seer_whois` | WHOIS registration data |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP address lookup |
| `seer_rdap_asn` | RDAP Autonomous System Number lookup |
| `seer_dig` | DNS record queries |
| `seer_propagation` | DNS propagation across global nameservers |
| `seer_status` | Domain health check (HTTP, SSL, expiration) |
| `seer_bulk_lookup` | Bulk RDAP/WHOIS lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |
| `seer_bulk_status` | Bulk health checks |
| `seer_bulk_propagation` | Bulk propagation checks |

### Tome — Reference Data

| Tool | Description |
|---|---|
| `tome_tld_lookup` | TLD information (type, registry, DNSSEC, restrictions) |
| `tome_tld_search` | Search TLDs by keyword |
| `tome_record_lookup` | DNS record type details |
| `tome_record_search` | Search DNS record types |
| `tome_glossary_lookup` | Domain industry term definitions |
| `tome_glossary_search` | Search the glossary |
