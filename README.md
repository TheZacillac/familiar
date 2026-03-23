# Familiar

AI agent for domain intelligence, powered by LangGraph and Ollama.

Familiar wraps the domain tools from [Tower](../tower/) — giving you a conversational interface to investigate domains, DNS records, WHOIS/RDAP data, TLD information, and domain industry terminology.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e . --find-links ../seer/seer-py --find-links ../tome/tome-py
```

Copy `.env.example` to `.env` and adjust if needed:

```bash
cp .env.example .env
```

Requires [Ollama](https://ollama.com/) running locally with a model pulled:

```bash
ollama pull qwen2.5:latest
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
| `OLLAMA_MODEL` | `qwen2.5:latest` | Ollama model to use |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |

## Observability (optional)

Agent runs can be traced via [LangSmith](https://smith.langchain.com/). Install the optional dependency:

```bash
pip install -e ".[tracing]" --find-links ../seer/seer-py --find-links ../tome/tome-py
```

Then set the following in `.env`:

| Variable | Default | Description |
|---|---|---|
| `LANGSMITH_TRACING` | `true` | Enable LangSmith tracing |
| `LANGSMITH_API_KEY` | | Your LangSmith API key |
| `LANGSMITH_PROJECT` | `familiar` | LangSmith project name |

Traces include every LLM call, tool invocation, and agent step. Without the extra install, the agent runs normally with no tracing.

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
