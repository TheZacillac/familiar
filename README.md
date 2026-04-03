# Familiar

AI agent for domain intelligence, powered by [Deep Agents](https://github.com/langchain-ai/deepagents) and LangGraph.

Familiar wraps the domain tools from [Tower](../tower/) — giving you a conversational interface to investigate domains, DNS records, WHOIS/RDAP data, TLD information, and domain industry terminology. Built on LangChain's Deep Agents framework for planning, subagent delegation, and context management over long-running tasks. Skill documentation from [Scrolls](../scrolls/) is loaded into the agent's system prompt at startup, giving it detailed knowledge of each tool's capabilities.

## Setup

Install the project (seer and tome are built from sibling Rust/PyO3 projects):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
pip install -e ../seer/seer-py -e ../tome/tome-py -e ../scrolls
pip install -e .
```

Then install the extra for your chosen LLM provider:

```bash
pip install -e ".[ollama]"      # Local models via Ollama (default)
pip install -e ".[openai]"      # OpenAI API
pip install -e ".[anthropic]"   # Anthropic API
pip install -e ".[google]"      # Google Gemini API
pip install -e ".[all]"         # All providers
```

Copy `.env.example` to `.env` and configure your model:

```bash
cp .env.example .env
```

For local usage with Ollama, pull a model:

```bash
ollama pull nemotron-3-nano:latest
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

Set `FAMILIAR_MODEL` in `.env` using `provider:model` format:

| Provider | Example | Required env var |
|---|---|---|
| Ollama | `ollama:nemotron-3-nano:latest` | — |
| OpenAI | `openai:gpt-4o` | `OPENAI_API_KEY` |
| Anthropic | `anthropic:claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| Google | `google_genai:gemini-2.5-pro` | `GOOGLE_API_KEY` |

| Variable | Default | Description |
|---|---|---|
| `FAMILIAR_MODEL` | `ollama:nemotron-3-nano:latest` | LLM to use (must support tool calling) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL (only for ollama provider) |

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

## Tools (61 total)

### Seer — Domain Intelligence (20 tools)

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
| `seer_availability` | Domain registration availability check |
| `seer_subdomains` | Subdomain enumeration via Certificate Transparency |
| `seer_ssl` | SSL/TLS certificate details |
| `seer_dnssec` | DNSSEC validation status |
| `seer_dns_compare` | Compare DNS records between two nameservers |
| `seer_dns_follow` | Monitor DNS record changes over time |
| `seer_diff` | Side-by-side comparison of two domains |
| `seer_bulk_lookup` | Bulk RDAP/WHOIS lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |
| `seer_bulk_status` | Bulk health checks |
| `seer_bulk_propagation` | Bulk propagation checks |

### Tome — Reference Data (9 tools)

| Tool | Description |
|---|---|
| `tome_tld_lookup` | TLD information (type, registry, DNSSEC, restrictions) |
| `tome_tld_search` | Search TLDs by keyword |
| `tome_tld_overview` | Comprehensive TLD overview joining all related data |
| `tome_tld_list_by_type` | List TLDs by type (gTLD, ccTLD, nTLD) |
| `tome_tld_count` | Total TLD count in the database |
| `tome_record_lookup` | DNS record type details |
| `tome_record_search` | Search DNS record types |
| `tome_glossary_lookup` | Domain industry term definitions |
| `tome_glossary_search` | Search the glossary |

### Strategic Advisors (6 tools)

| Tool | Description |
|---|---|
| `appraise_domain` | Domain value appraisal with market analysis |
| `plan_acquisition` | Acquisition strategy for a target domain |
| `suggest_domains` | Generate and check domain name suggestions for a brand |
| `audit_portfolio` | Audit a portfolio of domains for risk and value |
| `competitive_intel` | Competitive intelligence report for a domain |
| `migration_preflight` | Pre-migration readiness assessment |

### Composite Advisors (6 tools)

| Tool | Description |
|---|---|
| `security_audit` | Comprehensive security audit of a domain |
| `brand_protection_scan` | Brand protection and typosquatting analysis |
| `dns_health_check` | DNS configuration health check |
| `domain_timeline` | Historical timeline of a domain |
| `expiration_alert` | Expiration risk assessment |
| `compare_security` | Compare security posture of two domains |

### Pentest — Security Scanning (7 tools)

| Tool | Description |
|---|---|
| `subdomain_takeover_scan` | Subdomain takeover vulnerability detection |
| `http_security_scan` | HTTP security header analysis |
| `email_security_audit` | Email authentication (SPF, DKIM, DMARC) deep dive |
| `ssl_deep_scan` | SSL/TLS configuration analysis |
| `dns_zone_security` | DNS zone security assessment |
| `infrastructure_recon` | Infrastructure reconnaissance |
| `exposure_report` | Unified exposure report aggregating all scans |

### Memory and Workflow (13 tools)

| Tool | Description |
|---|---|
| `remember_domain` | Save domain notes and tags to persistent notebook |
| `recall_domain` | Retrieve notes for a specific domain |
| `recall_all_domains` | List all remembered domains |
| `watchlist_add` | Add a domain to the monitoring watchlist |
| `watchlist_remove` | Remove a domain from the watchlist |
| `watchlist_list` | List all watchlisted domains |
| `watchlist_check` | Check current status of watchlisted domains |
| `set_explanation_mode` | Toggle verbose/brief explanation mode |
| `get_explanation_mode` | Check current explanation mode |
| `tag_search` | Search domain notes by tag |
| `create_report` | Generate a structured domain report |
| `compare_domains` | Compare multiple domains side by side |
| `session_summary` | Summarize the current session's findings |
