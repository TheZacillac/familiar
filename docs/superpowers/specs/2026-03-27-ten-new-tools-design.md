# Ten New Tools for Familiar

**Date:** 2026-03-27
**Status:** Approved
**Scope:** Add 11 new LangChain tools, 1 utility function, 1 CLI subcommand

---

## Summary

Familiar currently has 61 tools covering domain diagnostics, security scanning, advisory intelligence, and memory. This spec adds 10 capabilities that fill gaps between "tool I query" and "advisor that watches my domains for me":

1. Scheduled watchlist monitoring (daemon)
2. DNS change history tracker
3. Structured report export (JSON, CSV)
4. Portfolio comparison matrix
5. Tool result validator
6. Conversation context summary
7. RFC/standards reference lookup
8. RDAP auto-detect wrapper
9. DNS record type status filter
10. Webhook configuration

After implementation, Familiar will have 72 tools (61 existing + 11 new).

---

## Decisions

| Question | Answer |
|----------|--------|
| Daemon model | Separate `familiar watch` CLI subcommand (long-running process) |
| Notification channels | Generic webhook POST only (covers Slack, Discord, ntfy, custom) |
| DNS history storage | Same SQLite database (`~/.familiar/familiar.db`), new table |
| Export formats | JSON + CSV (no new dependencies) |
| RFC retrieval method | Keyword search over scrolls docs (no vector store) |

---

## File Layout

```
src/familiar/
  monitoring.py              NEW   Daemon, scheduler, webhook sender
  reference.py               NEW   RFC/standards keyword index + search
  tools/
    monitoring_tools.py      NEW   @tool wrappers: watchlist_auto_check, dns_history,
                                   dns_snapshot, configure_webhook, get_webhook
    export_tools.py          NEW   @tool wrappers: export_report
    reference_tools.py       NEW   @tool wrappers: reference_lookup
    seer_tools.py            EXT   Add seer_rdap_auto
    tome_tools.py            EXT   Add tome_record_by_status
    advisor_tools.py         EXT   Add compare_portfolio_matrix
    memory_tools.py          EXT   Add context_summary
    __init__.py              EXT   Register new tool lists
  cli.py                     EXT   Add `familiar watch` subcommand
  memory.py                  EXT   Add dns_snapshots table + methods
```

New files: 5. Extended files: 7. No existing code moved or refactored.

---

## Database Schema Extension

Added to `memory.py` `_init_schema()`:

```sql
CREATE TABLE IF NOT EXISTS dns_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    source TEXT DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_dns_snapshots_domain
    ON dns_snapshots(domain, record_type, captured_at);
```

New `Memory` methods:

- `save_dns_snapshot(domain, record_type, records, source)` -- serialize records as JSON, store with UTC timestamp
- `get_dns_history(domain, record_type=None, limit=50)` -- return snapshots newest-first, optionally filtered by record type
- `get_dns_diff(domain, record_type)` -- compare the two most recent snapshots, return `{added, removed, unchanged}`
- `prune_dns_history(days=90)` -- delete snapshots older than threshold

Thread safety: same `self._lock` pattern as existing methods.

---

## Tool 1: Scheduled Watchlist Monitoring

### monitoring.py -- FamiliarDaemon

```python
class FamiliarDaemon:
    def __init__(self, interval_hours=6, webhook_url=None):
        self._interval = interval_hours * 3600
        self._webhook_url = webhook_url
        self._running = False
        self._memory = Memory()

    def run(self):
        """Main loop: check -> notify -> sleep -> repeat."""
        self._running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        while self._running:
            alerts = self.check_once()
            if alerts and self._webhook_url:
                self._notify(alerts)
            self._sleep_interruptible(self._interval)

    def check_once(self) -> list[dict]:
        """Single watchlist check cycle."""
        # 1. Load watchlist from Memory
        # 2. seer.bulk_status + seer.bulk_lookup
        # 3. Snapshot DNS (A, MX, NS, TXT) for each domain -> save_dns_snapshot
        # 4. Diff against previous snapshots -> detect changes
        # 5. Evaluate alerts: expiration, SSL, HTTP, DNS changes
        # 6. Update watchlist_update_status with results
        # 7. Return alert list

    def _notify(self, alerts):
        """HTTP POST to webhook URL."""
        # Uses urllib.request (no dependency) with timeout
        # Payload: {source, timestamp, alerts[], summary}

    def _sleep_interruptible(self, seconds):
        """Sleep in 1-second increments so SIGINT is responsive."""

    def _handle_signal(self, signum, frame):
        self._running = False

    def stop(self):
        self._running = False
        self._memory.close()
```

### cli.py -- subcommand

```
familiar watch                    # daemon, 6h default
familiar watch --interval 1h     # custom interval (supports h/m suffixes)
familiar watch --once             # single check, then exit
familiar watch --webhook URL      # override webhook for this session
```

Parsing: extend `main()` to check `sys.argv[1] == "watch"` before the existing REPL/single-query branch. Parse remaining args with simple string matching (consistent with existing cli.py style -- no argparse).

Output: Rich status line showing last check time, next check time, alert count.

---

## Tool 2: DNS Change History

### monitoring_tools.py -- dns_history

```python
@tool
def dns_history(domain: str, record_type: str = "A") -> str:
    """Show DNS record history for a domain. Returns past snapshots and
    a diff showing what changed between the two most recent captures."""
```

- Calls `Memory.get_dns_history(domain, record_type, limit=20)`
- Calls `Memory.get_dns_diff(domain, record_type)`
- Returns JSON:

```json
{
  "domain": "example.com",
  "record_type": "A",
  "snapshots": [
    {"captured_at": "2026-03-27T14:00:00Z", "records": [...], "source": "daemon"},
    {"captured_at": "2026-03-26T08:00:00Z", "records": [...], "source": "manual"}
  ],
  "changes": {
    "added": ["93.184.216.35"],
    "removed": ["93.184.216.34"],
    "unchanged": []
  },
  "total_snapshots": 12
}
```

### monitoring_tools.py -- dns_snapshot (manual capture)

```python
@tool
def dns_snapshot(domain: str, record_types: str = "A,MX,NS,TXT") -> str:
    """Capture a DNS snapshot for a domain. Stores current records for later
    comparison via dns_history."""
```

- Splits record_types by comma
- Calls `seer.dig(domain, rt)` for each type via `parallel_calls`
- Stores each via `Memory.save_dns_snapshot(domain, rt, records, "manual")`
- Returns confirmation JSON with record counts

---

## Tool 3: Structured Report Export

### export_tools.py -- export_report

```python
@tool
def export_report(title: str, sections: str, format: str = "json") -> str:
    """Export a report as structured data. Pass sections as a JSON string
    of [{heading, content}, ...]. Format: 'json' or 'csv'."""
```

- Parses sections JSON (same format as `create_report`)
- If format == "json": returns `{"title", "timestamp", "sections": [{heading, content}]}`
- If format == "csv": returns CSV string with columns `Section,Content` using stdlib `csv.StringIO`
- Invalid format: returns `{"error": "..."}`

---

## Tool 4: Portfolio Comparison Matrix

### advisor_tools.py -- compare_portfolio_matrix

```python
@tool
def compare_portfolio_matrix(domains: str) -> str:
    """Compare up to 20 domains in a matrix showing registrar, nameservers,
    SSL issuer, SSL expiry, HTTP status, SPF, and DMARC for each."""
```

- Parse comma-separated domains string, cap at 20
- Fan out: `seer.bulk_lookup` + `seer.bulk_status` + parallel `seer.dig` for TXT, MX, `_dmarc.` TXT
- Build per-domain row dict:
  - `registrar` (from _extract_registration)
  - `nameservers` (from lookup)
  - `ssl_issuer`, `ssl_expiry_days` (from status certificate)
  - `http_status` (from status)
  - `has_spf` (scan TXT for v=spf1)
  - `has_dmarc` (scan _dmarc TXT for v=DMARC1)
- Collect `warnings` for critical issues (SSL <30d, no SPF with MX, HTTP unreachable)

Output:
```json
{
  "domains": ["a.com", "b.com"],
  "columns": ["registrar", "nameservers", "ssl_issuer", "ssl_expiry_days",
              "http_status", "has_spf", "has_dmarc"],
  "rows": [{"domain": "a.com", "registrar": "Cloudflare", ...}],
  "warnings": ["b.com: SSL expires in 12 days"]
}
```

---

## Tool 5: Tool Result Validator

### utils.py -- validate_tool_result

```python
def validate_tool_result(result: str) -> str:
    """Verify a tool result is valid JSON. Replace malformed output with
    a clean error dict. Returns the original string if valid."""
    try:
        json.loads(result)
        return result
    except (json.JSONDecodeError, TypeError):
        return json.dumps({"error": "Tool returned malformed output",
                           "raw_preview": result[:200] if isinstance(result, str) else str(result)[:200]})
```

Applied as a wrapper in the tools most prone to complex output:

```python
# In the tool function body, before return:
return validate_tool_result(json.dumps(output, default=str))
```

Applied to: `exposure_report`, `audit_portfolio`, `compare_security`, `compare_portfolio_matrix`, `watchlist_auto_check`.

---

## Tool 6: Conversation Context Summary

### memory_tools.py -- context_summary

```python
@tool
def context_summary() -> str:
    """Summarize domains discussed and watchlist state for maintaining
    conversation coherence in long sessions."""
```

- Calls `Memory.recall_all_domains()` -- list with notes/tags
- Calls `Memory.watchlist_list()` -- watched domains with last status
- Calls `Memory.get_preference("explanation_mode")`
- Returns condensed JSON:

```json
{
  "domains_discussed": 5,
  "recent_domains": [{"domain": "a.com", "tags": "ssl,dns", "last_seen": "..."}],
  "watchlist_count": 3,
  "watchlist_domains": ["a.com", "b.com", "c.com"],
  "explanation_mode": false
}
```

The system prompt instructs the agent to call this when the conversation feels long or when context seems lost.

---

## Tool 7: RFC/Standards Reference Lookup

### reference.py -- ReferenceIndex

```python
class ReferenceIndex:
    """Keyword index over scrolls SKILL.md and reference docs."""

    def __init__(self):
        self._sections: list[dict] = []  # {title, content, source_file, keywords}

    def build(self):
        """Scan scrolls skill dirs, split into sections by ## headings,
        extract keywords from headings and content."""

    def search(self, query: str, limit: int = 5) -> list[dict]:
        """Score sections by keyword overlap with query terms.
        Returns [{title, content, source_file, score}]."""
```

Index built once at import time (same pattern as `_load_skill_docs` in agent.py).

### monitoring_tools.py -- reference_lookup

```python
@tool
def reference_lookup(query: str) -> str:
    """Search domain industry reference docs for a topic. Covers RFCs,
    DNS standards, email authentication, TLD policies, and security
    best practices."""
```

- Calls `ReferenceIndex.search(query, limit=5)`
- Returns JSON with matching sections, source files, and relevance scores

---

## Tool 8: RDAP Auto-Detect

### seer_tools.py -- seer_rdap_auto

```python
@tool
def seer_rdap_auto(query: str) -> str:
    """Auto-detect RDAP lookup type. Accepts a domain name, IP address,
    or ASN number and routes to the appropriate RDAP endpoint."""
```

- Calls `seer.rdap(query)`
- Returns JSON result or `{"error": "..."}`
- Follows existing seer_tools pattern exactly (try/except, json.dumps, logging)

---

## Tool 9: DNS Record Type Status Filter

### tome_tools.py -- tome_record_by_status

```python
@tool
def tome_record_by_status(status: str) -> str:
    """List DNS record types by status. Valid statuses: 'standard',
    'experimental', 'deprecated', 'obsolete'."""
```

- Calls `tome.record_by_status(status)`
- Returns JSON list or `{"error": "..."}`
- Follows existing tome_tools pattern exactly

---

## Tool 10: Webhook Configuration

### monitoring_tools.py -- configure_webhook / get_webhook

```python
@tool
def configure_webhook(url: str) -> str:
    """Set the webhook URL for watchlist monitoring alerts. Accepts any
    HTTP/HTTPS endpoint (Slack, Discord, ntfy, custom)."""

@tool
def get_webhook() -> str:
    """Check the currently configured webhook URL."""
```

- `configure_webhook`: validates URL starts with `http://` or `https://`, stores in `Memory.set_preference("webhook_url", url)`, sends a test ping with `{"source": "familiar", "test": true}`
- `get_webhook`: reads `Memory.get_preference("webhook_url")`
- Webhook payload format (used by daemon and watchlist_auto_check):

```json
{
  "source": "familiar",
  "timestamp": "2026-03-27T14:00:00Z",
  "alerts": [
    {"domain": "example.com", "type": "expiration", "severity": "critical",
     "message": "Expires in 5 days"}
  ],
  "summary": "2 domains checked, 1 alert"
}
```

---

## Tool Registration

### tools/__init__.py update

```python
from .monitoring_tools import MONITORING_TOOLS
from .export_tools import EXPORT_TOOLS
from .reference_tools import REFERENCE_TOOLS

ALL_TOOLS = (SEER_TOOLS + TOME_TOOLS + ADVISOR_TOOLS + COMPOSITE_ADVISOR_TOOLS
             + PENTEST_TOOLS + MEMORY_TOOLS + WORKFLOW_TOOLS
             + MONITORING_TOOLS + EXPORT_TOOLS + REFERENCE_TOOLS)
```

New tool lists:
- `MONITORING_TOOLS`: watchlist_auto_check, dns_history, dns_snapshot, configure_webhook, get_webhook
- `EXPORT_TOOLS`: export_report
- `REFERENCE_TOOLS`: reference_lookup

Extended lists:
- `SEER_TOOLS` += seer_rdap_auto (21 total)
- `TOME_TOOLS` += tome_record_by_status (10 total)
- `ADVISOR_TOOLS` += compare_portfolio_matrix (7 total)
- `WORKFLOW_TOOLS` += context_summary (5 total)

Final count: 72 tools (61 + 11 new @tool functions).

---

## System Prompt Update

Add to SYSTEM_PROMPT in agent.py:

```
**Monitoring:** Check watchlist health on demand, track DNS record changes over time,
configure webhook alerts for ongoing monitoring, and summarize conversation context.
**Reference:** Look up RFC standards, DNS protocol details, and industry best practices
from the built-in reference library.
**Export:** Generate structured reports in JSON or CSV format for integration with
external tools. Compare domain portfolios in matrix format.
```

Add to slash commands in cli.py:
```python
"/history": "Show DNS change history for {args}. Use dns_history to display snapshots and diffs.",
"/snapshot": "Capture a DNS snapshot of {args}. Use dns_snapshot to record current state.",
"/webhook": "Configure webhook alerts: {args}. Use configure_webhook.",
"/matrix": "Compare domains in a matrix: {args}. Use compare_portfolio_matrix.",
"/ref": "Look up a domain industry topic: {args}. Use reference_lookup.",
```

---

## Dependencies

**No new dependencies.** All implementations use:
- `urllib.request` for webhook HTTP POST (stdlib)
- `csv` + `io.StringIO` for CSV export (stdlib)
- `signal` for daemon signal handling (stdlib)
- `threading.Event` for interruptible sleep (stdlib)
- Existing `seer`, `tome`, `scrolls`, `rich` dependencies

---

## Testing Strategy

Each new tool gets:
- Happy path test (mock seer/tome, verify JSON output structure)
- Error/None handling test (graceful degradation)
- Edge case tests (empty input, normalization)

New test files:
- `tests/test_monitoring.py` -- FamiliarDaemon, check_once, webhook sending
- `tests/test_monitoring_tools.py` -- dns_history, dns_snapshot, watchlist_auto_check, configure_webhook
- `tests/test_export_tools.py` -- export_report JSON + CSV
- `tests/test_reference.py` -- ReferenceIndex build + search

Extended test files:
- `tests/test_advisor_tools.py` += compare_portfolio_matrix tests
- `tests/test_remaining_wrappers.py` += seer_rdap_auto, tome_record_by_status
- `tests/test_memory_tool_wrappers.py` += context_summary
- `tests/test_memory_notebook.py` += dns snapshot Memory methods
- `tests/test_cli_handlers.py` += watch subcommand parsing
