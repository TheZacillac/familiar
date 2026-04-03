# Familiar Agent — 8 New Tool Capabilities

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 new tool capabilities to the Familiar domain intelligence agent — filling gaps in bulk availability, domain reputation, website fingerprinting, zone transfer testing, email transport security, DANE validation, structured change tracking, and tome record filtering.

**Architecture:** New tools follow existing patterns exactly — `@tool` decorated functions returning `json.dumps(result, default=str)`, using `parallel_calls()` for concurrency and `safe_call()` for fault tolerance. One Rust/PyO3 change (bulk_availability in seer-py), the rest are pure Python in familiar's tools package. The Memory class gets a new `domain_snapshots` table for structured change tracking.

**Tech Stack:** Python 3.11+, LangChain `@tool` decorator, seer (PyO3 bindings), tome (PyO3 bindings), SQLite (via familiar's Memory class), Rust/PyO3 (seer-py only), `socket` stdlib (AXFR), `urllib.request` stdlib (MTA-STS HTTP fetch)

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `seer/seer-py/src/lib.rs` | Add `bulk_availability` PyO3 function |
| Modify | `seer/seer-py/python/seer/__init__.py` | Export `bulk_availability` |
| Modify | `familiar/src/familiar/tools/seer_tools.py` | Add `seer_bulk_availability` tool wrapper |
| Modify | `familiar/src/familiar/tools/tome_tools.py` | Add `tome_record_by_status` tool wrapper |
| Create | `familiar/src/familiar/tools/security_tools.py` | 5 new security tools: `domain_reputation_check`, `zone_transfer_test`, `mta_sts_check`, `dane_tlsa_check`, `website_fingerprint` |
| Modify | `familiar/src/familiar/memory.py` | Add `domain_snapshots` table + snapshot/diff methods |
| Modify | `familiar/src/familiar/tools/memory_tools.py` | Add `snapshot_domain`, `diff_snapshots` tools + SNAPSHOT_TOOLS list |
| Modify | `familiar/src/familiar/tools/__init__.py` | Import and register new tool lists |
| Create | `familiar/tests/test_bulk_availability_wrapper.py` | Tests for seer_bulk_availability |
| Create | `familiar/tests/test_tome_record_by_status.py` | Tests for tome_record_by_status |
| Create | `familiar/tests/test_security_tools.py` | Tests for all 5 security tools |
| Create | `familiar/tests/test_memory_snapshots.py` | Tests for Memory snapshot/diff methods |
| Create | `familiar/tests/test_snapshot_tool_wrappers.py` | Tests for snapshot_domain, diff_snapshots tool wrappers |

---

## Task 1: Bulk Availability — Seer PyO3 Binding

Expose seer-core's existing `BulkOperation::Avail` through seer-py so Python consumers can check availability for many domains concurrently.

**Files:**
- Modify: `seer/seer-py/src/lib.rs:378` (after `bulk_status`)
- Modify: `seer/seer-py/src/lib.rs:600` (module registration)
- Modify: `seer/seer-py/python/seer/__init__.py:27-81` (import + `__all__`)

- [ ] **Step 1: Add `bulk_availability` function to lib.rs**

Insert after the `bulk_status` function (after line 378):

```rust
#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_availability(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Avail { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}
```

- [ ] **Step 2: Register in the pymodule**

In the `_seer` module function, add after the `bulk_status` registration (after line 600):

```rust
    m.add_function(wrap_pyfunction!(bulk_availability, m)?)?;
```

- [ ] **Step 3: Export from Python `__init__.py`**

In `seer/seer-py/python/seer/__init__.py`, add `bulk_availability` to the import block (line 27-48) and the `__all__` list (line 60-81).

Add to the `from seer._seer import (...)` block after `bulk_status`:
```python
    bulk_availability,
```

Add to `__all__` after `"bulk_status"`:
```python
    "bulk_availability",
```

- [ ] **Step 4: Build and verify**

```bash
cd /home/zac/Projects/arcanum_suite/seer/seer-py && maturin develop --release
```

Then verify the function is importable:
```bash
python -c "import seer; print(hasattr(seer, 'bulk_availability'))"
```

Expected: `True`

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/seer
git add seer-py/src/lib.rs seer-py/python/seer/__init__.py
git commit -m "feat: expose bulk_availability in PyO3 bindings"
```

---

## Task 2: Bulk Availability — Familiar Tool Wrapper

Wrap the new `seer.bulk_availability` as a LangChain tool.

**Files:**
- Modify: `familiar/src/familiar/tools/seer_tools.py` (add tool at end, before SEER_TOOLS list)
- Test: `familiar/tests/test_bulk_availability_wrapper.py`

- [ ] **Step 1: Write the failing test**

Create `familiar/tests/test_bulk_availability_wrapper.py`:

```python
import json
from unittest.mock import patch

from familiar.tools.seer_tools import seer_bulk_availability


class TestSeerBulkAvailability:
    """Tests for the seer_bulk_availability tool wrapper."""

    @patch("familiar.tools.seer_tools.seer")
    def test_returns_availability_results(self, mock_seer):
        mock_seer.bulk_availability.return_value = [
            {
                "operation": {"Avail": {"domain": "fresh-startup.com"}},
                "success": True,
                "data": {"domain": "fresh-startup.com", "available": True, "confidence": "high", "method": "rdap"},
                "error": None,
                "duration_ms": 312,
            },
            {
                "operation": {"Avail": {"domain": "google.com"}},
                "success": True,
                "data": {"domain": "google.com", "available": False, "confidence": "high", "method": "rdap"},
                "error": None,
                "duration_ms": 205,
            },
        ]
        result = json.loads(seer_bulk_availability.invoke({"domains": '["fresh-startup.com", "google.com"]'}))
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["data"]["available"] is True
        assert result[1]["data"]["available"] is False

    @patch("familiar.tools.seer_tools.seer")
    def test_passes_concurrency(self, mock_seer):
        mock_seer.bulk_availability.return_value = []
        seer_bulk_availability.invoke({"domains": '["a.com"]', "concurrency": "5"})
        mock_seer.bulk_availability.assert_called_once_with(["a.com"], 5)

    @patch("familiar.tools.seer_tools.seer")
    def test_error_returns_json(self, mock_seer):
        mock_seer.bulk_availability.side_effect = RuntimeError("bulk fail")
        result = json.loads(seer_bulk_availability.invoke({"domains": '["fail.com"]'}))
        assert "error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_bulk_availability_wrapper.py -v
```

Expected: FAIL with `ImportError` (function doesn't exist yet)

- [ ] **Step 3: Implement the tool**

Add to `familiar/src/familiar/tools/seer_tools.py`, before the `SEER_TOOLS` list:

```python
@tool
def seer_bulk_availability(domains: str, concurrency: int = 10) -> str:
    """Check domain registration availability in bulk. Pass domains as a JSON list
    of strings. Each result includes available (bool), confidence level, and check
    method. Uses concurrent RDAP/WHOIS checks for speed."""
    logger.debug("seer_bulk_availability called: concurrency=%d", concurrency)
    try:
        domain_list = json.loads(domains) if isinstance(domains, str) else domains
        return json.dumps(seer.bulk_availability(domain_list, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

Add `seer_bulk_availability` to the `SEER_TOOLS` list at the end.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_bulk_availability_wrapper.py -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/seer_tools.py tests/test_bulk_availability_wrapper.py
git commit -m "feat: add seer_bulk_availability tool wrapper"
```

---

## Task 3: Tome Record By Status

Wrap the already-exported `tome.record_by_status()` as a LangChain tool.

**Files:**
- Modify: `familiar/src/familiar/tools/tome_tools.py` (add tool + update TOME_TOOLS)
- Test: `familiar/tests/test_tome_record_by_status.py`

- [ ] **Step 1: Write the failing test**

Create `familiar/tests/test_tome_record_by_status.py`:

```python
import json
from unittest.mock import patch

from familiar.tools.tome_tools import tome_record_by_status


class TestTomeRecordByStatus:
    """Tests for the tome_record_by_status tool wrapper."""

    @patch("familiar.tools.tome_tools.tome")
    def test_returns_matching_records(self, mock_tome):
        mock_tome.record_by_status.return_value = [
            {"name": "A", "type_code": 1, "status": "Active"},
            {"name": "AAAA", "type_code": 28, "status": "Active"},
        ]
        result = json.loads(tome_record_by_status.invoke({"status": "Active"}))
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "A"

    @patch("familiar.tools.tome_tools.tome")
    def test_empty_result(self, mock_tome):
        mock_tome.record_by_status.return_value = []
        result = json.loads(tome_record_by_status.invoke({"status": "Experimental"}))
        assert result == []

    @patch("familiar.tools.tome_tools.tome")
    def test_error_returns_json(self, mock_tome):
        mock_tome.record_by_status.side_effect = RuntimeError("db error")
        result = json.loads(tome_record_by_status.invoke({"status": "Active"}))
        assert "error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_tome_record_by_status.py -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement the tool**

Add to `familiar/src/familiar/tools/tome_tools.py`, before the `TOME_TOOLS` list:

```python
@tool
def tome_record_by_status(status: str) -> str:
    """Filter DNS record types by IANA status. Valid statuses: 'Active', 'Experimental', 'Obsolete', 'Reserved'. Returns all record types matching the given status."""
    logger.debug("tome_record_by_status called: status=%s", status)
    try:
        return json.dumps(tome.record_by_status(status), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

Add `tome_record_by_status` to the `TOME_TOOLS` list.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_tome_record_by_status.py -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/tome_tools.py tests/test_tome_record_by_status.py
git commit -m "feat: add tome_record_by_status tool wrapper"
```

---

## Task 4: Security Tools Module — Scaffold + Domain Reputation

Create a new tool module for the 5 security tools. Start with the domain reputation/blocklist checker.

**Files:**
- Create: `familiar/src/familiar/tools/security_tools.py`
- Create: `familiar/tests/test_security_tools.py`

- [ ] **Step 1: Write the failing test for domain_reputation_check**

Create `familiar/tests/test_security_tools.py`:

```python
import json
from unittest.mock import patch

from familiar.tools.security_tools import domain_reputation_check


def _mock_dig_for_blocklist(domain, record_type="A", nameserver=None):
    """Simulate DNS responses for blocklist queries."""
    # Spamhaus returns 127.0.0.2 for listed domains
    if "zen.spamhaus.org" in domain:
        return [{"data": {"address": "127.0.0.2"}, "record_type": "A"}]
    # Other blocklists return empty
    return []


class TestDomainReputationCheck:
    """Tests for the domain_reputation_check tool."""

    @patch("familiar.tools.security_tools.seer")
    def test_clean_domain(self, mock_seer):
        mock_seer.dig.return_value = []  # No blocklist hits
        result = json.loads(domain_reputation_check.invoke({"domain": "clean-example.com"}))
        assert result["domain"] == "clean-example.com"
        assert result["listed_count"] == 0
        assert result["overall_status"] == "clean"
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) > 0

    @patch("familiar.tools.security_tools.seer")
    def test_listed_domain(self, mock_seer):
        def _dig_side_effect(query, record_type="A", nameserver=None):
            if "zen.spamhaus.org" in query:
                return [{"data": {"address": "127.0.0.2"}, "record_type": "A"}]
            if "dbl.spamhaus.org" in query:
                return [{"data": {"address": "127.0.1.2"}, "record_type": "A"}]
            return []
        mock_seer.dig.side_effect = _dig_side_effect
        result = json.loads(domain_reputation_check.invoke({"domain": "bad-actor.com"}))
        assert result["listed_count"] >= 1
        assert result["overall_status"] == "listed"
        listed = [c for c in result["checks"] if c["listed"]]
        assert len(listed) >= 1

    @patch("familiar.tools.security_tools.seer")
    def test_error_returns_json(self, mock_seer):
        mock_seer.dig.side_effect = RuntimeError("DNS fail")
        result = json.loads(domain_reputation_check.invoke({"domain": "fail.com"}))
        assert result["domain"] == "fail.com"
        # Should handle errors gracefully per-blocklist, not crash entirely
        assert "checks" in result
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestDomainReputationCheck -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement domain_reputation_check**

Create `familiar/src/familiar/tools/security_tools.py`:

```python
"""Security analysis tools for domain reputation, transport security, and zone hardening.

These tools extend Familiar's pentest capabilities with blocklist checking,
zone transfer testing, MTA-STS/TLS-RPT validation, DANE/TLSA verification,
and website technology fingerprinting.
"""

import json
import re
import socket
import struct

import seer
from langchain_core.tools import tool

from ..utils import parallel_calls, safe_call

# --- DNS-based blocklist providers ---
# Each entry: (name, zone_suffix, query_type, description)
# query_type: "ip" means reverse the IP octets, "domain" means prepend the domain directly
_BLOCKLISTS = [
    ("Spamhaus ZEN", "zen.spamhaus.org", "ip", "Combined Spamhaus IP blocklist (SBL+XBL+PBL)"),
    ("Spamhaus DBL", "dbl.spamhaus.org", "domain", "Spamhaus Domain Block List"),
    ("SURBL", "multi.surbl.org", "domain", "Spam URI Realtime Blocklist"),
    ("URIBL", "multi.uribl.com", "domain", "URI-based blocklist"),
    ("Barracuda", "b.barracudacentral.org", "ip", "Barracuda Reputation Block List"),
    ("SpamCop", "bl.spamcop.net", "ip", "SpamCop Blocking List"),
    ("CBL", "cbl.abuseat.org", "ip", "Composite Blocking List (malware/botnet)"),
    ("PSBL", "psbl.surriel.com", "ip", "Passive Spam Block List"),
    ("Mailspike", "bl.mailspike.net", "ip", "Mailspike IP reputation"),
    ("SORBS", "dnsbl.sorbs.net", "ip", "SORBS combined blocklist"),
]


def _reverse_ip(ip: str) -> str:
    """Reverse IP octets for DNSBL query (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


def _extract_address(record) -> str:
    """Extract IP address string from a seer dig record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("address", "")
        return str(data)
    return str(record)


@tool
def domain_reputation_check(domain: str) -> str:
    """Check a domain's reputation across DNS-based blocklists (DNSBL). Queries
    Spamhaus (ZEN+DBL), SURBL, URIBL, Barracuda, SpamCop, and others. Checks both
    the domain directly and its resolved IP addresses against IP-based blocklists."""
    domain = domain.lower().strip()

    # Step 1: Resolve the domain's A records to get IPs for IP-based blocklists
    a_records = safe_call(seer.dig, domain, "A") or []
    ips = []
    for rec in (a_records if isinstance(a_records, list) else []):
        addr = _extract_address(rec)
        if addr and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", addr):
            ips.append(addr)

    # Step 2: Build all DNSBL queries
    queries = []
    query_meta = []  # Track which blocklist and target each query maps to

    for name, zone, qtype, desc in _BLOCKLISTS:
        if qtype == "domain":
            query = f"{domain}.{zone}"
            queries.append((seer.dig, query, "A"))
            query_meta.append({"name": name, "zone": zone, "target": domain, "type": "domain", "description": desc})
        elif qtype == "ip":
            for ip in ips:
                query = f"{_reverse_ip(ip)}.{zone}"
                queries.append((seer.dig, query, "A"))
                query_meta.append({"name": name, "zone": zone, "target": ip, "type": "ip", "description": desc})

    # Step 3: Execute all queries concurrently
    results = parallel_calls(*queries) if queries else []

    # Step 4: Interpret results
    checks = []
    listed_count = 0

    for i, raw in enumerate(results):
        meta = query_meta[i]
        listed = False
        return_code = None

        if raw and isinstance(raw, list) and len(raw) > 0:
            addr = _extract_address(raw[0])
            if addr.startswith("127."):
                listed = True
                return_code = addr
                listed_count += 1

        checks.append({
            "blocklist": meta["name"],
            "description": meta["description"],
            "target": meta["target"],
            "query_type": meta["type"],
            "listed": listed,
            "return_code": return_code,
        })

    # Step 5: Determine overall status
    if listed_count == 0:
        overall_status = "clean"
        severity = "INFO"
    elif listed_count <= 2:
        overall_status = "listed"
        severity = "MEDIUM"
    else:
        overall_status = "widely_listed"
        severity = "HIGH"

    findings = []
    for check in checks:
        if check["listed"]:
            findings.append({
                "severity": "HIGH" if "spamhaus" in check["blocklist"].lower() else "MEDIUM",
                "finding": f"Listed on {check['blocklist']} ({check['query_type']} check: {check['target']})",
                "detail": f"{check['description']}. Return code: {check['return_code']}",
                "recommendation": f"Investigate listing at {check['blocklist']} and request delisting if legitimate",
            })

    return json.dumps({
        "domain": domain,
        "resolved_ips": ips,
        "overall_status": overall_status,
        "overall_severity": severity,
        "listed_count": listed_count,
        "total_checks": len(checks),
        "checks": checks,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)


SECURITY_TOOLS = [
    domain_reputation_check,
]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestDomainReputationCheck -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/security_tools.py tests/test_security_tools.py
git commit -m "feat: add domain_reputation_check security tool"
```

---

## Task 5: Zone Transfer Testing (AXFR)

Add a tool that tests whether a domain's nameservers allow unauthorized DNS zone transfers.

**Files:**
- Modify: `familiar/src/familiar/tools/security_tools.py` (add tool + update SECURITY_TOOLS)
- Modify: `familiar/tests/test_security_tools.py` (add test class)

- [ ] **Step 1: Write the failing test**

Add to `familiar/tests/test_security_tools.py`:

```python
from familiar.tools.security_tools import zone_transfer_test


class TestZoneTransferTest:
    """Tests for the zone_transfer_test tool."""

    @patch("familiar.tools.security_tools.seer")
    @patch("familiar.tools.security_tools._attempt_axfr")
    def test_secure_domain(self, mock_axfr, mock_seer):
        mock_seer.dig.return_value = [
            {"data": {"nameserver": "ns1.example.com."}, "record_type": "NS"},
            {"data": {"nameserver": "ns2.example.com."}, "record_type": "NS"},
        ]
        mock_axfr.return_value = {"success": False, "error": "Transfer refused"}
        result = json.loads(zone_transfer_test.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["vulnerable"] is False
        assert len(result["nameservers_tested"]) == 2

    @patch("familiar.tools.security_tools.seer")
    @patch("familiar.tools.security_tools._attempt_axfr")
    def test_vulnerable_domain(self, mock_axfr, mock_seer):
        mock_seer.dig.return_value = [
            {"data": {"nameserver": "ns1.example.com."}, "record_type": "NS"},
        ]
        mock_axfr.return_value = {
            "success": True,
            "record_count": 42,
            "records_sample": ["example.com. 3600 IN A 93.184.216.34"],
        }
        result = json.loads(zone_transfer_test.invoke({"domain": "example.com"}))
        assert result["vulnerable"] is True
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "CRITICAL"

    @patch("familiar.tools.security_tools.seer")
    def test_no_nameservers(self, mock_seer):
        mock_seer.dig.return_value = []
        result = json.loads(zone_transfer_test.invoke({"domain": "noname.com"}))
        assert result["vulnerable"] is False
        assert "no nameservers" in result.get("note", "").lower() or len(result["nameservers_tested"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestZoneTransferTest -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement zone_transfer_test**

Add to `familiar/src/familiar/tools/security_tools.py`:

```python
def _attempt_axfr(nameserver: str, domain: str, timeout: float = 5.0) -> dict:
    """Attempt a DNS zone transfer (AXFR) against a single nameserver.

    Uses raw TCP DNS protocol — constructs an AXFR query packet, connects to
    the nameserver on port 53/TCP, and checks if the response contains zone data.
    """
    try:
        # Build minimal DNS AXFR query
        # Header: ID=0xABCD, QR=0, OPCODE=0, QDCOUNT=1
        txn_id = 0xABCD
        flags = 0x0000  # Standard query
        header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

        # Question section: encode domain name + QTYPE=AXFR(252) + QCLASS=IN(1)
        question = b""
        for label in domain.rstrip(".").split("."):
            question += struct.pack("B", len(label)) + label.encode("ascii")
        question += b"\x00"  # Root label
        question += struct.pack(">HH", 252, 1)  # AXFR, IN

        message = header + question

        # TCP DNS: 2-byte length prefix
        tcp_msg = struct.pack(">H", len(message)) + message

        # Resolve nameserver hostname to IP first
        try:
            ns_ip = socket.getaddrinfo(nameserver.rstrip("."), 53, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except socket.gaierror:
            return {"success": False, "error": f"Cannot resolve nameserver {nameserver}"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ns_ip, 53))
            sock.sendall(tcp_msg)

            # Read response length
            length_data = sock.recv(2)
            if len(length_data) < 2:
                return {"success": False, "error": "No response from nameserver"}

            resp_len = struct.unpack(">H", length_data)[0]
            if resp_len < 12:
                return {"success": False, "error": "Transfer refused or empty response"}

            # Read response
            response = b""
            while len(response) < resp_len:
                chunk = sock.recv(min(4096, resp_len - len(response)))
                if not chunk:
                    break
                response += chunk

            # Parse response header
            if len(response) < 12:
                return {"success": False, "error": "Incomplete response"}

            _, resp_flags, _, ancount, _, _ = struct.unpack(">HHHHHH", response[:12])
            rcode = resp_flags & 0x000F

            # RCODE 5 = REFUSED, RCODE 9 = NOTAUTH
            if rcode in (5, 9):
                return {"success": False, "error": "Transfer refused (RCODE={})".format(rcode)}

            if rcode != 0:
                return {"success": False, "error": f"DNS error RCODE={rcode}"}

            if ancount > 0:
                return {
                    "success": True,
                    "record_count": ancount,
                    "response_size": len(response),
                    "records_sample": [f"({ancount} records transferred — {len(response)} bytes)"],
                }

            return {"success": False, "error": "No records in response"}

        finally:
            sock.close()

    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"success": False, "error": "Connection refused (port 53/TCP closed)"}
    except OSError as e:
        return {"success": False, "error": f"Network error: {e}"}


def _extract_nameserver(record) -> str:
    """Extract nameserver hostname from a seer dig NS record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("nameserver", "").rstrip(".")
        return str(data).rstrip(".")
    return str(record).rstrip(".")


@tool
def zone_transfer_test(domain: str) -> str:
    """Test whether a domain's nameservers allow unauthorized DNS zone transfers
    (AXFR). Zone transfers that succeed from arbitrary sources expose the entire
    DNS zone contents — a critical security finding in any pentest."""
    domain = domain.lower().strip()

    # Get nameservers
    ns_records = safe_call(seer.dig, domain, "NS") or []
    nameservers = []
    for rec in (ns_records if isinstance(ns_records, list) else []):
        ns = _extract_nameserver(rec)
        if ns:
            nameservers.append(ns)

    if not nameservers:
        return json.dumps({
            "domain": domain,
            "vulnerable": False,
            "nameservers_tested": [],
            "results": [],
            "findings": [],
            "note": "No nameservers found for this domain",
        }, default=str)

    # Test each nameserver (max 4)
    test_ns = nameservers[:4]
    results = []
    findings = []
    vulnerable = False

    for ns in test_ns:
        axfr_result = _attempt_axfr(ns, domain)
        result_entry = {
            "nameserver": ns,
            "axfr_allowed": axfr_result["success"],
        }
        if axfr_result["success"]:
            vulnerable = True
            result_entry["record_count"] = axfr_result.get("record_count", 0)
            result_entry["response_size"] = axfr_result.get("response_size", 0)
            findings.append({
                "severity": "CRITICAL",
                "finding": f"Zone transfer (AXFR) allowed on {ns}",
                "detail": f"Nameserver {ns} returned {axfr_result.get('record_count', '?')} records — "
                          "entire zone contents exposed to unauthenticated queries",
                "recommendation": f"Restrict AXFR on {ns} to authorized secondary nameservers only "
                                  "(allow-transfer ACL in BIND, xfr-out in Knot, etc.)",
            })
        else:
            result_entry["status"] = axfr_result.get("error", "refused")

        results.append(result_entry)

    return json.dumps({
        "domain": domain,
        "vulnerable": vulnerable,
        "nameservers_tested": test_ns,
        "results": results,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)
```

Add `zone_transfer_test` to `SECURITY_TOOLS`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestZoneTransferTest -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/security_tools.py tests/test_security_tools.py
git commit -m "feat: add zone_transfer_test security tool (AXFR)"
```

---

## Task 6: MTA-STS and TLS-RPT Checking

Check email transport security beyond SPF/DMARC/DKIM — validate MTA-STS policy and TLS-RPT reporting.

**Files:**
- Modify: `familiar/src/familiar/tools/security_tools.py` (add tool)
- Modify: `familiar/tests/test_security_tools.py` (add test class)

- [ ] **Step 1: Write the failing test**

Add to `familiar/tests/test_security_tools.py`:

```python
from familiar.tools.security_tools import mta_sts_check


class TestMtaStsCheck:
    """Tests for the mta_sts_check tool."""

    @patch("familiar.tools.security_tools._fetch_mta_sts_policy")
    @patch("familiar.tools.security_tools.seer")
    def test_full_mta_sts(self, mock_seer, mock_fetch):
        def _dig(query, record_type="A", nameserver=None):
            if "_mta-sts" in query:
                return [{"data": {"text": "v=STSv1; id=20240101"}, "record_type": "TXT"}]
            if "_smtp._tls" in query:
                return [{"data": {"text": "v=TLSRPTv1; rua=mailto:tls@example.com"}, "record_type": "TXT"}]
            if record_type == "MX":
                return [{"data": {"exchange": "mail.example.com.", "preference": 10}, "record_type": "MX"}]
            return []
        mock_seer.dig.side_effect = _dig
        mock_fetch.return_value = {
            "success": True,
            "policy": "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400",
        }
        result = json.loads(mta_sts_check.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["mta_sts"]["txt_record"]["found"] is True
        assert result["mta_sts"]["policy"]["found"] is True
        assert result["tls_rpt"]["found"] is True

    @patch("familiar.tools.security_tools._fetch_mta_sts_policy")
    @patch("familiar.tools.security_tools.seer")
    def test_no_mta_sts(self, mock_seer, mock_fetch):
        mock_seer.dig.return_value = []
        mock_fetch.return_value = {"success": False, "error": "404"}
        result = json.loads(mta_sts_check.invoke({"domain": "no-sts.com"}))
        assert result["mta_sts"]["txt_record"]["found"] is False
        assert result["mta_sts"]["policy"]["found"] is False
        assert result["tls_rpt"]["found"] is False
        assert any(f["severity"] in ("MEDIUM", "LOW") for f in result["findings"])
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestMtaStsCheck -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement mta_sts_check**

Add to `familiar/src/familiar/tools/security_tools.py`. Add `from urllib.request import urlopen, Request` and `from urllib.error import URLError` to the imports at the top.

```python
def _fetch_mta_sts_policy(domain: str, timeout: float = 5.0) -> dict:
    """Fetch the MTA-STS policy file from .well-known/mta-sts.txt."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        req = Request(url, headers={"User-Agent": "familiar/0.1"})
        with urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read(8192).decode("utf-8", errors="replace")
                return {"success": True, "policy": body.strip()}
            return {"success": False, "error": f"HTTP {resp.status}"}
    except URLError as e:
        return {"success": False, "error": str(e)}
    except OSError as e:
        return {"success": False, "error": str(e)}


def _extract_txt_value(record) -> str:
    """Extract text value from a seer dig TXT record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("text", data.get("value", str(data)))
        return str(data)
    return str(record)


@tool
def mta_sts_check(domain: str) -> str:
    """Check MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) configuration. MTA-STS
    enforces TLS for inbound email, preventing downgrade attacks. TLS-RPT enables
    reporting of TLS negotiation failures. Checks the _mta-sts TXT record, the
    .well-known/mta-sts.txt policy file, and the _smtp._tls TXT record."""
    domain = domain.lower().strip()

    # Fetch all DNS records and the policy file concurrently
    sts_txt, tlsrpt_txt, mx_records, policy_raw = parallel_calls(
        (seer.dig, f"_mta-sts.{domain}", "TXT"),
        (seer.dig, f"_smtp._tls.{domain}", "TXT"),
        (seer.dig, domain, "MX"),
        (_fetch_mta_sts_policy, domain),
    )

    findings = []
    has_mx = bool(mx_records and isinstance(mx_records, list) and len(mx_records) > 0)

    # --- MTA-STS TXT Record ---
    sts_txt_info = {"found": False}
    if sts_txt and isinstance(sts_txt, list):
        for rec in sts_txt:
            txt = _extract_txt_value(rec)
            if "v=stsv1" in txt.lower():
                sts_txt_info = {"found": True, "record": txt.strip()}
                # Extract id parameter
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("id="):
                        sts_txt_info["id"] = part.split("=", 1)[1].strip()
                break

    # --- MTA-STS Policy File ---
    sts_policy_info = {"found": False}
    if policy_raw and isinstance(policy_raw, dict) and policy_raw.get("success"):
        raw_policy = policy_raw["policy"]
        sts_policy_info["found"] = True
        sts_policy_info["raw"] = raw_policy

        # Parse policy fields
        for line in raw_policy.splitlines():
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "mode":
                    sts_policy_info["mode"] = val
                elif key == "max_age":
                    sts_policy_info["max_age"] = val
                elif key == "mx":
                    sts_policy_info.setdefault("mx_patterns", []).append(val)

        mode = sts_policy_info.get("mode", "")
        if mode == "none":
            findings.append({
                "severity": "MEDIUM",
                "finding": "MTA-STS policy mode is 'none' — no enforcement",
                "detail": "Policy exists but does not enforce TLS for inbound email",
                "recommendation": "Set mode to 'testing' then 'enforce' after validating delivery",
            })
        elif mode == "testing":
            findings.append({
                "severity": "LOW",
                "finding": "MTA-STS policy mode is 'testing' — monitoring only",
                "detail": "TLS failures are reported but mail is still delivered over plaintext",
                "recommendation": "Upgrade to 'enforce' mode after confirming all MX servers support TLS",
            })

        max_age = sts_policy_info.get("max_age", "")
        try:
            if max_age and int(max_age) < 86400:
                findings.append({
                    "severity": "LOW",
                    "finding": f"MTA-STS max_age is short ({max_age}s / {int(max_age) // 3600}h)",
                    "detail": "Short max_age means senders must re-fetch the policy frequently",
                    "recommendation": "Consider max_age of at least 86400 (1 day), ideally 604800 (1 week)",
                })
        except ValueError:
            pass

    # --- Consistency checks ---
    if sts_txt_info["found"] and not sts_policy_info["found"]:
        findings.append({
            "severity": "HIGH",
            "finding": "MTA-STS TXT record exists but policy file is missing",
            "detail": "The _mta-sts TXT record advertises STS, but https://mta-sts.{domain}/.well-known/mta-sts.txt is unreachable",
            "recommendation": "Publish the MTA-STS policy file at the .well-known URL on the mta-sts subdomain",
        })
    elif not sts_txt_info["found"] and sts_policy_info["found"]:
        findings.append({
            "severity": "HIGH",
            "finding": "MTA-STS policy file exists but TXT record is missing",
            "detail": "Senders will not discover the policy without the _mta-sts TXT record",
            "recommendation": "Add a TXT record at _mta-sts.{domain} with v=STSv1; id=<unique-id>",
        })
    elif not sts_txt_info["found"] and not sts_policy_info["found"] and has_mx:
        findings.append({
            "severity": "MEDIUM",
            "finding": "No MTA-STS configured for domain with MX records",
            "detail": "Without MTA-STS, email can be delivered over unencrypted connections (STARTTLS downgrade)",
            "recommendation": "Deploy MTA-STS: add _mta-sts TXT record and publish policy at .well-known/mta-sts.txt",
        })

    # --- TLS-RPT Record ---
    tlsrpt_info = {"found": False}
    if tlsrpt_txt and isinstance(tlsrpt_txt, list):
        for rec in tlsrpt_txt:
            txt = _extract_txt_value(rec)
            if "v=tlsrptv1" in txt.lower():
                tlsrpt_info = {"found": True, "record": txt.strip()}
                # Extract rua
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("rua="):
                        tlsrpt_info["reporting_uri"] = part.split("=", 1)[1].strip()
                break

    if not tlsrpt_info["found"] and has_mx:
        findings.append({
            "severity": "LOW",
            "finding": "No TLS-RPT (RFC 8460) record configured",
            "detail": "Without TLS-RPT, you won't receive reports about TLS negotiation failures for inbound email",
            "recommendation": "Add a TXT record at _smtp._tls.{domain} with v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
        })

    return json.dumps({
        "domain": domain,
        "has_mx": has_mx,
        "mta_sts": {
            "txt_record": sts_txt_info,
            "policy": sts_policy_info,
        },
        "tls_rpt": tlsrpt_info,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)
```

Add `mta_sts_check` to `SECURITY_TOOLS`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestMtaStsCheck -v
```

Expected: all 2 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/security_tools.py tests/test_security_tools.py
git commit -m "feat: add mta_sts_check tool (MTA-STS + TLS-RPT)"
```

---

## Task 7: DANE/TLSA Validation

Check whether a domain publishes DANE TLSA records and validate them against the actual certificate chain.

**Files:**
- Modify: `familiar/src/familiar/tools/security_tools.py` (add tool)
- Modify: `familiar/tests/test_security_tools.py` (add test class)

- [ ] **Step 1: Write the failing test**

Add to `familiar/tests/test_security_tools.py`:

```python
from familiar.tools.security_tools import dane_tlsa_check


class TestDaneTlsaCheck:
    """Tests for the dane_tlsa_check tool."""

    @patch("familiar.tools.security_tools.seer")
    def test_no_tlsa(self, mock_seer):
        mock_seer.dig.return_value = []
        mock_seer.ssl.return_value = {"is_valid": True, "chain": [{"subject": "example.com"}]}
        result = json.loads(dane_tlsa_check.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["dane_configured"] is False

    @patch("familiar.tools.security_tools.seer")
    def test_with_tlsa_records(self, mock_seer):
        def _dig(query, record_type="A", nameserver=None):
            if record_type == "TLSA":
                return [{"data": {"usage": 3, "selector": 1, "matching_type": 1,
                         "certificate_data": "abc123"}, "record_type": "TLSA"}]
            return []
        mock_seer.dig.side_effect = _dig
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "chain": [{"subject": "example.com", "key_type": "EC", "key_bits": 256}],
        }
        result = json.loads(dane_tlsa_check.invoke({"domain": "example.com"}))
        assert result["dane_configured"] is True
        assert len(result["tlsa_records"]) >= 1

    @patch("familiar.tools.security_tools.seer")
    def test_smtp_port(self, mock_seer):
        mock_seer.dig.return_value = []
        mock_seer.ssl.return_value = None
        result = json.loads(dane_tlsa_check.invoke({"domain": "mail.example.com", "port": "25"}))
        assert result["port"] == 25
        mock_seer.dig.assert_any_call("_25._tcp.mail.example.com", "TLSA")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestDaneTlsaCheck -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement dane_tlsa_check**

Add to `familiar/src/familiar/tools/security_tools.py`:

```python
# DANE TLSA usage field descriptions
_TLSA_USAGE = {
    0: "CA constraint (PKIX-TA) — certificate must chain to specified CA",
    1: "Service certificate constraint (PKIX-EE) — must match leaf cert + pass PKIX validation",
    2: "Trust anchor assertion (DANE-TA) — specified cert is trust anchor (no PKIX required)",
    3: "Domain-issued certificate (DANE-EE) — must match leaf cert exactly (no PKIX required)",
}

_TLSA_SELECTOR = {
    0: "Full certificate",
    1: "SubjectPublicKeyInfo (public key only)",
}

_TLSA_MATCHING = {
    0: "Exact match (no hash)",
    1: "SHA-256 hash",
    2: "SHA-512 hash",
}


@tool
def dane_tlsa_check(domain: str, port: int = 443) -> str:
    """Check DANE TLSA records (RFC 6698/7671) for a domain and port. DANE binds
    TLS certificates to DNS via DNSSEC, preventing CA compromise attacks. Checks
    _<port>._tcp.<domain> for TLSA records and validates against the actual
    certificate. Common ports: 443 (HTTPS), 25 (SMTP), 587 (submission)."""
    domain = domain.lower().strip()
    port = int(port)

    tlsa_name = f"_{port}._tcp.{domain}"

    # Fetch TLSA records, DNSSEC status, and the actual certificate concurrently
    tlsa_records, dnssec_data, ssl_data = parallel_calls(
        (seer.dig, tlsa_name, "TLSA"),
        (seer.dnssec, domain),
        (seer.ssl, domain),
    )

    findings = []

    # --- Parse TLSA records ---
    parsed_tlsa = []
    if tlsa_records and isinstance(tlsa_records, list):
        for rec in tlsa_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                if isinstance(data, dict):
                    usage = data.get("usage", data.get("certificate_usage"))
                    selector = data.get("selector")
                    matching = data.get("matching_type")
                    cert_data = data.get("certificate_data", data.get("certificate_association_data", ""))

                    entry = {
                        "usage": usage,
                        "usage_description": _TLSA_USAGE.get(usage, f"Unknown ({usage})"),
                        "selector": selector,
                        "selector_description": _TLSA_SELECTOR.get(selector, f"Unknown ({selector})"),
                        "matching_type": matching,
                        "matching_description": _TLSA_MATCHING.get(matching, f"Unknown ({matching})"),
                        "certificate_data": str(cert_data)[:64] + ("..." if len(str(cert_data)) > 64 else ""),
                    }
                    parsed_tlsa.append(entry)

                    # Validate usage field
                    if usage in (0, 1):
                        findings.append({
                            "severity": "INFO",
                            "finding": f"TLSA usage {usage} (PKIX-based) — requires both DANE match and CA validation",
                            "detail": _TLSA_USAGE.get(usage, ""),
                            "recommendation": "Ensure the certificate chain satisfies both PKIX and DANE constraints",
                        })
                    elif usage == 3:
                        findings.append({
                            "severity": "INFO",
                            "finding": "TLSA usage 3 (DANE-EE) — strongest DANE mode, bypasses CA system",
                            "detail": "The leaf certificate must match the TLSA record exactly. PKIX validation is not required.",
                            "recommendation": "Update the TLSA record whenever the certificate is renewed",
                        })

                    # Check matching type
                    if matching == 0:
                        findings.append({
                            "severity": "LOW",
                            "finding": "TLSA uses full certificate match (matching type 0) instead of a hash",
                            "detail": "Full certificate data in DNS increases record size and is less common",
                            "recommendation": "Consider SHA-256 (matching type 1) for smaller, more standard TLSA records",
                        })

    dane_configured = len(parsed_tlsa) > 0

    # --- DNSSEC dependency ---
    dnssec_ok = False
    if dnssec_data and isinstance(dnssec_data, dict):
        dnssec_status = dnssec_data.get("status", "unknown")
        dnssec_ok = dnssec_status == "secure"
        if dane_configured and not dnssec_ok:
            findings.append({
                "severity": "CRITICAL",
                "finding": "DANE TLSA records exist but DNSSEC is not fully validated",
                "detail": f"DNSSEC status: {dnssec_status}. DANE requires a secure DNSSEC chain to prevent "
                          "spoofed TLSA records from being used in MitM attacks.",
                "recommendation": "Enable and validate DNSSEC before relying on DANE for certificate pinning",
            })

    if dane_configured and dnssec_ok:
        findings.append({
            "severity": "INFO",
            "finding": "DANE is properly configured with DNSSEC validation",
            "detail": "TLSA records are protected by a secure DNSSEC chain",
            "recommendation": "Maintain DNSSEC signing and update TLSA records on certificate renewal",
        })

    # --- Certificate info ---
    cert_info = {}
    if ssl_data and isinstance(ssl_data, dict):
        chain = ssl_data.get("chain", [])
        if chain and isinstance(chain, list) and isinstance(chain[0], dict):
            leaf = chain[0]
            cert_info = {
                "subject": leaf.get("subject"),
                "issuer": leaf.get("issuer"),
                "key_type": leaf.get("key_type"),
                "key_bits": leaf.get("key_bits"),
                "valid_until": leaf.get("valid_until"),
                "is_valid": ssl_data.get("is_valid", False),
            }

    if not dane_configured:
        findings.append({
            "severity": "INFO",
            "finding": f"No DANE TLSA records at {tlsa_name}",
            "detail": "DANE is not configured for this domain/port combination",
            "recommendation": "Consider adding DANE TLSA records if DNSSEC is enabled — provides certificate "
                              "pinning independent of the CA system",
        })

    return json.dumps({
        "domain": domain,
        "port": port,
        "tlsa_name": tlsa_name,
        "dane_configured": dane_configured,
        "dnssec_validated": dnssec_ok,
        "tlsa_records": parsed_tlsa,
        "certificate": cert_info,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)
```

Add `dane_tlsa_check` to `SECURITY_TOOLS`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestDaneTlsaCheck -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/security_tools.py tests/test_security_tools.py
git commit -m "feat: add dane_tlsa_check tool (DANE/TLSA validation)"
```

---

## Task 8: Website Technology Fingerprinting

Analyze HTTP response headers and DNS signals to identify web technologies, CMS platforms, and frameworks.

**Files:**
- Modify: `familiar/src/familiar/tools/security_tools.py` (add tool)
- Modify: `familiar/tests/test_security_tools.py` (add test class)

- [ ] **Step 1: Write the failing test**

Add to `familiar/tests/test_security_tools.py`:

```python
from familiar.tools.security_tools import website_fingerprint


class TestWebsiteFingerprint:
    """Tests for the website_fingerprint tool."""

    @patch("familiar.tools.security_tools._fetch_http_headers")
    @patch("familiar.tools.security_tools.seer")
    def test_detects_technologies(self, mock_seer, mock_fetch):
        mock_seer.dig.return_value = []
        mock_seer.status.return_value = {"http_status": 200}
        mock_fetch.return_value = {
            "success": True,
            "status_code": 200,
            "headers": {
                "server": "nginx/1.24",
                "x-powered-by": "PHP/8.2",
                "set-cookie": "wp_session=abc123",
            },
        }
        result = json.loads(website_fingerprint.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        techs = result["technologies"]
        server_names = [t["name"] for t in techs]
        assert "nginx" in server_names
        assert "PHP" in server_names

    @patch("familiar.tools.security_tools._fetch_http_headers")
    @patch("familiar.tools.security_tools.seer")
    def test_unreachable_site(self, mock_seer, mock_fetch):
        mock_seer.dig.return_value = []
        mock_seer.status.return_value = {"http_status": None}
        mock_fetch.return_value = {"success": False, "error": "Connection refused"}
        result = json.loads(website_fingerprint.invoke({"domain": "down.com"}))
        assert len(result["technologies"]) == 0 or result.get("error")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestWebsiteFingerprint -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement website_fingerprint**

Add to `familiar/src/familiar/tools/security_tools.py`:

```python
# Technology fingerprint patterns: (header_field, pattern, tech_name, category)
_TECH_FINGERPRINTS = [
    # Web servers
    ("server", r"nginx", "nginx", "Web Server"),
    ("server", r"apache", "Apache", "Web Server"),
    ("server", r"cloudflare", "Cloudflare", "CDN/Web Server"),
    ("server", r"microsoft-iis", "IIS", "Web Server"),
    ("server", r"litespeed", "LiteSpeed", "Web Server"),
    ("server", r"caddy", "Caddy", "Web Server"),
    ("server", r"openresty", "OpenResty", "Web Server"),
    ("server", r"gunicorn", "Gunicorn", "WSGI Server"),
    ("server", r"uvicorn", "Uvicorn", "ASGI Server"),
    ("server", r"cowboy", "Cowboy (Erlang)", "Web Server"),
    # Languages/runtimes
    ("x-powered-by", r"php", "PHP", "Language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"),
    ("x-powered-by", r"express", "Express.js", "Framework"),
    ("x-powered-by", r"next\.js", "Next.js", "Framework"),
    ("x-powered-by", r"nuxt", "Nuxt.js", "Framework"),
    # CMS platforms
    ("x-powered-by", r"wordpress", "WordPress", "CMS"),
    ("x-powered-by", r"drupal", "Drupal", "CMS"),
    ("x-generator", r"wordpress", "WordPress", "CMS"),
    ("x-generator", r"drupal", "Drupal", "CMS"),
    ("x-generator", r"joomla", "Joomla", "CMS"),
    ("x-generator", r"hugo", "Hugo", "Static Site Generator"),
    ("x-generator", r"gatsby", "Gatsby", "Static Site Generator"),
    ("x-generator", r"astro", "Astro", "Static Site Generator"),
    # CDN/proxy
    ("x-served-by", r"cache", "Varnish/CDN Cache", "Caching"),
    ("x-cache", r".", "CDN Cache Layer", "Caching"),
    ("cf-ray", r".", "Cloudflare", "CDN"),
    ("x-vercel-id", r".", "Vercel", "Platform"),
    ("x-netlify", r".", "Netlify", "Platform"),
    ("x-amz-cf-id", r".", "AWS CloudFront", "CDN"),
    ("x-azure-ref", r".", "Azure Front Door", "CDN"),
    # Security
    ("x-xss-protection", r".", "XSS Protection Header", "Security Header"),
    ("x-content-type-options", r"nosniff", "X-Content-Type-Options", "Security Header"),
    ("strict-transport-security", r".", "HSTS", "Security Header"),
    ("content-security-policy", r".", "CSP", "Security Header"),
    ("permissions-policy", r".", "Permissions-Policy", "Security Header"),
    ("referrer-policy", r".", "Referrer-Policy", "Security Header"),
]

# Cookie-based CMS detection patterns
_COOKIE_FINGERPRINTS = [
    (r"wp_", "WordPress", "CMS"),
    (r"wordpress", "WordPress", "CMS"),
    (r"drupal", "Drupal", "CMS"),
    (r"joomla", "Joomla", "CMS"),
    (r"laravel_session", "Laravel", "Framework"),
    (r"django", "Django", "Framework"),
    (r"rails", "Ruby on Rails", "Framework"),
    (r"phpsessid", "PHP", "Language"),
    (r"jsessionid", "Java", "Language"),
    (r"asp\.net", "ASP.NET", "Framework"),
    (r"__cfduid|__cf_bm", "Cloudflare", "CDN"),
    (r"incap_ses", "Imperva/Incapsula", "WAF"),
    (r"visid_incap", "Imperva/Incapsula", "WAF"),
    (r"akamai", "Akamai", "CDN"),
]


def _fetch_http_headers(domain: str, timeout: float = 8.0) -> dict:
    """Fetch HTTP response headers from a domain via HEAD request."""
    url = f"https://{domain}/"
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "familiar/0.1"})
        with urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"success": True, "status_code": resp.status, "headers": headers}
    except Exception:
        # Retry with HTTP if HTTPS fails
        try:
            url = f"http://{domain}/"
            req = Request(url, method="HEAD", headers={"User-Agent": "familiar/0.1"})
            with urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return {"success": True, "status_code": resp.status, "headers": headers}
        except Exception as e:
            return {"success": False, "error": str(e)}


@tool
def website_fingerprint(domain: str) -> str:
    """Identify web technologies, CMS platforms, frameworks, CDN providers, and
    security headers by analyzing HTTP response headers and cookies. Detects
    server software, language/runtime, CMS, caching layers, and security posture."""
    domain = domain.lower().strip()

    # Fetch HTTP headers and DNS data concurrently
    header_data, cname_records, txt_records = parallel_calls(
        (_fetch_http_headers, domain),
        (seer.dig, domain, "CNAME"),
        (seer.dig, domain, "TXT"),
    )

    technologies = []
    seen_techs = set()  # Deduplicate

    def _add_tech(name, category, evidence, confidence="high"):
        key = f"{name}:{category}"
        if key not in seen_techs:
            seen_techs.add(key)
            technologies.append({
                "name": name,
                "category": category,
                "evidence": evidence,
                "confidence": confidence,
            })

    security_headers = {}
    raw_headers = {}

    if header_data and isinstance(header_data, dict) and header_data.get("success"):
        headers = header_data.get("headers", {})
        raw_headers = dict(headers)

        # Header-based detection
        for header_field, pattern, tech_name, category in _TECH_FINGERPRINTS:
            value = headers.get(header_field, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                if category == "Security Header":
                    security_headers[tech_name] = value
                else:
                    version_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", value)
                    evidence = f"{header_field}: {value[:100]}"
                    _add_tech(
                        f"{tech_name}/{version_match.group()}" if version_match else tech_name,
                        category,
                        evidence,
                    )

        # Cookie-based detection
        cookies = headers.get("set-cookie", "")
        for pattern, tech_name, category in _COOKIE_FINGERPRINTS:
            if re.search(pattern, cookies, re.IGNORECASE):
                _add_tech(tech_name, category, f"Cookie pattern: {pattern}", confidence="medium")

    # DNS-based detection (CNAME fingerprinting)
    if cname_records and isinstance(cname_records, list):
        for rec in cname_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                target = ""
                if isinstance(data, dict):
                    target = data.get("target", data.get("cname", "")).lower().rstrip(".")
                else:
                    target = str(data).lower().rstrip(".")

                if "shopify" in target:
                    _add_tech("Shopify", "E-Commerce Platform", f"CNAME → {target}")
                elif "squarespace" in target:
                    _add_tech("Squarespace", "Website Builder", f"CNAME → {target}")
                elif "wixdns" in target or "wixsite" in target:
                    _add_tech("Wix", "Website Builder", f"CNAME → {target}")
                elif "ghost.io" in target:
                    _add_tech("Ghost", "CMS", f"CNAME → {target}")
                elif "webflow" in target:
                    _add_tech("Webflow", "Website Builder", f"CNAME → {target}")
                elif "github.io" in target:
                    _add_tech("GitHub Pages", "Hosting", f"CNAME → {target}")
                elif "netlify" in target:
                    _add_tech("Netlify", "Platform", f"CNAME → {target}")
                elif "vercel" in target:
                    _add_tech("Vercel", "Platform", f"CNAME → {target}")

    # TXT-based technology detection
    if txt_records and isinstance(txt_records, list):
        for rec in txt_records:
            txt = _extract_txt_value(rec)
            txt_lower = txt.lower()
            if "google-site-verification" in txt_lower:
                _add_tech("Google Search Console", "SEO/Analytics", "TXT verification record", confidence="medium")
            elif re.match(r"ms=ms\d", txt_lower):
                _add_tech("Microsoft 365", "Email/Productivity", "TXT verification record", confidence="medium")
            elif "facebook-domain-verification" in txt_lower:
                _add_tech("Meta/Facebook", "Advertising", "TXT verification record", confidence="medium")
            elif "apple-domain-verification" in txt_lower:
                _add_tech("Apple", "Platform", "TXT verification record", confidence="medium")
            elif "atlassian-domain-verification" in txt_lower:
                _add_tech("Atlassian", "Productivity", "TXT verification record", confidence="medium")
            elif "docusign" in txt_lower:
                _add_tech("DocuSign", "Business Tool", "TXT verification record", confidence="medium")

    return json.dumps({
        "domain": domain,
        "technologies": technologies,
        "security_headers": security_headers,
        "security_header_count": len(security_headers),
        "total_technologies": len(technologies),
        "headers_available": bool(raw_headers),
    }, default=str)
```

Add `website_fingerprint` to `SECURITY_TOOLS`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_security_tools.py::TestWebsiteFingerprint -v
```

Expected: all 2 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/security_tools.py tests/test_security_tools.py
git commit -m "feat: add website_fingerprint technology detection tool"
```

---

## Task 9: Structured Change Tracking — Memory Schema

Extend the Memory class with a `domain_snapshots` table for storing structured domain state over time.

**Files:**
- Modify: `familiar/src/familiar/memory.py`
- Test: `familiar/tests/test_memory_snapshots.py`

- [ ] **Step 1: Write the failing test**

Create `familiar/tests/test_memory_snapshots.py`:

```python
import json
import time

import pytest
from familiar.memory import Memory


class TestMemorySnapshots:
    """Tests for the domain_snapshots table and diff functionality."""

    @pytest.fixture()
    def memory(self, tmp_path):
        db_path = tmp_path / "test_snapshots.db"
        mem = Memory(db_path=db_path)
        yield mem
        mem.close()

    def test_save_snapshot(self, memory):
        data = {"registrar": "Example Inc", "nameservers": ["ns1.example.com"], "ssl_valid": True}
        result = memory.save_snapshot("example.com", data)
        assert result["domain"] == "example.com"
        assert result["snapshot_id"] is not None
        assert "captured_at" in result

    def test_list_snapshots(self, memory):
        memory.save_snapshot("example.com", {"registrar": "A"})
        time.sleep(0.01)
        memory.save_snapshot("example.com", {"registrar": "B"})
        snapshots = memory.list_snapshots("example.com")
        assert len(snapshots) == 2
        # Most recent first
        assert json.loads(snapshots[0]["data"])["registrar"] == "B"

    def test_list_snapshots_empty(self, memory):
        snapshots = memory.list_snapshots("nonexistent.com")
        assert snapshots == []

    def test_diff_snapshots(self, memory):
        s1 = memory.save_snapshot("example.com", {
            "registrar": "Old Registrar",
            "nameservers": ["ns1.old.com", "ns2.old.com"],
            "ssl_valid": True,
        })
        s2 = memory.save_snapshot("example.com", {
            "registrar": "New Registrar",
            "nameservers": ["ns1.new.com", "ns2.new.com"],
            "ssl_valid": True,
        })
        diff = memory.diff_snapshots(s1["snapshot_id"], s2["snapshot_id"])
        assert diff["domain"] == "example.com"
        assert len(diff["changes"]) >= 1
        # registrar changed
        reg_change = [c for c in diff["changes"] if c["field"] == "registrar"]
        assert len(reg_change) == 1
        assert reg_change[0]["old"] == "Old Registrar"
        assert reg_change[0]["new"] == "New Registrar"
        # ssl_valid didn't change — should not appear
        ssl_changes = [c for c in diff["changes"] if c["field"] == "ssl_valid"]
        assert len(ssl_changes) == 0

    def test_diff_snapshots_invalid_id(self, memory):
        with pytest.raises(ValueError, match="not found"):
            memory.diff_snapshots(999, 998)

    def test_get_latest_snapshot(self, memory):
        memory.save_snapshot("example.com", {"version": 1})
        time.sleep(0.01)
        memory.save_snapshot("example.com", {"version": 2})
        latest = memory.get_latest_snapshot("example.com")
        assert json.loads(latest["data"])["version"] == 2

    def test_get_latest_snapshot_none(self, memory):
        result = memory.get_latest_snapshot("missing.com")
        assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_memory_snapshots.py -v
```

Expected: FAIL with `AttributeError` (methods don't exist yet)

- [ ] **Step 3: Implement snapshot methods in Memory**

Add to `familiar/src/familiar/memory.py`:

Update `_init_schema` to add the new table — append to the `executescript` string:

```sql
                CREATE TABLE IF NOT EXISTS domain_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    data TEXT NOT NULL,
                    captured_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_domain
                    ON domain_snapshots(domain, captured_at DESC);
```

Add the following methods to the `Memory` class, after the Preferences section and before `_check_open`:

```python
    # --- Domain Snapshots ---

    def save_snapshot(self, domain: str, data: dict) -> dict:
        """Save a structured snapshot of a domain's current state."""
        self._check_open()
        now = datetime.now(timezone.utc).isoformat()
        domain = domain.lower().strip()
        data_json = json.dumps(data, default=str)
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO domain_snapshots (domain, data, captured_at) VALUES (?, ?, ?)",
                (domain, data_json, now),
            )
            self._conn.commit()
            return {
                "domain": domain,
                "snapshot_id": cursor.lastrowid,
                "captured_at": now,
            }

    def list_snapshots(self, domain: str, limit: int = 20) -> list[dict]:
        """List snapshots for a domain, most recent first."""
        domain = domain.lower().strip()
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, domain, data, captured_at FROM domain_snapshots "
                "WHERE domain = ? ORDER BY captured_at DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
            return [
                {"snapshot_id": r["id"], "domain": r["domain"], "data": r["data"], "captured_at": r["captured_at"]}
                for r in rows
            ]

    def get_latest_snapshot(self, domain: str) -> dict | None:
        """Get the most recent snapshot for a domain."""
        snapshots = self.list_snapshots(domain, limit=1)
        return snapshots[0] if snapshots else None

    def diff_snapshots(self, snapshot_id_a: int, snapshot_id_b: int) -> dict:
        """Compare two snapshots and return the differences."""
        with self._lock:
            row_a = self._conn.execute(
                "SELECT id, domain, data, captured_at FROM domain_snapshots WHERE id = ?",
                (snapshot_id_a,),
            ).fetchone()
            row_b = self._conn.execute(
                "SELECT id, domain, data, captured_at FROM domain_snapshots WHERE id = ?",
                (snapshot_id_b,),
            ).fetchone()

        if not row_a:
            raise ValueError(f"Snapshot {snapshot_id_a} not found")
        if not row_b:
            raise ValueError(f"Snapshot {snapshot_id_b} not found")

        data_a = json.loads(row_a["data"])
        data_b = json.loads(row_b["data"])

        changes = []
        all_keys = sorted(set(list(data_a.keys()) + list(data_b.keys())))
        for key in all_keys:
            val_a = data_a.get(key)
            val_b = data_b.get(key)
            if val_a != val_b:
                changes.append({
                    "field": key,
                    "old": val_a,
                    "new": val_b,
                })

        return {
            "domain": row_a["domain"],
            "snapshot_a": {"id": row_a["id"], "captured_at": row_a["captured_at"]},
            "snapshot_b": {"id": row_b["id"], "captured_at": row_b["captured_at"]},
            "changes": changes,
            "total_changes": len(changes),
        }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_memory_snapshots.py -v
```

Expected: all 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/memory.py tests/test_memory_snapshots.py
git commit -m "feat: add domain_snapshots table and diff methods to Memory"
```

---

## Task 10: Structured Change Tracking — Tool Wrappers

Create LangChain tool wrappers for the snapshot/diff functionality.

**Files:**
- Modify: `familiar/src/familiar/tools/memory_tools.py` (add tools + SNAPSHOT_TOOLS list)
- Test: `familiar/tests/test_snapshot_tool_wrappers.py`

- [ ] **Step 1: Write the failing test**

Create `familiar/tests/test_snapshot_tool_wrappers.py`:

```python
import json
from unittest.mock import MagicMock, patch

from familiar.tools.memory_tools import snapshot_domain, diff_snapshots


class TestSnapshotDomain:
    """Tests for the snapshot_domain tool wrapper."""

    @patch("familiar.tools.memory_tools.seer")
    @patch("familiar.tools.memory_tools.get_memory")
    def test_captures_snapshot(self, mock_get_memory, mock_seer):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.save_snapshot.return_value = {
            "domain": "example.com",
            "snapshot_id": 1,
            "captured_at": "2026-03-29T00:00:00+00:00",
        }
        mock_seer.lookup.return_value = {"source": "rdap", "data": {"registrar": "Test"}}
        mock_seer.status.return_value = {"http_status": 200}
        mock_seer.dig.return_value = [{"data": {"nameserver": "ns1.test.com."}}]
        mock_seer.dnssec.return_value = {"status": "secure"}

        result = json.loads(snapshot_domain.invoke({"domain": "example.com"}))
        assert result["snapshot_id"] == 1
        assert result["domain"] == "example.com"
        mock_mem.save_snapshot.assert_called_once()

    @patch("familiar.tools.memory_tools.seer")
    @patch("familiar.tools.memory_tools.get_memory")
    def test_error_returns_json(self, mock_get_memory, mock_seer):
        mock_seer.lookup.side_effect = RuntimeError("network error")
        mock_seer.status.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.dnssec.return_value = None
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.save_snapshot.return_value = {
            "domain": "fail.com", "snapshot_id": 2, "captured_at": "2026-03-29T00:00:00+00:00",
        }
        # Should still save whatever data it gathered, not crash
        result = json.loads(snapshot_domain.invoke({"domain": "fail.com"}))
        assert "snapshot_id" in result


class TestDiffSnapshots:
    """Tests for the diff_snapshots tool wrapper."""

    @patch("familiar.tools.memory_tools.get_memory")
    def test_returns_diff(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.diff_snapshots.return_value = {
            "domain": "example.com",
            "snapshot_a": {"id": 1, "captured_at": "2026-03-01"},
            "snapshot_b": {"id": 2, "captured_at": "2026-03-29"},
            "changes": [{"field": "registrar", "old": "A", "new": "B"}],
            "total_changes": 1,
        }
        result = json.loads(diff_snapshots.invoke({"snapshot_id_a": "1", "snapshot_id_b": "2"}))
        assert result["total_changes"] == 1
        assert result["changes"][0]["field"] == "registrar"

    @patch("familiar.tools.memory_tools.get_memory")
    def test_invalid_id(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.diff_snapshots.side_effect = ValueError("Snapshot 999 not found")
        result = json.loads(diff_snapshots.invoke({"snapshot_id_a": "999", "snapshot_id_b": "1"}))
        assert "error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_snapshot_tool_wrappers.py -v
```

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement tool wrappers**

Add to `familiar/src/familiar/tools/memory_tools.py`, after the `WORKFLOW_TOOLS` list:

```python
# --- Snapshot Tools ---


@tool
def snapshot_domain(domain: str) -> str:
    """Capture a structured snapshot of a domain's current state: registration data,
    DNS nameservers, HTTP status, SSL validity, and DNSSEC status. Snapshots are stored
    persistently and can be compared with diff_snapshots to track changes over time."""
    domain = domain.lower().strip()

    # Gather current domain state concurrently
    lookup_data, status_data, ns_records, dnssec_data = parallel_calls(
        (seer.lookup, domain),
        (seer.status, domain),
        (seer.dig, domain, "NS"),
        (seer.dnssec, domain),
    )

    # Build snapshot data dict
    snapshot_data = {"domain": domain}

    # Registration data
    if lookup_data and isinstance(lookup_data, dict):
        inner = lookup_data.get("data", lookup_data)
        if isinstance(inner, dict):
            snapshot_data["registrar"] = inner.get("registrar")
            snapshot_data["expiration_date"] = inner.get("expiration_date") or inner.get("expiry")
            snapshot_data["creation_date"] = inner.get("creation_date") or inner.get("created")
            snapshot_data["source"] = lookup_data.get("source")

    # Nameservers
    if ns_records and isinstance(ns_records, list):
        ns_list = []
        for rec in ns_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                ns = data.get("nameserver", str(data)) if isinstance(data, dict) else str(data)
                ns_list.append(ns.rstrip("."))
        snapshot_data["nameservers"] = sorted(ns_list)

    # HTTP/SSL status
    if status_data and isinstance(status_data, dict):
        snapshot_data["http_status"] = status_data.get("http_status")
        cert = status_data.get("certificate")
        if cert and isinstance(cert, dict):
            snapshot_data["ssl_valid"] = cert.get("is_valid")
            snapshot_data["ssl_issuer"] = cert.get("issuer")
            snapshot_data["ssl_expiry"] = cert.get("expiry") or cert.get("not_after")
            snapshot_data["ssl_days_remaining"] = cert.get("days_until_expiry")

    # DNSSEC
    if dnssec_data and isinstance(dnssec_data, dict):
        snapshot_data["dnssec_status"] = dnssec_data.get("status")

    # Save the snapshot
    mem = get_memory()
    save_result = mem.save_snapshot(domain, snapshot_data)

    # Also auto-remember the domain in the notebook
    safe_call(mem.remember_domain, domain, "", "snapshot")

    return json.dumps(save_result, default=str)


@tool
def diff_snapshots(snapshot_id_a: int, snapshot_id_b: int) -> str:
    """Compare two domain snapshots by their IDs and show what changed. Use
    snapshot_domain first to capture snapshots at different times, then diff_snapshots
    to see registration, DNS, SSL, or other changes between them."""
    try:
        result = get_memory().diff_snapshots(int(snapshot_id_a), int(snapshot_id_b))
        return json.dumps(result, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)})


@tool
def list_domain_snapshots(domain: str) -> str:
    """List all stored snapshots for a domain, most recent first. Each entry includes
    the snapshot ID (for use with diff_snapshots) and the capture timestamp."""
    snapshots = get_memory().list_snapshots(domain.lower().strip())
    return json.dumps({
        "domain": domain,
        "total": len(snapshots),
        "snapshots": [
            {"snapshot_id": s["snapshot_id"], "captured_at": s["captured_at"]}
            for s in snapshots
        ],
    }, default=str)


SNAPSHOT_TOOLS = [
    snapshot_domain,
    diff_snapshots,
    list_domain_snapshots,
]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_snapshot_tool_wrappers.py -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/memory_tools.py tests/test_snapshot_tool_wrappers.py
git commit -m "feat: add snapshot_domain, diff_snapshots, list_domain_snapshots tools"
```

---

## Task 11: Wire Everything Together

Update `__init__.py` to import and register all new tool lists.

**Files:**
- Modify: `familiar/src/familiar/tools/__init__.py`

- [ ] **Step 1: Write the failing test (tool count)**

The existing `test_tool_inventory.py` likely checks tool counts. First, verify the current expected count. The new tools are:

- `seer_bulk_availability` (1 in SEER_TOOLS)
- `tome_record_by_status` (1 in TOME_TOOLS)
- `domain_reputation_check`, `zone_transfer_test`, `mta_sts_check`, `dane_tlsa_check`, `website_fingerprint` (5 in SECURITY_TOOLS)
- `snapshot_domain`, `diff_snapshots`, `list_domain_snapshots` (3 in SNAPSHOT_TOOLS)

Total new: 10. Previous total: 61. New total: 71.

- [ ] **Step 2: Update `__init__.py`**

Replace `familiar/src/familiar/tools/__init__.py` contents:

```python
"""All LangChain tools for the Familiar agent."""

from .advisor_tools import ADVISOR_TOOLS, COMPOSITE_ADVISOR_TOOLS
from .memory_tools import MEMORY_TOOLS, SNAPSHOT_TOOLS, WORKFLOW_TOOLS
from .pentest_tools import PENTEST_TOOLS
from .security_tools import SECURITY_TOOLS
from .seer_tools import SEER_TOOLS
from .tome_tools import TOME_TOOLS

ALL_TOOLS = (
    SEER_TOOLS
    + TOME_TOOLS
    + ADVISOR_TOOLS
    + COMPOSITE_ADVISOR_TOOLS
    + PENTEST_TOOLS
    + SECURITY_TOOLS
    + MEMORY_TOOLS
    + WORKFLOW_TOOLS
    + SNAPSHOT_TOOLS
)

__all__ = [
    "ALL_TOOLS",
    "SEER_TOOLS",
    "TOME_TOOLS",
    "ADVISOR_TOOLS",
    "COMPOSITE_ADVISOR_TOOLS",
    "PENTEST_TOOLS",
    "SECURITY_TOOLS",
    "MEMORY_TOOLS",
    "WORKFLOW_TOOLS",
    "SNAPSHOT_TOOLS",
]
```

- [ ] **Step 3: Verify all tools import correctly**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && python -c "
from familiar.tools import ALL_TOOLS, SECURITY_TOOLS, SNAPSHOT_TOOLS
print(f'Total tools: {len(ALL_TOOLS)}')
print(f'Security tools: {len(SECURITY_TOOLS)}')
print(f'Snapshot tools: {len(SNAPSHOT_TOOLS)}')
print('Names:', [t.name for t in ALL_TOOLS])
"
```

Expected: `Total tools: 71`, `Security tools: 5`, `Snapshot tools: 3`

- [ ] **Step 4: Run full test suite**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest -v
```

Expected: All tests pass including existing tests (no regressions).

- [ ] **Step 5: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/__init__.py
git commit -m "feat: register SECURITY_TOOLS and SNAPSHOT_TOOLS in ALL_TOOLS (71 total)"
```

---

## Task 12: Update exposure_report to Include New Security Tools

Update the `exposure_report` tool to optionally include the new security scan results.

**Files:**
- Modify: `familiar/src/familiar/tools/pentest_tools.py` (update exposure_report)

- [ ] **Step 1: Add new tool imports to pentest_tools.py**

At the top of `pentest_tools.py`, after the existing `from ..utils import` line, add:

```python
from .security_tools import (
    domain_reputation_check,
    zone_transfer_test,
    mta_sts_check,
    dane_tlsa_check,
)
```

- [ ] **Step 2: Update the exposure_report function**

In the `exposure_report` function, add the new scans to the `parallel_calls` block. Update the scan call list:

```python
    scan_results = parallel_calls(
        (subdomain_takeover_scan.func, domain),
        (http_security_scan.func, domain),
        (email_security_audit.func, domain),
        (ssl_deep_scan.func, domain),
        (dns_zone_security.func, domain),
        (infrastructure_recon.func, domain),
        (domain_reputation_check.func, domain),
        (zone_transfer_test.func, domain),
        (mta_sts_check.func, domain),
        (dane_tlsa_check.func, domain),
    )
```

Add parsing for the 4 new results after `infra`:

```python
    reputation = _parse_scan(scan_results[6])
    zt_result = _parse_scan(scan_results[7])
    mta_sts = _parse_scan(scan_results[8])
    dane = _parse_scan(scan_results[9])
```

Add collection of findings from the new tools after the existing `_collect` calls:

```python
    _collect("domain_reputation", reputation)
    _collect("zone_transfer", zt_result)
    _collect("mta_sts", mta_sts)
    _collect("dane_tlsa", dane)
```

Add section summaries for the new tools:

```python
    if reputation and isinstance(reputation, dict):
        sections["domain_reputation"] = {
            "overall_status": reputation.get("overall_status", "unknown"),
            "listed_count": reputation.get("listed_count", 0),
            "total_checks": reputation.get("total_checks", 0),
        }

    if zt_result and isinstance(zt_result, dict):
        sections["zone_transfer"] = {
            "vulnerable": zt_result.get("vulnerable", False),
            "nameservers_tested": len(zt_result.get("nameservers_tested", [])),
        }

    if mta_sts and isinstance(mta_sts, dict):
        sections["mta_sts"] = {
            "mta_sts_configured": mta_sts.get("mta_sts", {}).get("txt_record", {}).get("found", False),
            "tls_rpt_configured": mta_sts.get("tls_rpt", {}).get("found", False),
        }

    if dane and isinstance(dane, dict):
        sections["dane_tlsa"] = {
            "dane_configured": dane.get("dane_configured", False),
            "dnssec_validated": dane.get("dnssec_validated", False),
        }
```

- [ ] **Step 3: Run existing exposure_report tests**

```bash
cd /home/zac/Projects/arcanum_suite/familiar && pytest tests/test_exposure_report.py -v
```

Expected: All existing tests still pass (the new tools return `None` when mocked, which `_collect` handles gracefully).

- [ ] **Step 4: Commit**

```bash
cd /home/zac/Projects/arcanum_suite/familiar
git add src/familiar/tools/pentest_tools.py
git commit -m "feat: integrate new security tools into exposure_report"
```

---

## Summary

After all 12 tasks, the Familiar agent will have:

| Category | Before | After | Delta |
|----------|--------|-------|-------|
| Seer Tools | 20 | 21 | +1 (bulk_availability) |
| Tome Tools | 9 | 10 | +1 (record_by_status) |
| Advisor Tools | 6 | 6 | — |
| Composite Advisor | 6 | 6 | — |
| Pentest Tools | 7 | 7 | — (exposure_report enhanced) |
| **Security Tools** | 0 | **5** | +5 (new module) |
| Memory Tools | 9 | 9 | — |
| Workflow Tools | 4 | 4 | — |
| **Snapshot Tools** | 0 | **3** | +3 (new category) |
| **Total** | **61** | **71** | **+10** |

New capabilities:
1. **Bulk availability checking** via seer's Rust executor
2. **DNS record type filtering** by IANA status
3. **Domain reputation** across 10 DNS blocklists
4. **Zone transfer testing** with real AXFR queries
5. **MTA-STS + TLS-RPT** email transport security
6. **DANE/TLSA** certificate pinning validation
7. **Website fingerprinting** via HTTP headers, cookies, and DNS
8. **Structured change tracking** with persistent snapshots and diffs
