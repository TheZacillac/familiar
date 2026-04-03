"""Tests for all remaining thin LangChain @tool wrappers without coverage.

Covers seer wrappers (seer_tools.py), tome wrappers (tome_tools.py), and
memory/workflow wrappers (memory_tools.py).  Each function gets a success test
(valid JSON output) and an error test (exception -> {"error": ...} JSON).
"""

import json
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Seer tool imports
# ---------------------------------------------------------------------------
from familiar.tools.seer_tools import (
    seer_availability,
    seer_bulk_dig,
    seer_bulk_lookup,
    seer_bulk_propagation,
    seer_bulk_status,
    seer_bulk_whois,
    seer_diff,
    seer_dns_compare,
    seer_dns_follow,
    seer_dnssec,
    seer_propagation,
    seer_rdap_asn,
    seer_rdap_ip,
    seer_subdomains,
)

# ---------------------------------------------------------------------------
# Tome tool imports
# ---------------------------------------------------------------------------
from familiar.tools.tome_tools import (
    tome_record_search,
    tome_tld_count,
    tome_tld_list_by_type,
    tome_tld_overview,
)

# ---------------------------------------------------------------------------
# Memory / workflow tool imports
# ---------------------------------------------------------------------------
from familiar.tools.memory_tools import (
    compare_domains,
    recall_all_domains,
    recall_domain,
    remember_domain,
    session_summary,
    tag_search,
    watchlist_add,
    watchlist_list,
    watchlist_remove,
)


# ===================================================================
# Seer wrappers
# ===================================================================


class TestSeerRdapIp:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.rdap_ip.return_value = {
            "handle": "NET-93-184-0-0-1",
            "name": "EDGECAST-NETBLK-03",
            "country": "US",
        }
        result = seer_rdap_ip.invoke({"ip": "93.184.216.34"})
        parsed = json.loads(result)
        assert parsed["handle"] == "NET-93-184-0-0-1"
        assert parsed["country"] == "US"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.rdap_ip.side_effect = ValueError("Invalid IP address")
        result = seer_rdap_ip.invoke({"ip": "not-an-ip"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "Invalid IP" in parsed["error"]


class TestSeerRdapAsn:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.rdap_asn.return_value = {
            "handle": "AS15169",
            "name": "GOOGLE",
            "type": "DIRECT ALLOCATION",
        }
        result = seer_rdap_asn.invoke({"asn": 15169})
        parsed = json.loads(result)
        assert parsed["handle"] == "AS15169"
        assert parsed["name"] == "GOOGLE"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.rdap_asn.side_effect = RuntimeError("ASN lookup failed")
        result = seer_rdap_asn.invoke({"asn": 99999999})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "ASN lookup failed" in parsed["error"]


class TestSeerPropagation:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.propagation.return_value = {
            "domain": "example.com",
            "record_type": "A",
            "servers": [
                {"server": "8.8.8.8", "result": ["93.184.216.34"]},
                {"server": "1.1.1.1", "result": ["93.184.216.34"]},
            ],
        }
        result = seer_propagation.invoke({"domain": "example.com", "record_type": "A"})
        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert len(parsed["servers"]) == 2

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.propagation.side_effect = ConnectionError("DNS servers unreachable")
        result = seer_propagation.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "unreachable" in parsed["error"]


class TestSeerBulkLookup:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            {"domain": "a.com", "success": True, "data": {"registrar": "R1"}},
            {"domain": "b.com", "success": True, "data": {"registrar": "R2"}},
        ]
        result = seer_bulk_lookup.invoke({"domains": ["a.com", "b.com"], "concurrency": 5})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["domain"] == "a.com"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.bulk_lookup.side_effect = RuntimeError("bulk failed")
        result = seer_bulk_lookup.invoke({"domains": ["a.com"]})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "bulk failed" in parsed["error"]


class TestSeerBulkWhois:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.bulk_whois.return_value = [
            {"domain": "x.com", "success": True, "data": {"registrar": "MarkMonitor"}},
        ]
        result = seer_bulk_whois.invoke({"domains": ["x.com"], "concurrency": 10})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["data"]["registrar"] == "MarkMonitor"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.bulk_whois.side_effect = TimeoutError("WHOIS timeout")
        result = seer_bulk_whois.invoke({"domains": ["x.com"]})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerBulkDig:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.bulk_dig.return_value = [
            {"domain": "a.com", "success": True, "data": [{"data": {"address": "1.2.3.4"}}]},
        ]
        result = seer_bulk_dig.invoke({"domains": ["a.com"], "record_type": "A", "concurrency": 10})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["success"] is True

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.bulk_dig.side_effect = Exception("DNS batch error")
        result = seer_bulk_dig.invoke({"domains": ["a.com"]})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerBulkStatus:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.bulk_status.return_value = [
            {"domain": "up.com", "success": True, "data": {"http_status": 200}},
        ]
        result = seer_bulk_status.invoke({"domains": ["up.com"], "concurrency": 10})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["data"]["http_status"] == 200

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.bulk_status.side_effect = OSError("Network error")
        result = seer_bulk_status.invoke({"domains": ["up.com"]})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerBulkPropagation:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.bulk_propagation.return_value = [
            {"domain": "test.com", "success": True, "data": {"consistent": True}},
        ]
        result = seer_bulk_propagation.invoke({
            "domains": ["test.com"],
            "record_type": "A",
            "concurrency": 5,
        })
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["data"]["consistent"] is True

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.bulk_propagation.side_effect = RuntimeError("propagation batch error")
        result = seer_bulk_propagation.invoke({"domains": ["test.com"]})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerAvailability:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.availability.return_value = {
            "domain": "brandnew.xyz",
            "available": True,
            "method": "rdap",
            "confidence": "high",
        }
        result = seer_availability.invoke({"domain": "brandnew.xyz"})
        parsed = json.loads(result)
        assert parsed["available"] is True
        assert parsed["confidence"] == "high"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.availability.side_effect = ValueError("Invalid TLD")
        result = seer_availability.invoke({"domain": "bad..domain"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "Invalid TLD" in parsed["error"]


class TestSeerSubdomains:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.subdomains.return_value = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "mail.example.com"],
            "count": 2,
        }
        result = seer_subdomains.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["count"] == 2
        assert "www.example.com" in parsed["subdomains"]

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.subdomains.side_effect = RuntimeError("CT log unreachable")
        result = seer_subdomains.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerDnssec:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.dnssec.return_value = {
            "domain": "example.com",
            "signed": True,
            "ds_records": [{"key_tag": 12345}],
        }
        result = seer_dnssec.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["signed"] is True
        assert len(parsed["ds_records"]) == 1

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.dnssec.side_effect = Exception("DNSSEC validation error")
        result = seer_dnssec.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerDnsCompare:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.dns_compare.return_value = {
            "domain": "example.com",
            "record_type": "A",
            "matching": ["93.184.216.34"],
            "only_a": [],
            "only_b": [],
        }
        result = seer_dns_compare.invoke({
            "domain": "example.com",
            "record_type": "A",
            "server_a": "8.8.8.8",
            "server_b": "1.1.1.1",
        })
        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert "matching" in parsed

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.dns_compare.side_effect = ConnectionError("server unreachable")
        result = seer_dns_compare.invoke({
            "domain": "fail.com",
            "record_type": "A",
            "server_a": "8.8.8.8",
            "server_b": "1.1.1.1",
        })
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerDnsFollow:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.dns_follow.return_value = {
            "domain": "example.com",
            "record_type": "A",
            "iterations": [
                {"timestamp": "2026-03-27T10:00:00Z", "records": ["93.184.216.34"]},
                {"timestamp": "2026-03-27T10:01:00Z", "records": ["93.184.216.34"]},
            ],
            "changed": False,
        }
        result = seer_dns_follow.invoke({
            "domain": "example.com",
            "record_type": "A",
            "iterations": 2,
            "interval_minutes": 1.0,
        })
        parsed = json.loads(result)
        assert parsed["changed"] is False
        assert len(parsed["iterations"]) == 2

    @patch("familiar.tools.seer_tools.seer")
    def test_with_nameserver(self, mock_seer):
        mock_seer.dns_follow.return_value = {"domain": "example.com", "changed": False, "iterations": []}
        result = seer_dns_follow.invoke({
            "domain": "example.com",
            "record_type": "A",
            "nameserver": "8.8.8.8",
            "iterations": 1,
            "interval_minutes": 0.5,
        })
        parsed = json.loads(result)
        assert "changed" in parsed
        mock_seer.dns_follow.assert_called_once_with("example.com", "A", "8.8.8.8", 1, 0.5)

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.dns_follow.side_effect = TimeoutError("follow timed out")
        result = seer_dns_follow.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerDiff:
    @patch("familiar.tools.seer_tools.seer")
    def test_success(self, mock_seer):
        mock_seer.diff.return_value = {
            "domain_a": "example.com",
            "domain_b": "example.org",
            "registration": {"same_registrar": False},
            "dns": {"same_a_records": False},
        }
        result = seer_diff.invoke({"domain_a": "example.com", "domain_b": "example.org"})
        parsed = json.loads(result)
        assert parsed["domain_a"] == "example.com"
        assert parsed["domain_b"] == "example.org"

    @patch("familiar.tools.seer_tools.seer")
    def test_error(self, mock_seer):
        mock_seer.diff.side_effect = RuntimeError("diff failed")
        result = seer_diff.invoke({"domain_a": "a.com", "domain_b": "b.com"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "diff failed" in parsed["error"]


# ===================================================================
# Tome wrappers
# ===================================================================


class TestTomeRecordSearchSuccess:
    @patch("familiar.tools.tome_tools.tome")
    def test_success_returns_list(self, mock_tome):
        mock_tome.record_search.return_value = [
            {"type": "A", "description": "IPv4 address"},
            {"type": "AAAA", "description": "IPv6 address"},
        ]
        result = tome_record_search.invoke({"query": "A"})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["type"] == "A"

    @patch("familiar.tools.tome_tools.tome")
    def test_success_empty_results(self, mock_tome):
        mock_tome.record_search.return_value = []
        result = tome_record_search.invoke({"query": "nonexistent"})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 0


class TestTomeTldOverview:
    @patch("familiar.tools.tome_tools.tome")
    def test_success(self, mock_tome):
        mock_tome.tld_overview.return_value = {
            "tld": "com",
            "registry": "Verisign",
            "whois_server": "whois.verisign-grs.com",
            "dnssec": True,
        }
        result = tome_tld_overview.invoke({"tld": "com"})
        parsed = json.loads(result)
        assert parsed["tld"] == "com"
        assert parsed["registry"] == "Verisign"

    @patch("familiar.tools.tome_tools.tome")
    def test_none_returns_error(self, mock_tome):
        mock_tome.tld_overview.return_value = None
        result = tome_tld_overview.invoke({"tld": "zzzzz"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "zzzzz" in parsed["error"]

    @patch("familiar.tools.tome_tools.tome")
    def test_exception(self, mock_tome):
        mock_tome.tld_overview.side_effect = RuntimeError("DB error")
        result = tome_tld_overview.invoke({"tld": "com"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestTomeTldListByType:
    @patch("familiar.tools.tome_tools.tome")
    def test_success(self, mock_tome):
        mock_tome.tld_list_by_type.return_value = ["com", "net", "org"]
        result = tome_tld_list_by_type.invoke({"tld_type": "gTLD"})
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert "com" in parsed

    @patch("familiar.tools.tome_tools.tome")
    def test_error(self, mock_tome):
        mock_tome.tld_list_by_type.side_effect = ValueError("Unknown type")
        result = tome_tld_list_by_type.invoke({"tld_type": "bogus"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestTomeTldCount:
    @patch("familiar.tools.tome_tools.tome")
    def test_success(self, mock_tome):
        mock_tome.tld_count.return_value = 1589
        result = tome_tld_count.invoke({})
        parsed = json.loads(result)
        assert parsed["count"] == 1589

    @patch("familiar.tools.tome_tools.tome")
    def test_error(self, mock_tome):
        mock_tome.tld_count.side_effect = RuntimeError("connection lost")
        result = tome_tld_count.invoke({})
        parsed = json.loads(result)
        assert "error" in parsed


# ===================================================================
# Memory tool wrappers
# ===================================================================


class TestRememberDomain:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.remember_domain.return_value = {
            "domain": "example.com",
            "action": "created",
            "tags": ["portfolio"],
        }
        mock_get_memory.return_value = mock_mem
        result = remember_domain.invoke({"domain": "example.com", "notes": "Main site", "tags": "portfolio"})
        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert parsed["action"] == "created"
        mock_mem.remember_domain.assert_called_once_with("example.com", "Main site", "portfolio")

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.remember_domain.side_effect = RuntimeError("DB write failed")
        mock_get_memory.return_value = mock_mem
        # remember_domain does NOT have a try/except, so it will raise.
        # However, the tool framework may handle it. Let's verify the call
        # propagates. Since the source has no try/except, we test that the
        # exception is raised.
        with pytest.raises(RuntimeError, match="DB write failed"):
            remember_domain.invoke({"domain": "fail.com"})


class TestRecallDomain:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_found(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_domain.return_value = {
            "domain": "example.com",
            "notes": "Main site",
            "tags": ["portfolio"],
            "first_seen": "2026-01-01",
            "last_seen": "2026-03-27",
        }
        mock_get_memory.return_value = mock_mem
        result = recall_domain.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["found"] is True
        assert parsed["domain"] == "example.com"
        assert parsed["notes"] == "Main site"

    @patch("familiar.tools.memory_tools.get_memory")
    def test_not_found(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_domain.return_value = None
        mock_get_memory.return_value = mock_mem
        result = recall_domain.invoke({"domain": "unknown.com"})
        parsed = json.loads(result)
        assert parsed["found"] is False
        assert parsed["domain"] == "unknown.com"

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_domain.side_effect = RuntimeError("DB read failed")
        mock_get_memory.return_value = mock_mem
        with pytest.raises(RuntimeError, match="DB read failed"):
            recall_domain.invoke({"domain": "fail.com"})


class TestRecallAllDomains:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success_with_domains(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_all_domains.return_value = [
            {"domain": "a.com", "tags": ["web"], "last_seen": "2026-03-27"},
            {"domain": "b.com", "tags": [], "last_seen": "2026-03-26"},
        ]
        mock_get_memory.return_value = mock_mem
        result = recall_all_domains.invoke({})
        parsed = json.loads(result)
        assert parsed["total"] == 2
        assert len(parsed["domains"]) == 2
        assert parsed["domains"][0]["domain"] == "a.com"

    @patch("familiar.tools.memory_tools.get_memory")
    def test_success_empty(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_all_domains.return_value = []
        mock_get_memory.return_value = mock_mem
        result = recall_all_domains.invoke({})
        parsed = json.loads(result)
        assert parsed["total"] == 0
        assert parsed["domains"] == []


class TestWatchlistAdd:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_add.return_value = {
            "domain": "watch.com",
            "action": "added",
        }
        mock_get_memory.return_value = mock_mem
        result = watchlist_add.invoke({"domain": "watch.com"})
        parsed = json.loads(result)
        assert parsed["domain"] == "watch.com"
        assert parsed["action"] == "added"
        mock_mem.watchlist_add.assert_called_once_with("watch.com")

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_add.side_effect = RuntimeError("DB error")
        mock_get_memory.return_value = mock_mem
        with pytest.raises(RuntimeError, match="DB error"):
            watchlist_add.invoke({"domain": "fail.com"})


class TestWatchlistRemove:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_remove.return_value = {
            "domain": "watch.com",
            "action": "removed",
        }
        mock_get_memory.return_value = mock_mem
        result = watchlist_remove.invoke({"domain": "watch.com"})
        parsed = json.loads(result)
        assert parsed["domain"] == "watch.com"
        assert parsed["action"] == "removed"
        mock_mem.watchlist_remove.assert_called_once_with("watch.com")

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_remove.side_effect = RuntimeError("DB error")
        mock_get_memory.return_value = mock_mem
        with pytest.raises(RuntimeError, match="DB error"):
            watchlist_remove.invoke({"domain": "fail.com"})


class TestWatchlistList:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success_with_domains(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = [
            {"domain": "watch1.com", "added": "2026-03-01"},
            {"domain": "watch2.com", "added": "2026-03-15"},
        ]
        mock_get_memory.return_value = mock_mem
        result = watchlist_list.invoke({})
        parsed = json.loads(result)
        assert parsed["total"] == 2
        assert len(parsed["domains"]) == 2

    @patch("familiar.tools.memory_tools.get_memory")
    def test_success_empty(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = []
        mock_get_memory.return_value = mock_mem
        result = watchlist_list.invoke({})
        parsed = json.loads(result)
        assert parsed["total"] == 0
        assert parsed["domains"] == []


class TestTagSearch:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.tag_search.return_value = [
            {"domain": "a.com", "tags": ["portfolio"]},
            {"domain": "b.com", "tags": ["portfolio", "client"]},
        ]
        mock_get_memory.return_value = mock_mem
        result = tag_search.invoke({"tag": "portfolio"})
        parsed = json.loads(result)
        assert parsed["tag"] == "portfolio"
        assert parsed["total"] == 2
        assert len(parsed["domains"]) == 2

    @patch("familiar.tools.memory_tools.get_memory")
    def test_no_results(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.tag_search.return_value = []
        mock_get_memory.return_value = mock_mem
        result = tag_search.invoke({"tag": "nonexistent"})
        parsed = json.loads(result)
        assert parsed["total"] == 0
        assert parsed["domains"] == []

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.tag_search.side_effect = RuntimeError("DB error")
        mock_get_memory.return_value = mock_mem
        result = tag_search.invoke({"tag": "fail"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSessionSummary:
    @patch("familiar.tools.memory_tools.get_memory")
    def test_success(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_all_domains.return_value = [
            {"domain": "a.com", "tags": ["web"], "last_seen": "2026-03-27"},
            {"domain": "b.com", "tags": [], "last_seen": "2026-03-26"},
        ]
        mock_mem.watchlist_list.return_value = [
            {"domain": "a.com", "added": "2026-03-01"},
        ]
        mock_get_memory.return_value = mock_mem
        result = session_summary.invoke({})
        parsed = json.loads(result)
        assert parsed["total_domains"] == 2
        assert len(parsed["domains"]) == 2
        assert parsed["watchlist_count"] == 1
        assert "a.com" in parsed["watchlist"]

    @patch("familiar.tools.memory_tools.get_memory")
    def test_empty_session(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_all_domains.return_value = []
        mock_mem.watchlist_list.return_value = []
        mock_get_memory.return_value = mock_mem
        result = session_summary.invoke({})
        parsed = json.loads(result)
        assert parsed["total_domains"] == 0
        assert parsed["domains"] == []
        assert parsed["watchlist_count"] == 0
        assert parsed["watchlist"] == []

    @patch("familiar.tools.memory_tools.get_memory")
    def test_error(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.recall_all_domains.side_effect = RuntimeError("DB error")
        mock_get_memory.return_value = mock_mem
        result = session_summary.invoke({})
        parsed = json.loads(result)
        assert "error" in parsed


class TestCompareDomains:
    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_success(self, mock_parallel):
        mock_parallel.return_value = [
            {"registrar": "RegistrarA"},  # reg_a
            {"registrar": "RegistrarB"},  # reg_b
            [{"data": {"address": "1.1.1.1"}}],  # dns_a
            [{"data": {"address": "2.2.2.2"}}],  # dns_b
            {"http_status": 200},  # status_a
            {"http_status": 301},  # status_b
        ]
        result = compare_domains.invoke({"domain_a": "Example.COM", "domain_b": "Example.ORG"})
        parsed = json.loads(result)
        assert parsed["domain_a"] == "example.com"
        assert parsed["domain_b"] == "example.org"
        assert "registration" in parsed
        assert "dns_a_records" in parsed
        assert "status" in parsed
        assert parsed["registration"]["domain_a"]["registrar"] == "RegistrarA"
        assert parsed["status"]["domain_b"]["http_status"] == 301

    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_partial_failures(self, mock_parallel):
        mock_parallel.return_value = [
            None,  # reg_a failed
            {"registrar": "RegistrarB"},  # reg_b
            None,  # dns_a failed
            [{"data": {"address": "2.2.2.2"}}],  # dns_b
            None,  # status_a failed
            {"http_status": 200},  # status_b
        ]
        result = compare_domains.invoke({"domain_a": "fail.com", "domain_b": "ok.com"})
        parsed = json.loads(result)
        assert parsed["registration"]["domain_a"] is None
        assert parsed["registration"]["domain_b"]["registrar"] == "RegistrarB"
        assert parsed["dns_a_records"]["domain_a"] is None
        assert parsed["status"]["domain_a"] is None
