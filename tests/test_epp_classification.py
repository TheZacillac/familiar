"""Test 8: EPP status code classification accuracy.

Validates parsing of RFC 5731 EPP status codes in various formats,
including URL fragments, mixed case, and multiple statuses. Ensures
transfer lock and hold detection is reliable.
"""

import pytest

from familiar.tools.advisor_tools import (
    _classify_epp_statuses,
    _normalize_epp_status,
)


class TestEppNormalization:
    """_normalize_epp_status must handle multiple input formats."""

    def test_standard_camelcase(self):
        assert _normalize_epp_status("clientTransferProhibited") == "clienttransferprohibited"

    def test_url_with_fragment(self):
        s = "https://icann.org/epp#clientTransferProhibited"
        assert _normalize_epp_status(s) == "clienttransferprohibited"

    def test_status_with_trailing_url(self):
        s = "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
        assert _normalize_epp_status(s) == "clienttransferprohibited"

    def test_already_lowercase(self):
        assert _normalize_epp_status("ok") == "ok"

    def test_whitespace_stripped(self):
        assert _normalize_epp_status("  clientHold  ") == "clienthold"

    def test_server_status(self):
        assert _normalize_epp_status("serverDeleteProhibited") == "serverdeleteprohibited"


class TestEppClassification:
    """_classify_epp_statuses must correctly categorize status codes."""

    def test_transfer_locked(self):
        result = _classify_epp_statuses(["clientTransferProhibited"])
        assert result["is_transfer_locked"] is True
        assert "clienttransferprohibited" in result["transfer_locks"]

    def test_server_transfer_lock(self):
        result = _classify_epp_statuses(["serverTransferProhibited"])
        assert result["is_transfer_locked"] is True

    def test_not_transfer_locked(self):
        result = _classify_epp_statuses(["ok"])
        assert result["is_transfer_locked"] is False
        assert result["transfer_locks"] == []

    def test_client_hold_detected(self):
        result = _classify_epp_statuses(["clientHold"])
        assert result["is_held"] is True
        assert "clienthold" in result["holds"]

    def test_server_hold_detected(self):
        result = _classify_epp_statuses(["serverHold"])
        assert result["is_held"] is True

    def test_no_holds_when_only_locks(self):
        result = _classify_epp_statuses([
            "clientTransferProhibited",
            "clientDeleteProhibited",
        ])
        assert result["is_held"] is False

    def test_all_locks_collected(self):
        statuses = [
            "clientTransferProhibited",
            "serverTransferProhibited",
            "clientDeleteProhibited",
            "serverDeleteProhibited",
            "clientUpdateProhibited",
            "serverUpdateProhibited",
            "clientRenewProhibited",
            "serverRenewProhibited",
        ]
        result = _classify_epp_statuses(statuses)
        assert len(result["all_locks"]) == 8
        assert result["is_transfer_locked"] is True

    def test_mixed_statuses_with_url_format(self):
        """Real-world WHOIS often returns statuses with ICANN URLs."""
        statuses = [
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "ok",
        ]
        result = _classify_epp_statuses(statuses)
        assert result["is_transfer_locked"] is True
        assert len(result["all_locks"]) == 2
        assert len(result["normalized"]) == 3

    def test_empty_statuses(self):
        result = _classify_epp_statuses([])
        assert result["is_transfer_locked"] is False
        assert result["is_held"] is False
        assert result["raw"] == []

    def test_raw_preserved(self):
        original = ["clientHold", "serverTransferProhibited"]
        result = _classify_epp_statuses(original)
        assert result["raw"] == original

    def test_normalized_output(self):
        result = _classify_epp_statuses(["ClientTransferProhibited"])
        assert result["normalized"] == ["clienttransferprohibited"]
