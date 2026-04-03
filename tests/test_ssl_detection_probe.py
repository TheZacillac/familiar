"""SSL detection probe — verifies every SSL finding path actually fires.

Each test targets one specific detection branch and asserts the exact finding
is produced.  This catches silent failures where the code path exists but
the condition never triggers due to data shape issues, default values, or
short-circuit logic.

Organized by detection category:
  1. Certificate validity detection
  2. Certificate expiry detection (every threshold boundary)
  3. Key strength detection (RSA sizes, EC, missing key_bits)
  4. Signature algorithm detection (SHA-1, MD5, mixed case)
  5. SAN / wildcard detection
  6. Issuer identification (all known CAs + edge cases)
  7. Chain parsing robustness
  8. No-cert / error paths
  9. http_security_scan SSL detection paths
  10. Cross-tool: same seer data → consistent findings
  11. Bugs found during audit
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.pentest_tools import http_security_scan, ssl_deep_scan


# ── Builders ──────────────────────────────────────────────────────────────

def _ssl(*, valid=True, days=90, key_type="EC", key_bits=256,
         sig="SHA256withECDSA", issuer="CN=Test CA", subject="test.com",
         sans=None, extra_chain=None, serial="ABC123DEF"):
    """Minimal seer.ssl() mock response."""
    leaf = {
        "key_type": key_type, "key_bits": key_bits,
        "signature_algorithm": sig, "issuer": issuer,
        "subject": subject, "is_ca": False,
        "valid_from": "2025-01-01", "valid_until": "2027-01-01",
        "serial_number": serial,
    }
    chain = [leaf]
    if extra_chain:
        chain.extend(extra_chain)
    return {
        "is_valid": valid, "days_until_expiry": days,
        "chain": chain, "san_names": sans or [subject],
        "protocol_version": "TLSv1.3",
    }


def _status(*, http=200, cert_valid=True, cert_days=90):
    return {
        "http_status": http,
        "certificate": {"is_valid": cert_valid, "days_until_expiry": cert_days},
    }


def _deep(domain="test.com", **ssl_kwargs):
    """Invoke ssl_deep_scan with controlled ssl data and return parsed result."""
    with patch("familiar.tools.pentest_tools.seer") as m:
        m.ssl.return_value = _ssl(**ssl_kwargs)
        return json.loads(ssl_deep_scan.invoke({"domain": domain}))


def _http(domain="test.com", ssl_kwargs=None, status_kwargs=None, caa=None):
    """Invoke http_security_scan with controlled data and return parsed result."""
    with patch("familiar.tools.pentest_tools.seer") as m:
        m.ssl.return_value = _ssl(**(ssl_kwargs or {}))
        m.status.return_value = _status(**(status_kwargs or {}))
        m.dig.return_value = caa or []
        return json.loads(http_security_scan.invoke({"domain": domain}))


def _find(result, *, text=None, severity=None, category=None):
    """Filter findings by optional text substring, severity, and category."""
    out = result.get("findings", [])
    if text:
        out = [f for f in out if text.lower() in f.get("finding", "").lower()]
    if severity:
        out = [f for f in out if f["severity"] == severity]
    if category:
        out = [f for f in out if f.get("category") == category]
    return out


# ══════════════════════════════════════════════════════════════════════════
#  1. Certificate validity detection
# ══════════════════════════════════════════════════════════════════════════

class TestValidityDetection:

    def test_deep_scan_detects_invalid_cert(self):
        r = _deep(valid=False)
        assert len(_find(r, text="invalid", severity="CRITICAL")) == 1

    def test_deep_scan_valid_cert_no_invalid_finding(self):
        r = _deep(valid=True)
        assert len(_find(r, text="invalid")) == 0

    def test_http_scan_detects_invalid_cert(self):
        r = _http(ssl_kwargs={"valid": False}, status_kwargs={"cert_valid": False})
        assert len(_find(r, text="invalid", severity="CRITICAL", category="SSL")) == 1

    def test_http_scan_no_ssl_data_server_up_is_critical(self):
        """Server reachable but seer.ssl returns None → CRITICAL."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = None
            m.status.return_value = _status()
            m.dig.return_value = []
            r = json.loads(http_security_scan.invoke({"domain": "t.com"}))
        assert len(_find(r, text="no ssl certificate", severity="CRITICAL")) == 1

    def test_http_scan_no_ssl_data_server_down_is_info(self):
        """Server unreachable AND seer.ssl None → INFO, not CRITICAL."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = None
            m.status.return_value = None
            m.dig.return_value = []
            r = json.loads(http_security_scan.invoke({"domain": "t.com"}))
        ssl_f = _find(r, category="SSL")
        assert all(f["severity"] != "CRITICAL" for f in ssl_f)
        assert any(f["severity"] == "INFO" for f in ssl_f)

    def test_deep_scan_seer_ssl_returns_none_unreachable(self):
        """No SSL data + no DNS records → INFO (not reachable), not CRITICAL."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = None
            m.dig.return_value = None
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert r.get("error")
        assert _find(r, severity="INFO")
        assert not _find(r, severity="CRITICAL")

    def test_deep_scan_seer_ssl_returns_none_reachable(self):
        """No SSL data but domain has routable IP → CRITICAL (genuine cert issue)."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = None
            m.dig.side_effect = lambda domain, rtype, *a: (
                [{"data": {"address": "93.184.216.34"}}] if rtype == "A" else []
            )
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert r.get("error")
        assert _find(r, severity="CRITICAL")

    def test_deep_scan_seer_ssl_raises_exception(self):
        """seer.ssl raises → safe_call returns None → same as no cert."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.side_effect = ConnectionError("refused")
            m.dig.return_value = None
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert r.get("error")


# ══════════════════════════════════════════════════════════════════════════
#  2. Certificate expiry detection — every boundary
# ══════════════════════════════════════════════════════════════════════════

class TestExpiryDetection:

    @pytest.mark.parametrize("days,sev,text_frag", [
        (-100, "CRITICAL", "expired"),
        (-1,   "CRITICAL", "expired"),
        (0,    "CRITICAL", "expires in 0"),
        (1,    "CRITICAL", "expires in 1"),
        (6,    "CRITICAL", "expires in 6"),
        (7,    "HIGH",     "expires in 7"),
        (15,   "HIGH",     "expires in 15"),
        (29,   "HIGH",     "expires in 29"),
        (30,   "MEDIUM",   "expires in 30"),
        (60,   "MEDIUM",   "expires in 60"),
        (89,   "MEDIUM",   "expires in 89"),
    ])
    def test_deep_scan_expiry(self, days, sev, text_frag):
        r = _deep(days=days)
        matches = _find(r, text=text_frag, severity=sev)
        assert len(matches) == 1, f"Expected {sev} finding with '{text_frag}' for {days}d, got {[f['finding'] for f in r['findings']]}"

    def test_deep_scan_90_days_no_expiry_finding(self):
        r = _deep(days=90)
        assert len(_find(r, text="expire")) == 0

    def test_deep_scan_365_days_no_expiry_finding(self):
        r = _deep(days=365)
        assert len(_find(r, text="expire")) == 0

    def test_deep_scan_none_days_no_expiry_finding(self):
        ssl = _ssl()
        ssl["days_until_expiry"] = None
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert len(_find(r, text="expire")) == 0

    def test_deep_scan_invalid_cert_suppresses_expiry(self):
        """is_valid=False should suppress expiry findings."""
        r = _deep(valid=False, days=-30)
        assert len(_find(r, text="invalid")) == 1
        assert len(_find(r, text="expire")) == 0

    def test_http_scan_expiry_0_days_critical(self):
        """days_left=0 → http_security_scan's `else` branch → 'has expired'."""
        r = _http(ssl_kwargs={"days": 0}, status_kwargs={"cert_days": 0})
        assert _find(r, text="expired", severity="CRITICAL", category="SSL")

    def test_http_scan_expiry_negative_critical(self):
        r = _http(ssl_kwargs={"days": -5}, status_kwargs={"cert_days": -5})
        assert _find(r, text="expired", severity="CRITICAL", category="SSL")


# ══════════════════════════════════════════════════════════════════════════
#  3. Key strength detection
# ══════════════════════════════════════════════════════════════════════════

class TestKeyStrengthDetection:

    def test_rsa_512_critical(self):
        r = _deep(key_type="RSA", key_bits=512, sig="SHA256withRSA")
        assert _find(r, text="512", severity="CRITICAL")

    def test_rsa_1024_critical(self):
        r = _deep(key_type="RSA", key_bits=1024, sig="SHA256withRSA")
        assert _find(r, text="1024", severity="CRITICAL")

    def test_rsa_2048_info(self):
        r = _deep(key_type="RSA", key_bits=2048, sig="SHA256withRSA")
        assert _find(r, text="2048", severity="INFO")

    def test_rsa_4096_no_key_finding(self):
        """4096-bit RSA should produce no key-related finding (> minimum)."""
        r = _deep(key_type="RSA", key_bits=4096, sig="SHA256withRSA")
        # Should NOT get a key size finding — 4096 exceeds minimum
        key_f = [f for f in r["findings"]
                 if "rsa" in f["finding"].lower() and "bit" in f["finding"].lower()]
        assert len(key_f) == 0

    def test_ec_256_info(self):
        r = _deep(key_type="EC", key_bits=256)
        assert _find(r, text="ecdsa", severity="INFO")

    def test_ec_none_bits_still_detected(self):
        """EC with key_bits=None should still produce INFO finding."""
        r = _deep(key_type="EC", key_bits=None)
        assert _find(r, text="ecdsa", severity="INFO")

    def test_rsa_none_bits_no_finding(self):
        """RSA with key_bits=None should not produce key finding."""
        r = _deep(key_type="RSA", key_bits=None, sig="SHA256withRSA")
        key_f = [f for f in r["findings"]
                 if "rsa" in f["finding"].lower() and "bit" in f["finding"].lower()]
        assert len(key_f) == 0

    def test_unknown_key_type_no_finding(self):
        r = _deep(key_type="DSA", key_bits=2048, sig="SHA256withDSA")
        key_f = [f for f in r["findings"]
                 if "key" in f["finding"].lower() and ("rsa" in f["finding"].lower() or "ecdsa" in f["finding"].lower())]
        assert len(key_f) == 0

    def test_http_scan_weak_rsa_critical(self):
        r = _http(ssl_kwargs={"key_type": "RSA", "key_bits": 1024, "sig": "SHA256withRSA"})
        assert _find(r, text="1024", severity="CRITICAL", category="SSL")

    def test_http_scan_strong_rsa_passes(self):
        r = _http(ssl_kwargs={"key_type": "RSA", "key_bits": 4096, "sig": "SHA256withRSA"})
        assert not _find(r, text="weak", category="SSL")


# ══════════════════════════════════════════════════════════════════════════
#  4. Signature algorithm detection
# ══════════════════════════════════════════════════════════════════════════

class TestSignatureDetection:

    def test_sha1_detected_deep(self):
        r = _deep(sig="sha-1WithRSAEncryption", key_type="RSA", key_bits=2048)
        assert _find(r, text="sha-1", severity="CRITICAL")

    def test_sha1_mixed_case_detected(self):
        r = _deep(sig="SHA-1WithRSAEncryption", key_type="RSA", key_bits=2048)
        assert _find(r, text="sha-1", severity="CRITICAL")

    def test_md5_detected_deep(self):
        r = _deep(sig="md5WithRSAEncryption", key_type="RSA", key_bits=2048)
        assert _find(r, text="md5", severity="CRITICAL")

    def test_sha256_clean(self):
        r = _deep(sig="SHA256withRSA", key_type="RSA", key_bits=4096)
        assert not _find(r, text="sha-1")
        assert not _find(r, text="md5")

    def test_sha384_clean(self):
        r = _deep(sig="SHA384withECDSA")
        assert not _find(r, text="sha-1")

    def test_http_scan_sha1_detected(self):
        r = _http(ssl_kwargs={"sig": "sha-1WithRSA", "key_type": "RSA", "key_bits": 2048})
        assert _find(r, text="sha-1", severity="HIGH", category="SSL")

    def test_empty_sig_algo_no_crash(self):
        r = _deep(sig="", key_type="RSA", key_bits=2048)
        assert not _find(r, text="sha-1")
        assert not _find(r, text="md5")

    def test_none_sig_algo_no_crash(self):
        ssl = _ssl(key_type="RSA", key_bits=2048)
        ssl["chain"][0]["signature_algorithm"] = None
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        # Should not crash and should not flag sha-1 or md5
        assert not _find(r, text="sha-1")


# ══════════════════════════════════════════════════════════════════════════
#  5. SAN / wildcard detection
# ══════════════════════════════════════════════════════════════════════════

class TestSanDetection:

    def test_wildcard_detected(self):
        r = _deep(sans=["*.example.com", "example.com"])
        assert r["san_analysis"]["has_wildcard"] is True
        assert _find(r, text="wildcard", severity="MEDIUM")

    def test_no_wildcard_no_finding(self):
        r = _deep(sans=["example.com", "www.example.com"])
        assert r["san_analysis"]["has_wildcard"] is False
        assert not _find(r, text="wildcard")

    def test_multi_domain_4_detected(self):
        r = _deep(sans=["a.com", "b.com", "c.com", "d.com"])
        assert _find(r, text="distinct domains", severity="LOW")

    def test_multi_domain_3_not_triggered(self):
        r = _deep(sans=["a.com", "b.com", "c.com"])
        assert not _find(r, text="distinct domains")

    def test_sans_capped_at_20_display(self):
        r = _deep(sans=[f"s{i}.example.com" for i in range(50)])
        assert len(r["san_analysis"]["names"]) == 20
        assert r["san_analysis"]["count"] == 50

    def test_empty_sans(self):
        ssl = _ssl()
        ssl["san_names"] = []
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert r["san_analysis"]["count"] == 0
        assert not _find(r, text="wildcard")


# ══════════════════════════════════════════════════════════════════════════
#  6. Issuer identification — all known CAs
# ══════════════════════════════════════════════════════════════════════════

class TestIssuerDetection:

    @pytest.mark.parametrize("issuer_str,expected_provider", [
        ("CN=R3, O=Let's Encrypt, C=US", "Let's Encrypt"),
        ("CN=E1, O=Let's Encrypt", "Let's Encrypt"),
        ("CN=DigiCert Global G2", "DigiCert"),
        ("CN=Sectigo RSA DV", "Sectigo (formerly Comodo)"),
        ("CN=Comodo RSA CA", "Sectigo (formerly Comodo)"),
        ("CN=GlobalSign R3", "GlobalSign"),
        ("CN=Starfield Secure CA - G2", "GoDaddy"),  # starfield triggers godaddy
        ("CN=Amazon RSA 2048 M01, O=Amazon", "AWS Certificate Manager"),
        ("CN=GTS CA 1P5, O=Google Trust Services", "Google Trust Services"),
        ("CN=Cloudflare Inc ECC CA-3", "Cloudflare"),
        ("CN=ZeroSSL RSA Domain Secure Site CA", "ZeroSSL"),
    ])
    def test_known_issuer(self, issuer_str, expected_provider):
        r = _deep(issuer=issuer_str)
        assert r["issuer"].get("provider") == expected_provider

    def test_unknown_issuer_no_provider_key(self):
        r = _deep(issuer="CN=Mystery CA, O=Unknown Corp")
        assert "provider" not in r["issuer"]
        assert r["issuer"]["issuer"] == "CN=Mystery CA, O=Unknown Corp"

    def test_empty_issuer_no_crash(self):
        r = _deep(issuer="")
        assert r["issuer"] == {"issuer": ""}

    def test_godaddy_with_space_not_matched(self):
        """Known gap: 'Go Daddy' (with space) doesn't match 'godaddy' pattern."""
        r = _deep(issuer="CN=Go Daddy Secure Certificate Authority - G2")
        # This is a documented code gap — the code checks for "godaddy" (no space)
        assert "provider" not in r["issuer"]


# ══════════════════════════════════════════════════════════════════════════
#  7. Chain parsing robustness
# ══════════════════════════════════════════════════════════════════════════

class TestChainParsing:

    def test_empty_chain_no_key_findings(self):
        ssl = _ssl()
        ssl["chain"] = []
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        key_f = [f for f in r["findings"] if "rsa" in f["finding"].lower() or "ecdsa" in f["finding"].lower()]
        assert len(key_f) == 0

    def test_chain_with_non_dict_entries_skipped(self):
        ssl = _ssl()
        ssl["chain"] = ["garbage", None, 42]
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert r["chain"] == []

    def test_chain_leaf_missing_key_type(self):
        ssl = _ssl()
        del ssl["chain"][0]["key_type"]
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        # key_type defaults to "" — should not match RSA or EC branches
        key_f = [f for f in r["findings"] if "rsa" in f["finding"].lower() or "ecdsa" in f["finding"].lower()]
        assert len(key_f) == 0

    def test_chain_positions_correct(self):
        ssl = _ssl()
        ssl["chain"] = [
            {"subject": "leaf.com", "issuer": "Intermediate", "key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256"},
            {"subject": "Intermediate", "issuer": "Root CA"},
            {"subject": "Root CA", "issuer": "Root CA"},
        ]
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            r = json.loads(ssl_deep_scan.invoke({"domain": "t.com"}))
        assert [c["position"] for c in r["chain"]] == ["leaf", "intermediate", "root"]

    def test_http_scan_chain_leaf_used(self):
        """http_security_scan checks chain[0] for key strength."""
        r = _http(ssl_kwargs={"key_type": "RSA", "key_bits": 1024, "sig": "SHA256withRSA"})
        assert _find(r, text="1024", severity="CRITICAL")

    def test_http_scan_empty_chain_no_key_finding(self):
        ssl = _ssl()
        ssl["chain"] = []
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = ssl
            m.status.return_value = _status()
            m.dig.return_value = []
            r = json.loads(http_security_scan.invoke({"domain": "t.com"}))
        key_f = _find(r, text="weak", category="SSL")
        assert len(key_f) == 0


# ══════════════════════════════════════════════════════════════════════════
#  8. http_security_scan HTTPS enforcement detection
# ══════════════════════════════════════════════════════════════════════════

class TestHttpsEnforcementDetection:

    def test_valid_cert_good_status_passes(self):
        r = _http(status_kwargs={"cert_valid": True, "http": 200})
        https_f = _find(r, text="no valid https", category="HTTPS")
        assert len(https_f) == 0

    def test_invalid_cert_flags_https(self):
        r = _http(status_kwargs={"cert_valid": False, "http": 200},
                  ssl_kwargs={"valid": False})
        https_f = _find(r, text="no valid https", category="HTTPS")
        assert len(https_f) == 1
        assert https_f[0]["severity"] == "HIGH"

    def test_http_400_flags_info(self):
        r = _http(status_kwargs={"http": 404, "cert_valid": True})
        http_f = _find(r, text="http status 404", category="HTTP")
        assert len(http_f) == 1
        assert http_f[0]["severity"] == "INFO"


# ══════════════════════════════════════════════════════════════════════════
#  9. http_security_scan expiry — thresholds differ from ssl_deep_scan
# ══════════════════════════════════════════════════════════════════════════

class TestHttpExpiryThresholds:
    """http_security_scan uses >=30 pass, 7-29 HIGH, 1-6 CRITICAL, <=0 CRITICAL."""

    def test_30_days_passes(self):
        r = _http(ssl_kwargs={"days": 30})
        expiry_f = _find(r, text="expires", category="SSL")
        assert len(expiry_f) == 0

    def test_29_days_high(self):
        r = _http(ssl_kwargs={"days": 29})
        assert _find(r, text="expires in 29", severity="HIGH", category="SSL")

    def test_7_days_high(self):
        r = _http(ssl_kwargs={"days": 7})
        assert _find(r, text="expires in 7", severity="HIGH", category="SSL")

    def test_6_days_critical(self):
        r = _http(ssl_kwargs={"days": 6})
        assert _find(r, text="expires in 6", severity="CRITICAL", category="SSL")

    def test_0_days_critical(self):
        r = _http(ssl_kwargs={"days": 0})
        assert _find(r, text="expired", severity="CRITICAL", category="SSL")


# ══════════════════════════════════════════════════════════════════════════
#  10. Cross-tool consistency for same input
# ══════════════════════════════════════════════════════════════════════════

class TestCrossToolConsistency:
    """Same SSL condition must produce equivalent severity across tools."""

    @pytest.mark.parametrize("condition,deep_text,http_text", [
        ({"valid": False}, "invalid", "invalid"),
        ({"days": -10}, "expired", "expired"),
        ({"key_type": "RSA", "key_bits": 1024, "sig": "SHA256withRSA"}, "1024", "1024"),
    ])
    def test_severity_matches(self, condition, deep_text, http_text):
        deep = _deep(**condition)
        http = _http(ssl_kwargs=condition)
        deep_f = _find(deep, text=deep_text)
        http_f = _find(http, text=http_text)
        assert deep_f, f"ssl_deep_scan did not detect '{deep_text}' for {condition}"
        assert http_f, f"http_security_scan did not detect '{http_text}' for {condition}"
        # Both should be CRITICAL (or at least same level)
        assert deep_f[0]["severity"] in ("CRITICAL", "HIGH")
        assert http_f[0]["severity"] in ("CRITICAL", "HIGH")


# ══════════════════════════════════════════════════════════════════════════
#  11. Known bugs / gaps found during audit
# ══════════════════════════════════════════════════════════════════════════

class TestKnownGaps:

    def test_godaddy_go_daddy_not_matched(self):
        """Real GoDaddy certs use 'Go Daddy' (space) but code checks 'godaddy'."""
        r = _deep(issuer="CN=Go Daddy Secure Certificate Authority - G2")
        assert "provider" not in r["issuer"]

    def test_godaddy_without_space_matched(self):
        """If issuer string contains 'godaddy' (no space), it IS matched."""
        r = _deep(issuer="CN=GoDaddy Secure Certificate Authority - G2")
        assert r["issuer"]["provider"] == "GoDaddy"

    def test_starfield_matches_godaddy(self):
        """Starfield (GoDaddy subsidiary) should match."""
        r = _deep(issuer="CN=Starfield Secure Certificate Authority - G2")
        assert r["issuer"]["provider"] == "GoDaddy"

    def test_http_scan_invalid_cert_but_valid_expiry_both_reported(self):
        """http_security_scan does NOT suppress expiry when cert is invalid
        (unlike ssl_deep_scan which does). Verify both findings fire."""
        r = _http(ssl_kwargs={"valid": False, "days": 5})
        invalid_f = _find(r, text="invalid", severity="CRITICAL", category="SSL")
        expiry_f = _find(r, text="expires", severity="CRITICAL", category="SSL")
        # http_security_scan checks is_valid and days_left independently
        assert len(invalid_f) == 1
        # Note: http_security_scan's expiry check has no is_valid guard,
        # so it WILL report expiry even for invalid certs
        assert len(expiry_f) == 1

    def test_deep_scan_rsa_4096_no_finding_but_http_passes_check(self):
        """RSA 4096 should pass in both tools — no CRITICAL or WARNING."""
        deep = _deep(key_type="RSA", key_bits=4096, sig="SHA256withRSA")
        http = _http(ssl_kwargs={"key_type": "RSA", "key_bits": 4096, "sig": "SHA256withRSA"})
        # Neither should flag the key
        deep_key = [f for f in deep["findings"] if "weak" in f["finding"].lower()]
        http_key = [f for f in http["findings"] if "weak" in f["finding"].lower()]
        assert len(deep_key) == 0
        assert len(http_key) == 0

    def test_http_scan_sha1_is_high_not_critical(self):
        """http_security_scan assigns HIGH to SHA-1, but ssl_deep_scan assigns CRITICAL.
        This is an intentional severity difference between tools."""
        http = _http(ssl_kwargs={"sig": "sha-1WithRSA", "key_type": "RSA", "key_bits": 2048})
        deep = _deep(sig="sha-1WithRSA", key_type="RSA", key_bits=2048)
        http_sha1 = _find(http, text="sha-1")
        deep_sha1 = _find(deep, text="sha-1")
        assert http_sha1[0]["severity"] == "HIGH"
        assert deep_sha1[0]["severity"] == "CRITICAL"

    def test_http_scan_md5_not_checked(self):
        """http_security_scan only checks for sha-1, NOT md5.
        Verify md5 goes undetected in http scan (potential gap)."""
        r = _http(ssl_kwargs={"sig": "md5WithRSA", "key_type": "RSA", "key_bits": 2048})
        md5_f = _find(r, text="md5", category="SSL")
        # http_security_scan's code: `if sig_algo and "sha-1" in sig_algo.lower()`
        # There is NO md5 check in http_security_scan — only in ssl_deep_scan
        assert len(md5_f) == 0  # Confirms the gap

    def test_http_scan_key_check_condition(self):
        """http_security_scan's key check: `if key_bits or key_type == "EC"`.
        EC with no key_bits still triggers the check (passes), but RSA with
        no key_bits does NOT trigger the check (skipped silently)."""
        # EC with no bits → still gets a checks_total increment
        r = _http(ssl_kwargs={"key_type": "EC", "key_bits": None})
        assert r["checks_passed"] >= 1  # EC passes the strength check

        # RSA with no bits → check is skipped entirely
        r = _http(ssl_kwargs={"key_type": "RSA", "key_bits": None, "sig": "SHA256withRSA"})
        weak_f = _find(r, text="weak", category="SSL")
        assert len(weak_f) == 0  # No finding because check was skipped


# ══════════════════════════════════════════════════════════════════════════
#  12. www subdomain certificate comparison (_compare_www_cert)
# ══════════════════════════════════════════════════════════════════════════

_ROUTABLE_A = [{"data": {"address": "93.184.216.34"}}]
_REACH_OK = {"reachable": True, "reason": None, "has_records": True, "ips": ["93.184.216.34"]}
_REACH_NONE = {"reachable": False, "reason": "no A or AAAA records", "has_records": False, "ips": []}
_REACH_UNROUTABLE = {"reachable": False, "reason": "resolves to non-routable IP(s): 0.0.0.0", "has_records": True, "ips": ["0.0.0.0"]}


def _invoke_deep_with_sides(root_ssl, www_ssl, root_a=None, www_a=None):
    """Invoke ssl_deep_scan with independent root/www SSL and DNS mocks."""
    with patch("familiar.tools.pentest_tools.seer") as m:
        def ssl_side(domain):
            return www_ssl if domain.startswith("www.") else root_ssl
        m.ssl.side_effect = ssl_side
        m.dig.side_effect = lambda domain, rtype, *a: (
            (www_a if domain.startswith("www.") else root_a)
            if rtype in ("A", "AAAA") else []
        )
        return json.loads(ssl_deep_scan.invoke({"domain": "example.com"}))


class TestWwwComparisonBothValid:
    """Both root and www present valid certificates."""

    def test_same_cert_shared(self):
        """Same serial → reports shared certificate, no findings."""
        cert = _ssl(serial="SERIAL-SAME")
        r = _invoke_deep_with_sides(cert, cert, _ROUTABLE_A, _ROUTABLE_A)
        assert r["www_comparison"]["same_certificate"] is True
        assert "share the same" in r["www_comparison"]["summary"]
        assert not _find(r, text="different CAs")

    def test_different_certs_same_ca(self):
        """Different serials, same CA → notes difference, no LOW finding."""
        root = _ssl(serial="SERIAL-A", issuer="CN=Let's Encrypt")
        www = _ssl(serial="SERIAL-B", issuer="CN=Let's Encrypt")
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        assert r["www_comparison"]["same_certificate"] is False
        assert "different certificates" in r["www_comparison"]["summary"]
        assert not _find(r, text="different CAs")

    def test_different_certs_different_ca(self):
        """Different serials + different CAs → LOW finding."""
        root = _ssl(serial="SERIAL-A", issuer="CN=Let's Encrypt")
        www = _ssl(serial="SERIAL-B", issuer="CN=DigiCert")
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        assert r["www_comparison"]["same_certificate"] is False
        ca_findings = _find(r, text="different CAs")
        assert len(ca_findings) == 1
        assert ca_findings[0]["severity"] == "LOW"

    def test_missing_serial_reports_unknown(self):
        """No serial_number on certs → same_certificate is None, not False."""
        root = _ssl(serial=None)
        www = _ssl(serial=None)
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        assert r["www_comparison"]["same_certificate"] is None
        assert "could not compare" in r["www_comparison"]["summary"]
        assert not _find(r, text="different CAs")


class TestWwwComparisonMismatch:
    """One side valid, the other not."""

    def test_root_valid_www_invalid_cert(self):
        """Root OK, www presents an invalid cert → HIGH."""
        root = _ssl(valid=True)
        www = _ssl(valid=False)
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        f = _find(r, text="www.example.com certificate is invalid")
        assert len(f) == 1
        assert f[0]["severity"] == "HIGH"

    def test_root_valid_www_no_cert_reachable(self):
        """Root OK, www reachable but no cert → HIGH."""
        root = _ssl(valid=True)
        r = _invoke_deep_with_sides(root, None, _ROUTABLE_A, _ROUTABLE_A)
        f = _find(r, text="www.example.com has no SSL")
        assert len(f) == 1
        assert f[0]["severity"] == "HIGH"

    def test_root_valid_www_no_cert_unreachable(self):
        """Root OK, www not reachable → no HIGH finding (not a cert issue)."""
        root = _ssl(valid=True)
        r = _invoke_deep_with_sides(root, None, _ROUTABLE_A, None)
        f = _find(r, severity="HIGH")
        assert len(f) == 0
        assert "not reachable" in r["www_comparison"]["summary"]

    def test_www_valid_root_invalid_cert(self):
        """www OK, root presents an invalid cert → HIGH."""
        root = _ssl(valid=False)
        www = _ssl(valid=True)
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        f = _find(r, text="root domain example.com certificate is invalid")
        assert len(f) == 1
        assert f[0]["severity"] == "HIGH"

    def test_www_valid_root_no_cert_reachable(self):
        """www OK, root reachable but no cert → CRITICAL from main path."""
        r = _invoke_deep_with_sides(None, _ssl(valid=True), _ROUTABLE_A, _ROUTABLE_A)
        f = _find(r, severity="CRITICAL")
        assert len(f) == 1  # Main ssl_deep_scan body handles this

    def test_www_valid_root_no_cert_unreachable(self):
        """www OK, root not reachable → INFO (not a cert issue)."""
        r = _invoke_deep_with_sides(None, _ssl(valid=True), None, _ROUTABLE_A)
        f = _find(r, severity="INFO")
        assert len(f) == 1
        assert not _find(r, severity="CRITICAL")


class TestWwwComparisonNeitherValid:
    """Neither side has a valid cert — the else branch."""

    def test_both_invalid_certs(self):
        """Both present invalid certs → summary notes both broken."""
        root = _ssl(valid=False)
        www = _ssl(valid=False)
        r = _invoke_deep_with_sides(root, www, _ROUTABLE_A, _ROUTABLE_A)
        assert "Neither" in r["www_comparison"]["summary"]

    def test_root_invalid_www_no_cert_reachable(self):
        """Root has invalid cert, www is reachable but has no cert → MEDIUM for www."""
        root = _ssl(valid=False)
        r = _invoke_deep_with_sides(root, None, _ROUTABLE_A, _ROUTABLE_A)
        f = _find(r, text="www.example.com is reachable but has no certificate")
        assert len(f) == 1
        assert f[0]["severity"] == "MEDIUM"

    def test_root_invalid_www_no_cert_unreachable(self):
        """Root has invalid cert, www not reachable → no extra www finding."""
        root = _ssl(valid=False)
        r = _invoke_deep_with_sides(root, None, _ROUTABLE_A, None)
        f = _find(r, text="www.example.com is reachable")
        assert len(f) == 0


class TestWwwComparisonUnreachable:
    """Unreachable domains should not generate false cert findings."""

    def test_both_unreachable(self):
        """Neither side reachable → INFO, no HIGH/CRITICAL from www comparison."""
        r = _invoke_deep_with_sides(None, None, None, None)
        assert not _find(r, severity="HIGH")
        assert not _find(r, severity="CRITICAL")

    def test_non_routable_ip_not_flagged_as_cert_issue(self):
        """Domain resolves to 0.0.0.0 → INFO, not CRITICAL."""
        with patch("familiar.tools.pentest_tools.seer") as m:
            m.ssl.return_value = None
            m.dig.side_effect = lambda domain, rtype, *a: (
                [{"data": {"address": "0.0.0.0"}}] if rtype == "A" else []
            )
            r = json.loads(ssl_deep_scan.invoke({"domain": "parked.com"}))
        assert r.get("error")
        assert _find(r, severity="INFO")
        assert not _find(r, severity="CRITICAL")


# ══════════════════════════════════════════════════════════════════════════
#  13. DNS resolution mismatch detection
# ══════════════════════════════════════════════════════════════════════════

class TestResolutionMismatch:
    """seer.ssl and seer.dig can use different resolvers, producing different
    IPs for the same domain.  When dig shows routable IPs but ssl fails with
    a non-routable address error, the report must flag the mismatch rather
    than blindly reporting CRITICAL no-cert."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_ssl_sees_unroutable_dig_sees_routable(self, m):
        """The markmonitor.com scenario: dig → Cloudflare IPs, ssl → 0.0.0.0."""
        m.ssl.side_effect = RuntimeError(
            "cannot connect to example.com: 0.0.0.0 — unspecified address (0.0.0.0) "
            "— domain has no routable IP"
        )
        m.dig.side_effect = lambda domain, rtype, *a: (
            [{"data": {"address": "172.64.148.104"}},
             {"data": {"address": "104.18.39.152"}}]
            if rtype == "A" else []
        )
        r = json.loads(ssl_deep_scan.invoke({"domain": "example.com"}))
        assert r["error"] == "DNS resolution mismatch"
        assert "172.64.148.104" in r["detail"]
        # Must NOT be CRITICAL — we genuinely don't know if there's a cert
        assert not _find(r, severity="CRITICAL")
        # Should be HIGH with "inconclusive"
        f = _find(r, text="inconclusive")
        assert len(f) == 1
        assert f[0]["severity"] == "HIGH"
        assert "ssl_error" in r

    @patch("familiar.tools.pentest_tools.seer")
    def test_ssl_sees_unroutable_dig_also_unroutable(self, m):
        """Both agree domain is unroutable → INFO, not mismatch."""
        m.ssl.side_effect = RuntimeError(
            "cannot connect: unspecified address (0.0.0.0)"
        )
        m.dig.side_effect = lambda domain, rtype, *a: (
            [{"data": {"address": "0.0.0.0"}}] if rtype == "A" else []
        )
        r = json.loads(ssl_deep_scan.invoke({"domain": "parked.com"}))
        assert r["error"] == "Domain is not reachable"
        assert _find(r, severity="INFO")
        assert not _find(r, text="mismatch")

    @patch("familiar.tools.pentest_tools.seer")
    def test_ssl_connection_refused_not_mismatch(self, m):
        """SSL fails with connection refused (not a DNS issue) → CRITICAL."""
        m.ssl.side_effect = RuntimeError("connection refused on port 443")
        m.dig.side_effect = lambda domain, rtype, *a: (
            [{"data": {"address": "93.184.216.34"}}] if rtype == "A" else []
        )
        r = json.loads(ssl_deep_scan.invoke({"domain": "example.com"}))
        assert r["error"] == "Could not retrieve SSL certificate"
        f = _find(r, severity="CRITICAL")
        assert len(f) == 1
        assert "connection refused" in f[0]["detail"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_resolution_mismatch_in_comparison(self, m):
        """Root cert valid, www has resolution mismatch → no false HIGH for www."""
        root_cert = _ssl(valid=True)
        def ssl_side(domain):
            if domain.startswith("www."):
                raise RuntimeError("cannot connect: unspecified address (0.0.0.0)")
            return root_cert
        m.ssl.side_effect = ssl_side
        m.dig.side_effect = lambda domain, rtype, *a: (
            [{"data": {"address": "93.184.216.34"}}]
            if rtype == "A" else []
        )
        r = json.loads(ssl_deep_scan.invoke({"domain": "example.com"}))
        # Root cert analysis should succeed
        assert r.get("is_valid") is True
        # www comparison should note the mismatch, not flag HIGH
        assert "mismatch" in r["www_comparison"]["summary"].lower()
        www_findings = _find(r, text="www.example.com")
        high_www = [f for f in www_findings if f["severity"] == "HIGH"]
        assert len(high_www) == 0
