"""Tests for the infrastructure_recon tool in familiar.tools.pentest_tools.

Validates CDN/WAF detection, DNS provider identification, hosting provider
mapping, IPv6 detection, email infrastructure recognition, technology signal
extraction from TXT records, SSL certificate signals, web server parking
detection, and edge-case resilience.
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.pentest_tools import infrastructure_recon


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_a(address: str) -> dict:
    return {"data": {"address": address}}


def _make_aaaa(address: str) -> dict:
    return {"data": {"address": address}}


def _make_ns(nameserver: str) -> dict:
    return {"data": {"nameserver": nameserver}}


def _make_cname(target: str) -> dict:
    return {"data": {"target": target}}


def _make_mx(exchange: str, preference: int = 10) -> dict:
    return {"data": {"exchange": exchange, "preference": preference}}


def _make_txt(text: str) -> dict:
    return {"data": {"text": text}}


def _invoke(domain: str = "example.com") -> dict:
    """Invoke infrastructure_recon and return parsed JSON."""
    raw = infrastructure_recon.invoke({"domain": domain})
    return json.loads(raw)


def _dig_router(**record_map):
    """Return a side_effect callable that routes seer.dig(domain, rtype) calls.

    Usage::

        mock_seer.dig.side_effect = _dig_router(A=[...], MX=[...])

    Unspecified record types return ``None``.
    """
    def _route(domain, rtype):
        return record_map.get(rtype)
    return _route


def _setup_mock(mock_seer, *, a=None, aaaa=None, ns=None, cname=None,
                mx=None, txt=None, status=None, ssl=None):
    """Configure *mock_seer* with sensible defaults for all calls.

    Any parameter left as ``None`` will return ``None`` from the mock.
    """
    mock_seer.dig.side_effect = _dig_router(
        A=a, AAAA=aaaa, NS=ns, CNAME=cname, MX=mx, TXT=txt,
    )
    mock_seer.status.return_value = status
    mock_seer.ssl.return_value = ssl


# ---------------------------------------------------------------------------
# CDN / WAF Detection
# ---------------------------------------------------------------------------


class TestCdnWafDetection:
    """CDN and WAF provider detection from CNAME and IP signals."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_cloudfront_cname_detected(self, mock_seer):
        """1. CNAME to cloudfront.net detects AWS CloudFront."""
        _setup_mock(mock_seer, cname=[_make_cname("d1234.cloudfront.net")])
        result = _invoke()
        assert "AWS CloudFront" in result["cdn_waf"]["detected"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_cloudflare_cname_detected(self, mock_seer):
        """2. CNAME to cloudflare.net detects Cloudflare."""
        _setup_mock(mock_seer, cname=[_make_cname("cdn.cloudflare.net")])
        result = _invoke()
        assert "Cloudflare" in result["cdn_waf"]["detected"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_cloudflare_ip_range_detected(self, mock_seer):
        """3. IP in Cloudflare range (104.16.x.x) detects Cloudflare."""
        _setup_mock(mock_seer, a=[_make_a("104.16.5.100")])
        result = _invoke()
        assert "Cloudflare" in result["cdn_waf"]["detected"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_cdn_signals_empty(self, mock_seer):
        """4. No CNAME, no CDN IPs -> empty detected list."""
        _setup_mock(mock_seer, a=[_make_a("192.168.1.1")])
        result = _invoke()
        assert result["cdn_waf"]["detected"] == []

    @patch("familiar.tools.pentest_tools.seer")
    def test_duplicate_cdn_signals_deduplicated(self, mock_seer):
        """5. Both CNAME and IP pointing to Cloudflare -> single entry."""
        _setup_mock(
            mock_seer,
            cname=[_make_cname("cdn.cloudflare.net")],
            a=[_make_a("104.16.5.100")],
        )
        result = _invoke()
        cloudflare_count = result["cdn_waf"]["detected"].count("Cloudflare")
        assert cloudflare_count == 1


# ---------------------------------------------------------------------------
# DNS Provider Detection
# ---------------------------------------------------------------------------


class TestDnsProviderDetection:
    """DNS provider identification from NS records."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_cloudflare_dns(self, mock_seer):
        """6. NS containing 'cloudflare' -> Cloudflare DNS."""
        _setup_mock(mock_seer, ns=[
            _make_ns("art.ns.cloudflare.com"),
            _make_ns("pat.ns.cloudflare.com"),
        ])
        result = _invoke()
        assert "Cloudflare DNS" in result["dns_provider"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_aws_route53(self, mock_seer):
        """7. NS containing 'awsdns' -> AWS Route 53."""
        _setup_mock(mock_seer, ns=[
            _make_ns("ns-123.awsdns-45.com"),
            _make_ns("ns-456.awsdns-67.net"),
        ])
        result = _invoke()
        assert "AWS Route 53" in result["dns_provider"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_azure_dns(self, mock_seer):
        """8. NS containing 'azure-dns' -> Azure DNS."""
        _setup_mock(mock_seer, ns=[_make_ns("ns1-01.azure-dns.com")])
        result = _invoke()
        assert "Azure DNS" in result["dns_provider"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_godaddy_dns(self, mock_seer):
        """9. NS containing 'domaincontrol' -> GoDaddy DNS."""
        _setup_mock(mock_seer, ns=[_make_ns("ns51.domaincontrol.com")])
        result = _invoke()
        assert "GoDaddy DNS" in result["dns_provider"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_namecheap_dns(self, mock_seer):
        """10. NS containing 'registrar-servers' -> Namecheap DNS."""
        _setup_mock(mock_seer, ns=[_make_ns("dns1.registrar-servers.com")])
        result = _invoke()
        assert "Namecheap DNS" in result["dns_provider"]


# ---------------------------------------------------------------------------
# Hosting Provider Identification
# ---------------------------------------------------------------------------


class TestHostingProviderIdentification:
    """Hosting provider detection from A record IP addresses."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_aws_ip(self, mock_seer):
        """11. A record 54.200.1.1 -> AWS in hosting providers."""
        _setup_mock(mock_seer, a=[_make_a("54.200.1.1")])
        result = _invoke()
        assert "AWS" in result["hosting"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_cloudflare_ip(self, mock_seer):
        """12. A record 104.21.50.1 -> Cloudflare in hosting providers."""
        _setup_mock(mock_seer, a=[_make_a("104.21.50.1")])
        result = _invoke()
        assert "Cloudflare" in result["hosting"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_unknown_ip_no_provider(self, mock_seer):
        """13. Unknown IP -> no hosting provider listed."""
        _setup_mock(mock_seer, a=[_make_a("192.168.1.1")])
        result = _invoke()
        assert result["hosting"]["providers"] == []

    @patch("familiar.tools.pentest_tools.seer")
    def test_same_provider_deduplicated(self, mock_seer):
        """14. Multiple IPs from same provider -> deduplicated."""
        _setup_mock(mock_seer, a=[
            _make_a("54.200.1.1"),
            _make_a("54.201.2.2"),
        ])
        result = _invoke()
        assert result["hosting"]["providers"].count("AWS") == 1


# ---------------------------------------------------------------------------
# IPv6 Detection
# ---------------------------------------------------------------------------


class TestIpv6Detection:
    """IPv6 presence and count from AAAA records."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_has_ipv6_true(self, mock_seer):
        """15. AAAA records present -> has_ipv6: true with accurate count."""
        _setup_mock(mock_seer, aaaa=[
            _make_aaaa("2001:db8::1"),
            _make_aaaa("2001:db8::2"),
        ])
        result = _invoke()
        assert result["hosting"]["has_ipv6"] is True
        assert result["hosting"]["ipv6_count"] == 2

    @patch("familiar.tools.pentest_tools.seer")
    def test_has_ipv6_false(self, mock_seer):
        """16. No AAAA records -> has_ipv6: false."""
        _setup_mock(mock_seer)
        result = _invoke()
        assert result["hosting"]["has_ipv6"] is False


# ---------------------------------------------------------------------------
# Email Infrastructure
# ---------------------------------------------------------------------------


class TestEmailInfrastructure:
    """Email provider and security service identification from MX records."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_google_workspace(self, mock_seer):
        """17. MX google/gmail -> Google Workspace."""
        _setup_mock(mock_seer, mx=[
            _make_mx("aspmx.l.google.com", 1),
            _make_mx("alt1.aspmx.l.google.com", 5),
        ])
        result = _invoke()
        assert "Google Workspace" in result["email_infrastructure"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_microsoft_365(self, mock_seer):
        """18. MX outlook/microsoft -> Microsoft 365."""
        _setup_mock(mock_seer, mx=[
            _make_mx("example-com.mail.protection.outlook.com", 10),
        ])
        result = _invoke()
        assert "Microsoft 365" in result["email_infrastructure"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_proton_mail(self, mock_seer):
        """19. MX protonmail -> Proton Mail."""
        _setup_mock(mock_seer, mx=[_make_mx("mail.protonmail.ch", 10)])
        result = _invoke()
        assert "Proton Mail" in result["email_infrastructure"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_proofpoint_security_service(self, mock_seer):
        """20. MX proofpoint -> Proofpoint in security_services."""
        _setup_mock(mock_seer, mx=[
            _make_mx("mx1.pphosted.com", 10),
        ])
        result = _invoke()
        assert "Proofpoint" in result["email_infrastructure"]["security_services"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_mimecast_security_service(self, mock_seer):
        """21. MX mimecast -> Mimecast in security_services."""
        _setup_mock(mock_seer, mx=[
            _make_mx("us-smtp-inbound-1.mimecast.com", 10),
        ])
        result = _invoke()
        assert "Mimecast" in result["email_infrastructure"]["security_services"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_mx_empty_providers(self, mock_seer):
        """22. No MX records -> empty providers and security_services."""
        _setup_mock(mock_seer)
        result = _invoke()
        assert result["email_infrastructure"]["providers"] == []
        assert result["email_infrastructure"]["security_services"] == []


# ---------------------------------------------------------------------------
# Technology Signals from TXT Records
# ---------------------------------------------------------------------------


class TestTechnologySignals:
    """Technology/service verification signals from DNS TXT records."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_google_search_console(self, mock_seer):
        """23. google-site-verification -> Google Search Console verified."""
        _setup_mock(mock_seer, txt=[
            _make_txt("google-site-verification=abc123xyz"),
        ])
        result = _invoke()
        assert "Google Search Console verified" in result["technology_signals"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_facebook_domain(self, mock_seer):
        """24. facebook-domain-verification -> Facebook domain verified."""
        _setup_mock(mock_seer, txt=[
            _make_txt("facebook-domain-verification=abcdef12345"),
        ])
        result = _invoke()
        assert "Facebook domain verified" in result["technology_signals"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_microsoft_365_domain(self, mock_seer):
        """25. ms=ms12345 -> Microsoft 365 domain verified."""
        _setup_mock(mock_seer, txt=[_make_txt("ms=ms12345678")])
        result = _invoke()
        assert "Microsoft 365 domain verified" in result["technology_signals"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_stripe_verification(self, mock_seer):
        """26. stripe-verification -> Stripe domain verified."""
        _setup_mock(mock_seer, txt=[
            _make_txt("stripe-verification=f123456789abcdef"),
        ])
        result = _invoke()
        assert "Stripe domain verified" in result["technology_signals"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_amazon_ses(self, mock_seer):
        """27. amazonses -> Amazon SES configured."""
        _setup_mock(mock_seer, txt=[
            _make_txt("amazonses:abcdefg1234567890"),
        ])
        result = _invoke()
        assert "Amazon SES configured" in result["technology_signals"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_verification_txt_empty(self, mock_seer):
        """28. No verification TXT records -> empty technology_signals."""
        _setup_mock(mock_seer, txt=[
            _make_txt("v=spf1 include:_spf.google.com ~all"),
        ])
        result = _invoke()
        assert result["technology_signals"] == []


# ---------------------------------------------------------------------------
# SSL Certificate Signals
# ---------------------------------------------------------------------------


class TestSslSignals:
    """SSL certificate metadata extraction."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_issuer_populated(self, mock_seer):
        """29. SSL chain with issuer -> ssl_signals.issuer populated."""
        _setup_mock(mock_seer, ssl={
            "is_valid": True,
            "chain": [
                {"issuer": "CN=Let's Encrypt Authority X3", "key_type": "EC", "key_bits": 256},
            ],
            "san_names": ["example.com"],
        })
        result = _invoke()
        assert result["ssl_signals"]["issuer"] == "CN=Let's Encrypt Authority X3"

    @patch("familiar.tools.pentest_tools.seer")
    def test_shared_cert_true_many_sans(self, mock_seer):
        """30. SSL with >10 SANs -> shared_cert: true."""
        sans = [f"site{i}.example.com" for i in range(15)]
        _setup_mock(mock_seer, ssl={
            "is_valid": True,
            "chain": [{"issuer": "CN=Sectigo", "key_type": "RSA", "key_bits": 2048}],
            "san_names": sans,
        })
        result = _invoke()
        assert result["ssl_signals"]["shared_cert"] is True
        assert result["ssl_signals"]["san_count"] == 15

    @patch("familiar.tools.pentest_tools.seer")
    def test_shared_cert_false_few_sans(self, mock_seer):
        """31. SSL with <=10 SANs -> shared_cert: false."""
        _setup_mock(mock_seer, ssl={
            "is_valid": True,
            "chain": [{"issuer": "CN=DigiCert", "key_type": "EC", "key_bits": 256}],
            "san_names": ["example.com", "www.example.com"],
        })
        result = _invoke()
        assert result["ssl_signals"]["shared_cert"] is False
        assert result["ssl_signals"]["san_count"] == 2

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_ssl_data_graceful(self, mock_seer):
        """32. No SSL data -> ssl_signals gracefully empty."""
        _setup_mock(mock_seer, ssl=None)
        result = _invoke()
        assert result["ssl_signals"] == {}


# ---------------------------------------------------------------------------
# Web Signals / Parking Detection
# ---------------------------------------------------------------------------


class TestWebSignals:
    """HTTP status and parking/placeholder detection."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_title_for_sale_parked(self, mock_seer):
        """33. Title contains 'for sale' -> likely_parked: true."""
        _setup_mock(mock_seer, status={
            "http_status": 200,
            "title": "This Domain is For Sale",
        })
        result = _invoke()
        assert result["web_signals"]["likely_parked"] is True

    @patch("familiar.tools.pentest_tools.seer")
    def test_title_coming_soon_parked(self, mock_seer):
        """34. Title contains 'coming soon' -> likely_parked: true."""
        _setup_mock(mock_seer, status={
            "http_status": 200,
            "title": "Coming Soon - Under Development",
        })
        result = _invoke()
        assert result["web_signals"]["likely_parked"] is True

    @patch("familiar.tools.pentest_tools.seer")
    def test_normal_title_not_parked(self, mock_seer):
        """35. Normal title -> likely_parked: false."""
        _setup_mock(mock_seer, status={
            "http_status": 200,
            "title": "Example Corp - Official Website",
        })
        result = _invoke()
        assert result["web_signals"]["likely_parked"] is False

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_http_response(self, mock_seer):
        """36. No HTTP response -> web_signals empty (no http_status key)."""
        _setup_mock(mock_seer, status=None)
        result = _invoke()
        assert result["web_signals"] == {}


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Resilience under missing data and unusual inputs."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_all_seer_calls_return_none(self, mock_seer):
        """37. All seer calls return None -> no crash, graceful output."""
        mock_seer.dig.return_value = None
        mock_seer.status.return_value = None
        mock_seer.ssl.return_value = None
        result = _invoke()
        assert result["domain"] == "example.com"
        assert result["cdn_waf"]["detected"] == []
        assert result["dns_provider"] == []
        assert result["hosting"]["providers"] == []
        assert result["hosting"]["ips"] == []
        assert result["hosting"]["has_ipv6"] is False
        assert result["email_infrastructure"]["providers"] == []
        assert result["technology_signals"] == []
        assert result["ssl_signals"] == {}
        assert result["web_signals"] == {}

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization(self, mock_seer):
        """38. Domain with uppercase and whitespace is normalized."""
        _setup_mock(mock_seer)
        result = _invoke("  EXAMPLE.COM  ")
        assert result["domain"] == "example.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_empty_lists_all_record_types(self, mock_seer):
        """39. Empty lists for all record types -> valid output with no detections."""
        _setup_mock(
            mock_seer,
            a=[], aaaa=[], ns=[], cname=[], mx=[], txt=[],
            status={}, ssl={},
        )
        result = _invoke()
        assert result["cdn_waf"]["detected"] == []
        assert result["dns_provider"] == []
        assert result["hosting"]["providers"] == []
        assert result["hosting"]["ips"] == []
        # Empty list is falsy, so has_ipv6 should be False
        assert result["hosting"]["has_ipv6"] is False
        assert result["email_infrastructure"]["providers"] == []
        assert result["technology_signals"] == []
        assert result["ssl_signals"] == {}
        assert result["web_signals"] == {}


# ---------------------------------------------------------------------------
# Combined / Integration-style
# ---------------------------------------------------------------------------


class TestCombinedScenario:
    """Full-stack scenario with multiple signals populated simultaneously."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_fully_populated_domain(self, mock_seer):
        """All record types present produces a complete, well-formed result."""
        _setup_mock(
            mock_seer,
            a=[_make_a("104.21.50.1"), _make_a("172.67.200.100")],
            aaaa=[_make_aaaa("2606:4700:3030::ac43:c864")],
            ns=[_make_ns("art.ns.cloudflare.com"), _make_ns("pat.ns.cloudflare.com")],
            cname=[_make_cname("cdn.cloudflare.net")],
            mx=[
                _make_mx("aspmx.l.google.com", 1),
                _make_mx("alt1.aspmx.l.google.com", 5),
            ],
            txt=[
                _make_txt("v=spf1 include:_spf.google.com ~all"),
                _make_txt("google-site-verification=abc123"),
                _make_txt("facebook-domain-verification=def456"),
            ],
            status={"http_status": 200, "title": "Example Corp"},
            ssl={
                "is_valid": True,
                "chain": [{"issuer": "CN=Cloudflare Inc ECC CA-3", "key_type": "EC", "key_bits": 256}],
                "san_names": ["example.com", "www.example.com"],
            },
        )
        result = _invoke()

        # CDN/WAF
        assert "Cloudflare" in result["cdn_waf"]["detected"]
        assert len(result["cdn_waf"]["evidence"]) >= 1

        # DNS provider
        assert "Cloudflare DNS" in result["dns_provider"]

        # Hosting
        assert "Cloudflare" in result["hosting"]["providers"]
        assert len(result["hosting"]["ips"]) == 2
        assert result["hosting"]["has_ipv6"] is True
        assert result["hosting"]["ipv6_count"] == 1

        # Email
        assert "Google Workspace" in result["email_infrastructure"]["providers"]

        # Tech signals
        assert "Google Search Console verified" in result["technology_signals"]
        assert "Facebook domain verified" in result["technology_signals"]

        # SSL
        assert result["ssl_signals"]["issuer"] == "CN=Cloudflare Inc ECC CA-3"
        assert result["ssl_signals"]["shared_cert"] is False

        # Web
        assert result["web_signals"]["http_status"] == 200
        assert result["web_signals"]["likely_parked"] is False
