"""Test 9: Domain name analysis and TLD splitting accuracy.

Validates length tier classification, TLD tier assignment, multi-level TLD
handling, and intrinsic domain name property detection (hyphens, digits, etc.).
"""

import pytest

from familiar.tools.advisor_tools import _domain_name_analysis, _split_domain


class TestSplitDomain:
    """_split_domain must correctly handle multi-level and standard TLDs."""

    def test_simple_com(self):
        assert _split_domain("example.com") == ("example", "com")

    def test_multi_level_co_uk(self):
        assert _split_domain("example.co.uk") == ("example", "co.uk")

    def test_multi_level_com_au(self):
        assert _split_domain("example.com.au") == ("example", "com.au")

    def test_multi_level_co_jp(self):
        assert _split_domain("example.co.jp") == ("example", "co.jp")

    def test_multi_level_com_br(self):
        assert _split_domain("example.com.br") == ("example", "com.br")

    def test_multi_level_co_nz(self):
        assert _split_domain("shop.co.nz") == ("shop", "co.nz")

    def test_standard_org(self):
        assert _split_domain("example.org") == ("example", "org")

    def test_new_gtld(self):
        assert _split_domain("example.app") == ("example", "app")

    def test_no_tld(self):
        assert _split_domain("localhost") == ("localhost", "")

    def test_multi_level_co_za(self):
        assert _split_domain("mysite.co.za") == ("mysite", "co.za")


class TestLengthTiers:
    """SLD length determines the length tier."""

    @pytest.mark.parametrize("domain,expected_tier", [
        ("ab.com", "ultra-premium"),       # 2 chars
        ("abc.com", "ultra-premium"),      # 3 chars
        ("abcd.com", "premium"),           # 4 chars
        ("abcde.com", "premium"),          # 5 chars
        ("abcdef.com", "standard"),        # 6 chars
        ("abcdefgh.com", "standard"),      # 8 chars
        ("abcdefghi.com", "long"),         # 9 chars
        ("abcdefghijkl.com", "long"),      # 12 chars
        ("abcdefghijklm.com", "very-long"),  # 13 chars
        ("superlongdomainname.com", "very-long"),
    ])
    def test_length_tier(self, domain, expected_tier):
        result = _domain_name_analysis(domain)
        assert result["length_tier"] == expected_tier


class TestTldTiers:
    """TLD determines the TLD tier classification."""

    @pytest.mark.parametrize("domain,expected_tier", [
        ("example.com", "premium"),
        ("example.net", "established"),
        ("example.org", "established"),
        ("example.edu", "restricted"),
        ("example.gov", "restricted"),
        ("example.io", "tech-premium"),
        ("example.ai", "tech-premium"),
        ("example.dev", "tech-premium"),
        ("example.app", "tech-premium"),
        ("example.tech", "tech-premium"),
        ("example.co.uk", "country-code"),  # multi-level TLD
        ("example.de", "country-code"),     # 2-letter ccTLD
        ("example.xyz", "new-gtld"),
        ("example.blog", "new-gtld"),
    ])
    def test_tld_tier(self, domain, expected_tier):
        result = _domain_name_analysis(domain)
        assert result["tld_tier"] == expected_tier


class TestDomainProperties:
    """Hyphen, digit, and alpha detection."""

    def test_clean_alpha_domain(self):
        result = _domain_name_analysis("example.com")
        assert result["has_hyphens"] is False
        assert result["has_numbers"] is False
        assert result["is_all_alpha"] is True
        assert result["hyphen_count"] == 0
        assert result["digit_count"] == 0

    def test_hyphenated_domain(self):
        result = _domain_name_analysis("my-example.com")
        assert result["has_hyphens"] is True
        assert result["hyphen_count"] == 1
        assert result["is_all_alpha"] is False

    def test_numeric_domain(self):
        result = _domain_name_analysis("123.com")
        assert result["has_numbers"] is True
        assert result["digit_count"] == 3
        assert result["is_all_alpha"] is False

    def test_mixed_domain(self):
        result = _domain_name_analysis("web-2-go.com")
        assert result["has_hyphens"] is True
        assert result["has_numbers"] is True
        assert result["hyphen_count"] == 2
        assert result["digit_count"] == 1

    def test_sld_and_tld_fields(self):
        result = _domain_name_analysis("hello.co.uk")
        assert result["sld"] == "hello"
        assert result["tld"] == "co.uk"
        assert result["sld_length"] == 5
        assert result["full_domain"] == "hello.co.uk"
