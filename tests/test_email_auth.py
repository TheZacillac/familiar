"""Shared SPF/DMARC parsing primitives (familiar.email_auth).

These exist so every consumer (pentest deep audit, security_audit,
compare_security) parses records the same tag-aware way — substring
matching like ``"p=none" in txt`` misfires on values such as
``sp=none`` or ``p=nonexistent``.
"""

import pytest

from familiar.email_auth import parse_dmarc_tags, parse_spf_all_qualifier


class TestParseDmarcTags:

    def test_basic_record(self):
        tags = parse_dmarc_tags("v=DMARC1; p=reject; rua=mailto:agg@x.com")
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "reject"
        assert tags["rua"] == "mailto:agg@x.com"

    def test_whitespace_and_key_case_normalized(self):
        tags = parse_dmarc_tags("V=DMARC1 ;  P = reject ;PCT= 50")
        assert tags["p"] == "reject"
        assert tags["pct"] == "50"

    def test_sp_tag_does_not_create_p(self):
        """The whole point: sp=none must not be readable as p=none."""
        tags = parse_dmarc_tags("v=DMARC1; sp=none; rua=mailto:x@y.com")
        assert "p" not in tags
        assert tags["sp"] == "none"

    def test_empty_and_garbage(self):
        assert parse_dmarc_tags("") == {}
        assert parse_dmarc_tags("no tags here") == {}


class TestParseSpfAllQualifier:

    @pytest.mark.parametrize("record,qualifier", [
        ("v=spf1 include:x.com -all", "-"),
        ("v=spf1 include:x.com ~all", "~"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        ("v=spf1 a mx all", "+"),  # bare all is +all per RFC 7208 §4.6.2
        ("v=spf1 include:x.com redirect=other.com", None),
        ("v=spf1 ip4:1.2.3.4/32", None),
        ("V=SPF1 INCLUDE:X.COM -ALL", "-"),
    ])
    def test_qualifiers(self, record, qualifier):
        assert parse_spf_all_qualifier(record) == qualifier

    def test_all_inside_other_tokens_ignored(self):
        """'ball.example' or 'a:small.com' must not register as an all mechanism."""
        assert parse_spf_all_qualifier("v=spf1 include:ball.example -all") == "-"
        assert parse_spf_all_qualifier("v=spf1 a:small.com") is None
