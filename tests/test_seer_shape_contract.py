"""Contract test against real seer output.

Asserts the shape that ``familiar.seer_shape`` expects. If seer changes
its record layout in a future release (as happened with 0.24), this is
the test that fails — pointing maintainers at the ACL to update.

Marked ``slow`` because it hits real DNS. Skipped automatically when
seer can't reach the network (sandboxed CI, offline laptop).
"""

import pytest

import seer

from familiar.seer_shape import record_field, record_text, record_value_dict

# google.com is the canonical "always responds" test target. Each test
# pulls one record per type and asserts the ACL can read it.
DOMAIN = "google.com"


def _dig(rtype: str):
    try:
        return seer.dig(DOMAIN, rtype)
    except Exception as e:
        pytest.skip(f"seer.dig unreachable: {e}")


@pytest.mark.slow
def test_a_record_shape():
    records = _dig("A")
    if not records:
        pytest.skip("no A records returned")
    fields = record_value_dict(records[0])
    assert isinstance(fields, dict), "record_value_dict must return a dict for A"
    address = record_field(records[0], "address")
    assert address, "address field must be non-empty"
    assert address.count(".") == 3, f"address looks malformed: {address!r}"


@pytest.mark.slow
def test_ns_record_shape():
    records = _dig("NS")
    if not records:
        pytest.skip("no NS records returned")
    nameserver = record_field(records[0], "nameserver")
    assert nameserver, "nameserver field must be non-empty"


@pytest.mark.slow
def test_mx_record_shape():
    records = _dig("MX")
    if not records:
        pytest.skip("no MX records returned")
    exchange = record_field(records[0], "exchange")
    assert exchange, "exchange field must be non-empty"


@pytest.mark.slow
def test_txt_record_shape():
    records = _dig("TXT")
    if not records:
        pytest.skip("no TXT records returned")
    text = record_text(records[0])
    assert text, "text must be non-empty"


@pytest.mark.slow
def test_soa_record_shape():
    records = _dig("SOA")
    if not records:
        pytest.skip("no SOA returned")
    fields = record_value_dict(records[0])
    assert isinstance(fields, dict)
    for key in ("mname", "rname", "serial", "refresh", "retry", "expire", "minimum"):
        assert key in fields, f"SOA field {key!r} missing — seer shape may have changed"
