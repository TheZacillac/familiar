"""Builders for seer DNS record dicts in the seer >=0.24 nested shape.

Real seer responses look like:

    {"data": {"record_type": "A",
              "value": {"address": "1.2.3.4"}},
     "name": "example.com",
     "record_type": "A",
     "ttl": 300}

Tests that emit hand-rolled flat dicts (e.g. ``{"data": {"address": ip}}``)
silently drift from production every time seer's schema evolves. Use these
builders so the shape lives in one place — when seer changes again, only
this file needs updating.
"""

from __future__ import annotations


def _record(record_type: str, name: str, value: dict, ttl: int = 300) -> dict:
    return {
        "data": {"record_type": record_type, "value": value},
        "name": name,
        "record_type": record_type,
        "ttl": ttl,
    }


def a_record(address: str, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("A", name, {"address": address}, ttl)


def aaaa_record(address: str, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("AAAA", name, {"address": address}, ttl)


def ns_record(nameserver: str, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("NS", name, {"nameserver": nameserver}, ttl)


def cname_record(target: str, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("CNAME", name, {"target": target}, ttl)


def mx_record(exchange: str, preference: int = 10, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("MX", name, {"exchange": exchange, "preference": preference}, ttl)


def txt_record(text: str, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("TXT", name, {"text": text}, ttl)


def caa_record(tag: str, value: str, flags: int = 0, *, name: str = "example.com", ttl: int = 300) -> dict:
    return _record("CAA", name, {"tag": tag, "value": value, "flags": flags}, ttl)


def soa_record(
    *,
    mname: str = "ns1.example.com.",
    rname: str = "admin.example.com.",
    serial: int = 2024010101,
    refresh: int = 3600,
    retry: int = 900,
    expire: int = 1209600,
    minimum: int = 3600,
    name: str = "example.com",
    ttl: int = 3600,
) -> dict:
    return _record(
        "SOA",
        name,
        {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        },
        ttl,
    )


def tlsa_record(
    usage: int,
    selector: int,
    matching_type: int,
    certificate_data: str,
    *,
    name: str = "_443._tcp.example.com",
    ttl: int = 300,
) -> dict:
    return _record(
        "TLSA",
        name,
        {
            "usage": usage,
            "selector": selector,
            "matching_type": matching_type,
            "certificate_data": certificate_data,
        },
        ttl,
    )


# Convenience list builders ------------------------------------------------


def ns_records(*nameservers: str, name: str = "example.com") -> list[dict]:
    return [ns_record(ns, name=name) for ns in nameservers]


def a_records(*addresses: str, name: str = "example.com") -> list[dict]:
    return [a_record(a, name=name) for a in addresses]


def caa_records(tags: list[tuple[str, str]], *, name: str = "example.com") -> list[dict]:
    return [caa_record(t, v, name=name) for t, v in tags]


def txt_records(*texts: str, name: str = "example.com") -> list[dict]:
    return [txt_record(t, name=name) for t in texts]
