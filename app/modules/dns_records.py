"""DNS records lookup module — uses DNS-over-HTTPS to bypass port-53 blocks."""
from __future__ import annotations
from app.dns_client import query as doh_query

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def _query(domain: str, rtype: str) -> list[str]:
    try:
        return doh_query(domain, rtype)
    except RuntimeError as exc:
        return [f"ERROR: {exc}"]
    except Exception as exc:
        return [f"ERROR: {exc}"]


def run(domain: str) -> dict:
    try:
        records = {rtype: _query(domain, rtype) for rtype in RECORD_TYPES}
        return {"records": records}
    except Exception as exc:
        return {"error": f"DNS lookup failed: {exc}"}
