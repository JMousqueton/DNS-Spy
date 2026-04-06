"""ASN / BGP information via ipinfo.io (primary) + RIPE NCC Stat (secondary)."""
from __future__ import annotations
import re
import socket
import urllib3
import requests

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"}


def _resolve_ipv4(domain: str) -> str | None:
    try:
        return socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


def _ipinfo(ip: str, verify_ssl: bool) -> dict:
    resp = requests.get(
        f"https://ipinfo.io/{ip}/json",
        timeout=10,
        verify=verify_ssl,
        headers=_HEADERS,
    )
    resp.raise_for_status()
    return resp.json()


def _ripe_asn_overview(asn: int, verify_ssl: bool) -> dict:
    resp = requests.get(
        f"https://stat.ripe.net/data/whois/data.json?resource=AS{asn}",
        timeout=10,
        verify=verify_ssl,
        headers=_HEADERS,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    # Flatten whois records into a dict
    result: dict = {}
    for rec in data.get("records", []):
        for item in rec:
            key = item.get("key", "").lower()
            val = item.get("value", "")
            if key and val and key not in result:
                result[key] = val
    return result


def _ripe_prefixes(asn: int, verify_ssl: bool) -> list:
    resp = requests.get(
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
        timeout=10,
        verify=verify_ssl,
        headers=_HEADERS,
    )
    resp.raise_for_status()
    prefixes = resp.json().get("data", {}).get("prefixes", [])
    return [p.get("prefix") for p in prefixes[:20] if p.get("prefix")]


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ip = _resolve_ipv4(domain)
    if not ip:
        return {"error": f"Could not resolve IP for {domain}"}

    try:
        info = _ipinfo(ip, verify_ssl)
    except Exception as exc:
        return {"ip": ip, "error": f"ipinfo.io lookup failed: {exc}"}

    # Parse ASN and org name from "AS12345 Org Name" format
    org_raw = info.get("org", "")
    asn_number: int | None = None
    asn_name: str | None = None
    m = re.match(r"AS(\d+)\s+(.*)", org_raw)
    if m:
        asn_number = int(m.group(1))
        asn_name = m.group(2)

    # Enrich with RIPE NCC data
    ripe_data: dict = {}
    announced_prefixes: list = []
    if asn_number:
        try:
            ripe_data = _ripe_asn_overview(asn_number, verify_ssl)
        except Exception:
            pass
        try:
            announced_prefixes = _ripe_prefixes(asn_number, verify_ssl)
        except Exception:
            pass

    country = info.get("country") or ripe_data.get("country")
    network = info.get("network", {}) if isinstance(info.get("network"), dict) else {}

    return {
        "ip": ip,
        "asn": {
            "asn": asn_number,
            "name": asn_name,
            "description": ripe_data.get("descr") or asn_name,
            "country_code": country,
        },
        "asn_detail": {
            "number": asn_number,
            "name": asn_name,
            "description": ripe_data.get("descr") or asn_name,
            "country_code": country,
            "website": None,
            "emails": [ripe_data["abuse-mailbox"]] if "abuse-mailbox" in ripe_data else [],
            "abuse": [ripe_data["abuse-mailbox"]] if "abuse-mailbox" in ripe_data else [],
            "date_allocated": ripe_data.get("created"),
            "rir": ripe_data.get("source"),
            "looking_glass": None,
        } if asn_number else {},
        "prefix": {
            "prefix": announced_prefixes[0] if announced_prefixes else network.get("range"),
            "name": asn_name,
            "description": ripe_data.get("descr") or asn_name,
            "country_code": country,
        },
        "rir": {
            "name": ripe_data.get("source"),
            "country_code": country,
            "prefix": announced_prefixes[0] if announced_prefixes else None,
            "date_allocated": ripe_data.get("created"),
            "status": ripe_data.get("status"),
        },
        "iana": {
            "description": ripe_data.get("descr"),
            "status": ripe_data.get("status"),
        },
        "announced_prefixes": [{"prefix": p} for p in announced_prefixes],
        "prefix_count": len(announced_prefixes),
        "location": {
            "city": info.get("city"),
            "region": info.get("region"),
            "country": country,
            "timezone": info.get("timezone"),
        },
    }
