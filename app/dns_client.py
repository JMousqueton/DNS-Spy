"""
DNS-over-HTTPS client with multiple provider fallback.

Port 53 is often blocked on corporate networks (Zscaler etc.).
This module resolves DNS records via HTTPS (port 443) instead.
Providers are tried in order; the first successful response wins.
"""
from __future__ import annotations
import re
import ipaddress
import socket
import requests

# Providers tried in order. Each is a (url_template, param_style) tuple.
# param_style "json" = ?name=&type=  (Google / Cloudflare JSON API)
_DOH_PROVIDERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.quad9.net:5053/dns-query",
]

# Module-level SSL verification flag — set once at app startup via configure()
_verify_ssl: bool = True


def configure(verify_ssl: bool) -> None:
    """Call this at app startup to propagate the SSL verification setting."""
    global _verify_ssl
    _verify_ssl = verify_ssl


_TYPE_MAP: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257,
}


def _unquote_txt(data: str) -> str:
    """Strip quotes from TXT record data segments and join them."""
    parts = re.findall(r'"([^"]*)"', data)
    return " ".join(parts) if parts else data


def _try_doh(name: str, qtype_int: int, rtype: str, ssl: bool, timeout: int) -> list[str] | None:
    """Try all DoH providers in order. Returns results on first success, None if all fail."""
    last_exc: Exception | None = None
    for url in _DOH_PROVIDERS:
        try:
            resp = requests.get(
                url,
                params={"name": name, "type": qtype_int},
                timeout=timeout,
                verify=ssl,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)",
                    "Accept": "application/dns-json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            status = data.get("Status", -1)
            if status == 3:  # NXDOMAIN
                return []
            if status != 0:
                continue  # try next provider
            results = []
            for answer in data.get("Answer", []):
                if answer.get("type") != qtype_int:
                    continue
                raw = answer.get("data", "")
                if rtype.upper() == "TXT":
                    raw = _unquote_txt(raw)
                results.append(raw)
            return results
        except Exception as exc:
            last_exc = exc
            continue  # try next provider

    return None  # all providers failed


def _system_resolve(name: str, rtype: str) -> list[str] | None:
    """Last-resort fallback using the OS resolver (only works for A/AAAA)."""
    if rtype.upper() == "A":
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except Exception:
            return None
    if rtype.upper() == "AAAA":
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET6)
            return list({info[4][0] for info in infos})
        except Exception:
            return None
    return None


def query(
    name: str,
    rtype: str,
    verify_ssl: bool | None = None,
    timeout: int = 10,
) -> list[str]:
    """
    Query DNS via DoH (multiple providers with fallback).
    Returns list of record data strings.
    Raises RuntimeError only if all providers fail and no system fallback is available.
    """
    ssl = _verify_ssl if verify_ssl is None else verify_ssl
    qtype_int = _TYPE_MAP.get(rtype.upper())
    if qtype_int is None:
        raise ValueError(f"Unsupported record type: {rtype}")

    results = _try_doh(name, qtype_int, rtype, ssl, timeout)
    if results is not None:
        return results

    # All DoH providers failed — try OS resolver for A/AAAA as last resort
    fallback = _system_resolve(name, rtype)
    if fallback is not None:
        return fallback

    raise RuntimeError(f"All DNS resolvers failed for {rtype} {name} (DoH blocked and no system fallback)")


def reverse_name(ip: str) -> str:
    """Convert an IP address to its reverse DNS name (e.g. 1.2.3.4 → 4.3.2.1.in-addr.arpa)."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        parts = str(addr).split(".")
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    else:
        expanded = addr.exploded.replace(":", "")
        return ".".join(reversed(list(expanded))) + ".ip6.arpa"
