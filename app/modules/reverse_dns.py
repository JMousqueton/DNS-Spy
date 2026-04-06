"""Reverse DNS (PTR record) module — uses DNS-over-HTTPS."""
from __future__ import annotations
import socket
from app.dns_client import query as doh_query, reverse_name


def _resolve_ips(domain: str) -> list[tuple[str, str]]:
    """Return deduplicated list of (ip, family) tuples for both IPv4 and IPv6."""
    try:
        infos = socket.getaddrinfo(domain, None)
        seen: set[str] = set()
        ips: list[tuple[str, str]] = []
        for info in infos:
            ip = info[4][0]
            family = "IPv6" if info[0] == socket.AF_INET6 else "IPv4"
            if ip not in seen:
                seen.add(ip)
                ips.append((ip, family))
        return ips
    except socket.gaierror:
        return []


def _ptr_lookup(ip: str) -> list[str]:
    try:
        rev = reverse_name(ip)
        records = doh_query(rev, "PTR")
        return [r.rstrip(".") for r in records] if records else []
    except Exception:
        return []


def run(domain: str) -> dict:
    try:
        entries = _resolve_ips(domain)
        if not entries:
            return {"error": f"Could not resolve any IP addresses for {domain}"}

        ptr_records = {}
        for ip, family in entries:
            ptrs = _ptr_lookup(ip)
            ptr_records[ip] = {
                "family": family,
                "ptrs": ptrs if ptrs else ["No PTR record found"],
            }

        return {"ptr_records": ptr_records, "ips": [ip for ip, _ in entries]}
    except Exception as exc:
        return {"error": f"Reverse DNS lookup failed: {exc}"}
