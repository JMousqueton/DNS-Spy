"""Subdomain discovery by scanning the page HTML source."""
from __future__ import annotations
import re
import urllib3
import requests
from urllib.parse import urlparse

# Matches http(s):// and protocol-relative // URLs
_URL_RE = re.compile(r'(?:https?:)?//([a-zA-Z0-9._-]+)', re.IGNORECASE)

# Attributes worth scanning explicitly (catches encoded/templated values too)
_ATTR_RE = re.compile(
    r'''(?:href|src|action|data-src|data-href|data-url|content|poster|srcset)\s*=\s*["']([^"']{4,})["']''',
    re.IGNORECASE,
)


def _extract_hosts(html: str) -> set[str]:
    """Return every unique hostname found in the HTML."""
    hosts: set[str] = set()

    # 1 — scan every URL-like string
    for m in _URL_RE.finditer(html):
        host = m.group(1).lower().rstrip(".,;)")
        if "." in host:
            hosts.add(host)

    # 2 — scan attribute values explicitly (catches relative paths too)
    for m in _ATTR_RE.finditer(html):
        try:
            parsed = urlparse(m.group(1))
            if parsed.hostname and "." in parsed.hostname:
                hosts.add(parsed.hostname.lower())
        except Exception:
            pass

    return hosts


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    domain_lower = domain.lower()

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url,
                timeout=12,
                allow_redirects=True,
                verify=verify_ssl,
                headers={"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"},
            )
        except requests.RequestException:
            continue
        except Exception as exc:
            return {"error": f"Failed to fetch page: {exc}"}

        all_hosts = _extract_hosts(resp.text)

        # Keep only proper subdomains of the target domain
        # e.g. target=example.com → cdn.example.com ✓, example.com ✗, other.com ✗
        suffix = f".{domain_lower}"
        subdomains: list[dict] = []
        seen: set[str] = set()

        for host in sorted(all_hosts):
            if host.endswith(suffix) and host != domain_lower and host not in seen:
                seen.add(host)
                subdomains.append({"subdomain": host})

        return {
            "found": subdomains,
            "count": len(subdomains),
            "scanned_url": resp.url,
        }

    return {"error": "Could not fetch the page HTML.", "found": [], "count": 0}
