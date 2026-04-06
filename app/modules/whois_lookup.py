"""WHOIS lookup module."""
from __future__ import annotations
import whois
from datetime import datetime


def _fmt_date(d) -> str | None:
    if d is None:
        return None
    if isinstance(d, list):
        d = d[0]
    if isinstance(d, datetime):
        return d.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(d)


def _first(val):
    """Return first element if list, else val."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


def run(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        if w is None or not w.domain_name:
            return {"error": "No WHOIS data found for this domain."}

        return {
            "domain_name": _first(w.domain_name),
            "registrar": _first(w.registrar),
            "registrar_url": _first(getattr(w, "registrar_url", None)),
            "whois_server": _first(getattr(w, "whois_server", None)),
            "creation_date": _fmt_date(w.creation_date),
            "updated_date": _fmt_date(w.updated_date),
            "expiration_date": _fmt_date(w.expiration_date),
            "status": w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
            "name_servers": (
                [ns.lower() for ns in w.name_servers]
                if isinstance(w.name_servers, (list, set))
                else ([w.name_servers.lower()] if w.name_servers else [])
            ),
            "emails": (
                w.emails if isinstance(w.emails, list)
                else ([w.emails] if w.emails else [])
            ),
            "org": _first(getattr(w, "org", None)),
            "country": _first(getattr(w, "country", None)),
            "dnssec": _first(getattr(w, "dnssec", None)),
        }
    except Exception as exc:
        return {"error": f"WHOIS lookup failed: {exc}"}
