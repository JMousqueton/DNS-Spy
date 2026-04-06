"""Certificate Transparency log search via crt.sh."""
from __future__ import annotations
from datetime import date
import urllib3
import requests


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=15,
            verify=verify_ssl,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"},
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.JSONDecodeError:
        return {"error": "crt.sh returned no results or is temporarily unavailable."}
    except requests.RequestException as exc:
        return {"error": f"crt.sh request failed: {exc}"}
    except Exception as exc:
        return {"error": f"Certificate Transparency lookup failed: {exc}"}

    today = date.today()
    seen_ids: set[int] = set()
    certs: list[dict] = []
    subdomains: set[str] = set()

    for entry in data:
        cert_id = entry.get("id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        not_after_str = (entry.get("not_after") or "")[:10]

        # Skip expired certificates
        try:
            if date.fromisoformat(not_after_str) < today:
                continue
        except ValueError:
            pass  # unparseable date — include it to be safe

        # Collect subdomains from valid certs only
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name and "." in name:
                subdomains.add(name.lower())

        certs.append({
            "id": cert_id,
            "issuer": _short_issuer(entry.get("issuer_name", "")),
            "common_name": entry.get("common_name", ""),
            "name_value": entry.get("name_value", ""),
            "not_before": (entry.get("not_before") or "")[:10],
            "not_after":  not_after_str,
            "logged_at":  (entry.get("entry_timestamp") or "")[:10],
        })

    # Most recently logged first
    certs.sort(key=lambda x: x.get("logged_at", ""), reverse=True)

    return {
        "count": len(certs),
        "certs": certs[:50],
        "subdomains": sorted(subdomains),
        "subdomain_count": len(subdomains),
    }


def _short_issuer(raw: str) -> str:
    """Extract O= or CN= from an issuer DN string."""
    for field in ("O=", "CN="):
        if field in raw:
            part = raw.split(field, 1)[1]
            return part.split(",")[0].strip()
    return raw
