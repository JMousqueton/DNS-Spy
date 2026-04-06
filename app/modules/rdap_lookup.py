"""RDAP lookup — structured JSON replacement for WHOIS via rdap.org aggregator."""
from __future__ import annotations
import urllib3
import requests
from datetime import datetime


def _parse_events(events: list) -> dict:
    result = {}
    for ev in events:
        action = ev.get("eventAction", "").lower()
        date_str = ev.get("eventDate", "")
        try:
            date_fmt = datetime.fromisoformat(date_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            date_fmt = date_str[:10] if date_str else None
        if "registration" in action:
            result["created"] = date_fmt
        elif "expir" in action:
            result["expires"] = date_fmt
        elif "last changed" in action or "updated" in action:
            result["updated"] = date_fmt
    return result


def _parse_entity(entity: dict) -> dict:
    info: dict = {"roles": entity.get("roles", [])}
    vcard = entity.get("vcardArray", [])
    if isinstance(vcard, list) and len(vcard) > 1:
        for field in vcard[1]:
            label = field[0].lower() if field else ""
            value = field[3] if len(field) > 3 else None
            if label == "fn" and value:
                info["name"] = value
            elif label == "org" and value:
                info["org"] = value
            elif label == "email" and value:
                info.setdefault("emails", []).append(value)
            elif label == "tel" and value:
                info.setdefault("phones", []).append(value)
            elif label == "adr" and isinstance(value, list):
                parts = [p for p in value if p]
                info["address"] = ", ".join(parts)
    return info


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=12,
            verify=verify_ssl,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)",
            },
            allow_redirects=True,
        )

        if resp.status_code == 404:
            # Distinguish "domain not registered" from "TLD has no RDAP server"
            tld = domain.rsplit(".", 1)[-1].upper()
            try:
                err_body = resp.json()
                description = " ".join(err_body.get("description", []))
            except Exception:
                description = ""
            if "no rdap" in description.lower() or "not found" not in description.lower():
                return {"error": f"RDAP is not available for .{tld} — the registry does not publish an RDAP endpoint."}
            return {"error": f"Domain not found in RDAP: {domain}"}
        resp.raise_for_status()
        data = resp.json()

    except requests.exceptions.JSONDecodeError:
        return {"error": "RDAP server returned an invalid response."}
    except requests.RequestException as exc:
        return {"error": f"RDAP request failed: {exc}"}
    except Exception as exc:
        return {"error": f"RDAP lookup failed: {exc}"}

    # Events → dates
    dates = _parse_events(data.get("events", []))

    # Entities → registrar / registrant / contacts
    entities = []
    registrar = None
    for entity in data.get("entities", []):
        parsed = _parse_entity(entity)
        entities.append(parsed)
        if "registrar" in parsed.get("roles", []):
            registrar = parsed
        # Some registries nest registrant inside registrar entity
        for sub in entity.get("entities", []):
            sub_parsed = _parse_entity(sub)
            entities.append(sub_parsed)
            if "registrar" in sub_parsed.get("roles", []) and not registrar:
                registrar = sub_parsed

    # Name servers
    nameservers = [
        ns.get("ldhName", "").lower()
        for ns in data.get("nameservers", [])
        if ns.get("ldhName")
    ]

    # DNSSEC
    secure_dns = data.get("secureDNS", {})
    dnssec = secure_dns.get("delegationSigned", False)

    # Status
    status = data.get("status", [])

    # Registry source link
    links = [
        lnk.get("href") for lnk in data.get("links", [])
        if lnk.get("rel") == "self" and lnk.get("href")
    ]

    return {
        "domain": data.get("ldhName", domain).lower(),
        "handle": data.get("handle"),
        "status": status,
        "created": dates.get("created"),
        "updated": dates.get("updated"),
        "expires": dates.get("expires"),
        "registrar": registrar,
        "entities": entities,
        "nameservers": nameservers,
        "dnssec": dnssec,
        "rdap_url": links[0] if links else None,
    }
