"""Email security records: DMARC, SPF, DKIM module."""
from __future__ import annotations
import re
from app.dns_client import query as doh_query

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2", "selector1", "selector2",
    "dkim", "smtp", "email", "s1", "s2", "mx", "mailjet", "mandrill",
    "sendgrid", "ses", "postmark", "sparkpost", "mailgun",
]


def _query_txt(name: str) -> list[str]:
    try:
        return doh_query(name, "TXT")
    except Exception:
        return []


def _get_spf(domain: str) -> dict:
    records = _query_txt(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return {"found": False, "record": None, "analysis": {}}

    record = spf_records[0]
    analysis = {
        "all_mechanism": None,
        "includes": [],
        "ip4": [],
        "ip6": [],
        "redirect": None,
    }

    for part in record.split():
        if part in ("-all", "~all", "+all", "?all"):
            analysis["all_mechanism"] = part
        elif part.startswith("include:"):
            analysis["includes"].append(part[8:])
        elif part.startswith("ip4:"):
            analysis["ip4"].append(part[4:])
        elif part.startswith("ip6:"):
            analysis["ip6"].append(part[4:])
        elif part.startswith("redirect="):
            analysis["redirect"] = part[9:]

    # Determine policy strength
    all_mech = analysis["all_mechanism"]
    if all_mech == "-all":
        policy = "strict"
    elif all_mech == "~all":
        policy = "soft-fail"
    elif all_mech == "+all":
        policy = "permissive (dangerous)"
    else:
        policy = "none"

    analysis["policy"] = policy

    return {"found": True, "record": record, "analysis": analysis}


def _get_dmarc(domain: str) -> dict:
    records = _query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {"found": False, "record": None, "analysis": {}}

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    return {
        "found": True,
        "record": record,
        "analysis": {
            "policy": tags.get("p", "none"),
            "subdomain_policy": tags.get("sp", tags.get("p", "none")),
            "pct": tags.get("pct", "100"),
            "rua": tags.get("rua"),
            "ruf": tags.get("ruf"),
            "adkim": tags.get("adkim", "r"),
            "aspf": tags.get("aspf", "r"),
            "fo": tags.get("fo", "0"),
        },
    }


def _get_dkim(domain: str) -> dict:
    found = []
    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _query_txt(name)
        dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
        if dkim_records:
            found.append({
                "selector": selector,
                "record": dkim_records[0],
                "has_public_key": "p=" in dkim_records[0] and len(dkim_records[0].split("p=")[-1]) > 10,
            })

    return {"found": bool(found), "selectors": found}


def _get_bimi(domain: str) -> dict:
    records = _query_txt(f"default._bimi.{domain}")
    bimi_records = [r for r in records if r.startswith("v=BIMI1")]
    if bimi_records:
        return {"found": True, "record": bimi_records[0]}
    return {"found": False, "record": None}


def _get_mta_sts(domain: str) -> dict:
    records = _query_txt(f"_mta-sts.{domain}")
    sts_records = [r for r in records if r.startswith("v=STSv1")]
    if sts_records:
        return {"found": True, "record": sts_records[0]}
    return {"found": False, "record": None}


def run(domain: str) -> dict:
    try:
        return {
            "spf": _get_spf(domain),
            "dmarc": _get_dmarc(domain),
            "dkim": _get_dkim(domain),
            "bimi": _get_bimi(domain),
            "mta_sts": _get_mta_sts(domain),
        }
    except Exception as exc:
        return {"error": f"Email security lookup failed: {exc}"}
