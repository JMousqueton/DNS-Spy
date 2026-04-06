"""Aggregate security score computed from all other modules' results."""
from __future__ import annotations


def run(data: dict) -> dict:
    score = 0
    checks: list[dict] = []

    # ── SSL Certificate (20 pts) ──────────────────────────────────────────────
    ssl = data.get("ssl") or {}
    if ssl.get("error"):
        checks.append({"name": "SSL Certificate", "category": "Transport", "status": "fail", "pts": 0, "max": 20, "detail": "No SSL/TLS"})
    elif ssl.get("expired"):
        checks.append({"name": "SSL Certificate", "category": "Transport", "status": "fail", "pts": 0, "max": 20, "detail": "Certificate expired"})
    elif ssl.get("expiring_soon"):
        pts = 10
        checks.append({"name": "SSL Certificate", "category": "Transport", "status": "warn", "pts": pts, "max": 20, "detail": f"Expiring in {ssl.get('days_remaining')} days"})
        score += pts
    else:
        checks.append({"name": "SSL Certificate", "category": "Transport", "status": "pass", "pts": 20, "max": 20, "detail": f"Valid ({ssl.get('days_remaining')} days remaining)"})
        score += 20

    # ── HSTS (5 pts) ──────────────────────────────────────────────────────────
    headers = data.get("headers") or {}
    sec_hdrs = headers.get("security_headers") or {}
    hsts_info = sec_hdrs.get("HSTS") or {}
    hsts_present = hsts_info.get("present", False)
    hsts_preloaded = (data.get("headers") or {}).get("hsts_preloaded", False)
    if hsts_preloaded:
        checks.append({"name": "HSTS", "category": "Transport", "status": "pass", "pts": 5, "max": 5, "detail": "Present + preloaded"})
        score += 5
    elif hsts_present:
        checks.append({"name": "HSTS", "category": "Transport", "status": "warn", "pts": 3, "max": 5, "detail": "Present (not preloaded)"})
        score += 3
    else:
        checks.append({"name": "HSTS", "category": "Transport", "status": "fail", "pts": 0, "max": 5, "detail": "Missing"})

    # ── HTTP Security Headers (20 pts) ────────────────────────────────────────
    if not headers.get("error"):
        grade = headers.get("security_grade", "F")
        grade_pts = {"A": 20, "B": 15, "C": 10, "D": 5, "F": 0}.get(grade, 0)
        status = "pass" if grade in ("A", "B") else ("warn" if grade == "C" else "fail")
        checks.append({"name": "Security Headers", "category": "Headers", "status": status, "pts": grade_pts, "max": 20, "detail": f"Grade {grade}"})
        score += grade_pts
    else:
        checks.append({"name": "Security Headers", "category": "Headers", "status": "fail", "pts": 0, "max": 20, "detail": "Could not fetch headers"})

    # ── SPF (10 pts) ──────────────────────────────────────────────────────────
    email = data.get("email_sec") or {}
    spf = email.get("spf") or {}
    if spf.get("found"):
        policy = (spf.get("analysis") or {}).get("policy", "")
        if policy == "strict":
            checks.append({"name": "SPF", "category": "Email", "status": "pass", "pts": 10, "max": 10, "detail": "Present, strict (-all)"})
            score += 10
        elif policy == "soft-fail":
            checks.append({"name": "SPF", "category": "Email", "status": "warn", "pts": 6, "max": 10, "detail": "Present, soft-fail (~all)"})
            score += 6
        else:
            checks.append({"name": "SPF", "category": "Email", "status": "warn", "pts": 3, "max": 10, "detail": f"Present ({policy})"})
            score += 3
    else:
        checks.append({"name": "SPF", "category": "Email", "status": "fail", "pts": 0, "max": 10, "detail": "Missing"})

    # ── DMARC (10 pts) ────────────────────────────────────────────────────────
    dmarc = email.get("dmarc") or {}
    if dmarc.get("found"):
        policy = (dmarc.get("analysis") or {}).get("policy", "none")
        if policy == "reject":
            checks.append({"name": "DMARC", "category": "Email", "status": "pass", "pts": 10, "max": 10, "detail": "Present, policy=reject"})
            score += 10
        elif policy == "quarantine":
            checks.append({"name": "DMARC", "category": "Email", "status": "warn", "pts": 7, "max": 10, "detail": "Present, policy=quarantine"})
            score += 7
        else:
            checks.append({"name": "DMARC", "category": "Email", "status": "warn", "pts": 3, "max": 10, "detail": "Present, policy=none (monitoring only)"})
            score += 3
    else:
        checks.append({"name": "DMARC", "category": "Email", "status": "fail", "pts": 0, "max": 10, "detail": "Missing"})

    # ── DKIM (10 pts) ─────────────────────────────────────────────────────────
    dkim = email.get("dkim") or {}
    if dkim.get("found"):
        n = len(dkim.get("selectors", []))
        checks.append({"name": "DKIM", "category": "Email", "status": "pass", "pts": 10, "max": 10, "detail": f"{n} selector(s) found"})
        score += 10
    else:
        checks.append({"name": "DKIM", "category": "Email", "status": "fail", "pts": 0, "max": 10, "detail": "No selector found"})

    # ── DNSSEC (10 pts) ───────────────────────────────────────────────────────
    rdap = data.get("rdap") or {}
    dnssec = rdap.get("dnssec", False) if not rdap.get("error") else False
    if dnssec:
        checks.append({"name": "DNSSEC", "category": "DNS", "status": "pass", "pts": 10, "max": 10, "detail": "Signed"})
        score += 10
    else:
        checks.append({"name": "DNSSEC", "category": "DNS", "status": "fail", "pts": 0, "max": 10, "detail": "Unsigned"})

    # ── Cookie Security (5 pts) ───────────────────────────────────────────────
    cookies = data.get("cookies") or {}
    if cookies.get("error"):
        pass  # don't penalise if we couldn't fetch
    elif cookies.get("count", 0) == 0:
        checks.append({"name": "Cookie Security", "category": "Headers", "status": "pass", "pts": 5, "max": 5, "detail": "No cookies set"})
        score += 5
    else:
        insecure = cookies.get("insecure_count", 0)
        if insecure == 0:
            checks.append({"name": "Cookie Security", "category": "Headers", "status": "pass", "pts": 5, "max": 5, "detail": "All cookies properly secured"})
            score += 5
        else:
            checks.append({"name": "Cookie Security", "category": "Headers", "status": "warn", "pts": 2, "max": 5, "detail": f"{insecure} of {cookies['count']} cookie(s) missing security flags"})
            score += 2

    # ── Grade ─────────────────────────────────────────────────────────────────
    max_score = sum(c["max"] for c in checks)
    pct = round(score / max_score * 100) if max_score else 0
    if pct >= 90:
        grade = "A"
    elif pct >= 75:
        grade = "B"
    elif pct >= 60:
        grade = "C"
    elif pct >= 45:
        grade = "D"
    else:
        grade = "F"

    # Group checks by category for display
    by_category: dict[str, list] = {}
    for c in checks:
        by_category.setdefault(c["category"], []).append(c)

    return {
        "score": score,
        "max_score": max_score,
        "percent": pct,
        "grade": grade,
        "checks": checks,
        "by_category": by_category,
    }
