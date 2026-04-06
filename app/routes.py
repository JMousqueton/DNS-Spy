import re
import concurrent.futures
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, jsonify, current_app
from app import cache, rate_limiter
from app.modules import (
    whois_lookup,
    dns_records,
    ssl_cert,
    geolocation,
    http_headers,
    reverse_dns,
    email_security,
    screenshot,
    tech_detection,
    cert_transparency,
    html_subdomains,
    rdap_lookup,
    asn_info,
    saas_detection,
    waf_detection,
    cookie_analysis,
    security_score,
)

main = Blueprint("main", __name__)

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def _clean_domain(raw: str) -> str:
    raw = raw.strip()
    # If it looks like a URL (has a scheme or starts with //), parse it properly
    if "://" in raw or raw.startswith("//"):
        if not raw.startswith("//") and "://" not in raw:
            raw = "//" + raw
        try:
            parsed = urlparse(raw if "://" in raw else "http:" + raw)
            hostname = parsed.hostname or ""
            return hostname.lower()
        except Exception:
            pass
    # Otherwise treat as a bare domain/host, strip anything after the first /
    domain = raw.lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def _run_all_modules(domain: str, config) -> dict:
    verify_ssl = config.get("VERIFY_SSL", True)
    tasks = {
        "whois":       (whois_lookup.run,      [domain]),
        "dns":         (dns_records.run,        [domain]),
        "ssl":         (ssl_cert.run,           [domain, verify_ssl]),
        "geo":         (geolocation.run,        [domain, verify_ssl]),
        "headers":     (http_headers.run,       [domain, verify_ssl]),
        "reverse_dns": (reverse_dns.run,        [domain]),
        "email_sec":   (email_security.run,     [domain]),
        "cert_transparency":  (cert_transparency.run,  [domain, verify_ssl]),
        "html_subdomains":    (html_subdomains.run,    [domain, verify_ssl]),
        "rdap":               (rdap_lookup.run,        [domain, verify_ssl]),
        "asn":                (asn_info.run,           [domain, verify_ssl]),
        "waf":                (waf_detection.run,      [domain, verify_ssl]),
        "cookies":            (cookie_analysis.run,    [domain, verify_ssl]),
        "screenshot":  (screenshot.run,         [domain, config.get("SCREENSHOT_ENABLED", True), config.get("SCREENSHOT_TIMEOUT", 15)]),
        "tech":        (tech_detection.run,     [domain, verify_ssl]),
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(fn, *args): key
            for key, (fn, args) in tasks.items()
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return results


@main.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@main.route("/analyze", methods=["POST"])
def analyze():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        return render_template(
            "index.html",
            error=f"Rate limit exceeded. Please wait {retry_after} seconds before trying again.",
        )

    raw_domain = request.form.get("domain", "").strip()
    if not raw_domain:
        return render_template("index.html", error="Please enter a domain name.")

    domain = _clean_domain(raw_domain)

    if not DOMAIN_RE.match(domain):
        return render_template("index.html", error=f"'{raw_domain}' does not look like a valid domain name.")

    cache_key = f"analyze:{domain}"
    cached = cache.get(cache_key)
    if cached:
        return render_template("results.html", domain=domain, data=cached, from_cache=True)

    config = {
        "SUBDOMAIN_WORDLIST_SIZE": current_app.config.get("SUBDOMAIN_WORDLIST_SIZE", 50),
        "SCREENSHOT_ENABLED": current_app.config.get("SCREENSHOT_ENABLED", True),
        "SCREENSHOT_TIMEOUT": current_app.config.get("SCREENSHOT_TIMEOUT", 15),
        "VERIFY_SSL": current_app.config.get("VERIFY_SSL", True),
    }
    data = _run_all_modules(domain, config)

    # Derive SaaS detection from already-fetched TXT records (no extra DNS query)
    txt_records = (data.get("dns") or {}).get("records", {}).get("TXT", [])
    data["saas"] = saas_detection.run(txt_records)

    # Security score is derived from all other module results
    data["security_score"] = security_score.run(data)

    cache.set(cache_key, data)

    return render_template("results.html", domain=domain, data=data, from_cache=False)


@main.route("/api/analyze", methods=["GET"])
def api_analyze():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        return jsonify({"error": "rate_limit_exceeded", "retry_after": retry_after}), 429

    raw_domain = request.args.get("domain", "").strip()
    if not raw_domain:
        return jsonify({"error": "domain parameter is required"}), 400

    domain = _clean_domain(raw_domain)
    if not DOMAIN_RE.match(domain):
        return jsonify({"error": f"Invalid domain: {raw_domain}"}), 400

    cache_key = f"analyze:{domain}"
    cached = cache.get(cache_key)
    if cached:
        return jsonify({"domain": domain, "cached": True, "data": cached})

    config = {
        "SUBDOMAIN_WORDLIST_SIZE": current_app.config.get("SUBDOMAIN_WORDLIST_SIZE", 50),
        "SCREENSHOT_ENABLED": False,  # Disable for API
        "SCREENSHOT_TIMEOUT": current_app.config.get("SCREENSHOT_TIMEOUT", 15),
        "VERIFY_SSL": current_app.config.get("VERIFY_SSL", True),
    }
    data = _run_all_modules(domain, config)

    txt_records = (data.get("dns") or {}).get("records", {}).get("TXT", [])
    data["saas"] = saas_detection.run(txt_records)
    data["security_score"] = security_score.run(data)

    cache.set(cache_key, data)

    return jsonify({"domain": domain, "cached": False, "data": data})
