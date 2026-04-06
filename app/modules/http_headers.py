"""HTTP response headers module."""
from __future__ import annotations
import warnings
import requests
from requests.exceptions import RequestException


def _check_hsts_preload(domain: str, verify_ssl: bool) -> bool:
    """Return True if domain is on the HSTS preload list."""
    try:
        resp = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={domain}",
            timeout=8,
            verify=verify_ssl,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"},
        )
        return resp.json().get("status") == "preloaded"
    except Exception:
        return False


# Security headers to highlight
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
    "expect-ct": "Expect-CT",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-resource-policy": "CORP",
}


def _grade_security(headers_lower: dict) -> str:
    present = sum(1 for h in SECURITY_HEADERS if h in headers_lower)
    total = len(SECURITY_HEADERS)
    ratio = present / total
    if ratio >= 0.8:
        return "A"
    elif ratio >= 0.6:
        return "B"
    elif ratio >= 0.4:
        return "C"
    elif ratio >= 0.2:
        return "D"
    return "F"


def run(domain: str, verify_ssl: bool = True) -> dict:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            with warnings.catch_warnings():
                if not verify_ssl:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    verify=verify_ssl,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"},
                )
            headers = dict(resp.headers)
            headers_lower = {k.lower(): v for k, v in headers.items()}

            security_analysis = {}
            for header_key, display_name in SECURITY_HEADERS.items():
                security_analysis[display_name] = {
                    "present": header_key in headers_lower,
                    "value": headers_lower.get(header_key),
                }

            redirect_chain = [r.url for r in resp.history] + [resp.url]

            hsts_present = "strict-transport-security" in headers_lower
            hsts_preloaded = _check_hsts_preload(domain, verify_ssl) if hsts_present else False

            return {
                "url": url,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "redirect_chain": redirect_chain,
                "headers": headers,
                "security_headers": security_analysis,
                "security_grade": _grade_security(headers_lower),
                "server": headers_lower.get("server"),
                "content_type": headers_lower.get("content-type"),
                "x_powered_by": headers_lower.get("x-powered-by"),
                "hsts_preloaded": hsts_preloaded,
            }
        except RequestException:
            continue
        except Exception as exc:
            return {"error": f"HTTP headers fetch failed: {exc}"}

    return {"error": "Could not connect to the domain over HTTP or HTTPS."}
