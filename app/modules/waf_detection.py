"""WAF / CDN / proxy detection from HTTP response headers and body."""
from __future__ import annotations
import urllib3
import requests

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"}

# (waf_name, category, detection_fn)
# detection_fn receives (headers_lower: dict, cookies_lower: set, body: str) -> bool
_RULES: list[tuple[str, str, object]] = [
    # CDN / Cloud
    ("Cloudflare",     "CDN",        lambda h, c, b: "cf-ray" in h or h.get("server", "") == "cloudflare"),
    ("AWS CloudFront", "CDN",        lambda h, c, b: "x-amz-cf-id" in h or "cloudfront" in h.get("x-cache", "").lower()),
    ("Fastly",         "CDN",        lambda h, c, b: "x-fastly-request-id" in h or "fastly" in h.get("via", "").lower()),
    ("Azure Front Door","CDN",       lambda h, c, b: "x-azure-ref" in h or "x-fd-healthproberesult" in h),
    ("Varnish",        "CDN",        lambda h, c, b: "x-varnish" in h or "varnish" in h.get("via", "").lower()),
    ("Akamai",         "CDN",        lambda h, c, b: "x-akamai-transformed" in h or "akamai-request-id" in h or "akamaierror" in b.lower()),
    ("Sucuri",         "WAF",        lambda h, c, b: "x-sucuri-id" in h or "x-sucuri-cache" in h),
    ("Imperva",        "WAF",        lambda h, c, b: "x-iinfo" in h or "incapsula" in b.lower() or any("incap_ses" in ck for ck in c)),
    ("F5 BIG-IP",      "WAF",        lambda h, c, b: "bigipserver" in c or "f5" in h.get("server", "").lower() or "big-ip" in h.get("server", "").lower()),
    ("Barracuda",      "WAF",        lambda h, c, b: any("barra_counter" in ck for ck in c)),
    ("Fortinet",       "WAF",        lambda h, c, b: "fortigate" in h.get("server", "").lower() or any("cookiesession1" in ck for ck in c)),
    ("Reblaze",        "WAF",        lambda h, c, b: any("rbzid" in ck for ck in c)),
    ("StackPath",      "CDN",        lambda h, c, b: "x-sp-url" in h or "x-stackpath" in h),
    ("KeyCDN",         "CDN",        lambda h, c, b: "x-edge-location" in h and "keycdn" in h.get("x-edge-location", "").lower()),
    ("Netlify",        "CDN/Hosting",lambda h, c, b: "x-nf-request-id" in h),
    ("Vercel",         "CDN/Hosting",lambda h, c, b: "x-vercel-id" in h),
    ("Nginx",          "Web Server", lambda h, c, b: h.get("server", "").lower().startswith("nginx")),
    ("Apache",         "Web Server", lambda h, c, b: h.get("server", "").lower().startswith("apache")),
    ("IIS",            "Web Server", lambda h, c, b: "iis" in h.get("server", "").lower() or "asp.net" in h.get("x-powered-by", "").lower()),
    ("LiteSpeed",      "Web Server", lambda h, c, b: "litespeed" in h.get("server", "").lower()),
    ("Caddy",          "Web Server", lambda h, c, b: h.get("server", "").lower().startswith("caddy")),
]


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=10,
                verify=verify_ssl,
                allow_redirects=True,
                headers=_HEADERS,
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            cookies_lower = {c.lower() for c in resp.cookies.keys()}
            try:
                body = resp.text[:4096]
            except Exception:
                body = ""

            detected = []
            for name, category, fn in _RULES:
                try:
                    if fn(headers_lower, cookies_lower, body):
                        detected.append({"name": name, "category": category})
                except Exception:
                    pass

            # Extract raw server header for display
            server = resp.headers.get("Server") or resp.headers.get("server")

            return {
                "detected": detected,
                "count": len(detected),
                "server_header": server,
            }
        except requests.RequestException:
            continue
        except Exception as exc:
            return {"error": f"WAF detection failed: {exc}"}

    return {"error": "Could not connect to domain.", "detected": [], "count": 0}
