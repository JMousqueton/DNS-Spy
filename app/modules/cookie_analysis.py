"""Cookie security analysis — inspect Set-Cookie flags."""
from __future__ import annotations
import urllib3
import requests

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"}


def _parse_set_cookie(raw: str) -> dict:
    """Parse a single Set-Cookie header string into a structured dict."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return {}

    name_part = parts[0]
    name, _, value = name_part.partition("=")
    name = name.strip()
    value = value.strip()

    attrs_lower = {p.lower().split("=")[0].strip() for p in parts[1:]}
    attr_map = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attr_map[k.strip().lower()] = v.strip()

    http_only = "httponly" in attrs_lower
    secure = "secure" in attrs_lower
    samesite = attr_map.get("samesite")
    path = attr_map.get("path", "/")
    domain = attr_map.get("domain")
    expires = attr_map.get("expires")
    max_age = attr_map.get("max-age")

    # Determine issues
    issues = []
    if not http_only:
        issues.append("Missing HttpOnly")
    if not secure:
        issues.append("Missing Secure")
    if not samesite:
        issues.append("Missing SameSite")
    elif samesite.lower() == "none" and not secure:
        issues.append("SameSite=None requires Secure")

    return {
        "name": name,
        "value_preview": value[:20] + "…" if len(value) > 20 else value,
        "http_only": http_only,
        "secure": secure,
        "samesite": samesite,
        "path": path,
        "domain": domain,
        "expires": expires or (f"Max-Age={max_age}" if max_age else "Session"),
        "issues": issues,
        "secure_score": 3 - len(issues) if len(issues) <= 3 else 0,
    }


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

            # Collect all Set-Cookie headers (urllib3 preserves duplicates)
            raw_cookies: list[str] = []
            try:
                raw_cookies = resp.raw.headers.getlist("set-cookie")
            except Exception:
                sc = resp.headers.get("Set-Cookie")
                if sc:
                    raw_cookies = [sc]

            cookies = [_parse_set_cookie(r) for r in raw_cookies if r.strip()]
            insecure = [c for c in cookies if c.get("issues")]

            return {
                "count": len(cookies),
                "cookies": cookies,
                "insecure_count": len(insecure),
                "scheme": scheme,
            }
        except requests.RequestException:
            continue
        except Exception as exc:
            return {"error": f"Cookie analysis failed: {exc}"}

    return {"error": "Could not connect to domain.", "count": 0, "cookies": [], "insecure_count": 0}
