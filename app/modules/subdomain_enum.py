"""Subdomain enumeration module via DNS brute-force."""
from __future__ import annotations
import concurrent.futures
from app.dns_client import query as doh_query

# Common subdomains wordlist
SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev", "staging",
    "test", "portal", "m", "mobile", "app", "secure", "cdn", "media", "img",
    "images", "assets", "static", "help", "support", "docs", "wiki", "forum",
    "community", "status", "vpn", "remote", "gitlab", "github", "jira",
    "confluence", "jenkins", "ci", "monitor", "smtp", "pop", "imap",
    "webmail", "mx", "ns1", "ns2", "dns", "dns1", "dns2", "cpanel", "whm",
    "webdisk", "autodiscover", "autoconfig", "calendar", "chat", "crm",
    "dashboard", "demo", "download", "files", "git", "grafana", "ldap",
    "login", "panel", "payment", "proxy", "redis", "signup", "sso",
    "stage", "upload", "video", "vpn2", "web", "www2", "xml", "beta",
    "alpha", "new", "old", "v1", "v2", "intranet", "internal", "private",
    "public", "s3", "storage", "backup", "db", "database", "mysql",
    "pgsql", "postgres", "mongo", "elasticsearch", "kibana", "analytics",
    "tracking", "metrics", "logs", "alerts", "reporting", "data",
    "exchange", "office", "outlook", "teams", "meet", "zoom",
]


def _check_subdomain(sub: str, domain: str) -> dict | None:
    fqdn = f"{sub}.{domain}"
    try:
        ips = doh_query(fqdn, "A", timeout=5)
        if ips:
            return {"subdomain": fqdn, "ips": ips, "type": "A"}
    except Exception:
        pass

    try:
        targets = doh_query(fqdn, "CNAME", timeout=5)
        if targets:
            return {"subdomain": fqdn, "cname": targets, "type": "CNAME"}
    except Exception:
        pass

    return None


def run(domain: str, limit: int = 50) -> dict:
    try:
        wordlist = SUBDOMAINS[:limit]
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(_check_subdomain, sub, domain): sub
                for sub in wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        found.sort(key=lambda x: x["subdomain"])

        return {
            "found": found,
            "count": len(found),
            "checked": len(wordlist),
        }
    except Exception as exc:
        return {"error": f"Subdomain enumeration failed: {exc}"}
