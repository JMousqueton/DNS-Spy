# DNS Spy

**Comprehensive domain intelligence tool in one click.**

DNS Spy runs 16+ analysis modules in parallel and aggregates the results into a clean, searchable web UI with dark/light mode.

![DNS Spy Screenshot](https://raw.githubusercontent.com/JMousqueton/DNS-Spy/main/docs/screenshot.png)

## Features

| Module | Description |
|--------|-------------|
| 🔒 Security Score | Aggregate A–F grade from all security checks |
| 📋 WHOIS | Registrar, owner, key dates |
| 🗄️ RDAP | Structured registration data (RDAP protocol) |
| 🔗 DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA via DNS-over-HTTPS |
| 🔐 SSL / TLS | Certificate details, expiry, chain |
| 🌍 Geolocation | Country, city, ISP (IPv4 + IPv6) |
| 📡 ASN / BGP | Autonomous system, prefixes, RIR info |
| 📶 HTTP Headers | Security headers, grade, redirect chain |
| 🛡️ WAF / CDN | Cloudflare, Akamai, AWS, Fastly, Imperva, F5… |
| 🍪 Cookie Security | HttpOnly, Secure, SameSite flags per cookie |
| ↩️ Reverse DNS | PTR records for all resolved IPs |
| ✉️ Email Security | SPF, DMARC, DKIM, BIMI, MTA-STS |
| 📜 Cert Transparency | Certificates from crt.sh, subdomain discovery |
| 💻 HTML Subdomains | Subdomains extracted from page source |
| 📷 Screenshot | Visual preview via Playwright/Chromium |
| ⚙️ Tech Stack | CMS, frameworks, CDN, analytics (127+ signatures) |
| ☁️ SaaS Detection | Google Workspace, M365, HubSpot, Okta… from TXT records |

## Quick Start

### With Docker (recommended)

```bash
cp .env.example .env
docker compose up -d
```

Open [http://localhost:5005](http://localhost:5005).

### Without Docker

**Requirements:** Python 3.11+

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium

cp .env.example .env
python run.py
```

Open [http://localhost:5005](http://localhost:5005).

## Configuration

Copy `.env.example` to `.env` and edit as needed:

```env
SECRET_KEY=change-me-to-a-random-secret
DEBUG=false
CACHE_TTL=300             # Result cache in seconds (default: 5 min)
RATE_LIMIT_REQUESTS=10    # Max requests per window per IP
RATE_LIMIT_WINDOW=60      # Rate limit window in seconds
SCREENSHOT_ENABLED=true
SCREENSHOT_TIMEOUT=15
```

### Behind a MITM proxy (Zscaler, etc.)

Set `DEBUG=true` or `VERIFY_SSL=false` to disable SSL certificate verification for outbound requests. DNS resolution automatically uses DNS-over-HTTPS (port 443) to bypass port-53 blocks.

```env
DEBUG=true
```

## API

A JSON API is available alongside the web UI:

```
GET /api/analyze?domain=example.com
```

```json
{
  "domain": "example.com",
  "cached": false,
  "data": { ... }
}
```

## Architecture

```
run.py
└── app/
    ├── __init__.py       Flask factory, cache & rate limiter init
    ├── routes.py         Web + API routes, parallel module runner
    ├── dns_client.py     DNS-over-HTTPS client (Cloudflare → Google → Quad9)
    ├── cache.py          In-memory TTL cache (thread-safe)
    ├── rate_limiter.py   Per-IP sliding window rate limiter
    └── modules/          One file per analysis module
```

All modules run concurrently via `ThreadPoolExecutor`. Results are cached in memory for `CACHE_TTL` seconds.

## Author

**Julien Mousqueton**  
CISO @ [Cohesity](https://www.cohesity.com)  
Owner of [ransomware.live](https://www.ransomware.live)

## License

MIT
