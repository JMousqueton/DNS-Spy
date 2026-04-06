import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dns-spy-secret-key-change-in-prod")
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

    # Cache settings (in-memory)
    CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))  # 5 minutes

    # Rate limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 10))
    RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))  # seconds

    # Subdomain wordlist size (top N subdomains to try)
    SUBDOMAIN_WORDLIST_SIZE = int(os.environ.get("SUBDOMAIN_WORDLIST_SIZE", 50))

    # Request timeout
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))

    # Screenshot
    SCREENSHOT_ENABLED = os.environ.get("SCREENSHOT_ENABLED", "true").lower() == "true"
    SCREENSHOT_TIMEOUT = int(os.environ.get("SCREENSHOT_TIMEOUT", 15))

    # SSL verification — auto-disabled in DEBUG mode (e.g. behind Zscaler / MITM proxy).
    # Override explicitly with VERIFY_SSL=true/false env var.
    @classmethod
    def _default_verify_ssl(cls) -> bool:
        env = os.environ.get("VERIFY_SSL")
        if env is not None:
            return env.lower() == "true"
        return not cls.DEBUG  # disabled when DEBUG=true

    VERIFY_SSL: bool = not (os.environ.get("DEBUG", "false").lower() == "true") \
        if os.environ.get("VERIFY_SSL") is None \
        else os.environ.get("VERIFY_SSL", "true").lower() == "true"
