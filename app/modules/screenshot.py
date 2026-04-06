"""Website screenshot capture module using Playwright."""
from __future__ import annotations
import os
import time
import hashlib


SCREENSHOTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "static", "screenshots"
)


def run(domain: str, enabled: bool = True, timeout: int = 15) -> dict:
    if not enabled:
        return {"enabled": False, "path": None, "error": None}

    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    filename = hashlib.md5(domain.encode()).hexdigest() + ".png"
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    web_path = f"/static/screenshots/{filename}"

    # Return cached screenshot if recent (< 5 min)
    if os.path.exists(filepath):
        age = time.time() - os.path.getmtime(filepath)
        if age < 300:
            return {"enabled": True, "path": web_path, "error": None, "cached": True}

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (compatible; DNS-Spy/1.0)",
                ignore_https_errors=True,
            )
            page = context.new_page()
            try:
                page.goto(f"https://{domain}", timeout=timeout * 1000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                page.screenshot(path=filepath, full_page=False, clip={"x": 0, "y": 0, "width": 1280, "height": 800})
            except PlaywrightTimeout:
                # Fallback to http
                try:
                    page.goto(f"http://{domain}", timeout=timeout * 1000, wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)
                    page.screenshot(path=filepath, full_page=False, clip={"x": 0, "y": 0, "width": 1280, "height": 800})
                except Exception as exc:
                    return {"enabled": True, "path": None, "error": f"Screenshot timed out: {exc}"}
            finally:
                context.close()
                browser.close()

        return {"enabled": True, "path": web_path, "error": None, "cached": False}

    except ImportError:
        return {
            "enabled": False,
            "path": None,
            "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
        }
    except Exception as exc:
        return {"enabled": True, "path": None, "error": f"Screenshot failed: {exc}"}
