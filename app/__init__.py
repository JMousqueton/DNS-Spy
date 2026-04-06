import urllib3
from flask import Flask, redirect, url_for
from config import Config
from app.cache import Cache
from app.rate_limiter import RateLimiter
from app import dns_client

cache = Cache()
rate_limiter = RateLimiter()


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)

    verify_ssl = app.config.get("VERIFY_SSL", True)
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    dns_client.configure(verify_ssl)

    cache.init(ttl=app.config["CACHE_TTL"])
    rate_limiter.init(
        max_requests=app.config["RATE_LIMIT_REQUESTS"],
        window=app.config["RATE_LIMIT_WINDOW"],
    )

    from app.routes import main
    app.register_blueprint(main)

    @app.errorhandler(404)
    def not_found(e):
        return redirect(url_for("main.index"))

    @app.errorhandler(405)
    def method_not_allowed(e):
        return redirect(url_for("main.index"))

    return app
