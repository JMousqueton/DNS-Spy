import os
import sys

# Allow: python run.py --debug
if "--debug" in sys.argv:
    os.environ["DEBUG"] = "true"

from app import create_app

app = create_app()

if __name__ == "__main__":
    verify_ssl = app.config["VERIFY_SSL"]
    debug = app.config["DEBUG"]
    print(f"  * SSL verification : {'ENABLED' if verify_ssl else 'DISABLED (MITM/proxy mode)'}")
    if not verify_ssl:
        print("  * WARNING: certificate validation is OFF — do not use in production")
    app.run(host="0.0.0.0", port=5005, debug=debug)
