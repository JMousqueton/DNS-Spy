"""SSL/TLS certificate details module."""
from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


def _parse_san(cert: x509.Certificate) -> list[str]:
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        return []


def _parse_name(name: x509.Name) -> dict:
    def get(oid):
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, Exception):
            return None

    return {
        "common_name": get(NameOID.COMMON_NAME),
        "organization": get(NameOID.ORGANIZATION_NAME),
        "country": get(NameOID.COUNTRY_NAME),
        "state": get(NameOID.STATE_OR_PROVINCE_NAME),
        "locality": get(NameOID.LOCALITY_NAME),
    }


def run(domain: str, verify_ssl: bool = True) -> dict:
    try:
        ctx = ssl.create_default_context()

        if not verify_ssl:
            # Disable hostname check and cert verification so we can still
            # retrieve and inspect the raw certificate (e.g. behind Zscaler).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                cipher = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_remaining = (not_after - now).days

        pub_key = cert.public_key()
        key_type = type(pub_key).__name__
        try:
            key_size = pub_key.key_size
        except AttributeError:
            key_size = None

        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

        result = {
            "subject": _parse_name(cert.subject),
            "issuer": _parse_name(cert.issuer),
            "serial_number": str(cert.serial_number),
            "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining": days_remaining,
            "expired": days_remaining < 0,
            "expiring_soon": 0 <= days_remaining <= 30,
            "san": _parse_san(cert),
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "key_type": key_type,
            "key_size": key_size,
            "signature_algorithm": sig_algo,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
        }

        # Warn in the UI when cert validation was skipped
        if not verify_ssl:
            result["verification_skipped"] = True

        return result

    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}"}
    except ConnectionRefusedError:
        return {"error": "Port 443 is closed or not reachable."}
    except socket.timeout:
        return {"error": "Connection timed out."}
    except Exception as exc:
        return {"error": f"SSL lookup failed: {exc}"}
