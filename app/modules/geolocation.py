"""IP geolocation module — supports both IPv4 and IPv6 via ip-api.com."""
from __future__ import annotations
import socket
import requests

_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"


def _resolve(domain: str, family: socket.AddressFamily) -> str | None:
    try:
        infos = socket.getaddrinfo(domain, None, family)
        return infos[0][4][0] if infos else None
    except socket.gaierror:
        return None


def _geolocate(ip: str) -> dict:
    """Query ip-api.com for a single IP (IPv4 or IPv6). Uses plain HTTP — unaffected by MITM."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": _FIELDS},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return {"ip": ip, "error": data.get("message", "Geolocation failed")}

        return {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "asname": data.get("asname"),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
            "is_mobile": data.get("mobile", False),
        }
    except Exception as exc:
        return {"ip": ip, "error": f"Geolocation API error: {exc}"}


def run(domain: str, verify_ssl: bool = True) -> dict:
    ipv4 = _resolve(domain, socket.AF_INET)
    ipv6 = _resolve(domain, socket.AF_INET6)

    if not ipv4 and not ipv6:
        return {"error": f"Could not resolve any IP address for {domain}"}

    result: dict = {}

    if ipv4:
        geo4 = _geolocate(ipv4)
        result["ipv4"] = geo4
        # Top-level fields mirror IPv4 for backward-compat with existing template chips
        result.update({k: v for k, v in geo4.items() if k != "error"})
        result["ip"] = ipv4

    if ipv6:
        geo6 = _geolocate(ipv6)
        result["ipv6"] = geo6
        # If no IPv4, also populate top-level from IPv6
        if not ipv4:
            result.update({k: v for k, v in geo6.items() if k != "error"})
            result["ip"] = ipv6

    return result
