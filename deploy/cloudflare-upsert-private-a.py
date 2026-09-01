#!/usr/bin/python3
"""Create the unproxied private A record used by internal clients."""

from __future__ import annotations

import configparser
import json
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "your-domain.com"
NAME = "radius.your-domain.com"
ADDRESS = "192.0.2.112"
CREDENTIALS = "/etc/letsencrypt/cloudflare.ini"


def request(method: str, path: str, token: str, body: dict | None = None):
    payload = None if body is None else json.dumps(body).encode()
    operation = urllib.request.Request(  # noqa: S310 - API is a fixed HTTPS origin.
        API + path,
        data=payload,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(operation, timeout=20) as response:  # noqa: S310
        result = json.load(response)
    if not result.get("success"):
        raise RuntimeError("Cloudflare API rejected the DNS change.")
    return result["result"]


def main() -> None:
    config = configparser.ConfigParser()
    config.read_string("[cloudflare]\n" + open(CREDENTIALS, encoding="utf-8").read())
    token = config["cloudflare"]["dns_cloudflare_api_token"]
    query = urllib.parse.urlencode({"name": ZONE, "status": "active"})
    zones = request("GET", f"/zones?{query}", token)
    if len(zones) != 1:
        raise RuntimeError("Expected one active DNS zone.")
    zone_id = zones[0]["id"]
    query = urllib.parse.urlencode({"type": "A", "name": NAME})
    records = request("GET", f"/zones/{zone_id}/dns_records?{query}", token)
    desired = {"type": "A", "name": NAME, "content": ADDRESS, "ttl": 300, "proxied": False}
    if not records:
        result = request("POST", f"/zones/{zone_id}/dns_records", token, desired)
        action = "created"
    elif len(records) == 1:
        result = request(
            "PATCH", f"/zones/{zone_id}/dns_records/{records[0]['id']}", token, desired
        )
        action = "updated" if records[0]["content"] != ADDRESS else "unchanged"
    else:
        raise RuntimeError("Multiple A records require manual review.")
    print(json.dumps({"action": action, "name": result["name"], "content": result["content"]}))


if __name__ == "__main__":
    main()
