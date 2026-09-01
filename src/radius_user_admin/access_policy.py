from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any


class AccessPolicyError(ValueError):
    pass


DEFAULT_ALLOWED_DESTINATIONS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
MAX_RULES = 24
MAX_ACES = 64
MAX_REPLY_ATTRIBUTES = 48
MAX_REPLY_ATTRIBUTE_BYTES = 3000
MAX_OBJECTS = 64
MAX_OBJECT_DESCRIPTION = 120
MAX_REFERENCE_DEPTH = 8
PROTOCOL_ORDER = {"ip": 0, "icmp": 1, "tcp": 2, "udp": 3}
OBJECT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")


def full_access_policy() -> dict[str, Any]:
    return {"mode": "full", "rules": []}


def allowed_destinations(value: str | None = None) -> tuple[ipaddress.IPv4Network, ...]:
    raw = value
    if raw is None:
        raw = os.environ.get(
            "RADIUS_ADMIN_POLICY_DESTINATIONS", DEFAULT_ALLOWED_DESTINATIONS
        )
    networks: list[ipaddress.IPv4Network] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise AccessPolicyError(
                "The configured policy destination allowlist is invalid."
            ) from exc
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen == 0:
            raise AccessPolicyError("The configured policy destination allowlist is unsafe.")
        networks.append(network)
    if not networks:
        raise AccessPolicyError("No policy destinations have been configured.")
    return tuple(networks)


def clean_object_name(value: object) -> str:
    name = str(value or "").strip().lower()
    if not OBJECT_NAME.fullmatch(name):
        raise AccessPolicyError(
            "Object names use 1-32 lowercase letters, digits, dots, dashes or underscores."
        )
    return name


def _clean_ports(value: object, protocol: str) -> list[list[int]]:
    if isinstance(value, str):
        raw_items: list[object] = [item.strip() for item in value.split(",") if item.strip()]
    elif value in (None, []):
        raw_items = []
    elif isinstance(value, list):
        raw_items = value
    else:
        raise AccessPolicyError("Ports must be a comma-separated list or a list of ranges.")

    if protocol not in {"tcp", "udp"}:
        if raw_items:
            raise AccessPolicyError("Only TCP and UDP rules may contain ports.")
        return []
    if not raw_items:
        raise AccessPolicyError("TCP and UDP rules require at least one port or port range.")

    ranges: set[tuple[int, int]] = set()
    for item in raw_items:
        if isinstance(item, str):
            pieces = item.split("-", 1)
            try:
                start = int(pieces[0])
                end = int(pieces[-1])
            except ValueError as exc:
                raise AccessPolicyError(
                    "Ports must be numbers or ranges such as 8000-8010."
                ) from exc
        elif (
            isinstance(item, list)
            and len(item) == 2
            and all(isinstance(port, int) and not isinstance(port, bool) for port in item)
        ):
            start, end = item
        else:
            raise AccessPolicyError("Each port must be a number or a start/end range.")
        if not 1 <= start <= end <= 65535:
            raise AccessPolicyError("Ports must be between 1 and 65535 with ordered ranges.")
        ranges.add((start, end))
    return [[start, end] for start, end in sorted(ranges)]


def _clean_rule(
    raw_rule: object, allowed: tuple[ipaddress.IPv4Network, ...]
) -> dict[str, Any]:
    if not isinstance(raw_rule, dict) or set(raw_rule) - {
        "destination",
        "protocol",
        "ports",
    }:
        raise AccessPolicyError("Each access rule must contain a destination and protocol.")
    raw_destination = str(raw_rule.get("destination") or "").strip()
    if not raw_destination:
        raise AccessPolicyError("Every access rule requires a destination.")
    try:
        destination = ipaddress.ip_network(raw_destination, strict=False)
    except ValueError as exc:
        raise AccessPolicyError(
            "Destinations must be IPv4 addresses or CIDR networks."
        ) from exc
    if not isinstance(destination, ipaddress.IPv4Network):
        raise AccessPolicyError("Only IPv4 destinations are supported.")
    if destination.prefixlen == 0 or not any(destination.subnet_of(item) for item in allowed):
        raise AccessPolicyError("The destination is outside the configured private networks.")
    if any(
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        for address in (destination.network_address, destination.broadcast_address)
    ):
        raise AccessPolicyError(
            "Loopback, link-local, multicast and unspecified addresses are denied."
        )

    protocol = str(raw_rule.get("protocol") or "").strip().lower()
    if protocol not in PROTOCOL_ORDER:
        raise AccessPolicyError("Protocols are limited to IP, ICMP, TCP and UDP.")
    ports = _clean_ports(raw_rule.get("ports"), protocol)
    return {
        "destination": destination.with_prefixlen,
        "protocol": protocol,
        "ports": ports,
    }


def _clean_entry(
    raw: object, allowed: tuple[ipaddress.IPv4Network, ...]
) -> dict[str, Any]:
    if isinstance(raw, dict) and set(raw) == {"object"}:
        return {"object": clean_object_name(raw.get("object"))}
    return _clean_rule(raw, allowed)


def _canonical_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    canonical = {
        json.dumps(rule, sort_keys=True, separators=(",", ":")): rule for rule in rules
    }
    return sorted(
        canonical.values(),
        key=lambda rule: (
            int(ipaddress.ip_network(rule["destination"]).network_address),
            ipaddress.ip_network(rule["destination"]).prefixlen,
            PROTOCOL_ORDER[rule["protocol"]],
            rule["ports"],
        ),
    )


def _canonical_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    references = sorted({entry["object"] for entry in entries if "object" in entry})
    rules = _canonical_rules([entry for entry in entries if "object" not in entry])
    return [{"object": name} for name in references] + rules


def _resolve_reference(
    name: str,
    objects: dict[str, dict[str, Any]],
    seen: frozenset[str],
    depth: int,
) -> list[dict[str, Any]]:
    if depth > MAX_REFERENCE_DEPTH:
        raise AccessPolicyError("Access objects are nested too deeply.")
    if name in seen:
        raise AccessPolicyError("Access objects may not reference each other in a loop.")
    if name not in objects:
        raise AccessPolicyError("An access rule references an unknown saved object.")
    rules: list[dict[str, Any]] = []
    for entry in objects[name]["rules"]:
        if "object" in entry:
            rules.extend(
                _resolve_reference(entry["object"], objects, seen | {name}, depth + 1)
            )
        else:
            rules.append(entry)
    return rules


def _resolve_entries(
    entries: list[dict[str, Any]], objects: dict[str, dict[str, Any]] | None
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for entry in entries:
        if "object" in entry:
            rules.extend(
                _resolve_reference(entry["object"], objects or {}, frozenset(), 1)
            )
        else:
            rules.append(entry)
    return _canonical_rules(rules)


def clean_access_objects(
    value: object,
    *,
    destination_allowlist: tuple[ipaddress.IPv4Network, ...] | None = None,
) -> dict[str, dict[str, Any]]:
    if value in (None, []):
        return {}
    if not isinstance(value, list):
        raise AccessPolicyError("The saved access object store is invalid.")
    if len(value) > MAX_OBJECTS:
        raise AccessPolicyError(f"At most {MAX_OBJECTS} access objects are supported.")
    allowed = destination_allowlist or allowed_destinations()
    objects: dict[str, dict[str, Any]] = {}
    for raw in value:
        if not isinstance(raw, dict) or set(raw) - {"name", "description", "rules"}:
            raise AccessPolicyError("Each access object needs a name and its rules.")
        name = clean_object_name(raw.get("name"))
        if name in objects:
            raise AccessPolicyError("Access object names must be unique.")
        description = str(raw.get("description") or "").strip()
        if len(description) > MAX_OBJECT_DESCRIPTION:
            raise AccessPolicyError(
                f"Object descriptions are limited to {MAX_OBJECT_DESCRIPTION} characters."
            )
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise AccessPolicyError("Each access object requires at least one rule.")
        if len(raw_rules) > MAX_RULES:
            raise AccessPolicyError(
                f"Access objects support at most {MAX_RULES} rules each."
            )
        entries = [_clean_entry(item, allowed) for item in raw_rules]
        objects[name] = {
            "name": name,
            "description": description,
            "rules": _canonical_entries(entries),
        }
    for item in objects.values():
        for entry in item["rules"]:
            if "object" in entry and entry["object"] not in objects:
                raise AccessPolicyError(
                    "An access object references an unknown saved object."
                )
    for name in objects:
        _resolve_reference(name, objects, frozenset(), 1)
    return objects


def clean_access_policy(
    value: object,
    *,
    destination_allowlist: tuple[ipaddress.IPv4Network, ...] | None = None,
    objects: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if value is None:
        return full_access_policy()
    if not isinstance(value, dict):
        raise AccessPolicyError("The access policy is invalid.")
    if set(value) - {"mode", "rules"}:
        raise AccessPolicyError("The access policy contains unsupported fields.")
    mode = str(value.get("mode") or "").strip().lower()
    if mode == "full":
        if value.get("rules") not in (None, []):
            raise AccessPolicyError("Full access cannot contain restricted rules.")
        return full_access_policy()
    if mode != "custom":
        raise AccessPolicyError("Choose full or custom access.")

    raw_rules = value.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise AccessPolicyError("Custom access requires at least one rule.")
    if len(raw_rules) > MAX_RULES:
        raise AccessPolicyError(f"Custom access supports at most {MAX_RULES} rules.")
    allowed = destination_allowlist or allowed_destinations()
    entries = [_clean_entry(raw_rule, allowed) for raw_rule in raw_rules]
    for entry in entries:
        if "object" in entry and (objects is None or entry["object"] not in objects):
            raise AccessPolicyError("An access rule references an unknown saved object.")
    resolved = _resolve_entries(entries, objects)
    if len(resolved) > MAX_RULES:
        raise AccessPolicyError(
            f"The policy resolves to more than {MAX_RULES} rules."
        )
    ace_count = sum(max(1, len(rule["ports"])) for rule in resolved)
    if ace_count + 1 > MAX_ACES:
        raise AccessPolicyError(f"Custom access supports at most {MAX_ACES - 1} permit entries.")
    return {"mode": "custom", "rules": _canonical_entries(entries)}


def resolved_policy(
    policy: dict[str, Any],
    *,
    objects: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if policy["mode"] == "full":
        return full_access_policy()
    return {"mode": "custom", "rules": _resolve_entries(policy["rules"], objects)}


def cisco_avpairs(
    policy: dict[str, Any],
    *,
    destination_allowlist: tuple[ipaddress.IPv4Network, ...] | None = None,
    objects: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    clean = clean_access_policy(
        policy, destination_allowlist=destination_allowlist, objects=objects
    )
    if clean["mode"] == "full":
        return []
    rules = _resolve_entries(clean["rules"], objects)
    routes = sorted({rule["destination"] for rule in rules})
    attributes = [f"ipsec:route-set=prefix {route}" for route in routes]
    sequence = 1
    for rule in rules:
        destination = _ios_destination(rule["destination"])
        port_ranges = rule["ports"] or [[0, 0]]
        for start, end in port_ranges:
            suffix = ""
            if start:
                suffix = f" eq {start}" if start == end else f" range {start} {end}"
            attributes.append(
                f"ip:inacl#{sequence}=permit {rule['protocol']} any {destination}{suffix}"
            )
            sequence += 1
    attributes.append(f"ip:inacl#{sequence}=deny ip any any")
    encoded_size = sum(len(attribute.encode()) + 8 for attribute in attributes)
    if len(attributes) > MAX_REPLY_ATTRIBUTES or encoded_size > MAX_REPLY_ATTRIBUTE_BYTES:
        raise AccessPolicyError(
            "The custom policy is too large for one RADIUS Access-Accept response."
        )
    return attributes


def _ios_destination(value: str) -> str:
    network = ipaddress.ip_network(value)
    if network.prefixlen == 32:
        return f"host {network.network_address}"
    return f"{network.network_address} {network.hostmask}"


def access_summary(
    policy: dict[str, Any],
    *,
    destination_allowlist: tuple[ipaddress.IPv4Network, ...] | None = None,
    objects: dict[str, dict[str, Any]] | None = None,
) -> str:
    clean = clean_access_policy(
        policy, destination_allowlist=destination_allowlist, objects=objects
    )
    if clean["mode"] == "full":
        return "Full access"
    rules = _resolve_entries(clean["rules"], objects)
    destinations = len({rule["destination"] for rule in rules})
    services = sum(max(1, len(rule["ports"])) for rule in rules)
    destination_label = "destination" if destinations == 1 else "destinations"
    service_label = "service" if services == 1 else "services"
    return f"Custom · {destinations} {destination_label} · {services} {service_label}"
