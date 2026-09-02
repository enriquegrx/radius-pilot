"""Country-based access policy: region presets and the allow/deny decision.

Pure data and logic, no I/O. Used by the console to evaluate what a policy
would do (monitor mode) and by the enforcement hook to actually decide. A policy
is a small dict::

    {
        "regions": ["EU_EEA"],          # zero or more preset keys
        "countries_add": ["CH", "GB"],  # extra ISO-3166 alpha-2 codes to allow
        "countries_remove": ["RO"],     # codes to subtract from the presets
        "fail_open": True,              # allow when the IP cannot be located
    }

The global default and any per-user override share this shape; the mode
(off / monitor / enforce) is global and lives alongside the default.
"""

from __future__ import annotations

# ISO-3166 alpha-2 country sets behind each region preset.
_EU = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
}
_EEA = _EU | {"IS", "LI", "NO"}
_SCHENGEN = {
    "AT", "BE", "BG", "HR", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU",
    "IS", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO",
    "SK", "SI", "ES", "SE", "CH",
}
_EUROPE_WIDE = _EEA | {
    "GB", "CH", "AL", "AD", "BA", "MC", "ME", "MK", "RS", "SM", "VA", "XK",
    "UA", "MD",
}

REGIONS: dict[str, dict[str, object]] = {
    "EU_EEA": {"label": "EU / EEA", "countries": sorted(_EEA)},
    "SCHENGEN": {"label": "Schengen area", "countries": sorted(_SCHENGEN)},
    "EUROPE": {"label": "Europe (incl. UK & Switzerland)", "countries": sorted(_EUROPE_WIDE)},
    "ES": {"label": "Spain only", "countries": ["ES"]},
}

# Decisions. The *_deny variants are the ones that would block a login.
ALLOW = "allow"
DENY = "deny"
UNKNOWN_ALLOW = "unknown-allow"
UNKNOWN_DENY = "unknown-deny"
_BLOCKING = {DENY, UNKNOWN_DENY}


def expand_allowed(policy: dict | None) -> set[str]:
    """The final set of allowed ISO-3166 alpha-2 codes for a policy."""
    if not isinstance(policy, dict):
        return set()
    allowed: set[str] = set()
    for key in policy.get("regions", []) or []:
        region = REGIONS.get(str(key))
        if region:
            allowed.update(region["countries"])  # type: ignore[arg-type]
    for code in policy.get("countries_add", []) or []:
        allowed.add(str(code).strip().upper())
    for code in policy.get("countries_remove", []) or []:
        allowed.discard(str(code).strip().upper())
    allowed.discard("")
    return allowed


def decide(country: str | None, allowed: set[str], fail_open: bool) -> str:
    """Classify one connection. `country` is an ISO-3166 alpha-2 code or None
    when the client IP could not be located (or is private/LAN)."""
    if not allowed:
        # No allow-list configured means no restriction — never block. This keeps
        # an unset or empty policy a safe no-op instead of locking everyone out.
        return ALLOW
    if not country:
        return UNKNOWN_ALLOW if fail_open else UNKNOWN_DENY
    return ALLOW if country.strip().upper() in allowed else DENY


def is_block(decision: str) -> bool:
    """True when the decision would reject the login (in enforce mode)."""
    return decision in _BLOCKING
