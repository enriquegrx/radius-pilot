"""Offline, dependency-free approximate GeoIP resolution.

This module maps a client IPv4/IPv6 address to a rough geographic location
without any third-party package, network access, or CDN. It is used by the web
dashboard to plot VPN sessions on a world map.

Resolution order inside :func:`locate`:

1. Private / loopback / link-local / CGNAT / unique-local addresses are reported
   as ``source="private"`` and are never plotted.
2. An optional GeoLite2-style CSV pointed to by ``RADIUS_ADMIN_GEOIP_CSV``.
3. A small bundled table of well-known public ranges (:data:`KNOWN_NETWORKS`).
4. A country centroid, when a matched row supplies a country code but no
   coordinates.
5. Otherwise ``None`` (could not resolve).

Everything here uses only the Python standard library.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import threading

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Environment variable that may point at a GeoLite2-style CSV export.
CSV_ENV_VAR = "RADIUS_ADMIN_GEOIP_CSV"

# RFC1918 / loopback / link-local / CGNAT (RFC6598) / IPv6 unique-local ranges.
# These are matched explicitly instead of relying on ``ip_address.is_private``
# so that documentation ranges (e.g. 203.0.113.0/24) are *not* treated as
# private and simply fall through to "unresolved".
_PRIVATE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
_PRIVATE_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(cidr) for cidr in _PRIVATE_CIDRS
)


# A handful of recognizable public ranges so a demo map looks alive. Each entry
# is (cidr, latitude, longitude, country_iso, country_name, city). Longest
# prefix wins, so the /8 below is only used when no more specific row matches.
KNOWN_NETWORKS: tuple[tuple[str, float, float, str, str, str], ...] = (
    # University of Granada / RedIRIS - the range this project actually sees.
    ("150.214.0.0/16", 37.1773, -3.5986, "ES", "Spain", "Granada"),
    # Google Public DNS (anycast, commonly served from Mountain View, US).
    ("8.0.0.0/8", 37.751, -97.822, "US", "United States", ""),
    ("8.8.8.0/24", 37.386, -122.0838, "US", "United States", "Mountain View"),
    # Cloudflare 1.1.1.1 (anycast; Sydney is a fine approximation).
    ("1.1.1.0/24", -33.8688, 151.2093, "AU", "Australia", "Sydney"),
    # Telefonica, Madrid.
    ("80.58.0.0/16", 40.4168, -3.7038, "ES", "Spain", "Madrid"),
    # OVH, Paris.
    ("51.68.0.0/16", 48.8566, 2.3522, "FR", "France", "Paris"),
    # Azure UK South, London.
    ("51.140.0.0/16", 51.5074, -0.1278, "GB", "United Kingdom", "London"),
    # AWS eu-central-1, Frankfurt.
    ("3.120.0.0/16", 50.1109, 8.6821, "DE", "Germany", "Frankfurt"),
    # SURFnet, Amsterdam.
    ("145.100.0.0/16", 52.3676, 4.9041, "NL", "Netherlands", "Amsterdam"),
    # AWS us-east-1, Ashburn (US East).
    ("44.192.0.0/11", 39.0438, -77.4874, "US", "United States", "Ashburn"),
    # NIC.br, Sao Paulo (South America).
    ("200.160.0.0/16", -23.5505, -46.6333, "BR", "Brazil", "Sao Paulo"),
)


def _parse_known(
    rows: tuple[tuple[str, float, float, str, str, str], ...],
) -> tuple[tuple[IPNetwork, float | None, float | None, str, str, str], ...]:
    """Pre-parse the bundled table into ``ipaddress`` network objects."""
    parsed: list[tuple[IPNetwork, float | None, float | None, str, str, str]] = []
    for cidr, lat, lon, iso, name, city in rows:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        parsed.append((network, lat, lon, iso, name, city))
    return tuple(parsed)


# Parsed once at import so lookups never re-parse the strings.
_KNOWN_PARSED = _parse_known(KNOWN_NETWORKS)


# Approximate geographic centroids by ISO-3166 alpha-2 code:
# code -> (latitude, longitude, English country name). Coordinates are rough
# country centroids and are only used as a last-resort fallback.
COUNTRY_CENTROIDS: dict[str, tuple[float, float, str]] = {
    "AD": (42.5, 1.5, "Andorra"),
    "AE": (24.0, 54.0, "United Arab Emirates"),
    "AF": (33.0, 65.0, "Afghanistan"),
    "AG": (17.05, -61.8, "Antigua and Barbuda"),
    "AI": (18.25, -63.17, "Anguilla"),
    "AL": (41.0, 20.0, "Albania"),
    "AM": (40.0, 45.0, "Armenia"),
    "AO": (-12.5, 18.5, "Angola"),
    "AQ": (-75.25, -0.07, "Antarctica"),
    "AR": (-34.0, -64.0, "Argentina"),
    "AS": (-14.33, -170.0, "American Samoa"),
    "AT": (47.33, 13.33, "Austria"),
    "AU": (-25.0, 135.0, "Australia"),
    "AW": (12.5, -69.97, "Aruba"),
    "AX": (60.25, 20.0, "Aland Islands"),
    "AZ": (40.5, 47.5, "Azerbaijan"),
    "BA": (44.0, 18.0, "Bosnia and Herzegovina"),
    "BB": (13.17, -59.53, "Barbados"),
    "BD": (24.0, 90.0, "Bangladesh"),
    "BE": (50.83, 4.0, "Belgium"),
    "BF": (13.0, -2.0, "Burkina Faso"),
    "BG": (43.0, 25.0, "Bulgaria"),
    "BH": (26.0, 50.55, "Bahrain"),
    "BI": (-3.5, 30.0, "Burundi"),
    "BJ": (9.5, 2.25, "Benin"),
    "BL": (17.9, -62.83, "Saint Barthelemy"),
    "BM": (32.33, -64.75, "Bermuda"),
    "BN": (4.5, 114.67, "Brunei"),
    "BO": (-17.0, -65.0, "Bolivia"),
    "BQ": (12.18, -68.25, "Caribbean Netherlands"),
    "BR": (-10.0, -55.0, "Brazil"),
    "BS": (24.25, -76.0, "Bahamas"),
    "BT": (27.5, 90.5, "Bhutan"),
    "BV": (-54.43, 3.4, "Bouvet Island"),
    "BW": (-22.0, 24.0, "Botswana"),
    "BY": (53.0, 28.0, "Belarus"),
    "BZ": (17.25, -88.75, "Belize"),
    "CA": (60.0, -95.0, "Canada"),
    "CC": (-12.17, 96.83, "Cocos Islands"),
    "CD": (-2.5, 23.5, "DR Congo"),
    "CF": (7.0, 21.0, "Central African Republic"),
    "CG": (-1.0, 15.0, "Congo"),
    "CH": (47.0, 8.0, "Switzerland"),
    "CI": (8.0, -5.5, "Cote d'Ivoire"),
    "CK": (-21.23, -159.77, "Cook Islands"),
    "CL": (-30.0, -71.0, "Chile"),
    "CM": (6.0, 12.0, "Cameroon"),
    "CN": (35.0, 105.0, "China"),
    "CO": (4.0, -72.0, "Colombia"),
    "CR": (10.0, -84.0, "Costa Rica"),
    "CU": (21.5, -80.0, "Cuba"),
    "CV": (16.0, -24.0, "Cape Verde"),
    "CW": (12.17, -69.0, "Curacao"),
    "CX": (-10.5, 105.67, "Christmas Island"),
    "CY": (35.0, 33.0, "Cyprus"),
    "CZ": (49.75, 15.5, "Czechia"),
    "DE": (51.0, 9.0, "Germany"),
    "DJ": (11.5, 43.0, "Djibouti"),
    "DK": (56.0, 10.0, "Denmark"),
    "DM": (15.42, -61.33, "Dominica"),
    "DO": (19.0, -70.67, "Dominican Republic"),
    "DZ": (28.0, 3.0, "Algeria"),
    "EC": (-2.0, -77.5, "Ecuador"),
    "EE": (59.0, 26.0, "Estonia"),
    "EG": (27.0, 30.0, "Egypt"),
    "EH": (24.5, -13.0, "Western Sahara"),
    "ER": (15.0, 39.0, "Eritrea"),
    "ES": (40.0, -4.0, "Spain"),
    "ET": (8.0, 38.0, "Ethiopia"),
    "FI": (64.0, 26.0, "Finland"),
    "FJ": (-18.0, 178.0, "Fiji"),
    "FK": (-51.75, -59.0, "Falkland Islands"),
    "FM": (6.92, 158.25, "Micronesia"),
    "FO": (62.0, -7.0, "Faroe Islands"),
    "FR": (46.0, 2.0, "France"),
    "GA": (-1.0, 11.75, "Gabon"),
    "GB": (54.0, -2.0, "United Kingdom"),
    "GD": (12.12, -61.67, "Grenada"),
    "GE": (42.0, 43.5, "Georgia"),
    "GF": (4.0, -53.0, "French Guiana"),
    "GG": (49.47, -2.58, "Guernsey"),
    "GH": (8.0, -2.0, "Ghana"),
    "GI": (36.13, -5.35, "Gibraltar"),
    "GL": (72.0, -40.0, "Greenland"),
    "GM": (13.47, -16.57, "Gambia"),
    "GN": (11.0, -10.0, "Guinea"),
    "GP": (16.25, -61.58, "Guadeloupe"),
    "GQ": (2.0, 10.0, "Equatorial Guinea"),
    "GR": (39.0, 22.0, "Greece"),
    "GS": (-54.5, -37.0, "South Georgia"),
    "GT": (15.5, -90.25, "Guatemala"),
    "GU": (13.45, 144.78, "Guam"),
    "GW": (12.0, -15.0, "Guinea-Bissau"),
    "GY": (5.0, -59.0, "Guyana"),
    "HK": (22.33, 114.2, "Hong Kong"),
    "HM": (-53.1, 72.5, "Heard Island and McDonald Islands"),
    "HN": (15.0, -86.5, "Honduras"),
    "HR": (45.17, 15.5, "Croatia"),
    "HT": (19.0, -72.42, "Haiti"),
    "HU": (47.0, 20.0, "Hungary"),
    "ID": (-5.0, 120.0, "Indonesia"),
    "IE": (53.0, -8.0, "Ireland"),
    "IL": (31.5, 34.75, "Israel"),
    "IM": (54.23, -4.55, "Isle of Man"),
    "IN": (22.0, 79.0, "India"),
    "IO": (-6.0, 71.5, "British Indian Ocean Territory"),
    "IQ": (33.0, 44.0, "Iraq"),
    "IR": (32.0, 53.0, "Iran"),
    "IS": (65.0, -18.0, "Iceland"),
    "IT": (42.83, 12.83, "Italy"),
    "JE": (49.21, -2.13, "Jersey"),
    "JM": (18.25, -77.5, "Jamaica"),
    "JO": (31.0, 36.0, "Jordan"),
    "JP": (36.0, 138.0, "Japan"),
    "KE": (1.0, 38.0, "Kenya"),
    "KG": (41.0, 75.0, "Kyrgyzstan"),
    "KH": (13.0, 105.0, "Cambodia"),
    "KI": (1.42, 173.0, "Kiribati"),
    "KM": (-12.17, 44.25, "Comoros"),
    "KN": (17.33, -62.75, "Saint Kitts and Nevis"),
    "KP": (40.0, 127.0, "North Korea"),
    "KR": (37.0, 127.5, "South Korea"),
    "KW": (29.34, 47.66, "Kuwait"),
    "KY": (19.5, -80.5, "Cayman Islands"),
    "KZ": (48.0, 68.0, "Kazakhstan"),
    "LA": (18.0, 105.0, "Laos"),
    "LB": (33.83, 35.83, "Lebanon"),
    "LC": (13.88, -61.13, "Saint Lucia"),
    "LI": (47.17, 9.53, "Liechtenstein"),
    "LK": (7.0, 81.0, "Sri Lanka"),
    "LR": (6.5, -9.5, "Liberia"),
    "LS": (-29.5, 28.5, "Lesotho"),
    "LT": (56.0, 24.0, "Lithuania"),
    "LU": (49.75, 6.17, "Luxembourg"),
    "LV": (57.0, 25.0, "Latvia"),
    "LY": (25.0, 17.0, "Libya"),
    "MA": (32.0, -5.0, "Morocco"),
    "MC": (43.73, 7.4, "Monaco"),
    "MD": (47.0, 29.0, "Moldova"),
    "ME": (42.5, 19.3, "Montenegro"),
    "MF": (18.08, -63.05, "Saint Martin"),
    "MG": (-20.0, 47.0, "Madagascar"),
    "MH": (7.12, 171.06, "Marshall Islands"),
    "MK": (41.83, 22.0, "North Macedonia"),
    "ML": (17.0, -4.0, "Mali"),
    "MM": (22.0, 98.0, "Myanmar"),
    "MN": (46.0, 105.0, "Mongolia"),
    "MO": (22.17, 113.55, "Macau"),
    "MP": (15.2, 145.75, "Northern Mariana Islands"),
    "MQ": (14.67, -61.0, "Martinique"),
    "MR": (20.0, -12.0, "Mauritania"),
    "MS": (16.75, -62.2, "Montserrat"),
    "MT": (35.92, 14.43, "Malta"),
    "MU": (-20.28, 57.55, "Mauritius"),
    "MV": (3.25, 73.0, "Maldives"),
    "MW": (-13.5, 34.0, "Malawi"),
    "MX": (23.0, -102.0, "Mexico"),
    "MY": (2.5, 112.5, "Malaysia"),
    "MZ": (-18.25, 35.0, "Mozambique"),
    "NA": (-22.0, 17.0, "Namibia"),
    "NC": (-21.5, 165.5, "New Caledonia"),
    "NE": (16.0, 8.0, "Niger"),
    "NF": (-29.03, 167.95, "Norfolk Island"),
    "NG": (10.0, 8.0, "Nigeria"),
    "NI": (13.0, -85.0, "Nicaragua"),
    "NL": (52.5, 5.75, "Netherlands"),
    "NO": (62.0, 10.0, "Norway"),
    "NP": (28.0, 84.0, "Nepal"),
    "NR": (-0.53, 166.92, "Nauru"),
    "NU": (-19.03, -169.87, "Niue"),
    "NZ": (-41.0, 174.0, "New Zealand"),
    "OM": (21.0, 57.0, "Oman"),
    "PA": (9.0, -80.0, "Panama"),
    "PE": (-10.0, -76.0, "Peru"),
    "PF": (-15.0, -140.0, "French Polynesia"),
    "PG": (-6.0, 147.0, "Papua New Guinea"),
    "PH": (13.0, 122.0, "Philippines"),
    "PK": (30.0, 70.0, "Pakistan"),
    "PL": (52.0, 20.0, "Poland"),
    "PM": (46.83, -56.33, "Saint Pierre and Miquelon"),
    "PN": (-24.7, -127.4, "Pitcairn Islands"),
    "PR": (18.25, -66.5, "Puerto Rico"),
    "PS": (31.9, 35.2, "Palestine"),
    "PT": (39.5, -8.0, "Portugal"),
    "PW": (7.5, 134.5, "Palau"),
    "PY": (-23.0, -58.0, "Paraguay"),
    "QA": (25.5, 51.25, "Qatar"),
    "RE": (-21.1, 55.6, "Reunion"),
    "RO": (46.0, 25.0, "Romania"),
    "RS": (44.0, 21.0, "Serbia"),
    "RU": (60.0, 100.0, "Russia"),
    "RW": (-2.0, 30.0, "Rwanda"),
    "SA": (25.0, 45.0, "Saudi Arabia"),
    "SB": (-8.0, 159.0, "Solomon Islands"),
    "SC": (-4.58, 55.67, "Seychelles"),
    "SD": (15.0, 30.0, "Sudan"),
    "SE": (62.0, 15.0, "Sweden"),
    "SG": (1.37, 103.8, "Singapore"),
    "SH": (-15.95, -5.7, "Saint Helena"),
    "SI": (46.0, 15.0, "Slovenia"),
    "SJ": (78.0, 20.0, "Svalbard and Jan Mayen"),
    "SK": (48.67, 19.5, "Slovakia"),
    "SL": (8.5, -11.5, "Sierra Leone"),
    "SM": (43.94, 12.46, "San Marino"),
    "SN": (14.0, -14.0, "Senegal"),
    "SO": (6.0, 47.0, "Somalia"),
    "SR": (4.0, -56.0, "Suriname"),
    "SS": (7.0, 30.0, "South Sudan"),
    "ST": (1.0, 7.0, "Sao Tome and Principe"),
    "SV": (13.83, -88.92, "El Salvador"),
    "SX": (18.03, -63.05, "Sint Maarten"),
    "SY": (35.0, 38.0, "Syria"),
    "SZ": (-26.5, 31.5, "Eswatini"),
    "TC": (21.75, -71.58, "Turks and Caicos Islands"),
    "TD": (15.0, 19.0, "Chad"),
    "TF": (-49.25, 69.17, "French Southern Territories"),
    "TG": (8.0, 1.17, "Togo"),
    "TH": (15.0, 100.0, "Thailand"),
    "TJ": (39.0, 71.0, "Tajikistan"),
    "TK": (-9.2, -171.85, "Tokelau"),
    "TL": (-8.83, 125.75, "Timor-Leste"),
    "TM": (40.0, 60.0, "Turkmenistan"),
    "TN": (34.0, 9.0, "Tunisia"),
    "TO": (-20.0, -175.0, "Tonga"),
    "TR": (39.0, 35.0, "Turkey"),
    "TT": (11.0, -61.0, "Trinidad and Tobago"),
    "TV": (-8.0, 178.0, "Tuvalu"),
    "TW": (23.5, 121.0, "Taiwan"),
    "TZ": (-6.0, 35.0, "Tanzania"),
    "UA": (49.0, 32.0, "Ukraine"),
    "UG": (1.0, 32.0, "Uganda"),
    "UM": (19.3, 166.6, "U.S. Minor Outlying Islands"),
    "US": (38.0, -97.0, "United States"),
    "UY": (-33.0, -56.0, "Uruguay"),
    "UZ": (41.0, 64.0, "Uzbekistan"),
    "VA": (41.9, 12.45, "Vatican City"),
    "VC": (13.25, -61.2, "Saint Vincent and the Grenadines"),
    "VE": (8.0, -66.0, "Venezuela"),
    "VG": (18.42, -64.62, "British Virgin Islands"),
    "VI": (18.34, -64.93, "U.S. Virgin Islands"),
    "VN": (16.0, 106.0, "Vietnam"),
    "VU": (-16.0, 167.0, "Vanuatu"),
    "WF": (-13.3, -176.2, "Wallis and Futuna"),
    "WS": (-13.75, -172.1, "Samoa"),
    "XK": (42.6, 20.9, "Kosovo"),
    "YE": (15.0, 48.0, "Yemen"),
    "YT": (-12.83, 45.17, "Mayotte"),
    "ZA": (-29.0, 24.0, "South Africa"),
    "ZM": (-15.0, 30.0, "Zambia"),
    "ZW": (-19.0, 29.0, "Zimbabwe"),
}


# Cache of parsed CSV tables keyed by absolute path. Each value is
# (mtime, table) so a file edited in place is transparently re-read.
_CSV_CACHE: dict[str, tuple[float, tuple[_CsvEntry, ...]]] = {}
_CSV_CACHE_LOCK = threading.Lock()

# A parsed CSV/known row: (network, latitude, longitude, iso, name, city).
_CsvEntry = tuple[IPNetwork, "float | None", "float | None", str, str, str]


def country_centroid(iso2: str) -> tuple[float, float, str] | None:
    """Return ``(latitude, longitude, country_name)`` for an ISO-2 code.

    The lookup is case-insensitive and whitespace tolerant. Returns ``None``
    for an unknown or empty code.
    """
    if not isinstance(iso2, str):
        return None
    code = iso2.strip().upper()
    if not code:
        return None
    return COUNTRY_CENTROIDS.get(code)


def _is_private(addr: IPAddress) -> bool:
    """True for RFC1918, loopback, link-local, CGNAT or unique-local addresses."""
    return any(addr in network for network in _PRIVATE_NETWORKS)


def _to_coordinate(value: str | None, limit: float) -> float | None:
    """Parse a latitude/longitude string, rejecting out-of-range values."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        number = float(text)
    except (TypeError, ValueError):
        return None
    if number != number or abs(number) > limit:  # NaN or out of range
        return None
    return number


def _best_match(addr: IPAddress, entries: tuple[_CsvEntry, ...]) -> _CsvEntry | None:
    """Return the entry whose network contains ``addr`` with the longest prefix."""
    best: _CsvEntry | None = None
    best_prefix = -1
    for entry in entries:
        network = entry[0]
        if network.version != addr.version:
            continue
        if addr in network and network.prefixlen > best_prefix:
            best = entry
            best_prefix = network.prefixlen
    return best


def _make_result(
    lat: float, lon: float, iso: str, name: str, city: str, source: str
) -> dict:
    """Build a resolved location dict, filling a missing name from the centroid."""
    iso = (iso or "").strip().upper()
    name = (name or "").strip()
    if iso and not name:
        centroid = country_centroid(iso)
        if centroid is not None:
            name = centroid[2]
    return {
        "lat": float(lat),
        "lon": float(lon),
        "country": iso,
        "country_name": name,
        "city": (city or "").strip(),
        "source": source,
        "private": False,
    }


def _resolve_entry(entry: _CsvEntry, coordinate_source: str) -> dict | None:
    """Turn a matched row into a location dict.

    When the row supplies coordinates they are used directly with
    ``coordinate_source``. When it only supplies a country code, the country
    centroid is used and the source becomes ``"country"``. A row with neither
    yields ``None`` so the caller can keep searching.
    """
    _network, lat, lon, iso, name, city = entry
    if lat is not None and lon is not None:
        return _make_result(lat, lon, iso, name, city, coordinate_source)
    iso = (iso or "").strip().upper()
    if iso:
        centroid = country_centroid(iso)
        if centroid is not None:
            clat, clon, cname = centroid
            return _make_result(clat, clon, iso, name or cname, "", "country")
    return None


def _row_to_entry(row: dict[str, object]) -> _CsvEntry | None:
    """Convert a raw CSV row into a parsed entry, or ``None`` if unusable."""
    data: dict[str, str] = {}
    for key, value in row.items():
        if key is None:
            continue
        text = value if isinstance(value, str) else ""
        data[key.strip().lower()] = text.strip()

    cidr = data.get("network", "")
    if not cidr:
        return None
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    lat = _to_coordinate(data.get("latitude"), 90.0)
    lon = _to_coordinate(data.get("longitude"), 180.0)
    iso = data.get("country_iso", "").upper()[:2]
    name = data.get("country_name", "")
    city = data.get("city", "")
    return (network, lat, lon, iso, name, city)


def _parse_csv(path: str) -> tuple[_CsvEntry, ...]:
    """Parse a GeoLite2-style CSV, skipping malformed rows."""
    entries: list[_CsvEntry] = []
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return ()
            for row in reader:
                entry = _row_to_entry(row)
                if entry is not None:
                    entries.append(entry)
    except (OSError, csv.Error, UnicodeDecodeError):
        return ()
    return tuple(entries)


def _load_csv_table() -> tuple[_CsvEntry, ...] | None:
    """Return the parsed CSV table for :data:`CSV_ENV_VAR`, cached by path+mtime."""
    path = os.environ.get(CSV_ENV_VAR)
    if not path:
        return None
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None

    with _CSV_CACHE_LOCK:
        cached = _CSV_CACHE.get(path)
        if cached is not None and cached[0] == mtime:
            return cached[1]

    table = _parse_csv(path)

    with _CSV_CACHE_LOCK:
        _CSV_CACHE[path] = (mtime, table)
    return table


def _private_result() -> dict:
    """The location dict returned for any private/loopback/CGNAT address."""
    return {
        "lat": 0.0,
        "lon": 0.0,
        "country": "",
        "country_name": "",
        "city": "Private network",
        "source": "private",
        "private": True,
    }


def locate(ip: str) -> dict | None:
    """Resolve ``ip`` (IPv4 or IPv6) to an approximate location.

    Returns a dict with ``lat``, ``lon``, ``country`` (ISO-2), ``country_name``,
    ``city``, ``source`` (one of ``"geolite"``, ``"known"``, ``"country"`` or
    ``"private"``) and ``private``. Returns ``None`` when the address is invalid
    or cannot be resolved. Never raises on bad input.
    """
    if not isinstance(ip, str):
        return None
    text = ip.strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None

    if _is_private(addr):
        return _private_result()

    table = _load_csv_table()
    if table:
        match = _best_match(addr, table)
        if match is not None:
            result = _resolve_entry(match, "geolite")
            if result is not None:
                return result

    match = _best_match(addr, _KNOWN_PARSED)
    if match is not None:
        result = _resolve_entry(match, "known")
        if result is not None:
            return result

    return None
