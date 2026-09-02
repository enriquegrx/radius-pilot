from __future__ import annotations

from pathlib import Path

import pytest

from radius_user_admin import geoip
from radius_user_admin.geoip import CSV_ENV_VAR, country_centroid, locate


@pytest.fixture(autouse=True)
def _clear_csv_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient GeoLite2 CSV leaks in from the environment."""
    monkeypatch.delenv(CSV_ENV_VAR, raising=False)
    geoip._CSV_CACHE.clear()


@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.10.10",
        "100.64.0.1",  # CGNAT / RFC6598
        "::1",  # IPv6 loopback
        "fc00::1234",  # IPv6 unique-local
        "fd12:3456::1",
        "fe80::1",  # IPv6 link-local
    ],
)
def test_private_and_loopback_addresses(ip: str) -> None:
    result = locate(ip)
    assert result is not None
    assert result["private"] is True
    assert result["source"] == "private"
    assert result["city"] == "Private network"
    assert result["country"] == ""
    assert result["lat"] == 0.0
    assert result["lon"] == 0.0


def test_known_ugr_granada_match() -> None:
    result = locate("150.214.205.52")
    assert result is not None
    assert result["source"] == "known"
    assert result["private"] is False
    assert result["country"] == "ES"
    assert result["country_name"] == "Spain"
    assert result["city"] == "Granada"
    assert result["lat"] == pytest.approx(37.1773)
    assert result["lon"] == pytest.approx(-3.5986)


def test_longest_prefix_precedence_in_known_table() -> None:
    # 8.8.8.0/24 is more specific than 8.0.0.0/8 and must win.
    specific = locate("8.8.8.8")
    assert specific is not None
    assert specific["city"] == "Mountain View"

    # An address inside 8.0.0.0/8 but outside 8.8.8.0/24 falls back to the /8.
    broad = locate("8.9.9.9")
    assert broad is not None
    assert broad["country"] == "US"
    assert broad["city"] == ""


def test_geolite_csv_override_and_most_specific_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv_path = tmp_path / "geo.csv"
    csv_path.write_text(
        "network,latitude,longitude,country_iso,country_name,city\n"
        "150.214.0.0/16,37.1000,-3.6000,ES,Spain,GranadaWide\n"
        "150.214.205.0/24,37.1773,-3.5986,ES,Spain,GranadaCampus\n"
        # A deliberately malformed row that must be skipped.
        "not-a-network,0,0,ES,Spain,Bad\n"
        # A row with only a country code (no coordinates) -> country fallback.
        "203.0.113.0/24,,,FR,,\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(CSV_ENV_VAR, str(csv_path))

    # Most-specific CSV network wins over the broader one.
    campus = locate("150.214.205.52")
    assert campus is not None
    assert campus["source"] == "geolite"
    assert campus["city"] == "GranadaCampus"

    # Inside the /16 but outside the /24 -> the wider CSV row.
    wide = locate("150.214.10.10")
    assert wide is not None
    assert wide["source"] == "geolite"
    assert wide["city"] == "GranadaWide"

    # A CSV row with a country but no coordinates falls back to the centroid.
    country_only = locate("203.0.113.7")
    assert country_only is not None
    assert country_only["source"] == "country"
    assert country_only["country"] == "FR"
    assert country_only["country_name"] == "France"
    fr = country_centroid("FR")
    assert fr is not None
    assert country_only["lat"] == pytest.approx(fr[0])
    assert country_only["lon"] == pytest.approx(fr[1])


def test_geolite_csv_table_is_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv_path = tmp_path / "geo.csv"
    csv_path.write_text(
        "network,latitude,longitude,country_iso,country_name,city\n"
        "45.0.0.0/8,10.0,20.0,XX,Example,Somewhere\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(CSV_ENV_VAR, str(csv_path))

    calls = {"n": 0}
    original = geoip._parse_csv

    def counting(path: str):
        calls["n"] += 1
        return original(path)

    monkeypatch.setattr(geoip, "_parse_csv", counting)
    geoip._CSV_CACHE.clear()

    first = locate("45.1.2.3")
    second = locate("45.4.5.6")
    assert first is not None and second is not None
    assert first["city"] == "Somewhere"
    # The file was parsed exactly once despite two lookups.
    assert calls["n"] == 1


def test_country_centroid_lookup() -> None:
    result = country_centroid("ES")
    assert result is not None
    lat, lon, name = result
    assert (lat, lon) == (40.0, -4.0)
    assert name == "Spain"

    # Case-insensitive and whitespace tolerant.
    assert country_centroid("es") == result
    assert country_centroid(" ES ") == result

    # Unknown / empty codes return None.
    assert country_centroid("ZZ") is None
    assert country_centroid("") is None


def test_unresolved_public_ip_returns_none() -> None:
    # 203.0.113.7 is documentation space: not private, not in the known table,
    # and no CSV is configured -> unresolved.
    assert locate("203.0.113.7") is None


@pytest.mark.parametrize("bad", ["", "   ", "not-an-ip", "999.999.999.999", "1.2.3"])
def test_bad_input_returns_none_without_raising(bad: str) -> None:
    assert locate(bad) is None


def test_non_string_input_returns_none() -> None:
    assert locate(None) is None  # type: ignore[arg-type]
    assert locate(12345) is None  # type: ignore[arg-type]


def test_country_of_uses_known_networks_and_guards() -> None:
    assert geoip.country_of("150.214.205.52") == "ES"  # UGR / Granada
    assert geoip.country_of("8.8.8.8") == "US"  # Google DNS, known net
    assert geoip.country_of("10.0.0.5") is None  # private
    assert geoip.country_of("::1") is None  # loopback
    assert geoip.country_of("203.0.113.7") is None  # documentation range, unresolved
    assert geoip.country_of("") is None
    assert geoip.country_of("not-an-ip") is None
