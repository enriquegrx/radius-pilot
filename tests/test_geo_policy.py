from __future__ import annotations

from radius_user_admin import geo_policy as gp


def test_region_presets_have_spain_and_exclude_us() -> None:
    eu = set(gp.REGIONS["EU_EEA"]["countries"])
    assert "ES" in eu
    assert "US" not in eu
    assert {"IS", "LI", "NO"} <= eu  # EEA extends the EU


def test_expand_allowed_combines_regions_and_edits() -> None:
    allowed = gp.expand_allowed(
        {"regions": ["EU_EEA"], "countries_add": ["ch", "gb"], "countries_remove": ["RO"]}
    )
    assert "CH" in allowed and "GB" in allowed  # added, upper-cased
    assert "RO" not in allowed  # removed
    assert "ES" in allowed  # from the preset
    assert "US" not in allowed


def test_expand_allowed_handles_empty_and_bad_input() -> None:
    assert gp.expand_allowed(None) == set()
    assert gp.expand_allowed({}) == set()
    assert gp.expand_allowed({"regions": ["NOPE"], "countries_add": [""]}) == set()


def test_decide_allow_deny_and_unknown() -> None:
    allowed = gp.expand_allowed({"regions": ["EU_EEA"]})
    assert gp.decide("ES", allowed, fail_open=True) == gp.ALLOW
    assert gp.decide("es", allowed, fail_open=True) == gp.ALLOW  # case-insensitive
    assert gp.decide("US", allowed, fail_open=True) == gp.DENY
    # unresolved IP follows the fail mode
    assert gp.decide(None, allowed, fail_open=True) == gp.UNKNOWN_ALLOW
    assert gp.decide(None, allowed, fail_open=False) == gp.UNKNOWN_DENY


def test_empty_allowlist_is_a_safe_no_op() -> None:
    # No configured countries means no restriction — never block anyone.
    assert gp.decide("US", set(), fail_open=True) == gp.ALLOW
    assert gp.decide("US", set(), fail_open=False) == gp.ALLOW
    assert gp.decide(None, set(), fail_open=False) == gp.ALLOW


def test_is_block_only_for_deny_decisions() -> None:
    assert gp.is_block(gp.DENY)
    assert gp.is_block(gp.UNKNOWN_DENY)
    assert not gp.is_block(gp.ALLOW)
    assert not gp.is_block(gp.UNKNOWN_ALLOW)


def test_spain_only_preset_blocks_the_rest_of_europe() -> None:
    allowed = gp.expand_allowed({"regions": ["ES"]})
    assert gp.decide("ES", allowed, fail_open=True) == gp.ALLOW
    assert gp.decide("FR", allowed, fail_open=True) == gp.DENY
