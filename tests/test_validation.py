"""Unit tests for option validation, date parsing, and CVE ID detection."""

import pytest
from datetime import date
from searchcve.exceptions import ValidationError
from searchcve.search import is_cve_id, parse_date, validate_search_options


def test_is_cve_id():
    # Valid CVE IDs
    assert is_cve_id("CVE-2026-12345") is True
    assert is_cve_id("cve-2021-44228") is True
    assert is_cve_id("CVE-1999-0001") is True
    assert is_cve_id("CVE-2024-1234567") is True
    assert is_cve_id("  CVE-2024-99999  ") is True

    # Invalid CVE IDs
    assert is_cve_id("openclaw") is False
    assert is_cve_id("apache") is False
    assert is_cve_id("CVE-2024") is False
    assert is_cve_id("CVE-24-1234") is False
    assert is_cve_id("CVE-2024-123") is False  # Minimum 4 digits for suffix
    assert is_cve_id("") is False


def test_parse_date():
    assert parse_date("2025-01-01", "--from") == date(2025, 1, 1)
    assert parse_date("2026-09-28", "--to") == date(2026, 9, 28)

    with pytest.raises(ValidationError, match="Invalid --from date"):
        parse_date("2025-13-01", "--from")

    with pytest.raises(ValidationError, match="Invalid --to date"):
        parse_date("2025/01/01", "--to")

    with pytest.raises(ValidationError, match="Invalid --from date"):
        parse_date("not-a-date", "--from")

    with pytest.raises(ValidationError, match="Invalid --to date"):
        parse_date("2025-02-30", "--to")


def test_empty_query():
    with pytest.raises(ValidationError, match="Search query cannot be empty"):
        validate_search_options(query="   ")


def test_last_and_limit_conflict():
    with pytest.raises(ValidationError, match="Cannot use both --last and --limit together"):
        validate_search_options(query="openclaw", last=10, limit=20)


def test_invalid_last_and_limit_numbers():
    with pytest.raises(ValidationError, match="--last must be a positive integer"):
        validate_search_options(query="openclaw", last=0)

    with pytest.raises(ValidationError, match="--last must be a positive integer"):
        validate_search_options(query="openclaw", last=-5)

    with pytest.raises(ValidationError, match="--limit must be a positive integer"):
        validate_search_options(query="openclaw", limit=0)

    with pytest.raises(ValidationError, match="--limit must be a positive integer"):
        validate_search_options(query="openclaw", limit=-10)


def test_year_validation():
    opts = validate_search_options(query="apache", year=2026)
    assert opts.year == 2026

    with pytest.raises(ValidationError, match="Invalid year"):
        validate_search_options(query="apache", year=1980)

    with pytest.raises(ValidationError, match="Invalid year"):
        validate_search_options(query="apache", year=2150)


def test_date_range_validation():
    opts = validate_search_options(
        query="wordpress",
        from_date_str="2025-01-01",
        to_date_str="2026-09-28",
    )
    assert opts.from_date == date(2025, 1, 1)
    assert opts.to_date == date(2026, 9, 28)

    with pytest.raises(ValidationError, match="cannot be after --to date"):
        validate_search_options(
            query="wordpress",
            from_date_str="2026-01-01",
            to_date_str="2025-01-01",
        )


def test_year_date_conflict():
    with pytest.raises(ValidationError, match="conflicts with --from"):
        validate_search_options(
            query="test",
            year=2024,
            from_date_str="2025-01-01",
        )

    with pytest.raises(ValidationError, match="conflicts with --to"):
        validate_search_options(
            query="test",
            year=2026,
            to_date_str="2025-12-31",
        )


def test_sort_validation():
    opts = validate_search_options("bluetooth", sort="id")
    assert opts.sort == "id"

    opts2 = validate_search_options("bluetooth", sort="cvss")
    assert opts2.sort == "cvss"

    opts3 = validate_search_options("bluetooth", sort="date")
    assert opts3.sort == "date"

    with pytest.raises(ValidationError, match="Invalid sort option"):
        validate_search_options("bluetooth", sort="invalid_sort")

