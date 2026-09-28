"""Unit tests for keyword matching, filtering, and search engine logic."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from searchcve.models import CVEItem, SearchOptions
from searchcve.search import (
    CVESearchEngine,
    matches_filters,
    matches_keyword,
    validate_search_options,
)


def make_cve(cve_id: str, desc: str, published_str: str = "2025-05-10T12:00:00") -> CVEItem:
    pub = datetime.fromisoformat(published_str).replace(tzinfo=timezone.utc)
    return CVEItem(
        id=cve_id,
        description=desc,
        published=pub,
    )


def test_keyword_case_insensitivity():
    cve1 = make_cve("CVE-2026-0001", "OpenClaw is affected by a buffer overflow.")
    cve2 = make_cve("CVE-2026-0002", "Vulnerability in OPENCLAW component.")
    cve3 = make_cve("CVE-2026-0003", "A flaw in openclaw allows remote code execution.")
    cve4 = make_cve("CVE-2026-0004", "Apache Tomcat contains an issue.")

    assert matches_keyword(cve1, "openclaw") is True
    assert matches_keyword(cve2, "openclaw") is True
    assert matches_keyword(cve3, "OPENCLAW") is True
    assert matches_keyword(cve4, "openclaw") is False


def test_exact_keyword_matching():
    cve_exact = make_cve("CVE-2026-0001", "A bug in openclaw allows privilege escalation.")
    cve_word_boundary = make_cve("CVE-2026-0002", "OpenClaw: improper input validation.")
    cve_fuzzy = make_cve("CVE-2026-0003", "A bug in openclaws-extra allows DoS.")
    cve_prefix = make_cve("CVE-2026-0004", "Prefix myopenclaw vulnerability.")

    # With exact=False (default substring match)
    assert matches_keyword(cve_exact, "openclaw", exact=False) is True
    assert matches_keyword(cve_word_boundary, "openclaw", exact=False) is True
    assert matches_keyword(cve_fuzzy, "openclaw", exact=False) is True
    assert matches_keyword(cve_prefix, "openclaw", exact=False) is True

    # With exact=True (word boundary)
    assert matches_keyword(cve_exact, "openclaw", exact=True) is True
    assert matches_keyword(cve_word_boundary, "openclaw", exact=True) is True
    assert matches_keyword(cve_fuzzy, "openclaw", exact=True) is False
    assert matches_keyword(cve_prefix, "openclaw", exact=True) is False


def test_multi_term_and_version_matching():
    cve = make_cve(
        "CVE-2015-2686",
        "net/socket.c in the Linux kernel 3.19 before 3.19.3 does not validate certain range data, "
        "as demonstrated by the Bluetooth subsystem"
    )
    assert matches_keyword(cve, "bluetooth 3.1") is True
    assert matches_keyword(cve, "bluetooth 4.0") is False
    assert matches_keyword(cve, "bluetooth 3.1", exact=True) is False  # 3.19 is not whole word 3.1

    cve_exact_version = make_cve(
        "CVE-2020-0001",
        "A vulnerability in the Bluetooth Core Specification 3.1 allows DoS"
    )
    assert matches_keyword(cve_exact_version, "bluetooth 3.1", exact=True) is True


def test_year_filtering():
    cve_2025 = make_cve("CVE-2025-0001", "OpenClaw issue", "2025-06-01T10:00:00")
    cve_2026 = make_cve("CVE-2026-0001", "OpenClaw issue", "2026-02-15T10:00:00")

    opts_2025 = validate_search_options("openclaw", year=2025)
    opts_2026 = validate_search_options("openclaw", year=2026)

    assert matches_filters(cve_2025, opts_2025) is True
    assert matches_filters(cve_2026, opts_2025) is False
    assert matches_filters(cve_2025, opts_2026) is False
    assert matches_filters(cve_2026, opts_2026) is True


def test_date_range_filtering():
    cve_early = make_cve("CVE-2025-0001", "OpenClaw flaw", "2025-01-15T10:00:00")
    cve_mid = make_cve("CVE-2025-0002", "OpenClaw flaw", "2025-06-20T10:00:00")
    cve_late = make_cve("CVE-2026-0003", "OpenClaw flaw", "2026-05-01T10:00:00")

    opts = validate_search_options(
        "openclaw",
        from_date_str="2025-02-01",
        to_date_str="2025-12-31",
    )

    assert matches_filters(cve_early, opts) is False
    assert matches_filters(cve_mid, opts) is True
    assert matches_filters(cve_late, opts) is False


def test_search_engine_last_n_sorting():
    mock_client = MagicMock()
    # 3 mock CVEs with different publication dates
    cve_old = make_cve("CVE-2024-0001", "OpenClaw bug 1", "2024-01-01T00:00:00")
    cve_new = make_cve("CVE-2026-0002", "OpenClaw bug 2", "2026-03-01T00:00:00")
    cve_mid = make_cve("CVE-2025-0003", "OpenClaw bug 3", "2025-06-01T00:00:00")

    mock_client.fetch_page.return_value = (3, [cve_old, cve_new, cve_mid])

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("openclaw", last=2)

    results = engine.execute_search(opts)
    assert len(results) == 2
    # Newest first
    assert results[0].id == "CVE-2026-0002"
    assert results[1].id == "CVE-2025-0003"


def test_search_engine_last_n_tail_fetching():
    mock_client = MagicMock()
    cve_old = make_cve("CVE-2004-0001", "Bluetooth bug", "2004-01-01T00:00:00")
    cve_new1 = make_cve("CVE-2026-0001", "Bluetooth bug new 1", "2026-09-20T00:00:00")
    cve_new2 = make_cve("CVE-2026-0002", "Bluetooth bug new 2", "2026-09-25T00:00:00")

    # Call 1 (start_index=0): total_results=1000, returns old item
    # Call 2 (tail start_index=970): returns the newest items from the end
    mock_client.fetch_page.side_effect = [
        (1000, [cve_old]),
        (1000, [cve_new1, cve_new2]),
    ]

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("bluetooth", last=2)

    results = engine.execute_search(opts)
    assert len(results) == 2
    assert results[0].id == "CVE-2026-0002"
    assert results[1].id == "CVE-2026-0001"
    assert mock_client.fetch_page.call_count == 2


def test_search_engine_limit_stops_early():
    mock_client = MagicMock()
    items_page1 = [make_cve(f"CVE-2025-{i:04d}", f"OpenClaw flaw {i}") for i in range(1, 11)]
    mock_client.fetch_page.return_value = (100, items_page1)

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("openclaw", limit=5)

    results = engine.execute_search(opts)
    assert len(results) == 5
    assert results[0].id == "CVE-2025-0001"
    assert results[4].id == "CVE-2025-0005"
    # Should only call fetch_page once because limit was satisfied
    assert mock_client.fetch_page.call_count == 1


def test_search_engine_cve_id_lookup():
    mock_client = MagicMock()
    target_cve = make_cve("CVE-2026-12345", "Specific lookup target")
    mock_client.get_cve_by_id.return_value = target_cve

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("CVE-2026-12345")

    results = engine.execute_search(opts)
    assert len(results) == 1
    assert results[0].id == "CVE-2026-12345"
    mock_client.get_cve_by_id.assert_called_once_with("CVE-2026-12345")
    mock_client.fetch_page.assert_not_called()


def test_search_engine_empty_results():
    mock_client = MagicMock()
    mock_client.fetch_page.return_value = (0, [])

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("nonexistentpackage123")

    results = engine.execute_search(opts)
    assert results == []


def test_extract_fallback_query():
    from searchcve.search import extract_fallback_query

    assert extract_fallback_query("android 14 bluetooth") == "android bluetooth"
    assert extract_fallback_query("bluetooth 3.1") == "bluetooth"
    assert extract_fallback_query("apache 2.4.49 mod_proxy") == "apache mod_proxy"
    assert extract_fallback_query("singleterm") is None


def test_search_engine_year_backward_scan():
    mock_client = MagicMock()
    cve_old = make_cve("CVE-2004-0001", "Bluetooth bug", "2004-01-01T00:00:00")
    cve_2025 = make_cve("CVE-2025-0001", "Bluetooth bug 2025", "2025-10-01T00:00:00")
    cve_2026_a = make_cve("CVE-2026-0001", "Bluetooth bug 2026 a", "2026-02-01T00:00:00")
    cve_2026_b = make_cve("CVE-2026-0002", "Bluetooth bug 2026 b", "2026-09-01T00:00:00")

    # Call 1: probe at start_index=0 returns total_results=1000 and 2004 item
    # Call 2: tail returns items spanning 2025-2026
    mock_client.fetch_page.side_effect = [
        (1000, [cve_old]),
        (1000, [cve_2025, cve_2026_a, cve_2026_b]),
    ]

    engine = CVESearchEngine(client=mock_client)
    opts = validate_search_options("bluetooth", year=2026)

    results = engine.execute_search(opts)
    assert len(results) == 2
    # Only 2026 items returned, sorted newest first
    assert results[0].id == "CVE-2026-0002"
    assert results[1].id == "CVE-2026-0001"
    # Should stop after call 2 because earliest item in call 2 was 2025 (< 2026)
    assert mock_client.fetch_page.call_count == 2


def test_search_engine_last_n_combined_with_year():
    mock_client = MagicMock()
    cve_2004 = make_cve("CVE-2004-0001", "Bluetooth bug 2004", "2004-01-01T00:00:00")
    cve_2025_a = make_cve("CVE-2025-0001", "Bluetooth bug 2025 a", "2025-03-01T00:00:00")
    cve_2025_b = make_cve("CVE-2025-0002", "Bluetooth bug 2025 b", "2025-11-01T00:00:00")
    cve_2025_c = make_cve("CVE-2025-0003", "Bluetooth bug 2025 c", "2025-12-01T00:00:00")
    cve_2026 = make_cve("CVE-2026-0001", "Bluetooth bug 2026", "2026-05-01T00:00:00")

    # Tail page contains mix of 2025 and 2026
    mock_client.fetch_page.side_effect = [
        (1000, [cve_2004]),
        (1000, [cve_2025_a, cve_2025_b, cve_2025_c, cve_2026]),
    ]

    engine = CVESearchEngine(client=mock_client)
    # Search for newest 2 items published in 2025
    opts = validate_search_options("bluetooth", last=2, year=2025)

    results = engine.execute_search(opts)
    assert len(results) == 2
    # Only 2025 items, newest first
    assert results[0].id == "CVE-2025-0003"
    assert results[1].id == "CVE-2025-0002"


def test_search_engine_last_n_combined_with_date_range():
    mock_client = MagicMock()
    cve_2004 = make_cve("CVE-2004-0001", "Bluetooth bug 2004", "2004-01-01T00:00:00")
    cve_apr = make_cve("CVE-2025-0001", "Bluetooth bug", "2025-04-15T00:00:00")
    cve_may = make_cve("CVE-2025-0002", "Bluetooth bug", "2025-05-20T00:00:00")
    cve_jun = make_cve("CVE-2025-0003", "Bluetooth bug", "2025-06-10T00:00:00")
    cve_aug = make_cve("CVE-2025-0004", "Bluetooth bug", "2025-08-01T00:00:00")

    mock_client.fetch_page.side_effect = [
        (1000, [cve_2004]),
        (1000, [cve_apr, cve_may, cve_jun, cve_aug]),
    ]

    engine = CVESearchEngine(client=mock_client)
    # Search for newest 2 items in date range 2025-04-01 to 2025-06-30
    opts = validate_search_options(
        "bluetooth",
        last=2,
        from_date_str="2025-04-01",
        to_date_str="2025-06-30",
    )

    results = engine.execute_search(opts)
    assert len(results) == 2
    # Only items within the date range, newest first (jun, then may)
    assert results[0].id == "CVE-2025-0003"
    assert results[1].id == "CVE-2025-0002"


def test_sort_cve_results():
    from searchcve.search import sort_cve_results

    cve1 = CVEItem(id="CVE-2025-1000", description="desc", cvss_score=5.0, published=datetime(2025, 1, 1, tzinfo=timezone.utc))
    cve2 = CVEItem(id="CVE-2026-0005", description="desc", cvss_score=9.8, published=datetime(2026, 2, 1, tzinfo=timezone.utc))
    cve3 = CVEItem(id="CVE-2026-0002", description="desc", cvss_score=7.5, published=datetime(2026, 3, 1, tzinfo=timezone.utc))
    cve4 = CVEItem(id="CVE-2025-9999", description="desc", cvss_score=None, published=datetime(2025, 6, 1, tzinfo=timezone.utc))

    items = [cve1, cve2, cve3, cve4]

    # Sort by date (newest first)
    by_date = sort_cve_results(items, sort_by="date")
    assert [c.id for c in by_date] == ["CVE-2026-0002", "CVE-2026-0005", "CVE-2025-9999", "CVE-2025-1000"]

    # Sort by ID (highest year, then highest number)
    by_id = sort_cve_results(items, sort_by="id")
    assert [c.id for c in by_id] == ["CVE-2026-0005", "CVE-2026-0002", "CVE-2025-9999", "CVE-2025-1000"]

    # Sort by CVSS (highest score first, None at the end)
    by_cvss = sort_cve_results(items, sort_by="cvss")
    assert [c.id for c in by_cvss] == ["CVE-2026-0005", "CVE-2026-0002", "CVE-2025-1000", "CVE-2025-9999"]



