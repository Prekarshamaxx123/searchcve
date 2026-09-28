"""Unit tests for output formatting (SearchSploit table, JSON, quiet)."""

import json
from io import StringIO
from unittest.mock import patch

from searchcve.models import CVEItem, SearchOptions
from searchcve.output import (
    ProgressBar,
    display_results,
    format_json,
    format_quiet,
    format_table,
)


def sample_cves():
    return [
        CVEItem(id="CVE-2026-12345", description="OpenClaw contains a vulnerability that allows RCE."),
        CVEItem(id="CVE-2026-12346", description="A vulnerability in OpenClaw allows denial of service."),
    ]


def test_format_json():
    cves = sample_cves()
    json_str = format_json(cves)
    parsed = json.loads(json_str)

    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0] == {
        "cve": "CVE-2026-12345",
        "description": "OpenClaw contains a vulnerability that allows RCE.",
    }
    assert parsed[1] == {
        "cve": "CVE-2026-12346",
        "description": "A vulnerability in OpenClaw allows denial of service.",
    }

    # Verify no extra fields
    assert set(parsed[0].keys()) == {"cve", "description"}


def test_format_json_empty():
    assert json.loads(format_json([])) == []


def test_format_quiet():
    cves = sample_cves()
    quiet_str = format_quiet(cves)
    assert quiet_str == "CVE-2026-12345\nCVE-2026-12346"

    assert format_quiet([]) == ""


def test_format_table():
    cves = sample_cves()
    opts = SearchOptions(query="openclaw")
    table = format_table(cves, opts)

    assert "SearchCVE" in table
    assert "Query: openclaw" in table
    assert "CVSS" in table
    assert "CVE" in table
    assert "Description" in table
    assert "CVE-2026-12345" in table
    assert "CVE-2026-12346" in table
    assert "Found: 2 CVEs" in table


def test_format_table_cvss_scores():
    cves = [
        CVEItem(id="CVE-2026-0001", description="Critical flaw", cvss_score=9.8),
        CVEItem(id="CVE-2026-0002", description="Unknown flaw", cvss_score=None),
    ]
    opts = SearchOptions(query="test")
    table = format_table(cves, opts)

    assert "9.8" in table
    assert "-" in table


def test_format_table_spacing_between_cves():
    cves = sample_cves()
    opts = SearchOptions(query="openclaw")
    table = format_table(cves, opts)

    # There should be an empty line separating CVE items
    lines = table.split("\n")
    # Find line index of first CVE and second CVE
    idx1 = next(i for i, l in enumerate(lines) if "CVE-2026-12345" in l)
    idx2 = next(i for i, l in enumerate(lines) if "CVE-2026-12346" in l)
    # Between idx1 and idx2 there must be at least one empty line
    intermediate_lines = lines[idx1 + 1 : idx2]
    assert "" in intermediate_lines


def test_format_table_empty():
    opts = SearchOptions(query="nonexistent")
    table = format_table([], opts)
    assert "No matching CVEs found." in table


def test_display_results_json(capsys):
    cves = sample_cves()
    opts = SearchOptions(query="openclaw", json_output=True)
    display_results(cves, opts)

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert len(parsed) == 2
    assert parsed[0]["cve"] == "CVE-2026-12345"


def test_display_results_quiet(capsys):
    cves = sample_cves()
    opts = SearchOptions(query="openclaw", quiet=True)
    display_results(cves, opts)

    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert lines == ["CVE-2026-12345", "CVE-2026-12346"]


class MockTTYStream(StringIO):
    def isatty(self):
        return True


def test_progress_bar_renders_hash_and_estimate():
    stream = MockTTYStream()
    with ProgressBar(message="Searching NVD", enabled=True, stream=stream):
        import time
        time.sleep(0.15)

    output = stream.getvalue()
    # Check that '#' characters and time estimates are included
    assert "#" in output
    assert "Searching NVD" in output
    assert "elapsed:" in output
    assert "est:" in output
    assert "100%" in output
    assert "completed in" in output


def test_progress_bar_disabled():
    stream = StringIO()  # isatty is False
    with ProgressBar(message="Searching NVD", enabled=False, stream=stream):
        pass
    assert stream.getvalue() == ""


def test_progress_bar_exception_clears_line():
    stream = MockTTYStream()
    try:
        with ProgressBar(message="Searching NVD", enabled=True, stream=stream):
            raise ValueError("Test error")
    except ValueError:
        pass

    output = stream.getvalue()
    # Ensure ANSI clear line sequence is written on failure
    assert "\r\033[K" in output


def test_get_save_filename():
    from searchcve.output import get_save_filename

    opts1 = SearchOptions(query="bluetooth", year=2026)
    assert get_save_filename(opts1) == "searchcve_bluetooth_2026.txt"

    opts2 = SearchOptions(query="android 14 bluetooth")
    assert get_save_filename(opts2) == "searchcve_android_14_bluetooth.txt"

    opts3 = SearchOptions(query="CVE-2026-12345", json_output=True)
    assert get_save_filename(opts3, extension="json") == "searchcve_cve-2026-12345.json"


def test_auto_save_when_more_than_50_cves(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    # Generate 55 CVEs (> 50)
    cves = [CVEItem(id=f"CVE-2026-{i:05d}", description=f"Test vulnerability {i}") for i in range(1, 56)]
    opts = SearchOptions(query="bluetooth", year=2026)

    display_results(cves, opts)

    captured = capsys.readouterr()
    # Check that notification message was printed
    assert "More than 50 CVEs found" in captured.out
    assert "Saving output to 'searchcve_bluetooth_2026.txt'" in captured.out
    assert "Output successfully saved to" in captured.out
    assert "searchcve_bluetooth_2026.txt" in captured.out

    # Check that file was created and contains all 55 CVEs
    saved_file = tmp_path / "searchcve_bluetooth_2026.txt"
    assert saved_file.exists()
    content = saved_file.read_text(encoding="utf-8")
    assert "CVE-2026-00001" in content
    assert "CVE-2026-00055" in content
    assert "Found: 55 CVEs" in content


def test_no_save_when_50_or_fewer_cves(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    # Exactly 50 CVEs (should NOT auto-save)
    cves = [CVEItem(id=f"CVE-2026-{i:05d}", description=f"Test vulnerability {i}") for i in range(1, 51)]
    opts = SearchOptions(query="bluetooth")

    display_results(cves, opts)

    captured = capsys.readouterr()
    assert "More than 50 CVEs found" not in captured.out
    assert not (tmp_path / "searchcve_bluetooth.txt").exists()


