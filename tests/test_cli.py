"""Integration tests for CLI execution and arguments."""

from unittest.mock import MagicMock, patch
import pytest

from searchcve.cli import HELP_TEXT, main
from searchcve.models import CVEItem


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "SearchCVE - Live NVD CVE Search Tool" in captured.out
    assert "searchcve <keyword> [options]" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "SearchCVE 1.0.0" in captured.out


def test_cli_no_args(capsys):
    ret = main([])
    assert ret == 2
    captured = capsys.readouterr()
    assert "A search query or CVE ID is required" in captured.err


def test_cli_last_and_limit_conflict(capsys):
    ret = main(["openclaw", "--last", "10", "--limit", "20"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Cannot use both --last and --limit together" in captured.err


def test_cli_invalid_date(capsys):
    ret = main(["openclaw", "--from", "invalid-date"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Invalid --from date" in captured.err


@patch("searchcve.search.CVESearchEngine.execute_search")
def test_cli_json_output(mock_execute, capsys):
    mock_execute.return_value = [
        CVEItem(id="CVE-2026-0001", description="OpenClaw issue")
    ]
    ret = main(["openclaw", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert '"cve": "CVE-2026-0001"' in captured.out
    assert '"description": "OpenClaw issue"' in captured.out


@patch("searchcve.search.CVESearchEngine.execute_search")
def test_cli_quiet_output(mock_execute, capsys):
    mock_execute.return_value = [
        CVEItem(id="CVE-2026-0001", description="OpenClaw issue 1"),
        CVEItem(id="CVE-2026-0002", description="OpenClaw issue 2"),
    ]
    ret = main(["openclaw", "--quiet"])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "CVE-2026-0001\nCVE-2026-0002"
