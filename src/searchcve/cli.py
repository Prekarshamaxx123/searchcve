"""Command Line Interface (CLI) entry point for SearchCVE."""

import argparse
import logging
import os
import shutil
import sys
from typing import List, Optional

from searchcve import __version__
from searchcve.config import Config
from searchcve.exceptions import SearchCVEError, ValidationError
from searchcve.nvd import NVDClient
from searchcve.output import ProgressBar, display_results
from searchcve.search import CVESearchEngine, validate_search_options

HELP_TEXT = """SearchCVE - Live NVD CVE Search Tool
Owner - https://github.com/Prekarshamaxx123

Usage:
  searchcve <keyword> [options]

Options:
  --last N              Show newest N matching CVEs
  --limit N             Limit number of results
  --year YEAR           Filter by publication year
  --from DATE           Start date YYYY-MM-DD
  --to DATE             End date YYYY-MM-DD
  --sort {date,id,cvss} Sort results by date, id, or cvss (default: date)
  --exact               Exact keyword matching
  --json                Output JSON
  --quiet               Output CVE IDs only
  --version             Show version
  -h, --help            Show help

Examples:
  searchcve openclaw
  searchcve openclaw --last 10
  searchcve apache --year 2026
  searchcve wordpress --from 2025-01-01
  searchcve openssh --from 2025-01-01 --to 2026-09-28
  searchcve CVE-2026-12345
  searchcve log4j --json
"""


class SearchCVEArgumentParser(argparse.ArgumentParser):
    """Custom parser to output exact SearchCVE help format."""

    def format_help(self) -> str:
        return HELP_TEXT

    def error(self, message: str) -> None:
        """Handle CLI parse errors gracefully."""
        sys.stderr.write(f"[!] Error: {message}\n\nRun 'searchcve --help' for usage.\n")
        sys.exit(2)


def create_parser() -> argparse.ArgumentParser:
    """Build the argument parser for SearchCVE."""
    parser = SearchCVEArgumentParser(
        prog="searchcve",
        add_help=False,
    )
    parser.add_argument(
        "query",
        nargs="*",
        default=[],
        help="Keyword or CVE ID to search",
    )
    parser.add_argument(
        "--last",
        type=int,
        default=None,
        metavar="N",
        help="Show newest N matching CVEs",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Limit number of results",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        metavar="YEAR",
        help="Filter by publication year",
    )
    parser.add_argument(
        "--from",
        dest="from_date",
        type=str,
        default=None,
        metavar="DATE",
        help="Start date YYYY-MM-DD",
    )
    parser.add_argument(
        "--to",
        dest="to_date",
        type=str,
        default=None,
        metavar="DATE",
        help="End date YYYY-MM-DD",
    )
    parser.add_argument(
        "--exact",
        action="store_true",
        help="Exact keyword matching",
    )
    parser.add_argument(
        "--sort",
        choices=["date", "id", "cvss"],
        default="date",
        help="Sort results by date, id, or cvss (default: date)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Output CVE IDs only",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show debug logs and full tracebacks",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"SearchCVE {__version__}",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show help",
    )
    return parser


def auto_register_shell() -> None:
    """Silently ensure SearchCVE is registered in user's ~/.bashrc and ~/.zshrc."""
    try:
        home = os.path.expanduser("~")
        if not home or not os.path.isdir(home):
            return

        bin_path = shutil.which("searchcve") or os.path.join(home, ".local", "bin", "searchcve")

        shell_configs = [
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc"),
        ]

        snippet = (
            '\n# SearchCVE - Live NVD CVE Search Tool (Owner: Prekarshamaxx123)\n'
            'export PATH="$HOME/.local/bin:$PATH"\n'
            f'alias searchcve="{bin_path}"\n'
        )

        for cfg in shell_configs:
            if os.path.exists(cfg):
                try:
                    with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if "SearchCVE" not in content and "alias searchcve=" not in content:
                        with open(cfg, "a", encoding="utf-8") as f:
                            f.write(snippet)
                except Exception:
                    pass
    except Exception:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    auto_register_shell()
    parser = create_parser()
    args = parser.parse_args(argv)
    query_str = " ".join(args.query).strip() if isinstance(args.query, list) else str(args.query or "").strip()
    if not query_str:
        sys.stderr.write("[!] Error: A search query or CVE ID is required.\n\n")
        sys.stderr.write(HELP_TEXT)
        return 2

    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="[DEBUG] %(name)s: %(message)s" if args.debug else "%(message)s",
    )

    try:
        # Validate options
        options = validate_search_options(
            query=query_str,
            last=args.last,
            limit=args.limit,
            year=args.year,
            from_date_str=args.from_date,
            to_date_str=args.to_date,
            exact=args.exact,
            sort=args.sort,
            json_output=args.json,
            quiet=args.quiet,
            debug=args.debug,
        )

        config = Config.from_env()
        client = NVDClient(config=config)
        engine = CVESearchEngine(client=client, config=config)

        progress_msg = f"Searching NVD for: {options.query}"
        show_progress = not (options.json_output or options.quiet)

        with ProgressBar(message=progress_msg, enabled=show_progress):
            results = engine.execute_search(options)

        display_results(results, options)
        return 0

    except ValidationError as e:
        sys.stderr.write(f"[!] Error: {e}\n")
        return 1

    except SearchCVEError as e:
        if args.debug:
            raise
        sys.stderr.write(f"{e.user_friendly_message}\n")
        return 1

    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Search cancelled by user.\n")
        return 130

    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0

    except Exception as e:
        if args.debug:
            raise
        sys.stderr.write(f"[!] Unexpected error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
