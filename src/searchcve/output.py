"""Output formatting for SearchCVE (SearchSploit-style, JSON, quiet)."""

import json
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from typing import List, Optional

from searchcve import __version__
from searchcve.models import CVEItem, SearchOptions


def supports_color() -> bool:
    """Check if the current terminal environment supports ANSI color codes."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


class Colors:
    """ANSI color codes with automatic disable if not supported."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cvss_color(self, score: Optional[float], text: str) -> str:
        """Apply color coding based on CVSS severity."""
        if not self.enabled:
            return text
        if score is None:
            return self.dim(text)
        if score >= 9.0:
            return self.bold(self.red(text))
        if score >= 7.0:
            return self.red(text)
        if score >= 4.0:
            return self.yellow(text)
        return self.green(text)


class ProgressBar:
    """An animated ASCII progress bar using '#' characters with dynamic time estimation."""

    def __init__(
        self,
        message: str = "Searching NVD",
        enabled: bool = True,
        bar_width: int = 20,
        initial_est: float = 3.5,
        stream=sys.stderr,
    ):
        self.message = message
        self.stream = stream
        self.enabled = bool(enabled and getattr(self.stream, "isatty", lambda: False)())
        self.bar_width = bar_width
        self.initial_est = initial_est
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time: float = 0.0
        self._color = Colors(supports_color() and getattr(self.stream, "isatty", lambda: False)())

    def start(self) -> "ProgressBar":
        """Start the background animation thread."""
        if not self.enabled:
            return self
        self._start_time = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def _animate(self) -> None:
        """Render the progress bar using '#' with dynamic elapsed and estimated time."""
        est = self.initial_est
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            if elapsed > est - 0.4:
                est = elapsed + 1.2
            pct = min(0.95, elapsed / est)
            filled = int(self.bar_width * pct)
            empty = self.bar_width - filled
            bar = "#" * filled + "." * empty
            pct_int = int(pct * 100)

            line = (
                f"\r{self.message}: [{self._color.cyan(bar)}] "
                f"{pct_int:>2}% (elapsed: {elapsed:.1f}s / est: ~{est:.1f}s) "
            )
            try:
                self.stream.write(line)
                self.stream.flush()
            except Exception:
                break
            self._stop_event.wait(0.08)

    def stop(self, success: bool = True) -> None:
        """Stop the animation and print the final 100% completion bar or clear on error."""
        if not self.enabled:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        elapsed = time.time() - self._start_time
        try:
            if success:
                full_bar = "#" * self.bar_width
                line = (
                    f"\r{self.message}: [{self._color.green(full_bar)}] "
                    f"100% (completed in {elapsed:.1f}s)\033[K\n\n"
                )
                self.stream.write(line)
                self.stream.flush()
            else:
                self.stream.write("\r\033[K")
                self.stream.flush()
        except Exception:
            pass

    def __enter__(self) -> "ProgressBar":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop(success=(exc_type is None))



def get_divider(char: str = "─", length: Optional[int] = None) -> str:
    """Get a horizontal divider matching terminal width or standard length."""
    if length is None:
        term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
        length = min(max(term_width - 1, 40), 100)
    try:
        return char * length
    except UnicodeEncodeError:
        return "-" * length


def format_json(cves: List[CVEItem]) -> str:
    """Format CVE results as valid JSON matching requirements."""
    data = [item.to_dict() for item in cves]
    return json.dumps(data, indent=2)


def format_quiet(cves: List[CVEItem]) -> str:
    """Format CVE results as a newline-separated list of CVE IDs."""
    if not cves:
        return ""
    return "\n".join(item.id for item in cves)


def format_table(
    cves: List[CVEItem],
    options: SearchOptions,
    color_enabled: Optional[bool] = None,
    max_display: Optional[int] = None,
    saved_filename: Optional[str] = None,
) -> str:
    """Format CVE results in SearchSploit style."""
    enabled = supports_color() if color_enabled is None else color_enabled
    color = Colors(enabled)
    divider = get_divider("─")

    if not cves:
        return f"\n{color.yellow('No matching CVEs found.')}\n"

    # Terminal width calculations (no arbitrary 120 cap)
    term_width = shutil.get_terminal_size(fallback=(100, 24)).columns
    max_line_width = max(term_width - 1, 80)

    # Column widths
    cvss_col_width = 5
    cve_col_width = 16
    for item in cves:
        if len(item.id) > cve_col_width:
            cve_col_width = len(item.id) + 2

    fixed_width = cvss_col_width + 2 + cve_col_width + 2
    desc_col_width = max(max_line_width - fixed_width, 40)
    indent = " " * fixed_width

    lines: List[str] = []

    # Title & query header
    lines.append(f"{color.bold('SearchCVE')} {color.dim(f'v{__version__}')}")
    lines.append(f"Owner - {color.cyan('https://github.com/Prekarshamaxx123')}")
    lines.append(get_divider("─", max_line_width))
    lines.append(f"Query: {color.cyan(options.query)}")
    lines.append("")

    # Table Header
    header = f"{'CVSS':<{cvss_col_width}}  {'CVE':<{cve_col_width}}  {'Description'}"
    lines.append(color.bold(header))
    lines.append(get_divider("─", max_line_width))

    # Slice items if max_display is specified
    display_items = cves[:max_display] if max_display is not None else cves

    # Table Rows
    for i, item in enumerate(display_items):
        if i > 0:
            lines.append("")

        if item.cvss_score is not None:
            score_text = f"{item.cvss_score:4.1f}"
        else:
            score_text = "   -"
        cvss_cell = color.cvss_color(item.cvss_score, f"{score_text:<{cvss_col_width}}")

        # Wrap description across lines (up to 3 full lines, ~250-300 chars)
        # cleanly indented under the Description column
        desc_lines = textwrap.wrap(item.description, width=desc_col_width)
        if not desc_lines:
            desc_lines = [""]
        elif len(desc_lines) > 3:
            desc_lines = desc_lines[:3]
            if len(desc_lines[2]) + 3 <= desc_col_width:
                desc_lines[2] = desc_lines[2].rstrip() + "..."
            else:
                desc_lines[2] = desc_lines[2][: desc_col_width - 3].rstrip() + "..."

        row = f"{cvss_cell}  {item.id:<{cve_col_width}}  {desc_lines[0]}"
        lines.append(row)
        for sub_line in desc_lines[1:]:
            lines.append(f"{indent}{sub_line}")

    # Footer
    lines.append(get_divider("─", max_line_width))
    if max_display is not None and len(cves) > max_display and saved_filename:
        found_msg = f"Found: {len(cves)} CVEs (Showing first {max_display}. Full results saved to '{saved_filename}')"
    elif saved_filename:
        found_msg = f"Found: {len(cves)} CVEs (Saved to '{saved_filename}')"
    else:
        found_msg = f"Found: {len(cves)} CVE{'s' if len(cves) != 1 else ''}"
    lines.append(color.green(found_msg))

    return "\n".join(lines)


def get_save_filename(options: SearchOptions, extension: str = "txt") -> str:
    """Generate a clean, descriptive filename for saving search results."""
    raw_query = options.query.strip().lower()
    safe_query = re.sub(r"[^\w\-]+", "_", raw_query).strip("_") or "results"

    parts = ["searchcve", safe_query]
    if options.year:
        parts.append(str(options.year))
    elif options.from_date:
        parts.append(options.from_date.strftime("%Y%m%d"))

    return f"{'_'.join(parts)}.{extension}"


def save_cve_results(cves: List[CVEItem], options: SearchOptions, filename: str) -> str:
    """Save full CVE results to a file in the current working directory."""
    if options.json_output:
        content = format_json(cves)
    elif options.quiet:
        content = format_quiet(cves)
    else:
        # Save complete results in plain text table (without terminal color codes)
        content = format_table(cves, options, color_enabled=False, max_display=None)

    filepath = os.path.join(os.getcwd(), filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")
    return filepath


def display_results(cves: List[CVEItem], options: SearchOptions) -> None:
    """Route output to stdout based on specified formatting options, saving if > 50 CVEs."""
    saved_filename: Optional[str] = None

    # Requirement: If CVEs are more than 50, say that the output will be saved and save it
    if len(cves) > 50:
        ext = "json" if options.json_output else "txt"
        saved_filename = get_save_filename(options, extension=ext)
        save_cve_results(cves, options, saved_filename)

        color = Colors(supports_color() and not (options.json_output or options.quiet))
        notice = (
            f"{color.yellow('[i] More than 50 CVEs found')} ({len(cves)} total). "
            f"Saving output to '{color.cyan(saved_filename)}'...\n"
            f"{color.green('[+] Output successfully saved to')} {color.bold(saved_filename)}\n\n"
        )

        if options.json_output or options.quiet:
            sys.stderr.write(f"[i] More than 50 CVEs found ({len(cves)} total). Saving output to '{saved_filename}'...\n")
            sys.stderr.write(f"[+] Output successfully saved to '{saved_filename}'\n")
            sys.stderr.flush()
        else:
            sys.stdout.write(notice)
            sys.stdout.flush()

    if options.json_output:
        sys.stdout.write(format_json(cves) + "\n")
    elif options.quiet:
        output = format_quiet(cves)
        if output:
            sys.stdout.write(output + "\n")
    else:
        # In terminal: if more than 50 and no explicit limit given, show first 50
        max_display = 50 if (len(cves) > 50 and options.limit is None) else None
        sys.stdout.write(format_table(
            cves,
            options,
            max_display=max_display,
            saved_filename=saved_filename,
        ) + "\n")
    sys.stdout.flush()
