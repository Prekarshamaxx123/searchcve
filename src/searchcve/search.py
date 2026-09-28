"""Search engine logic, CVE filtering, and query execution."""

import logging
import re
from datetime import date, datetime
from typing import List, Optional

from searchcve.config import Config
from searchcve.exceptions import ValidationError
from searchcve.models import CVEItem, SearchOptions
from searchcve.nvd import NVDClient

logger = logging.getLogger("searchcve.search")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
DATE_FORMAT = "%Y-%m-%d"


def is_cve_id(query: str) -> bool:
    """Return True if query strictly matches CVE identifier format."""
    return bool(CVE_PATTERN.match(query.strip()))


def parse_date(date_str: str, field_name: str) -> date:
    """Validate and parse a YYYY-MM-DD date string strictly."""
    stripped = date_str.strip()
    try:
        dt = datetime.strptime(stripped, DATE_FORMAT)
        return dt.date()
    except ValueError as e:
        raise ValidationError(
            f"Invalid {field_name} date: '{date_str}'. Expected format is YYYY-MM-DD."
        ) from e


def validate_search_options(
    query: str,
    last: Optional[int] = None,
    limit: Optional[int] = None,
    year: Optional[int] = None,
    from_date_str: Optional[str] = None,
    to_date_str: Optional[str] = None,
    exact: bool = False,
    sort: str = "date",
    json_output: bool = False,
    quiet: bool = False,
    debug: bool = False,
) -> SearchOptions:
    """Validate all CLI options and construct a SearchOptions object."""
    clean_query = query.strip()
    if not clean_query:
        raise ValidationError("Search query cannot be empty.")

    sort_clean = (sort or "date").strip().lower()
    if sort_clean not in ("date", "id", "cvss"):
        raise ValidationError(f"Invalid sort option: '{sort}'. Must be 'date', 'id', or 'cvss'.")

    # Mutual exclusivity of --last and --limit
    if last is not None and limit is not None:
        raise ValidationError(
            "Cannot use both --last and --limit together. "
            "Use --last N to sort by newest first, or --limit N to limit results."
        )

    if last is not None and last <= 0:
        raise ValidationError(f"--last must be a positive integer, got {last}.")

    if limit is not None and limit <= 0:
        raise ValidationError(f"--limit must be a positive integer, got {limit}.")

    if year is not None:
        if year < 1999 or year > 2100:
            raise ValidationError(f"Invalid year: {year}. Must be between 1999 and 2100.")

    parsed_from: Optional[date] = None
    if from_date_str:
        parsed_from = parse_date(from_date_str, "--from")

    parsed_to: Optional[date] = None
    if to_date_str:
        parsed_to = parse_date(to_date_str, "--to")

    if parsed_from and parsed_to and parsed_from > parsed_to:
        raise ValidationError(
            f"--from date ({parsed_from}) cannot be after --to date ({parsed_to})."
        )

    # If year is provided with from/to, check for consistency
    if year is not None:
        if parsed_from and parsed_from.year > year:
            raise ValidationError(
                f"--year {year} conflicts with --from {parsed_from}."
            )
        if parsed_to and parsed_to.year < year:
            raise ValidationError(
                f"--year {year} conflicts with --to {parsed_to}."
            )

    cve_lookup = is_cve_id(clean_query)

    return SearchOptions(
        query=clean_query,
        is_cve_lookup=cve_lookup,
        last=last,
        limit=limit,
        year=year,
        from_date=parsed_from,
        to_date=parsed_to,
        exact=exact,
        sort=sort_clean,
        json_output=json_output,
        quiet=quiet,
        debug=debug,
    )


def matches_keyword(cve: CVEItem, query: str, exact: bool = False) -> bool:
    """Check if CVE description matches the query string (SearchSploit-style multi-term matching)."""
    desc = cve.description
    if not desc:
        return False

    clean_query = query.strip()
    if not clean_query:
        return False

    # Exact matching: whole word boundaries
    if exact:
        terms = clean_query.split()
        for term in terms:
            pattern = r"(?i)\b" + re.escape(term) + r"\b"
            if not re.search(pattern, desc):
                return False
        return True

    # SearchSploit-style case-insensitive matching:
    # 1. Direct contiguous match (fast path)
    if clean_query.lower() in desc.lower():
        return True

    # 2. Multi-term match: all terms (e.g. 'bluetooth' and '3.1') must appear in description
    terms = clean_query.split()
    desc_lower = desc.lower()
    return all(term.lower() in desc_lower for term in terms)


def matches_filters(cve: CVEItem, options: SearchOptions) -> bool:
    """Apply all filter criteria (description matching, year, date range) to a CVE item."""
    # Description matching (unless exact CVE lookup by ID)
    if not options.is_cve_lookup:
        if not matches_keyword(cve, options.query, exact=options.exact):
            return False

    # Year filtering
    if options.year is not None:
        if not cve.published or cve.published.year != options.year:
            return False

    # Date range filtering
    if options.from_date is not None:
        if not cve.published or cve.published.date() < options.from_date:
            return False

    if options.to_date is not None:
        if not cve.published or cve.published.date() > options.to_date:
            return False

    return True


def extract_fallback_query(query: str) -> Optional[str]:
    """Extract a smart fallback query when a multi-term query yields 0 results.

    For example:
    - 'android 14 bluetooth' -> 'android bluetooth' (drops version number)
    - 'bluetooth 3.1' -> 'bluetooth' (drops version number)
    - 'apache 2.4.49' -> 'apache' (drops version number)
    """
    terms = query.strip().split()
    if len(terms) <= 1:
        return None

    # Separate non-version terms from numbers / version tokens
    non_version = [
        t for t in terms
        if not re.match(r"^[vV]?\d+(\.\d+)*[a-zA-Z]?$", t) and not t.isdigit()
    ]

    if non_version and len(non_version) < len(terms):
        return " ".join(non_version)

    if len(terms) > 2:
        return " ".join(terms[:2])

def cve_sort_key(cve_id: str) -> tuple:
    """Parse CVE ID into numeric tuple for accurate sorting (e.g. CVE-2026-9810 -> (2026, 9810))."""
    parts = cve_id.upper().split("-")
    if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
        return (int(parts[1]), int(parts[2]))
    return (0, 0)


def sort_cve_results(cves: List[CVEItem], sort_by: str = "date") -> List[CVEItem]:
    """Sort CVE items by date, id, or cvss score."""
    if sort_by == "id":
        return sorted(cves, key=lambda it: cve_sort_key(it.id), reverse=True)
    elif sort_by == "cvss":
        return sorted(
            cves,
            key=lambda it: (
                it.cvss_score if it.cvss_score is not None else -1.0,
                it.published.timestamp() if it.published else float("-inf"),
                cve_sort_key(it.id),
            ),
            reverse=True,
        )
    else:  # "date"
        return sorted(
            cves,
            key=lambda it: (
                it.published.timestamp() if it.published else float("-inf"),
                cve_sort_key(it.id),
            ),
            reverse=True,
        )


class CVESearchEngine:
    """Executes searches against NVD and coordinates filtering and pagination."""

    def __init__(self, client: Optional[NVDClient] = None, config: Optional[Config] = None):
        self.config = config or Config.from_env()
        self.client = client or NVDClient(self.config)

    def execute_search(self, options: SearchOptions) -> List[CVEItem]:
        """Perform search based on options and return filtered matching CVE items."""
        # Specific CVE ID lookup
        if options.is_cve_lookup:
            logger.debug("Performing specific CVE lookup for %s", options.query)
            cve_item = self.client.get_cve_by_id(options.query)
            if cve_item and matches_filters(cve_item, options):
                return [cve_item]
            return []

        search_keyword = options.query

        # Probe first page to check total_results and sample earliest dates
        probe_size = min(max(50, (options.last or 0) * 3, (options.limit or 0) * 2), 100)
        total_results, first_items = self.client.fetch_page(
            keyword=search_keyword,
            start_index=0,
            results_per_page=probe_size,
        )

        # Smart fallback if combined query returns 0 (e.g. 'android 14 bluetooth' -> 'android bluetooth')
        if total_results == 0 and len(search_keyword.split()) > 1:
            fallback = extract_fallback_query(search_keyword)
            if fallback and fallback != search_keyword:
                search_keyword = fallback
                logger.debug("Combined query returned 0; falling back to: %s", search_keyword)
                total_results, first_items = self.client.fetch_page(
                    keyword=search_keyword,
                    start_index=0,
                    results_per_page=probe_size,
                )

        if total_results == 0 or not first_items:
            return []

        # If all results in NVD fit within the first page, filter and return immediately
        if total_results <= len(first_items):
            matching_results = [item for item in first_items if matches_filters(item, options)]
            matching_results = sort_cve_results(matching_results, sort_by=options.sort)
            if options.last is not None:
                return matching_results[: options.last]
            if options.limit is not None:
                return matching_results[: options.limit]
            return matching_results

        # Determine scan direction:
        # NVD returns results chronologically (oldest first).
        probe_pub_year = first_items[-1].published.year if first_items[-1].published else 2000

        scan_backward = False
        if options.year is not None:
            # If the requested year is newer than the probe page, it's towards the tail
            scan_backward = (options.year > probe_pub_year)
        elif options.from_date is not None:
            scan_backward = (options.from_date.year > probe_pub_year)
        elif options.to_date is not None:
            scan_backward = (options.to_date.year > probe_pub_year)
        elif options.last is not None:
            scan_backward = True

        matching_results: List[CVEItem] = []
        max_requests = 4 if self.config.api_key is None else 15
        requests_made = 1  # 1 probe request already completed
        chunk_size = min(500, self.config.page_size)

        if scan_backward:
            # Determine target count if limited
            if options.last is not None:
                target_count = options.last
            elif options.limit is not None:
                target_count = options.limit
            else:
                target_count = self.config.max_results

            current_start = max(0, total_results - chunk_size)

            while requests_made < max_requests:
                requests_made += 1
                _, page_items = self.client.fetch_page(
                    keyword=search_keyword,
                    start_index=current_start,
                    results_per_page=chunk_size,
                )
                if not page_items:
                    break

                for item in page_items:
                    if matches_filters(item, options) and not any(m.id == item.id for m in matching_results):
                        matching_results.append(item)

                if target_count and len(matching_results) >= target_count:
                    break

                earliest_in_page = page_items[0].published
                latest_in_page = page_items[-1].published

                # If searching for a specific year and the earliest item on this page is from an earlier year,
                # no more items for this year can possibly exist in preceding pages.
                if options.year is not None:
                    if earliest_in_page and earliest_in_page.year < options.year:
                        break
                    # If the newest item in the entire tail is older than the requested year, nothing matches
                    if latest_in_page and latest_in_page.year < options.year:
                        break

                # If searching from a date and earliest on page is before from_date, stop
                if options.from_date is not None:
                    if earliest_in_page and earliest_in_page.date() < options.from_date:
                        break

                if current_start <= 0:
                    break

                current_start = max(0, current_start - chunk_size)

            # Sort according to requested sort option
            matching_results = sort_cve_results(matching_results, sort_by=options.sort)
            if options.last is not None:
                return matching_results[: options.last]
            if options.limit is not None:
                return matching_results[: options.limit]
            return matching_results

        else:
            # Forward scan starting from index 0 (oldest items or historical year queries)
            for item in first_items:
                if matches_filters(item, options):
                    matching_results.append(item)
                    if options.limit and len(matching_results) >= options.limit:
                        return matching_results[: options.limit]

            target_count = options.limit or self.config.max_results
            start_index = len(first_items)

            while start_index < total_results and requests_made < max_requests:
                if options.limit and len(matching_results) >= options.limit:
                    break
                if options.last and len(matching_results) >= options.last and options.year is None and options.to_date is None:
                    break

                requests_made += 1
                _, page_items = self.client.fetch_page(
                    keyword=search_keyword,
                    start_index=start_index,
                    results_per_page=chunk_size,
                )
                if not page_items:
                    break

                early_break = False
                for item in page_items:
                    # Early stop if we surpassed the requested year
                    if options.year is not None and item.published and item.published.year > options.year:
                        early_break = True
                        break
                    if options.to_date is not None and item.published and item.published.date() > options.to_date:
                        early_break = True
                        break

                    if matches_filters(item, options) and not any(m.id == item.id for m in matching_results):
                        matching_results.append(item)
                        if options.limit and len(matching_results) >= options.limit:
                            early_break = True
                            break

                if early_break:
                    break

                start_index += len(page_items)

            matching_results = sort_cve_results(matching_results, sort_by=options.sort)
            if options.last is not None:
                return matching_results[: options.last]
            if options.limit is not None:
                return matching_results[: options.limit]

            return matching_results
