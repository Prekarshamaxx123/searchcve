"""Client for interacting with the National Vulnerability Database (NVD) API 2.0."""

import json
import logging
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from searchcve.config import Config
from searchcve.exceptions import (
    APIAuthError,
    APIConnectionError,
    APIServiceError,
    MalformedResponseError,
    NotFoundError,
    RateLimitError,
    SearchCVEError,
)
from searchcve.models import CVEItem

logger = logging.getLogger("searchcve.nvd")


class NVDClient:
    """HTTP client for NVD API 2.0 with connection reuse, retries, and rate-limit handling."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.from_env()
        self._opener = urllib.request.build_opener()

    def _build_request(self, params: Dict[str, Any]) -> urllib.request.Request:
        """Construct urllib Request with appropriate headers and encoded query params."""
        query_str = urllib.parse.urlencode(params)
        url = f"{self.config.nvd_base_url}?{query_str}"
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "application/json",
        }
        if self.config.api_key:
            headers["apiKey"] = self.config.api_key

        return urllib.request.Request(url, headers=headers, method="GET")

    def _execute_request(self, req: urllib.request.Request) -> Dict[str, Any]:
        """Execute request with retries, exponential backoff, and error translation."""
        attempts = 0
        backoff = self.config.initial_backoff

        while attempts <= self.config.max_retries:
            try:
                attempts += 1
                logger.debug("Requesting: %s (attempt %d/%d)", req.full_url, attempts, self.config.max_retries + 1)
                with self._opener.open(req, timeout=self.config.timeout) as response:
                    raw_body = response.read()
                    try:
                        data = json.loads(raw_body.decode("utf-8"))
                        if not isinstance(data, dict):
                            raise MalformedResponseError(
                                "Invalid NVD API response format: root must be a JSON object."
                            )
                        return data
                    except (UnicodeDecodeError, json.JSONDecodeError) as e:
                        raise MalformedResponseError(
                            f"Received malformed response from NVD API: {e}",
                            user_friendly_message="[!] Received malformed response from NVD API."
                        ) from e

            except urllib.error.HTTPError as e:
                status = e.code
                logger.debug("HTTP Error: %d for %s", status, req.full_url)

                if status == 404:
                    raise NotFoundError(
                        f"Resource not found (HTTP 404): {req.full_url}",
                        user_friendly_message="[!] CVE or endpoint not found (HTTP 404)."
                    ) from e

                if status == 403:
                    raise APIAuthError(
                        f"Access forbidden (HTTP 403): check your NVD API key if configured.",
                        user_friendly_message="[!] Access forbidden by NVD API (HTTP 403). Check your NVD_API_KEY."
                    ) from e

                if status == 429:
                    # Rate limited: check Retry-After header
                    retry_after_header = e.headers.get("Retry-After") if e.headers else None
                    sleep_time = backoff
                    if retry_after_header:
                        try:
                            sleep_time = max(1.0, float(retry_after_header))
                        except ValueError:
                            pass

                    if attempts <= self.config.max_retries:
                        try:
                            sys.stderr.write("\r\033[K")
                            sys.stderr.flush()
                        except Exception:
                            pass
                        logger.warning("[!] Rate limit hit (HTTP 429). Waiting %.1fs...", sleep_time)
                        time.sleep(sleep_time)
                        backoff *= 2
                        continue
                    else:
                        raise RateLimitError(
                            "NVD API rate limit exceeded and maximum retries reached.",
                            user_friendly_message=(
                                "[!] NVD API rate limit exceeded (HTTP 429).\n"
                                "    Please wait a few moments before searching again,\n"
                                "    or set an NVD_API_KEY environment variable for higher limits."
                            )
                        ) from e

                if status in (500, 502, 503, 504):
                    if attempts <= self.config.max_retries:
                        logger.warning("NVD API server error (%d). Retrying in %.1fs...", status, backoff)
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        raise APIServiceError(
                            f"NVD API service error (HTTP {status}) after retries.",
                            user_friendly_message=f"[!] NVD API service temporarily unavailable (HTTP {status}). Please try again later."
                        ) from e

                # Other HTTP errors (e.g. 400 Bad Request)
                error_body = ""
                try:
                    error_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                raise SearchCVEError(
                    f"NVD API request failed with HTTP {status}: {error_body}",
                    user_friendly_message=f"[!] NVD API request error (HTTP {status})."
                ) from e

            except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError) as e:
                logger.debug("Network error: %s for %s", e, req.full_url)
                if attempts <= self.config.max_retries and not isinstance(e, ssl.SSLCertVerificationError):
                    logger.warning("Connection failure (%s). Retrying in %.1fs...", e, backoff)
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                else:
                    raise APIConnectionError(
                        f"Unable to connect to NVD API: {e}",
                        user_friendly_message=(
                            "[!] Unable to connect to NVD API.\n"
                            "    Check your internet connection and try again."
                        )
                    ) from e

        raise APIConnectionError(
            "Maximum retries exceeded without successful response.",
            user_friendly_message="[!] Unable to connect to NVD API after multiple attempts."
        )

    def get_cve_by_id(self, cve_id: str) -> Optional[CVEItem]:
        """Lookup a specific CVE by its ID."""
        params = {"cveId": cve_id.upper()}
        req = self._build_request(params)
        data = self._execute_request(req)
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return CVEItem.from_nvd_dict(vulnerabilities[0])

    def fetch_page(
        self,
        keyword: str,
        start_index: int = 0,
        results_per_page: Optional[int] = None,
    ) -> Tuple[int, List[CVEItem]]:
        """Fetch a single page of CVE candidates from NVD matching keywordSearch."""
        rpp = results_per_page or self.config.page_size
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": min(rpp, self.config.page_size),
        }
        req = self._build_request(params)
        data = self._execute_request(req)
        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])
        items = [CVEItem.from_nvd_dict(v) for v in vulnerabilities]
        return total_results, items
