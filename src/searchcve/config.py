"""Configuration settings and environment variable management for SearchCVE."""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Config:
    """Application configuration."""

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: Optional[str] = None
    timeout: float = 15.0
    max_results: int = 1000
    page_size: int = 2000
    max_retries: int = 3
    initial_backoff: float = 6.0
    user_agent: str = "SearchCVE/1.0.0 (https://github.com/searchcve/searchcve)"

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration with environment variable overrides."""
        api_key = os.environ.get("NVD_API_KEY", "").strip() or None

        timeout_str = os.environ.get("SEARCHCVE_TIMEOUT", "15.0")
        try:
            timeout = max(1.0, float(timeout_str))
        except ValueError:
            timeout = 15.0

        max_results_str = os.environ.get("SEARCHCVE_MAX_RESULTS", "1000")
        try:
            max_results = max(1, int(max_results_str))
        except ValueError:
            max_results = 1000

        return cls(
            api_key=api_key,
            timeout=timeout,
            max_results=max_results,
        )
