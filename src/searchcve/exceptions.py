"""Custom exceptions for SearchCVE."""

from typing import Optional


class SearchCVEError(Exception):
    """Base exception for all SearchCVE errors."""

    def __init__(self, message: str, user_friendly_message: Optional[str] = None):
        super().__init__(message)
        self.user_friendly_message = user_friendly_message or message


class ValidationError(SearchCVEError):
    """Raised when user input or options fail validation."""
    pass


class APIConnectionError(SearchCVEError):
    """Raised when network connection to NVD API fails (DNS, timeout, TLS, offline)."""
    pass


class RateLimitError(SearchCVEError):
    """Raised when NVD API rate limit (HTTP 429) is exceeded and retries are exhausted."""
    pass


class APIServiceError(SearchCVEError):
    """Raised when NVD API returns server errors (500, 502, 503, etc.)."""
    pass


class APIAuthError(SearchCVEError):
    """Raised when NVD API returns authentication errors (HTTP 403)."""
    pass


class NotFoundError(SearchCVEError):
    """Raised when requested CVE or endpoint is not found (HTTP 404)."""
    pass


class MalformedResponseError(SearchCVEError):
    """Raised when NVD API returns unparseable or unexpected response payload."""
    pass
