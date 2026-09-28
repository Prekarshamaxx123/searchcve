"""Data models representing CVE entities and search query parameters."""

import re
from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Any, Dict, List, Optional


def clean_description(raw: str) -> str:
    """Normalize whitespace and strip control characters from descriptions."""
    if not raw:
        return ""
    # Strip terminal control characters (ANSI codes, etc.) for safety
    cleaned = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", raw)
    # Normalize newlines, carriage returns, tabs to single spaces
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


@dataclass(frozen=True)
class CVEItem:
    """Represents a single CVE record."""

    id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    vuln_status: Optional[str] = None
    # Extensible fields for future options (--cwe, --references, etc.)
    metrics: Dict[str, Any] = field(default_factory=dict)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @classmethod
    def from_nvd_dict(cls, item: Dict[str, Any]) -> "CVEItem":
        """Parse a CVE object from the NVD API 2.0 vulnerability schema."""
        cve = item.get("cve", item)
        cve_id = cve.get("id", "").strip()

        # Find best description (prefer English 'en')
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        desc_text = clean_description(desc_text)

        # Parse CVSS score and severity from metrics
        cvss_score: Optional[float] = None
        cvss_severity: Optional[str] = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if not isinstance(metric_list, list) or not metric_list:
                continue
            sorted_entries = sorted(
                metric_list,
                key=lambda m: 0 if isinstance(m, dict) and m.get("type") == "Primary" else 1,
            )
            for entry in sorted_entries:
                if not isinstance(entry, dict):
                    continue
                cvss_data = entry.get("cvssData")
                if isinstance(cvss_data, dict):
                    raw_score = cvss_data.get("baseScore")
                    if raw_score is not None:
                        try:
                            cvss_score = float(raw_score)
                            cvss_severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
                            if cvss_severity:
                                cvss_severity = str(cvss_severity).upper()
                            break
                        except (ValueError, TypeError):
                            pass
            if cvss_score is not None:
                break

        # Parse published date
        published = None
        pub_raw = cve.get("published")
        if pub_raw:
            try:
                published = datetime.fromisoformat(pub_raw.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                published = None

        # Parse lastModified date
        last_modified = None
        mod_raw = cve.get("lastModified")
        if mod_raw:
            try:
                last_modified = datetime.fromisoformat(mod_raw.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                last_modified = None

        # Parse CWEs
        cwe_ids: List[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value")
                if val and val not in cwe_ids:
                    cwe_ids.append(val)

        # Parse references
        references: List[str] = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        return cls(
            id=cve_id,
            description=desc_text,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            published=published,
            last_modified=last_modified,
            vuln_status=cve.get("vulnStatus"),
            metrics=metrics,
            cwe_ids=cwe_ids,
            references=references,
        )

    def to_dict(self) -> Dict[str, str]:
        """Convert to machine-readable dictionary for JSON output."""
        return {
            "cve": self.id,
            "description": self.description,
        }


@dataclass
class SearchOptions:
    """Validated options for a CVE search."""

    query: str
    is_cve_lookup: bool = False
    last: Optional[int] = None
    limit: Optional[int] = None
    year: Optional[int] = None
    from_date: Optional[date] = None
    to_date: Optional[date] = None
    exact: bool = False
    sort: str = "date"
    json_output: bool = False
    quiet: bool = False
    debug: bool = False
