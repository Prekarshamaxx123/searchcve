# SearchCVE

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-v1.0.0-success.svg)](https://github.com/Prekarshamaxx123/searchcve)
[![API](https://img.shields.io/badge/NVD%20API-v2.0%20Live-orange.svg)](https://services.nvd.nist.gov/rest/json/cves/2.0)
[![Author](https://img.shields.io/badge/Author-Prekarshamaxx123-purple.svg)](https://github.com/Prekarshamaxx123)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red.svg)](LICENSE)

**A high-performance, SearchSploit-style CLI tool for searching Common Vulnerabilities and Exposures (CVEs) live via the official National Vulnerability Database (NVD) REST API 2.0.**

</div>

---

> [!IMPORTANT]
> **Zero Local Database:** SearchCVE does **not** download, clone, or maintain a local CVE database (no SQLite, PostgreSQL, MongoDB, or Redis). All queries are executed in real-time against NIST's NVD API with intelligent, in-memory bidirectional pagination and filtering.

---

## Terminal Preview (Live Demo)

```text
┌──(kali㉿security)-[~/Projects/searchcve]
└─$ searchcve "bluetooth" --last 5 --year 2025 --sort cvss
Searching NVD for: bluetooth: [####################] 100% (completed in 1.4s)

SearchCVE v1.0.0
────────────────────────────────────────────────────────────────────────────────
Query: bluetooth

CVSS   CVE               Description
────────────────────────────────────────────────────────────────────────────────
 9.8   CVE-2024-45434    OpenSynergy BlueSDK (aka Blue SDK) through 6.x has a
                         Use-After-Free. The specific flaw exists within the
                         BlueSDK Bluetooth stack. The issue results from the...

 9.8   CVE-2025-9994     The Amp’ed RF BT-AP 111 Bluetooth access point's HTTP
                         admin interface does not have an authentication
                         feature, allowing unauthorized access to anyone with...

 9.8   CVE-2025-55031    Malicious pages could use Firefox for iOS to pass FIDO:
                         links to the OS and trigger the hybrid passkey
                         transport. An attacker within Bluetooth range could...

 9.8   CVE-2025-20680    In Bluetooth driver, there is a possible out of bounds
                         write due to an incorrect bounds check. This could lead
                         to local escalation of privilege with User execution...

 9.8   CVE-2025-20672    In Bluetooth driver, there is a possible out of bounds
                         write due to an incorrect bounds check. This could lead
                         to local escalation of privilege with User execution...
────────────────────────────────────────────────────────────────────────────────
Found: 5 CVEs
```

---

## Key Features

- **SearchSploit-Style Terminal UX**: Clean, structured 3-column table (`CVSS | CVE | Description`) with multi-line indented descriptions and CVSS severity color-coding.
- **Bidirectional Smart Scanning**:
  - Automatically queries the NVD tail end for recent years (e.g. 2026, 2025) and `--last N`.
  - Performs intelligent early termination (early break) as soon as year or date boundaries are crossed, saving network requests.
- **Combined Multi-Option Filtering**: Supports using any combination of flags together (e.g. `--last 5 --year 2025 --sort cvss`).
- **Flexible Sorting Options (`--sort`)**:
  - `--sort date` (Default): Publication date descending (newest first).
  - `--sort id`: Numerical CVE ID descending (`CVE-2026-XXXXX` > `CVE-2025-XXXXX`).
  - `--sort cvss`: Severity score descending (Critical 9.8 first).
- **Auto-Save Protection (> 50 CVEs)**: When search results exceed 50 CVEs, SearchCVE alerts the user and automatically saves the full, uncolored report to disk (e.g. `searchcve_bluetooth_2026.txt`).
- **Smart Fallback Queries**: Automatically handles multi-term version queries (e.g. `"bluetooth 3.1"` or `"android 14 bluetooth"`).
- **Direct CVE Lookup**: Fast instant retrieval for exact CVE identifiers (`CVE-YYYY-NNNNN`).
- **Scripting & Automation Ready**:
  - `--json`: Pure machine-readable JSON for `jq` or data pipelines.
  - `--quiet`: Outputs only matching CVE IDs, one per line, for Unix pipes (`xargs`, `while read`).
- **Zero Runtime Dependencies**: Built entirely using Python's standard library (`urllib`, `json`, `dataclasses`, `textwrap`).

---

## Installation

### Method 1: Direct from GitHub via pip (Recommended)

```bash
pip install git+https://github.com/Prekarshamaxx123/searchcve.git
```

### Method 2: Clone and Install Locally

```bash
git clone https://github.com/Prekarshamaxx123/searchcve.git
cd searchcve
pip install .
```

### Method 3: Development Mode

```bash
git clone https://github.com/Prekarshamaxx123/searchcve.git
cd searchcve
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Command Reference

```text
Usage:
  searchcve <keyword> [options]

Options:
  --last N              Show newest N matching CVEs
  --limit N             Limit number of results
  --year YEAR           Filter by publication year (e.g., 2025, 2026)
  --from DATE           Start date YYYY-MM-DD
  --to DATE             End date YYYY-MM-DD
  --sort {date,id,cvss} Sort results by date, id, or cvss (default: date)
  --exact               Exact keyword matching (word boundaries)
  --json                Output JSON
  --quiet               Output CVE IDs only
  --version             Show version
  -h, --help            Show help
```

---

## Usage Examples

### 1. Basic Keyword Search
```bash
searchcve openclaw
```

### 2. Year Filtering
```bash
searchcve bluetooth --year 2026
```

### 3. Retrieve Newest N Results (`--last N`)
```bash
searchcve apache --last 10
```

### 4. Combining Multiple Options
Combine `--last`, `--year`, and custom sorting at once:
```bash
searchcve bluetooth --last 5 --year 2025 --sort cvss
```

### 5. Sorting by Numerical CVE ID
```bash
searchcve bluetooth --last 5 --year 2025 --sort id
```

### 6. Date Range Filtering
```bash
searchcve openssh --from 2025-01-01 --to 2025-12-31 --last 5
```

### 7. Version & Multi-Word Queries
```bash
searchcve "bluetooth 3.1"
searchcve "android 14 bluetooth" --last 5
```

### 8. Exact Word-Boundary Match
```bash
searchcve cat --exact
```

### 9. Direct Specific CVE Lookup
```bash
searchcve CVE-2021-44228
```

### 10. Automation with JSON or Quiet Mode
```bash
# JSON output piped to jq
searchcve log4j --json | jq .

# Quiet mode (CVE IDs only) piped to loop
searchcve wordpress --last 5 --quiet | while read -r cve; do
    echo "Inspecting $cve..."
done
```

---

## Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NVD_API_KEY` | `None` | Official NIST NVD API key (increases request allowance 10x). |
| `SEARCHCVE_TIMEOUT` | `15.0` | HTTP network connection timeout in seconds. |
| `SEARCHCVE_MAX_RESULTS` | `1000` | Safety cap on maximum candidate CVEs retrieved in a single run. |
| `NO_COLOR` | `None` | Set to any non-empty value to disable ANSI terminal colors. |

### Optional: Setting up an NVD API Key

By default, NVD API allows up to 5 requests per 30-second rolling window without an API key. With a free API key from NIST, the allowance increases to 50 requests per 30 seconds.

Request a free key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and add it to your profile:

```bash
export NVD_API_KEY="your-api-key-here"
```

---

## Running Unit Tests

SearchCVE includes an extensive test suite verifying keyword matching, bidirectional scanning, flag combinations, rate-limit backoff, and formatting:

```bash
python3 -m pytest -v
```

---

## Author & Contact

- **Author**: Prekarshamaxx123
- **GitHub**: [https://github.com/Prekarshamaxx123](https://github.com/Prekarshamaxx123)
- **Repository**: [https://github.com/Prekarshamaxx123/searchcve](https://github.com/Prekarshamaxx123/searchcve)

---

## Security & Copyright Notice

**Copyright (c) 2026 Prekarshamaxx123. All Rights Reserved.**

This software and associated source files are proprietary and confidential.

- **Strictly Prohibited:** Unauthorized copying, cloning for public redistribution, mirroring, commercial resale, sublicensing, or creation of derivative works without prior express written permission from **Prekarshamaxx123** is strictly prohibited.
- **Legal Enforcement:** Any unauthorized duplication or infringement will be subject to legal claims under applicable international copyright laws.

See [LICENSE](LICENSE) for full legal terms.
