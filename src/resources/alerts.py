ALERTS_SCHEMA_URI = "resource://ctd/alerts-schema"

ALERTS_SCHEMA_DOCS = """# CTD Alerts Search Schema and Guide

This document provides the allowed search filters and enum mappings for tools in the Alerts module.

## 1. Allowed Search Filters
Use these keys in the `filters` dictionary. Match the data types exactly.
For any filter marked with **Enums**, pass a single value or an array of multiple values to perform an "OR" search (e.g., `"severity__exact": [2, 3]`).

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `category__exact` | Integer | Alert category. **Enums:** `0` (Integrity), `1` (Security). | `1` |
| `severity__exact` | Integer | Alert severity level. **Enums:** `0` (Low), `1` (Medium), `2` (High), `3` (Critical). | `3` |
| `virtual_zone__exact` | Integer | Exact virtual zone ID. | `79` |
| `story_id__exact`| String | Exact story resource ID. | `"1-1"` |
| `id__exact` | String | Exact alert resource ID. *Note: You can pass multiple IDs in a list to fetch specific alerts.* | `"204-1"` |
| `type__exact` | Integer | Specific alert classification. **Enums:** *(See Section 3 for mappings)*. | `23` |

---

## 2. Alert Type Enums (`type__exact`)
When filtering by alert type, use the corresponding Integer value from this table:

| ID | Alert Type | ID | Alert Type |
| :--- | :--- | :--- | :--- |
| `2` | New Asset | `4` | Man-In-The-Middle |
| `5` | Asset Information Change | `13` | New Conflict Asset |
| `22` | Baseline Rule | `23` | Known Threat Alerts |
| `24` | Suspicious File Transfer | `25` | Policy Violation Alert |
| `26` | Policy Rule Match | `27` | Host Scan |
| `28` | Port Scan | `29` | Denial of Service |
| `1000` | Firmware Download | `1001` | Configuration Download |
| `1002` | Configuration Upload | `1003` | Online Edit |
| `1004` | Failed Login | `1005` | Memory Reset |
| `1007` | Mode Change | `1010` | Monitor/Debug Mode |
| `1011` | File System Change | `1012` | DCS Configuration Change |
| `1013` | Suspicious Activity | `1014` | Invalid Session |
| `1016` | Settings Change | | |
"""