# src/resources/vulnerabilities.py

VULNERABILITIES_SCHEMA_URI = "resource://ctd/vulnerabilities-schema"
    
VULNERABILITIES_SCHEMA_DOCS = """# CTD Vulnerabilities Search Schema and Guide

This document provides the allowed search filters and return fields for the `search_vulnerabilities` tool.

## 1. Default Parameters
Unless explicitly overridden by the user, the `search_vulnerabilities` tool automatically applies:
* `site_id__exact`: `1`
* `ghost__exact`: `false`
* `affected_assets__exact`: `0` (Only returns CVEs matched to assets in your environment)
* `special_hint__exact`: `0` (Unicast)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary.

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `actively_exploited__exact` | Boolean | Exploited in the wild flag. | `true` |
| `class_type__exact` | Integer | Asset class. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |
| `relevance__exact` | Integer | Pairing accuracy. **Enums:** `0` (Potentially Relevant), `1` (Confirmed). | `1` |
| `status__exact` | Integer | Vulnerability status. **Enums:** `0` (Open), `1` (Fixed), `2` (Irrelevant), `3` (Accept), `4` (Manually Fixed). | `0` |
| `epss_score__exact` | String | EPSS score category. **Enums:** `"low"`, `"medium"`, `"high"`, `"critical"`. | `"high"` |
| `cvss_v3_score__exact`| String | CVSS v3 score category. **Enums:** `"low"`, `"medium"`, `"high"`, `"critical"`. | `"critical"` |
| `vulnerability_type__exact` | Integer | Type ID. **Enums:** `0` (Clinical), `1` (IoT), `2` (Platform), `3` (Application), `4` (OT). | `2` |
| `q__icontains` | String | Open text search. Matches against vulnerability names, descriptions, or general text (e.g., "use after free", "buffer overflow"). | `"use after free"` |


---

## 3. Allowed Return Fields
Pass these exact strings in the `fields` array parameter to specify what columns to return in the response:

* `resource_id` — Primary identifier (Required to call `get_vulnerability_details`)
* `cve_id` — Standard CVE identifier string
* `cve_link` — URL to NVD entry
* `cvss_v3_score` — CVSS v3 score object (value and severity label)
* `cvss_v2_score` — CVSS v2 score object
* `epss_score` — EPSS score object (value and probability label)
* `actively_exploited` — Boolean flag indicating known threat activity
* `vulnerability_type` — Integer classification enum
* `access_vector` — Exploitation path required (e.g., "Network", "Local")
* `release_date` — Date published to NVD
* `last_modified` — Date updated in NVD
* `advisory_names` — List of vendor advisory IDs
* `assets_count` — Counts of affected assets by category

*(Note: The 'description' field is omitted by default to preserve LLM token context. Use `get_vulnerability_details` to read full descriptions).*
"""