VULNERABILITIES_SCHEMA_URI = "resource://ctd/vulnerabilities-schema"
    
VULNERABILITIES_SCHEMA_DOCS = """# CTD Vulnerabilities Search Schema and Guide

This document provides the allowed search filters, default parameters, and return fields for the tools in the Vulnerabilities module.

## 1. Tool-Specific Defaults & Behaviors

### A. `search_vulnerabilities`
**Purpose:** Lists standalone vulnerabilities (CVEs) present in the environment.
**Default Parameters Applied:**
* `site_id__exact`: `1`
* `ghost__exact`: `false`
* `affected_assets__exact`: `0` (Only returns CVEs matched to assets in your environment)
* `special_hint__exact`: `0` (Unicast)
* `relevance__exact`: `1` (Confirmed matches only)


### B. `list_assets_per_cve` & `list_cves_per_asset`
**Purpose:** Maps the specific relationships betwee n Assets and CVEs.
**Default Parameters Applied:**
* `site_id__exact`: `1`
* `ghost__exact`: `false`
* `special_hint__exact`: `0` (Unicast)
* `relevance__exact`: `1` (Confirmed matches only)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary. 

*(Note: Filters with NO tool label can be used across ALL vulnerability tools. Tool-specific filters are explicitly marked in bold and will fail if used on the wrong tool).*

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `actively_exploited__exact` | Boolean | Exploited in the wild flag. | `true` |
| `status__exact` | Integer | Vulnerability status. **Enums:** `0` (Open), `1` (Fixed), `2` (Irrelevant), `3` (Accept), `4` (Manually Fixed). | `0` |
| `epss_score__exact` | String | EPSS score category. **Enums:** `"low"`, `"medium"`, `"high"`, `"critical"`. | `"high"` |
| `cvss_v3_score__exact`| String | CVSS v3 score category. **Enums:** `"low"`, `"medium"`, `"high"`, `"critical"`. | `"critical"` |
| `cve_id__exact` | String | **(`list_assets_per_cve` & `list_cves_per_asset` ONLY)** Exact standard CVE identifier. | `"CVE-2020-6088"` |
| `asset_id__exact` | String | **(`list_assets_per_cve` & `list_cves_per_asset` ONLY)** Exact asset resource ID. | `"11-1"` |
| `virtual_zone__exact` | String | **(`list_assets_per_cve` & `list_cves_per_asset` ONLY)** Exact virtual zone resource ID. | `"23-1"` |
| `match_type__exact` | Integer | **(`list_assets_per_cve` & `list_cves_per_asset` ONLY)** How the CVE was matched to the asset. **Enums:** `0` (Vendor), `1` (Program), `2` (WindowsKB), `3` (WindowsOS). | `0` |
| `q__icontains` | String | **(`search_vulnerabilities` ONLY)** Open text search. Matches against vulnerability names, descriptions, or general text. | `"use after free"` |
| `class_type__exact` | Integer | **(`search_vulnerabilities` ONLY)** Asset class. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |

---
"""

# ## 3. Allowed Return Fields (`search_vulnerabilities` ONLY)
# *(Note: `list_assets_per_cve` and `list_cves_per_asset` do NOT accept custom return fields. They automatically format their output into a fixed Markdown table to map the relationship.)*

# When using `search_vulnerabilities`, you may pass these exact strings in the `fields` array parameter to specify what columns to return:

# * `resource_id` — Primary identifier (Required to call `get_vulnerability_details`)
# * `cve_id` — Standard CVE identifier string
# * `cve_link` — URL to NVD entry
# * `cvss_v3_score` — CVSS v3 score object (value and severity label)
# * `cvss_v2_score` — CVSS v2 score object
# * `epss_score` — EPSS score object (value and probability label)
# * `actively_exploited` — Boolean flag indicating known threat activity
# * `access_vector` — Exploitation path required (e.g., "Network", "Local")
# * `release_date` — Date published to NVD
# * `last_modified` — Date updated in NVD
# * `advisory_names` — List of vendor advisory IDs
# * `assets_count` — Counts of affected assets by category

# *(Note: The 'description' field is omitted by default to preserve LLM token context. Use `get_vulnerability_details` to read full descriptions).*
# """