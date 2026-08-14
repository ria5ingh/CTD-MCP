# src/resources/baselines.py

BASELINES_SCHEMA_URI = "resource://ctd/baselines-schema"

BASELINES_SCHEMA_DOCS = """# CTD Baselines Search Schema and Guide

A **Baseline** is a collection of valid network behaviors learned during Training Mode. An individual baseline represents a specific instance of communication between two assets. A baseline deviation occurs when new communication happens that hasn't been defined yet. Once in Operational Mode, baselines might be modified by auto-generated Zones and user-approved Alerts.

## 1. Allowed Search Filters
Use these keys in the `filters` dictionary parameter. Match the data types exactly.
For filters marked with **Enums**, pass a single value or an array of multiple values for an "OR" search (e.g., `"category__exact": [2, 5]`).

*(Note: Filters with NO tool label can be used across ALL baseline tools. Tool-specific filters are explicitly marked in bold and will fail if used on the wrong tool).*

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `category_access__exact` | Integer | Access level type. **Enums:** `0` (None), `1` (Read), `2` (Write), `3` (Execute), `4` (Publish). | `1` |
| `category__exact` | Integer | Baseline category type. **Enums:** *(See Section 2)*. | `2` |
| `protocol__exact` | String | Exact protocol name, CAPITALIZED. | `"CIP"` |
| `source_virtual_zone__exact` | String | Exact Source Virtual Zone Resource ID. | `"79-1"` |
| `destination_virtual_zone__exact` | String | Exact Destination Virtual Zone Resource ID. | `"82-1"` |
| `description__icontains` | String | **(`search_specific_baselines` ONLY)** Partial/full match of the baseline description/name. | `"Read HR Tag"` |
| `source__exact` | String | **(`search_specific_baselines` ONLY)** Exact Source IPv4 or IPv6 address. | `"10.1.20.5"` |
| `destination__exact` | String | **(`search_specific_baselines` ONLY)** Exact Destination IPv4 or IPv6 address. | `"10.1.20.10"` |

---

## 2. Baseline Category Enums (`category__exact`)
When filtering by category, use the corresponding Integer value. *(Note: Category 11 / Network is ignored by default to reduce broadcast/multicast noise).*

| ID | Category Name | ID | Category Name |
| :--- | :--- | :--- | :--- |
| `1` | Other | `2` | Data Acquisition |
| `3` | Protocol | `4` | Firmware |
| `5` | Operation | `6` | Programming |
| `7` | Alarm | `8` | Diagnosis |
| `9` | Auth | `10` | Remote Conn |
| `12` | Filesystem | | |
"""