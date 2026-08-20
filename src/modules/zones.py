from typing import Any
from mcp.types import ToolAnnotations
from pydantic import Field
from mcp.server.fastmcp import FastMCP

from src.client import CTDClient
from src.modules.base import BaseModule

class ZonesModule(BaseModule):
    """
    Zones module for Claroty CTD MCP Server.

    This module provides tools for analyzing Virtual Zones, zone grouping
    methods and configurations, zone assets and vulnerabilities, 
    and zone communications.
    """

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(server=server,
            method=self.get_all_zones_info, 
            name="get_all_zones_info",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False
            )
        )

        self._add_tool(server=server,
            method=self.get_zone_details_by_id, 
            name="get_zone_details_by_id",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False
            )
        )

        self._add_tool(server=server,
            method=self.get_assets_per_zone, 
            name="get_assets_per_zone",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False
            )
        )

        self._add_tool(server=server,
            method=self.get_vulnerabilities_per_zone,
            name="get_vulnerabilites_per_zone",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False
            )
        )

        self._add_tool(server=server,
            method=self.get_zone_communications, 
            name="get_zone_communications",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False
            )
        )

    def register_resources(self, server: FastMCP) -> None:
        super().register_resources(server)

    def get_all_zones_info(
        self,
        sort_by: str = Field(
            default="-risk_level",
            description="Field to sort the results by. Prefix with '-' for descending order.",
            json_schema_extra={
                "enum": ["risk_level", "-risk_level", "num_assets", "-num_assets", "name", "-name"]
            }
        ),
        limit: int | None = Field(
            default=100,
            ge=1,
            le=500,
            description="Maximum number of zones to fetch per page. Defaults to 100 to conserve context window.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if the response indicates more pages are available.",
        ),
    ) -> str:
        """Fetch a list of all virtual zones and the active zone grouping algorithm.
        
        Returns the overarching grouping method (e.g., Default, Subnet, VLAN) along with 
        a paginated list of zones including their resource-ID, risk level, criticality, asset counts, 
        and associated Purdue levels.
        """
        try:
            # 1. Fetch the Grouping Algorithm (Micro-request)
            alg_params = {"site_id": "1"}
            alg_data = self.client.request("GET", "/ranger/virtual_zones_grouping_algorithm", params=alg_params)
            
            grouping_alg = "Unknown"
            if isinstance(alg_data, dict):
                grouping_alg = str(alg_data.get("method", "Unknown")).title()

            # 2. Fetch the Virtual Zones
            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 100

            fields_list = [
                "name", 
                "num_assets", 
                "risk_level", 
                "criticality", 
                "resource_id", 
                "asset_purdue_levels"
            ]

            zone_params = {
                'site_id__exact': '1',
                'sort': sort_by,
                'fields': ",;$".join(fields_list),
                'page': str(current_page),
                'per_page': str(per_page)
            }

            response_data = self.client.request("GET", "/ranger/virtual_zones", params=zone_params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                return f"**Grouping Algorithm:** {grouping_alg}\n\nNo virtual zones found on page {current_page}."

            risk_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
            crit_map = {0: "Low", 1: "Medium", 2: "High"}
            
            processed_zones = []
            
            for item in objects:
                raw_risk = item.get("risk_level")
                risk_str = f"{risk_map.get(raw_risk, 'Unknown')} ({raw_risk})" if isinstance(raw_risk, int) else str(raw_risk)
                
                raw_crit = item.get("criticality")
                crit_str = f"{crit_map.get(raw_crit, 'Unknown')} ({raw_crit})" if isinstance(raw_crit, int) else str(raw_crit)
                
                purdue_raw = item.get("asset_purdue_levels", [])
                if isinstance(purdue_raw, list):
                    purdue_str = ", ".join(str(p) for p in purdue_raw) if purdue_raw else "None"
                else:
                    purdue_str = str(purdue_raw)
                
                processed_zones.append({
                    "Name": item.get("name", "Unknown"),
                    "Resource ID": item.get("resource_id", "Unknown"),
                    "Assets": item.get("num_assets", 0),
                    "Risk Level": risk_str,
                    "Criticality": crit_str,
                    "Purdue Levels": purdue_str
                })

            md_output = self._format_to_markdown(processed_zones)

            metadata_header = [
                f"### Virtual Zones Overview",
                f"- **Grouping Algorithm:** {grouping_alg}",
                f"- **Page {current_page} Results:** Displaying {len(objects)} zones (Total available: {total_records})"
            ]

            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"\n> **NOTICE:** More zones are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page}."
                )

            return "\n".join(metadata_header) + "\n\n" + md_output

        except Exception as e:
            return f"Error fetching zones info: {str(e)}"

    def get_zone_details_by_id(
        self,
        resource_id: str | int = Field(
            description=(
                "The ID or resource ID of the target virtual zone (e.g., '89' or '89-1'). "
                "If only a zone name is provided, call 'get_all_zones_info' first to find the matching ID."
            ),
            examples=["179-1", "402", 79]
        )
    ) -> str:
        """Fetch comprehensive configuration and operational details for a specific Virtual Zone.
        
        Returns metadata including subnets, protocols, vendors, asset counts, risk score, risk vector
        and Purdue levels for the specified zone resource ID.
        """
        try:
            clean_id = str(resource_id).strip()
            if not clean_id:
                return "Error: Invalid zone identifier provided."
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            # 1. Fetch Main Zone Details
            data = self.client.request("GET", f"/ranger/virtual_zones/{clean_id}")

            if not isinstance(data, dict) or not data:
                return f"Error: No details found for zone resource ID '{clean_id}'."

            risk_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
            crit_map = {0: "Low", 1: "Medium", 2: "High"}

            raw_risk = data.get("risk_level")
            risk_str = risk_map.get(raw_risk, "Unknown")
            
            raw_score = data.get("risk_score", "N/A")
            combined_risk = f"{raw_score} ({risk_str})" if raw_score != "N/A" else risk_str

            raw_crit = data.get("criticality")
            crit_str = f"{crit_map.get(raw_crit, 'Unknown')} ({raw_crit})"

            details = {
                "Zone Name": data.get("name", "Unknown"),
                "Resource ID": data.get("resource_id", clean_id),
                "Risk Score": combined_risk,
                "Criticality": crit_str,
                "Total Assets": data.get("num_assets", 0),
                "Assets Active Last 24h": data.get("num_assets_last_day", 0),
                "Purdue Levels": ", ".join(str(v) for v in data.get("asset_purdue_levels") or []) or "None",
                "Class Types": ", ".join(str(v) for v in data.get("class_types") or []) or "None",
                "Networks": ", ".join(str(v) for v in data.get("networks") or []) or "None",
                "Subnets": ", ".join(str(v) for v in data.get("subnets") or []) or "None",
                "Vendors": ", ".join(str(v) for v in data.get("vendors") or []) or "None",
                "Protocols": ", ".join(str(v) for v in data.get("protocols") or []) or "None",
                "First Seen": data.get("first_seen", "N/A"),
                "Last Seen": data.get("last_seen", "N/A"),
            }

            formatted_output = self._format_to_markdown(details)
            
            # 2. Fetch Risk Vectors Breakdown
            risk_data = self.client.request("GET", f"/ranger/lazy_loaded/{clean_id}/virtual_zone/risk_vectors")
            
            risk_dict = {}
            
            if isinstance(risk_data, list) and risk_data:
                for rv in risk_data:
                    name = rv.get("name", "Unknown")
                    score = rv.get("score", "N/A")
                    rv_details = rv.get("details", [])
                    key = f"{name} (Score: {score})"
                    
                    if rv_details:
                        descriptions = [str(detail.get("description", "")).strip().rstrip(".") for detail in rv_details if detail.get("description")]
                        risk_dict[key] = ". ".join(descriptions)
                    else:
                        risk_dict[key] = "No additional details provided"
            
            if risk_dict:
                risk_formatted_output = f"### Risk Vectors Breakdown\n{self._format_to_markdown(risk_dict)}"
            else:
                risk_formatted_output = "### Risk Vectors Breakdown\nNo detailed risk vector data available."

            return f"### Virtual Zone Details: {details['Zone Name']}\n{formatted_output}\n{risk_formatted_output}"

        except Exception as e:
            return f"Error fetching details for zone '{resource_id}': {str(e)}"

    def get_assets_per_zone(
        self,
        resource_id: str | int = Field(
            description=(
                "The ID or resource ID of the target virtual zone (e.g., '89' or '89-1'). "
                "If only a zone name is provided, call 'get_all_zones_info' first to find the matching ID."
            ),
            examples=["179-1", "402", 79]
        ),
        limit: int | None = Field(
            default=100,
            ge=1,
            le=500,
            description="Maximum number of assets to fetch per page. Defaults to 100 to conserve context window.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if more pages are available.",
        ),
    ) -> str:
        """Fetch a list of all assets residing within a specific Virtual Zone, given a Zone resource ID.
        
        Returns asset details including Name, IP address, MAC, Vendor, Asset Type, and Risk Level.
        """
        try:
            clean_id = str(resource_id).strip()
            if not clean_id:
                return "Error: Invalid zone identifier provided."
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 100

            # Request only the fields the LLM needs to save massive amounts of network bandwidth and memory
            fields_list = ["id", "name", "ipv4", "mac", "asset_type__", "vendor", "risk_level", "purdue_level"]

            params: dict[str, Any] = {
                'page': str(current_page),
                'per_page': str(per_page),
                'site_id__exact': 1,
                'virtual_zone_id__exact': clean_id,
                #'special_hint__exact': 0,
                #'ghost__exact': False,
                'sort': '-risk_level',
                'fields': ",;$".join(fields_list),
            }

            response_data = self.client.request("GET", "/ranger/assets", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                return f"No assets found in zone ID '{clean_id}' on page {current_page}."

            risk_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
            processed_assets = []

            for item in objects:
                raw_ips = item.get("ipv4", [])
                ip_str = ", ".join(str(ip) for ip in raw_ips) if isinstance(raw_ips, list) else str(raw_ips or "None")
                
                raw_type = str(item.get("asset_type__", "Unknown"))
                clean_type = raw_type[1:] if raw_type.startswith('e') and len(raw_type) > 1 else raw_type

                raw_risk = item.get("risk_level")
                risk_str = f"{risk_map.get(raw_risk, 'Unknown')} ({raw_risk})" if isinstance(raw_risk, int) else str(raw_risk)

                processed_assets.append({
                    "Asset Name": item.get("name", "Unknown"),
                    "Asset ID": item.get("id", "N/A"),
                    "IP Address": ip_str,
                    "Type": clean_type,
                    "Vendor": item.get("vendor", "Unknown"),
                    "Risk": risk_str,
                    "Purdue": item.get("purdue_level", "None")
                })

            md_output = self._format_to_markdown(processed_assets)

            metadata_header = [
                f"### Assets in Zone {clean_id}",
                f"- **Page {current_page} Results:** Displaying {len(objects)} assets (Total available: {total_records})"
            ]

            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"\n> **NOTICE:** More assets are available in this zone. Call this tool again with `page={current_page + 1}` to fetch the next {per_page}."
                )

            return "\n".join(metadata_header) + "\n\n" + md_output

        except Exception as e:
            return f"Error fetching assets for zone '{clean_id}': {str(e)}"

    def get_vulnerabilities_per_zone(
        self,
        resource_id: str | int = Field(
            description=(
                "The ID or resource ID of the target virtual zone (e.g., '89' or '89-1'). "
                "If only a zone name is provided, call 'get_all_zones_info' first to find the matching ID."
            ),
            examples=["179-1", "402", 79]
        ),
        limit: int | None = Field(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of vulnerabilities to fetch per page. Defaults to 50.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if more pages are available.",
        ),
    ) -> str:
        """Fetch all vulnerabilities residing within a specific Virtual Zone.
        
        Returns a table of CVEs including their CVSS v3/v2 scores, EPSS scores, risk levels, 
        relevance status, active exploitation status, and vulnerability type.
        """
        try:
            # 1. Bulletproof Identifier Validation & Construction
            clean_id = str(resource_id).strip()
            
            if not clean_id:
                return "Error: Invalid zone identifier provided."
                
            # Safely append '-1' ONLY if it's a pure number
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 50

            # Request only the necessary fields to optimize bandwidth and memory
            fields_list = [
                "cve_id", 
                "cvss_v3_score", 
                "cvss_v2_score", 
                "epss_score", 
                "risk_level", 
                "relevance__", 
                "actively_exploited",
                "vulnerability_type"
            ]

            params: dict[str, Any] = {
                'site_id__exact': 1,
                'virtual_zone__exact': clean_id,
                'ghost__exact': 'false',
                'special_hint__exact': '0',
                'sort': '-cvss_v3_score',
                'fields': ",;$".join(fields_list),
                'page': str(current_page),
                'per_page': str(per_page)
            }

            # 2. Execute API Request
            response_data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                return f"No vulnerabilities found in zone ID '{clean_id}' on page {current_page}."

            processed_vulns = []
            risk_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}

            # 3. Parse and Map Data for the Table
            for item in objects:
                # Handle CVSS logic (prefer v3, fallback to v2)
                cvss_v3 = item.get("cvss_v3_score")
                cvss_v2 = item.get("cvss_v2_score")
                
                if isinstance(cvss_v3, dict) and cvss_v3.get("value") is not None:
                    cvss_score = f"{cvss_v3.get('value')} (v3)"
                elif isinstance(cvss_v2, dict) and cvss_v2.get("value") is not None:
                    cvss_score = f"{cvss_v2.get('value')} (v2)"
                else:
                    cvss_score = "N/A"

                # Handle EPSS Score
                epss_data = item.get("epss_score")
                epss_score = str(epss_data.get("value")) if isinstance(epss_data, dict) and epss_data.get("value") is not None else "N/A"

                # Map Risk Level
                raw_risk = item.get("risk_level")
                risk_str = f"{risk_map.get(raw_risk, 'Unknown')} ({raw_risk})" if isinstance(raw_risk, int) else str(raw_risk)

                # Clean up Relevance string (e.g., "eConfirmed" -> "Confirmed")
                raw_rel = str(item.get("relevance__", "Unknown"))
                clean_rel = raw_rel[1:] if raw_rel.startswith('e') and len(raw_rel) > 1 else raw_rel

                # Format Active Exploitation
                is_exploited = "Yes" if item.get("actively_exploited") else "No"

                processed_vulns.append({
                    "CVE ID": item.get("cve_id", "Unknown"),
                    "CVSS": cvss_score,
                    "EPSS": epss_score,
                    "Risk": risk_str,
                    "Relevance": clean_rel,
                    "Exploited": is_exploited,
                    "Type": item.get("vulnerability_type", "Unknown")
                })

            # Automatically generate a highly token-efficient Markdown table
            md_output = self._format_to_markdown(processed_vulns)

            # 4. Metadata header with Pagination Intelligence
            metadata_header = [
                f"### Vulnerabilities in Zone {clean_id}",
                f"- **Page {current_page} Results:** Displaying {len(objects)} vulnerabilities (Total available: {total_records})"
            ]

            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"\n> **NOTICE:** More vulnerabilities are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page} records."
                )

            return "\n".join(metadata_header) + "\n\n" + md_output

        except Exception as e:
            return f"Error fetching vulnerabilities for zone '{resource_id}': {str(e)}"

    def get_zone_communications(
        self,
        resource_id: str | int = Field(
            description=(
                "The ID or resource ID of the target virtual zone (e.g., '89' or '89-1'). "
                "If only a zone name is provided, call 'get_all_zones_info' first to find the matching ID."
            ),
            examples=["89-1", "100", 90]
        ),
        limit: int | None = Field(
            default=25,
            ge=1,
            le=500,
            description="Maximum number of policy rules to fetch per page. Defaults to 25.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if more pages are available.",
        ),
    ) -> str:
        """Fetch network policy rules and communications involving a specific virtual zone.
        
        Returns a table detailing source/destination zones, protocols, ports, actions, hit counts, and approval status.
        """
        try:
            # 1. Bulletproof Identifier Validation & Construction
            clean_id = str(resource_id).strip()
            
            if not clean_id:
                return "Error: Invalid zone identifier provided."
                
            # Safely append '-1' ONLY if it's a pure number
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 25

            params: dict[str, Any] = {
                'site_id__exact': 1,
                'source_or_dest_virtual_zone_id__exact': clean_id,
                'sort': '-id',
                'page': str(current_page),
                'per_page': str(per_page)
            }

            response_data = self.client.request("GET", "/ranger/policy_rule", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                return f"No communications found for zone ID '{clean_id}' on page {current_page}."

            processed_rules = []
            
            # Map integers to the display strings shown in the UI
            action_map = {0: "Allow", 1: "Block"}
            cat_map = {11: "Network"}
            access_map = {0: "None"}

            for item in objects:
                # Extract Zone Information
                vz_info = item.get("virtual_zones", {})
                
                src_zone = vz_info.get("source_virtual_zone", {})
                src_display = f"{src_zone.get('name', 'Unknown')} ({src_zone.get('num_assets', 0)})"
                
                dst_zone = vz_info.get("destination_virtual_zone", {})
                dst_display = f"{dst_zone.get('name', 'Unknown')} ({dst_zone.get('num_assets', 0)})"
                
                # Protocol and combined Ports/Port Ranges
                protocols = ", ".join(str(p) for p in item.get("protocols") or []) or "None"
                
                # Combine distinct ports and port ranges into one readable string
                raw_ports = item.get("ports") or []
                raw_ranges = item.get("port_ranges") or []
                combined_ports = raw_ports + raw_ranges
                ports_str = ", ".join(str(p) for p in combined_ports) if combined_ports else "Any"
                
                raw_cats = item.get("categories", [])
                cat_str = ", ".join(cat_map.get(c, str(c)) for c in raw_cats) if raw_cats else "None"
                
                raw_access = item.get("categories_access", [])
                access_str = ", ".join(access_map.get(a, str(a)) for a in raw_access) if raw_access else "None"
                
                # Boolean processing
                exact_match = "Yes" if item.get("full_match") else "No"
                is_approved = "Yes" if item.get("approved_user_id") is not None else "No"
                is_active = "Yes" if item.get("active") else "No"
                
                raw_action = item.get("action", 0)
                action_str = action_map.get(raw_action, str(raw_action))

                # Construct the dictionary mirroring the UI table structure PLUS context fields
                processed_rules.append({
                    "ID": item.get("id", "N/A"),
                    "Status": "Active" if is_active == "Yes" else "Disabled", # Consolidating active state
                    "Action": action_str,
                    "Source Zone": src_display,
                    "Destination Zone": dst_display,
                    "Protocol": protocols,
                    "Port": ports_str,            # Now includes ranges
                    "Category": cat_str,
                    "Access": access_str,
                    "Exact Match": exact_match,
                    "Hit Count": item.get("hit_count", 0),
                    "Approved": is_approved,
                    "Description": item.get("description") or "None", # Excellent for LLM context
                    "Last Modified": item.get("last_modified", "N/A") # Excellent for timelines
                })

            # Automatically generate a highly token-efficient Markdown table
            md_output = self._format_to_markdown(processed_rules)

            # Metadata header with Pagination Intelligence
            metadata_header = [
                f"### Zone Communications (ID: {clean_id})",
                f"- **Page {current_page} Results:** Displaying {len(objects)} rules (Total available: {total_records})"
            ]

            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"\n> **NOTICE:** More rules are available for this zone. Call this tool again with `page={current_page + 1}` to fetch the next {per_page}."
                )

            return "\n".join(metadata_header) + "\n\n" + md_output

        except Exception as e:
            return f"Error fetching communications for zone '{resource_id}': {str(e)}"