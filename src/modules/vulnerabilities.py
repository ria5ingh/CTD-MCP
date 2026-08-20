import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.vulnerabilities import VULNERABILITIES_SCHEMA_URI, VULNERABILITIES_SCHEMA_DOCS


class VulnerabilitiesModule(BaseModule):
    """
    Vulnerabilities module for Claroty CTD MCP Server.

    This module provides tools for querying and analyzing network vulnerabilities (CVEs), 
    including searching confirmed vulnerabilities, mapping affected assets to CVEs 
    (and vice-versa), and extracting in-depth metadata and metrics for specific CVEs.
    """

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(
                server=server, 
                method=self.get_vulnerabilities_schema, 
                name="get_vulnerabilities_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )   

        self._add_tool(
                server=server, 
                method=self.search_vulnerabilities, 
                name="search_vulnerabilities",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        self._add_tool(
                server=server, 
                method=self.list_assets_per_vulnerabilities, 
                name="list_assets_per_vulnerabilities",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        self._add_tool(
                server=server, 
                method=self.list_vulnerabilities_per_assets, 
                name="list_vulnerabilities_per_assets",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        self._add_tool(
                server=server, 
                method=self.get_vulnerability_details, 
                name="get_vulnerability_details",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )


    def register_resources(self, server: FastMCP) -> None:
        """Register the Vulnerabilities schema resources with the MCP Server."""
        super().register_resources(server)
        
        resource = TextResource(
            uri=AnyUrl(VULNERABILITIES_SCHEMA_URI),
            name="ctd_vulnerabilities_schema",
            description="Contains the allowed filters and enums for the `search_vulnerabilities` and `get_vulnerability_details` tool.",
            text=VULNERABILITIES_SCHEMA_DOCS, 
            mime_type="text/markdown"
        )
        
        self._add_resource(server, resource)

        
    #TOOL FOR VULN SCHEMA
    def get_vulnerabilities_schema(self) -> str:
        """Retrieves the complete Claroty CTD Vulnerabilities Search Schema and Filter Keys.
        
        Call this tool BEFORE executing search_vulnerabilities to look up 
        allowed filter keys, required data types, or integer enum mappings.
        """
        return VULNERABILITIES_SCHEMA_DOCS
    
    def search_vulnerabilities(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for valid filter keys and enum mappings.",
            examples=[{"q__icontains": "use after free", "cvss_severity": ["high", "critical"]}],
        ),
        sort_by: str = Field(
            default="-cvss_v3_score",
            description="Field to sort the results by. Prefix with '-' for descending order.",
            json_schema_extra={
                "enum": [
                    "cvss_v3_score", "-cvss_v3_score",
                    "epss_score", "-epss_score",
                    "confirmed_assets_count", "-confirmed_assets_count"
                ]
            }
        ),
        limit: int | None = Field(
            default=500,
            ge=1,
            le=500,
            description="Maximum number of vulnerabilities to fetch per page (capped at 500). Defaults to 500.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if the response indicates more pages are available.",
        ),
    ) -> str:
        #"""Find CONFIRMED vulnerabilities (CVEs) based on keyword search, severity, exploitability, or other criteria."""
        """Find ALL (confirmed AND potentially relevant) vulnerabilities (CVEs) based on keyword search, severity, exploitability, or other criteria."""

        try:
            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 500

            # Base API parameters
            params: dict[str, Any] = {
                'site_id__exact': 1,
                'ghost__exact': False,
                'affected_assets__exact': 0, 
                'special_hint__exact': 0,    
                #'relevance__exact': 1,  #ONLY CONFIRMED
                'sort': sort_by,
                'page': current_page,
                'per_page': per_page
            }

            # Apply LLM filters with Bug Workaround
            if filters:
               self.cvss_grouping(filters)
               for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # Single API Request
            response_data = self.client.request("GET", "/ranger/vulnerabilities", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                return f"No vulnerabilities found matching the specified criteria on page {current_page}."

            # Format into a clean, vertical data table
            md_lines = []
            for item in objects:
                cve_id = item.get("cve_id", "N/A")
                res_id = item.get("resource_id", "N/A")

                assets_count = item.get("assets_count", {})
                if isinstance(assets_count, dict):
                    total_affected = assets_count.get("total_affected_assets_count", 0)
                    confirmed = assets_count.get("confirmed_assets_count", 0)
                    potential = assets_count.get("potentially_relevant_assets_count", 0)
                    affected_assets = f"{total_affected} (Confirmed: {confirmed}, Potential: {potential})"
                else:
                    affected_assets = "0"

                # Extract CVSS Score safely (prefer v3, fallback to v2)
                cvss_v3 = item.get("cvss_v3_score")
                cvss_v2 = item.get("cvss_v2_score")
                
                if isinstance(cvss_v3, dict) and cvss_v3.get("value"):
                    cvss_str = f"v3: {cvss_v3.get('value')} ({cvss_v3.get('label', 'N/A')})"
                elif isinstance(cvss_v2, dict) and cvss_v2.get("value"):
                    cvss_str = f"v2: {cvss_v2.get('value')} ({cvss_v2.get('label', 'N/A')})"
                elif isinstance(cvss_v3, (float, int)): 
                    cvss_str = f"v3: {cvss_v3}"
                else:
                    cvss_str = "N/A"

                md_lines.append(f"- **{cve_id}** (`{res_id}`): {cvss_str} | Assets: {affected_assets}")

            md_output = "\n".join(md_lines)

            # Metadata header with Pagination Intelligence
            metadata_header = [
                f"**Page {current_page} Results:** Displaying {len(objects)} records (Total available: {total_records})"
            ]

            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"**NOTICE:** More records are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page} records."
                )

            return "\n".join(metadata_header) + "\n\n" + md_output

        except Exception as e:
            return f"Error searching vulnerabilities: {str(e)}"
            
    def list_assets_per_vulnerabilities(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for allowed search filter and enums.",
            examples=[{"virtual_zone__exact": "106-1", "cvss_severity": ["high", "critical"]}],
        ),
        cve_id: str | None = Field(
            default=None,
            description="Optional CVE ID to list all assets for (e.g., 'CVE-2020-6088').",
            examples=["CVE-2026-215", "RA-66658"],
        ),
        limit: int | None = Field(
            default=500,
            ge=1,
            le=500,
            description="Maximum number of matches to fetch per page. Defaults to 500.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if the response indicates more pages are available.",
        ),
    ) -> str:
        """List all confirmed assets per vulnerabilities in the environment.
        
        Use this tool to view affected devices grouped by CVE, or to check 
        all CONFIRMED assets affected by aspecific CVE by passing `cve_id`. Call `get_vulnerabilities_schema`
        to view allowed filter keys and enum mappings before executing this tool.
        """
        try:
            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 500

            # 1. Base mandatory API parameters
            mandatory_fields = ['cve_id', 'asset_id', 'asset_name', 'risk_level']
            fields_param = ",;$".join(mandatory_fields)

            params: dict[str, Any] = {
                'site_id__exact': '1',
                'ghost__exact': 'false',
                'special_hint__exact': '0',   
                'relevance__exact': '1',      
                'sort': 'cve_id',             
                'fields': fields_param,
                'page': current_page,
                'per_page': per_page
            }

            if cve_id:
                params['cve_id__exact'] = cve_id.strip()

            # Apply additional LLM filters
            if filters:
                self.cvss_grouping(filters)
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # 2. Single API Request
            response_data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                msg = f"No assets found affected by '{cve_id}' on page {current_page}." if cve_id else f"No asset-vulnerability matches found for the specified criteria on page {current_page}."
                return msg

            # 3. Group records by CVE
            grouped_data: dict[str, list[str]] = {}
            for item in objects:
                c_id = item.get("cve_id", "Unknown CVE")
                asset_name = str(item.get("asset_name", "Unknown")).strip()
                a_id = item.get("asset_id", "N/A")
                risk = item.get("risk_level", "N/A")
                
                # ULTRA COMPRESSED FORMAT: Name [ID:X, R:Y]
                asset_str = f"{asset_name} [ID:{a_id}, R:{risk}]"
                
                if c_id not in grouped_data:
                    grouped_data[c_id] = []
                grouped_data[c_id].append(asset_str)

            # 4. Build Highly Compressed Output
            md_lines = []
            for c_id, assets in grouped_data.items():
                total_assets_in_page = len(assets)
                
                # Cap inline display at 25 assets per CVE to save context
                display_limit = 25
                display_assets = assets[:display_limit]
                
                assets_joined = ", ".join(display_assets)
                
                if total_assets_in_page > display_limit:
                    assets_joined += f" ... (+{total_assets_in_page - display_limit} more on this page)"
                
                md_lines.append(f"- **{c_id}** ({total_assets_in_page} assets: {assets_joined}")

            # 5. Assemble final output with Pagination Intelligence
            metadata_header = [
                f"**Page {current_page} Results:** Displaying {len(objects)} matches (Total available: {total_records})",
            ]
            
            # Check if there are more records beyond the current page scope
            if total_records > (current_page * per_page):
                metadata_header.append(
                    f" **NOTICE:** More matches are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page} records."
                )

            return "\n".join(metadata_header) + "\n\n" + "\n".join(md_lines)

        except Exception as e:
            return f"Error listing assets per CVE: {str(e)}"

    def list_vulnerabilities_per_assets(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for allowed search filters and enums.",
            examples=[{"virtual_zone__exact": "106-1", "cvss_severity": ["high", "critical"]}],
        ),
        asset_id: str | None = Field(
            default=None,
            description="Optional Asset ID to list all CVEs for (e.g., '11-1').",
            examples=["11-1", "24-2"],
        ),
        limit: int | None = Field(
            default=500,
            ge=1,
            le=500,
            description="Maximum number of matches to fetch per page. Defaults to 500.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch. Use this to paginate through results if the response indicates more pages are available.",
        ),
    ) -> str:
        """List all confirmed vulnerabilities per assets in the environment.
        
        Use this tool to view CVEs grouped by affected device, or when checking all CONFIRMED CVEs 
        for a specific asset by passing `asset_id`. Call `get_vulnerabilities_schema` to view
        allowed filter keys and enum mappings before executing this tool.
        """
        try:
            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 500

            # 1. Base mandatory API parameters
            mandatory_fields = ['cve_id', 'asset_id', 'asset_name', 'risk_level']
            fields_param = ",;$".join(mandatory_fields)

            params: dict[str, Any] = {
                'site_id__exact': '1',
                'ghost__exact': 'false',
                'special_hint__exact': '0',   
                'relevance__exact': '1',      
                'sort': 'asset_id',           # Group by Asset natively from the API
                'fields': fields_param,
                'page': current_page,
                'per_page': per_page
            }

            if asset_id:
                params['asset_id__exact'] = asset_id.strip()

            # Apply additional LLM filters
            if filters:
                self.cvss_grouping(filters)
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # 2. Single API Request
            response_data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

            if not objects:
                msg = f"No CVEs found for asset '{asset_id}' on page {current_page}." if asset_id else f"No asset-vulnerability matches found for the specified criteria on page {current_page}."
                return msg

            # 3. Group records by Asset
            grouped_data: dict[str, list[str]] = {}
            for item in objects:
                c_id = item.get("cve_id", "Unknown CVE")
                asset_name = str(item.get("asset_name", "Unknown")).strip()
                a_id = item.get("asset_id", "N/A")
                risk = item.get("risk_level", "N/A")
                
                # Create a unique key for the asset header
                asset_key = f"{asset_name} [ID:{a_id}, R:{risk}]"
                
                if asset_key not in grouped_data:
                    grouped_data[asset_key] = []
                grouped_data[asset_key].append(c_id)

            # 4. Build Highly Compressed Output
            md_lines = []
            for asset_key, cves in grouped_data.items():
                total_cves_in_page = len(cves)
                
                # Cap inline display at 25 CVEs per asset to save context
                display_limit = 25
                display_cves = cves[:display_limit]
                
                cves_joined = ", ".join(display_cves)
                
                if total_cves_in_page > display_limit:
                    cves_joined += f" ... (+{total_cves_in_page - display_limit} more on this page)"
                
                md_lines.append(f"- **{asset_key}** ({total_cves_in_page} CVEs): {cves_joined}")

            # 5. Assemble final output with Pagination Intelligence
            metadata_header = [
                f"**Page {current_page} Results:** Displaying {len(objects)} matches (Total available: {total_records})",
            ]
            
            # Check if there are more records beyond the current page scope
            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"**NOTICE:** There are more matches available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page} records."
                )

            return "\n".join(metadata_header) + "\n\n" + "\n".join(md_lines)

        except Exception as e:
            return f"Error listing CVEs per asset: {str(e)}"

    def get_vulnerability_details(
        self,
        cve_id: str = Field(
            description="The exact CVE ID to fetch details for (e.g., 'CVE-2020-6088').",
            examples=["CVE-2025-20352"]
        ),
        fields: list[str] | None = Field(
            default=None,
            description="Optional list of specific fields to return. Call `get_vulnerabilities_schema` to see allowed return fields. If omitted, returns a standard summary."
        )
    ) -> str:
        """Fetch the full description, severity scores, exploitability metrics, and asset counts for a specific CVE.
        
        Use this tool when you need to understand exactly what a vulnerability is, 
        how it works, and how it impacts the environment across asset types.
        """
        try:
            # We only need 1 object since we are querying a specific CVE ID
            params: dict[str, Any] = {
                'site_id__exact': 1,
                'ghost__exact': False,
                'affected_assets__exact': 0, # Only return if it affects assets in the environment
                'special_hint__exact': 0,
                'cve_id__exact': cve_id.strip(),
                'page': 1,
                'per_page': 1
            }

            response_data = self.client.request("GET", "/ranger/vulnerabilities", params=params)
            
            if not isinstance(response_data, dict):
                return "Invalid response format from the server."

            objects = response_data.get('objects', [])
            if not objects:
                return f"CVE '{cve_id}' not found in the environment."

            # Grab the specific CVE object
            vuln_data = objects[0]

            # Determine which fields to extract
            if fields:
                target_fields = fields
            else:
                # The ideal default summary if the LLM doesn't ask for specific fields
                target_fields = [
                    "cve_id", 
                    "description", 
                    "cvss_v3_score", 
                    "epss_score", 
                    "actively_exploited", 
                    "access_vector", 
                    "assets_count"
                ]

            # Filter the raw API object down to just the requested fields
            filtered_data = {}
            for field in target_fields:
                if field not in vuln_data:
                    continue
                    
                val = vuln_data[field]
                
                # Special handling for the assets_count dictionary
                if field == "assets_count" and isinstance(val, dict):
                    confirmed = val.get("confirmed_assets_count", 0)
                    potential = val.get("potentially_relevant_assets_count", 0)
                    it = val.get("affected_it_assets_count", 0)
                    iot = val.get("affected_iot_assets_count", 0)
                    ot = val.get("affected_ot_assets_count", 0)
                    
                    # Format into a clean, readable string
                    filtered_data["Impacted Assets"] = (
                        f"**{confirmed}** Confirmed, **{potential}** Potentially Relevant "
                        f"(Breakdown: {it} IT | {iot} IoT | {ot} OT)"
                    )
                
                # Clean up nested score dicts (like CVSS/EPSS)
                elif isinstance(val, dict) and "value" in val and "label" in val:
                    filtered_data[field] = f"{val['value']} ({val['label']})"
                
                # Handle all other standard fields
                else:
                    filtered_data[field] = val

            # Format the dictionary into a clean Markdown list using the base class helper
            md_output = f"### Details for {cve_id}\n\n"
            md_output += self._format_to_markdown(filtered_data)

            return md_output

        except Exception as e:
            return f"Error fetching vulnerability details: {str(e)}"

    def cvss_grouping(self, filters: dict) -> None:
        """Helper to translate categorical CVSS labels into numeric ranges"""
        if not filters or 'cvss_severity' not in filters:
            return
            
        val = filters.pop('cvss_severity')
        val_list = [str(v).lower() for v in val] if isinstance(val, list) else [str(val).lower()]        
        numeric_vals = []
        
        for v in val_list:
            if v == 'critical':
                numeric_vals.extend([f"{i/10:.1f}" for i in range(90, 101)])
            elif v == 'high':
                numeric_vals.extend([f"{i/10:.1f}" for i in range(70, 90)])
            elif v == 'medium':
                numeric_vals.extend([f"{i/10:.1f}" for i in range(40, 70)])
            elif v == 'low':
                numeric_vals.extend([f"{i/10:.1f}" for i in range(1, 40)])
                
        if numeric_vals:
            filters['numeric_cvss_v3_score__exact'] = ",;$".join(numeric_vals)
        