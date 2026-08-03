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
    Unified interface for querying and analyzing vulnerabilities via Claroty CTD REST API endpoints.

    Provides mechanisms for bulk vulnerability discovery (`search_vulnerabilities`), asset-to-CVE 
    mapping (`search_asset_vulnerabilities`), and deep-dive metadata extraction (`get_vulnerability_details`).
    Use this module to perform threat intelligence lookups and identify exposed assets.
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
                method=self.list_assets_per_cves, 
                name="list_assets_per_cves",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        self._add_tool(
                server=server, 
                method=self.list_cves_per_assets, 
                name="list_cves_per_assets",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        # self._add_tool(
        #         server=server, 
        #         method=self.get_vulnerability_details, 
        #         name="get_vulnerability_details",
        #         annotations=ToolAnnotations(
        #             readOnlyHint=True,
        #             destructiveHint=False,
        #             idempotentHint=True,
        #             openWorldHint=False,
        #         )
        # )


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

    # def search_vulnerabilities(
    #     self,
    #     filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
    #         default=None,
    #         description="Dictionary of search filters. Call `get_vulnerabilities_schema` for valid filter keys and enum mappings.",
    #         examples=[{"q__icontains": "use after free", "cvss_v3_score__exact": ["high", "critical"]}],
    #     ),
    #     limit: int | None = Field(
    #         default=200,
    #         ge=1,
    #         le=200,
    #         description="Maximum number of vulnerabilities to return (capped at 200). Defaults to 200 to preserve context.",
    #     ),
    # ) -> str:
    #     """Find vulnerabilities (CVEs) based on keyword search, severity, exploitability, or other criteria.
        
    #     Use this tool to list threats present in the environment. Call `get_vulnerabilities_schema` 
    #     before constructing filter expressions.
    #     """
    #     try:
    #         effective_limit = min(limit, 200) if limit is not None else 200

    #         # Base API parameters
    #         params: dict[str, Any] = {
    #             'site_id__exact': 1,
    #             'ghost__exact': False,
    #             'affected_assets__exact': 0, # 0 = True in Claroty Enum
    #             'special_hint__exact': 0,    # 0 = Unicast
    #             'sort': '-cvss_v3_score'
    #         }

    #         # Apply LLM filters
    #         if filters:
    #             for key, value in filters.items():
    #                 if isinstance(value, list):
    #                     params[key] = ",;$".join(str(v).strip() for v in value)
    #                 else:
    #                     params[key] = value

    #         # Pagination fetching loop
    #         all_objects = []
    #         current_page = 1
    #         per_page = min(effective_limit, 100)
    #         params['per_page'] = per_page
    #         total_records = 0

    #         while True:
    #             params['page'] = current_page
    #             response_data = self.client.request("GET", "/ranger/vulnerabilities", params=params)
                
    #             if not isinstance(response_data, dict):
    #                 break

    #             if current_page == 1:
    #                 total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

    #             objects = response_data.get('objects', [])
    #             if not objects:
    #                 break
                    
    #             all_objects.extend(objects)

    #             if len(all_objects) >= effective_limit:
    #                 all_objects = all_objects[:effective_limit]
    #                 break
                
    #             if len(objects) < per_page:
    #                 break
                    
    #             current_page += 1

    #         if not all_objects:
    #             return "No vulnerabilities found matching the specified criteria."

    #         # Format fixed fields into compact strings
    #         compact_entries = []
    #         for item in all_objects:
    #             cve_id = item.get("cve_id", "N/A")
    #             res_id = item.get("resource_id", "N/A")
                
    #             # Extract total_affected_assets
    #             assets_count = item.get("assets_count", {})
    #             affected_assets = (
    #                 assets_count.get("total_affected_assets_count", 0) 
    #                 if isinstance(assets_count, dict) else 0
    #             )

    #             # Extract cvss_v3_score
    #             cvss = item.get("cvss_v3_score")
    #             if isinstance(cvss, dict):
    #                 val = cvss.get("value")
    #                 lbl = cvss.get("label")
    #                 cvss_str = f"{val} ({lbl})" if val and lbl else str(val or lbl or "N/A")
    #             else:
    #                 cvss_str = str(cvss) if cvss is not None else "N/A"

    #             compact_entries.append(
    #                 f"**{cve_id}** [ID: `{res_id}` | CVSS: {cvss_str} | Assets: {affected_assets}]"
    #             )

    #         # Pack multiple CVE entries per row (3 entries per row)
    #         items_per_row = 3
    #         table_rows = []
    #         for i in range(0, len(compact_entries), items_per_row):
    #             chunk = compact_entries[i:i + items_per_row]
    #             # Pad empty cells if the final row has fewer than 3 items
    #             while len(chunk) < items_per_row:
    #                 chunk.append("")
    #             table_rows.append({"Vulnerabilities (Col 1)": chunk[0], "Vulnerabilities (Col 2)": chunk[1], "Vulnerabilities (Col 3)": chunk[2]})

    #         md_table = self._format_to_markdown(table_rows)

    #         metadata_header = [
    #             f"**Total Records Found:** {total_records}",
    #             f"**Returned Records:** {len(compact_entries)}"
    #         ]

    #         if total_records > len(compact_entries):
    #             metadata_header.append(
    #                 "⚠️ **Truncation Notice:** Results capped at 200 entries to preserve context window."
    #             )

    #         return "\n".join(metadata_header) + "\n\n" + md_table

    #     except Exception as e:
    #         return f"Error searching vulnerabilities: {str(e)}"

    def search_vulnerabilities(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for valid filter keys and enum mappings.",
            examples=[{"q__icontains": "use after free", "cvss_v3_score__exact": ["high", "critical"]}],
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
        """Find confirmed vulnerabilities (CVEs) based on keyword search, severity, exploitability, or other criteria.
        
        Use this tool to list threats present in the environment. Call `get_vulnerabilities_schema` 
        before constructing filter expressions.
        """
        try:
            current_page = page if page is not None else 1
            per_page = min(limit, 500) if limit is not None else 500

            # Base API parameters
            params: dict[str, Any] = {
                'site_id__exact': 1,
                'ghost__exact': False,
                'affected_assets__exact': 0, # 0 = True in Claroty Enum
                'special_hint__exact': 0,    # 0 = Unicast
                'relevance__exact': 1,      # 1 = Confirmed matches only
                'sort': sort_by,
                'page': current_page,
                'per_page': per_page
            }

            # Apply LLM filters
            if filters:
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

            # Format fixed fields into compact strings
            compact_entries = []
            for item in objects:
                cve_id = item.get("cve_id", "N/A")
                res_id = item.get("resource_id", "N/A")
                
                # Extract total_affected_assets
                assets_count = item.get("assets_count", {})
                affected_assets = (
                    assets_count.get("total_affected_assets_count", 0) 
                    if isinstance(assets_count, dict) else 0
                )

                # Extract cvss_v3_score
                cvss = item.get("cvss_v3_score")
                if isinstance(cvss, dict):
                    val = cvss.get("value")
                    lbl = cvss.get("label")
                    cvss_str = f"{val} ({lbl})" if val and lbl else str(val or lbl or "N/A")
                else:
                    cvss_str = str(cvss) if cvss is not None else "N/A"

                compact_entries.append(
                    f"**{cve_id}** [ID: `{res_id}` | CVSS: {cvss_str} | Assets: {affected_assets}]"
                )

            # Pack multiple CVE entries per row (3 entries per row)
            items_per_row = 3
            table_rows = []
            for i in range(0, len(compact_entries), items_per_row):
                chunk = compact_entries[i:i + items_per_row]
                # Pad empty cells if the final row has fewer than 3 items
                while len(chunk) < items_per_row:
                    chunk.append("")
                table_rows.append({"Vulnerabilities (Col 1)": chunk[0], "Vulnerabilities (Col 2)": chunk[1], "Vulnerabilities (Col 3)": chunk[2]})

            md_table = self._format_to_markdown(table_rows)

            # Metadata header with Pagination Intelligence
            metadata_header = [
                f"**Page {current_page} Results:** Displaying {len(objects)} records (Total available: {total_records})"
            ]

            # Check if there are more records beyond the current page scope
            if total_records > (current_page * per_page):
                metadata_header.append(
                    f"**NOTICE:** More records are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page} records."
                )

            return "\n".join(metadata_header) + "\n\n" + md_table

        except Exception as e:
            return f"Error searching vulnerabilities: {str(e)}"

    # def list_assets_per_cves(
    #     self,
    #     filters: dict[str, str | int | bool | list[str | int]] | None = Field(
    #         default=None,
    #         description="Dictionary of search filters. Call `get_vulnerabilities_schema` for valid filter keys and enum mappings.",
    #         examples=[{"virtual_zone__exact": "106-1", "cvss_v3_score__exact": ["high", "critical"]}],
    #     ),
    #     cve_id: str | None = Field(
    #         default=None,
    #         description="Optional specific CVE ID to list all assets for",
    #         examples=["CVE-2026-215", "RA-66658"],
    #     ),
    #     limit: int | None = Field(
    #         default=500,
    #         ge=1,
    #         le=1000,
    #         description="Maximum number of asset-vulnerability matches to fetch from the API. Defaults to 500.",
    #     ),
    # ) -> str:
    #     """List all assets affected by vulnerabilities (CVEs) in the environment.
        
    #     Use this tool when you need to view affected devices grouped by CVE, or when 
    #     checking the blast radius of a specific CVE by passing `cve_id`.
    #     """
    #     try:
    #         effective_limit = min(limit, 1000) if limit is not None else 500

    #         # 1. Base mandatory API parameters
    #         mandatory_fields = ['cve_id', 'asset_id', 'asset_name', 'risk_level']
    #         fields_param = ",;$".join(mandatory_fields)

    #         params: dict[str, Any] = {
    #             'site_id__exact': '1',
    #             'ghost__exact': 'false',
    #             'special_hint__exact': '0',   
    #             'relevance__exact': '1',      
    #             'sort': 'cve_id',             
    #             'fields': fields_param
    #         }

    #         if cve_id:
    #             params['cve_id__exact'] = cve_id.strip()

    #         # Apply additional LLM filters
    #         if filters:
    #             for key, value in filters.items():
    #                 if isinstance(value, list):
    #                     params[key] = ",;$".join(str(v).strip() for v in value)
    #                 else:
    #                     params[key] = value

    #         # Paginated API execution loop
    #         all_objects = []
    #         current_page = 1
    #         per_page = min(effective_limit, 200)
    #         params['per_page'] = per_page
    #         total_records = 0

    #         while True:
    #             params['page'] = current_page
    #             response_data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
                
    #             if not isinstance(response_data, dict):
    #                 break

    #             if current_page == 1:
    #                 total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

    #             objects = response_data.get('objects', [])
    #             if not objects:
    #                 break
                    
    #             all_objects.extend(objects)

    #             if len(all_objects) >= effective_limit:
    #                 all_objects = all_objects[:effective_limit]
    #                 break
                
    #             if len(objects) < per_page:
    #                 break
                    
    #             current_page += 1

    #         if not all_objects:
    #             msg = f"No assets found affected by '{cve_id}'." if cve_id else "No asset-vulnerability matches found for the specified criteria."
    #             return msg

    #         # 2. Group records by CVE
    #         grouped_data: dict[str, list[str]] = {}
    #         for item in all_objects:
    #             c_id = item.get("cve_id", "Unknown CVE")
    #             asset_name = str(item.get("asset_name", "Unknown")).strip()
    #             a_id = item.get("asset_id", "N/A")
    #             risk = item.get("risk_level", "N/A")
                
    #             # ULTRA COMPRESSED FORMAT: Name [ID:X, R:Y]
    #             asset_str = f"{asset_name} [ID:{a_id}, R:{risk}]"
                
    #             if c_id not in grouped_data:
    #                 grouped_data[c_id] = []
    #             grouped_data[c_id].append(asset_str)

    #         # 3. Build Highly Compressed Output
    #         md_lines = []
    #         for c_id, assets in grouped_data.items():
    #             total_assets = len(assets)
                
    #             # Hard cap inline display at 25 assets per CVE to save context
    #             display_limit = 25
    #             display_assets = assets[:display_limit]
                
    #             # Join them with a simple comma
    #             assets_joined = ", ".join(display_assets)
                
    #             # Add truncation note if it exceeds the cap
    #             if total_assets > display_limit:
    #                 assets_joined += f" ... (+{total_assets - display_limit} more assets)"
                
    #             md_lines.append(f"- **{c_id}** ({total_assets} total): {assets_joined}")

    #         # Assemble final output
    #         metadata_header = [
    #             f"**Matches Fetched:** {len(all_objects)} / {total_records} total available.",
    #         ]
            
    #         if total_records > len(all_objects):
    #             metadata_header.append(
    #                 "⚠️ **Truncation Notice:** Results capped at 500 entries to preserve context window. Use optional filters for more precise results."
    #             )

    #         return "\n".join(metadata_header) + "\n\n" + "\n".join(md_lines)

    #     except Exception as e:
    #         return f"Error listing assets per CVE: {str(e)}"
        
    def list_assets_per_cves(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for allowed search filter and enums.",
            examples=[{"virtual_zone__exact": "106-1", "cvss_v3_score__exact": ["high", "critical"]}],
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
        all assets affected by aspecific CVE by passing `cve_id`. Call `get_vulnerabilities_schema`
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

    def list_cves_per_assets(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for allowed search filters and enums.",
            examples=[{"virtual_zone__exact": "106-1", "cvss_v3_score__exact": ["high", "critical"]}],
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
        
        Use this tool to view CVEs grouped by affected device, or when 
        checking all confirmed CVEs for a specific asset by passing `asset_id`.
        Call `get_vulnerabilities_schema` to view allowed filter keys and 
        enum mappings before executing this tool.
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
                asset_key = f"{asset_name} (ID: `{a_id}`, Risk: {risk})"
                
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


        
    # def search_asset_vulnerabilities(
    #         self,
    #         cve_id: Optional[str] = Field(
    #             default=None, 
    #             description="Exact CVE ID to find all affected assets (e.g., 'CVE-2020-6088')."
    #         ),
    #         asset_id: Optional[str] = Field(
    #             default=None, 
    #             description="Exact Asset ID to find all CVEs on that asset (e.g., '11')."
    #         ),
    #         actively_exploited: Optional[bool] = Field(
    #             default=None, 
    #             description="Filter for matches that are actively exploited."
    #         ),
    #         limit: int | None = Field(
    #             default=None,
    #             ge=1,
    #             le=500,
    #             description="Maximum number of matches to return. If omitted, retrieves all matches via auto-pagination.",
    #         ),
    #     ) -> str:
    #         """Retrieves exact matches between Assets and Vulnerabilities. 
            
    #         CRITICAL: Use this to answer "List all CVEs for asset xxxx" or 
    #         "List all assets affected by CVE xxxx".
    #         """
    #         try:
    #             # Base parameters
    #             params: dict[str, Any] = {}
    #             if cve_id: params['cve_id__exact'] = cve_id
    #             if asset_id: params['asset_id__exact'] = asset_id
    #             if actively_exploited is not None: params['actively_exploited__exact'] = actively_exploited

    #             # Pagination
    #             all_objects = []
    #             current_page = 1
                
    #             # Chunking
    #             per_page = min(limit, 500) if limit is not None else 500
    #             params['per_page'] = per_page

    #             while True:
    #                 params['page'] = current_page
                    
    #                 response_data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
                    
    #                 if not isinstance(response_data, dict):
    #                     break

    #                 objects = response_data.get('objects', [])
    #                 if not objects:
    #                     break
                        
    #                 all_objects.extend(objects)

    #                 # Stop Conditions:
    #                 if limit is not None and len(all_objects) >= limit:
    #                     all_objects = all_objects[:limit]
    #                     break
                    
    #                 if len(objects) < per_page:
    #                     break
                        
    #                 current_page += 1
                
    #             if not all_objects:
    #                 return "No asset-vulnerability matches found for those criteria."

    #             # Flatten and optimize token output
    #             matches = []
    #             for match in all_objects:
    #                 clean_match = {
    #                     "match_resource_id": match.get("resource_id"),
    #                     "asset_id": match.get("asset_id"),
    #                     "asset_name": match.get("asset_name"),
    #                     "ipv4": match.get("ipv4", [None])[0] if match.get("ipv4") else None,
    #                     "cve_id": match.get("cve_id"),
    #                     "cvss_v3": match.get("cvss_v3_score", {}).get("value"),
    #                     "relevance": match.get("relevance__"),
    #                     "status": match.get("status__")
    #                 }
    #                 # Strip out empty/null values
    #                 clean_match = {k: v for k, v in clean_match.items() if v not in (None, "", [], {})}
    #                 matches.append(clean_match)

    #             return self._format_to_markdown(matches)
                
    #         except Exception as e:
    #             return f"Error searching asset vulnerabilities: {str(e)}"

    # def get_vulnerability_details(
    #         self, 
    #         resource_id: str = Field(
    #             description="The exact 'resource_id' of the vulnerability (e.g., '1-1').",
    #             examples=["1-1", "12-1"]
    #         )
    #     ) -> str:
    #         """Retrieves the complete, raw diagnostic profile of a single vulnerability.
            
    #         Use this when a deep-dive into a specific CVE's metadata, scoring, 
    #         or description is requested.
    #         """
    #         try:
    #             identifier_str = str(resource_id).strip()
    #             if not identifier_str:
    #                 return "Error: Invalid resource_id provided."

    #             response_data = self.client.request("GET", f"/ranger/vulnerabilities/{identifier_str}")
                
    #             if not response_data:
    #                 return f"No data found for vulnerability {identifier_str}."
                    
    #             # Output Token Optimization
    #             if isinstance(response_data, dict):
    #                 response_data = {k: v for k, v in response_data.items() if v not in (None, "", [], {})}
                    
    #             return self._format_to_markdown(response_data)
                
    #         except Exception as e:
    #             return f"Error fetching details for vulnerability {resource_id}: {str(e)}"


        