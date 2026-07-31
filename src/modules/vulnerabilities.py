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

        # self._add_tool(
        #         server=server, 
        #         method=self.search_asset_vulnerabilities, 
        #         name="search_asset_vulnerabilities",
        #         annotations=ToolAnnotations(
        #             readOnlyHint=True,
        #             destructiveHint=False,
        #             idempotentHint=True,
        #             openWorldHint=False,
        #         )
        # )

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

    def search_vulnerabilities(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
            default=None,
            description="Dictionary of search filters. Call `get_vulnerabilities_schema` for valid filter keys and enum mappings.",
            examples=[{"q__icontains": "use after free", "cvss_v3_score__exact": ["high", "critical"]}],
        ),
        limit: int | None = Field(
            default=200,
            ge=1,
            le=200,
            description="Maximum number of vulnerabilities to return (capped at 200). Defaults to 200 to preserve context.",
        ),
    ) -> str:
        """Find vulnerabilities (CVEs) based on keyword search, severity, exploitability, or other criteria.
        
        Use this tool to list threats present in the environment. Call `get_vulnerabilities_schema` 
        before constructing filter expressions.
        """
        try:
            effective_limit = min(limit, 200) if limit is not None else 200

            # Base API parameters
            params: dict[str, Any] = {
                'site_id__exact': 1,
                'ghost__exact': False,
                'affected_assets__exact': 0, # 0 = True in Claroty Enum
                'special_hint__exact': 0,    # 0 = Unicast
                'sort': '-cvss_v3_score'
            }

            # Apply LLM filters
            if filters:
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # Pagination fetching loop
            all_objects = []
            current_page = 1
            per_page = min(effective_limit, 100)
            params['per_page'] = per_page
            total_records = 0

            while True:
                params['page'] = current_page
                response_data = self.client.request("GET", "/ranger/vulnerabilities", params=params)
                
                if not isinstance(response_data, dict):
                    break

                if current_page == 1:
                    total_records = response_data.get("count_total", response_data.get("count_filtered", 0))

                objects = response_data.get('objects', [])
                if not objects:
                    break
                    
                all_objects.extend(objects)

                if len(all_objects) >= effective_limit:
                    all_objects = all_objects[:effective_limit]
                    break
                
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return "No vulnerabilities found matching the specified criteria."

            # Format fixed fields into compact strings
            compact_entries = []
            for item in all_objects:
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

            metadata_header = [
                f"**Total Records Found:** {total_records}",
                f"**Returned Records:** {len(compact_entries)}"
            ]

            if total_records > len(compact_entries):
                metadata_header.append(
                    "⚠️ **Truncation Notice:** Results capped at 200 entries to preserve context window."
                )

            return "\n".join(metadata_header) + "\n\n" + md_table

        except Exception as e:
            return f"Error searching vulnerabilities: {str(e)}"


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


        