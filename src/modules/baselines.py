    
import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.baselines import BASELINES_SCHEMA_DOCS, BASELINES_SCHEMA_URI

class BaselinesModule(BaseModule):

    def register_tools(self, server: FastMCP) -> None:
            super().register_tools(server)

            self._add_tool(
                server=server, 
                method=self.get_baselines_schema, 
                name="get_baselines_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
            )
            
            self._add_tool(
                server=server, 
                method=self.get_baseline_summaries, 
                name="get_baseline_summaries",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
            )

            self._add_tool(
                server=server, 
                method=self.search_specific_baselines, 
                name="search_specific_baselines",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
            )
            



    def register_resources(self, server: FastMCP) -> None:
            super().register_resources(server)
            resource = TextResource(
                        uri=AnyUrl(BASELINES_SCHEMA_URI),
                        name="ctd_baselines_schema",
                        description="Contains the master guide, allowed filters, and enums for the `get_baseline_summaries` tool",
                        text=BASELINES_SCHEMA_DOCS, 
                        mime_type="text/markdown"
                    )        
            self._add_resource(server, resource)   
    
    def get_baselines_schema(self) -> str:
            """Retrieves the complete CTD Baselines Search Schema, and Filter Keys.
            
            Call this tool BEFORE executing get_baselines_summaries to look up 
            allowed filter keys, required data types, or integer enum mappings.
            """
            return BASELINES_SCHEMA_DOCS
    

    def get_baseline_summaries(
            self,
            filters: dict[str, str | int | list[str | int]] | None = Field(
                default=None,
                description="Dictionary of search filters. Call `get_baselines_schema` to find allowed filter keys and enum mappings (e.g., category__exact, category_access__exact, protocol__exact).",
                examples=[{"category__exact": [2, 6], "protocol__exact": "CIP"}],
            ),
            limit: int | None = Field(
                default=100,
                ge=1,
                le=500,
                description="Maximum number of summary groups to return. Defaults to 100.",
            ),
        ) -> str:
            """Fetch a high-level summary of baseline network communications.
        
            Returns the total count of baseline events grouped by Protocol, Port, Category, and Access Type. 
            Filter the search results by source/dest virtual zone, category, access type, or protocol to narrow the scope.
            (Noisy broadcast/multicast communications are excluded by default).
            """
            try:
                # Inline Enum Maps for readable output
                category_map = {
                    1: "Other", 2: "Data Acquisition", 3: "Protocol", 4: "Firmware", 
                    5: "Operation", 6: "Programming", 7: "Alarm", 8: "Diagnosis", 
                    9: "Auth", 10: "Remote Connection", 12: "Filesystem"
                }
                access_map = {
                    0: "None", 1: "Read", 2: "Write", 3: "Execute", 4: "Publish"
                }

                # Base parameters with default category exclusions (dropping 11/Network)
                params: dict[str, Any] = {
                    'sort': 'protocol',
                    'category__exact': '1,;$2,;$3,;$4,;$5,;$6,;$7,;$8,;$9,;$10,;$12',
                    'distinct': 'false',
                }

                # Apply LLM filters with List Joining
                if filters:
                    zone_keys = {"source_virtual_zone__exact", "destination_virtual_zone__exact"}
                    for key, value in filters.items(): 
                        val_list = value if isinstance(value, list) else [value]
                        
                        cleaned_vals = []
                        for v in val_list:
                            cv = str(v).strip()
                            # Automatically append '-1' for virtual zone IDs if omitted
                            if key in zone_keys and cv.isdigit():
                                cv = f"{cv}-1"
                            cleaned_vals.append(cv)
                            
                        params[key] = ",;$".join(cleaned_vals)

                # Pagination Setup
                all_objects = []
                current_page = 1
                per_page = min(limit, 500) if limit is not None else 100
                params['per_page'] = per_page

                while True:
                    params['page'] = current_page
                    
                    # Fetch from Baseline Summaries endpoint
                    response_data = self.client.request("GET", "/ranger/baselines_summary", params=params)
                    
                    if not isinstance(response_data, dict):
                        break
                        
                    objects = response_data.get('objects', [])
                    
                    if not objects:
                        break
                        
                    all_objects.extend(objects)
                    
                    # Stop Conditions
                    if limit is not None and len(all_objects) >= limit:
                        all_objects = all_objects[:limit]
                        break
                        
                    if len(objects) < per_page:
                        break
                        
                    current_page += 1

                if not all_objects:
                    return "No baseline summaries found matching the specified criteria."

                # Map API response to readable strings
                processed_summaries = []
                for item in all_objects:
                    cat_id = item.get("category")
                    acc_id = item.get("category_access")
                    
                    processed_summaries.append({
                        "Protocol": item.get("protocol", "Unknown"),
                        "Dest Port": item.get("dst_port") or "",
                        "Category": category_map.get(cat_id, f"Unknown ({cat_id})"),
                        "Access Type": access_map.get(acc_id, f"Unknown ({acc_id})"),
                        "Count": item.get("count", 0)
                    })

                header = f"### Baseline Summaries ({len(processed_summaries)} groups retrieved)\n"
                table_output = self._format_to_markdown(processed_summaries)
                
                return header + table_output

            except Exception as e:
                return f"Error fetching baseline summaries: {str(e)}"

    def search_specific_baselines(
        self,
        filters: dict[str, str | int | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call `get_baselines_schema` for allowed keys (e.g., source__exact, destination__exact, protocol__exact, description__icontains).",
            examples=[{"source__exact": "10.1.30.1", "protocol__exact": "CIP"}],
        ),
        limit: int | None = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of baselines to return. Defaults to 100.",
        ),
    ) -> str:
        """Search and retrieve specific baseline communications between assets.
        
        Returns individual baseline events representing commands or communications observed during Training Mode.
        Filter the results by source/dest IP, virtual zone, protocol, or baseline description for more granular searching.
        (Broadcast/multicast communications are excluded by default).
        """
        try:
            category_map = {
                1: "Other", 2: "Data Acquisition", 3: "Protocol", 4: "Firmware", 
                5: "Operation", 6: "Programming", 7: "Alarm", 8: "Diagnosis", 
                9: "Auth", 10: "Remote Conn", 12: "Filesystem"
            }
            access_map = {
                0: "None", 1: "Read", 2: "Write", 3: "Execute", 4: "Publish"
            }

            # Base parameters, dropping 11 (Network) to reduce multicast noise
            params: dict[str, Any] = {
                'category__exact': '1,;$2,;$3,;$4,;$5,;$6,;$7,;$8,;$9,;$10,;$12',
                'distinct': 'false',
            }

            # Apply LLM filters with List Joining
            if filters:
                zone_keys = {"source_virtual_zone__exact", "destination_virtual_zone__exact"}
                for key, value in filters.items(): 
                    val_list = value if isinstance(value, list) else [value]
                    
                    cleaned_vals = []
                    for v in val_list:
                        cv = str(v).strip()
                        # Automatically append '-1' for virtual zone IDs if omitted
                        if key in zone_keys and cv.isdigit():
                            cv = f"{cv}-1"
                        cleaned_vals.append(cv)
                        
                    params[key] = ",;$".join(cleaned_vals)

            all_objects = []
            current_page = 1
            per_page = min(limit, 500) if limit is not None else 100
            total_count = 0

            # Target fields to minimize API payload
            target_fields = ",;$".join([
                "resource_id", "source", "destination", "protocol", 
                "category", "category_access", "description"
            ])
            params['fields'] = target_fields

            while True:
                params['page'] = current_page
                params['per_page'] = per_page
                
                response_data = self.client.request("GET", "/ranger/baselines", params=params)
                
                if not isinstance(response_data, dict):
                    break
                
                # Capture total count on the first page
                if current_page == 1:
                    total_count = response_data.get('count_total', 0)
                    
                objects = response_data.get('objects', [])
                
                if not objects:
                    break
                    
                all_objects.extend(objects)
                
                # Stop Conditions
                if limit is not None and len(all_objects) >= limit:
                    all_objects = all_objects[:limit]
                    break
                    
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return "No baselines found matching the specified criteria."

            # Process and flatten the data for Markdown
            processed_baselines = []
            for item in all_objects:
                cat_id = item.get("category")
                acc_id = item.get("category_access")
                
                # Source and Dest can sometimes be dicts depending on the CTD version/endpoint
                raw_src = item.get("source", "Unknown")
                src_str = raw_src.get("name", raw_src.get("ip", "Unknown")) if isinstance(raw_src, dict) else str(raw_src)
                
                raw_dst = item.get("destination", "Unknown")
                dst_str = raw_dst.get("name", raw_dst.get("ip", "Unknown")) if isinstance(raw_dst, dict) else str(raw_dst)

                processed_baselines.append({
                    "ID": item.get("resource_id", "N/A"),
                    "Source": src_str,
                    "Destination": dst_str,
                    "Protocol": item.get("protocol", "Unknown"),
                    "Category": category_map.get(cat_id, f"Unknown ({cat_id})"),
                    "Access Type": access_map.get(acc_id, f"Unknown ({acc_id})"),
                    "Description": item.get("description", "None")
                })

            header = f"### Specific Baselines (Showing {len(processed_baselines)} of {total_count} total)\n"
            table_output = self._format_to_markdown(processed_baselines)
            
            return header + table_output

        except Exception as e:
            return f"Error fetching specific baselines: {str(e)}"