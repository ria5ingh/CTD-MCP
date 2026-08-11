
import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.alerts import ALERTS_SCHEMA_URI, ALERTS_SCHEMA_DOCS


class AlertsModule(BaseModule):

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(
            server=server, 
            method=self.search_alerts, 
            name="self.search_alerts",
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
                    uri=AnyUrl(ALERTS_SCHEMA_URI),
                    name="ctd_alerts_schema",
                    description="Contains the master guide, allowed filters, and enums for the `search_alerts` tools",
                    text=ALERTS_SCHEMA_DOCS, 
                    mime_type="text/markdown"
                )        
        self._add_resource(server, resource)
        

    def get_alerts_schema(self) -> str:
            """Retrieves the complete CTD Alerts Search Schema, and Filter Keys.
            
            Call this tool BEFORE executing search_alerts to look up 
            allowed filter keys, required data types, or integer enum mappings.
            """
            return ALERTS_SCHEMA_DOCS

    def search_alerts(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call the `get_alerts_schema` tool to find allowed filter keys, data types, and enum mappings.",
            examples=[{"severity__exact": [2, 3], "category__exact": 0}],
        ),
        limit: int | None = Field(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of alerts to return. If omitted, all matching alerts are retrieved via auto-pagination up to a safe limit.",
        ),
    ) -> str:
        """Fetch and filter network security and integrity alerts from the system.
        
        Returns a high-level triage list including the alert ID, timestamp, type, category, 
        severity, score, story ID, and description. Only UNRESOLVED alerts are returned by default.
        Call the `get_alerts_schema` tool before constructing filter expressions.
        """
        try:
            # Explicitly define the exact fields needed for the triage view
            target_fields = ",;$".join([
                "resource_id", 
                "timestamp", 
                "category__", 
                "type__", 
                "severity", 
                "severity__", 
                "score", 
                "story_id", 
                "description"
            ])
        
            # Base default parameters
            params: dict[str, Any] = {
                'sort': '-timestamp',
                'resolved__exact': 'false',
                'is_qualified__exact': 'true',
                'site_id__exact': 1,
                'fields': target_fields, # Server-side field filtering
            }

            # Apply LLM filters with Bulletproof ID Safety and Optimized Joining
            if filters:
                id_keys = {"virtual_zone__exact", "id__exact"} # Set for O(1) lookup
                for key, value in filters.items(): 
                    # Normalize scalar values to a list to process everything uniformly
                    val_list = value if isinstance(value, list) else [value]
                    
                    cleaned_vals = []
                    for v in val_list:
                        cv = str(v).strip()
                        # Automatically append '-1' for resource ID filters if omitted
                        if key in id_keys and cv.isdigit():
                            cv = f"{cv}-1"
                        cleaned_vals.append(cv)
                        
                    # Joining a single-item list naturally returns just the single item
                    params[key] = ",;$".join(cleaned_vals)

            # Pagination Setup
            all_objects = []
            current_page = 1
            per_page = min(limit, 500) if limit is not None else 100
            params['per_page'] = per_page

            while True:
                params['page'] = current_page
                
                # Fetch from V2 Alerts endpoint
                response_data = self.client.request("GET", "/ranger/v2/alerts", params=params)
                
                if not isinstance(response_data, dict):
                    break
                    
                objects = response_data.get('objects', [])
                
                if not objects:
                    break
                    
                all_objects.extend(objects)
                
                # Stop Conditions
                if limit is not None and len(all_objects) >= limit:
                    all_objects = all_objects[:limit]  # Truncate to exact requested limit
                    break
                    
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return "No alerts found matching the specified criteria."

            # Map directly from API response to bypass unnecessary server-side processing
            processed_alerts = []
            for item in all_objects:
                processed_alerts.append({
                    "Alert ID": item.get("resource_id", "N/A"),
                    "Timestamp": item.get("timestamp", "N/A"),
                    "Category": item.get("category__", "Unknown"),
                    "Type": item.get("type__", "Unknown"),
                    "Severity": f"{item.get('severity__', 'Unknown')} ({item.get('severity', '')})",
                    "Score": item.get("score", "N/A"),
                    "Story ID": item.get("story_id", "N/A"),
                    "Description": item.get("description", "No description")
                })

            # Automatically generate a highly token-efficient Markdown table
            return self._format_to_markdown(processed_alerts)

        except Exception as e:
            return f"Error fetching alerts: {str(e)}"

# get all alerts
# --> return id, type, alert category, severity, status, and score 

# get alert info (given an alert id)