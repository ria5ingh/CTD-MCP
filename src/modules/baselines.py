import json
from typing import Any, Optional
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule

class BaselinesModule(BaseModule):
    """Interface for auditing Claroty CTD network and behavioral baselines."""
    
    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)
        
        self._add_tool(
            server=server, 
            method=self.get_baselines_summary, 
            name="get_baselines_summary", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        self._add_tool(
            server=server, 
            method=self.get_baseline_details, 
            name="get_baseline_details", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        self._add_tool(
            server=server, 
            method=self.get_unapproved_baselines, 
            name="get_unapproved_baselines", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        self._add_tool(
            server=server, 
            method=self.get_asset_baselines, 
            name="get_asset_baselines", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )

    def _format_lightweight_list(self, objects: list, page: int, total: int, per_page: int) -> str:
        """Helper function to format lightweight baseline lists."""
        if not objects:
            return f"No baselines found matching the criteria on page {page}."

        output = [
            f"**Page {page} Results:** Displaying {len(objects)} records (Total available: {total})\n",
            "### Baseline Summary"
        ]
        
        for item in objects:
            b_id = item.get("resource_id", "N/A")
            desc = item.get("description", "Unknown Baseline")
            proto = item.get("protocol", "Unknown")
            is_appr = item.get("approved", False)
            
            status = "Approved" if is_appr else "Unapproved"
            output.append(f"* **ID:** `{b_id}` | **Status:** {status} | **Protocol:** {proto} | **Desc:** {desc}")

        if total > (page * per_page):
            output.append(f"\n**NOTICE:** More baselines available. Call this tool again with `page={page + 1}`.")

        return "\n".join(output)

    def get_baselines_summary(
        self,
        limit: int = Field(default=100, ge=1, le=500, description="Maximum number of baselines to return per page."),
        page: int = Field(default=1, ge=1, description="Page number for pagination.")
    ) -> str:
        """Retrieve a highly compressed summary of all baselines. Use this to find specific Baseline IDs."""
        try:
            params = {
                "site_id": 1,
                "page": page,
                "per_page": min(limit, 500),
                "fields": "resource_id,;$description,;$protocol,;$approved"
            }

            response_data = self.client.request("GET", "/ranger/baselines", params=params)
            if not isinstance(response_data, dict):
                return "Error: Invalid response format from the server."

            objects = response_data.get("objects", [])
            total = response_data.get("count_total", 0)

            return self._format_lightweight_list(objects, page, total, params["per_page"])

        except Exception as e:
            return f"Error retrieving baselines summary: {str(e)}"

    def get_baseline_details(
        self,
        resource_id: str = Field(description="The exact 'resource_id' of the baseline (e.g., '419-1').")
    ) -> str:
        """Retrieve the complete, raw JSON metadata for a specific baseline. Use this for deep-dive investigations."""
        try:
            identifier_str = str(resource_id).strip()
            
            # Using exact filter to grab the specific baseline
            params = {"site_id": 1, "resource_id__exact": identifier_str}
            response_data = self.client.request("GET", "/ranger/baselines", params=params)
            
            if not isinstance(response_data, dict) or not response_data.get("objects"):
                return f"No detailed data found for baseline ID `{identifier_str}`."
                
            baseline_data = response_data["objects"][0]
            
            # Strip out empty/null values to save tokens
            clean_data = {k: v for k, v in baseline_data.items() if v not in (None, "", [], {})}
            
            return f"### Baseline Details: `{identifier_str}`\n```json\n{json.dumps(clean_data, indent=2)}\n```"
            
        except Exception as e:
            return f"Error fetching details for baseline {resource_id}: {str(e)}"

    def get_unapproved_baselines(
        self,
        limit: int = Field(default=100, ge=1, le=500, description="Maximum number of baselines to return per page."),
        page: int = Field(default=1, ge=1, description="Page number for pagination.")
    ) -> str:
        """Retrieve a list of all unapproved baselines. Critical for daily security audits."""
        try:
            params = {
                "site_id": 1,
                "page": page,
                "per_page": min(limit, 500),
                "approved": "false",
                "fields": "resource_id,;$description,;$protocol,;$approved"
            }

            response_data = self.client.request("GET", "/ranger/baselines", params=params)
            if not isinstance(response_data, dict):
                return "Error: Invalid response format from the server."

            objects = response_data.get("objects", [])
            total = response_data.get("count_total", 0)

            return self._format_lightweight_list(objects, page, total, params["per_page"])

        except Exception as e:
            return f"Error retrieving unapproved baselines: {str(e)}"

    def get_asset_baselines(
        self,
        asset_id: str = Field(description="The exact ID of the asset (e.g., '29')."),
        limit: int = Field(default=100, ge=1, le=500, description="Maximum number of baselines to return per page."),
        page: int = Field(default=1, ge=1, description="Page number for pagination.")
    ) -> str:
        """Retrieve all baselines where a specific asset acts as either the source or destination."""
        try:
            per_page = min(limit, 500)
            
            # Query for where the asset is the source
            src_params = {"site_id": 1, "page": page, "per_page": per_page, "source_entity_id": asset_id}
            src_resp = self.client.request("GET", "/ranger/baselines", params=src_params)
            src_objs = src_resp.get("objects", []) if isinstance(src_resp, dict) else []
            
            # Query for where the asset is the destination
            dst_params = {"site_id": 1, "page": page, "per_page": per_page, "destination_entity_id": asset_id}
            dst_resp = self.client.request("GET", "/ranger/baselines", params=dst_params)
            dst_objs = dst_resp.get("objects", []) if isinstance(dst_resp, dict) else []

            # Deduplicate just in case
            seen_ids = set()
            combined_objects = []
            
            for obj in (src_objs + dst_objs):
                b_id = obj.get("resource_id")
                if b_id and b_id not in seen_ids:
                    seen_ids.add(b_id)
                    combined_objects.append(obj)

            if not combined_objects:
                return f"No baselines found involving asset ID `{asset_id}`."

            # Trim to the requested limit across both combined lists
            combined_objects = combined_objects[:per_page]

            return self._format_lightweight_list(combined_objects, page, len(seen_ids), per_page)

        except Exception as e:
            return f"Error retrieving baselines for asset {asset_id}: {str(e)}"