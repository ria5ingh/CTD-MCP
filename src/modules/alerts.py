import json
from typing import Any, Optional
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule

class AlertsModule(BaseModule):
    """Interface for querying and investigating Claroty CTD Alerts."""

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)
        
        self._add_tool(
            server=server, 
            method=self.list_my_alerts, 
            name="list_my_alerts", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        self._add_tool(
            server=server, 
            method=self.get_alert_investigation_data, 
            name="get_alert_investigation_data", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        self._add_tool(
            server=server, 
            method=self.get_alert_signature_events, 
            name="get_alert_signature_events", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )

    def list_my_alerts(
        self,
        severity: Optional[int] = Field(default=None, description="Filter by severity: 0=Low, 1=Medium, 2=High, 3=Critical"),
        resolved: Optional[bool] = Field(default=False, description="Filter by status: True=Resolved, False=Unresolved"),
        limit: int = Field(default=20, ge=1, le=100, description="Number of alerts to return (max 100)."),
        page: int = Field(default=1, ge=1, description="Page number.")
    ) -> str:
        """List alerts in a queue format, identical to the main Alerts UI dashboard."""
        try:
            params: dict[str, Any] = {
                "page": page,
                "per_page": min(limit, 100),
                "fields": "resource_id,;$type__,;$description,;$timestamp,;$category__,;$resolved"
            }
            
            if severity is not None: params["severity__exact"] = severity
            if resolved is not None: params["resolved__exact"] = str(resolved).lower()

            response_data = self.client.request("GET", "/ranger/v2/alerts", params=params) #[cite: 2]
            
            if not isinstance(response_data, dict):
                return "Error: Invalid response format from the server."

            objects = response_data.get("objects", [])
            total = response_data.get("count_total", 0)

            if not objects:
                return f"No alerts found matching the criteria on page {page}."

            output = [
                f"### Alerts Dashboard (Page {page} of {max(1, total // params['per_page'])})",
                "| ID | Type | Description | Date Detected | Category | Status |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |"
            ]
            
            for item in objects:
                a_id = item.get("resource_id", "N/A")
                a_type = str(item.get("type__", "Unknown")).replace("e", "")
                desc = str(item.get("description", "N/A")).replace("\n", " ")[:80] + "..."
                date = item.get("timestamp", "N/A")
                cat = str(item.get("category__", "Unknown")).replace("e", "")
                status = "Resolved" if item.get("resolved") else "Unresolved"
                
                output.append(f"| `{a_id}` | {a_type} | {desc} | {date} | {cat} | {status} |")

            return "\n".join(output)

        except Exception as e:
            return f"Error retrieving alerts list: {str(e)}"

    def get_alert_investigation_data(
        self,
        resource_id: str = Field(description="The exact 'resource_id' of the alert (e.g., '538-1').")
    ) -> str:
        """Retrieve the deep-dive investigation data for an alert, including scores, indicators, and asset profiles."""
        try:
            identifier_str = str(resource_id).strip()
            response_data = self.client.request("GET", f"/ranger/alerts/{identifier_str}") #[cite: 2]
            
            if not isinstance(response_data, dict):
                return f"No detailed data found for alert ID `{identifier_str}`."
                
            output = [f"### Alert Investigation: `{identifier_str}`"]

            # 1. Score & Severity
            score = response_data.get("score", "N/A") #[cite: 2]
            severity = str(response_data.get("severity__", "Unknown")).replace("e", "") #[cite: 2]
            output.append(f"**Alert Score:** {score}/100 | **Severity:** {severity}")
            output.append(f"**Description:** {response_data.get('description', 'N/A')}\n") #[cite: 2]

            # 2. Significant Indicators
            indicators = response_data.get("significant_indicators", []) #[cite: 2]
            if indicators:
                output.append("#### Significant Indicators")
                for ind in indicators:
                    info = ind.get("indicator_info", {})
                    output.append(f"* {info.get('description', 'Unknown Indicator')} (Points: {info.get('points', 0)})")
                output.append("")

            # 3. Asset Breakdown (Source/Dest)
            assets = response_data.get("actionable_assets", []) #[cite: 2]
            if assets:
                output.append("#### Asset Profiles (Source/Destination)")
                for aa in assets:
                    asset = aa.get("asset", {})
                    role = str(aa.get("role__", "Unknown Role")).replace("e", "")
                    name = asset.get("name", "Unknown Host")
                    ip = ", ".join(asset.get("ip", []))
                    mac = ", ".join(asset.get("mac", []))
                    vendor = asset.get("vendor", "N/A")
                    a_type = str(asset.get("asset_type__", "Unknown")).replace("e", "")
                    
                    output.append(f"* **[{role}] {name}**")
                    output.append(f"  * IP: {ip} | MAC: {mac}")
                    output.append(f"  * Type: {a_type} | Vendor: {vendor}")
                output.append("")

            # 4. Mitigation/Story Details
            story = response_data.get("story_group_name", []) #[cite: 2]
            if story:
                output.append("#### Root Cause / Story Group")
                for s in story:
                    output.append(f"* {s}")

            return "\n".join(output)
            
        except Exception as e:
            return f"Error fetching investigation data for alert {resource_id}: {str(e)}"

    def get_alert_signature_events(
        self,
        alert_id: str = Field(description="The exact alert resource_id (e.g., '538-1').")
    ) -> str:
        """Retrieve the underlying network events and raw signature payloads that triggered the alert."""
        try:
            params = {
                "page": 1,
                "per_page": 20,
                "alert_id__exact": str(alert_id).strip()
            }
            
            response_data = self.client.request("GET", "/ranger/events", params=params)
            
            if not isinstance(response_data, dict):
                return "Error: Invalid response format from the server."
                
            objects = response_data.get("objects", [])
            if not objects:
                return f"No underlying events or network signatures found for alert ID `{alert_id}`."
                
            output = [f"### Network Signature & Event Logs for Alert `{alert_id}`"]
            
            for item in objects:
                e_type = str(item.get("type__", "Unknown Event")).replace("e", "")
                desc = item.get("description", "No signature description available.")
                timestamp = item.get("timestamp", "N/A")
                
                output.append(f"#### Event: {e_type} ({timestamp})")
                output.append(f"```text\n{desc.strip()}\n```")
                
            return "\n".join(output)
            
        except Exception as e:
            return f"Error retrieving signature events: {str(e)}"