from typing import Any, Optional
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule

class ZonesModule(BaseModule):
    """Interface for auditing Claroty CTD Virtual Zones and asset grouping algorithms."""
    
    def __init__(self, client: CTDClient):
        super().__init__(client)
        self.algorithm_mappings = {
            "default": "Default Behavioral Grouping Algorithm",
            "purdue": "Purdue Model Grouping",
            "network": "Network Subnet Grouping",
            "custom": "Custom Grouping Algorithm"
        }

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)
        
        self._add_tool(
            server=server, 
            method=self.get_virtual_zones, 
            name="get_virtual_zones", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )
        
        self._add_tool(
            server=server, 
            method=self.get_zone_grouping_algorithm, 
            name="get_zone_grouping_algorithm", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )

    def get_virtual_zones(self) -> str:
        """Retrieve all configured Virtual Zones, their criticality, and their assigned asset counts."""
        try:
            # Hardcoded parameters to prevent LLM hesitation
            params = {"page": "1", "per_page": "100", "site_id": "1"}
            data = self.client.request("GET", "/ranger/virtual_zones", params=params)
            objects = data.get("objects", [])
            
            if not objects:
                return "No Virtual Zones discovered in the CTD appliance."

            output = ["### Virtual Zones Mapping"]
            total_assets = 0

            for z in objects:
                raw_crit = z.get("criticality__", "Unknown")
                # Clean up the criticality string (e.g., removing arbitrary leading characters like 'e')
                clean_crit = raw_crit.replace("e", "") if isinstance(raw_crit, str) else "Unknown"
                
                assets = z.get("num_assets", 0)
                total_assets += assets
                
                name = z.get('name', 'Unknown')
                zone_id = z.get('id', 'N/A')
                
                output.append(f"* **{name}** | ID: `{zone_id}` | Criticality: {clean_crit} | Assets: {assets}")

            output.insert(1, f"**Total Zones:** {len(objects)} | **Total Mapped Assets:** {total_assets}\n")
            
            return "\n".join(output)
            
        except Exception as e:
            return f"Error retrieving virtual zones: {str(e)}"

    def get_zone_grouping_algorithm(self) -> str:
        """Determine the core algorithm CTD is using to automatically group assets into Virtual Zones."""
        try:
            # Hardcoded parameter to prevent LLM hesitation
            params = {"site_id": "1"}
            data = self.client.request("GET", "/ranger/virtual_zones_grouping_algorithm", params=params)
            
            def find_grouping(payload: Any) -> Optional[str]:
                if isinstance(payload, dict):
                    for key in ["algorithm", "grouping_algorithm", "name", "value", "method"]:
                        if key in payload and payload[key]:
                            raw_val = str(payload[key]).lower()
                            return self.algorithm_mappings.get(raw_val, str(payload[key]).title())
                    for val in payload.values():
                        if res := find_grouping(val): 
                            return res
                elif isinstance(payload, list):
                    for item in payload:
                        if res := find_grouping(item): 
                            return res
                return None

            extracted = find_grouping(data)
            if extracted:
                return f"### Virtual Zone Grouping Algorithm\n**Active Configuration:** {extracted}"
                
            return "Error: Could not parse the grouping algorithm from the CTD payload."
            
        except Exception as e:
            return f"Error fetching zone grouping algorithm: {str(e)}"