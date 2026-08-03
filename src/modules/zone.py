from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient


class ZonesModule:
    def __init__(self, client: CTDClient):
        self.client = client

        # GUI Mappings for Zone Grouping Algorithms from the Wizard script
        self.algorithm_mappings = {
            "default": "Default Behavioral Grouping Algorithm",
            "purdue": "Purdue Model Grouping",
            "network": "Network Subnet Grouping",
            "custom": "Custom Grouping Algorithm"
        }

    def register_tools(self, mcp: FastMCP):

        @mcp.tool()
        def get_virtual_zones(
            criticality_filter: Optional[str] = None,
            summary_only: bool = False,
            page: int = 1,
            per_page: int = 100
        ) -> Dict[str, Any]:
            """
            Retrieve configured Virtual Zones and their asset allocations.
            
            Args:
                criticality_filter: Filter zones by criticality level (e.g., "High", "Medium", "Low").
                summary_only: If True, returns only zone counts and total assets to save tokens.
                page: Page number for pagination (default 1).
                per_page: Items per page (default 100).
            """
            try:
                params = {"page": str(page), "per_page": str(per_page)}
                data = self.client.request("GET", "/ranger/virtual_zones", params=params)
                
                objects = data.get("objects", [])
                
                formatted_zones = []
                total_assets = 0
                matching_assets = 0

                for z in objects:
                    # Clean up the criticality string (CTD often prepends an 'e', e.g., 'eHigh')
                    raw_crit = z.get("criticality__", "Unknown")
                    clean_crit = raw_crit.replace("e", "") if isinstance(raw_crit, str) else "Unknown"
                    
                    assets = z.get("num_assets", 0)
                    total_assets += assets

                    # Apply server-side filtering to save LLM context
                    if criticality_filter and clean_crit.lower() != criticality_filter.lower():
                        continue
                        
                    matching_assets += assets

                    if not summary_only:
                        formatted_zones.append({
                            "id": z.get("id", "N/A"),
                            "name": z.get("name", "Unknown"),
                            "criticality": clean_crit,
                            "asset_count": assets
                        })

                status = "PASS" if objects else "REVIEW"

                res = {
                    "status": status,
                    "total_zones": len(objects),
                    "matching_zones": len(formatted_zones) if not summary_only else len(objects),
                    "total_assets_in_all_zones": total_assets,
                    "assets_in_matching_zones": matching_assets
                }

                if not summary_only:
                    res["zones"] = formatted_zones

                return res

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to retrieve virtual zones: {str(e)}"}

        @mcp.tool()
        def get_zone_grouping_algorithm(
            site_id: str = "1"
        ) -> Dict[str, Any]:
            """
            Determine the algorithm CTD is using to automatically group assets into Virtual Zones.
            
            Args:
                site_id: CTD site ID identifier (default "1").
            """
            try:
                data = self.client.request("GET", "/ranger/virtual_zones_grouping_algorithm", params={"site_id": site_id})
                
                # Recursive search function to handle deeply nested algorithm payload structures
                def find_grouping(payload: Any) -> Optional[str]:
                    if isinstance(payload, dict):
                        for key in ["algorithm", "grouping_algorithm", "name", "value", "method"]:
                            if key in payload and payload[key]:
                                raw_val = str(payload[key]).lower()
                                return self.algorithm_mappings.get(raw_val, str(payload[key]).title())
                        for val in payload.values():
                            res = find_grouping(val)
                            if res:
                                return res
                    elif isinstance(payload, list):
                        for item in payload:
                            res = find_grouping(item)
                            if res:
                                return res
                    return None

                extracted_algorithm = find_grouping(data)

                if extracted_algorithm:
                    return {
                        "status": "PASS",
                        "active_grouping_algorithm": extracted_algorithm
                    }
                else:
                    return {
                        "status": "REVIEW",
                        "active_grouping_algorithm": "Unknown",
                        "error": "Could not parse algorithm from payload."
                    }

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to fetch zone grouping algorithm: {str(e)}"}

    def register_resources(self, mcp: FastMCP):
        pass