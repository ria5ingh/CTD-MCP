from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient


class NetworkModule:
    def __init__(self, client: CTDClient):
        self.client = client

    def register_tools(self, mcp: FastMCP):

        @mcp.tool()
        def get_subnets(
            site_id: str = "1",
            type_filter: Optional[str] = None,
            summary_only: bool = False,
            page: int = 1,
            per_page: int = 50
        ) -> Dict[str, Any]:
            """
            Retrieve subnets discovered by CTD.
            
            Args:
                site_id: CTD site ID identifier (default "1").
                type_filter: Filter results by classification: "Internal" or "External".
                summary_only: If True, returns only status, counts, and warnings to save tokens.
                page: Page number for pagination (default 1).
                per_page: Items per page (default 50).
            """
            try:
                params = {
                    "sort": "name",
                    "page": str(page),
                    "per_page": str(per_page),
                    "with_assets__exact": "true",
                    "site_id__exact": site_id,
                    "distinct": "false"
                }

                type_map = {0: "Internal", 1: "External"}
                data = self.client.request("GET", "/ranger/subnets", params=params)
                objects = data.get("objects", [])

                formatted = []
                total_assets = 0

                for item in objects:
                    raw_type = item.get("type")
                    subnet_type = type_map.get(raw_type, "Unknown")
                    
                    if type_filter and subnet_type.lower() != type_filter.lower():
                        continue

                    assets = item.get("num_assets") or item.get("assets_count") or 0
                    total_assets += assets

                    if not summary_only:
                        formatted.append({
                            "subnet": item.get("name") or item.get("subnet") or "Unknown",
                            "network": item.get("network_name") or item.get("network") or "N/A",
                            "type": subnet_type,
                            "assets": assets
                        })

                res = {
                    "status": "PASS" if objects else "REVIEW",
                    "total_subnets": len(objects),
                    "matching_subnets": len(formatted) if not summary_only else len(objects),
                    "total_assets": total_assets
                }

                if not summary_only:
                    res["subnets"] = formatted

                return res

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to retrieve subnets: {str(e)}"}

        @mcp.tool()
        def get_network_profiles(
            page: int = 1,
            per_page: int = 100,
            warnings_only: bool = False,
            summary_only: bool = False
        ) -> Dict[str, Any]:
            """
            Audit Network Profiles for security baseline features (Known Threats & PCAP).
            
            Args:
                page: Page number (default 1).
                per_page: Items per page (default 100).
                warnings_only: If True, returns only network profiles with disabled threat detection.
                summary_only: If True, returns status and warning counts without profile lists.
            """
            try:
                params = {"sort": "name", "page": str(page), "per_page": str(per_page)}
                data = self.client.request("GET", "/ranger/networks", params=params)
                
                objects = data.get("objects", [])
                networks = []
                warnings = []

                for item in objects:
                    name = item.get("name", "Unknown")
                    known_threats = item.get("use_known_threats", True)
                    save_caps = item.get("save_caps", False)

                    if not known_threats:
                        warnings.append(f"Threat Detection disabled on '{name}'.")

                    if warnings_only and known_threats:
                        continue

                    if not summary_only:
                        networks.append({
                            "id": item.get("id"),
                            "name": name,
                            "known_threats": known_threats,
                            "pcap_enabled": save_caps
                        })

                status = "PASS" if not warnings else "WARNING"
                if not objects:
                    status = "REVIEW"

                res = {
                    "status": status,
                    "total_networks": len(objects),
                    "warnings": warnings
                }

                if not summary_only:
                    res["networks"] = networks

                return res

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to audit network profiles: {str(e)}"}

        @mcp.tool()
        def get_sensor_status(
            site_id: str = "1",
            summary_only: bool = False
        ) -> Dict[str, Any]:
            """
            Check health and connectivity status of Claroty edge sensors.
            
            Args:
                site_id: CTD site ID identifier (default "1").
                summary_only: If True, returns overall connectivity count and status without full list.
            """
            try:
                data = self.client.request("GET", "/ranger/system/check", params={"site_id": site_id})
                parents = data.get("data", {}).get("statuses", {}).get("parents", [])
                
                sensors = []
                warnings = []
                connected_count = 0

                for p in parents:
                    name = p.get("name", "Unknown")
                    addr = p.get("address", "N/A")
                    is_conn = p.get("is_connected", False)

                    if is_conn:
                        connected_count += 1
                    else:
                        warnings.append(f"Sensor '{name}' ({addr}) is offline.")

                    if not summary_only:
                        sensors.append({
                            "name": name,
                            "ip": addr,
                            "connected": is_conn
                        })

                status = "PASS"
                if not parents:
                    status = "REVIEW"
                    warnings.append("No collection sensors attached.")
                elif warnings:
                    status = "FAIL"

                res = {
                    "status": status,
                    "total_sensors": len(parents),
                    "online_sensors": connected_count,
                    "warnings": warnings
                }

                if not summary_only:
                    res["sensors"] = sensors

                return res

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to check sensors: {str(e)}"}

    def register_resources(self, mcp: FastMCP):
        pass