import ipaddress
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule

class NetworkModule(BaseModule):
    """Interface for network topology, subnets, profiles, and collection sensors."""

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(server=server, method=self.get_subnets, name="get_subnets", annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
        self._add_tool(server=server, method=self.get_network_profiles, name="get_network_profiles", annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
        self._add_tool(server=server, method=self.get_sensor_status, name="get_sensor_status", annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))

    def get_subnets(self) -> str:
        """Retrieve subnets discovered by CTD and audit for RFC-1918 compliance."""
        try:
            params = {
                'sort': "name",
                'page': "1", 
                'per_page': "50", 
                'with_assets__exact': "true", 
                'site_id__exact': "1", 
            }
            
            type_map = {0: "Internal", 1: "External"}
            data = self.client.request("GET", "/ranger/subnets", params=params)
            objects = data.get("objects", [])

            if not objects:
                return "No subnet data objects found."

            output = ["### Subnet Topology Summary"]
            warnings = []
            
            for item in objects:
                subnet_ip = item.get("name") or "Unknown"
                network = item.get("network_name") or "N/A"
                assets = item.get("assets_count") or 0
                subnet_type = type_map.get(item.get("type"), "Unknown")
                subnet_id = item.get("resource_id") or "N/A"
                
                output.append(f"* **{subnet_ip}** | Network: {network} | Type: {subnet_type} | Assets: {assets} | ID: {subnet_id}")

                # RFC-1918 Compliance Check
                try:
                    if subnet_ip and subnet_ip != "Unknown":
                        net = ipaddress.ip_network(subnet_ip, strict=False)
                        if not net.is_private and not net.is_link_local:
                            warnings.append(f"Public IP used internally (Flagged: {subnet_ip})")
                except ValueError:
                    pass

            if warnings:
                output.append("\n**Compliance Warnings (RFC-1918):**")
                for w in warnings:
                    output.append(f"* ⚠️ {w}")

            return "\n".join(output)
        except Exception as e:
            return f"Error retrieving subnets: {str(e)}"

    def get_network_profiles(self) -> str:
        """Audit Network Profiles for security baseline features (Known Threats & PCAP)."""
        try:
            params = {'sort': "name", 'page': "1", 'per_page': "100"}
            data = self.client.request("GET", "/ranger/networks", params=params)
            objects = data.get("objects", [])
            
            if not objects:
                return "No configured network profiles discovered."

            output = ["### Network Profiles Audit"]
            warnings = []

            for item in objects:
                name = item.get("name", "Unknown")
                known_threats = item.get("use_known_threats", True)
                save_caps = item.get("save_caps", False)

                if not known_threats:
                    warnings.append(f"Threat Detection is disabled on network profile '{name}'.")

                output.append(f"* **{name}** | Known Threats: {'Enabled' if known_threats else 'Disabled'} | PCAP: {'Enabled' if save_caps else 'Disabled'}")

            if warnings:
                output.append("\n**Security Warnings:**")
                for w in warnings:
                    output.append(f"* ⚠️ {w}")
            else:
                output.append("\n**Status:** PASS (All profiles comply with Threat Detection baseline)")

            return "\n".join(output)
        except Exception as e:
            return f"Error auditing network profiles: {str(e)}"

    def get_sensor_status(self) -> str:
        """Check health and connectivity status of Claroty edge sensors."""
        try:
            data = self.client.request("GET", "/ranger/system/check", params={"site_id": "1"})
            parents = data.get("data", {}).get("statuses", {}).get("parents", [])
            
            if not parents:
                return "No collection sensors are currently connected to this site."

            output = ["### Collection Sensors Status"]
            warnings = []

            for p in parents:
                name = p.get("name", "Unknown")
                addr = p.get("address", "N/A")
                is_conn = p.get("is_connected", False)
                
                output.append(f"* **{name}** | IP: {addr} | Connected: {is_conn}")

                if not is_conn:
                    warnings.append(f"Sensor '{name}' ({addr}) is offline.")

            if warnings:
                output.append("\n**Connectivity Warnings:**")
                for w in warnings:
                    output.append(f"* ⚠️ {w}")
            else:
                output.append("\n**Status:** PASS (All sensors online)")

            return "\n".join(output)
        except Exception as e:
            return f"Error checking sensors: {str(e)}"