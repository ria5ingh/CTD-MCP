import datetime
import json
import ipaddress
from typing import Any
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule


class SystemModule(BaseModule):
    """
    Unified interface for querying Claroty CTD system health, license status, 
    operational mode, network configurations, and subnets.
    """

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(
            server=server, 
            method=self.get_system_health, 
            name="get_system_health",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_license_info, 
            name="get_license_info",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_system_version, 
            name="get_system_version",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_sensor_status, 
            name="get_sensor_status", 
            annotations=ToolAnnotations(
                readOnlyHint=True, 
                destructiveHint=False, 
                idempotentHint=True, 
                openWorldHint=False
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_subnets, 
            name="get_subnets", 
            annotations=ToolAnnotations(
                readOnlyHint=True, 
                destructiveHint=False, 
                idempotentHint=True, 
                openWorldHint=False
            )
        )
        
        self._add_tool(
            server=server, 
            method=self.get_networks, 
            name="get_networks", 
            annotations=ToolAnnotations(
                readOnlyHint=True, 
                destructiveHint=False, 
                idempotentHint=True, 
                openWorldHint=False
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_network_interfaces, 
            name="get_network_interfaces",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register the System resources with the MCP Server."""
        super().register_resources(server)

    def get_system_health(self) -> str:
        """Fetch host-level system performance metrics (CPU, RAM, and Disk storage partitions)."""
        # Hardcoded thresholds based on CTD Wizard defaults to prevent LLM hesitation
        max_cpu_pct = 80.0
        max_ram_pct = 80.0
        max_disk_pct = 80.0

        try:
            try:
                payload = self.client.request("GET", "/ranger/system_health")
            except Exception:
                payload = self.client.request("GET", "/ranger/ranger_api/system_health")

            data_block = payload.get("data", {}) if isinstance(payload, dict) else {}
            site_data = next((v for v in data_block.values() if isinstance(v, dict) and "factors" in v), {})
            
            factors = site_data.get("factors")
            system_factor = None
            
            if isinstance(factors, dict):
                system_factor = factors.get("application_health", {}).get("system_status") or factors.get("system_status")
            elif isinstance(factors, list):
                system_factor = next((f for f in factors if isinstance(f, dict) and f.get("type") == "system_status"), None)

            cpu_pct, ram_pct = "N/A", "N/A"
            partitions = {}
            warnings = []

            if isinstance(system_factor, dict):
                info_block = system_factor.get("info", {})
                sys_status = info_block.get("system_status", {}) if isinstance(info_block, dict) else {}

                raw_cpu = sys_status.get("cpu", {}).get("value") if isinstance(sys_status.get("cpu"), dict) else sys_status.get("cpu")
                raw_ram = sys_status.get("memory", {}).get("value") if isinstance(sys_status.get("memory"), dict) else sys_status.get("memory")
                
                try:
                    if raw_cpu is not None:
                        cpu_float = float(str(raw_cpu).replace('%', ''))
                        cpu_pct = f"{cpu_float}%"
                        if cpu_float > max_cpu_pct:
                            warnings.append(f"CPU usage ({cpu_pct}) exceeds threshold of {max_cpu_pct}%.")
                    
                    if raw_ram is not None:
                        ram_float = float(str(raw_ram).replace('%', ''))
                        ram_pct = f"{ram_float}%"
                        if ram_float > max_ram_pct:
                            warnings.append(f"RAM usage ({ram_pct}) exceeds threshold of {max_ram_pct}%.")
                except (ValueError, TypeError):
                    pass

                disk_block = sys_status.get("disk", {})
                display_names = {"os": "OS (/)", "data": "Data (/var)", "logs": "Logs (/var/log)", "temp": "Temp (/tmp)", "audit": "Audit (/var/log/audit)"}

                if isinstance(disk_block, dict):
                    for key, part in disk_block.items():
                        if isinstance(part, dict):
                            name = display_names.get(key, f"Partition ({key})")
                            pct = part.get("percentage") if "percentage" in part else (
                                round((part.get("used", 0) / part.get("total", 1)) * 100, 2)
                                if part.get("total", 0) > 0 else None
                            )
                            if pct is not None:
                                partitions[name] = f"{pct}%"
                                if pct > max_disk_pct:
                                    warnings.append(f"Storage {name} ({pct}%) exceeds threshold of {max_disk_pct}%.")

            # Format as Markdown for LLM compatibility
            output = ["### System Health Summary"]
            output.append(f"**Status:** {'WARNING' if warnings else 'PASS'} | ")
            output.append(f"**CPU Usage:** {cpu_pct} | ")
            output.append(f"**RAM Usage:** {ram_pct}")
            
            output.append("\n**Disk Partitions:**")
            if partitions:
                for name, pct in partitions.items():
                    output.append(f"* {name}: {pct}")
            else:
                output.append("* No partition data available.")
                
            if warnings:
                output.append("\n**Warnings:**")
                for w in warnings:
                    output.append(f"* ⚠️ {w}")
                    
            return "\n".join(output)

        except Exception as e:
            return f"Error retrieving system health: {str(e)}"

    def get_license_info(self) -> str:
        """Retrieve Claroty CTD license details, FIPS operational status, and expiration limits."""
        # Hardcoded parameters to prevent LLM hesitation
        site_id = "1"
        warning_days = 14

        try:
            lic_data = self.client.request("GET", "/ranger/license", params={"site_id": site_id})
            
            if isinstance(lic_data, dict) and lic_data.get("success"):
                info = lic_data.get("data", {})
                status_color = info.get("status", "unknown").lower()
                is_fips = info.get("is_fips", False)
                exp_date_str = info.get("expiration_date")
                machine_uuid = info.get("machine_uuid", "N/A")

                days_left = None
                warnings = []
                assessment = "PASS" if status_color == "green" else "FAIL"

                if exp_date_str:
                    exp_date = datetime.datetime.strptime(exp_date_str[:10], "%Y-%m-%d").date()
                    days_left = (exp_date - datetime.date.today()).days
                    if days_left <= warning_days:
                        assessment = "WARNING"
                        warnings.append(f"License expires in {days_left} days! Renewal recommended.")

                output = [
                    "### License Information",
                    f"**Overall Status:** {assessment} | ",
                    f"**License State:** {status_color.capitalize()} |",
                    f"**FIPS Enabled:** {is_fips} |",
                    f"**Expiration Date:** {exp_date_str} |",
                    f"**Days Remaining:** {days_left if days_left is not None else 'N/A'} |",
                    f"**Machine UUID:** {machine_uuid}"
                ]
                
                if warnings:
                    output.append("\n**Warnings:**")
                    for w in warnings:
                        output.append(f"* ⚠️ {w}")
                        
                return "\n".join(output)
            else:
                return "Error: Unable to parse license response payload."

        except Exception as e:
            return f"Error fetching license info: {str(e)}"

    def get_system_version(self) -> str:
        """Fetch system software version numbers, applied threat intelligence bundle, and operational mode."""
        site_id = "1"

        base_version, update_version, threat_bundle, operational_mode = "Unknown", "Unknown", "Unavailable", "Unknown"

        try:
            base_res = self.client.request("GET", "/ranger/current_version", params={"ids": site_id})
            if isinstance(base_res.get("data", {}), dict):
                for v in base_res["data"].values():
                    if isinstance(v, dict) and "response" in v:
                        base_version = v["response"]
                        break
        except Exception: pass

        try:
            u_res = self.client.request("GET", "/ranger/current_update_version", params={"site_id": site_id})
            update_version = str(u_res.get("data", {}).get("update_version", "Unknown"))
        except Exception: pass

        try:
            b_res = self.client.request("GET", "/ranger/ranger_api/last_date_of_update", params={"site_id__exact": site_id})
            threat_bundle = str(b_res.get("data", {}).get("bundle_id", "Unavailable"))
        except Exception: pass

        try:
            m_res = self.client.request("GET", "/ranger/sites", params={"format": "site_list_slim", "sort": "name", "page": "1", "per_page": "0"})
            if isinstance(m_res, dict) and m_res.get("objects"):
                operational_mode = "Training" if m_res["objects"][0].get("training_mode") else "Operational"
        except Exception: pass

        output = [
            "### System Versioning Information",
            f"**Base Version:** {base_version} | **Update Version:** {update_version} | **Threat Bundle ID:** {threat_bundle} | **Operational Mode:** {operational_mode}"
        ]
        return "\n".join(output)

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
                
                output.append(f"* Name: **{name}** | IP: {addr} | Connected: {is_conn}")

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

    def get_networks(self) -> str:
        """Audit Networks for security baseline features (Known Threats & PCAP)."""
        try:
            params = {'sort': "name", 'page': "1", 'per_page': "100"}
            data = self.client.request("GET", "/ranger/networks", params=params)
            objects = data.get("objects", [])
            
            if not objects:
                return "No configured networks discovered."

            output = ["### Networks Audit"]
            warnings = []

            for item in objects:
                name = item.get("name", "Unknown")
                known_threats = item.get("use_known_threats", True)
                save_caps = item.get("save_caps", False)

                if not known_threats:
                    warnings.append(f"Threat Detection is disabled on network '{name}'.")

                output.append(f"* **{name}** | Known Threats: {'Enabled' if known_threats else 'Disabled'} | PCAP: {'Enabled' if save_caps else 'Disabled'}")

            if warnings:
                output.append("\n**Security Warnings:**")
                for w in warnings:
                    output.append(f"* ⚠️ {w}")
            else:
                output.append("\n**Status:** PASS (All networks comply with Threat Detection baseline)")

            return "\n".join(output)
        except Exception as e:
            return f"Error auditing networks: {str(e)}"

    def get_network_interfaces(self) -> str:
        """Retrieve server physical/virtual network interfaces and audit deep packet inspection (DPI) ingestion."""
        site_id = "1"
        require_span_interface = True

        try:
            remote_name = None
            try:
                loc_res = self.client.request("GET", "/ranger/wizard/remote_locations", params={"site_id": site_id})
                if isinstance(loc_res, list) and len(loc_res) > 0: remote_name = loc_res[0].get("id")
                elif isinstance(loc_res, dict) and loc_res.get("objects"): remote_name = loc_res["objects"][0].get("id")
            except Exception: pass

            if not remote_name:
                lic_res = self.client.request("GET", "/ranger/license", params={"site_id": site_id})
                remote_name = lic_res.get("data", {}).get("machine_uuid", "072043d5-2ad1-5937-e26a-c5d0ec0b09ff")

            iface_list = self.client.request("GET", "/ranger/wizard/interfaces", params={"remote_name": remote_name, "site_id": site_id}).get("data", [])
            
            has_ingestion = False
            output = ["### Network Interfaces"]
            
            for iface in iface_list:
                is_mgmt = iface.get("is_management", False)
                enabled = iface.get("enabled", False)
                if not is_mgmt and enabled: has_ingestion = True
                
                output.append(f"* **{iface.get('name', 'N/A')}** | IP: {iface.get('ip', 'N/A')} | MAC: {iface.get('mac', 'N/A')} | Process Data: {enabled} | Mgmt: {is_mgmt}")

            warnings = []
            if require_span_interface and not has_ingestion:
                warnings.append("No active data-ingestion (DPI) interfaces detected. Ensure SPAN/mirror traffic is mapped.")

            output.insert(1, f"**Status:** {'WARNING' if warnings else 'PASS'}\n**SPAN Ingestion Active:** {has_ingestion}\n")
            
            if warnings:
                output.append("\n**Warnings:**")
                for w in warnings: output.append(f"* ⚠️ {w}")

            return "\n".join(output)
        except Exception as e:
            return f"Error fetching interface configuration: {str(e)}"