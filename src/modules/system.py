import datetime
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule


class SystemModule(BaseModule):
    """
    Unified interface for querying Claroty CTD system health, license status, 
    operational mode, and network interface configurations.
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
            method=self.get_system_overview, 
            name="get_system_overview",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
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

    def get_system_health(self) -> Dict[str, Any]:
        """Fetch host-level system performance metrics (CPU, RAM, and Disk storage partitions)."""
        # Hardcoded parameters to prevent LLM hesitation
        max_cpu_pct = 80.0
        max_ram_pct = 80.0
        max_disk_pct = 80.0

        try:
            # Primary endpoint attempt, fallback to secondary endpoint
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

            cpu_pct, ram_pct = None, None
            partitions = {}
            warnings = []

            if isinstance(system_factor, dict):
                info_block = system_factor.get("info", {})
                sys_status = info_block.get("system_status", {}) if isinstance(info_block, dict) else {}

                # Parse CPU & RAM
                raw_cpu = sys_status.get("cpu", {}).get("value") if isinstance(sys_status.get("cpu"), dict) else sys_status.get("cpu")
                raw_ram = sys_status.get("memory", {}).get("value") if isinstance(sys_status.get("memory"), dict) else sys_status.get("memory")
                
                try:
                    if raw_cpu is not None:
                        cpu_pct = float(str(raw_cpu).replace('%', ''))
                        if cpu_pct > max_cpu_pct:
                            warnings.append(f"CPU usage ({cpu_pct}%) exceeds threshold of {max_cpu_pct}%.")
                    
                    if raw_ram is not None:
                        ram_pct = float(str(raw_ram).replace('%', ''))
                        if ram_pct > max_ram_pct:
                            warnings.append(f"RAM usage ({ram_pct}%) exceeds threshold of {max_ram_pct}%.")
                except (ValueError, TypeError):
                    pass

                # Parse Disk Partitions
                disk_block = sys_status.get("disk", {})
                display_names = {
                    "os": "OS (/)",
                    "data": "Data (/var)",
                    "logs": "Logs (/var/log)",
                    "temp": "Temp (/tmp)",
                    "audit": "Audit (/var/log/audit)"
                }

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

            status = "WARNING" if warnings else "PASS"

            return {
                "status": status,
                "metrics": {
                    "cpu_pct": f"{cpu_pct}%" if cpu_pct is not None else "N/A",
                    "ram_pct": f"{ram_pct}%" if ram_pct is not None else "N/A",
                    "partitions": partitions if partitions else "No partitions parsed."
                },
                "warnings": warnings
            }

        except Exception as e:
            return {"status": "ERROR", "error": f"Failed to retrieve system health: {str(e)}"}

    def get_license_info(self) -> Dict[str, Any]:
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

                return {
                    "assessment_status": assessment,
                    "license_status": status_color.capitalize(),
                    "fips_enabled": is_fips,
                    "expiration_date": exp_date_str,
                    "days_remaining": days_left if days_left is not None else "N/A",
                    "machine_uuid": machine_uuid,
                    "warnings": warnings
                }
            else:
                return {"status": "ERROR", "error": "Unable to parse license response payload."}

        except Exception as e:
            return {"status": "ERROR", "error": f"Failed to fetch license info: {str(e)}"}

    def get_system_overview(self) -> Dict[str, Any]:
        """Fetch system software version numbers, applied threat intelligence bundle, and operational mode."""
        # Hardcoded parameters to prevent LLM hesitation
        site_id = "1"

        base_version = "Unknown"
        update_version = "Unknown"
        threat_bundle = "Unavailable"
        operational_mode = "Unknown"

        # 1. Base Version
        try:
            base_res = self.client.request("GET", "/ranger/current_version", params={"ids": site_id})
            bv_data = base_res.get("data", {})
            if isinstance(bv_data, dict):
                for v in bv_data.values():
                    if isinstance(v, dict) and "response" in v:
                        base_version = v["response"]
                        break
        except Exception:
            pass

        # 2. Update Version
        try:
            u_res = self.client.request("GET", "/ranger/current_update_version", params={"site_id": site_id})
            update_version = str(u_res.get("data", {}).get("update_version", "Unknown"))
        except Exception:
            pass

        # 3. Threat Bundle
        try:
            b_res = self.client.request("GET", "/ranger/ranger_api/last_date_of_update", params={"site_id__exact": site_id})
            threat_bundle = str(b_res.get("data", {}).get("bundle_id", "Unavailable"))
        except Exception:
            pass

        # 4. System Mode (Training vs Operational)
        try:
            mode_params = {"format": "site_list_slim", "sort": "name", "page": "1", "per_page": "0"}
            m_res = self.client.request("GET", "/ranger/sites", params=mode_params)
            if isinstance(m_res, dict) and m_res.get("objects"):
                is_training = m_res["objects"][0].get("training_mode")
                operational_mode = "Training" if is_training else "Operational"
        except Exception:
            pass

        return {
            "base_version": base_version,
            "update_version": update_version,
            "threat_bundle_id": threat_bundle,
            "operational_mode": operational_mode
        }

    def get_network_interfaces(self) -> Dict[str, Any]:
        """Retrieve server physical/virtual network interfaces and audit deep packet inspection (DPI) ingestion."""
        # Hardcoded parameters to prevent LLM hesitation
        site_id = "1"
        require_span_interface = True

        try:
            remote_name = None
            
            # Fetch remote location ID or fallback to machine UUID
            try:
                loc_res = self.client.request("GET", "/ranger/wizard/remote_locations", params={"site_id": site_id})
                if isinstance(loc_res, list) and len(loc_res) > 0:
                    remote_name = loc_res[0].get("id")
                elif isinstance(loc_res, dict) and loc_res.get("objects"):
                    remote_name = loc_res["objects"][0].get("id")
            except Exception:
                pass

            if not remote_name:
                lic_res = self.client.request("GET", "/ranger/license", params={"site_id": site_id})
                remote_name = lic_res.get("data", {}).get("machine_uuid", "072043d5-2ad1-5937-e26a-c5d0ec0b09ff")

            iface_res = self.client.request(
                "GET", 
                "/ranger/wizard/interfaces", 
                params={"remote_name": remote_name, "site_id": site_id}
            )
            iface_list = iface_res.get("data", []) if isinstance(iface_res, dict) else []

            formatted_ifaces = []
            has_ingestion = False

            for iface in iface_list:
                is_mgmt = iface.get("is_management", False)
                enabled = iface.get("enabled", False)
                
                if not is_mgmt and enabled:
                    has_ingestion = True

                formatted_ifaces.append({
                    "name": iface.get("name", "N/A"),
                    "ip": iface.get("ip", "N/A"),
                    "mac": iface.get("mac", "N/A"),
                    "process_data_enabled": enabled,
                    "is_management": is_mgmt
                })

            warnings = []
            if require_span_interface and not has_ingestion:
                warnings.append("No active data-ingestion (DPI) interfaces detected. Ensure SPAN/mirror traffic is mapped.")

            return {
                "status": "WARNING" if warnings else "PASS",
                "interface_count": len(formatted_ifaces),
                "interfaces": formatted_ifaces,
                "span_ingestion_active": has_ingestion,
                "warnings": warnings
            }

        except Exception as e:
            return {"status": "ERROR", "error": f"Failed to fetch interface configuration: {str(e)}"}