from pydantic import AnyUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations

from src.client import CTDClient
from src.modules.base import BaseModule

# Import the baseline and documentation from your new resources file
from src.resources.protocols import FEDERAL_GOLDEN_BASELINE, PROTOCOLS_BASELINE_DOCS

class ProtocolsModule(BaseModule):
    """Interface for Deep Packet Inspection (DPI) protocols and drift analysis."""
    
    def __init__(self, client: CTDClient):
        super().__init__(client)
        # Point to the imported dictionary instead of hardcoding it
        self.default_protocols = FEDERAL_GOLDEN_BASELINE

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)
        self._add_tool(
            server=server, 
            method=self.audit_protocol_drift, 
            name="audit_protocol_drift", 
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register the Protocols baseline resources with the MCP Server."""
        super().register_resources(server)
        
        resource = TextResource(
            uri=AnyUrl("resource://ctd/protocols/baseline"),
            name="federal_golden_baseline_protocols",
            description="A complete list of which DPI protocols should be Enabled or Disabled according to the Federal Golden Baseline.",
            text=PROTOCOLS_BASELINE_DOCS, 
            mime_type="text/markdown"
        )
        
        self._add_resource(server, resource)

    def audit_protocol_drift(self) -> str:
        """Compare live DPI protocol configurations against the federal Golden Baseline to identify drift."""
        try:
            proto_data = self.client.request("GET", "/ranger/ranger_api/protocols", params={"site_id": "1"})
            if not proto_data.get("success"):
                return "Error: Failed to retrieve protocol data from CTD."

            proto_master_list = []
            drifted_protocols = []

            for proto in proto_data.get("data", []):
                name = proto.get("name", "Unknown")
                is_en = proto.get("is_enabled")
                proto_master_list.append((name, is_en))
                
                if name in self.default_protocols:
                    if is_en != self.default_protocols[name]:
                        drifted_protocols.append(f"'{name}' (Live: {is_en}, Default: {self.default_protocols[name]})")

            proto_master_list.sort(key=lambda x: x[0].lower())

            output = [
                "### DPI Protocols Audit & Drift Analysis",
                "*Legend: `+` = Enabled | `x` = Disabled*\n"
            ]

            if drifted_protocols:
                output.append("**Protocol Drift Detected (Review Required):**")
                for dp in drifted_protocols:
                    output.append(f"* ⚠️ {dp}")
                output.append("")
            else:
                output.append("**Status:** PASS (System perfectly matches baseline configuration)\n")

            output.append("**Full Protocol State:**")
            for name, is_en in proto_master_list:
                output.append(f"* {'+' if is_en else 'x'} {name}")

            return "\n".join(output)
        except Exception as e:
            return f"Error auditing protocol drift: {str(e)}"