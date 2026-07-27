from typing import Callable, Any
from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient

from src.resources.common import COMMON_SCHEMA_URI, COMMON_SCHEMA_DOCS

# Default Annotations for Read-Only Tools
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False, #CTD is closed
)

class BaseModule:
    #class-level flags shared across all module instances
    _common_tool_registered = False
    _common_resource_registered = False

    def __init__(self, client: CTDClient) -> None:
        """
        Initializes the base module with a shared Claroty CTD API client.
        """
        self.client = client
        self.tools: list[str] = []       # Tracks registered tool names
        self.resources: list[str] = []   # Tracks registered resource URIs

    def register_tools(self, server: FastMCP) -> None:
        """
        Registers shared base tools. 
        Child modules MUST call super().register_tools(server) when adding more tools.
        """
        if not BaseModule._common_tool_registered:
            self._add_tool(
                server=server,
                method=self.get_common_schema,
                name="get_common_schema",
                annotations=READ_ONLY_ANNOTATIONS
            )
            BaseModule._common_tool_registered = True

    def register_resources(self, server: FastMCP) -> None:
        """
        Registers shared base resources.
        Child modules should call super().register_resources(server) when overriding.
        """
        if not BaseModule._common_resource_registered:
            resource = Resource(
                uri=COMMON_SCHEMA_URI,
                name="CTD Common Schema",
                description="Shared enums and return fields used across multiple tools.",
                mimeType="text/markdown",
                text=COMMON_SCHEMA_DOCS
            )
            self._add_resource(server, resource)
            BaseModule._common_resource_registered = True

    def _add_tool(
        self, 
        server: FastMCP, 
        method: Callable[..., Any], 
        name: str,
        annotations: ToolAnnotations | None = None
    ) -> None:
        """Programmatically registers a class method as an MCP tool using add_tool."""
        prefixed_name = f"ctd_{name}"
        server.add_tool(
            method,
            name=prefixed_name,
            annotations=annotations or READ_ONLY_ANNOTATIONS,
            structured_output=False,
        )
        self.tools.append(prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        """
        Programmatically registers an MCP Resource object with the server.
        """
        server.add_resource(resource=resource)
        
        resource_uri = resource.uri
        self.resources.append(str(resource_uri))

    def get_common_schema(self) -> str:
        """Retrieve the shared schema containing common info across multiple tools (asset type IDs, return fields, and insight names)."""
        return COMMON_SCHEMA_DOCS