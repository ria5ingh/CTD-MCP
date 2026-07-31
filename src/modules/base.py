# src/modules/base.py
import sys
import os
import inspect
import json
from typing import Callable, Any
from pydantic import create_model, Field
from dotenv import load_dotenv

from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient
from src.resources.common import COMMON_SCHEMA_URI, COMMON_SCHEMA_DOCS

# ==========================================
# MODE TOGGLE
# Checks for the "--dynamic" CLI flag (if running in mcpo)
# ==========================================


load_dotenv()
USE_DYNAMIC_MODE = (
    "--dynamic" in sys.argv or 
    os.getenv("USE_DYNAMIC_MODE", "False").lower() in ("true")
)

# UNCOMMENT TO RUN WITH OLLMCP
# USE_DYNAMIC_MODE = True

# Global Registry for Dynamic Mode
# Format: { "module_name": { "tool_name": { "func": Callable, "schema_model": BaseModel, "schema_json": dict, "description": str } } }
DYNAMIC_REGISTRY: dict[str, dict[str, dict[str, Any]]] = {}

# Default Annotations for Read-Only Tools (Normal Mode)
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False, #CTD is closed
)

class BaseModule:
    # Class-level flags shared across all module instances
    _common_tool_registered = False
    _common_resource_registered = False

    def __init__(self, client: CTDClient) -> None:
        """Initializes the base module with a shared Claroty CTD API client."""
        self.client = client
        self.tools: list[str] = []       # Tracks registered tool names
        self.resources: list[str] = []   # Tracks registered resource URIs
        
        # Auto-derive module bucket name for Dynamic Mode (e.g. "AssetsModule" -> "assets")
        if USE_DYNAMIC_MODE:
            self.module_name = self.__class__.__name__.replace("Module", "").lower()
            if self.module_name not in DYNAMIC_REGISTRY:
                DYNAMIC_REGISTRY[self.module_name] = {}

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
                mime_type="text/markdown",
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
        """
        Registers a tool. Behavior changes based on USE_DYNAMIC_MODE flag.
        - Dynamic: Intercepts registration, extracts metadata, saves to registry.
        - Normal: Directly registers to the MCP server.
        """
        prefixed_name = f"ctd_{name}"

        if USE_DYNAMIC_MODE:
            # --- DYNAMIC MODE REGISTRATION ---
            sig = inspect.signature(method)
            fields = {}
            
            for param_name, param in sig.parameters.items():
                if param_name == "self":
                    continue
                
                annotation = param.annotation if param.annotation != inspect.Parameter.empty else Any
                
                if hasattr(param.default, "default"):
                    fields[param_name] = (annotation, param.default)
                elif param.default != inspect.Parameter.empty:
                    fields[param_name] = (annotation, param.default)
                else:
                    fields[param_name] = (annotation, ...)

            schema_model = create_model(f"{name}_Model", **fields)
            
            DYNAMIC_REGISTRY[self.module_name][prefixed_name] = {
                "func": method,
                "schema_model": schema_model,
                "schema_json": schema_model.model_json_schema(),
                "description": method.__doc__ or f"Tool to execute {prefixed_name}",
                "annotations": {
                    "readOnlyHint": annotations.readOnlyHint if annotations else True,
                    "destructiveHint": annotations.destructiveHint if annotations else False,
                    "idempotentHint": annotations.idempotentHint if annotations else True,
                    "openWorldHint": annotations.openWorldHint if annotations else False,
                }
            }
            self.tools.append(prefixed_name)

        else:
            # --- NORMAL MODE REGISTRATION ---
            server.add_tool(
                method,
                name=prefixed_name,
                annotations=annotations or READ_ONLY_ANNOTATIONS,
                structured_output=False,
            )
            self.tools.append(prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        """Programmatically registers an MCP Resource object with the server."""
        server.add_resource(resource=resource)
        self.resources.append(str(resource.uri))

    def get_common_schema(self) -> str:
        """Retrieve the shared schema containing common info across multiple tools (asset type IDs, return fields, and insight names)."""
        return COMMON_SCHEMA_DOCS

    @staticmethod
    def _format_to_markdown(data: Any) -> str:
        """
        Dynamically converts JSON-like data (dicts or lists of dicts) into clean Markdown.
        Agnostic to specific keys. Nested objects are safely stringified.
        """
        if not data:
            return "No data returned."

        if isinstance(data, list) and all(isinstance(i, dict) for i in data):
            if not data:
                return "Empty list."
            
            headers = []
            for item in data:
                for key in item.keys():
                    if key not in headers:
                        headers.append(key)
            
            header_row = "| " + " | ".join(str(h) for h in headers) + " |"
            separator = "|" + "|".join(["---"] * len(headers)) + "|"
            
            rows = []
            for item in data:
                row_vals = []
                for h in headers:
                    val = item.get(h, "")
                    if isinstance(val, (dict, list)):
                        val = f"`{json.dumps(val, separators=(',', ':'))}`"
                    safe_val = str(val).replace("|", "\\|").replace("\n", " ")
                    row_vals.append(safe_val)
                    
                rows.append("| " + " | ".join(row_vals) + " |")
                
            return "\n".join([header_row, separator] + rows)

        elif isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    formatted_val = f"`{json.dumps(value, separators=(',', ':'))}`"
                else:
                    formatted_val = str(value).replace("\n", " ")
                lines.append(f"- **{key}**: {formatted_val}")
            return "\n".join(lines)

        elif isinstance(data, list):
            return "\n".join(f"- {item}" for item in data)
            
        else:
            return str(data)