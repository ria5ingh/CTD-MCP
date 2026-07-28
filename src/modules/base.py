# src/modules/base.py
import inspect
import json
from typing import Callable, Any
from pydantic import create_model, Field
from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient

from src.resources.common import COMMON_SCHEMA_URI, COMMON_SCHEMA_DOCS

# Global Registry for Dynamic Mode
# Format: { "module_name": { "tool_name": { "func": Callable, "schema_model": BaseModel, "schema_json": dict, "description": str } } }
DYNAMIC_REGISTRY: dict[str, dict[str, dict[str, Any]]] = {}

class BaseModule:
    _common_tool_registered = False
    _common_resource_registered = False

    def __init__(self, client: CTDClient) -> None:
        self.client = client
        self.tools: list[str] = []       
        self.resources: list[str] = []   
        
        # Auto-derive module bucket name from class name (e.g. "AssetsModule" -> "assets")
        self.module_name = self.__class__.__name__.replace("Module", "").lower()
        if self.module_name not in DYNAMIC_REGISTRY:
            DYNAMIC_REGISTRY[self.module_name] = {}

    def register_tools(self, server: FastMCP) -> None:
        if not BaseModule._common_tool_registered:
            self._add_tool(
                server=server,
                method=self.get_common_schema,
                name="get_common_schema"
            )
            BaseModule._common_tool_registered = True

    def register_resources(self, server: FastMCP) -> None:
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
        Intercepts tool registration, extracts method type hints/descriptions,
        and saves the tool schema to the dynamic registry.
        """
        prefixed_name = f"ctd_{name}"

        # Inspect signature to dynamically extract Pydantic fields
        sig = inspect.signature(method)
        fields = {}
        
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
            
            annotation = param.annotation if param.annotation != inspect.Parameter.empty else Any
            
            # Check for Pydantic Field default vs standard default vs required parameter
            if hasattr(param.default, "default"):
                fields[param_name] = (annotation, param.default)
            elif param.default != inspect.Parameter.empty:
                fields[param_name] = (annotation, param.default)
            else:
                fields[param_name] = (annotation, ...)

        # Create a dynamic Pydantic model for parameter validation
        schema_model = create_model(f"{name}_Model", **fields)
        
        # Save tool metadata to the registry
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

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
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

        # SCENARIO A: It's a list of dictionaries -> Build a Markdown Table
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
                    
                    # Escape pipes and newlines so they don't break the markdown table format
                    safe_val = str(val).replace("|", "\\|").replace("\n", " ")
                    row_vals.append(safe_val)
                    
                rows.append("| " + " | ".join(row_vals) + " |")
                
            return "\n".join([header_row, separator] + rows)

        # SCENARIO B: It's a single dictionary -> Build a Bulleted List
        elif isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    formatted_val = f"`{json.dumps(value, separators=(',', ':'))}`"
                else:
                    formatted_val = str(value).replace("\n", " ")
                lines.append(f"- **{key}**: {formatted_val}")
            return "\n".join(lines)

        # SCENARIO C: It's a flat list of strings/numbers -> Build a simple list
        elif isinstance(data, list):
            return "\n".join(f"- {item}" for item in data)
            
        # SCENARIO D: Fallback for raw strings/ints
        else:
            return str(data)

    