import os
import sys
import json
import inspect
from typing import Callable, Any
from pydantic import create_model, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient
from src.resources.common import COMMON_SCHEMA_URI, COMMON_SCHEMA_DOCS

# 1. Check for CLI flag (mcpo / Open WebUI) --> passing"--dynamic" will override the config and set it to TRUE no matter what the setting is.
cli_flag = False
if "--dynamic" in sys.argv:
    cli_flag = True
    sys.argv.remove("--dynamic")

# 2. Silently Check for Config File (ollmcp)
current_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.abspath(os.path.join(current_dir, "../../mcp_config.json"))

config_flag = False
config_data = {}

if os.path.exists(config_path):
    try:
        with open(config_path, "r") as f:
            config_data = json.load(f)
            # Support both flat and nested JSON structures
            if "SERVER_MODE" in config_data:
                config_flag = bool(config_data["SERVER_MODE"].get("USE_DYNAMIC_MODE", False))
            else:
                config_flag = bool(config_data.get("USE_DYNAMIC_MODE", False))
    except Exception:
        pass  # SILENT FAIL: Print statements corrupt MCP stdout

USE_DYNAMIC_MODE = cli_flag or config_flag

# Global Registry for Dynamic Mode
DYNAMIC_REGISTRY: dict[str, dict[str, dict[str, Any]]] = {}

# Default Annotations for Read-Only Tools
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False, 
)

class BaseModule:
    _common_tool_registered = False
    _common_resource_registered = False

    def __init__(self, client: CTDClient) -> None:
        self.client = client
        self.tools: list[str] = []       
        self.resources: list[str] = []   
        
        if USE_DYNAMIC_MODE:
            self.module_name = self.__class__.__name__.replace("Module", "").lower()
            if self.module_name not in DYNAMIC_REGISTRY:
                DYNAMIC_REGISTRY[self.module_name] = {}

    def register_tools(self, server: FastMCP) -> None:
        if not BaseModule._common_tool_registered:
            self._add_tool(
                server=server,
                method=self.get_common_schema,
                name="get_common_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
            )
            BaseModule._common_tool_registered = True

    def register_resources(self, server: FastMCP) -> None:
        if not BaseModule._common_resource_registered:
            resource = Resource(
                uri=AnyUrl(COMMON_SCHEMA_URI),
                name="ctd_common_schema",
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
        prefixed_name = f"ctd_{name}"

        if USE_DYNAMIC_MODE:
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

            schema_model = create_model(name, **fields)
            
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
            server.add_tool(
                method,
                name=prefixed_name,
                annotations=annotations or READ_ONLY_ANNOTATIONS,
                structured_output=False,
            )
            self.tools.append(prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        server.add_resource(resource=resource)
        self.resources.append(str(resource.uri))

    def get_common_schema(self) -> str:
        return COMMON_SCHEMA_DOCS

    @staticmethod
    def _format_to_markdown(data: Any) -> str:
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