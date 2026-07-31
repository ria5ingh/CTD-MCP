import sys
import json
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient
from src.modules.base import DYNAMIC_REGISTRY
from src.modules.assets import AssetsModule
from src.modules.insights import InsightsModule
from src.modules.vulnerabilities import VulnerabilitiesModule
# Add future modules here as they are created

# Initialize the FastMCP Server
mcp = FastMCP("Claroty CTD MCP Server")

# ==========================================
# Dynamic Meta-Tools
# ==========================================

# Define a strict schema for the meta-tool
class ExecuteToolArgs(BaseModel):
    tool_name: str = Field(description="The exact name of the tool to run (e.g., ctd_search_assets)")
    arguments: dict = Field(description="A dictionary of arguments to pass to the tool, exactly matching its schema")

def list_enabled_modules() -> str:
    """Returns a list of available system modules. Call this first to discover capabilities."""
    return json.dumps(list(DYNAMIC_REGISTRY.keys()))

def search_tools(module_name: str) -> str:
    """Returns the names, descriptions, and required parameter schemas for all tools inside a specific module."""
    if module_name not in DYNAMIC_REGISTRY:
        return f"Error: Module '{module_name}' not found. Available modules: {list(DYNAMIC_REGISTRY.keys())}"
    
    tools_info = []
    for name, data in DYNAMIC_REGISTRY[module_name].items():
        tools_info.append({
            "name": name,
            "description": data["description"],
            "annotations": data.get("annotations", {}),
            "schema": data["schema_json"]
        })
    return json.dumps(tools_info, indent=2)

def execute_tool(tool_name: str, arguments: dict) -> str:
    """Executes a specific backend tool. The 'arguments' dictionary MUST match the schema provided by search_tools."""
    for module, tools in DYNAMIC_REGISTRY.items():
        if tool_name in tools:
            tool_data = tools[tool_name]
            try:
                # Validate LLM arguments against the dynamically generated model
                validated_args = tool_data["schema_model"].model_validate(arguments)
                result = tool_data["func"](**validated_args.model_dump())
                
                # Ensure output is stringified if the tool returns a dict/object
                if isinstance(result, (dict, list)):
                    return json.dumps(result)
                return str(result)
            except Exception as e:
                return f"Validation or Execution Error in '{tool_name}': {str(e)}"
    
    return f"Error: Tool '{tool_name}' not found. Call ctd_search_tools to find available tools."


def main():
    try:
        # Initialize the API Client
        client = CTDClient()

        # Instantiate Modules
        modules = [
            AssetsModule(client=client),
            InsightsModule(client=client),
            VulnerabilitiesModule(client=client),
        ]

        # Register tools and resources for all modules
        for module in modules:
            module.register_tools(mcp)
            module.register_resources(mcp)

        # Register ONLY the 3 dynamic meta-tools with FastMCP/Open WebUI
        mcp.add_tool(list_enabled_modules, name="ctd_list_enabled_modules")
        mcp.add_tool(search_tools, name="ctd_search_tools")
        mcp.add_tool(execute_tool, name="ctd_execute_tool")

        # Start FastMCP server
        mcp.run()
        
    except ValueError as e:
        sys.stderr.write(f"Configuration Error: {e}\n")
    except Exception as e:
        sys.stderr.write(f"Failed to start MCP server: {e}\n")

if __name__ == "__main__":
    main()