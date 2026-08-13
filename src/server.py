import sys
import json
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP

from src.client import CTDClient
from src.modules.base import DYNAMIC_REGISTRY, USE_DYNAMIC_MODE, config_data
from src.modules.assets import AssetsModule
from src.modules.insights import InsightsModule
from src.modules.vulnerabilities import VulnerabilitiesModule
from src.modules.system import SystemModule
from src.modules.zones import ZonesModule
from src.modules.alerts import AlertsModule
from src.modules.baselines import BaselinesModule

#from src.modules.modulename import NameModule


mcp = FastMCP("Claroty CTD MCP Server")

# ==========================================
# Dynamic Meta-Tools
# ==========================================

# Map config key names to their class references
# append as list grows, append in config as well
AVAILABLE_MODULES = {
    "assets": AssetsModule,
    "insights": InsightsModule,
    "vulnerabilities": VulnerabilitiesModule,
    "system": SystemModule,
    "zones": ZonesModule,
    "alerts" : AlertsModule,
    "baselines" : BaselinesModule,
    #"name" : NameModule,
}

class ExecuteToolArgs(BaseModel):
    tool_name: str = Field(description="The exact name of the tool to run (e.g., ctd_search_assets)")
    arguments: dict = Field(description="A dictionary of arguments to pass to the tool, exactly matching its schema")

# def list_enabled_modules() -> str:
#     """Returns a list of available system modules. Call this first to discover capabilities."""
#     return json.dumps(list(DYNAMIC_REGISTRY.keys()))

def list_enabled_modules() -> str:
    """Returns a list of available system modules and their descriptions. Call this first to discover capabilities."""
    output_lines = ["### Available Modules\n"]
    
    for module_name in DYNAMIC_REGISTRY.keys():
        # Retrieve the class reference from the available modules map
        module_class = AVAILABLE_MODULES.get(module_name)
        
        # Extract and clean up the docstring
        if module_class and module_class.__doc__:
            # .split() and " ".join() removes all awkward indentation and newlines
            description = " ".join(module_class.__doc__.strip().split())
        else:
            description = "No description provided."
            
        output_lines.append(f"- **{module_name}**: {description}")
        
    return "\n".join(output_lines)


# def search_tools(module_name: str) -> str:
#     """Returns the names, descriptions, and required parameter schemas for all tools inside a specific module."""
#     if module_name not in DYNAMIC_REGISTRY:
#         return f"Error: Module '{module_name}' not found. Available modules: {list(DYNAMIC_REGISTRY.keys())}"
    
#     tools_info = []
#     for name, data in DYNAMIC_REGISTRY[module_name].items():
#         tools_info.append({
#             "name": name,
#             "description": data["description"],
#             "annotations": data.get("annotations", {}),
#             "schema": data["schema_json"]
#         })
#     return json.dumps(tools_info, indent=2)

def search_tools(module_name: str) -> str:
    """Returns the names, descriptions, and required parameter schemas for all tools inside a specific module."""
    if module_name not in DYNAMIC_REGISTRY:
        return f"Error: Module '{module_name}' not found. Available modules: {list(DYNAMIC_REGISTRY.keys())}"
    
    output_lines = [f"### Tools available in `{module_name}` module:",
        "> **CRITICAL:** These tools cannot be called directly.",
        "> Execution requires using the `ctd_execute_tool` tool, passing the target tool's",
        "> name as `tool_name` and its parameters as the `arguments` dictionary.",
        "\n---"
    ]
    
    for name, data in DYNAMIC_REGISTRY[module_name].items():
        desc = data.get("description", "No description provided.").strip()
        schema = data.get("schema_json", {})
        properties = schema.get("properties", {})
        required_fields = schema.get("required", [])
        
        # Build function signature and parameter details
        args_list = []
        param_details = []
        
        for prop_name, prop_info in properties.items():
            is_required = prop_name in required_fields
            
            # Extract basic type and handle Pydantic's anyOf nullable bloat
            prop_type = prop_info.get("type", "Any")
            if "anyOf" in prop_info:
                types = [t.get("type") for t in prop_info["anyOf"] if t.get("type") and t.get("type") != "null"]
                if types:
                    prop_type = types[0]
            
            # Map JSON types to Python types for better LLM readability
            if prop_type == "object": prop_type = "dict"
            elif prop_type == "array": prop_type = "list"
            elif prop_type == "integer": prop_type = "int"
            elif prop_type == "string": prop_type = "str"
            elif prop_type == "boolean": prop_type = "bool"

            prop_desc = prop_info.get("description", "No description.")
            
            # Signature formatting
            req_str = "" if is_required else " = None"
            args_list.append(f"{prop_name}: {prop_type}{req_str}")
            
            # Detailed bullet point
            req_label = "Required" if is_required else "Optional"
            param_details.append(f"- `{prop_name}` ({prop_type}, {req_label}): {prop_desc}")

        # Assemble the formatted block for this tool
        sig = f"**`{name}({', '.join(args_list)})`**"
        output_lines.append(sig)
        output_lines.append(desc)
        if param_details:
            output_lines.append("\n**Arguments:**")
            output_lines.extend(param_details)
        output_lines.append("\n---\n") 
        
    return "\n".join(output_lines)

def execute_tool(tool_name: str, arguments: dict) -> str:
    """Executes a specific backend tool. The 'arguments' dictionary MUST match the schema provided by search_tools."""
    for module, tools in DYNAMIC_REGISTRY.items():
        if tool_name in tools:
            tool_data = tools[tool_name]
            try:
                validated_args = tool_data["schema_model"].model_validate(arguments)
                result = tool_data["func"](**validated_args.model_dump())
                
                if isinstance(result, (dict, list)):
                    return json.dumps(result)
                return str(result)
            except Exception as e:
                return f"Validation or Execution Error in '{tool_name}': {str(e)}"
    
    return f"Error: Tool '{tool_name}' not found. Call ctd_search_tools to find available tools."

# ==========================================
# Main Server Execution
# ==========================================

def main():
    try:
        client = CTDClient()
        
        # Read ENABLED_MODULES block from config
        enabled_modules = config_data.get("ENABLED_MODULES", {})

        # Dynamically instantiate modules based on config (defaults to True if key missing)
        modules = [
            module_class(client=client)
            for name, module_class in AVAILABLE_MODULES.items()
            if enabled_modules.get(name, True)
        ]

        # Register tools and resources for all enabled modules
        for module in modules:
            module.register_tools(mcp)
            module.register_resources(mcp)

        if USE_DYNAMIC_MODE:
            mcp.add_tool(list_enabled_modules, name="ctd_list_enabled_modules")
            mcp.add_tool(search_tools, name="ctd_search_tools")
            mcp.add_tool(execute_tool, name="ctd_execute_tool")

        mcp.run()
        
    except ValueError as e:
        sys.stderr.write(f"Configuration Error: {e}\n")
    except Exception as e:
        sys.stderr.write(f"Failed to start MCP server: {e}\n")

if __name__ == "__main__":
    main()