
import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.alerts import ALERTS_SCHEMA_URI, ALERTS_SCHEMA_DOCS


class AlertsModule(BaseModule):

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(
            server=server, 
            method=self.get_alerts_schema, 
            name="get_alerts_schema",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )
        
        self._add_tool(
            server=server, 
            method=self.search_alerts, 
            name="search_alerts",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server, 
            method=self.get_stories, 
            name="get_stories",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server,
            method=self.get_alert_details_by_id,
            name="get_alert_details_by_id",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )

        self._add_tool(
            server=server,
            method=self.get_events_by_id,
            name="get_events_by_id",
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        )
   
    def register_resources(self, server: FastMCP) -> None:
        super().register_resources(server)
        resource = TextResource(
                    uri=AnyUrl(ALERTS_SCHEMA_URI),
                    name="ctd_alerts_schema",
                    description="Contains the master guide, allowed filters, and enums for the `search_alerts` tool",
                    text=ALERTS_SCHEMA_DOCS, 
                    mime_type="text/markdown"
                )        
        self._add_resource(server, resource)   

    def get_alerts_schema(self) -> str:
            """Retrieves the complete CTD Alerts Search Schema, and Filter Keys.
            
            Call this tool BEFORE executing search_alerts to look up 
            allowed filter keys, required data types, or integer enum mappings.
            """
            return ALERTS_SCHEMA_DOCS

    def search_alerts(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(
            default=None,
            description="Dictionary of search filters. Call the `get_alerts_schema` tool to find allowed filter keys, data types, and enum mappings.",
            examples=[{"severity__exact": [2, 3], "category__exact": 0}],
        ),
        limit: int | None = Field(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of alerts to return. If omitted, all matching alerts are retrieved via auto-pagination up to a safe limit.",
        ),
    ) -> str:
        """Fetch and filter network security and integrity alerts from the system. 
        Filter searches by alert ID, category, severity, virtual zone, story id, or alert type. 
        
        Returns a high-level list of alerts and their info. Only UNRESOLVED alerts are returned by default.
        Call the `get_alerts_schema` tool before constructing filter expressions.
        """
        try:
            # Explicitly define the exact fields needed for the triage view
            target_fields = ",;$".join([
                "resource_id", 
                "timestamp", 
                "category__", 
                "type__", 
                "severity", 
                "severity__", 
                "score", 
                "story_id", 
                "description"
            ])
        
            # Base default parameters
            params: dict[str, Any] = {
                'sort': '-timestamp',
                'resolved__exact': 'false',
                'is_qualified__exact': 'true',
                'site_id__exact': 1,
                'fields': target_fields, # Server-side field filtering
            }

            # Apply LLM filters with Bulletproof ID Safety and Optimized Joining
            if filters:
                id_keys = {"id__exact", "story_id__exact"} # Set for O(1) lookup
                for key, value in filters.items(): 
                    # Normalize scalar values to a list to process everything uniformly
                    val_list = value if isinstance(value, list) else [value]
                    
                    cleaned_vals = []
                    for v in val_list:
                        cv = str(v).strip()
                        # Automatically append '-1' for resource ID filters if omitted
                        if key in id_keys and cv.isdigit():
                            cv = f"{cv}-1"
                        cleaned_vals.append(cv)
                        
                    # Joining a single-item list naturally returns just the single item
                    params[key] = ",;$".join(cleaned_vals)

            # Pagination Setup
            all_objects = []
            current_page = 1
            per_page = min(limit, 500) if limit is not None else 100
            params['per_page'] = per_page

            while True:
                params['page'] = current_page
                
                # Fetch from V2 Alerts endpoint
                response_data = self.client.request("GET", "/ranger/v2/alerts", params=params)
                
                if not isinstance(response_data, dict):
                    break
                    
                objects = response_data.get('objects', [])
                
                if not objects:
                    break
                    
                all_objects.extend(objects)
                
                # Stop Conditions
                if limit is not None and len(all_objects) >= limit:
                    all_objects = all_objects[:limit]  # Truncate to exact requested limit
                    break
                    
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return "No alerts found matching the specified criteria."

            # Map directly from API response to bypass unnecessary server-side processing
            processed_alerts = []
            for item in all_objects:
                processed_alerts.append({
                    "Alert ID": item.get("resource_id", "N/A"),
                    "Timestamp": item.get("timestamp", "N/A"),
                    "Category": item.get("category__", "Unknown"),
                    "Type": item.get("type__", "Unknown"),
                    "Severity": f"{item.get('severity__', 'Unknown')} ({item.get('severity', '')})",
                    "Score": item.get("score", "N/A"),
                    "Story ID": item.get("story_id", "N/A"),
                    "Description": item.get("description", "No description")
                })

            # Automatically generate a highly token-efficient Markdown table
            return self._format_to_markdown(processed_alerts)

        except Exception as e:
            return f"Error fetching alerts: {str(e)}"

    def get_stories(
        self,
        limit: int | None = Field(
            default=10,
            ge=1,
            le=100,
            description="Maximum number of stories to return. Defaults to 10.",
        ),
        page: int | None = Field(
            default=1,
            ge=1,
            description="Page number to fetch for pagination.",
        ),
    ) -> str:
        """Fetch a high-level overview of alert stories (grouped alerts).
        
        Returns a list of stories, including their summary, severity, and all 
        associated alert RIDs chained together in chronological order. 
        Only returns UNRESOLVED alert stories.
        """
        try:
            current_page = page if page is not None else 1
            per_page = limit if limit is not None else 10

            # 1. First API Call: Get grouped RIDs and story sizes
            rids_params: dict[str, Any] = {
                'sort': 'story_id',
                'resolved__exact': 'false',
                'is_qualified__exact': 'true',
                'site_id__exact': 1,
                'format': 'rids',
                'fields': 'story_id,;$site_id',
                'distinct': 'true',
                'page': current_page,
                'per_page': per_page
            }

            rids_response = self.client.request("GET", "/ranger/v2/alerts", params=rids_params)
            
            if not isinstance(rids_response, dict):
                return "Invalid response format from the server during RIDs extraction."

            story_groups = rids_response.get('objects', [])
            total_stories = rids_response.get('count_total', rids_response.get('count_filtered', 0))

            if not story_groups:
                return f"No stories found on page {current_page}."

            # Map representative RIDs to their full group data
            representative_rids = []
            group_mapping = {}

            for group in story_groups:
                rids_list = group.get("rids", [])
                if not rids_list:
                    continue
                
                # Take the first RID as the representative for the second API call
                first_rid = rids_list[0]
                representative_rids.append(first_rid)
                
                group_mapping[first_rid] = {
                    "group_size": group.get("group_size", len(rids_list)),
                    "all_rids": rids_list
                }

            if not representative_rids:
                return "No valid alert groups found to process."

            # 2. Second API Call: Fetch detailed info for the representative alerts
            target_fields = ",;$".join([
                "resource_id", 
                "timestamp", 
                "category__", 
                "type__", 
                "severity", 
                "severity__", 
                "score", 
                "story_id", 
                "description",
                "story_group_name"
            ])

            details_params: dict[str, Any] = {
                'sort': 'story_id',
                'resolved__exact': 'false',
                'is_qualified__exact': 'true',
                'site_id__exact': 1,
                'fields': target_fields,
                'id__exact': ",;$".join(representative_rids),
                'per_page': len(representative_rids)
            }

            details_response = self.client.request("GET", "/ranger/v2/alerts", params=details_params)
            detailed_alerts = details_response.get('objects', []) if isinstance(details_response, dict) else []

            # 3. Process and format output
            output_lines = [
                f"### Alert Stories Overview",
                f"- **Page {current_page} Results:** Displaying {len(detailed_alerts)} stories (Total available: {total_stories})\n"
            ]

            for alert in detailed_alerts:
                res_id = alert.get("resource_id")
                story_id = alert.get("story_id", "Unknown")
                
                # Retrieve group mapping data
                mapping_data = group_mapping.get(res_id, {})
                group_size = mapping_data.get("group_size", "Unknown")
                all_rids = mapping_data.get("all_rids", [res_id])
                
                # Parse the story_group_name list (skip the first element which is usually "Story Id X (score 100):")
                sgn = alert.get("story_group_name", [])
                if isinstance(sgn, list) and len(sgn) > 1:
                    summary_info = ", ".join(str(x).strip() for x in sgn[1:])
                else:
                    summary_info = "No summary available"

                # Parse basic alert details
                severity_str = str(alert.get("severity__", " Unknown"))[1:]
                timestamp = alert.get("timestamp", "N/A")

                # Format the header
                header = f"**Story ID {story_id}** | {summary_info} | {group_size} Alerts | {severity_str} | {timestamp}"
                output_lines.append(header)
                
                # Format the RIDs underneath
                for rid in all_rids:
                    output_lines.append(f"- {rid}")
                
                output_lines.append("") # Empty line for spacing between stories

            if total_stories > (current_page * per_page):
                output_lines.append(
                    f"> **NOTICE:** More stories are available. Call this tool again with `page={current_page + 1}` to fetch the next {per_page}."
                )

            return "\n".join(output_lines)

        except Exception as e:
            return f"Error fetching story information: {str(e)}"

    def get_alert_details_by_id(
        self,
        alert_id: str | int = Field(
            description="The exact Alert Resource ID to investigate (e.g., '319' or '319-1').",
            examples=["507-1", "319"]
        )
    ) -> str:
        """Fetch deep-dive information for a specific alert by its ID.
        
        Extracts the alert's severity, score, exact actionable assets involved, asset communications, 
        triggered network signatures, significant indicators, and the chronological 
        timeline of the story it belongs to.
        """
        try:
            # Cleanse and format the ID
            clean_id = str(alert_id).strip()
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            # Execute API Request
            alert = self.client.request("GET", f"/ranger/v2/alerts/{clean_id}")
            
            if not isinstance(alert, dict) or not alert:
                return f"Error: No details found for alert ID '{clean_id}'."

            # 1. Extract Network Info
            net_obj = alert.get("network", {})
            net_display = f"{net_obj.get('name', 'Unknown')} (ID: {net_obj.get('resource_id', 'Unknown')})" if net_obj else "None"

            # Clean top-level Enums inline
            category = str(alert.get("category__", " Unknown"))[1:]
            a_type = str(alert.get("type__", " Unknown"))[1:]
            severity_str = str(alert.get("severity__", " Unknown"))[1:]

            # 2. Top-Level Summary Table
            summary_dict = {
                "Alert ID": alert.get("resource_id", clean_id),
                "Category": category,
                "Type": a_type,
                "Severity": f"{severity_str} ({alert.get('severity', '')})",
                "Score": alert.get("score", "N/A"),
                "Protocol": alert.get("protocol") or "None",
                "Network": net_display
            }
            
            md_lines = [
                f"### Alert Deep Dive: {summary_dict['Alert ID']}",
                self._format_to_markdown(summary_dict)
            ]

            # 3. Actionable Assets
            md_lines.append("\n#### Actionable Assets")
            assets = alert.get("actionable_assets", [])
            if assets:
                for a in assets:
                    ast = a.get("asset", {})
                    name = ast.get("name", "Unknown")
                    res_id = ast.get("resource_id", "Unknown")
                    
                    # Clean nested enums inline
                    role = str(a.get("role__", " None"))[1:]
                    a_type_str = str(ast.get("asset_type__", " Unknown"))[1:]
                    
                    md_lines.append(f"* **[{role}]** {name} ({a_type_str}) | ID: {res_id}")
            else:
                md_lines.append("* No actionable assets found.")

            # 4. Actionable Virtual Zones
            md_lines.append("\n#### Actionable Virtual Zones")
            zones = alert.get("actionable_virtual_zones_names", [])
            if zones:
                md_lines.extend(f"* {z}" for z in zones)
            else:
                md_lines.append("* No virtual zones involved.")

            # 5. Actionable Network Signatures
            signatures = alert.get("actionable_network_signatures", [])
            if signatures:
                md_lines.append("\n#### Triggered Network Signatures")
                for sig in signatures:
                    ns = sig.get("network_signature", {})
                    name = ns.get("name", "Unknown Signature")
                    crit = ns.get("criticality", "Unknown")
                    md_lines.append(f"* {name} (Criticality: {crit})")

            # 6. Significant Indicators
            indicators = alert.get("significant_indicators", [])
            if indicators:
                md_lines.append("\n#### Significant Indicators")
                for ind in indicators:
                    info = ind.get("indicator_info", {})
                    desc = info.get("description", "No description")
                    md_lines.append(f"* {desc}")

            # 7. Story Timeline
            story_obj = alert.get("story", {})
            story_id = alert.get("story_id", "Unknown")
            story_alerts = story_obj.get("alerts", [])
            
            md_lines.append(f"\n#### Story Timeline (Story ID: {story_id})")
            if story_alerts:
                # Ensure chronological order
                story_alerts.sort(key=lambda x: x.get("timestamp", ""))
                for sa in story_alerts:
                    ts = sa.get("timestamp", "Unknown Time")
                    s_id = sa.get("id", "Unknown ID")
                    s_desc = sa.get("description", "No description")
                    
                    # Clean story timeline enum inline
                    s_type = str(sa.get("type__", " Unknown"))[1:]
                    
                    md_lines.append(f"* `{ts}` - **Alert {s_id}** ({s_type}): {s_desc}")
            else:
                md_lines.append("* No broader story timeline available.")

            if story_id is not None:
                md_lines.append(f"\n#### Story Communication Graph")
                try:
                    graph_res = self.client.request(
                        "GET", 
                        f"/ranger/story_graph/{story_id}-1", 
                        params={"show_orphans__exact": "false"}
                    )
                    
                    if isinstance(graph_res, dict) and graph_res.get("graphs"):
                        # Only grab the first graph in the array
                        graph_data = graph_res["graphs"][0]
                        nodes = graph_data.get("nodes", [])
                        edges = graph_data.get("edges", [])
                        
                        # Build a dictionary to quickly lookup node info by ID
                        node_map = {}
                        for n in nodes:
                            n_id = n.get("id")
                            ast = n.get("asset", {})
                            name = ast.get("name", "Unknown")
                            ipv4_list = ast.get("ipv4", [])
                            ip = ipv4_list[0] if ipv4_list else "No IP"
                            purdue = ast.get("purdue_level", "N/A")
                            node_map[n_id] = f"{name} (IP: {ip}, Purdue: {purdue})"
                            
                        # Map the edges into visual text strings
                        if edges:
                            for edge in edges:
                                src = node_map.get(edge.get("source"), "Unknown Source")
                                tgt = node_map.get(edge.get("target"), "Unknown Target")
                                arrow = "<--->" if edge.get("bidirectional") else "--->"
                                md_lines.append(f"* {src} {arrow} {tgt}")
                        else:
                            md_lines.append("* No communication edges found in graph.")
                    else:
                        md_lines.append("* No communication graph data available.")
                        
                except Exception as e:
                    md_lines.append(f"* Could not load graph data: {str(e)}")

            return "\n".join(md_lines)

        except Exception as e:
            return f"Error fetching details for alert '{alert_id}': {str(e)}"

    def get_events_by_id(
        self,
        alert_id: str | int = Field(
            description="The exact Alert Resource ID to retrieve events for (e.g., '507' or '507-1').",
            examples=["507-1", "319"]
        ),
        limit: int | None = Field(
            default=100,
            ge=1,
            le=500,
            description="Maximum number of events to fetch. Defaults to 100.",
        ),
    ) -> str:
        """Fetch and list all individual events grouped under a specific alert ID.
        
        Extracts the event ID, status, type, timestamp, and a cleaned description.
        Automatically handles pagination to retrieve all related events up to the limit.
        """
        try:
            # Cleanse and format the ID
            clean_id = str(alert_id).strip()
            if clean_id.isdigit():
                clean_id = f"{clean_id}-1"

            # Pagination Setup
            all_objects = []
            current_page = 1
            per_page = min(limit, 100) if limit is not None else 100

            # Explicitly define target fields to minimize API payload size
            target_fields = ",;$".join([
                "resource_id",
                "type",
                "timestamp",
                "description"
            ])

            while True:
                params: dict[str, Any] = {
                    'alert_id__exact': clean_id,
                    'page': current_page,
                    'per_page': per_page,
                    'fields': target_fields
                }

                # Fetch from Events endpoint
                response_data = self.client.request("GET", "/ranger/events", params=params)
                
                if not isinstance(response_data, dict):
                    break
                    
                objects = response_data.get('objects', [])
                
                if not objects:
                    break
                    
                all_objects.extend(objects)
                
                # Stop Conditions
                if limit is not None and len(all_objects) >= limit:
                    all_objects = all_objects[:limit]  # Truncate to exact requested limit
                    break
                    
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return f"No events found for alert ID '{clean_id}'."

            processed_events = []
            for item in all_objects:
                # Clean description: Drop the raw signature data to save tokens
                raw_desc = str(item.get("description", "No description"))
                clean_desc = raw_desc.split(". Signature:")[0].strip()

                # Clean type enum using slice with leading space fallback
                clean_type = str(item.get("type__", " Unknown"))[1:]

                processed_events.append({
                    "Event ID": item.get("resource_id", "N/A"),
                    "Type": clean_type,
                    "Timestamp": item.get("timestamp", "N/A"),
                    "Description": clean_desc
                })

            # Automatically generate a highly token-efficient Markdown table
            header = f"### Events for Alert {clean_id} ({len(processed_events)} retrieved)\n"
            table_output = self._format_to_markdown(processed_events)
            
            return header + table_output

        except Exception as e:
            return f"Error fetching events for alert '{alert_id}': {str(e)}"





