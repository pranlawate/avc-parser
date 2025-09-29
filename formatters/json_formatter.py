"""
JSON formatting functions for the SELinux AVC Denial Analyzer.

This module handles all JSON output formatting, normalization, and
data structure preparation for tool integration and downstream processing.
"""

import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Any

from rich.console import Console


def normalize_json_fields(log_data: dict) -> dict:
    """
    Normalize JSON fields for reliable tool integration and downstream processing.

    This function standardizes field formats, cleans data types, and ensures
    consistent representation across different denial types for optimal
    compatibility with SIEM systems, AI tools, and automated analysis.

    Args:
        log_data (dict): Raw log data dictionary to normalize

    Returns:
        dict: Normalized log data with standardized field formats

    Normalization Areas:
        - Path formatting: Absolute paths, consistent separators
        - Port extraction: Clean numeric ports with type information
        - Context structures: Standardized SELinux context components
        - Data types: Consistent field types and value formats
        - String cleaning: Remove problematic characters and whitespace
    """
    normalized = log_data.copy()

    # 1. STANDARDIZED PATH FORMATTING
    if "path" in normalized and normalized["path"]:
        path = normalized["path"].strip()
        if path:
            # Ensure absolute path representation
            if not path.startswith("/"):
                path = "/" + path
            # Normalize path separators and remove redundant slashes
            path = os.path.normpath(path)
            # Ensure forward slashes for cross-platform compatibility
            path = path.replace("\\", "/")
            normalized["path"] = path
            normalized["path_absolute"] = path
            normalized["path_normalized"] = True
        else:
            normalized["path"] = None

    # 2. CLEAN PORT EXTRACTION AND FORMATTING
    if "dest_port" in normalized and normalized["dest_port"]:
        port_str = str(normalized["dest_port"]).strip()
        try:
            # Extract numeric port value
            port_num = int(port_str)
            normalized["dest_port"] = port_num
            normalized["dest_port_string"] = str(port_num)
            normalized["dest_port_type"] = "numeric"

            # Add port classification
            if port_num <= 1023:
                normalized["dest_port_class"] = "system"
            elif port_num <= 49151:
                normalized["dest_port_class"] = "registered"
            else:
                normalized["dest_port_class"] = "dynamic"

        except (ValueError, TypeError):
            # Keep original if not numeric, but clean it
            normalized["dest_port"] = port_str
            normalized["dest_port_string"] = port_str
            normalized["dest_port_type"] = "non_numeric"

    # 3. NORMALIZED SELINUX CONTEXT FIELD STRUCTURES
    for context_field in ["scontext", "tcontext"]:
        if context_field in normalized and normalized[context_field]:
            context_str = str(normalized[context_field]).strip()
            if ":" in context_str:
                # Parse SELinux context components
                parts = context_str.split(":")
                if len(parts) >= 3:
                    context_base = f"{context_field}_components"
                    normalized[context_base] = {
                        "user": parts[0] if len(parts) > 0 else "",
                        "role": parts[1] if len(parts) > 1 else "",
                        "type": parts[2] if len(parts) > 2 else "",
                        "level": parts[3] if len(parts) > 3 else "",
                        "full": context_str,
                    }
                    # Add type extraction for easier filtering
                    if len(parts) > 2:
                        type_key = f"{context_field}_type"
                        normalized[type_key] = parts[2]

    # 4. NETWORK ADDRESS STANDARDIZATION
    if "saddr" in normalized and normalized["saddr"]:
        saddr_str = str(normalized["saddr"]).strip()
        # Parse network address information
        saddr_components = {}
        for component in saddr_str.split():
            if "=" in component:
                key, value = component.split("=", 1)
                saddr_components[key] = value

        if saddr_components:
            normalized["saddr_components"] = saddr_components
            # Extract commonly used fields
            if "laddr" in saddr_components:
                normalized["local_address"] = saddr_components["laddr"]
            if "lport" in saddr_components:
                try:
                    normalized["local_port"] = int(saddr_components["lport"])
                except (ValueError, TypeError):
                    normalized["local_port"] = saddr_components["lport"]

    # 5. DATA TYPE CONSISTENCY AND VALIDATION
    # Ensure numeric fields are properly typed
    numeric_fields = ["pid", "ino", "inode"]
    for field in numeric_fields:
        if field in normalized and normalized[field] is not None:
            try:
                normalized[field] = int(str(normalized[field]).strip())
            except (ValueError, TypeError):
                # Keep as string if conversion fails, but clean it
                normalized[field] = str(normalized[field]).strip()

    # Ensure boolean fields are properly typed
    boolean_fields = ["permissive"]
    for field in boolean_fields:
        if field in normalized and normalized[field] is not None:
            value = str(normalized[field]).strip().lower()
            if value in ["0", "false", "no"]:
                normalized[field] = False
                normalized[f"{field}_numeric"] = 0
            elif value in ["1", "true", "yes"]:
                normalized[field] = True
                normalized[f"{field}_numeric"] = 1
            else:
                normalized[field] = value

    # 6. STRING FIELD CLEANING AND STANDARDIZATION
    string_fields = ["comm", "exe", "syscall", "denial_type", "permission", "tclass"]
    for field in string_fields:
        if field in normalized and normalized[field] is not None:
            # Clean and standardize string values
            value = str(normalized[field]).strip()
            # Remove null bytes and control characters
            value = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value)
            # Normalize whitespace
            value = " ".join(value.split())
            normalized[field] = value if value else None

    # 7. TIMESTAMP STANDARDIZATION
    if "timestamp" in normalized and normalized["timestamp"]:
        try:
            # Ensure timestamp is float for consistency
            ts_value = float(str(normalized["timestamp"]).strip())
            normalized["timestamp"] = ts_value
            normalized["timestamp_float"] = ts_value
        except (ValueError, TypeError):
            # Keep original if conversion fails
            pass

    # 8. ADD METADATA FOR TOOL INTEGRATION
    normalized["_normalized"] = True
    normalized["_normalization_version"] = "1.0"

    return normalized


def format_as_json(unique_denials: Dict, valid_blocks: List, generate_sesearch_command) -> None:
    """
    Format denial data as structured JSON output for tool integration.

    Args:
        unique_denials (Dict): Dictionary of unique denial records
        valid_blocks (List): List of valid log blocks processed
        generate_sesearch_command: Function to generate sesearch commands

    This function converts the denial data into a structured JSON format
    suitable for SIEM systems, automated analysis, and downstream tools.
    """
    console = Console()

    # Convert the dictionary of unique denials to a list for JSON output
    output_list = []
    for denial_info in unique_denials.values():
        # Handle AvcContext objects (avoid circular import by checking type name)

        # Create a JSON-safe copy of the denial info
        json_denial = {
            "log": denial_info["log"].copy(),
            "count": denial_info["count"],
            "first_seen": (
                denial_info["first_seen_obj"].isoformat()
                if denial_info["first_seen_obj"]
                else None
            ),
            "last_seen": (
                denial_info["last_seen_obj"].isoformat()
                if denial_info["last_seen_obj"]
                else None
            ),
        }

        # Add permissions set if it exists
        if "permissions" in denial_info:
            json_denial["permissions"] = sorted(list(denial_info["permissions"]))

        # Add correlation data for PID-to-resource mapping with normalization
        if "correlations" in denial_info:
            normalized_correlations = []
            for correlation in denial_info["correlations"]:
                normalized_correlation = normalize_json_fields(correlation.copy())
                normalized_correlations.append(normalized_correlation)
            json_denial["correlations"] = normalized_correlations

        # Apply JSON field normalization for reliable tool integration
        json_denial["log"] = normalize_json_fields(json_denial["log"])

        # Remove datetime_obj from the log data and convert any remaining datetime
        # objects to strings
        json_denial["log"].pop("datetime_obj", None)
        for key, value in json_denial["log"].items():
            if isinstance(value, datetime):
                json_denial["log"][key] = value.isoformat()
            elif hasattr(value, '__class__') and value.__class__.__name__ == 'AvcContext':
                # Convert AvcContext objects to strings for JSON serialization
                json_denial["log"][key] = str(value)
            elif key == "timestamp" and isinstance(value, (int, float)):
                # Convert timestamp to string to ensure it's quoted in JSON
                json_denial["log"][key] = str(value)
            elif isinstance(value, str):
                # Clean up any problematic characters in string values
                json_denial["log"][key] = (
                    value.replace("\x00", "").replace("\r", "").replace("\n", "\\n")
                )

        # Add sesearch command for policy investigation
        # Use aggregated permissions if available, otherwise use single permission from log
        sesearch_log = denial_info["log"].copy()
        if "permissions" in json_denial and json_denial["permissions"]:
            # Use aggregated permissions for more complete sesearch command
            sesearch_log["permission"] = "{ " + " ".join(json_denial["permissions"]) + " }"

        sesearch_cmd = generate_sesearch_command(sesearch_log)
        if sesearch_cmd:
            json_denial["sesearch_command"] = sesearch_cmd

        output_list.append(json_denial)

    # Create structured JSON output with summary
    total_events = sum(denial["count"] for denial in unique_denials.values())
    json_structure = {
        "unique_denials": output_list,
        "summary": {
            "total_events": total_events,
            "unique_denials_count": len(unique_denials),
            "log_blocks_processed": len(valid_blocks),
        },
    }

    try:
        json_output = json.dumps(json_structure, indent=2, ensure_ascii=False)
        print(json_output)
    except (TypeError, ValueError) as e:
        console.print(f"Error generating JSON: {e}", style="bold red")
        # Fallback: print raw data for debugging
        console.print("Raw data that caused the error:", style="bold yellow")
        for i, item in enumerate(output_list):
            console.print(f"Item {i}: {item}")
        sys.exit(1)