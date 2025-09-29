"""
SELinux-specific utility functions for AVC Denial Analyzer.

This module contains functions for generating SELinux policy investigation
commands and handling SELinux-specific operations.
"""


def generate_sesearch_command(parsed_log: dict) -> str:
    """
    Generate sesearch command for policy investigation based on AVC denial data.

    Args:
        parsed_log (dict): Parsed AVC log data containing scontext, tcontext, tclass, permission

    Returns:
        str: sesearch command string, or empty string if required data is missing

    Example:
        Input: scontext="system_u:system_r:httpd_t:s0", tcontext="unconfined_u:object_r:default_t:s0",
               tclass="file", permission="read"
        Output: "sesearch -A -s httpd_t -t default_t -c file -p read"
    """
    try:
        # Extract required fields
        scontext = parsed_log.get("scontext", "")
        tcontext = parsed_log.get("tcontext", "")
        tclass = parsed_log.get("tclass", "")
        permission = parsed_log.get("permission", "")

        # Validate required fields
        if not all([scontext, tcontext, tclass, permission]):
            return ""

        # Extract type from SELinux contexts (user:role:type:mls format)
        # Convert context objects to strings if necessary, then split on ':' and take index [2] for type component
        try:
            scontext_str = str(scontext)
            tcontext_str = str(tcontext)
            source_type = scontext_str.split(":")[2]
            target_type = tcontext_str.split(":")[2]
        except (IndexError, AttributeError):
            # Handle malformed contexts gracefully
            return ""

        # Handle multiple permissions (convert from "{ read write }" format)
        if permission.startswith("{ ") and permission.endswith(" }"):
            # Multiple permissions: "{ read write execute }" -> "read,write,execute"
            perms = permission[2:-2].split()
            permission_str = ",".join(perms)
        else:
            # Single permission: "read" -> "read"
            permission_str = permission.strip()

        # Generate sesearch command
        sesearch_cmd = f"sesearch -A -s {source_type} -t {target_type} -c {tclass} -p {permission_str}"

        return sesearch_cmd

    except Exception:
        # Return empty string for any parsing errors
        return ""