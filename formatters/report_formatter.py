"""
Report formatting functions for SELinux AVC Denial Analyzer.

This module contains functions for formatting denial information in different
report formats including brief (executive) and sealert (technical) formats.
"""

from rich.console import Console

from utils import human_time_ago, generate_sesearch_command


def display_report_sealert_format(
    console: Console,
    denial_info: dict,
    denial_num: int,
    expand_groups: bool = False,
):
    """
    Display denial information in sealert-inspired technical report format.

    Technical analysis format with complete forensic detail in two-column layout.
    Based on setroubleshoot's sealert format but preserves our grouping advantages.

    Args:
        console (Console): Rich console object for formatted output
        denial_info (dict): Aggregated denial information with correlation data
        denial_num (int): Sequential denial number for display
        expand_groups (bool): Whether to show individual events instead of grouped view
    """
    parsed_log = denial_info["log"]
    count = denial_info["count"]
    correlations = denial_info.get("correlations", [])
    last_seen_dt = denial_info["last_seen_obj"]
    last_seen_ago = human_time_ago(last_seen_dt)

    # Header with denial group information (sealert-inspired)
    unique_pids = len(set(corr.get("pid") for corr in correlations if corr.get("pid")))
    console.print("-" * 80)
    console.print(f"SELinux Unique Denial Group #{denial_num} - {count} total events, {unique_pids} unique PIDs, last seen {last_seen_ago}")
    console.print()

    # Action-focused summary line
    source_context_obj = parsed_log.get("scontext")
    target_context_obj = parsed_log.get("tcontext")

    # Extract type from AvcContext objects (they have a .type attribute)
    source_type = "unknown"
    target_type = "unknown"

    if source_context_obj and hasattr(source_context_obj, 'type'):
        source_type = source_context_obj.type

    if target_context_obj and hasattr(target_context_obj, 'type'):
        target_type = target_context_obj.type

    permission = parsed_log.get("permission", "unknown")
    permissions_display = parsed_log.get("permissions_display", permission)

    # Use aggregated permissions for display if available
    if "permissions" in denial_info and denial_info["permissions"] and len(denial_info["permissions"]) > 1:
        permissions_list = sorted(list(denial_info["permissions"]))
        permissions_display = ", ".join(permissions_list)

    tclass = parsed_log.get("tclass", "unknown")

    console.print(f"{source_type} attempted {permissions_display} access to {target_type} {tclass} and was denied.")
    console.print()

    # Raw audit message context
    comm = parsed_log.get("comm", "unknown")
    pid = parsed_log.get("pid", "unknown")
    path = parsed_log.get("path", "")
    dest_port = parsed_log.get("dest_port", "")

    console.print("Raw Audit Message:")
    audit_parts = []
    audit_parts.append(f"avc: denied {{ {permissions_display} }}")
    audit_parts.append(f"for pid={pid} comm=\"{comm}\"")

    if path:
        audit_parts.append(f"path=\"{path}\"")
    elif dest_port:
        audit_parts.append(f"dest={dest_port}")

    console.print(f"  {' '.join(audit_parts)}")
    console.print()

    # Analysis Details in two-column format
    console.print("Analysis Details:")

    # Source and target contexts
    source_context = parsed_log.get("scontext", "unknown")
    target_context = parsed_log.get("tcontext", "unknown")
    source_desc = parsed_log.get("source_type_description", "")
    target_desc = parsed_log.get("target_type_description", "")

    source_line = f"  Source Context        {source_context}"
    if source_desc:
        source_line += f" ({source_desc})"
    console.print(source_line)

    target_line = f"  Target Context        {target_context}"
    if target_desc:
        target_line += f" ({target_desc})"
    console.print(target_line)

    # Target path or port information
    if path:
        console.print(f"  Target Path           {path}")
    elif dest_port:
        port_desc = parsed_log.get("port_description", "")
        port_line = f"  Target Port           {dest_port}"
        if port_desc:
            port_line += f" ({port_desc})"
        console.print(port_line)

        # Socket address if available
        saddr = parsed_log.get("saddr", "")
        if saddr:
            console.print(f"  Socket Address        {saddr}")

    # Permission details
    permission_semantic = parsed_log.get("permission_semantic", permissions_display)
    console.print(f"  Permissions           {permissions_display} ({permission_semantic})")

    # Object class
    console.print(f"  Object Class          {tclass}")

    # Process information
    exe = parsed_log.get("exe", "")
    cwd = parsed_log.get("cwd", "")
    if exe and cwd:
        console.print(f"  Process Info          {comm} ({exe}) in {cwd}")
    elif exe:
        console.print(f"  Process Info          {comm} ({exe})")
    elif comm != "unknown":
        console.print(f"  Process Info          {comm}")

    # SELinux mode and status
    is_permissive = parsed_log.get("permissive") == "1"
    status_symbol = "⚠️  ALLOWED" if is_permissive else "✗ BLOCKED"
    mode = "Permissive" if is_permissive else "Enforcing"
    console.print(f"  SELinux Mode          {mode} ({status_symbol})")

    # Time range if multiple events
    if count > 1:
        first_seen_dt = denial_info.get("first_seen_obj")
        if first_seen_dt and last_seen_dt:
            first_seen_str = first_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
            last_seen_str = last_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
            console.print(f"  Time Range            {first_seen_str} - {last_seen_str}")

    console.print()

    # Event Distribution - always show in report mode when there are multiple events
    if correlations and len(correlations) > 1:
        console.print("Event Distribution:")

        # Group correlations by PID and show distribution
        pid_events = {}
        for corr in correlations:
            pid = corr.get("pid")
            if pid:
                if pid not in pid_events:
                    pid_events[pid] = {
                        "count": 0,
                        "comm": corr.get("comm", "unknown"),
                        "timestamp": corr.get("timestamp", "unknown")
                    }
                pid_events[pid]["count"] += 1

        for pid, info in sorted(pid_events.items()):
            count_str = f"({info['count']}x)" if info["count"] > 1 else ""
            console.print(f"  PID {pid} {count_str}      {info['comm']} at {info['timestamp']}")

        console.print()

    # Policy Investigation
    # Use aggregated permissions if available for more complete sesearch command
    sesearch_log = parsed_log.copy()
    if (
        "permissions" in denial_info
        and denial_info["permissions"]
        and len(denial_info["permissions"]) > 1
    ):
        # Use aggregated permissions for more complete sesearch command
        permissions_list = sorted(list(denial_info["permissions"]))
        sesearch_log["permission"] = "{ " + " ".join(permissions_list) + " }"

    sesearch_command = generate_sesearch_command(sesearch_log)
    console.print("Policy Investigation:")
    console.print(f"  Command: {sesearch_command}")
    console.print()
    console.print("  This command shows existing allow rules for this access pattern.")

    # Contextual Analysis
    contextual_analysis = parsed_log.get("contextual_analysis", "")
    if contextual_analysis:
        console.print()
        console.print("Contextual Analysis:")
        console.print(f"  {contextual_analysis}")

    console.print()


def display_report_brief_format(
    console: Console,
    denial_info: dict,
    denial_num: int,
    expand_groups: bool = False,
):
    """
    Display denial information in executive brief format for management reporting.

    Executive summary format with business impact focus and visual hierarchy.
    Designed for incident reports, compliance documentation, and management briefings.

    Args:
        console (Console): Rich console object for formatted output
        denial_info (dict): Aggregated denial information with correlation data
        denial_num (int): Sequential denial number for display
        expand_groups (bool): Whether to show individual events instead of grouped view
    """
    parsed_log = denial_info["log"]
    count = denial_info["count"]
    correlations = denial_info.get("correlations", [])
    last_seen_dt = denial_info["last_seen_obj"]
    last_seen_ago = human_time_ago(last_seen_dt)

    # Extract key information
    source_context_obj = parsed_log.get("scontext")
    target_context_obj = parsed_log.get("tcontext")

    source_type = "unknown"
    target_type = "unknown"

    if source_context_obj and hasattr(source_context_obj, 'type'):
        source_type = source_context_obj.type

    if target_context_obj and hasattr(target_context_obj, 'type'):
        target_type = target_context_obj.type

    comm = parsed_log.get("comm", "unknown")
    tclass = parsed_log.get("tclass", "unknown")
    path = parsed_log.get("path", "")
    dest_port = parsed_log.get("dest_port", "")

    # Use aggregated permissions for display if available
    permissions_display = parsed_log.get("permission", "unknown")
    if "permissions" in denial_info and denial_info["permissions"] and len(denial_info["permissions"]) > 1:
        permissions_list = sorted(list(denial_info["permissions"]))
        permissions_display = ", ".join(permissions_list)

    # Count processes and files
    unique_pids = set()
    unique_paths = set()
    for corr in correlations:
        if corr.get("pid"):
            unique_pids.add(corr.get("pid"))
        if corr.get("path"):
            unique_paths.add(corr.get("path"))

    process_count = len(unique_pids)
    resource_count = len(unique_paths) if unique_paths else 1

    # Generate business-focused title
    if tclass == "file":
        if resource_count > 1:
            resource_desc = f"{resource_count} files"
        else:
            resource_desc = "files" if not path else "system configuration"
    elif tclass in ["tcp_socket", "udp_socket"]:
        resource_desc = "network services"
    elif tclass in ["dir", "lnk_file"]:
        resource_desc = "directories" if tclass == "dir" else "symbolic links"
    else:
        resource_desc = f"{tclass} resources"

    # Determine priority level
    is_permissive = parsed_log.get("permissive") == "1"
    if is_permissive:
        priority = "MEDIUM PRIORITY"  # Permissive mode = less urgent but still concerning
    elif count >= 10:
        priority = "HIGH PRIORITY"  # Many events = urgent
    elif tclass in ["tcp_socket", "udp_socket"] or "network" in str(path).lower():
        priority = "HIGH PRIORITY"  # Network access = security sensitive
    else:
        priority = "MEDIUM PRIORITY"

    console.print("=" * 80)
    console.print(f"SELINUX SECURITY INCIDENT #{denial_num}                                    [{priority}]")
    console.print()

    # Generate process category description
    if comm in ["systemd", "init"]:
        process_category = "System_Services"
    elif comm in ["httpd", "nginx", "apache"]:
        process_category = "Web_Services"
    elif comm in ["sshd", "ssh"]:
        process_category = "Remote_Access"
    elif comm in ["zabbix_agentd", "nrpe", "nagios"]:
        process_category = "Monitoring_Agent"
    elif comm.endswith("d"):
        process_category = "System_Daemon"
    else:
        process_category = source_type.replace("_t", "").title()

    # WHAT: Business impact description
    console.print(f"WHAT: {process_category} blocked from {permissions_display.replace(',', '').replace('  ', ' ')} {resource_desc}")

    # WHEN: Time information
    time_info = []
    if count == 1:
        time_info.append(last_seen_dt.strftime("%Y-%m-%d %H:%M:%S"))
    else:
        first_seen_dt = denial_info.get("first_seen_obj")
        if first_seen_dt and last_seen_dt:
            first_seen_str = first_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
            last_seen_str = last_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
            time_info.append(f"{first_seen_str} - {last_seen_str}")

    time_info.append(f"({count} events across {process_count} processes)")
    console.print(f"WHEN: {' '.join(time_info)}")

    # WHO: Process information
    if process_count == 1:
        console.print(f"WHO:  {comm} processes (PIDs: {', '.join(str(pid) for pid in sorted(unique_pids))})")
    else:
        pid_list = sorted(unique_pids)
        if len(pid_list) > 3:
            pid_display = f"{', '.join(str(p) for p in pid_list[:3])}..."
        else:
            pid_display = ', '.join(str(p) for p in pid_list)
        console.print(f"WHO:  {comm} processes (PIDs: {pid_display})")

    # WHERE: Resource information
    if path:
        if resource_count > 1:
            console.print(f"WHERE: {path} + {resource_count - 1} other files")
        else:
            console.print(f"WHERE: {path}")
    elif dest_port:
        port_desc = parsed_log.get("port_description", "")
        if port_desc:
            console.print(f"WHERE: Network connection to {port_desc} (port {dest_port})")
        else:
            console.print(f"WHERE: Network connection to port {dest_port}")
    else:
        console.print(f"WHERE: {tclass} resources")

    console.print()

    # IMPACT: Business impact assessment
    if tclass == "file":
        impact = "Application disruption - " + comm + " process cannot access required resources"
    elif tclass in ["tcp_socket", "udp_socket"]:
        impact = "Network connectivity issues - service communication blocked"
    elif tclass == "capability":
        impact = "System privilege restriction - advanced operations prevented"
    else:
        impact = f"System access restriction - {tclass} operations blocked"

    console.print(f"IMPACT: {impact}")

    # STATUS: Current enforcement status
    if is_permissive:
        status = "⚠️  ALLOWED due to permissive mode"
    else:
        status = "✗ BLOCKED by SELinux policy (Enforcing mode)"

    console.print(f"STATUS: {status}")
    console.print("=" * 80)
    console.print()

    # REMEDIATION: Technical guidance
    console.print("REMEDIATION:")

    # Generate sesearch command with aggregated permissions
    sesearch_log = parsed_log.copy()
    if (
        "permissions" in denial_info
        and denial_info["permissions"]
        and len(denial_info["permissions"]) > 1
    ):
        # Use aggregated permissions for more complete sesearch command
        permissions_list = sorted(list(denial_info["permissions"]))
        sesearch_log["permission"] = " ".join(permissions_list)

    sesearch_command = generate_sesearch_command(sesearch_log)
    console.print(f"$ {sesearch_command}")
    console.print("$ # If no rules exist, create custom policy or fix file contexts")

    # Security notice for permissive mode
    if is_permissive:
        console.print()
        console.print("⚠️  SECURITY ALERT: System running in permissive mode - denials logged but allowed")

    console.print()
    console.print()