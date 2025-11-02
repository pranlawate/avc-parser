"""
Statistics formatter for SELinux AVC Denial Analyzer.

This module provides summary statistics output for quick log overview
without displaying full denial details.
"""

from collections import Counter


def display_stats_summary(
    unique_denials: list,
    total_events: int,
    log_blocks_processed: int,
    file_info: dict = None,
    security_notices: dict = None,
    console=None,
):
    """
    Display concise statistics summary for quick log overview.

    Args:
        unique_denials: List of unique denial dictionaries
        total_events: Total number of AVC events found
        log_blocks_processed: Number of log blocks processed
        file_info: Optional dict with 'name', 'size_kb', 'time_range'
        security_notices: Optional dict with 'dontaudit', 'permissive' flags
        console: Rich console instance for formatted output
    """
    # Collect statistics
    process_counts = Counter()
    source_type_counts = Counter()
    permission_counts = Counter()

    time_first = None
    time_last = None

    for denial_info in unique_denials:
        count = denial_info.get("count", 1)
        parsed_log = denial_info.get("log", {})

        # Process names
        comm = parsed_log.get("comm", "unknown")
        process_counts[comm] += count

        # Source context types
        scontext = str(parsed_log.get("scontext", ""))
        if ":" in scontext:
            # Extract type from full context (user:role:type:level)
            parts = scontext.split(":")
            if len(parts) >= 3:
                source_type_counts[parts[2]] += count

        # Permissions
        if "permissions" in denial_info:
            for perm in denial_info["permissions"]:
                permission_counts[perm] += count
        elif "permission" in parsed_log:
            permission_counts[parsed_log["permission"]] += count

        # Time range
        first_seen = denial_info.get("first_seen_obj")
        last_seen = denial_info.get("last_seen_obj")
        if first_seen and (not time_first or first_seen < time_first):
            time_first = first_seen
        if last_seen and (not time_last or last_seen > time_last):
            time_last = last_seen

    # Display summary
    console.print()
    console.print("📊 [bold]SELinux AVC Log Summary[/bold]")
    console.print("═" * 79)

    # File information
    if file_info:
        console.print(f"File:              {file_info.get('name', 'N/A')}", end="")
        if file_info.get("size_kb"):
            console.print(f" ({file_info['size_kb']:.1f} KB)")
        else:
            console.print()

    # Event statistics
    console.print(f"Total Events:      {total_events}")
    console.print(f"Unique Denials:    {len(unique_denials)}")
    console.print(f"Blocks Processed:  {log_blocks_processed}")

    # Time range
    if time_first and time_last:
        duration = time_last - time_first
        hours = duration.total_seconds() / 3600
        if hours < 1:
            minutes = duration.total_seconds() / 60
            duration_str = f"{int(minutes)} minutes" if minutes >= 1 else "< 1 minute"
        elif hours < 24:
            duration_str = f"{hours:.1f} hours"
        else:
            days = hours / 24
            duration_str = f"{days:.1f} days"

        first_str = time_first.strftime("%Y-%m-%d %H:%M:%S")
        last_str = time_last.strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"Time Range:        {first_str} to {last_str} ({duration_str})")

    # Top processes
    if process_counts:
        console.print()
        console.print("Top Processes:")
        for i, (proc, count) in enumerate(process_counts.most_common(5), 1):
            console.print(f"  {i}. {proc:20s} ({count} events)")

    # Top source types
    if source_type_counts and len(source_type_counts) > 1:
        console.print()
        console.print("Top Source Contexts:")
        for i, (stype, count) in enumerate(source_type_counts.most_common(3), 1):
            console.print(f"  {i}. {stype:20s} ({count} events)")

    # Top permissions (if more than trivial)
    if permission_counts and len(permission_counts) > 1:
        console.print()
        console.print("Top Permissions Denied:")
        for i, (perm, count) in enumerate(permission_counts.most_common(5), 1):
            console.print(f"  {i}. {perm:20s} ({count} denials)")

    # Security notices
    if security_notices:
        console.print()
        console.print("Security Notices:")
        if security_notices.get("dontaudit"):
            console.print("  ⚠️  DONTAUDIT RULES DISABLED (enhanced audit mode)")
        if security_notices.get("permissive"):
            console.print("  ⚠️  PERMISSIVE MODE DENIALS DETECTED")

    # Next steps
    console.print()
    console.print("💡 [bold]Next Steps:[/bold]")
    if file_info and file_info.get("name"):
        file_path = file_info["name"]
        console.print(f"  • View all denials:     python3 parse_avc.py --file {file_path}")
        if process_counts:
            top_proc = process_counts.most_common(1)[0][0]
            console.print(
                f"  • Focus on {top_proc}:  python3 parse_avc.py --file {file_path} --process {top_proc}"
            )
        console.print(f"  • Export to JSON:       python3 parse_avc.py --file {file_path} --json")
    else:
        console.print("  • Remove --stats flag to view full denial details")
        console.print("  • Use --json for structured output")
        console.print("  • Use --detailed for per-PID breakdowns")

    console.print()
