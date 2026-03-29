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
    process_counts = Counter()
    source_type_counts = Counter()
    target_type_counts = Counter()
    permission_counts = Counter()
    tclass_counts = Counter()
    sensitivity_levels = set()
    mls_mismatch_count = 0
    enforcing_count = 0
    permissive_event_count = 0

    time_first = None
    time_last = None

    for denial_info in unique_denials:
        count = denial_info.get("count", 1)
        parsed_log = denial_info.get("log", {})

        comm = parsed_log.get("comm", "unknown")
        process_counts[comm] += count

        scontext = str(parsed_log.get("scontext", ""))
        if ":" in scontext:
            parts = scontext.split(":")
            if len(parts) >= 3:
                source_type_counts[parts[2]] += count
            if len(parts) > 3:
                mls_raw = ":".join(parts[3:])
                try:
                    from avc_selinux.mls import parse_mls_string
                    mls_range = parse_mls_string(mls_raw)
                    if mls_range:
                        sensitivity_levels.add(mls_range.low.sensitivity)
                        sensitivity_levels.add(mls_range.high.sensitivity)
                except (ImportError, Exception):
                    pass

        tcontext = str(parsed_log.get("tcontext", ""))
        if ":" in tcontext:
            parts = tcontext.split(":")
            if len(parts) >= 3:
                target_type_counts[parts[2]] += count

        tclass = parsed_log.get("tclass", "")
        if tclass:
            tclass_counts[tclass] += count

        if "permissions" in denial_info:
            for perm in denial_info["permissions"]:
                permission_counts[perm] += count
        elif "permission" in parsed_log:
            permission_counts[parsed_log["permission"]] += count

        if parsed_log.get("mls_analysis"):
            mls_mismatch_count += 1

        if parsed_log.get("permissive") == "1":
            permissive_event_count += count
        else:
            enforcing_count += count

        first_seen = denial_info.get("first_seen_obj")
        last_seen = denial_info.get("last_seen_obj")
        if first_seen and (not time_first or first_seen < time_first):
            time_first = first_seen
        if last_seen and (not time_last or last_seen > time_last):
            time_last = last_seen

    console.print()
    console.print("📊 [bold]SELinux AVC Log Summary[/bold]")
    console.print("═" * 79)

    if file_info:
        console.print(f"File:              {file_info.get('name', 'N/A')}", end="")
        if file_info.get("size_kb"):
            console.print(f" ({file_info['size_kb']:.1f} KB)")
        else:
            console.print()

    console.print(f"Total Events:      {total_events}")
    console.print(f"Unique Denials:    {len(unique_denials)}")
    console.print(f"Blocks Processed:  {log_blocks_processed}")
    if enforcing_count or permissive_event_count:
        console.print(f"Enforcing:         {enforcing_count} events")
        if permissive_event_count:
            console.print(f"Permissive:        {permissive_event_count} events (logged but allowed)")

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

    if process_counts:
        console.print()
        console.print("Top Processes:")
        for i, (proc, count) in enumerate(process_counts.most_common(5), 1):
            console.print(f"  {i}. {proc:20s} ({count} events)")

    if source_type_counts and len(source_type_counts) > 1:
        console.print()
        console.print("Top Source Types:")
        for i, (stype, count) in enumerate(source_type_counts.most_common(5), 1):
            console.print(f"  {i}. {stype:20s} ({count} events)")

    if target_type_counts and len(target_type_counts) > 1:
        console.print()
        console.print("Top Target Types:")
        for i, (ttype, count) in enumerate(target_type_counts.most_common(5), 1):
            console.print(f"  {i}. {ttype:20s} ({count} events)")

    if tclass_counts:
        console.print()
        console.print("Object Classes:")
        for i, (tclass, count) in enumerate(tclass_counts.most_common(8), 1):
            console.print(f"  {i}. {tclass:20s} ({count} events)")

    if permission_counts and len(permission_counts) > 1:
        console.print()
        console.print("Top Permissions Denied:")
        for i, (perm, count) in enumerate(permission_counts.most_common(5), 1):
            console.print(f"  {i}. {perm:20s} ({count} denials)")

    # MLS/MCS section
    non_s0_levels = sensitivity_levels - {"s0"}
    if non_s0_levels or mls_mismatch_count:
        console.print()
        console.print("MLS/MCS Security:")
        if non_s0_levels:
            levels_str = ", ".join(sorted(sensitivity_levels, key=lambda s: int(s[1:])))
            console.print(f"  Sensitivity levels seen: {levels_str}")
            console.print("  MLS policy active (non-default sensitivity levels detected)")
        if mls_mismatch_count:
            console.print(f"  Level mismatches:  {mls_mismatch_count} denial groups have source/target at different levels")
            console.print("  Use --mls to view only MLS-related denials")

    if security_notices:
        console.print()
        console.print("Security Notices:")
        if security_notices.get("dontaudit"):
            console.print("  ⚠️  DONTAUDIT RULES DISABLED (enhanced audit mode)")
        if security_notices.get("permissive"):
            console.print("  ⚠️  PERMISSIVE MODE DENIALS DETECTED")

    console.print()
    console.print("💡 [bold]Next Steps:[/bold]")
    if file_info and file_info.get("name"):
        file_path = file_info["name"]
        console.print(f"  • View all denials:     avc-parser --file {file_path}")
        if process_counts:
            top_proc = process_counts.most_common(1)[0][0]
            console.print(f"  • Focus on {top_proc}:  avc-parser --file {file_path} --process {top_proc}")
        console.print(f"  • Export to JSON:       avc-parser --file {file_path} --json")
        if mls_mismatch_count:
            console.print(f"  • MLS mismatches only:  avc-parser --file {file_path} --mls")
    else:
        console.print("  • Remove --stats flag to view full denial details")
        console.print("  • Use --json for structured output")
        console.print("  • Use --detailed for per-PID breakdowns")
        if mls_mismatch_count:
            console.print("  • Use --mls to view only MLS-related denials")

    console.print()
