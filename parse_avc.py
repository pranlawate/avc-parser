#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
SELinux AVC Denial Analyzer

A forensic-focused tool for analyzing SELinux audit logs with intelligent
deduplication and clear correlation tracking. This tool specializes in
post-incident SELinux audit log analysis for complex denial patterns.

Author: [Author Name]
License: [License Type]
Version: 1.0.0
"""

import argparse
import os
import re
import sys
import subprocess
import json
import signal
from datetime import datetime
from rich.console import Console
from rich.rule import Rule


def signal_handler(signum, frame):  # pylint: disable=unused-argument
    """
    Handles interrupt signals (Ctrl+C) with graceful cleanup and user feedback.

    Args:
        signum: Signal number (usually SIGINT)
        frame: Current stack frame (unused)

    Note:
        Provides clear feedback to user about interruption and exits cleanly.
    """
    console = Console()
    console.print("\n\n🛑 [bold yellow]Operation interrupted by user[/bold yellow]")
    console.print("   [dim]Cleaning up and exiting...[/dim]")
    sys.exit(130)  # Standard exit code for Ctrl+C interruption


# Enhanced audit record regex pattern from setroubleshoot for robust parsing
# Handles: (node=XXX )?(type=XXX )?(msg=)?audit(timestamp:serial): body
AUDIT_RECORD_RE = re.compile(
    r'(node=(\S+)\s+)?(type=(\S+)\s+)?(msg=)?audit\(((\d+)\.(\d+):(\d+))\):\s*(.*)'
)


def parse_audit_record_text(input_line: str) -> tuple[bool, str, str, str, str]:
    """
    Parse audit record using enhanced setroubleshoot regex pattern.

    Args:
        input_line (str): Raw audit log line to parse

    Returns:
        tuple[bool, str, str, str, str]: (parse_succeeded, host, record_type, event_id, body_text)
            - parse_succeeded: True if line matches audit record format
            - host: Node hostname if present (or None)
            - record_type: Record type (AVC, USER_AVC, SYSCALL, etc.) if present
            - event_id: Complete event ID (timestamp:serial) if present
            - body_text: Message body after event ID

    Note:
        Enhanced pattern handles edge cases like node= prefixes, optional msg=,
        and various audit record formats found in real-world logs.
    """
    match = AUDIT_RECORD_RE.search(input_line)
    if match is None:
        return False, None, None, None, None

    host = match.group(2) if match.group(2) else None
    record_type = match.group(4) if match.group(4) else None
    event_id = match.group(6) if match.group(6) else None
    body_text = match.group(10) if match.group(10) else None

    return True, host, record_type, event_id, body_text


def detect_file_format(file_path: str) -> str:
    """
    Analyze file content to detect if it's raw audit.log or pre-processed format.

    Args:
        file_path (str): Path to the file to analyze

    Returns:
        str: 'raw' for raw audit.log format, 'processed' for pre-processed format

    Note:
        Detection logic:
        - Pre-processed: Contains 'type=AVC msg=audit(...)' patterns with human-readable timestamps
        - Raw: Contains audit records without 'type=' prefix or with binary timestamps
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read first few lines for analysis
            lines = []
            for i, line in enumerate(f):
                if i >= 10:  # Analyze first 10 lines
                    break
                lines.append(line.strip())

        # Check for pre-processed patterns
        pre_processed_indicators = 0
        raw_indicators = 0

        for line in lines:
            if not line:
                continue

            # Pre-processed indicators
            if re.search(r'type=AVC.*msg=audit\(.*\):', line):
                pre_processed_indicators += 1

            # Human-readable timestamp patterns (ausearch -i output)
            if re.search(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', line):
                pre_processed_indicators += 1

            # Raw audit.log indicators
            # Unix timestamp pattern: audit(1234567890.123:456)
            if re.search(r'audit\(\d{10}\.\d{3}:\d+\)', line):
                raw_indicators += 1

            # Missing type= prefix (common in raw logs)
            if re.search(r'^audit\(\d{10}\.\d{3}:\d+\):', line):
                raw_indicators += 1

        # Decision logic
        if pre_processed_indicators > raw_indicators:
            return 'processed'
        else:
            return 'raw'

    except (FileNotFoundError, PermissionError, UnicodeDecodeError):
        # Default to processed format if we can't read the file
        # The file validation will catch and handle the actual error
        return 'processed'


def validate_log_entry(log_block: str) -> tuple[bool, str, list]:  # pylint: disable=too-many-branches
    """
    Validates and sanitizes a log block before parsing.

    Args:
        log_block (str): Raw log block to validate

    Returns:
        tuple[bool, str, list]: (is_valid, sanitized_log, warnings)
            - is_valid: True if log block contains parseable content
            - sanitized_log: Cleaned log block ready for parsing
            - warnings: List of validation warning messages

    Note:
        Handles common log corruption issues like truncated lines,
        encoding problems, and missing timestamps.
    """
    warnings = []

    # Basic sanity checks
    if not log_block or not log_block.strip():
        return False, "", ["Empty or whitespace-only log block"]

    # Remove null bytes and other control characters that can corrupt parsing
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', log_block)
    if sanitized != log_block:
        warnings.append("Removed control characters from log data")

    # Check for basic audit log structure
    lines = sanitized.strip().split('\n')
    valid_lines = []
    malformed_lines = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check for basic audit record structure (handles optional whitespace)
        if re.search(r'type=\w+.*msg=audit\([^)]+\)\s*:', line):
            # Standard audit record format - valid
            valid_lines.append(line)
        elif re.search(r'(type=|msg=|avc:|denied|granted)', line, re.IGNORECASE):
            # Looks like audit content but possibly malformed - try to salvage
            valid_lines.append(line)
            malformed_lines += 1
        else:
            # Line doesn't look like audit content - skip it
            malformed_lines += 1

    # Generate warnings for malformed content
    if malformed_lines > 0:
        warnings.append(f"Found {malformed_lines} malformed or non-audit lines (skipped)")

    # Check if we have any usable content
    if not valid_lines:
        return False, "", warnings + ["No valid audit log lines found"]

    # Look for audit/AVC content specifically
    has_audit_content = any(
        re.search(r'(type=AVC|type=USER_AVC|avc:.*denied|avc:.*granted)', line, re.IGNORECASE)
        for line in valid_lines
    )

    if not has_audit_content:
        warnings.append("No AVC denial/grant records found - may not contain SELinux events")

    # Check for timestamp consistency
    timestamps = []
    for line in valid_lines:
        ts_match = re.search(r'msg=audit\(([^)]+)\)', line)
        if ts_match:
            timestamps.append(ts_match.group(1))

    if len(set(timestamps)) > 1:
        warnings.append("Multiple different timestamps found - events may span different times")

    sanitized_log = '\n'.join(valid_lines)
    return True, sanitized_log, warnings


def parse_avc_log(log_block: str) -> tuple[list, set]:
    """
    Parses a multi-line AVC audit log block containing multiple record types.

    This function processes complex audit log blocks that may contain AVC, USER_AVC,
    SYSCALL, CWD, PATH, PROCTITLE, and SOCKADDR records. It extracts shared context
    from non-AVC records and applies it to AVC denials for complete correlation.

    Args:
        log_block (str): Multi-line audit log block from ausearch or raw audit.log

    Returns:
        tuple[list, set]: A tuple containing:
            - list: Parsed AVC denial dictionaries with complete context
            - set: Unparsed record types found in the log block for tracking

    Example:
        >>> log = '''type=AVC msg=audit(1234567890.123:456): avc: denied ...
        ... type=SYSCALL msg=audit(1234567890.123:456): ...'''
        >>> denials, unparsed = parse_avc_log(log)
        >>> len(denials)
        1

    Note:
        Implements robust error handling for corrupted audit records.
        Returns empty results rather than failing on malformed input.
    """
    avc_denials = []  # pylint: disable=unused-variable
    unparsed_types = set()  # pylint: disable=unused-variable

    try:
        return _parse_avc_log_internal(log_block)
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Log parsing failed completely - return empty results
        # This prevents one corrupted block from breaking the entire analysis
        return [], {f"PARSE_ERROR_{type(e).__name__}"}


def _parse_avc_log_internal(log_block: str) -> tuple[list, set]:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-nested-blocks
    """
    Internal parsing function with detailed error handling for audit record processing.

    This is separated from the main function to allow comprehensive error handling
    while maintaining clean code organization.
    """
    avc_denials = []
    unparsed_types = set()

    # Extract shared context that applies to all AVC records in this log block
    shared_context = {}

    # Parse timestamp from audit message header
    # Format: msg=audit(1234567890.123:456) where first part is timestamp
    timestamp_pattern = re.search(r'msg=audit\(([^)]+)\)', log_block)
    if timestamp_pattern:
        # Remove serial number (after last colon) to get just timestamp
        timestamp_str = timestamp_pattern.group(1).rsplit(':', 1)[0]

        # Try multiple timestamp formats in order of preference
        dt_object = None
        try:
            # Format 1: Human-readable MM/DD/YYYY from ausearch -i
            dt_object = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S.%f')
        except ValueError:
            try:
                # Format 2: Alternative DD/MM/YY format from some ausearch outputs
                dt_object = datetime.strptime(timestamp_str, '%d/%m/%y %H:%M:%S.%f')
            except ValueError:
                try:
                    # Format 3: Unix timestamp (fallback for raw audit.log)
                    dt_object = datetime.fromtimestamp(float(timestamp_str))
                except ValueError:
                    # Timestamp parsing failed - will be handled gracefully
                    dt_object = None

        # Store parsed timestamp in multiple useful formats
        if dt_object:
            shared_context['datetime_obj'] = dt_object
            shared_context['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            shared_context['timestamp'] = dt_object.timestamp()

    # Define regex patterns for extracting context from non-AVC audit records
    # These records provide additional context that enriches AVC denial information
    patterns = {
        "CWD": {"cwd": r"cwd=\"([^\"]+)\""},  # Current working directory
        "PATH": {
            "path": r"name=\"([^\"]+)\"",           # Quoted file path
            "path_unquoted": r"name=([^\s]+)",      # Unquoted path (fallback)
            "inode": r"inode=(\d+)",                # File inode number
            "dev": r"dev=([^\s]+)",                 # Device identifier
        },
        "SYSCALL": {
            "syscall": r"syscall=([\w\d]+)",       # System call name/number
            "exe": r"exe=\"([^\"]+)\"",             # Executable path
        },
        "PROCTITLE": {"proctitle": r"proctitle=(.+)"},  # Process command line
        "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}"}     # Socket address info
    }

    # Process non-AVC lines for shared context using enhanced parsing
    for line in log_block.strip().split('\n'):
        line = line.strip()

        # Use enhanced audit record parsing for better extraction
        parse_succeeded, host, record_type, event_id, body_text = parse_audit_record_text(line)
        if not parse_succeeded:
            # Fallback to simple regex for malformed lines
            match = re.search(r"type=(\w+)", line)
            if not match:
                continue
            log_type = match.group(1)
        else:
            log_type = record_type
            # Store additional parsed information if available
            if host:
                shared_context['host'] = host
            if event_id:
                shared_context['event_id'] = event_id

        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                field_match = re.search(pattern, line)
                if field_match:
                    value = field_match.group(1)
                    if key == 'proctitle':
                        value = value.strip()  # Remove any trailing whitespace
                        # Check if it's quoted
                        if value.startswith('"') and value.endswith('"'):
                            shared_context[key] = value[1:-1]  # Remove quotes
                        else:
                            try:
                                # Try hex decode first
                                shared_context[key] = bytes.fromhex(value).decode()
                            except ValueError:
                                # If not hex, use as-is (plain text)
                                shared_context[key] = value
                    elif key == 'path_unquoted':
                        # Only use unquoted path if we don't already have a quoted path
                        if 'path' not in shared_context:
                            shared_context['path'] = value.strip()
                    else:
                        shared_context[key] = value.strip()
        elif log_type not in ["AVC", "USER_AVC"]:
            # Track unparsed types (excluding AVC and USER_AVC)
            unparsed_types.add(log_type)

    # Now process each AVC and USER_AVC line separately
    for line in log_block.strip().split('\n'):
        line = line.strip()
        if 'type=AVC' in line or 'type=USER_AVC' in line:
            # Parse this specific AVC or USER_AVC line with error handling
            try:
                avc_data = shared_context.copy()  # Start with shared context

                # For USER_AVC, we need to extract from the msg field
                if 'type=USER_AVC' in line:
                    # Extract the msg content from USER_AVC
                    msg_match = re.search(r"msg='([^']+)'", line)
                    if msg_match:
                        avc_content = msg_match.group(1)
                        # Also extract basic USER_AVC fields from the outer message
                        user_avc_patterns = {
                            "pid": r"pid=(\S+)",
                            "uid": r"uid=(\S+)",
                        }
                        for key, pattern in user_avc_patterns.items():
                            field_match = re.search(pattern, line)
                            if field_match:
                                avc_data[key] = field_match.group(1).strip()
                    else:
                        # Skip if no msg content (like policyload notices)
                        continue
                else:
                    avc_content = line
            except Exception as parse_error:  # pylint: disable=broad-exception-caught
                # Individual AVC parsing failed - skip this record but continue with others
                # Add error information to unparsed types for tracking
                unparsed_types.add(f"AVC_PARSE_ERROR_{type(parse_error).__name__}")
                continue

            # Set the denial type based on the line type
            if 'type=USER_AVC' in line:
                avc_data['denial_type'] = 'USER_AVC'
            else:
                avc_data['denial_type'] = 'AVC'

            # Extract AVC-specific fields (works for both AVC and USER_AVC msg content)
            avc_patterns = {
                "permission": r"denied\s+\{ ([^}]+) \}",
                "pid": r"pid=(\S+)",
                "comm": r"comm=(?:\"([^\"]+)\"|([^\s]+))",
                "path": r"path=\"([^\"]+)\"",
                "path_unquoted": r"path=([^\s]+)",  # For unquoted paths in AVC
                "name": r"name=([^\s]+)",  # name field in AVC (often just filename)
                "dev": r"dev=\"?([^\"\\s]+)\"?",  # Device, may or may not be quoted
                "ino": r"ino=(\d+)",  # Inode number
                "scontext": r"scontext=(\S+)",
                "tcontext": r"tcontext=(\S+)",
                "tclass": r"tclass=(\S+)",
                "dest_port": r"dest=(\S+)",
                "permissive": r"permissive=(\d+)",
            }

            for key, pattern in avc_patterns.items():
                field_match = re.search(pattern, avc_content)
                if field_match:
                    # For USER_AVC, don't override pid if it was already set from outer message
                    if 'type=USER_AVC' in line and key == "pid" and key in avc_data:
                        continue

                    if key == "comm" and len(field_match.groups()) > 1:
                        # Handle comm field which can be quoted or unquoted
                        avc_data[key] = (field_match.group(1) or field_match.group(2)).strip()
                    elif key == 'path_unquoted':
                        # Only use unquoted path if we don't already have a quoted path
                        if 'path' not in avc_data:
                            avc_data['path'] = field_match.group(1).strip()
                    else:
                        avc_data[key] = field_match.group(1).strip()

            if "permission" in avc_data:  # Only add if it's a valid AVC
                # Enhanced path resolution logic
                # Priority: 1) PATH record name field, 2) AVC path field, 3) dev+inode combination
                if 'path' not in avc_data or not avc_data['path']:
                    # No path in AVC, try to use PATH record data or create dev+inode identifier
                    if shared_context.get('path'):
                        avc_data['path'] = shared_context['path']
                    elif avc_data.get('dev') and avc_data.get('ino'):
                        # Create a dev+inode identifier when path is missing
                        avc_data['path'] = f"dev:{avc_data['dev']},inode:{avc_data['ino']}"
                        avc_data['path_type'] = 'dev_inode'
                    elif shared_context.get('dev') and shared_context.get('inode'):
                        # Use PATH record dev+inode if available
                        dev_val = shared_context['dev']
                        inode_val = shared_context['inode']
                        avc_data['path'] = f"dev:{dev_val},inode:{inode_val}"
                        avc_data['path_type'] = 'dev_inode'
                else:
                    # We have a path, mark it as a regular path
                    avc_data['path_type'] = 'file_path'

                # Use comm as fallback for proctitle if proctitle is null or missing
                if avc_data.get('proctitle') in [
                        "(null)", "null", "", None] and avc_data.get('comm'):
                    avc_data['proctitle'] = avc_data['comm']

                avc_denials.append(avc_data)
#                print(f" [DEBUG] Parsed AVC: {avc_data}")  # DEBUG

#    print(f" [DEBUG] Found {len(avc_denials)} AVC denials in this block")  # DEBUG
    return avc_denials, unparsed_types


def human_time_ago(dt_object: datetime) -> str:  # pylint: disable=too-many-return-statements
    """
    Converts a datetime object into a human-readable relative time string.

    Args:
        dt_object (datetime): The datetime object to convert, or None

    Returns:
        str: Human-readable time difference (e.g., "2 days ago", "3 hours ago")
             Returns "an unknown time" if dt_object is None or invalid

    Example:
        >>> from datetime import datetime, timedelta
        >>> dt = datetime.now() - timedelta(days=2)
        >>> human_time_ago(dt)
        '2 day(s) ago'
    """
    if not dt_object:
        return "an unknown time"
    now = datetime.now()
    delta = now - dt_object

    if delta.days > 365:
        return f"{delta.days // 365} year(s) ago"
    elif delta.days > 30:
        return f"{delta.days // 30} month(s) ago"
    elif delta.days > 7:
        return f"{delta.days // 7} week(s) ago"
    elif delta.days > 0:
        return f"{delta.days} day(s) ago"
    elif delta.seconds > 3600:
        return f"{delta.seconds // 3600} hour(s) ago"
    else:
        return f"{max(0, delta.seconds // 60)} minute(s) ago"


def print_summary(console: Console, denial_info: dict, denial_num: int):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """
    Prints a formatted, color-coded summary of an AVC denial with aggregated information.

    This function displays a comprehensive summary including process information,
    denial details, target information, and occurrence statistics. Fields that
    are missing or empty are gracefully skipped.

    Args:
        console (Console): Rich console object for formatted output
        denial_info (dict): Aggregated denial information containing:
            - 'log': Parsed AVC log data
            - 'count': Number of occurrences
            - 'last_seen_obj': Datetime of last occurrence
        denial_num (int): Sequential denial number for display

    Note:
        Uses professional green/cyan/white color scheme for readability.
        Automatically handles field aggregation (e.g., multiple PIDs, paths).
    """
    parsed_log = denial_info['log']
    count = denial_info['count']
    last_seen_dt = denial_info['last_seen_obj']
    last_seen_ago = human_time_ago(last_seen_dt)

    header = f"[bold green]Unique Denial #{
        denial_num}[/bold green] ({count} occurrences, last seen {last_seen_ago})"
    console.print(Rule(header))

    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return

    # Define the fields and their labels for cleaner printing
    process_fields = [
        ("Timestamp", "datetime_str"),
        ("Process Title", "proctitle"), ("Executable", "exe"),
        ("Process Name", "comm"), ("Process ID (PID)", "pid"),
        ("Working Dir (CWD)", "cwd"), ("Source Context", "scontext")
    ]
    action_fields = [("Syscall", "syscall")]

    # Handle permissions - either single permission or comma-separated list
    if 'permissions' in denial_info and denial_info['permissions'] and len(
            denial_info['permissions']) > 0:
        permissions_str = ", ".join(sorted(denial_info['permissions']))
        action_fields.append(("Permission", permissions_str))
    elif parsed_log.get("permission"):
        action_fields.append(("Permission", parsed_log["permission"]))

    # Handle permissive mode - check both collected and single values
    if "permissives" in denial_info and denial_info["permissives"] and len(
            denial_info["permissives"]) > 0:
        modes = []
        for perm_val in sorted(denial_info["permissives"]):
            modes.append("Permissive" if perm_val == "1" else "Enforcing")
        action_fields.append(("SELinux Mode", ", ".join(modes)))
    elif parsed_log.get("permissive"):
        mode = "Permissive" if parsed_log["permissive"] == "1" else "Enforcing"
        action_fields.append(("SELinux Mode", mode))

    target_fields = [
        ("Target Path", "path"), ("Socket Address", "saddr"),
        ("Target Class", "tclass"), ("Target Context", "tcontext")
    ]

    # --- Process Information ---
    for label, key in process_fields:
        # Check if we have multiple values for this field
        multi_key = f"{key}s"
        if multi_key in denial_info and denial_info[multi_key] and len(denial_info[multi_key]) > 0:
            values = ", ".join(sorted(denial_info[multi_key]))
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            # Apply professional color scheme based on field type
            if key == "datetime_str":
                # For timestamp, show the last seen time instead of all times
                last_seen_str = denial_info['last_seen_obj'].strftime(
                    '%Y-%m-%d %H:%M:%S') if denial_info['last_seen_obj'] else values
                console.print(f"[dim white]{last_seen_str}[/dim white]")
            elif key in ["proctitle", "exe"]:
                console.print(f"[green]{values}[/green]")
            elif key == "comm":
                console.print(f"[green]{values}[/green]")
            elif key == "pid":
                console.print(f"[cyan]{values}[/cyan]")
            elif key == "cwd":
                console.print(f"[dim green]{values}[/dim green]")
            elif key == "scontext":
                # Signature field - use bright_cyan bold
                console.print(f"[bright_cyan bold]{values}[/bright_cyan bold]")
            else:
                console.print(values)
        elif parsed_log.get(key) and parsed_log[key] not in ["(null)", "null", ""]:
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            # Apply professional color scheme based on field type
            if key == "datetime_str":
                # For timestamp, show the last seen time for consistency
                last_seen_str = denial_info['last_seen_obj'].strftime(
                    '%Y-%m-%d %H:%M:%S') if denial_info['last_seen_obj'] else parsed_log[key]
                console.print(f"[dim white]{last_seen_str}[/dim white]")
            elif key in ["proctitle", "exe"]:
                console.print(f"[green]{parsed_log[key]}[/green]")
            elif key == "comm":
                console.print(f"[green]{parsed_log[key]}[/green]")
            elif key == "pid":
                console.print(f"[cyan]{parsed_log[key]}[/cyan]")
            elif key == "cwd":
                console.print(f"[dim green]{parsed_log[key]}[/dim green]")
            elif key == "scontext":
                # Signature field - use bright_cyan bold
                console.print(f"[bright_cyan bold]{parsed_log[key]}[/bright_cyan bold]")
            else:
                console.print(str(parsed_log[key]))

    console.print("-" * 35)
    # --- Action Details ---
    console.print(f"  [bold]Action:[/bold]".ljust(22) + "Denied")

    # Show denial type (AVC vs USER_AVC)
    if parsed_log.get("denial_type"):
        denial_type_display = "Kernel AVC" if parsed_log["denial_type"] == "AVC" else "Userspace AVC"
        console.print(f"  [bold]Denial Type:[/bold]".ljust(22), end="")
        console.print(f"[bright_green bold]{denial_type_display}[/bright_green bold]")

    for label, key in action_fields:
        if key in parsed_log or (
                label == "Permission" and 'permissions' in denial_info) or (
                label == "SELinux Mode"):
            if label == "Permission" and 'permissions' in denial_info:
                value = ", ".join(sorted(denial_info['permissions']))
            elif label == "SELinux Mode":
                value = key  # key already contains the computed value
            else:
                value = parsed_log.get(key, key)
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            # Apply professional color scheme for action fields
            if label == "Permission":
                console.print(f"[bright_cyan bold]{value}[/bright_cyan bold]")
            elif label == "Syscall":
                console.print(f"[green]{value}[/green]")
            elif label == "SELinux Mode":
                console.print(f"[cyan]{value}[/cyan]")
            else:
                console.print(str(value))

    console.print("-" * 35)
    # --- Target Information ---
    for label, key in target_fields:
        # Check if we have multiple values for this field
        multi_key = f"{key}s"
        if multi_key in denial_info and denial_info[multi_key] and len(denial_info[multi_key]) > 0:
            values = ", ".join(sorted(denial_info[multi_key]))
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            if key == "path":
                # No highlighting for Target Path due to color bleeding
                console.print(values, highlight=False)
            elif key == "tclass":
                # Signature field - use green bold
                console.print(f"[green bold]{values}[/green bold]")
            elif key == "tcontext":
                # Signature field - use bright_cyan bold
                console.print(f"[bright_cyan bold]{values}[/bright_cyan bold]")
            elif key == "saddr":
                # Socket address information
                console.print(f"[dim white]{values}[/dim white]")
            else:
                console.print(values)
        elif parsed_log.get(key) and parsed_log[key] not in ["(null)", "null", ""]:
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            if key == "path":
                # No highlighting for Target Path due to color bleeding
                console.print(str(parsed_log[key]), highlight=False)
            elif key == "tclass":
                # Signature field - use green bold
                console.print(f"[green bold]{parsed_log[key]}[/green bold]")
            elif key == "tcontext":
                # Signature field - use bright_cyan bold
                console.print(f"[bright_cyan bold]{parsed_log[key]}[/bright_cyan bold]")
            elif key == "saddr":
                # Socket address information
                console.print(f"[dim white]{parsed_log[key]}[/dim white]")
            else:
                console.print(str(parsed_log[key]))

    # Handle dest_port separately with dynamic labeling
    if parsed_log.get("dest_port") and parsed_log["dest_port"] not in ["(null)", "null", ""]:
        # Determine label based on target class
        if parsed_log.get("tclass") == "dbus":
            dest_label = "D-Bus Destination"
        else:
            dest_label = "Target Port"

        # Check if we have multiple dest_port values
        if "dest_ports" in denial_info and denial_info["dest_ports"] and len(
                denial_info["dest_ports"]) > 0:
            values = ", ".join(sorted(denial_info["dest_ports"]))
            console.print(f"  [bold]{dest_label}:[/bold]".ljust(22), end="")
            console.print(f"[green]{values}[/green]")
        else:
            console.print(f"  [bold]{dest_label}:[/bold]".ljust(22), end="")
            console.print(f"[green]{parsed_log['dest_port']}[/green]")

    console.print("-" * 35)


def validate_arguments(args, console: Console) -> str:
    """
    Comprehensive argument validation with detailed error messages.

    Args:
        args: Parsed command-line arguments
        console: Rich console for formatted error output

    Returns:
        str: Validation result - 'raw_file', 'avc_file', or 'interactive'

    Raises:
        SystemExit: On validation failures with descriptive error messages
    """
    # Check for conflicting arguments
    file_args = [args.file, args.raw_file, args.avc_file]
    file_args_count = sum(1 for arg in file_args if arg is not None)

    if file_args_count > 1:
        console.print("❌ [bold red]Error: Conflicting Arguments[/bold red]")
        console.print("   Cannot specify multiple file arguments simultaneously.")
        console.print("   [dim]Choose one input method:[/dim]")
        console.print("   • [cyan]--file[/cyan] for auto-detection (recommended)")
        console.print("   • [cyan]--raw-file[/cyan] for raw audit.log files")
        console.print("   • [cyan]--avc-file[/cyan] for pre-processed ausearch output")
        sys.exit(1)

    # Validate JSON flag requirements
    if args.json and file_args_count == 0:
        console.print("❌ [bold red]Error: Missing Required Arguments[/bold red]")
        console.print("   --json flag requires a file input to process.")
        console.print("   [dim]Valid combinations:[/dim]")
        console.print("   • [cyan]--json --file audit.log[/cyan] (recommended)")
        console.print("   • [cyan]--json --raw-file audit.log[/cyan]")
        console.print("   • [cyan]--json --avc-file processed.log[/cyan]")
        sys.exit(1)

    # Handle new --file argument with auto-detection
    if args.file:
        return validate_file_with_auto_detection(args.file, console)

    # Validate raw file if provided
    elif args.raw_file:
        return validate_raw_file(args.raw_file, console)

    # Validate AVC file if provided
    elif args.avc_file:
        return validate_avc_file(args.avc_file, console)

    # Interactive mode
    else:
        if args.json:
            console.print(
                "❌ [bold red]Error: Interactive mode not supported with --json[/bold red]")
            console.print("   JSON output requires file input for processing.")
            sys.exit(1)
        return 'interactive'


def validate_file_with_auto_detection(file_path: str, console: Console) -> str:
    """
    Validate file and auto-detect format type (raw vs pre-processed).

    Args:
        file_path (str): Path to the audit file
        console (Console): Rich console for formatted output

    Returns:
        str: 'raw_file' for raw audit.log format, 'avc_file' for pre-processed format

    Raises:
        SystemExit: On file validation errors
    """
    # First, perform basic file validation (similar to existing functions)
    try:
        if not os.path.exists(file_path):
            console.print(f"❌ [bold red]Error: File Not Found[/bold red]")
            console.print(f"   File does not exist: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Please verify the file path and try again.[/dim]")
            sys.exit(1)

        if not os.access(file_path, os.R_OK):
            console.print(f"❌ [bold red]Error: Permission Denied[/bold red]")
            console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
            sys.exit(1)

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            console.print(f"❌ [bold red]Error: Empty File[/bold red]")
            console.print(f"   File is empty: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Please provide a file with audit log content.[/dim]")
            sys.exit(1)

        if file_size > 100 * 1024 * 1024:  # 100MB limit
            console.print(f"⚠️  [bold yellow]Warning: Large File Detected[/bold yellow]")
            console.print(f"   File size: {file_size / (1024*1024):.1f}MB")
            console.print("   [dim]Processing may take some time...[/dim]")

        # Auto-detect format type
        detected_format = detect_file_format(file_path)

        if not console.quiet if hasattr(console, 'quiet') else False:
            if detected_format == 'raw':
                console.print(f"🔍 [bold green]Auto-detected:[/bold green] Raw audit.log format")
                console.print(f"   Will process using ausearch: [cyan]{file_path}[/cyan]")
            else:
                console.print(f"🔍 [bold green]Auto-detected:[/bold green] Pre-processed format")
                console.print(f"   Will parse directly: [cyan]{file_path}[/cyan]")

        return 'raw_file' if detected_format == 'raw' else 'avc_file'

    except UnicodeDecodeError:
        console.print(f"❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Audit files should be text files.[/dim]")
        sys.exit(1)
    except PermissionError:
        console.print(f"❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
        sys.exit(1)


def validate_raw_file(file_path: str, console: Console) -> str:
    """
    Validates raw audit.log file with comprehensive checks.

    Args:
        file_path: Path to the raw audit file
        console: Rich console for error output

    Returns:
        str: 'raw_file' if validation passes

    Raises:
        SystemExit: On validation failures
    """
    # Check if path exists
    if not os.path.exists(file_path):
        console.print(f"❌ [bold red]Error: File Not Found[/bold red]")
        console.print(f"   Raw file does not exist: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please check the file path and try again.[/dim]")
        sys.exit(1)

    # Check if it's actually a file
    if os.path.isdir(file_path):
        console.print(f"❌ [bold red]Error: Directory Provided[/bold red]")
        console.print(f"   Expected a file but got directory: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please specify the audit.log file path, not the directory.[/dim]")
        sys.exit(1)

    # Check file permissions
    if not os.access(file_path, os.R_OK):
        console.print(f"❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
        sys.exit(1)

    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        console.print(f"❌ [bold red]Error: Empty File[/bold red]")
        console.print(f"   Raw file is empty: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please provide a file with audit log content.[/dim]")
        sys.exit(1)

    # Check for binary file (basic heuristic)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)  # Try to read first 1KB as text
    except UnicodeDecodeError:
        console.print(f"❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Raw audit files should be text files. Please check the file format.[/dim]")
        sys.exit(1)

    return 'raw_file'


def validate_avc_file(file_path: str, console: Console) -> str:
    """
    Validates pre-processed AVC file with comprehensive checks.

    Args:
        file_path: Path to the AVC file
        console: Rich console for error output

    Returns:
        str: 'avc_file' if validation passes

    Raises:
        SystemExit: On validation failures
    """
    # Check if path exists
    if not os.path.exists(file_path):
        console.print(f"❌ [bold red]Error: File Not Found[/bold red]")
        console.print(f"   AVC file does not exist: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please check the file path and try again.[/dim]")
        sys.exit(1)

    # Check if it's actually a file
    if os.path.isdir(file_path):
        console.print(f"❌ [bold red]Error: Directory Provided[/bold red]")
        console.print(f"   Expected a file but got directory: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please specify the AVC log file path, not the directory.[/dim]")
        sys.exit(1)

    # Check file permissions
    if not os.access(file_path, os.R_OK):
        console.print(f"❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
        sys.exit(1)

    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        console.print(f"❌ [bold red]Error: Empty File[/bold red]")
        console.print(f"   AVC file is empty: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please provide a file with AVC log content.[/dim]")
        sys.exit(1)

    # Try to read and validate file content
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(1024)  # Read first 1KB for validation

        # Basic content validation - should contain audit-like content
        if not re.search(r'(type=AVC|msg=audit|avc:)', content, re.IGNORECASE):
            console.print(f"⚠️  [bold yellow]Warning: File Content Check[/bold yellow]")
            console.print(
                f"   File does not appear to contain AVC records: [cyan]{file_path}[/cyan]")
            console.print(
                "   [dim]Proceeding anyway - file may contain valid data in different format.[/dim]")

    except UnicodeDecodeError:
        console.print(f"❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print("   [dim]AVC files should be text files from ausearch output.[/dim]")
        sys.exit(1)
    except PermissionError:
        console.print(f"❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
        sys.exit(1)

    return 'avc_file'


def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-nested-blocks
    """
    Main entry point for the SELinux AVC Denial Analyzer.

    Handles command-line argument parsing, input validation, log processing,
    and output formatting. Supports multiple input methods (raw audit.log,
    pre-processed files, interactive input) and output formats (formatted, JSON).

    Command-line Arguments:
        -f, --file: Path to audit file (auto-detects format - recommended)
        -rf, --raw-file: Path to raw audit.log file (uses internal ausearch)
        -af, --avc-file: Path to pre-processed ausearch output file
        --json: Output results in JSON format for integration

    Raises:
        SystemExit: On argument validation errors or file processing failures
    """
    parser = argparse.ArgumentParser(
        description="A tool to parse an SELinux AVC denial log from a file or user prompt.")
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to audit file (auto-detects raw audit.log vs pre-processed format).")
    parser.add_argument(
        "-rf",
        "--raw-file",
        type=str,
        help="Path to a raw audit.log file containing the AVC log string.")
    parser.add_argument(
        "-af",
        "--avc-file",
        type=str,
        help="Path to a pre-processed file containing ausearch output.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the parsed data in JSON format.")
    args = parser.parse_args()

    # Set up signal handler for graceful interruption (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    # Create a Rich Console instance
    console = Console()

    # Comprehensive argument validation with enhanced error messages
    input_type = validate_arguments(args, console)

    log_string = ""

    if input_type == 'raw_file':
        # Determine the correct file path (could be from --file or --raw-file)
        file_path = args.file if args.file else args.raw_file
        if not args.json:
            console.print(f"Raw file input provided. Running ausearch on '{file_path}'...")
        try:
            ausearch_cmd = [
                "ausearch",
                "-m",
                "AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR",
                "-i",
                "-if",
                file_path]
            result = subprocess.run(ausearch_cmd, capture_output=True, text=True, check=True)
            log_string = result.stdout
        except FileNotFoundError:
            console.print("❌ [bold red]Error: ausearch Command Not Found[/bold red]")
            console.print("   The 'ausearch' command is required for processing raw audit files.")
            console.print("   [dim]Please install the audit package:[/dim]")
            console.print("   • [cyan]sudo dnf install audit[/cyan] (Fedora/RHEL)")
            console.print("   • [cyan]sudo apt install auditd[/cyan] (Ubuntu/Debian)")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            console.print("❌ [bold red]Error: ausearch Command Failed[/bold red]")
            console.print(f"   ausearch returned an error: [dim]{e.stderr.strip()}[/dim]")
            console.print("   [dim]This may indicate:[/dim]")
            console.print("   • File contains no AVC records")
            console.print("   • File format is not compatible with ausearch")
            console.print("   • Audit log file is corrupted")
            sys.exit(1)
    elif input_type == 'avc_file':
        # Determine the correct file path (could be from --file or --avc-file)
        file_path = args.file if args.file else args.avc_file
        if not args.json:
            console.print(f"Pre-processed AVC file provided: '{file_path}'")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                log_string = f.read()
        except Exception as e:
            # This should rarely happen due to pre-validation, but handle gracefully
            console.print(f"❌ [bold red]Error: Unexpected file reading error[/bold red]")
            console.print(f"   {str(e)}")
            sys.exit(1)
    else:  # interactive mode
        if not args.json:
            console.print(
                "📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] when done:")
#        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        try:
            log_string = sys.stdin.read()
        except EOFError:
            # Handle Ctrl+D (EOF) gracefully - this is normal end of input
            console.print("\n📄 [dim]Input completed (EOF received)[/dim]")
            log_string = ""

#   --- Split, De-duplicate, and Process Logic ---
# Old logic commented as it didn't look inside the block to remove time-> added by ausearch
    log_blocks = [block.strip() for block in log_string.split('----') if block.strip()]

# New logic trying to find and remove 'time->' if present in the log
#    log_blocks_raw = log_string.split('----')

#    log_blocks = []
#    for block in log_blocks_raw:
#        clean_lines = [line for line in block.strip().split('\n') if not line.strip().startswith('time->')]
#        if clean_lines:
#            log_blocks.append("\n".join(clean_lines))
    if not log_blocks:
        if not args.json:
            console.print("Error: No valid log blocks found.", style="bold red")
        sys.exit(1)

    unique_denials = {}
    all_unparsed_types = set()

    # First pass: Validate and analyze each block to determine signature strategy
    block_analysis = {}
    validation_warnings = []
    valid_blocks = []

    for i, block in enumerate(log_blocks):
        # Validate and sanitize the log block
        is_valid, sanitized_block, warnings = validate_log_entry(block)

        if not is_valid:
            if not args.json:
                console.print(
                    f"⚠️  [bold yellow]Warning: Skipping invalid log block {
                        i + 1}[/bold yellow]")
                for warning in warnings:
                    console.print(f"   [dim]• {warning}[/dim]")
            continue

        # Collect validation warnings for summary
        if warnings:
            validation_warnings.extend([(i + 1, w) for w in warnings])

        valid_blocks.append(sanitized_block)
        avc_denials, unparsed = parse_avc_log(sanitized_block)
        all_unparsed_types.update(unparsed)

        # Group by basic signature (without permission) to detect multiple permissions per block
        block_signatures = {}
        for parsed_log in avc_denials:
            if "permission" in parsed_log:
                basic_sig = (
                    parsed_log.get('scontext'), parsed_log.get('tcontext'),
                    parsed_log.get('tclass')
                )
                if basic_sig not in block_signatures:
                    block_signatures[basic_sig] = set()
                block_signatures[basic_sig].add(parsed_log.get('permission'))

        block_analysis[i] = {
            'avc_denials': avc_denials,
            'signatures_with_multiple_permissions': {
                sig for sig,
                perms in block_signatures.items() if len(perms) > 1}}

    # Check if we have any valid blocks after validation
    if not valid_blocks:
        if not args.json:
            console.print(
                "❌ [bold red]Error: No valid log blocks found after validation[/bold red]")
            console.print(
                "   [dim]All input blocks contained malformed or unrecognizable data.[/dim]")
        sys.exit(1)

    # Display validation summary (non-JSON mode only)
    if validation_warnings and not args.json:
        # Aggregate warnings by type for clearer messaging
        malformed_lines = 0
        empty_blocks = 0
        other_warnings = []

        for block_num, warning in validation_warnings:
            if "malformed or non-audit lines" in warning:
                # Extract number from warning like "Found 4 malformed or non-audit lines (skipped)"
                match = re.search(r'Found (\d+) malformed', warning)
                if match:
                    malformed_lines += int(match.group(1))
            elif "No AVC denial/grant records found" in warning:
                empty_blocks += 1
            else:
                other_warnings.append(warning)

        console.print(f"\n📋 [bold cyan]Input Processing Summary:[/bold cyan]")
        if malformed_lines > 0:
            console.print(f"   • Processed {len(valid_blocks)} audit record sections")
            console.print(f"   • Skipped {malformed_lines} non-audit lines (comments, headers, etc.)")
        if empty_blocks > 0:
            console.print(f"   • Found {empty_blocks} sections without AVC records (other audit types)")
        if other_warnings:
            for warning in other_warnings:
                console.print(f"   • {warning}")
        console.print(f"   • [bold green]Successfully processed all AVC data[/bold green]")
        console.print()  # Extra line for readability

    # Second pass: Process with appropriate signature strategy
    for i, block_data in block_analysis.items():
        avc_denials = block_data['avc_denials']
        multi_perm_sigs = block_data['signatures_with_multiple_permissions']

        for parsed_log in avc_denials:
            if "permission" in parsed_log:
                basic_sig = (
                    parsed_log.get('scontext'), parsed_log.get('tcontext'),
                    parsed_log.get('tclass')
                )
                permission = parsed_log.get('permission')

                # Decide signature strategy: include permission unless block has multiple
                # permissions for this signature
                if basic_sig in multi_perm_sigs:
                    # Multiple permissions in same block -> exclude permission from signature
                    signature = basic_sig
                else:
                    # Single permission in block -> include permission in signature
                    signature = basic_sig + (permission,)

                dt_obj = parsed_log.get('datetime_obj')

                if signature in unique_denials:
                    # Add permission to the set if not already present
                    if 'permissions' not in unique_denials[signature]:
                        unique_denials[signature]['permissions'] = set()
                    unique_denials[signature]['permissions'].add(permission)

                    # Collect varying fields (not part of signature)
                    varying_fields = ['pid', 'comm', 'path', 'dest_port', 'permissive', 'proctitle']
                    for field in varying_fields:
                        if field in parsed_log and parsed_log[field] not in ["(null)", "null", ""]:
                            field_key = f'{field}s'  # e.g., 'pids', 'comms', 'paths'
                            if field_key not in unique_denials[signature]:
                                unique_denials[signature][field_key] = set()
                            unique_denials[signature][field_key].add(parsed_log[field])

                    unique_denials[signature]['count'] += 1
                    # Only update last_seen_obj if this timestamp is newer
                    if dt_obj and (
                            not unique_denials[signature]['last_seen_obj'] or dt_obj > unique_denials[signature]['last_seen_obj']):
                        unique_denials[signature]['last_seen_obj'] = dt_obj
                else:
                    # Initialize new signature
                    denial_entry = {
                        'log': parsed_log,
                        'count': 1,
                        'first_seen_obj': dt_obj,
                        'last_seen_obj': dt_obj,
                        'permissions': {permission}
                    }

                    # Initialize varying fields for first occurrence
                    varying_fields = ['pid', 'comm', 'path', 'dest_port', 'permissive', 'proctitle']
                    for field in varying_fields:
                        if field in parsed_log and parsed_log[field] not in ["(null)", "null", ""]:
                            field_key = f'{field}s'  # e.g., 'pids', 'comms', 'paths'
                            denial_entry[field_key] = {parsed_log[field]}

                    unique_denials[signature] = denial_entry
    if args.json:
        # Convert the dictionary of unique denials to a list for JSON output
        output_list = []
        for denial_info in unique_denials.values():
            # Create a JSON-safe copy of the denial info
            json_denial = {
                'log': denial_info['log'].copy(),
                'count': denial_info['count'],
                'first_seen': denial_info['first_seen_obj'].isoformat() if denial_info['first_seen_obj'] else None,
                'last_seen': denial_info['last_seen_obj'].isoformat() if denial_info['last_seen_obj'] else None}

            # Add permissions set if it exists
            if 'permissions' in denial_info:
                json_denial['permissions'] = sorted(list(denial_info['permissions']))

            # Remove datetime_obj from the log data and convert any remaining datetime
            # objects to strings
            json_denial['log'].pop('datetime_obj', None)
            for key, value in json_denial['log'].items():
                if isinstance(value, datetime):
                    json_denial['log'][key] = value.isoformat()
                elif key == 'timestamp' and isinstance(value, (int, float)):
                    # Convert timestamp to string to ensure it's quoted in JSON
                    json_denial['log'][key] = str(value)
                elif isinstance(value, str):
                    # Clean up any problematic characters in string values
                    json_denial['log'][key] = value.replace(
                        '\x00',
                        '').replace(
                        '\r',
                        '').replace(
                        '\n',
                        '\\n')

            output_list.append(json_denial)

        try:
            json_output = json.dumps(output_list, indent=2, ensure_ascii=False)
            print(json_output)
        except (TypeError, ValueError) as e:
            console.print(f"Error generating JSON: {e}", style="bold red")
            # Fallback: print raw data for debugging
            console.print("Raw data that caused the error:", style="bold yellow")
            for i, item in enumerate(output_list):
                console.print(f"Item {i}: {item}")
            sys.exit(1)

    else:
        # Non JSON default output
        total_events = sum(denial['count'] for denial in unique_denials.values())
        console.print(
            f"\nFound {total_events} AVC events. Displaying {
                len(unique_denials)} unique denials...")
        sorted_denials = sorted(unique_denials.values(),
                                key=lambda x: x['first_seen_obj'] or datetime.fromtimestamp(0))
        if sorted_denials:
            console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))
        for i, denial_info in enumerate(sorted_denials):
            if i > 0:
                console.print(Rule(style="dim"))
            print_summary(console, denial_info, i + 1)
        console.print(
            f"\n[bold green]Analysis Complete:[/bold green] Processed {
                len(log_blocks)} log blocks and found {
                len(unique_denials)} unique denials.")

        # --- Added: Print the list of unparsed types found ---
        if all_unparsed_types:
            console.print(
                "\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:")
            console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")


if __name__ == "__main__":
    main()
