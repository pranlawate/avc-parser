#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
SELinux AVC Denial Analyzer

A forensic-focused tool for analyzing SELinux audit logs with intelligent
deduplication and clear correlation tracking. This tool specializes in
post-incident SELinux audit log analysis for complex denial patterns.

Author: Pranav Lawate
License: MIT
Version: 1.6.0
"""

import argparse
import io
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timedelta

from rich.align import Align
from rich.console import Console, Group
from rich.rule import Rule

from selinux.context import AvcContext, PermissionSemanticAnalyzer

# Local modules
from config import AUDIT_RECORD_RE, FILE_ANALYSIS_LINES, MAX_FILE_SIZE_MB
from utils import (
    context_matches,
    detect_file_format,
    format_bionic_text,
    format_path_for_display,
    generate_sesearch_command,
    human_time_ago,
    parse_time_range,
    path_matches,
    print_error,
    signal_handler,
    sort_denials,
)
from validators import (
    validate_arguments,
    validate_avc_file,
    validate_file_with_auto_detection,
    validate_raw_file,
)
from formatters import (
    display_report_brief_format,
    display_report_sealert_format,
    format_as_json,
    normalize_json_fields,
)
from detectors import (
    detect_dontaudit_disabled,
    detect_permissive_mode,
    has_container_paths,
    has_custom_paths,
    has_dontaudit_indicators,
    has_permissive_denials,
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

    host = match.group(2) or None
    record_type = match.group(4) or None
    event_id = match.group(6) or None
    body_text = match.group(10) or None

    return True, host, record_type, event_id, body_text




def validate_log_entry(
    log_block: str,
) -> tuple[bool, str, list]:  # pylint: disable=too-many-branches
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
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", log_block)
    if sanitized != log_block:
        warnings.append("Removed control characters from log data")

    # Check for basic audit log structure
    lines = sanitized.strip().split("\n")
    valid_lines = []
    malformed_lines = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check for basic audit record structure (handles optional whitespace)
        if re.search(r"type=\w+.*msg=audit\([^)]+\)\s*:", line):
            # Standard audit record format - valid
            valid_lines.append(line)
        elif re.search(r"(type=|msg=|avc:|denied|granted)", line, re.IGNORECASE):
            # Looks like audit content but possibly malformed - try to salvage
            valid_lines.append(line)
            malformed_lines += 1
        else:
            # Line doesn't look like audit content - skip it
            malformed_lines += 1

    # Generate warnings for malformed content
    if malformed_lines > 0:
        warnings.append(
            f"Found {malformed_lines} malformed or non-audit lines (skipped)"
        )

    # Check if we have any usable content
    if not valid_lines:
        return False, "", warnings + ["No valid audit log lines found"]

    # Look for audit/AVC content specifically
    has_audit_content = any(
        re.search(
            r"(type=AVC|type=USER_AVC|type=AVC_PATH|type=FANOTIFY|type=SELINUX_ERR|type=USER_SELINUX_ERR|type=MAC_POLICY_LOAD|type=1400|type=1107|type=1403|avc:.*denied|avc:.*granted|security_compute_sid)",
            line,
            re.IGNORECASE,
        )
        for line in valid_lines
    )

    if not has_audit_content:
        warnings.append(
            "No AVC/SELinux denial/error records found - may not contain SELinux events"
        )

    # Check for timestamp consistency
    timestamps = []
    for line in valid_lines:
        ts_match = re.search(r"msg=audit\(([^)]+)\)", line)
        if ts_match:
            timestamps.append(ts_match.group(1))

    if len(set(timestamps)) > 1:
        warnings.append(
            "Multiple different timestamps found - events may span different times"
        )

    sanitized_log = "\n".join(valid_lines)
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

    try:
        return _parse_avc_log_internal(log_block)
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Log parsing failed completely - return empty results
        # This prevents one corrupted block from breaking the entire analysis
        return [], {f"PARSE_ERROR_{type(e).__name__}"}


def _parse_avc_log_internal(log_block: str) -> tuple[list, set]:
    """
    Internal parsing function with detailed error handling for audit record processing.

    This is separated from the main function to allow comprehensive error handling
    while maintaining clean code organization.
    """
    avc_denials = []
    unparsed_types = set()

    # Extract timestamp context from the log block
    shared_context = parse_timestamp_from_audit_block(log_block)

    # Extract shared context from non-AVC records
    context_data, context_unparsed = extract_shared_context_from_non_avc_records(
        log_block
    )
    shared_context.update(context_data)
    unparsed_types.update(context_unparsed)

    # Process each AVC, USER_AVC, FANOTIFY, and SELINUX_ERR line separately
    for line in log_block.strip().split("\n"):
        line = line.strip()
        if re.search(r"type=(AVC|USER_AVC|AVC_PATH|FANOTIFY|SELINUX_ERR|USER_SELINUX_ERR|1400|1107)", line):
            # Parse this specific AVC/SELINUX_ERR line with error handling
            try:
                avc_data = process_individual_avc_record(line, shared_context)
                # For SELINUX_ERR, we don't have "permission", so check for error indicators or basic context
                if avc_data and ("permission" in avc_data or "selinux_error_reason" in avc_data or "selinux_operation" in avc_data or "invalid_context" in avc_data or avc_data.get("denial_type") in ["SELINUX_ERR", "USER_SELINUX_ERR"]):
                    avc_denials.append(avc_data)
            except Exception as parse_error:  # pylint: disable=broad-exception-caught
                # Individual AVC parsing failed - skip this record but continue with others
                # Add error information to unparsed types for tracking
                unparsed_types.add(f"AVC_PARSE_ERROR_{type(parse_error).__name__}")
                continue

    return avc_denials, unparsed_types


def parse_timestamp_from_audit_block(log_block: str) -> dict:
    """
    Extract and parse timestamp information from audit log block.

    Args:
        log_block (str): Multi-line audit log block

    Returns:
        dict: Timestamp context with datetime_obj, datetime_str, and timestamp fields
    """
    timestamp_context = {}

    # Parse timestamp from audit message header
    # Format: msg=audit(1234567890.123:456) where first part is timestamp
    timestamp_pattern = re.search(r"msg=audit\(([^)]+)\)", log_block)
    if timestamp_pattern:
        # Remove serial number (after last colon) to get just timestamp
        timestamp_str = timestamp_pattern.group(1).rsplit(":", 1)[0]

        # Try multiple timestamp formats in order of preference
        dt_object = None
        try:
            # Format 1: Human-readable MM/DD/YYYY from ausearch -i
            dt_object = datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S.%f")
        except ValueError:
            try:
                # Format 2: Alternative DD/MM/YY format from some ausearch outputs
                dt_object = datetime.strptime(timestamp_str, "%d/%m/%y %H:%M:%S.%f")
            except ValueError:
                try:
                    # Format 3: Unix timestamp (fallback for raw audit.log)
                    dt_object = datetime.fromtimestamp(float(timestamp_str))
                except ValueError:
                    # Timestamp parsing failed - will be handled gracefully
                    dt_object = None

        # Store parsed timestamp in multiple useful formats
        if dt_object:
            timestamp_context["datetime_obj"] = dt_object
            timestamp_context["datetime_str"] = dt_object.strftime("%Y-%m-%d %H:%M:%S")
            timestamp_context["timestamp"] = dt_object.timestamp()

    return timestamp_context




def extract_shared_context_from_non_avc_records(log_block: str) -> tuple[dict, set]:
    """
    Extract shared context information from non-AVC audit records.

    Args:
        log_block (str): Multi-line audit log block

    Returns:
        tuple[dict, set]: (shared_context, unparsed_types)
    """
    shared_context = {}
    unparsed_types = set()

    # Define regex patterns for extracting context from non-AVC audit records
    patterns = {
        "CWD": {"cwd": r"cwd=\"([^\"]+)\""},  # Current working directory
        "PATH": {
            "path": r"name=\"([^\"]+)\"",  # Quoted file path
            "path_unquoted": r"name=([^\s]+)",  # Unquoted path (fallback)
            "inode": r"inode=(\d+)",  # File inode number
            "dev": r"dev=([^\s]+)",  # Device identifier
        },
        "SYSCALL": {
            "syscall": r"syscall=([\w\d]+)",  # System call name/number
            "exe": r'exe=(?:"([^"]+)"|([^\s]+))',  # Executable path - quotes optional
            "exit": r"exit=([^\s(]+)",  # Exit code (EACCES, 0, etc.) - stop at parentheses
            "success": r"success=(yes|no)",  # Success flag
        },
        "PROCTITLE": {"proctitle": r"proctitle=(.+)"},  # Process command line
        "SOCKADDR": {
            "saddr": r"saddr=([a-fA-F0-9]+)"
        },  # Socket address info (hexadecimal format)
    }

    # Process non-AVC lines for shared context using enhanced parsing
    for line in log_block.strip().split("\n"):
        line = line.strip()

        # Use enhanced audit record parsing for better extraction
        parse_succeeded, host, record_type, event_id, body_text = (
            parse_audit_record_text(line)
        )
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
                shared_context["host"] = host
            if event_id:
                shared_context["event_id"] = event_id

        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                field_match = re.search(pattern, line)
                if field_match:
                    # Handle patterns with multiple capture groups (quoted/unquoted)
                    if key == "exe" and log_type == "SYSCALL" and len(field_match.groups()) > 1:
                        value = (field_match.group(1) or field_match.group(2)).strip()
                    else:
                        value = field_match.group(1)
                    if key == "proctitle":
                        value = value.strip()  # Remove any trailing whitespace
                        # Check if it's quoted
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]  # Remove quotes

                        # Try hex decode first (for raw audit.log processing)
                        try:
                            if all(c in "0123456789ABCDEFabcdef" for c in value) and len(value) % 2 == 0:
                                decoded = bytes.fromhex(value).decode()
                                decoded_with_spaces = decoded.replace('\x00', ' ')

                                # Check for audit system truncation (128 char limit for proctitle)
                                if (len(value) == 256 and len(decoded_with_spaces) == 128 and
                                    not decoded.endswith('\x00')):
                                    decoded_with_spaces += " [TRUNCATED BY AUDIT]"

                                shared_context[key] = decoded_with_spaces
                            else:
                                # Not hex - likely already decoded by ausearch -i
                                # Check for truncation in already-decoded text (128 char limit)
                                if len(value) == 128:
                                    value += " [TRUNCATED BY AUDIT]"
                                shared_context[key] = value
                        except ValueError:
                            # If hex decoding fails, use as-is and check for truncation
                            if len(value) == 128:
                                value += " [TRUNCATED BY AUDIT]"
                            shared_context[key] = value
                    elif key == "path_unquoted":
                        # Only use unquoted path if we don't already have a quoted path
                        if "path" not in shared_context:
                            shared_context["path"] = value.strip()
                    else:
                        shared_context[key] = value.strip()
        elif log_type not in ("AVC", "USER_AVC", "AVC_PATH", "FANOTIFY", "SELINUX_ERR", "USER_SELINUX_ERR", "MAC_POLICY_LOAD", "1400", "1107", "1403"):
            # Track unparsed types (excluding all supported AVC/SELinux-related types)
            unparsed_types.add(log_type)

    return shared_context, unparsed_types


def process_individual_avc_record(line: str, shared_context: dict) -> dict:
    """
    Process a single AVC record line and extract denial information.

    Args:
        line (str): Single AVC record line
        shared_context (dict): Shared context from non-AVC records

    Returns:
        dict: Parsed AVC data with semantic analysis, or empty dict if parsing fails
    """
    try:
        avc_data = shared_context.copy()  # Start with shared context

        # Determine record type and extract content accordingly
        record_type_match = re.search(r"type=(AVC|USER_AVC|AVC_PATH|FANOTIFY|SELINUX_ERR|USER_SELINUX_ERR|1400|1107)", line)
        if not record_type_match:
            return {}

        record_type = record_type_match.group(1)

        # Handle SELINUX_ERR - different format, SELinux internal errors
        if record_type == "SELINUX_ERR":
            # SELINUX_ERR format: security_compute_sid: invalid context ... for scontext=... tcontext=... tclass=...
            selinux_err_match = re.search(
                r"(?:security_compute_sid|security_bounded_transition|op=\w+).*?scontext=(\S+).*?tcontext=(\S+).*?tclass=(\S+)",
                line
            )
            if selinux_err_match:
                # Parse scontext into AvcContext object (same as AVC handling)
                scontext_string = selinux_err_match.group(1)
                scontext_obj = AvcContext(scontext_string)
                if scontext_obj.is_valid():
                    avc_data["scontext"] = scontext_obj
                    avc_data["scontext_raw"] = scontext_string
                else:
                    avc_data["scontext"] = scontext_string

                # Parse tcontext into AvcContext object (same as AVC handling)
                tcontext_string = selinux_err_match.group(2)
                tcontext_obj = AvcContext(tcontext_string)
                if tcontext_obj.is_valid():
                    avc_data["tcontext"] = tcontext_obj
                    avc_data["tcontext_raw"] = tcontext_string
                else:
                    avc_data["tcontext"] = tcontext_string

                avc_data["tclass"] = selinux_err_match.group(3)
                avc_data["denial_type"] = "SELINUX_ERR"
                # Extract operation/reason if available
                reason_match = re.search(r"reason=(\w+)", line)
                if reason_match:
                    avc_data["selinux_error_reason"] = reason_match.group(1)
                # Extract invalid context if present
                invalid_ctx_match = re.search(r"invalid context ([^\s]+)", line)
                if invalid_ctx_match:
                    avc_data["invalid_context"] = invalid_ctx_match.group(1)
                return avc_data
            else:
                return {}

        # Handle USER_SELINUX_ERR - similar to USER_AVC but for SELinux errors
        elif record_type == "USER_SELINUX_ERR":
            # Extract msg content from USER_SELINUX_ERR
            msg_match = re.search(r"msg='([^']+)'", line)
            if msg_match:
                err_content = msg_match.group(1)
                # Extract basic fields from outer message
                user_fields = {
                    "pid": r"pid=(\S+)",
                    "uid": r"uid=(\S+)",
                }
                for key, pattern in user_fields.items():
                    field_match = re.search(pattern, line)
                    if field_match:
                        avc_data[key] = field_match.group(1).strip()

                # Parse the error message content
                selinux_err_match = re.search(
                    r"(?:op=(\w+)).*?(?:oldcontext|scontext)=(\S+).*?(?:newcontext|tcontext)=(\S+)",
                    err_content
                )
                if selinux_err_match:
                    avc_data["selinux_operation"] = selinux_err_match.group(1)

                    # Parse scontext into AvcContext object (same as AVC handling)
                    scontext_string = selinux_err_match.group(2)
                    scontext_obj = AvcContext(scontext_string)
                    if scontext_obj.is_valid():
                        avc_data["scontext"] = scontext_obj
                        avc_data["scontext_raw"] = scontext_string
                    else:
                        avc_data["scontext"] = scontext_string

                    # Parse tcontext into AvcContext object (same as AVC handling)
                    tcontext_string = selinux_err_match.group(3)
                    tcontext_obj = AvcContext(tcontext_string)
                    if tcontext_obj.is_valid():
                        avc_data["tcontext"] = tcontext_obj
                        avc_data["tcontext_raw"] = tcontext_string
                    else:
                        avc_data["tcontext"] = tcontext_string

                    avc_data["denial_type"] = "USER_SELINUX_ERR"
                    # Extract result if available
                    result_match = re.search(r"seresult=(\w+)", err_content)
                    if result_match:
                        avc_data["selinux_error_result"] = result_match.group(1)
                    return avc_data
            return {}

        # Handle USER_AVC and numeric equivalent (1107)
        elif record_type in ("USER_AVC", "1107"):
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
                return {}
        else:
            # Handle AVC, AVC_PATH, FANOTIFY, and numeric equivalent (1400)
            avc_content = line

        # Set the denial type based on the record type
        if record_type == "FANOTIFY":
            avc_data["denial_type"] = "FANOTIFY"
        elif record_type in ("USER_AVC", "1107"):
            avc_data["denial_type"] = "USER_AVC"
        elif record_type == "AVC_PATH":
            avc_data["denial_type"] = "AVC_PATH"
        else:
            # AVC, 1400, or any other kernel AVC type
            avc_data["denial_type"] = "AVC"

        # Parse timestamp from this specific AVC line (overrides shared context)
        timestamp_pattern = re.search(r"msg=audit\(([^)]+)\)", line)
        if timestamp_pattern:
            # Remove serial number (after last colon) to get just timestamp
            timestamp_str = timestamp_pattern.group(1).rsplit(":", 1)[0]

            # Try multiple timestamp formats in order of preference
            dt_object = None
            try:
                # Format 1: Human-readable MM/DD/YYYY from ausearch -i
                dt_object = datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S.%f")
            except ValueError:
                try:
                    # Format 2: Alternative DD/MM/YY format from some ausearch outputs
                    dt_object = datetime.strptime(timestamp_str, "%d/%m/%y %H:%M:%S.%f")
                except ValueError:
                    try:
                        # Format 3: Unix timestamp (fallback for raw audit.log)
                        dt_object = datetime.fromtimestamp(float(timestamp_str))
                    except ValueError:
                        # Timestamp parsing failed - will be handled gracefully
                        dt_object = None

            # Store parsed timestamp in multiple useful formats (overrides shared context)
            if dt_object:
                avc_data["datetime_obj"] = dt_object
                avc_data["datetime_str"] = dt_object.strftime("%Y-%m-%d %H:%M:%S")
                avc_data["timestamp"] = dt_object.timestamp()

        # Extract AVC-specific fields (works for both AVC and USER_AVC msg content)
        avc_patterns = {
            "permission": r"denied\s+\{ ([^}]+) \}",
            "pid": r"pid=(\S+)",
            "comm": r"comm=(?:\"([^\"]+)\"|([^\s]+))",
            "exe": r'exe=(?:"([^"]+)"|([^\s]+))',  # Executable path - quotes optional (ausearch -i strips them)
            "proctitle": r'proctitle=(?:"([^"]+)"|([^\s]+))',  # Process title - quotes optional
            "path": r"path=\"([^\"]+)\"",
            "path_unquoted": r"path=([^\s]+)",  # For unquoted paths in AVC
            "name": r"name=([^\s]+)",  # name field in AVC (often just filename)
            "dev": r"dev=\"?([^\"\\s]+)\"?",  # Device, may or may not be quoted
            "ino": r"ino=(\d+)",  # Inode number
            "scontext": r"scontext=(\S+)",
            "tcontext": r"tcontext=(\S+)",
            "tclass": r"tclass=(\S+)",
            "dest_port": r"dest=(\S+)",
            "dbus_dest": r"dest=(:\d+\.\d+)",  # D-Bus destination pattern
            "permissive": r"permissive=(\d+)",
        }

        for key, pattern in avc_patterns.items():
            field_match = re.search(pattern, avc_content)
            if field_match:
                # For USER_AVC, don't override pid if it was already set from outer message
                if "type=USER_AVC" in line and key == "pid" and key in avc_data:
                    continue

                if key in ("comm", "exe") and len(field_match.groups()) > 1:
                    # Handle comm and exe fields that can be quoted or unquoted
                    # ausearch -i strips quotes, so we need to handle both formats
                    avc_data[key] = (
                        field_match.group(1) or field_match.group(2)
                    ).strip()
                elif key == "path_unquoted":
                    # Only use unquoted path if we don't already have a quoted path
                    if "path" not in avc_data:
                        avc_data["path"] = field_match.group(1).strip()
                elif key in ("scontext", "tcontext"):
                    # Parse SELinux contexts into AvcContext objects for enhanced analysis
                    context_string = field_match.group(1).strip()
                    avc_context = AvcContext(context_string)
                    if avc_context.is_valid():
                        avc_data[key] = avc_context
                        # Also store raw string for backward compatibility
                        avc_data[f"{key}_raw"] = context_string
                    else:
                        # Fall back to raw string if parsing fails
                        avc_data[key] = context_string
                elif key == "proctitle":
                    # Handle hex-encoded proctitle in AVC records (same as shared context processing)
                    # Handle quoted or unquoted proctitle
                    raw_proctitle = (field_match.group(1) or field_match.group(2)).strip() if len(field_match.groups()) > 1 else field_match.group(1).strip()
                    try:
                        # Check if it's hex-encoded (all hex characters and even length)
                        if all(c in "0123456789ABCDEFabcdef" for c in raw_proctitle) and len(raw_proctitle) % 2 == 0:
                            decoded = bytes.fromhex(raw_proctitle).decode('utf-8', errors='ignore')
                            # Replace null bytes with spaces (they're used as separators in proctitle)
                            decoded_with_spaces = decoded.replace('\x00', ' ')

                            # Check for audit system truncation (128 char limit for proctitle)
                            if (len(raw_proctitle) == 256 and len(decoded_with_spaces) == 128 and
                                not decoded.endswith('\x00')):
                                # Add truncation indicator
                                decoded_with_spaces += " [TRUNCATED BY AUDIT]"

                            avc_data[key] = decoded_with_spaces.strip()
                        else:
                            # Not hex-encoded, use as-is
                            avc_data[key] = raw_proctitle
                    except (ValueError, UnicodeDecodeError):
                        # If hex decoding fails, use raw value
                        avc_data[key] = raw_proctitle
                else:
                    avc_data[key] = field_match.group(1).strip()

        # Enhanced path resolution logic
        if "path" not in avc_data or not avc_data["path"]:
            # No path in AVC, try to use PATH record data or build from available info
            if shared_context.get("path"):
                avc_data["path"] = shared_context["path"]
                avc_data["path_type"] = "file_path"
            elif avc_data.get("name") and avc_data["name"] not in ("?", '"?"'):
                # We have a meaningful name field, use it as the path (common for directory access)
                # Skip meaningless names like "?" which appear in D-Bus records
                name_value = avc_data["name"]
                # Handle quoted vs unquoted names
                if name_value.startswith('"') and name_value.endswith('"'):
                    name_value = name_value[1:-1]

                # For directories, the name is often just the directory name without full path
                # Mark this as a partial path for better display and indicate it's incomplete
                if avc_data.get("tclass") == "dir":
                    avc_data["path"] = (
                        f".../{name_value}"  # Indicate this is a partial path
                    )
                    avc_data["path_type"] = "directory_name"
                else:
                    avc_data["path"] = name_value
                    avc_data["path_type"] = "name_only"
            elif avc_data.get("dev") and avc_data.get("ino"):
                # Create a dev+inode identifier when path is missing
                avc_data["path"] = f"dev:{avc_data['dev']},inode:{avc_data['ino']}"
                avc_data["path_type"] = "dev_inode"
            elif shared_context.get("dev") and shared_context.get("inode"):
                # Use PATH record dev+inode if available
                dev_val = shared_context["dev"]
                inode_val = shared_context["inode"]
                avc_data["path"] = f"dev:{dev_val},inode:{inode_val}"
                avc_data["path_type"] = "dev_inode"
        else:
            # We have a path, mark it as a regular path
            avc_data["path_type"] = "file_path"

        # Use comm as fallback for proctitle if proctitle is null or missing
        if avc_data.get("proctitle") in ("(null)", "null", "", None) and avc_data.get(
            "comm"
        ):
            avc_data["proctitle"] = avc_data["comm"]

        # Add semantic analysis for enhanced user comprehension
        if avc_data.get("permission") and avc_data.get("tclass"):
            permission = avc_data["permission"]
            obj_class = avc_data["tclass"]
            source_context = avc_data.get("scontext")
            target_context = avc_data.get("tcontext")

            # Add context-aware permission description
            # Map tclass to resource_type for context-aware descriptions
            resource_type = "directory" if obj_class == "dir" else "file" if obj_class == "file" else None
            if resource_type and resource_type in ["file", "directory"]:
                avc_data["permission_description"] = (
                    PermissionSemanticAnalyzer.get_permission_description_with_context(permission, resource_type)
                )
            else:
                avc_data["permission_description"] = (
                    PermissionSemanticAnalyzer.get_permission_description(permission)
                )

            # Add contextual analysis
            process_name = avc_data.get("comm")
            avc_data["contextual_analysis"] = (
                PermissionSemanticAnalyzer.get_contextual_analysis(
                    permission, obj_class, source_context, target_context, process_name
                )
            )

            # Add object class description
            avc_data["class_description"] = (
                PermissionSemanticAnalyzer.get_class_description(obj_class)
            )

            # Add source type description if available
            if source_context and hasattr(source_context, "get_type_description"):
                avc_data["source_type_description"] = (
                    source_context.get_type_description()
                )

            # Add target type description if available
            if target_context and hasattr(target_context, "get_type_description"):
                avc_data["target_type_description"] = (
                    target_context.get_type_description()
                )

            # Add port description for network denials
            if avc_data.get("dest_port"):
                avc_data["port_description"] = (
                    PermissionSemanticAnalyzer.get_port_description(
                        avc_data["dest_port"]
                    )
                )

        return avc_data

    except Exception:
        # Individual AVC parsing failed - return empty dict
        return {}


def parse_mac_policy_load_events(log_block: str) -> list:
    """
    Parse MAC_POLICY_LOAD events from audit log.

    MAC_POLICY_LOAD events indicate when SELinux policy is loaded or reloaded.
    These are informational events, not denials.

    Args:
        log_block (str): Multi-line audit log block

    Returns:
        list: List of policy load event dictionaries with timestamp, auid, ses
    """
    policy_events = []

    for line in log_block.strip().split('\n'):
        # Match MAC_POLICY_LOAD or numeric type 1403
        if not re.search(r"type=(MAC_POLICY_LOAD|1403)", line):
            continue

        event = {}

        # Extract timestamp - handle both raw and ausearch -i formats
        # Raw: audit(1163776448.949:12869)
        # ausearch -i: audit(17/11/06 20:44:08.949:12869)
        ts_match_raw = re.search(r"audit\((\d+\.\d+):(\d+)\)", line)
        ts_match_interpreted = re.search(r"audit\((\d{2}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+):(\d+)\)", line)

        if ts_match_raw:
            # Raw format
            timestamp = float(ts_match_raw.group(1))
            event_id = ts_match_raw.group(2)
            event["timestamp"] = timestamp
            event["event_id"] = f"{timestamp}:{event_id}"

            try:
                dt_obj = datetime.fromtimestamp(timestamp)
                event["datetime_obj"] = dt_obj
                event["datetime_str"] = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError):
                event["datetime_str"] = "unknown"
                event["datetime_obj"] = None
        elif ts_match_interpreted:
            # ausearch -i format: "17/11/06 20:44:08.949:12869"
            date_str = ts_match_interpreted.group(1)  # "17/11/06"
            time_str = ts_match_interpreted.group(2)  # "20:44:08.949"
            event_id = ts_match_interpreted.group(3)

            # Parse the date and time
            try:
                # Parse "DD/MM/YY HH:MM:SS.mmm" format
                dt_str = f"{date_str} {time_str}"
                dt_obj = datetime.strptime(dt_str, "%d/%m/%y %H:%M:%S.%f")
                event["datetime_obj"] = dt_obj
                event["datetime_str"] = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                event["timestamp"] = dt_obj.timestamp()
                event["event_id"] = f"{event['timestamp']}:{event_id}"
            except ValueError:
                event["datetime_str"] = "unknown"
                event["datetime_obj"] = None

        # Extract auid (audit user ID) - handle both raw and interpreted formats
        # Raw: auid=500 or auid=4294967295
        # Interpreted: auid=unknown(500) or auid=unset
        auid_match_interpreted = re.search(r"auid=(\w+)\((\d+)\)", line)  # auid=unknown(500)
        auid_match_raw = re.search(r"auid=(\d+)", line)  # auid=500
        auid_match_unset = re.search(r"auid=(unset)", line)  # auid=unset

        if auid_match_interpreted:
            # ausearch -i format: auid=unknown(500)
            auid = auid_match_interpreted.group(2)
            event["auid"] = auid
            event["auid_display"] = auid
        elif auid_match_unset:
            # ausearch -i format: auid=unset
            event["auid"] = "4294967295"
            event["auid_display"] = "unset"
        elif auid_match_raw:
            # Raw format: auid=500
            auid = auid_match_raw.group(1)
            event["auid"] = auid
            if auid == "4294967295":
                event["auid_display"] = "unset"
            else:
                event["auid_display"] = auid

        # Extract ses (session ID) - handle both formats
        ses_match_unset = re.search(r"ses=(unset)", line)
        ses_match = re.search(r"ses=(\d+)", line)

        if ses_match_unset:
            event["ses"] = "4294967295"
            event["ses_display"] = "unset"
        elif ses_match:
            ses = ses_match.group(1)
            event["ses"] = ses
            if ses == "4294967295":
                event["ses_display"] = "unset"
            else:
                event["ses_display"] = ses

        if event:  # Only append if we extracted some data
            policy_events.append(event)

    return policy_events


def build_correlation_event(parsed_log: dict, permission: str) -> dict:
    """
    Build a correlation event dictionary from parsed log data.

    Args:
        parsed_log (dict): Parsed AVC log data
        permission (str): The specific permission for this event

    Returns:
        dict: Clean correlation event with non-null values only
    """
    correlation_event = {
        "pid": parsed_log.get("pid"),
        "comm": parsed_log.get("comm"),
        "exe": parsed_log.get("exe"),  # Executable path for fallback when comm is missing
        "proctitle": parsed_log.get("proctitle"),  # Process title for fallback
        "path": parsed_log.get("path"),
        "permission": permission,
        "permissive": parsed_log.get("permissive"),
        "timestamp": parsed_log.get("datetime_str"),
        "syscall": parsed_log.get("syscall"),  # System call that triggered the denial
        "dest_port": parsed_log.get("dest_port"),
        "saddr": parsed_log.get("saddr"),
        "tclass": parsed_log.get("tclass"),
        "exit": parsed_log.get("exit"),
        "success": parsed_log.get("success"),
    }
    # Only store non-null values to keep correlations clean
    return {
        k: v
        for k, v in correlation_event.items()
        if v not in [None, "(null)", "null", ""]
    }


def get_enhanced_permissions_display(denial_info: dict, parsed_log: dict) -> str:
    """
    Generate enhanced permission display string with semantic descriptions.

    Args:
        denial_info (dict): Aggregated denial information containing permissions set
        parsed_log (dict): Parsed log data with permission_description if available

    Returns:
        str: Enhanced permissions string with descriptions
    """
    # Get tclass for context-aware permission descriptions
    tclass = parsed_log.get("tclass", "")
    # Map tclass to resource_type
    resource_type = "directory" if tclass == "dir" else "file" if tclass == "file" else None

    if "permissions" in denial_info and len(denial_info["permissions"]) > 1:
        # Multiple permissions case
        enhanced_perms = []
        for perm in sorted(denial_info["permissions"]):
            if parsed_log.get("permission") == perm and parsed_log.get(
                "permission_description"
            ):
                perm_desc = parsed_log["permission_description"]
            else:
                # Use context-aware description if we have a resource type
                if resource_type and resource_type in ["file", "directory"]:
                    perm_desc = PermissionSemanticAnalyzer.get_permission_description_with_context(perm, resource_type)
                else:
                    perm_desc = PermissionSemanticAnalyzer.get_permission_description(perm)

            if perm_desc != perm:
                enhanced_perms.append(f"{perm} ({perm_desc})")
            else:
                enhanced_perms.append(perm)
        return ", ".join(enhanced_perms)

    elif parsed_log.get("permission_description"):
        # Single permission with description
        permission = parsed_log.get("permission", "")
        return f"{permission} ({parsed_log['permission_description']})"

    else:
        # Fallback to raw permission
        return parsed_log.get("permission", "")


def get_process_category(comm: str, source_context: AvcContext = None) -> str:
    """
    Categorize processes for service distinction in smart signatures.

    Args:
        comm (str): Process command name
        source_context (AvcContext): Source security context

    Returns:
        str: Process category for signature grouping
    """
    if not comm:
        return "unknown"

    # Service-specific categorization for domains that run multiple services
    service_mappings = {
        # Web servers
        "httpd": "web_server_apache",
        "nginx": "web_server_nginx",
        "lighttpd": "web_server_lighttpd",
        "caddy": "web_server_caddy",
        # Database servers
        "mysqld": "database_mysql",
        "postgres": "database_postgresql",
        "mongod": "database_mongodb",
        "redis-server": "database_redis",
        # System services
        "systemd": "init_systemd",
        "init": "init_sysv",
        "logrotate": "system_logrotate",
        "cron": "system_cron",
        "crond": "system_cron",
        "ntpdate": "system_ntp",
        "chronyd": "system_ntp",
        "aide": "security_aide",
        # SSH services
        "sshd": "ssh_daemon",
        "ssh": "ssh_client",
        "unix_chkpwd": "ssh_auth",
        # Container/virtualization
        "docker": "container_docker",
        "podman": "container_podman",
        "runc": "container_runtime",
        # Desktop/user services
        "gnome-shell": "desktop_gnome",
        "plasma": "desktop_kde",
        "pulseaudio": "audio_pulse",
        "pipewire": "audio_pipewire",
    }

    # Check for direct mapping first
    if comm in service_mappings:
        return service_mappings[comm]

    # Check for pattern-based mappings for related processes
    # Apache web server variants
    if comm.startswith("httpd") or comm.endswith("-httpd") or "httpd" in comm:
        return "web_server_apache"

    # Nginx variants
    if comm.startswith("nginx") or comm.endswith("-nginx") or "nginx" in comm:
        return "web_server_nginx"

    # PostgreSQL variants
    if comm.startswith("postgres") or "postgres" in comm:
        return "database_postgresql"

    # MySQL variants
    if comm.startswith("mysql") or "mysql" in comm:
        return "database_mysql"

    # SSH variants
    if comm.startswith("sshd") or "sshd" in comm:
        return "ssh_daemon"

    # Handle multi-service domains that need process distinction
    if source_context and source_context.type:
        multi_service_domains = {
            "unconfined_t": f"unconfined_{comm}",
            "init_t": f"init_{comm}",
            "user_t": f"user_{comm}",
            "admin_t": f"admin_{comm}",
        }

        if source_context.type in multi_service_domains:
            return multi_service_domains[source_context.type]

    # Default: use command name directly
    return f"service_{comm}"


def get_permission_category(permission: str, tclass: str) -> str:
    """
    Categorize permissions for grouping related operations in smart signatures.

    Args:
        permission (str): SELinux permission
        tclass (str): Target object class

    Returns:
        str: Permission category for signature grouping
    """
    # File system operations that commonly group together
    file_access_perms = {"read", "write", "append", "getattr", "open"}
    file_create_perms = {"create", "write", "add_name", "setattr"}
    file_execute_perms = {"execute", "execute_no_trans", "entrypoint"}
    file_manage_perms = {"unlink", "remove_name", "rename", "rmdir"}

    # Network operations that commonly group together
    net_bind_perms = {"name_bind", "bind", "listen"}
    net_connect_perms = {"name_connect", "connect", "send_msg", "recv_msg"}

    # Process/security operations
    process_signal_perms = {"signal", "signull", "sigkill", "sigstop"}
    process_trace_perms = {"ptrace", "getsched", "setsched"}
    process_transition_perms = {"transition", "entrypoint", "execute"}

    # D-Bus operations
    dbus_communication_perms = {"send_msg", "acquire_svc", "own"}

    # Security key operations
    key_access_perms = {"read", "view", "search", "link"}
    key_manage_perms = {"write", "create", "setattr", "chown"}

    # System capability operations
    capability_perms = {"use", "audit_access", "audit_control", "setuid", "setgid"}

    # System security operations
    security_perms = {
        "enforce",
        "load_policy",
        "compute_av",
        "compute_create",
        "check_context",
    }

    # Check permission against categories
    if tclass in [
        "file",
        "dir",
        "lnk_file",
        "chr_file",
        "blk_file",
        "sock_file",
        "fifo_file",
    ]:
        if permission in file_access_perms:
            return "file_access"
        elif permission in file_create_perms:
            return "file_create"
        elif permission in file_execute_perms:
            return "file_execute"
        elif permission in file_manage_perms:
            return "file_manage"
        else:
            return f"file_{permission}"

    elif tclass in [
        "tcp_socket",
        "udp_socket",
        "unix_stream_socket",
        "unix_dgram_socket",
    ]:
        if permission in net_bind_perms:
            return "net_bind"
        elif permission in net_connect_perms:
            return "net_connect"
        else:
            return f"net_{permission}"

    elif tclass == "process":
        if permission in process_signal_perms:
            return "process_signal"
        elif permission in process_trace_perms:
            return "process_trace"
        elif permission in process_transition_perms:
            return "process_transition"
        else:
            return f"process_{permission}"

    elif tclass == "dbus":
        if permission in dbus_communication_perms:
            return "dbus_communication"
        else:
            return f"dbus_{permission}"

    elif tclass == "key":
        if permission in key_access_perms:
            return "key_access"
        elif permission in key_manage_perms:
            return "key_manage"
        else:
            return f"key_{permission}"

    elif tclass in ["capability", "capability2"]:
        if permission in capability_perms:
            return "capability_use"
        else:
            return f"capability_{permission}"

    elif tclass == "security":
        if permission in security_perms:
            return "security_control"
        else:
            return f"security_{permission}"

    # Default: use permission directly for other classes
    return permission


def get_object_group(tclass: str) -> str:
    """
    Group object classes for smart signature generation.

    Args:
        tclass (str): SELinux object class

    Returns:
        str: Object group for signature purposes
    """
    # Filesystem objects that often share similar remediation
    filesystem_objects = {
        "file",
        "dir",
        "lnk_file",
        "chr_file",
        "blk_file",
        "sock_file",
        "fifo_file",
        "anon_inode",
    }

    # Network objects
    network_objects = {
        "tcp_socket",
        "udp_socket",
        "rawip_socket",
        "netlink_socket",
        "unix_stream_socket",
        "unix_dgram_socket",
        "socket",
    }

    # IPC objects
    ipc_objects = {"sem", "msg", "msgq", "shm", "ipc"}

    # System objects
    system_objects = {"process", "security", "system", "capability", "capability2"}

    if tclass in filesystem_objects:
        return "filesystem"
    elif tclass in network_objects:
        return "network"
    elif tclass in ipc_objects:
        return "ipc"
    elif tclass in system_objects:
        return "system"
    else:
        # Keep specific classes that need distinct treatment
        return tclass


def get_path_pattern(path: str, tclass: str) -> str:
    """
    Extract path patterns for fcontext rule grouping.

    Args:
        path (str): File/directory path
        tclass (str): Target object class

    Returns:
        str: Path pattern for signature grouping
    """
    if not path or path in ["?", '"?"', "unknown"]:
        return "no_path"

    # Handle dev+inode identifiers
    if path.startswith("dev:"):
        return "dev_inode"

    # Extract meaningful path patterns for fcontext rules
    import re

    # Common system directories that group well
    system_patterns = {
        r"^/var/log(/.*)?$": "/var/log(/.*)?",
        r"^/var/local/log(/.*)?$": "/var/local/log(/.*)?",  # Add specific pattern for /var/local/log
        r"^/var/spool(/.*)?$": "/var/spool(/.*)?",
        r"^/var/run(/.*)?$": "/var/run(/.*)?",
        r"^/var/lib(/.*)?$": "/var/lib(/.*)?",
        r"^/etc(/.*)?$": "/etc(/.*)?",
        r"^/usr/bin(/.*)?$": "/usr/bin(/.*)?",
        r"^/usr/sbin(/.*)?$": "/usr/sbin(/.*)?",
        r"^/usr/lib(/.*)?$": "/usr/lib(/.*)?",
        r"^/home/[^/]+(/.*)?$": "/home/[^/]+(/.*)?",
        r"^/tmp(/.*)?$": "/tmp(/.*)?",
        r"^/var/tmp(/.*)?$": "/var/tmp(/.*)?",
    }

    # Web server specific patterns
    web_patterns = {
        r"^/var/www(/.*)?$": "/var/www(/.*)?",
        r"^/srv/www(/.*)?$": "/srv/www(/.*)?",
        r"^/usr/share/nginx(/.*)?$": "/usr/share/nginx(/.*)?",
        r"^/etc/httpd(/.*)?$": "/etc/httpd(/.*)?",
        r"^/etc/nginx(/.*)?$": "/etc/nginx(/.*)?",
    }

    # Container storage patterns (already handled by format_path_for_display)
    container_patterns = {
        r".*/containers/storage/overlay/[^/]+/.*": "/containers/storage/overlay/*/...",
    }

    # Check patterns in order of specificity
    all_patterns = {**web_patterns, **container_patterns, **system_patterns}

    for pattern, replacement in all_patterns.items():
        if re.match(pattern, path):
            return replacement

    # For unmatched paths, normalize to directory patterns for grouping
    # Both files and directories should use the same base pattern for location-based grouping
    if tclass in ["file", "dir"]:
        if tclass == "file":
            # Extract directory pattern for files
            dir_path = "/".join(path.split("/")[:-1])
            if dir_path:
                return f"{dir_path}/*"
        elif tclass == "dir":
            # For directories, use the directory itself as the pattern base
            if path.startswith("..."):
                # This is a partial directory name like ".../sterling" or ".../info_server"
                # Extract the actual directory name
                dir_name = path.split("/")[-1]

                # Map common directory names to use the same pattern as their corresponding files
                # This ensures directories and files in the same location get grouped together
                if dir_name in ["sterling", "info_server", "log"]:
                    # Use the same pattern that files in /var/local/log get from the regex
                    return "/var/local/log(/.*)?"

                # For unknown partial paths, assume they're also in /var/local/log
                return "/var/local/log(/.*)?"
            else:
                # For full directory paths, use the directory as base pattern
                return f"{path}/*"

    # Keep the exact path for other cases
    return path


def validate_grouping_optimality(unique_denials: dict) -> dict:
    """
    Validate grouping optimality by analyzing sesearch command uniqueness.

    This function checks if our current grouping produces optimal distinct policy queries
    by identifying groups that generate identical sesearch commands.

    Args:
        unique_denials (dict): Dictionary of grouped denials with signatures as keys

    Returns:
        dict: Validation report containing:
            - total_groups: Number of current groups
            - unique_sesearch_commands: Number of distinct sesearch commands
            - optimization_potential: Groups that could be merged
            - efficiency_score: Ratio of unique commands to total groups (1.0 = optimal)
    """
    sesearch_to_groups = {}
    optimization_potential = []

    # Group denials by their sesearch commands
    for signature, denial_info in unique_denials.items():
        sesearch_cmd = generate_sesearch_command(denial_info["log"])
        if sesearch_cmd:
            if sesearch_cmd not in sesearch_to_groups:
                sesearch_to_groups[sesearch_cmd] = []
            sesearch_to_groups[sesearch_cmd].append(signature)

    # Identify optimization opportunities (multiple groups with same sesearch command)
    for sesearch_cmd, group_signatures in sesearch_to_groups.items():
        if len(group_signatures) > 1:
            # Multiple groups have the same sesearch command - potential for merging
            group_details = []
            for signature in group_signatures:
                denial_info = unique_denials[signature]
                group_details.append({
                    "signature": signature,
                    "count": denial_info["count"],
                    "sample_process": denial_info["log"].get("comm", "unknown"),
                    "sample_path": denial_info["log"].get("path", "unknown")
                })

            optimization_potential.append({
                "sesearch_command": sesearch_cmd,
                "duplicate_groups": group_details,
                "merge_potential": len(group_signatures)
            })

    # Calculate efficiency metrics
    total_groups = len(unique_denials)
    unique_commands = len(sesearch_to_groups)
    efficiency_score = unique_commands / total_groups if total_groups > 0 else 1.0

    return {
        "total_groups": total_groups,
        "unique_sesearch_commands": unique_commands,
        "optimization_potential": optimization_potential,
        "efficiency_score": efficiency_score,
        "is_optimal": len(optimization_potential) == 0
    }




def generate_smart_signature(parsed_log: dict, legacy_mode: bool = False) -> tuple:
    """
    Generate intelligent signature for SELinux remediation-aware grouping.

    Args:
        parsed_log (dict): Parsed AVC log data
        legacy_mode (bool): Use legacy signature logic for regression testing

    Returns:
        tuple: Smart signature tuple for grouping
    """
    if legacy_mode:
        # Use original logic for regression testing
        scontext_val = parsed_log.get("scontext")
        tcontext_val = parsed_log.get("tcontext")
        return (
            str(scontext_val) if scontext_val else None,
            str(tcontext_val) if tcontext_val else None,
            parsed_log.get("tclass"),
            parsed_log.get("permission"),
        )

    # Smart signature generation
    scontext = parsed_log.get("scontext")
    tcontext = parsed_log.get("tcontext")
    tclass = parsed_log.get("tclass", "")
    permission = parsed_log.get("permission", "")
    path = parsed_log.get("path", "")
    comm = parsed_log.get("comm", "")

    # Generate signature components
    process_category = get_process_category(comm, scontext)
    permission_category = get_permission_category(permission, tclass)
    object_group = get_object_group(tclass)
    path_pattern = get_path_pattern(path, tclass)

    # Build signature based on object type
    if object_group == "filesystem":
        # Filesystem objects: group by (process_category, target_type, object_group, path_pattern, permission_category)
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            path_pattern,
            permission_category,
        )
    elif object_group == "network":
        # Network objects: group by (process_category, port/dest, protocol)
        dest_port = parsed_log.get("dest_port", "")
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            dest_port,
            permission_category,
        )
    else:
        # Other objects: use simpler grouping
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            permission_category,
        )

    return signature


def filter_denials(
    denials: list,
    process_filter: str = None,
    path_filter: str = None,
    since_filter: str = None,
    until_filter: str = None,
    source_filter: str = None,
    target_filter: str = None,
) -> list:
    """
    Filter denials based on multiple criteria.

    Args:
        denials (list): List of denial dictionaries to filter
        process_filter (str): Process name to filter by (case-insensitive partial match)
        path_filter (str): Path pattern to filter by (supports basic wildcards)
        since_filter (str): Only include denials since this time (e.g., 'yesterday', '2025-01-15')
        until_filter (str): Only include denials until this time (e.g., 'today', '2025-01-15 14:30')
        source_filter (str): Filter by source context pattern (e.g., 'httpd_t', '*unconfined*')
        target_filter (str): Filter by target context pattern (e.g., 'default_t', '*var_lib*')

    Returns:
        list: Filtered list of denials

    Raises:
        ValueError: If time filters cannot be parsed
    """
    # Parse time filters once
    since_dt = None
    until_dt = None

    if since_filter:
        try:
            since_dt = parse_time_range(since_filter)
        except ValueError as e:
            raise ValueError(f"Invalid --since value: {e}")

    if until_filter:
        try:
            until_dt = parse_time_range(until_filter)
        except ValueError as e:
            raise ValueError(f"Invalid --until value: {e}")

    # If no filters specified, return all denials
    if not any(
        [
            process_filter,
            path_filter,
            since_filter,
            until_filter,
            source_filter,
            target_filter,
        ]
    ):
        return denials

    filtered_denials = []

    for denial_info in denials:
        parsed_log = denial_info.get("log", {})
        include_denial = True

        # Process filtering
        if process_filter:
            comm = parsed_log.get("comm", "").lower()
            if process_filter.lower() not in comm:
                include_denial = False

        # Path filtering
        if path_filter and include_denial:
            path_found = False

            # Check main path
            path = parsed_log.get("path", "")
            if path and path_matches(path, path_filter):
                path_found = True

            # Check correlation events for paths
            if not path_found and "correlations" in denial_info:
                for correlation in denial_info["correlations"]:
                    corr_path = correlation.get("path", "")
                    if corr_path and path_matches(corr_path, path_filter):
                        path_found = True
                        break

            if not path_found:
                include_denial = False

        # Time range filtering
        if (since_dt or until_dt) and include_denial:
            denial_time = denial_info.get("last_seen_obj") or denial_info.get(
                "first_seen_obj"
            )
            if denial_time:
                if since_dt and denial_time < since_dt:
                    include_denial = False
                elif until_dt and denial_time > until_dt:
                    include_denial = False

        # Source context filtering
        if source_filter and include_denial:
            scontext = str(parsed_log.get("scontext", ""))
            if not context_matches(scontext, source_filter):
                include_denial = False

        # Target context filtering
        if target_filter and include_denial:
            tcontext = str(parsed_log.get("tcontext", ""))
            if not context_matches(tcontext, target_filter):
                include_denial = False

        if include_denial:
            filtered_denials.append(denial_info)

    return filtered_denials








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
    parsed_log = denial_info["log"]
    count = denial_info["count"]
    last_seen_dt = denial_info["last_seen_obj"]
    last_seen_ago = human_time_ago(last_seen_dt)

    # Check if this denial contains dontaudit permissions and add indicator
    has_dontaudit, dontaudit_perms = has_dontaudit_indicators(denial_info)
    dontaudit_indicator = (
        " [bright_yellow]⚠️ Enhanced Audit[/bright_yellow]" if has_dontaudit else ""
    )

    # Check if this denial contains permissive mode events and add indicator
    has_permissive = has_permissive_denials(denial_info)
    permissive_indicator = (
        " [bright_blue]🛡️ Permissive[/bright_blue]" if has_permissive else ""
    )

    header = f"[bold green]Unique Denial Group #{denial_num}[/bold green] ({count} occurrences, last seen {last_seen_ago}){dontaudit_indicator}{permissive_indicator}"
    console.print(Rule(header))

    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return

    # Define the fields and their labels for cleaner printing
    process_fields = [
        ("Timestamp", "datetime_str"),
        ("Process Title", "proctitle"),
        ("Executable", "exe"),
        ("Process Name", "comm"),
        ("Process ID (PID)", "pid"),
        ("Working Dir (CWD)", "cwd"),
        ("Source Context", "scontext"),
    ]
    action_fields = [("Syscall", "syscall")]

    # Handle permissions - either single permission or comma-separated list
    if (
        "permissions" in denial_info
        and denial_info["permissions"]
        and len(denial_info["permissions"]) > 0
    ):
        permissions_str = get_enhanced_permissions_display(denial_info, parsed_log)
        action_fields.append(("Permission", permissions_str))
    elif parsed_log.get("permission"):
        permission_display = get_enhanced_permissions_display(denial_info, parsed_log)
        action_fields.append(("Permission", permission_display))

    # Handle permissive mode - check both collected and single values
    if (
        "permissives" in denial_info
        and denial_info["permissives"]
        and len(denial_info["permissives"]) > 0
    ):
        modes = []
        for perm_val in sorted(denial_info["permissives"]):
            modes.append("Permissive" if perm_val == "1" else "Enforcing")
        action_fields.append(("SELinux Mode", ", ".join(modes)))
    elif parsed_log.get("permissive"):
        mode = "Permissive" if parsed_log["permissive"] == "1" else "Enforcing"
        action_fields.append(("SELinux Mode", mode))

    # Add contextual analysis if available
    if parsed_log.get("contextual_analysis"):
        action_fields.append(("Analysis", parsed_log["contextual_analysis"]))

    target_fields = [
        ("Target Path", "path"),
        ("Socket Address", "saddr"),
        ("Target Class", "tclass"),
        ("Target Context", "tcontext"),
    ]

    # --- Process Information ---
    for label, key in process_fields:
        # Check if we have multiple values for this field
        multi_key = f"{key}s"
        if (
            multi_key in denial_info
            and denial_info[multi_key]
            and len(denial_info[multi_key]) > 0
        ):
            values = ", ".join(sorted(denial_info[multi_key]))
            console.print(f"  [bold]{label}:[/bold]".ljust(22), end="")
            # Apply professional color scheme based on field type
            if key == "datetime_str":
                # For timestamp, show the last seen time instead of all times
                last_seen_str = (
                    denial_info["last_seen_obj"].strftime("%Y-%m-%d %H:%M:%S")
                    if denial_info["last_seen_obj"]
                    else values
                )
                console.print(f"[dim white]{last_seen_str}[/dim white]")
            elif key in ["proctitle", "exe"]:
                console.print(f"[green]{values}[/green]")
            elif key == "comm":
                # Enhance comm display with source type description if available
                if parsed_log.get("source_type_description"):
                    source_desc = parsed_log["source_type_description"]
                    enhanced_values = f"{values} ({source_desc})"
                    console.print(f"[green]{enhanced_values}[/green]")
                else:
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
                last_seen_str = (
                    denial_info["last_seen_obj"].strftime("%Y-%m-%d %H:%M:%S")
                    if denial_info["last_seen_obj"]
                    else parsed_log[key]
                )
                console.print(f"[dim white]{last_seen_str}[/dim white]")
            elif key in ["proctitle", "exe"]:
                console.print(f"[green]{parsed_log[key]}[/green]")
            elif key == "comm":
                # Enhance comm display with source type description if available
                if parsed_log.get("source_type_description"):
                    enhanced_comm = (
                        f"{parsed_log[key]} ({parsed_log['source_type_description']})"
                    )
                    console.print(f"[green]{enhanced_comm}[/green]")
                else:
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
    console.print("  [bold]Action:[/bold]".ljust(22) + "Denied")

    # Show denial type (AVC vs USER_AVC)
    if parsed_log.get("denial_type"):
        if parsed_log["denial_type"] == "AVC":
            denial_type_display = "Kernel AVC"
        elif parsed_log["denial_type"] == "USER_AVC":
            denial_type_display = "Userspace AVC"
        elif parsed_log["denial_type"] == "AVC_PATH":
            denial_type_display = "AVC Path Info"
        else:
            denial_type_display = parsed_log["denial_type"]
        console.print("  [bold]Denial Type:[/bold]".ljust(22), end="")
        console.print(f"[bright_green bold]{denial_type_display}[/bright_green bold]")

    for label, key in action_fields:
        if (
            key in parsed_log
            or (label == "Permission" and "permissions" in denial_info)
            or (label == "SELinux Mode")
        ):
            if label == "Permission" and "permissions" in denial_info:
                value = key  # key contains the enhanced permissions_str
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
            elif label == "Analysis":
                console.print(f"[yellow]{value}[/yellow]")
            else:
                console.print(str(value))

    console.print("-" * 35)
    # --- Target Information ---
    for label, key in target_fields:
        # Check if we have multiple values for this field
        multi_key = f"{key}s"
        if (
            multi_key in denial_info
            and denial_info[multi_key]
            and len(denial_info[multi_key]) > 0
        ):
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
                # Handle both AvcContext objects and raw strings
                if isinstance(values, str) and "," in values:
                    # Multiple values - display all
                    console.print(f"[bright_cyan bold]{values}[/bright_cyan bold]")
                else:
                    # Single value - could be AvcContext or string
                    display_value = str(values) if values else ""
                    # Enhance with target type description if available
                    if parsed_log.get("target_type_description"):
                        target_desc = parsed_log["target_type_description"]
                        enhanced_value = f"{display_value} ({target_desc})"
                        console.print(
                            f"[bright_cyan bold]{enhanced_value}[/bright_cyan bold]"
                        )
                    else:
                        console.print(
                            f"[bright_cyan bold]{display_value}[/bright_cyan bold]"
                        )
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
                # Handle both AvcContext objects and raw strings
                display_value = str(parsed_log[key]) if parsed_log[key] else ""
                # Enhance with target type description if available
                if parsed_log.get("target_type_description"):
                    enhanced_value = (
                        f"{display_value} ({parsed_log['target_type_description']})"
                    )
                    console.print(
                        f"[bright_cyan bold]{enhanced_value}[/bright_cyan bold]"
                    )
                else:
                    console.print(
                        f"[bright_cyan bold]{display_value}[/bright_cyan bold]"
                    )
            elif key == "saddr":
                # Socket address information
                console.print(f"[dim white]{parsed_log[key]}[/dim white]")
            else:
                console.print(str(parsed_log[key]))

    # Handle dest_port separately with dynamic labeling
    if parsed_log.get("dest_port") and parsed_log["dest_port"] not in [
        "(null)",
        "null",
        "",
    ]:
        # Determine label based on target class
        if parsed_log.get("tclass") == "dbus":
            dest_label = "D-Bus Destination"
        else:
            dest_label = "Target Port"

        # Check if we have multiple dest_port values
        if (
            "dest_ports" in denial_info
            and denial_info["dest_ports"]
            and len(denial_info["dest_ports"]) > 0
        ):
            values = ", ".join(sorted(denial_info["dest_ports"]))
            console.print(f"  [bold]{dest_label}:[/bold]".ljust(22), end="")
            console.print(f"[green]{values}[/green]")
        else:
            console.print(f"  [bold]{dest_label}:[/bold]".ljust(22), end="")
            # Enhance port display with description if available
            port_value = parsed_log["dest_port"]
            if parsed_log.get("port_description"):
                enhanced_port = f"{port_value} ({parsed_log['port_description']})"
                console.print(f"[green]{enhanced_port}[/green]")
            else:
                console.print(f"[green]{port_value}[/green]")

    console.print("-" * 35)


def group_events_by_resource(correlations: list) -> dict:
    """
    Group correlation events by exact resource (file path, port, etc.) for smart event grouping.

    Args:
        correlations (list): List of correlation event dictionaries

    Returns:
        dict: Grouped events with structure:
            {
                'grouped': [
                    {
                        'type': 'resource_group',
                        'resource': '/var/www/html/config.php',
                        'resource_type': 'file',
                        'count': 3,
                        'permissions': ['read'],
                        'pids': ['1234', '1235', '1236'],
                        'comms': ['httpd'],
                        'all_events': [...]
                    }
                ],
                'individual': [
                    {
                        'type': 'individual_event',
                        'event': {...}
                    }
                ]
            }
    """

    # Group events by exact resource (file path, port, socket address, etc.)
    resource_groups = {}
    individual_events = []

    for event in correlations:
        # Determine the resource identifier for grouping
        resource_key = None
        resource_type = None

        # Check for file/directory path
        path = event.get("path", "")
        if path:
            resource_key = path
            # Determine if it's a directory or file based on various indicators
            if (
                path.startswith("...")  # Partial directory paths like ".../sterling"
                or path.endswith("/")  # Explicit directory paths ending with /
                or event.get("tclass") == "dir"
            ):  # SELinux object class indicates directory
                resource_type = "directory"
            else:
                resource_type = "file"
        # Check for network port
        elif event.get("dest_port"):
            resource_key = f"port:{event.get('dest_port')}"
            resource_type = "port"
        # Check for socket address
        elif event.get("saddr"):
            resource_key = f"socket:{event.get('saddr')}"
            resource_type = "socket"
        # Check for other object classes without specific resources (like security keys)
        elif event.get("tclass"):
            tclass = event.get("tclass")
            permission = event.get("permission", "")
            # Group by object class + permission for resources without specific identifiers
            resource_key = f"{tclass}:{permission}"
            resource_type = tclass

        # If we found a resource to group by
        if resource_key:
            if resource_key not in resource_groups:
                resource_groups[resource_key] = {
                    "type": "resource_group",
                    "resource": resource_key,
                    "resource_type": resource_type,
                    "events": [],
                    "permissions": set(),
                    "pids": set(),
                    "comms": set(),
                }

            resource_groups[resource_key]["events"].append(event)
            resource_groups[resource_key]["permissions"].add(
                event.get("permission", "")
            )
            resource_groups[resource_key]["pids"].add(event.get("pid", ""))
            resource_groups[resource_key]["comms"].add(event.get("comm", ""))
        else:
            # No groupable resource found - treat as individual
            individual_events.append({"type": "individual_event", "event": event})

    # Convert resource groups to final format
    grouped_events = []
    for resource_key, group_data in resource_groups.items():
        events = group_data["events"]

        # Group if we have multiple PIDs accessing the same exact resource (2+ events)
        if len(events) >= 2:
            grouped_events.append(
                {
                    "type": "resource_group",
                    "resource": resource_key,
                    "resource_type": group_data["resource_type"],
                    "count": len(events),
                    "permissions": sorted(list(group_data["permissions"])),
                    "pids": sorted(list(group_data["pids"])),
                    "comms": sorted(list(group_data["comms"])),
                    "all_events": events,
                }
            )
        else:
            # Single event for this resource - treat as individual
            for event in events:
                individual_events.append({"type": "individual_event", "event": event})

    return {"grouped": grouped_events, "individual": individual_events}


def consolidate_resource_groups(grouped_events: dict) -> dict:
    """
    Consolidate groups that have identical PIDs accessing different resources.

    When the same PIDs access multiple files/resources, merge them into a single
    consolidated group to avoid repetition.

    Args:
        grouped_events (dict): Output from group_events_by_resource()

    Returns:
        dict: Consolidated groups with structure:
            {
                'grouped': [consolidated groups with multiple resources],
                'individual': [unchanged individual events]
            }
    """
    if not grouped_events["grouped"]:
        return grouped_events

    # Group by PID set signature
    pid_signature_groups = {}

    for group in grouped_events["grouped"]:
        # Create signature: frozenset of PIDs + comm + resource_type (to avoid mixing files and dirs)
        pids_tuple = tuple(sorted(group["pids"]))
        comm = group["comms"][0] if group["comms"] else "unknown"
        resource_type = group["resource_type"]

        signature = (pids_tuple, comm, resource_type)

        if signature not in pid_signature_groups:
            pid_signature_groups[signature] = []
        pid_signature_groups[signature].append(group)

    # Build consolidated groups
    consolidated_groups = []

    for signature, groups in pid_signature_groups.items():
        if len(groups) == 1:
            # Only one resource for this PID set - keep as-is
            consolidated_groups.append(groups[0])
        else:
            # Multiple resources for same PIDs - consolidate!
            pids_tuple, comm, resource_type = signature

            # Calculate total events
            total_events = sum(g["count"] for g in groups)

            # Collect all resources and their details
            resources_by_permission = {}
            all_events = []

            for group in groups:
                for perm in group["permissions"]:
                    if perm not in resources_by_permission:
                        resources_by_permission[perm] = []
                    resources_by_permission[perm].append({
                        "resource": group["resource"],
                        "resource_type": group["resource_type"],
                        "count": group["count"]
                    })
                all_events.extend(group["all_events"])

            # Create consolidated group
            consolidated = {
                "type": "consolidated_resource_group",
                "pids": list(pids_tuple),
                "comms": [comm],
                "count": total_events,
                "resource_count": len(groups),
                "resources_by_permission": resources_by_permission,
                "all_events": all_events,
                "permissions": sorted(resources_by_permission.keys())
            }

            consolidated_groups.append(consolidated)

    return {
        "grouped": consolidated_groups,
        "individual": grouped_events["individual"]
    }


def display_consolidated_group(console: Console, group: dict, parsed_log: dict, detailed: bool = False):
    """
    Display a consolidated group where same PIDs access multiple resources.

    Args:
        console: Rich console for output
        group: Consolidated group data
        parsed_log: Main denial log data for context
        detailed: Whether to show detailed view
    """
    from rich.tree import Tree

    pids = group["pids"]
    comms = group["comms"]
    total_events = group["count"]
    resource_count = group["resource_count"]
    resources_by_permission = group["resources_by_permission"]

    # Get process name and description
    process_name = comms[0] if comms else "unknown"
    process_desc = parsed_log.get("source_type_description", "")
    if process_desc:
        process_display = f"[green]{process_name}[/green] [dim]({process_desc})[/dim]"
    else:
        process_display = f"[green]{process_name}[/green]"

    # Analyze PID-resource correlation
    pid_resource_map = {}
    for event in group["all_events"]:
        pid = event.get("pid")
        perm = event.get("permission")
        # Build resource key similar to grouping logic
        path = event.get("path", "")
        if path:
            resource = path
        elif event.get("dest_port"):
            resource = f"port:{event.get('dest_port')}"
        elif event.get("saddr"):
            resource = f"socket:{event.get('saddr')}"
        elif event.get("tclass"):
            tclass = event.get("tclass")
            resource = f"{tclass}:{perm}"
        else:
            resource = "unknown"

        if pid not in pid_resource_map:
            pid_resource_map[pid] = set()
        pid_resource_map[pid].add(resource)

    # Check if all PIDs access all resources (perfect correlation)
    all_resources_set = set(r for resources in pid_resource_map.values() for r in resources)
    perfect_correlation = all(
        pid_resource_map[pid] == all_resources_set for pid in pid_resource_map
    )

    # Display header with correlation info
    pid_count = len(pids)
    if perfect_correlation:
        correlation_note = f" [dim](all PIDs access all resources)[/dim]"
    else:
        correlation_note = ""

    console.print(f"• {pid_count} PIDs ({process_display}), {total_events} events across {resource_count} resources{correlation_note}")

    # Show PID list
    pid_chunks = [pids[i : i + 8] for i in range(0, len(pids), 8)]
    for i, chunk in enumerate(pid_chunks):
        is_last_chunk = i == len(pid_chunks) - 1
        tree_symbol = "└─" if is_last_chunk else "├─"
        console.print(f"  {tree_symbol} {', '.join(chunk)}")

    # Check if any events are permissive
    group_is_permissive = any(
        event.get("permissive") == "1" for event in group["all_events"]
    )
    if group_is_permissive:
        enforcement_status = "[bright_blue]Permissive[/bright_blue] [bright_blue]⚠️  ALLOWED[/bright_blue]"
    else:
        enforcement_status = "[Enforcing] [red]✗ BLOCKED[/red]"

    # Display resources grouped by permission
    console.print("")
    console.print("  Resources affected:")
    for perm in sorted(resources_by_permission.keys()):
        resources = resources_by_permission[perm]
        perm_event_count = sum(r["count"] for r in resources)

        # Get permission description with context awareness
        # Check what resource types we have for this permission
        resource_types = set(r["resource_type"] for r in resources)
        # Use the most common resource type for description context
        primary_resource_type = list(resource_types)[0] if len(resource_types) == 1 else None

        from selinux.context import PermissionSemanticAnalyzer
        # Get context-aware description if we have a single resource type
        if primary_resource_type and primary_resource_type in ["file", "directory"]:
            perm_desc = PermissionSemanticAnalyzer.get_permission_description_with_context(perm, primary_resource_type)
        else:
            perm_desc = PermissionSemanticAnalyzer.get_permission_description(perm)

        console.print(f"  ├─ Permission: {perm} ({perm_desc}) - {perm_event_count} events")

        # List resources
        for i, res_info in enumerate(resources):
            is_last = i == len(resources) - 1
            res_symbol = "   └─" if is_last else "   ├─"

            # Format resource display
            resource = res_info["resource"]
            res_type = res_info["resource_type"]
            res_count = res_info["count"]

            # Simplify resource display
            if res_type == "file" or res_type == "directory":
                # Show basename for files, or truncate long paths
                if "/" in resource and len(resource) > 50:
                    parts = resource.split("/")
                    if len(parts) > 3:
                        resource_display = f".../{'/'.join(parts[-2:])}"
                    else:
                        resource_display = resource
                else:
                    resource_display = resource
            else:
                resource_display = resource

            console.print(f"  {res_symbol} {resource_display} ({res_count} events) {enforcement_status}")

    # Show Process Context once for the entire consolidated group
    console.print("")
    proctitle = parsed_log.get("proctitle", "")
    exe_path = parsed_log.get("exe", "")

    # Generate contextual analysis - use first permission for context
    first_perm = sorted(resources_by_permission.keys())[0]

    # Get tclass from this consolidated group's actual resources, not from parsed_log
    # which might be from a different tclass in the same denial signature
    first_resources = resources_by_permission[first_perm]
    actual_resource_type = first_resources[0]["resource_type"]
    # Map resource_type back to tclass
    if actual_resource_type == "directory":
        tclass = "dir"
    elif actual_resource_type == "file":
        tclass = "file"
    elif actual_resource_type in ["chr_file", "blk_file", "lnk_file", "sock_file", "fifo_file"]:
        tclass = actual_resource_type
    else:
        # Fall back to parsed_log tclass for non-filesystem resources
        tclass = parsed_log.get("tclass", "")

    scontext = parsed_log.get("scontext")
    tcontext = parsed_log.get("tcontext")

    contextual_analysis = ""
    if tclass:
        from selinux.context import PermissionSemanticAnalyzer
        contextual_analysis = PermissionSemanticAnalyzer.get_contextual_analysis(
            first_perm, tclass, scontext, tcontext, process_name
        )

    if contextual_analysis or proctitle:
        console.print("  └─ Process Context:")
        if contextual_analysis:
            console.print(f"     ├─ Analysis: [yellow]{contextual_analysis}[/yellow]")
        if proctitle and proctitle != process_name:
            console.print(f"     └─ Process Title: [dim]{proctitle}[/dim]")

    # Show detailed per-PID, per-resource breakdown if detailed flag is set
    if detailed:
        console.print("")
        console.print("  [bold]Detailed Breakdown:[/bold]")

        # Group events by PID
        events_by_pid = {}
        for event in group["all_events"]:
            pid = event.get("pid", "unknown")
            if pid not in events_by_pid:
                events_by_pid[pid] = []
            events_by_pid[pid].append(event)

        # Display per-PID breakdown
        for pid_idx, (pid, pid_events) in enumerate(sorted(events_by_pid.items())):
            is_last_pid = pid_idx == len(events_by_pid) - 1
            pid_branch = "  └─" if is_last_pid else "  ├─"

            console.print(f"{pid_branch} PID {pid} ({len(pid_events)} event{'s' if len(pid_events) != 1 else ''}):")

            # Group this PID's events by resource
            events_by_resource = {}
            for event in pid_events:
                # Build resource key
                path = event.get("path", "")
                if path:
                    resource = path
                elif event.get("dest_port"):
                    resource = f"port:{event.get('dest_port')}"
                elif event.get("saddr"):
                    resource = f"socket:{event.get('saddr')}"
                else:
                    resource = "unknown"

                if resource not in events_by_resource:
                    events_by_resource[resource] = []
                events_by_resource[resource].append(event)

            # Display per-resource events
            for res_idx, (resource, res_events) in enumerate(sorted(events_by_resource.items())):
                is_last_resource = res_idx == len(events_by_resource) - 1
                indent = "     " if is_last_pid else "  │  "
                res_branch = "└─" if is_last_resource else "├─"

                # Format resource display
                if "/" in resource and len(resource) > 60:
                    parts = resource.split("/")
                    if len(parts) > 3:
                        resource_display = f".../{'/'.join(parts[-2:])}"
                    else:
                        resource_display = resource
                else:
                    resource_display = resource

                permission = res_events[0].get("permission", "unknown")
                event_count = len(res_events)

                console.print(f"{indent}{res_branch} {resource_display}")
                console.print(f"{indent}   Permission: [bright_cyan]{permission}[/bright_cyan], {event_count} event{'s' if event_count != 1 else ''}")

                # Show timestamps and syscalls for these events
                for evt_idx, event in enumerate(res_events[:3]):  # Show first 3 events
                    timestamp = event.get("timestamp", "N/A")
                    syscall = event.get("syscall", "N/A")
                    exit_code = event.get("exit", "N/A")
                    success = event.get("success", "")

                    # Format success/failure
                    if success == "yes":
                        result = "[green]success[/green]"
                    elif success == "no":
                        result = "[red]failed[/red]"
                    else:
                        result = ""

                    evt_branch = "   " if evt_idx < 2 else "   "
                    console.print(f"{indent}   {evt_branch}• {timestamp} via [dim]{syscall}[/dim] (exit={exit_code}{', ' + result if result else ''})")

                if event_count > 3:
                    console.print(f"{indent}      [dim]... and {event_count - 3} more event{'s' if event_count - 3 != 1 else ''}[/dim]")


def print_rich_summary(
    console: Console,
    denial_info: dict,
    denial_num: int,
    detailed: bool = False,
):
    """
    Print a Rich-formatted summary with correlation events display.

    This function implements the Phase 3A Rich Display Format with:
    - Rich Rule responsive header format
    - Correlation events display showing individual PID-to-resource mappings
    - Professional styling with automatic width handling

    Args:
        console (Console): Rich console object for formatted output
        denial_info (dict): Aggregated denial information with correlation data
        denial_num (int): Sequential denial number for display
    """
    from rich.panel import Panel
    from selinux.context import PermissionSemanticAnalyzer

    parsed_log = denial_info["log"]
    count = denial_info["count"]
    last_seen_dt = denial_info["last_seen_obj"]
    last_seen_ago = human_time_ago(last_seen_dt)

    # Rich Rule header with responsive design using BIONIC reading format
    header_text = (
        f"Unique Denial Group #{denial_num} • {count} occurrences • last seen {last_seen_ago}"
    )
    header_bionic = format_bionic_text(header_text, "green")

    # Check if this denial contains dontaudit permissions and add indicator after BIONIC formatting
    has_dontaudit, dontaudit_perms = has_dontaudit_indicators(denial_info)
    if has_dontaudit:
        dontaudit_indicator = " • [bright_yellow]⚠️ Enhanced Audit[/bright_yellow]"
        header_bionic += dontaudit_indicator

    # Check if this denial contains permissive mode events and add indicator
    has_permissive = has_permissive_denials(denial_info)
    if has_permissive:
        permissive_indicator = " • [bright_blue]🛡️ Permissive[/bright_blue]"
        header_bionic += permissive_indicator

    # Check if this denial contains custom paths and add indicator
    has_custom, custom_patterns = has_custom_paths(denial_info)
    if has_custom:
        # Show primary pattern or "custom paths" if multiple
        if len(custom_patterns) == 1:
            custom_indicator = (
                f" • [bright_magenta]📁 {custom_patterns[0]}[/bright_magenta]"
            )
        else:
            custom_indicator = " • [bright_magenta]📁 custom paths[/bright_magenta]"
        header_bionic += custom_indicator

    # Check if this denial contains container issues and add indicator
    has_container, container_patterns, sample_paths = has_container_paths(denial_info)
    if has_container:
        container_indicator = " • [bright_cyan]🐳 container[/bright_cyan]"
        header_bionic += container_indicator

    console.print(Rule(header_bionic, style="cyan"))

    # Create WHEN/WHAT panel content
    when_what_content = []

    # 1. WHEN - Add timestamp with AVC type on same line
    # Get AVC type first
    avc_type_suffix = ""
    if parsed_log.get("denial_type"):
        denial_type_display = (
            "Kernel AVC"
            if parsed_log["denial_type"] == "AVC"
            else (
                "Userspace AVC"
                if parsed_log["denial_type"] == "USER_AVC"
                else parsed_log["denial_type"]
            )
        )
        avc_type_suffix = f" • [bright_green]{denial_type_display}[/bright_green]"

    if (
        count > 1
        and "first_seen_obj" in denial_info
        and denial_info["first_seen_obj"]
        and last_seen_dt
    ):
        # Show time range for multiple occurrences
        first_seen_str = denial_info["first_seen_obj"].strftime("%Y-%m-%d %H:%M:%S")
        last_seen_str = last_seen_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Check if they're on the same day
        if denial_info["first_seen_obj"].date() == last_seen_dt.date():
            # Same day - show date once with time range
            date_str = denial_info["first_seen_obj"].strftime("%Y-%m-%d")
            first_time = denial_info["first_seen_obj"].strftime("%H:%M:%S")
            last_time = last_seen_dt.strftime("%H:%M:%S")
            timestamp_display = f"{date_str} {first_time}–{last_time}"
        else:
            # Different days - show full range
            timestamp_display = f"{first_seen_str} – {last_seen_str}"

        when_what_content.append(
            f"[bold white]{timestamp_display}[/bold white]{avc_type_suffix}"
        )
    elif parsed_log.get("datetime_str"):
        # Single occurrence
        when_what_content.append(
            f"[bold white]{parsed_log['datetime_str']}[/bold white]{avc_type_suffix}"
        )

    # 2. WHAT - Action summary with syscall context
    permissions_display = get_enhanced_permissions_display(denial_info, parsed_log)

    # Handle multiple tclasses (e.g., file and dir in same denial group)
    if (
        "tclasss" in denial_info
        and denial_info["tclasss"]
        and len(denial_info["tclasss"]) > 1
    ):
        # Multiple tclasses - show all of them
        tclass_list = sorted(list(denial_info["tclasss"]))
        # Map to descriptions if available
        class_descs = [PermissionSemanticAnalyzer.get_class_description(tc) for tc in tclass_list]
        obj_class = " and ".join(class_descs)
    else:
        # Single tclass
        obj_class = parsed_log.get("class_description", parsed_log.get("tclass", ""))

    # Apply BIONIC reading to natural language parts only
    denied_bionic = format_bionic_text("Denied", "white")
    on_bionic = format_bionic_text("on", "white")

    action_line = f"{denied_bionic} [bright_cyan bold]{permissions_display}[/bright_cyan bold] {on_bionic} [green bold]{obj_class}[/green bold]"

    # Add syscall context to the action line
    if parsed_log.get("syscall"):
        via_bionic = format_bionic_text("via", "white")
        action_line += f" {via_bionic} [green]{parsed_log['syscall']}[/green]"

    when_what_content.append(action_line)

    # Display WHEN/WHAT panel
    if when_what_content:
        # Center each line individually for proper alignment
        centered_lines = [Align.center(line) for line in when_what_content]
        panel_content = Panel(
            Group(*centered_lines), border_style="dim", padding=(0, 3)
        )
        # Responsive width: minimum 60% of screen, maximum 120 characters
        panel_width = min(max(int(console.width * 0.6), 60), 120)
        console.print(Align.center(panel_content, width=panel_width))

    # 3. Security Context - Simplified panel showing only context transition
    scontext = str(parsed_log.get("scontext", ""))
    tcontext = str(parsed_log.get("tcontext", ""))
    if scontext and tcontext:
        context_text = f"[bright_cyan]{scontext}[/bright_cyan] → [bright_cyan]{tcontext}[/bright_cyan]"
        centered_context = Align.center(context_text)
        context_panel = Panel(centered_context, border_style="dim", padding=(0, 3))
        # Responsive width: minimum 60% of screen, maximum 120 characters
        panel_width = min(max(int(console.width * 0.6), 60), 120)
        console.print(Align.center(context_panel, width=panel_width))

    console.print()  # Space before events

    # Correlation events display with smart grouping
    if "correlations" in denial_info and denial_info["correlations"]:
        if detailed:
            console.print("[bold]Detailed Events:[/bold]")
        else:
            console.print("[bold]Events:[/bold]")

        # Apply smart event grouping by exact resource
        grouped_events = group_events_by_resource(
            denial_info["correlations"]
        )

        # Consolidate groups with same PIDs accessing different resources
        grouped_events = consolidate_resource_groups(grouped_events)

        # Display grouped events first (multiple PIDs accessing same exact resource)
        for group in grouped_events["grouped"]:
            # Check if this is a consolidated group (multiple resources, same PIDs)
            if group.get("type") == "consolidated_resource_group":
                # Display consolidated group
                display_consolidated_group(console, group, parsed_log, detailed)
                continue

            # Regular group (single resource)
            resource = group["resource"]
            resource_type = group["resource_type"]
            count = group["count"]
            permissions = group["permissions"]
            pids = group["pids"]
            comms = group["comms"]

            # Format permissions
            perm_display = (
                permissions[0] if len(permissions) == 1 else ", ".join(permissions)
            )

            # Get process name and description
            process_name = comms[0] if comms else "unknown"
            process_desc = parsed_log.get("source_type_description", "")
            if process_desc:
                process_display = (
                    f"[green]{process_name}[/green] [dim]({process_desc})[/dim]"
                )
            else:
                process_display = f"[green]{process_name}[/green]"

            # Format resource display based on type
            if resource_type == "file":
                # Check if this is a container file
                is_container_file = any(
                    pattern in resource
                    for pattern in [
                        "/containers/storage/overlay/",
                        "/.local/share/containers/",
                        "/var/lib/containers/",
                        "/var/lib/docker/",
                    ]
                )

                if is_container_file:
                    # For container files, show meaningful container context
                    if "/containers/storage/overlay/" in resource:
                        # Extract container path: .../overlay/[container-id]/diff/path/to/file
                        parts = resource.split("/containers/storage/overlay/")
                        if len(parts) > 1:
                            overlay_part = parts[1]
                            # Get container ID and internal path
                            overlay_parts = overlay_part.split("/")
                            if (
                                len(overlay_parts) >= 3
                            ):  # container-id/diff/internal/path
                                container_id = overlay_parts[0][
                                    :12
                                ]  # First 12 chars of container ID
                                internal_path = "/".join(
                                    overlay_parts[2:]
                                )  # Skip 'diff' part
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{internal_path}[/bright_white] [dim](container [bright_cyan]{container_id}[/bright_cyan])[/dim]"
                            else:
                                filename = resource.split("/")[-1]
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            filename = resource.split("/")[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                    elif "/.local/share/containers/" in resource:
                        # Handle user container storage
                        parts = resource.split("/.local/share/containers/")
                        if len(parts) > 1:
                            container_part = parts[1]
                            # Extract meaningful part after containers/
                            if "/overlay/" in container_part:
                                overlay_parts = container_part.split("/overlay/")
                                if len(overlay_parts) > 1:
                                    overlay_subpart = overlay_parts[1].split("/")
                                    if (
                                        len(overlay_subpart) >= 3
                                    ):  # container-id/diff/internal/path
                                        container_id = overlay_subpart[0][:12]
                                        internal_path = "/".join(overlay_subpart[2:])
                                        resource_display = f"[cyan]container file[/cyan] [bright_white]{internal_path}[/bright_white] [dim](container [bright_cyan]{container_id}[/bright_cyan])[/dim]"
                                    else:
                                        filename = resource.split("/")[-1]
                                        resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                                else:
                                    filename = resource.split("/")[-1]
                                    resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                            else:
                                filename = resource.split("/")[-1]
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            filename = resource.split("/")[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                    else:
                        # Fallback for other container patterns
                        if "/" in resource and len(resource) > 60:
                            filename = resource.split("/")[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{resource}[/bright_white]"
                else:
                    # Regular file handling
                    if "/" in resource and len(resource) > 60:
                        filename = resource.split("/")[-1]
                        resource_display = f"file {filename}"
                    else:
                        resource_display = f"file {resource}"
            elif resource_type == "directory":
                resource_display = f"directory {resource}"
            elif resource_type == "port":
                port_num = resource.replace("port:", "")
                port_desc = PermissionSemanticAnalyzer.get_port_description(port_num)
                if port_desc != f"port {port_num}":
                    resource_display = f"port {port_num} ({port_desc})"
                else:
                    resource_display = f"port {port_num}"
            elif resource_type == "socket":
                socket_addr = resource.replace("socket:", "")
                resource_display = f"socket {socket_addr}"
            elif resource_type in ["key", "capability", "process", "dbus"]:
                # For object classes without specific resource identifiers
                class_desc = PermissionSemanticAnalyzer.get_class_description(
                    resource_type
                )
                resource_display = f"{class_desc} resource"
            else:
                resource_display = resource

            denied_bionic = format_bionic_text("denied", "white")
            to_bionic = format_bionic_text("to", "white")

            # Check if any events in this group are permissive
            group_is_permissive = any(
                event.get("permissive") == "1" for event in group["all_events"]
            )

            # Determine enforcement status display
            if group_is_permissive:
                enforcement_status = "[bright_blue]Permissive[/bright_blue] [bright_blue]⚠️  ALLOWED[/bright_blue]"
            else:
                enforcement_status = "[Enforcing] [red]✗ BLOCKED[/red]"

            # Use tree structure only for multiple PIDs, simple format for single PID
            pid_count = len(pids)
            pid_label = "PID" if pid_count == 1 else "PIDs"

            # Check if this is a SELINUX_ERR (no PID info)
            denial_type = parsed_log.get("denial_type", "")
            is_selinux_error = denial_type in ["SELINUX_ERR", "USER_SELINUX_ERR"]

            if pid_count == 1:
                # Simple format for single PID - no tree structure needed
                single_pid = list(pids)[0]

                # Different display for SELINUX_ERR (no PID/process info)
                if is_selinux_error:
                    error_type = parsed_log.get("selinux_operation") or parsed_log.get("selinux_error_reason") or "security computation error"
                    invalid_ctx = parsed_log.get("invalid_context", "")
                    event_count_display = f" ({count}x)" if count > 1 else ""
                    console.print(f"• [yellow]Kernel Security Error[/yellow]: {error_type}{event_count_display}")
                    if invalid_ctx:
                        console.print(f"  Invalid context: [red]{invalid_ctx}[/red]")
                    console.print(
                        f"  Transition: {parsed_log.get('scontext', 'unknown')} → {parsed_log.get('tcontext', 'unknown')}"
                    )
                    console.print(f"  Target class: [bright_cyan]{parsed_log.get('tclass', 'unknown')}[/bright_cyan] {enforcement_status}")
                else:
                    # Regular AVC: process-level denial
                    # Count events for this specific PID in this group
                    pid_events_count = len(
                        [
                            event
                            for event in group["all_events"]
                            if event.get("pid") == single_pid
                        ]
                    )
                    pid_count_display = (
                        f" ({pid_events_count}x)" if pid_events_count > 1 else ""
                    )
                    console.print(
                        f"• {pid_label} {single_pid}{pid_count_display} ({process_display})"
                    )
                    console.print(
                        f"  {denied_bionic} '[bright_cyan]{perm_display}[/bright_cyan]' {to_bionic} {resource_display} {enforcement_status}"
                    )
            else:
                # Tree structure for multiple PIDs
                # Calculate total events for this permission group
                total_events = len(group["all_events"])
                events_info = f", {total_events} event{'s' if total_events != 1 else ''}" if total_events != pid_count else ""
                console.print(f"• {pid_count} {pid_label} ({process_display}){events_info}")

                # Tree structure for PID list (8 PIDs per line)
                pid_chunks = [pids[i : i + 8] for i in range(0, len(pids), 8)]
                for i, chunk in enumerate(pid_chunks):
                    is_last_chunk = i == len(pid_chunks) - 1
                    tree_symbol = "└─" if is_last_chunk else "├─"
                    console.print(f"  {tree_symbol} {', '.join(chunk)}")

                # Denial action line
                console.print(
                    f"  {denied_bionic} '[bright_cyan]{perm_display}[/bright_cyan]' {to_bionic} {resource_display} {enforcement_status}"
                )

            # Show Process Context for grouped events (only for regular AVC, not SELINUX_ERR)
            if not is_selinux_error:
                exe_path = parsed_log.get("exe", "")
                proctitle = parsed_log.get("proctitle", "")

                # Generate contextual analysis for the group's permission
                group_permission = permissions[0] if len(permissions) == 1 else None
                tclass = parsed_log.get("tclass", "")
                scontext = parsed_log.get("scontext")
                tcontext = parsed_log.get("tcontext")

                contextual_analysis = ""
                if group_permission and tclass:
                    # Generate fresh analysis specific to this group's permission
                    process_name = parsed_log.get("comm")
                    contextual_analysis = (
                        PermissionSemanticAnalyzer.get_contextual_analysis(
                            group_permission, tclass, scontext, tcontext, process_name
                        )
                    )

                if contextual_analysis or proctitle:
                    console.print("  └─ Process Context:")
                    if contextual_analysis:
                        console.print(
                            f"     ├─ Analysis: [yellow]{contextual_analysis}[/yellow]"
                        )
                    if proctitle and proctitle != parsed_log.get("comm", ""):
                        console.print(f"     └─ Process Title: [dim]{proctitle}[/dim]")

            if detailed:
                # Group events by PID for multi-level tree display
                events_by_pid = {}
                for event in group["all_events"]:
                    pid = event.get("pid", "unknown")
                    if pid not in events_by_pid:
                        events_by_pid[pid] = []
                    events_by_pid[pid].append(event)

                # Show multi-level tree: Resource -> PID -> Events -> Context
                pid_count = 0
                for pid, pid_events in events_by_pid.items():
                    pid_count += 1
                    is_last_pid = pid_count == len(events_by_pid)

                    # PID level header
                    event_count = len(pid_events)
                    pid_branch = "└─" if is_last_pid else "├─"
                    console.print(
                        f"  {pid_branch} PID {pid} ({event_count} event{'s' if event_count != 1 else ''}):"
                    )

                    # Consolidate identical events for this PID
                    consolidated_events = {}
                    for event in pid_events:
                        permission = event.get("permission", "")
                        timestamp = event.get("timestamp", "")
                        syscall = event.get(
                            "syscall", parsed_log.get("syscall", "unknown")
                        )
                        exit_code = event.get("exit", "unknown")

                        # Create key for identical events (ignore microsecond differences)
                        time_key = (
                            timestamp.split(".")[0] if "." in timestamp else timestamp
                        )  # Remove microseconds
                        event_key = (permission, time_key, syscall, exit_code)

                        if event_key not in consolidated_events:
                            consolidated_events[event_key] = {
                                "permission": permission,
                                "timestamp": timestamp,
                                "syscall": syscall,
                                "exit_code": exit_code,
                                "count": 0,
                            }
                        consolidated_events[event_key]["count"] += 1

                    # Display consolidated events
                    consolidated_list = list(consolidated_events.values())
                    display_events = consolidated_list[
                        :3
                    ]  # Limit to 3 unique event types per PID

                    for i, consolidated_event in enumerate(display_events):
                        permission = consolidated_event["permission"]
                        timestamp = consolidated_event["timestamp"]
                        syscall = consolidated_event["syscall"]
                        exit_code = consolidated_event["exit_code"]
                        count = consolidated_event["count"]

                        is_last_event = (
                            i == len(display_events) - 1 and len(consolidated_list) <= 3
                        )
                        event_branch = "└─" if is_last_event and is_last_pid else "├─"
                        pid_prefix = "   " if is_last_pid else "│  "

                        # Format with count if more than 1 identical event
                        if count > 1:
                            count_text = f" ({count}x)"
                        else:
                            count_text = ""

                        console.print(
                            f"  {pid_prefix} {event_branch} [bright_cyan]{permission}[/bright_cyan]{count_text} | Time: {timestamp} | Syscall: [bright_yellow]{syscall}[/bright_yellow] | Exit: {exit_code}"
                        )

                    # Show truncation if needed
                    if len(consolidated_list) > 3:
                        pid_prefix = "   " if is_last_pid else "│  "
                        remaining_count = len(consolidated_list) - 3
                        console.print(
                            f"  {pid_prefix} └─ ... and {remaining_count} more event type{'s' if remaining_count != 1 else ''}"
                        )

        # Display individual events (single PID per resource)
        for item in grouped_events["individual"]:
            correlation = item["event"]
            pid = correlation.get("pid", "unknown")
            # Get comm from correlation event, fallback to main parsed_log, then exe, then proctitle, then scontext
            comm = correlation.get("comm") or parsed_log.get("comm")
            if not comm or comm == "unknown":
                # Fallback 1: exe (executable path) - extract just the executable name
                exe = correlation.get("exe") or parsed_log.get("exe")
                if exe:
                    # Extract just the executable name from the path
                    comm = exe.split("/")[-1] if "/" in exe else exe
                else:
                    # Fallback 2: proctitle (process title)
                    proctitle = correlation.get("proctitle") or parsed_log.get(
                        "proctitle"
                    )
                    if proctitle and proctitle not in ["(null)", "null", ""]:
                        # Use proctitle, taking just the first word (command name) and clean it up
                        first_word = (
                            proctitle.split()[0] if proctitle.split() else "unknown"
                        )
                        # Remove common suffixes like ":" from process titles
                        comm = (
                            first_word.rstrip(":")
                            if first_word != "unknown"
                            else "unknown"
                        )
                    else:
                        # Fallback 3: Extract from scontext (e.g., system_dbusd_t → dbusd)
                        scontext = parsed_log.get("scontext")
                        if scontext:
                            # Get the type from scontext (3rd component)
                            try:
                                scontext_str = str(scontext)
                                stype = scontext_str.split(":")[2] if ":" in scontext_str else None
                                if stype and stype.endswith("_t"):
                                    # Remove _t suffix and clean up
                                    comm = stype[:-2].replace("system_", "").replace("_", "-")
                                else:
                                    comm = "unknown"
                            except (IndexError, AttributeError):
                                comm = "unknown"
                        else:
                            comm = "unknown"
            permission = correlation.get("permission", "")
            path = correlation.get("path", "")
            dest_port = correlation.get("dest_port", "")
            saddr = correlation.get("saddr", "")
            permissive = correlation.get("permissive", "")
            timestamp = correlation.get("timestamp", "")

            # Build event description with BIONIC reading for natural language parts
            if path:
                # Determine object type for better display
                tclass = parsed_log.get("tclass", "file")
                if tclass == "dir":
                    object_bionic = format_bionic_text("directory", "white")
                elif tclass in ["tcp_socket", "udp_socket"]:
                    object_bionic = format_bionic_text("socket", "white")
                elif tclass == "chr_file":
                    object_bionic = format_bionic_text("character device", "white")
                elif tclass == "blk_file":
                    object_bionic = format_bionic_text("block device", "white")
                else:
                    object_bionic = format_bionic_text("file", "white")

                # Smart path truncation for better display
                formatted_path = format_path_for_display(path)
                target_desc = f"{object_bionic} {formatted_path}"
            elif dest_port:
                # Check if this is a D-Bus destination or network port
                tclass = parsed_log.get("tclass", "")
                if tclass == "dbus" or dest_port.startswith(":"):
                    # D-Bus destination
                    dbus_bionic = format_bionic_text("D-Bus service", "white")
                    target_desc = f"{dbus_bionic} {dest_port}"
                else:
                    # Network port
                    port_desc = PermissionSemanticAnalyzer.get_port_description(
                        dest_port
                    )
                    port_bionic = format_bionic_text("port", "white")
                    if port_desc != f"port {dest_port}":
                        target_desc = f"{port_bionic} {dest_port} ({port_desc})"
                    else:
                        target_desc = f"{port_bionic} {dest_port}"
            elif saddr:
                socket_bionic = format_bionic_text("socket", "white")
                target_desc = f"{socket_bionic} {saddr}"
            else:
                target_desc = format_bionic_text("resource", "white")

            # Determine enforcement status
            if permissive == "1":
                enforcement = "[green]✓ ALLOWED[/green]"
                mode = "[yellow]Permissive[/yellow]"
            else:
                enforcement = "[red]✗ BLOCKED[/red]"
                mode = "[cyan]Enforcing[/cyan]"

            # Display correlation event
            denial_type = parsed_log.get("denial_type", "")
            is_selinux_error = denial_type in ["SELINUX_ERR", "USER_SELINUX_ERR"]

            if detailed:
                # Enhanced detailed view with additional information
                exe_path = parsed_log.get("exe", "")
                # Properly escape brackets in Rich markup - use double backslashes
                if exe_path:
                    escaped_exe = exe_path.replace("[", "\\[").replace("]", "\\]")
                    exe_display = f" \\[{escaped_exe}\\]"
                else:
                    exe_display = ""

                # Different display for SELINUX_ERR (no PID/process info)
                if is_selinux_error:
                    # SELINUX_ERR: kernel-level security computation error
                    error_type = parsed_log.get("selinux_operation") or parsed_log.get("selinux_error_reason") or "security computation error"
                    invalid_ctx = parsed_log.get("invalid_context", "")
                    console.print(f"• [yellow]Kernel Security Error[/yellow]: {error_type}")
                    if invalid_ctx:
                        console.print(f"  Invalid context: [red]{invalid_ctx}[/red]")
                    console.print(
                        f"  Transition: {parsed_log.get('scontext', 'unknown')} → {parsed_log.get('tcontext', 'unknown')}"
                    )
                    console.print(f"  Target class: [bright_cyan]{parsed_log.get('tclass', 'unknown')}[/bright_cyan] [{mode}] {enforcement}")
                else:
                    # Regular AVC: process-level denial
                    denied_bionic = format_bionic_text("denied", "white")
                    to_bionic = format_bionic_text("to", "white")
                    # Split into two lines: PID+process line and denial action line
                    console.print(f"• PID {pid} ([green]{comm}[/green]){exe_display}")
                    console.print(
                        f"  {denied_bionic} '[bright_cyan]{permission}[/bright_cyan]' {to_bionic} {target_desc} [{mode}] {enforcement}"
                    )

                # Add detailed sub-information with tree-like structure (only for regular AVC, not SELINUX_ERR)
                if not is_selinux_error:
                    syscall = parsed_log.get("syscall", "")
                    cwd = parsed_log.get("cwd", "")
                    proctitle = parsed_log.get("proctitle", "")

                    if syscall:
                        # Get actual exit code from the correlation event
                        exit_code = correlation.get("exit", "unknown")
                        console.print(
                            f"  ├─ [bright_cyan]{permission}[/bright_cyan] | Time: {timestamp} | Syscall: [bright_yellow]{syscall}[/bright_yellow] | Exit: {exit_code}"
                        )

                    # Add process context information
                    if cwd:
                        console.print(f"  ├─ Working Directory: [dim]{cwd}[/dim]")

                    if proctitle and proctitle != comm:
                        # Determine if this should be the last item for proper tree branching
                        has_analysis = (
                            permission
                            and hasattr(
                                PermissionSemanticAnalyzer, "get_contextual_analysis"
                            )
                            and parsed_log.get("contextual_analysis", "")
                        )
                        branch = "├─" if has_analysis else "└─"
                        console.print(f"  {branch} Process Title: [dim]{proctitle}[/dim]")

                    # Add semantic analysis last as it provides interpretive context
                    if permission and hasattr(
                        PermissionSemanticAnalyzer, "get_contextual_analysis"
                    ):
                        # Generate contextual analysis specific to this event's permission and object class
                        tclass = parsed_log.get("tclass", "")
                        scontext = parsed_log.get("scontext")
                        tcontext = parsed_log.get("tcontext")

                        if tclass:
                            contextual_analysis = (
                                PermissionSemanticAnalyzer.get_contextual_analysis(
                                    permission, tclass, scontext, tcontext, comm
                                )
                            )
                            if contextual_analysis:
                                console.print(
                                    f"  └─ Analysis: [dim]{contextual_analysis}[/dim]"
                                )

                    # Fallback closing branch if no other context is available
                    if not (
                        cwd
                        or (proctitle and proctitle != comm)
                        or (
                            permission
                            and hasattr(
                                PermissionSemanticAnalyzer, "get_contextual_analysis"
                            )
                            and parsed_log.get("contextual_analysis", "")
                        )
                    ):
                        console.print(f"  └─ Process: [dim]{comm}[/dim]")

            else:
                # Standard compact view
                if is_selinux_error:
                    # SELINUX_ERR compact view
                    error_type = parsed_log.get("selinux_operation") or parsed_log.get("selinux_error_reason") or "security error"
                    invalid_ctx = parsed_log.get("invalid_context", "")
                    console.print(f"• [yellow]Kernel Security Error[/yellow]: {error_type}")
                    if invalid_ctx:
                        console.print(f"  Invalid context: [red]{invalid_ctx}[/red] [{mode}] {enforcement}")
                    else:
                        console.print(f"  [{mode}] {enforcement}")
                else:
                    # Regular AVC compact view
                    denied_bionic = format_bionic_text("denied", "white")
                    to_bionic = format_bionic_text("to", "white")
                    # Split into two lines: PID+process line and denial action line
                    console.print(f"• PID {pid} ([green]{comm}[/green])")
                    console.print(
                        f"  {denied_bionic} '[bright_cyan]{permission}[/bright_cyan]' {to_bionic} {target_desc} [{mode}] {enforcement}"
                    )

    # Generate and display sesearch command for policy investigation
    # Use aggregated permissions if available for more complete sesearch command
    sesearch_log = parsed_log.copy()
    if (
        "permissions" in denial_info
        and denial_info["permissions"]
        and len(denial_info["permissions"]) > 1
    ):
        # Use aggregated permissions for more complete sesearch command
        permissions_list = sorted(list(denial_info["permissions"]))
        sesearch_log["permission"] = ",".join(permissions_list)

    sesearch_cmd = generate_sesearch_command(sesearch_log)

    # If we have multiple tclasses, show additional sesearch commands
    if (
        "tclasss" in denial_info
        and denial_info["tclasss"]
        and len(denial_info["tclasss"]) > 1
    ):
        # Generate additional sesearch commands for other tclasses
        other_tclasses = sorted([tc for tc in denial_info["tclasss"] if tc != parsed_log.get("tclass")])
        for tclass in other_tclasses:
            other_log = sesearch_log.copy()
            other_log["tclass"] = tclass
            other_cmd = generate_sesearch_command(other_log)
            if other_cmd:
                sesearch_cmd += f"\n{other_cmd}"
    if sesearch_cmd:
        # Create sesearch command panel
        sesearch_text = f"[bold green]{sesearch_cmd}[/bold green]"
        sesearch_panel = Panel(
            Align.center(sesearch_text),
            title="[bold yellow]Policy Investigation Command[/bold yellow]",
            border_style="yellow",
            padding=(0, 2)
        )
        panel_width = min(max(int(console.width * 0.8), 60), 140)
        console.print(Align.center(sesearch_panel, width=panel_width))

    console.print()  # Space after events


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
        description="A tool to parse an SELinux AVC denial log from a file or user prompt.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Input Options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to audit file (auto-detects raw audit.log vs pre-processed format). Note: processes one file at a time.",
    )
    input_group.add_argument(
        "-rf",
        "--raw-file",
        type=str,
        help="Path to a raw audit.log file containing the AVC log string.",
    )
    input_group.add_argument(
        "-af",
        "--avc-file",
        type=str,
        help="Path to a pre-processed file containing ausearch output.",
    )

    # Display Options
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument(
        "--json", action="store_true", help="Output the parsed data in JSON format."
    )
    display_group.add_argument(
        "--fields",
        action="store_true",
        help="Field-by-field technical breakdown for deep-dive analysis.",
    )
    display_group.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed view with per-PID timestamps, syscalls, and exit codes.",
    )
    display_group.add_argument(
        "--report",
        nargs="?",
        const="brief",
        choices=["brief", "sealert"],
        help="Professional report format: 'brief' (default) for executive summaries, 'sealert' for technical analysis.",
    )
    display_group.add_argument(
        "--pager",
        action="store_true",
        help="Use interactive pager for large outputs (like 'less' command).",
    )

    # Filtering Options
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument(
        "--process",
        type=str,
        help="Filter denials by process name (e.g., --process httpd).",
    )
    filter_group.add_argument(
        "--path",
        type=str,
        help="Filter denials by file path (supports wildcards, e.g., --path '/var/www/*').",
    )
    filter_group.add_argument(
        "--source",
        type=str,
        help="Filter by source context pattern (e.g., 'httpd_t', '*unconfined*', 'system_r').",
    )
    filter_group.add_argument(
        "--target",
        type=str,
        help="Filter by target context pattern (e.g., 'default_t', '*var_lib*').",
    )
    filter_group.add_argument(
        "--since",
        type=str,
        help="Only include denials since this time (e.g., 'yesterday', 'today', '2025-01-15', '2 hours ago').",
    )
    filter_group.add_argument(
        "--until",
        type=str,
        help="Only include denials until this time (e.g., 'today', '2025-01-15 14:30').",
    )

    # Sorting Options
    sort_group = parser.add_argument_group('Sorting Options')
    sort_group.add_argument(
        "--sort",
        type=str,
        choices=["recent", "count", "chrono"],
        default="recent",
        help="Sort order: 'recent' (newest first, default), 'count' (highest count first), 'chrono' (oldest first).",
    )

    # Advanced Options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        "--legacy-signatures",
        action="store_true",
        help="Use legacy signature logic for regression testing (disables smart deduplication).",
    )
    args = parser.parse_args()

    # Set up signal handler for graceful interruption (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    # Create a Rich Console instance
    console = Console()

    # Comprehensive argument validation with enhanced error messages
    input_type = validate_arguments(args, console)

    log_string = ""

    # Initialize display messages
    detection_message = ""
    ausearch_message = ""

    # Generate detection message if not in JSON mode
    if not args.json and args.file:
        file_path = args.file
        detected_format = detect_file_format(file_path)
        if detected_format == "raw":
            detection_message = f"🔍 [bold green]Auto-detected:[/bold green] Raw audit.log format\n   Will process using ausearch: [cyan]{file_path}[/cyan]"
        else:
            detection_message = f"🔍 [bold green]Auto-detected:[/bold green] Pre-processed format\n   Will parse the file [cyan]{file_path}[/cyan] directly"

    if input_type == "raw_file":
        # Determine the correct file path (could be from --file or --raw-file)
        file_path = args.file if args.file else args.raw_file
        if not args.json:
            ausearch_message = (
                f"Raw file input provided. Running ausearch on '{file_path}'..."
            )
        try:
            ausearch_cmd = [
                "ausearch",
                "-m",
                "AVC,USER_AVC,AVC_PATH,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR,MAC_POLICY_LOAD",
                "-i",
                "-if",
                file_path,
            ]
            result = subprocess.run(
                ausearch_cmd, capture_output=True, text=True, check=False
            )

            # Check if ausearch found no matches (normal case)
            if "<no matches>" in result.stderr:
                # No AVC records found - this is normal, not an error
                console.print("ℹ️  [blue]No AVC records found in the audit log.[/blue]")
                console.print(
                    "   This means no SELinux denials occurred during the logged period."
                )
                console.print(
                    "   [dim]This is often a good sign - your system's SELinux policy is working correctly.[/dim]"
                )
                sys.exit(0)
            elif result.returncode == 0:
                # Success - ausearch found records
                log_string = result.stdout
            else:
                # Actual error - ausearch failed for other reasons
                raise subprocess.CalledProcessError(
                    result.returncode, ausearch_cmd, stderr=result.stderr
                )
        except FileNotFoundError:
            print_error("❌ [bold red]Error: ausearch Command Not Found[/bold red]")
            print_error(
                "   The 'ausearch' command is required for processing raw audit files."
            )
            print_error("   [dim]Please install the audit package:[/dim]")
            print_error("   • [cyan]sudo dnf install audit[/cyan] (Fedora/RHEL)")
            print_error("   • [cyan]sudo apt install auditd[/cyan] (Ubuntu/Debian)")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print_error("❌ [bold red]Error: ausearch Command Failed[/bold red]")
            print_error(f"   ausearch returned an error: [dim]{e.stderr.strip()}[/dim]")
            print_error("   [dim]This may indicate:[/dim]")
            print_error("   • File contains no AVC records")
            print_error("   • File format is not compatible with ausearch")
            print_error("   • Audit log file is corrupted")
            sys.exit(1)
    elif input_type == "avc_file":
        # Determine the correct file path (could be from --file or --avc-file)
        file_path = args.file if args.file else args.avc_file
        # File path already shown in auto-detection message
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                log_string = f.read()
        except Exception as e:
            # This should rarely happen due to pre-validation, but handle gracefully
            console.print(
                "❌ [bold red]Error: Unexpected file reading error[/bold red]"
            )
            console.print(f"   {str(e)}")
            sys.exit(1)
    else:  # interactive mode
        if not args.json:
            console.print(
                "📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] when done:"
            )
        #        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        try:
            log_string = sys.stdin.read()
        except EOFError:
            # Handle Ctrl+D (EOF) gracefully - this is normal end of input
            console.print("\n📄 [dim]Input completed (EOF received)[/dim]")
            log_string = ""

    # Split log into blocks using '----' separator
    log_blocks = [block.strip() for block in log_string.split("----") if block.strip()]
    if not log_blocks:
        if not args.json:
            console.print("Error: No valid log blocks found.", style="bold red")
        sys.exit(1)

    unique_denials = {}
    all_unparsed_types = set()

    # Validate and process each block
    validation_warnings = []
    valid_blocks = []
    all_avc_denials = []
    all_policy_loads = []

    for i, block in enumerate(log_blocks):
        # Validate and sanitize the log block
        is_valid, sanitized_block, warnings = validate_log_entry(block)

        if not is_valid:
            if not args.json:
                console.print(
                    f"⚠️  [bold yellow]Warning: Skipping invalid log block {i + 1}[/bold yellow]"
                )
                for warning in warnings:
                    console.print(f"   [dim]• {warning}[/dim]")
            continue

        # Collect validation warnings for summary
        if warnings:
            validation_warnings.extend([(i + 1, w) for w in warnings])

        valid_blocks.append(sanitized_block)
        avc_denials, unparsed = parse_avc_log(sanitized_block)
        all_unparsed_types.update(unparsed)
        all_avc_denials.extend(avc_denials)

        # Parse MAC_POLICY_LOAD events (informational)
        policy_loads = parse_mac_policy_load_events(sanitized_block)
        all_policy_loads.extend(policy_loads)

    # Check if we have any valid blocks after validation
    if not valid_blocks:
        if not args.json:
            console.print(
                "❌ [bold red]Error: No valid log blocks found after validation[/bold red]"
            )
            console.print(
                "   [dim]All input blocks contained malformed or unrecognizable data.[/dim]"
            )
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
                match = re.search(r"Found (\d+) malformed", warning)
                if match:
                    malformed_lines += int(match.group(1))
            elif "No AVC denial/grant records found" in warning:
                empty_blocks += 1
            else:
                other_warnings.append(warning)

        console.print("\n📋 [bold cyan]Input Processing Summary:[/bold cyan]")
        if malformed_lines > 0:
            console.print(f"   • Processed {len(valid_blocks)} audit record sections")
            console.print(
                f"   • Skipped {malformed_lines} non-audit lines (comments, headers, etc.)"
            )
        if empty_blocks > 0:
            console.print(
                f"   • Found {empty_blocks} sections without AVC records (other audit types)"
            )
        if other_warnings:
            for warning in other_warnings:
                console.print(f"   • {warning}")
        console.print(
            "   • [bold green]Successfully processed all AVC data[/bold green]"
        )
        console.print()  # Extra line for readability

    # Process all AVC denials with smart signature generation
    for parsed_log in all_avc_denials:
        # Handle both regular AVC denials (with permission) and SELINUX_ERR records (without permission)
        if "permission" in parsed_log or parsed_log.get("denial_type") in ["SELINUX_ERR", "USER_SELINUX_ERR"]:
            # For regular AVC, use permission; for SELINUX_ERR, use error type as identifier
            if "permission" in parsed_log:
                permission = parsed_log.get("permission")
            else:
                # SELINUX_ERR doesn't have permission, use error type + operation/reason as identifier
                permission = parsed_log.get("selinux_error_reason") or parsed_log.get("selinux_operation") or "selinux_error"

            # Generate smart signature using new logic (or legacy for regression testing)
            signature = generate_smart_signature(
                parsed_log, legacy_mode=args.legacy_signatures
            )

            dt_obj = parsed_log.get("datetime_obj")

            if signature in unique_denials:
                # Add permission to the set if not already present
                if "permissions" not in unique_denials[signature]:
                    unique_denials[signature]["permissions"] = set()
                unique_denials[signature]["permissions"].add(permission)

                # Store individual event correlation for PID-to-resource mapping
                if "correlations" not in unique_denials[signature]:
                    unique_denials[signature]["correlations"] = []

                correlation_event = build_correlation_event(parsed_log, permission)
                unique_denials[signature]["correlations"].append(correlation_event)

                # Collect varying fields (not part of signature)
                varying_fields = [
                    "pid",
                    "comm",
                    "path",
                    "dest_port",
                    "permissive",
                    "proctitle",
                    "tclass",  # Collect tclass to handle file/dir mixing in same signature
                ]
                for field in varying_fields:
                    if field in parsed_log and parsed_log[field] not in [
                        "(null)",
                        "null",
                        "",
                    ]:
                        field_key = f"{field}s"  # e.g., 'pids', 'comms', 'paths'
                        if field_key not in unique_denials[signature]:
                            unique_denials[signature][field_key] = set()
                        unique_denials[signature][field_key].add(parsed_log[field])

                unique_denials[signature]["count"] += 1
                # Update first_seen_obj if this timestamp is older
                if dt_obj and (
                    not unique_denials[signature]["first_seen_obj"]
                    or dt_obj < unique_denials[signature]["first_seen_obj"]
                ):
                    unique_denials[signature]["first_seen_obj"] = dt_obj
                # Update last_seen_obj if this timestamp is newer
                if dt_obj and (
                    not unique_denials[signature]["last_seen_obj"]
                    or dt_obj > unique_denials[signature]["last_seen_obj"]
                ):
                    unique_denials[signature]["last_seen_obj"] = dt_obj
            else:
                # Initialize new signature
                denial_entry = {
                    "log": parsed_log,
                    "count": 1,
                    "first_seen_obj": dt_obj,
                    "last_seen_obj": dt_obj,
                    "permissions": {permission},
                }

                # Initialize correlation storage for first event
                correlation_event = build_correlation_event(parsed_log, permission)
                denial_entry["correlations"] = [correlation_event]

                # Initialize varying fields for first occurrence
                varying_fields = [
                    "pid",
                    "comm",
                    "path",
                    "dest_port",
                    "permissive",
                    "proctitle",
                    "tclass",  # Collect tclass to handle file/dir mixing in same signature
                ]
                for field in varying_fields:
                    if field in parsed_log and parsed_log[field] not in [
                        "(null)",
                        "null",
                        "",
                    ]:
                        field_key = f"{field}s"  # e.g., 'pids', 'comms', 'paths'
                        denial_entry[field_key] = {parsed_log[field]}

                unique_denials[signature] = denial_entry
    if args.json:
        format_as_json(unique_denials, valid_blocks, generate_sesearch_command)

    else:
        # Non JSON default output
        total_events = sum(denial["count"] for denial in unique_denials.values())

        # Apply sorting based on user preference
        sorted_denials = sort_denials(list(unique_denials.values()), args.sort)

        # Validate grouping optimality (analyze sesearch command uniqueness)
        validation_report = validate_grouping_optimality(unique_denials)

        # Apply filtering if specified
        try:
            filtered_denials = filter_denials(
                sorted_denials,
                args.process,
                args.path,
                args.since,
                args.until,
                args.source,
                args.target,
            )
        except ValueError as e:
            console.print(f"[red]Error in filtering: {e}[/red]")
            return

        # Check for detection warnings (on full results before filtering for complete context)
        dontaudit_detected, found_indicators = detect_dontaudit_disabled(sorted_denials)
        permissive_detected, permissive_count, total_events = detect_permissive_mode(
            sorted_denials
        )

        # Check for custom paths detection
        custom_paths_detected, found_custom_patterns = False, []
        for denial_info in sorted_denials:
            has_custom, custom_patterns = has_custom_paths(denial_info)
            if has_custom:
                custom_paths_detected = True
                found_custom_patterns.extend(custom_patterns)
        found_custom_patterns = sorted(list(set(found_custom_patterns)))

        # Check for container issues detection
        container_issues_detected, found_container_patterns, container_sample_paths = (
            False,
            [],
            [],
        )
        for denial_info in sorted_denials:
            has_container, container_patterns, sample_paths = has_container_paths(
                denial_info
            )
            if has_container:
                container_issues_detected = True
                found_container_patterns.extend(container_patterns)
                container_sample_paths.extend(sample_paths)
        found_container_patterns = sorted(list(set(found_container_patterns)))
        container_sample_paths = list(dict.fromkeys(container_sample_paths))[:3]

        # Create a function to display all content (including headers and summaries)
        def display_all_content():
            # Display detection and processing messages first
            if detection_message:
                console.print(detection_message)
            if ausearch_message:
                console.print(ausearch_message)
            if detection_message or ausearch_message:
                console.print()  # Empty line after processing messages

            # Display initial count message
            console.print(
                f"Found {total_events} AVC events. Displaying {len(unique_denials)} unique denials..."
            )

            # Display grouping optimality validation if there are optimization opportunities
            if not validation_report["is_optimal"]:
                efficiency = validation_report["efficiency_score"] * 100
                console.print(
                    f"⚠️  [yellow]Grouping efficiency: {efficiency:.1f}% "
                    f"({validation_report['unique_sesearch_commands']} unique policy queries "
                    f"vs {validation_report['total_groups']} groups)[/yellow]"
                )

            # Display filtering info if applicable
            if (
                args.process
                or args.path
                or args.since
                or args.until
                or args.source
                or args.target
            ):
                filter_msg = []
                if args.process:
                    filter_msg.append(f"process='{args.process}'")
                if args.path:
                    filter_msg.append(f"path='{args.path}'")
                if args.since:
                    filter_msg.append(f"since='{args.since}'")
                if args.until:
                    filter_msg.append(f"until='{args.until}'")
                if args.source:
                    filter_msg.append(f"source='{args.source}'")
                if args.target:
                    filter_msg.append(f"target='{args.target}'")
                filter_str = ", ".join(filter_msg)
                console.print(f"Applied filters: {filter_str}")
                console.print(
                    f"Showing {len(filtered_denials)} of {len(sorted_denials)} unique denials after filtering."
                )

            if filtered_denials:
                if not args.report:
                    console.print(Rule("[dim]Parsed Log Summary[/dim]"))

                # Display detection warnings at the top
                if dontaudit_detected:
                    indicators_str = ", ".join(found_indicators)

                    if args.report:
                        # Simple text format for report mode
                        console.print("═" * 79)
                        console.print("⚠️  SECURITY NOTICE: DONTAUDIT RULES DISABLED")
                        console.print("Enhanced audit mode is active on this system.")
                        console.print(f"Typically suppressed permissions detected: {indicators_str}")
                        console.print("This means you're seeing permissions that are normally hidden.")
                        console.print("═" * 79)
                        console.print()
                    else:
                        # Create a prominent warning panel for Rich format
                        from rich.align import Align
                        from rich.console import Group
                        from rich.panel import Panel

                        warning_lines = [
                            Align.center(
                                "[bold bright_yellow]⚠️  DONTAUDIT RULES DISABLED[/bold bright_yellow]"
                            ),
                            Align.center(""),
                            Align.center(
                                "[yellow]Enhanced audit mode is active on this system.[/yellow]"
                            ),
                            Align.center(
                                f"[dim]Typically suppressed permissions detected: [bright_yellow]{indicators_str}[/bright_yellow][/dim]"
                            ),
                            Align.center(""),
                            Align.center(
                                "[dim]This means you're seeing permissions that are normally hidden.[/dim]"
                            ),
                        ]

                        warning_panel = Panel(
                            Group(*warning_lines),
                            title="[bold red]Security Notice[/bold red]",
                            border_style="bright_yellow",
                            padding=(1, 4),
                        )
                        panel_width = min(max(int(console.width * 0.6), 60), 120)
                        console.print(Align.center(warning_panel, width=panel_width))
                        console.print()

                # Display permissive mode warning if found
                if permissive_detected:
                    if args.report:
                        # Simple text format for report mode
                        console.print("═" * 79)
                        console.print("🛡️  MODE NOTICE: PERMISSIVE MODE DETECTED")
                        console.print(f"{permissive_count} of {total_events} events were in permissive mode.")
                        console.print("These denials were logged but not enforced.")
                        console.print("═" * 79)
                        console.print()
                    else:
                        # Rich panel format for default mode
                        from rich.align import Align
                        from rich.console import Group
                        from rich.panel import Panel

                        warning_lines = [
                            Align.center(
                                "[bold bright_blue]🛡️  PERMISSIVE MODE DETECTED[/bold bright_blue]"
                            ),
                            Align.center(""),
                            Align.center(
                                f"[blue]{permissive_count} of {total_events} events were in permissive mode.[/blue]"
                            ),
                            Align.center(
                                "[dim]These denials were logged but not enforced.[/dim]"
                            ),
                        ]

                        permissive_panel = Panel(
                            Group(*warning_lines),
                            title="[bold blue]Mode Notice[/bold blue]",
                            border_style="bright_blue",
                            padding=(1, 4),
                        )
                        panel_width = min(max(int(console.width * 0.6), 60), 120)
                        console.print(Align.center(permissive_panel, width=panel_width))
                        console.print()

                # Display custom paths warning if found
                if custom_paths_detected:
                    patterns_str = ", ".join(found_custom_patterns[:3])
                    if len(found_custom_patterns) > 3:
                        patterns_str += f" (+{len(found_custom_patterns) - 3} more)"

                    if args.report:
                        # Simple text format for report mode
                        console.print("═" * 79)
                        console.print("📁  PATH NOTICE: CUSTOM PATHS DETECTED")
                        console.print(f"Non-standard paths found: {patterns_str}")
                        console.print("These may require custom fcontext rules.")
                        console.print("═" * 79)
                        console.print()
                    else:
                        # Rich panel format for default mode
                        from rich.align import Align
                        from rich.console import Group
                        from rich.panel import Panel

                        warning_lines = [
                            Align.center(
                                "[bold bright_magenta]📁  CUSTOM PATHS DETECTED[/bold bright_magenta]"
                            ),
                            Align.center(""),
                            Align.center(
                                f"[magenta]Non-standard paths found: {patterns_str}[/magenta]"
                            ),
                            Align.center(
                                "[dim]These may require custom fcontext rules.[/dim]"
                            ),
                        ]

                        custom_panel = Panel(
                            Group(*warning_lines),
                            title="[bold magenta]Path Notice[/bold magenta]",
                            border_style="bright_magenta",
                            padding=(1, 4),
                        )
                        panel_width = min(max(int(console.width * 0.6), 60), 120)
                        console.print(Align.center(custom_panel, width=panel_width))
                        console.print()

                # Display container issues warning if found
                if container_issues_detected:
                    if args.report:
                        # Simple text format for --report mode
                        console.print("═" * 79)
                        console.print("🐳  CONTAINER STORAGE DETECTED")
                        console.print("═" * 79)
                        console.print()
                        console.print("SELinux denials accessing container overlay storage.")
                        console.print()

                        # Show sample path information
                        if container_sample_paths:
                            sample_path = container_sample_paths[0]
                            console.print("Complete path = Base path + Container path:")

                            if "/containers/storage/overlay/" in sample_path:
                                parts = sample_path.split("/containers/storage/overlay/")
                                if len(parts) == 2:
                                    actual_base = parts[0] + "/containers/storage/overlay/"
                                    console.print(f"Base path: {actual_base}")
                                    console.print("Container path: [container-id]/diff/[container-files]")
                            elif "/.local/share/containers/" in sample_path:
                                parts = sample_path.split("/.local/share/containers/")
                                if len(parts) == 2:
                                    actual_base = parts[0] + "/.local/share/containers/storage/overlay/"
                                    console.print(f"Base path: {actual_base}")
                                    console.print("Container path: [container-id]/diff/[container-files]")
                            elif "/var/lib/containers/" in sample_path:
                                console.print("Base path: /var/lib/containers/storage/overlay/")
                                console.print("Container path: [container-id]/diff/[container-files]")
                            else:
                                console.print("Generic pattern: [storage-location]/overlay/[container-id]/diff/[files]")

                        console.print()
                        console.print("Recommendation: container-selinux policy package")
                        console.print("═" * 79)
                        console.print()
                    else:
                        # Rich panel format for other modes
                        from rich.align import Align
                        from rich.console import Group
                        from rich.panel import Panel

                        # Show sample path to help users understand the issue
                        sample_path_lines = []
                        if container_sample_paths:
                            # Show generic patterns based on detected container storage types
                            sample_path = container_sample_paths[0]

                            # Determine container storage type and show generic patterns
                            if "/containers/storage/overlay/" in sample_path:
                                # Extract the actual base path up to /containers/storage/overlay/
                                parts = sample_path.split("/containers/storage/overlay/")
                                if len(parts) == 2:
                                    actual_base = parts[0] + "/containers/storage/overlay/"
                                    sample_path_lines = [
                                        f"[dim]Base path: [bright_cyan]{actual_base}[/bright_cyan][/dim]",
                                        "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                    ]
                            elif "/.local/share/containers/" in sample_path:
                                # Extract the actual base path up to /.local/share/containers/storage/overlay/
                                parts = sample_path.split("/.local/share/containers/")
                                if len(parts) == 2:
                                    actual_base = (
                                        parts[0]
                                        + "/.local/share/containers/storage/overlay/"
                                    )
                                    sample_path_lines = [
                                        f"[dim]Base path: [bright_cyan]{actual_base}[/bright_cyan][/dim]",
                                        "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                    ]
                            elif "/var/lib/containers/" in sample_path:
                                # System container storage (alternative location)
                                sample_path_lines = [
                                    "[dim]Base path: [bright_cyan]/var/lib/containers/storage/overlay/[/bright_cyan][/dim]",
                                    "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                ]

                            # Fallback for other container patterns
                            if not sample_path_lines:
                                sample_path_lines = [
                                    "[dim]Generic pattern: [bright_cyan]\\[storage-location]/overlay/\\[container-id]/diff/\\[files][/bright_cyan][/dim]"
                                ]

                        # Create individual centered lines using Group
                        warning_lines = [
                            Align.center(
                                "[bold bright_cyan]🐳  CONTAINER STORAGE DETECTED[/bold bright_cyan]"
                            ),
                            Align.center(""),  # Empty line
                            Align.center(
                                "[cyan]SELinux denials accessing container overlay storage.[/cyan]"
                            ),
                            Align.center(""),  # Empty line
                            Align.center(
                                "[dim]Complete path = Base path + Container path:[/dim]"
                            ),
                        ]

                        # Add the sample path lines if available
                        if sample_path_lines:
                            for path_line in sample_path_lines:
                                warning_lines.append(Align.center(path_line))

                        warning_lines.extend(
                            [
                                Align.center(""),  # Empty line
                                Align.center(
                                    "[dim]Recommendation: container-selinux policy package[/dim]"
                                ),
                            ]
                        )

                        container_panel = Panel(
                            Group(*warning_lines),
                            title="[bold cyan]Container Notice[/bold cyan]",
                            border_style="bright_cyan",
                            padding=(1, 4),
                        )
                        panel_width = min(max(int(console.width * 0.6), 60), 120)
                        console.print(Align.center(container_panel, width=panel_width))
                        console.print()

                # Display denials
                for i, denial_info in enumerate(filtered_denials):
                    if i > 0:
                        if args.fields:
                            console.print(Rule(style="dim"))
                        else:
                            console.print()  # Space between denials

                    # Choose display format based on flags
                    if args.fields:
                        print_summary(console, denial_info, i + 1)
                    elif args.report:
                        if args.report == "sealert":
                            display_report_sealert_format(
                                console,
                                denial_info,
                                i + 1,
                            )
                        else:  # brief format (default)
                            display_report_brief_format(
                                console,
                                denial_info,
                                i + 1,
                            )
                    else:
                        print_rich_summary(
                            console,
                            denial_info,
                            i + 1,
                            detailed=args.detailed,
                        )

            # Display MAC_POLICY_LOAD events summary if any (outside if filtered_denials block)
            if all_policy_loads:
                console.print("\n" + "─" * console.width)
                console.print("[bold cyan]📋 SELinux Policy Load Events[/bold cyan]")
                console.print(f"\nDetected [bright_cyan]{len(all_policy_loads)}[/bright_cyan] policy reload(s):\n")
                for event in all_policy_loads:
                    timestamp_str = event.get('datetime_str', 'unknown')
                    auid = event.get('auid_display', 'unknown')
                    console.print(f"  • {timestamp_str} - User ID: {auid}")
                console.print()

            # Show filtering info in final summary if applicable
            if args.process or args.path:
                console.print(
                    f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_denials)} unique denials. Displayed {len(filtered_denials)} after filtering."
                )
            else:
                console.print(
                    f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_denials)} unique denials."
                )

            # --- Added: Print the list of unparsed types found ---
            if all_unparsed_types:
                console.print(
                    "\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:"
                )
                console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")

        # Use interactive pager for large outputs if requested and running in a terminal
        if args.pager and sys.stdout.isatty() and not args.json:
            # Capture output with colors preserved for pager
            import io

            from rich.console import Console as RichConsole

            # Create a string buffer to capture colored output
            string_buffer = io.StringIO()
            pager_console = RichConsole(
                file=string_buffer, width=console.width, force_terminal=True
            )

            try:
                # Create a modified display function that uses the pager console
                def display_all_content_pager():
                    # Display detection and processing messages first
                    if detection_message:
                        pager_console.print(detection_message)
                    if ausearch_message:
                        pager_console.print(ausearch_message)
                    if detection_message or ausearch_message:
                        pager_console.print()  # Empty line after processing messages

                    # Display initial count message
                    pager_console.print(
                        f"Found {total_events} AVC events. Displaying {len(unique_denials)} unique denials..."
                    )

                    # Display filtering info if applicable
                    if (
                        args.process
                        or args.path
                        or args.since
                        or args.until
                        or args.source
                        or args.target
                    ):
                        filter_msg = []
                        if args.process:
                            filter_msg.append(f"process='{args.process}'")
                        if args.path:
                            filter_msg.append(f"path='{args.path}'")
                        if args.since:
                            filter_msg.append(f"since='{args.since}'")
                        if args.until:
                            filter_msg.append(f"until='{args.until}'")
                        if args.source:
                            filter_msg.append(f"source='{args.source}'")
                        if args.target:
                            filter_msg.append(f"target='{args.target}'")
                        filter_str = ", ".join(filter_msg)
                        pager_console.print(f"Applied filters: {filter_str}")
                        pager_console.print(
                            f"Showing {len(filtered_denials)} of {len(sorted_denials)} unique denials after filtering."
                        )

                    if filtered_denials:
                        pager_console.print(Rule("[dim]Parsed Log Summary[/dim]"))

                        # Display detection warnings at the top
                        if dontaudit_detected:
                            indicators_str = ", ".join(found_indicators)
                            if args.report:
                                # Simple text format for --report mode
                                pager_console.print("═" * 79)
                                pager_console.print("⚠️  SECURITY NOTICE: DONTAUDIT RULES DISABLED")
                                pager_console.print("═" * 79)
                                pager_console.print()
                                pager_console.print("Enhanced audit mode is active on this system.")
                                pager_console.print(f"Typically suppressed permissions detected: {indicators_str}")
                                pager_console.print("This means you're seeing permissions that are normally hidden.")
                                pager_console.print("═" * 79)
                                pager_console.print()
                            else:
                                # Rich panel format for other modes
                                from rich.align import Align
                                from rich.console import Group
                                from rich.panel import Panel

                                warning_lines = [
                                    Align.center(
                                        "[bold bright_yellow]⚠️  DONTAUDIT RULES DISABLED[/bold bright_yellow]"
                                    ),
                                    Align.center(""),
                                    Align.center(
                                        "[yellow]Enhanced audit mode is active on this system.[/yellow]"
                                    ),
                                    Align.center(
                                        f"[dim]Typically suppressed permissions detected: [bright_yellow]{indicators_str}[/bright_yellow][/dim]"
                                    ),
                                    Align.center(""),
                                    Align.center(
                                        "[dim]This means you're seeing permissions that are normally hidden.[/dim]"
                                    ),
                                ]

                                warning_panel = Panel(
                                    Group(*warning_lines),
                                    title="[bold red]Security Notice[/bold red]",
                                    border_style="bright_yellow",
                                    padding=(1, 4),
                                )
                                panel_width = min(
                                    max(int(pager_console.width * 0.6), 60), 120
                                )
                                pager_console.print(
                                    Align.center(warning_panel, width=panel_width)
                                )
                                pager_console.print()

                        # Display permissive mode warning if found
                        if permissive_detected:
                            if args.report:
                                # Simple text format for --report mode
                                pager_console.print("═" * 79)
                                pager_console.print("🛡️  MODE NOTICE: PERMISSIVE MODE DETECTED")
                                pager_console.print("═" * 79)
                                pager_console.print()
                                pager_console.print(f"{permissive_count} of {total_events} events were in permissive mode.")
                                pager_console.print("These denials were logged but not enforced.")
                                pager_console.print("═" * 79)
                                pager_console.print()
                            else:
                                # Rich panel format for other modes
                                from rich.align import Align
                                from rich.console import Group
                                from rich.panel import Panel

                                warning_lines = [
                                    Align.center(
                                        "[bold bright_blue]🛡️  PERMISSIVE MODE DETECTED[/bold bright_blue]"
                                    ),
                                    Align.center(""),
                                    Align.center(
                                        f"[blue]{permissive_count} of {total_events} events were in permissive mode.[/blue]"
                                    ),
                                    Align.center(
                                        "[dim]These denials were logged but not enforced.[/dim]"
                                    ),
                                ]

                                permissive_panel = Panel(
                                    Group(*warning_lines),
                                    title="[bold blue]Mode Notice[/bold blue]",
                                    border_style="bright_blue",
                                    padding=(1, 4),
                                )
                                panel_width = min(
                                    max(int(pager_console.width * 0.6), 60), 120
                                )
                                pager_console.print(
                                    Align.center(permissive_panel, width=panel_width)
                                )
                                pager_console.print()

                        # Display custom paths warning if found
                        if custom_paths_detected:
                            patterns_str = ", ".join(found_custom_patterns[:3])
                            if len(found_custom_patterns) > 3:
                                patterns_str += (
                                    f" (+{len(found_custom_patterns) - 3} more)"
                                )

                            if args.report:
                                # Simple text format for --report mode
                                pager_console.print("═" * 79)
                                pager_console.print("📁  PATH NOTICE: CUSTOM PATHS DETECTED")
                                pager_console.print("═" * 79)
                                pager_console.print()
                                pager_console.print(f"Non-standard paths found: {patterns_str}")
                                pager_console.print("These may require custom fcontext rules.")
                                pager_console.print("═" * 79)
                                pager_console.print()
                            else:
                                # Rich panel format for other modes
                                from rich.align import Align
                                from rich.console import Group
                                from rich.panel import Panel

                                warning_lines = [
                                    Align.center(
                                        "[bold bright_magenta]📁  CUSTOM PATHS DETECTED[/bold bright_magenta]"
                                    ),
                                    Align.center(""),
                                    Align.center(
                                        f"[magenta]Non-standard paths found: {patterns_str}[/magenta]"
                                    ),
                                    Align.center(
                                        "[dim]These may require custom fcontext rules.[/dim]"
                                    ),
                                ]

                                custom_panel = Panel(
                                    Group(*warning_lines),
                                    title="[bold magenta]Path Notice[/bold magenta]",
                                    border_style="bright_magenta",
                                    padding=(1, 4),
                                )
                                panel_width = min(
                                    max(int(pager_console.width * 0.6), 60), 120
                                )
                                pager_console.print(
                                    Align.center(custom_panel, width=panel_width)
                                )
                                pager_console.print()

                        # Display container issues warning if found
                        if container_issues_detected:
                            if args.report:
                                # Simple text format for --report mode
                                pager_console.print("═" * 79)
                                pager_console.print("🐳  CONTAINER STORAGE DETECTED")
                                pager_console.print("═" * 79)
                                pager_console.print()
                                pager_console.print("SELinux denials accessing container overlay storage.")
                                pager_console.print()

                                # Show sample path information
                                if container_sample_paths:
                                    sample_path = container_sample_paths[0]
                                    pager_console.print("Complete path = Base path + Container path:")

                                    if "/containers/storage/overlay/" in sample_path:
                                        parts = sample_path.split("/containers/storage/overlay/")
                                        if len(parts) == 2:
                                            actual_base = parts[0] + "/containers/storage/overlay/"
                                            pager_console.print(f"Base path: {actual_base}")
                                            pager_console.print("Container path: [container-id]/diff/[container-files]")
                                    elif "/.local/share/containers/" in sample_path:
                                        parts = sample_path.split("/.local/share/containers/")
                                        if len(parts) == 2:
                                            actual_base = parts[0] + "/.local/share/containers/storage/overlay/"
                                            pager_console.print(f"Base path: {actual_base}")
                                            pager_console.print("Container path: [container-id]/diff/[container-files]")
                                    elif "/var/lib/containers/" in sample_path:
                                        pager_console.print("Base path: /var/lib/containers/storage/overlay/")
                                        pager_console.print("Container path: [container-id]/diff/[container-files]")
                                    else:
                                        pager_console.print("Generic pattern: [storage-location]/overlay/[container-id]/diff/[files]")

                                pager_console.print()
                                pager_console.print("Recommendation: container-selinux policy package")
                                pager_console.print("═" * 79)
                                pager_console.print()
                            else:
                                # Rich panel format for other modes
                                from rich.align import Align
                                from rich.console import Group
                                from rich.panel import Panel

                                # Show sample path to help users understand the issue
                                sample_path_lines = []
                                if container_sample_paths:
                                    # Show generic patterns based on detected container storage types
                                    sample_path = container_sample_paths[0]

                                    # Determine container storage type and show generic patterns
                                    if "/containers/storage/overlay/" in sample_path:
                                        # Extract the actual base path up to /containers/storage/overlay/
                                        parts = sample_path.split(
                                            "/containers/storage/overlay/"
                                        )
                                        if len(parts) == 2:
                                            actual_base = (
                                                parts[0] + "/containers/storage/overlay/"
                                            )
                                            sample_path_lines = [
                                                f"[dim]Base path: [bright_cyan]{actual_base}[/bright_cyan][/dim]",
                                                "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                            ]
                                    elif "/.local/share/containers/" in sample_path:
                                        # Extract the actual base path up to /.local/share/containers/storage/overlay/
                                        parts = sample_path.split(
                                            "/.local/share/containers/"
                                        )
                                        if len(parts) == 2:
                                            actual_base = (
                                                parts[0]
                                                + "/.local/share/containers/storage/overlay/"
                                            )
                                            sample_path_lines = [
                                                f"[dim]Base path: [bright_cyan]{actual_base}[/bright_cyan][/dim]",
                                                "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                            ]
                                    elif "/var/lib/containers/" in sample_path:
                                        # System container storage (alternative location)
                                        sample_path_lines = [
                                            "[dim]Base path: [bright_cyan]/var/lib/containers/storage/overlay/[/bright_cyan][/dim]",
                                            "[dim]Container path: [bright_cyan]\\[container-id]/diff/\\[container-files][/bright_cyan][/dim]",
                                        ]

                                    # Fallback for other container patterns
                                    if not sample_path_lines:
                                        sample_path_lines = [
                                            "[dim]Generic pattern: [bright_cyan]\\[storage-location]/overlay/\\[container-id]/diff/\\[files][/bright_cyan][/dim]"
                                        ]

                                # Create individual centered lines using Group
                                warning_lines = [
                                    Align.center(
                                        "[bold bright_cyan]🐳  CONTAINER STORAGE DETECTED[/bold bright_cyan]"
                                    ),
                                    Align.center(""),  # Empty line
                                    Align.center(
                                        "[cyan]SELinux denials accessing container overlay storage.[/cyan]"
                                    ),
                                    Align.center(""),  # Empty line
                                    Align.center(
                                        "[dim]Complete path = Base path + Container path:[/dim]"
                                    ),
                                ]

                                # Add the sample path lines if available
                                if sample_path_lines:
                                    for path_line in sample_path_lines:
                                        warning_lines.append(Align.center(path_line))

                                warning_lines.extend(
                                    [
                                        Align.center(""),  # Empty line
                                        Align.center(
                                            "[dim]Recommendation: container-selinux policy package[/dim]"
                                        ),
                                    ]
                                )

                                container_panel = Panel(
                                    Group(*warning_lines),
                                    title="[bold cyan]Container Notice[/bold cyan]",
                                    border_style="bright_cyan",
                                    padding=(1, 4),
                                )
                                panel_width = min(
                                    max(int(pager_console.width * 0.6), 60), 120
                                )
                                pager_console.print(
                                    Align.center(container_panel, width=panel_width)
                                )
                                pager_console.print()

                        # Display denials using pager console
                        for i, denial_info in enumerate(filtered_denials):
                            if i > 0:
                                if args.fields:
                                    pager_console.print(Rule(style="dim"))
                                else:
                                    pager_console.print()  # Space between denials

                            # Choose display format based on flags
                            if args.fields:
                                print_summary(pager_console, denial_info, i + 1)
                            elif args.report:
                                if args.report == "sealert":
                                    display_report_sealert_format(
                                        pager_console,
                                        denial_info,
                                        i + 1,
                                    )
                                else:  # brief format (default)
                                    display_report_brief_format(
                                        pager_console,
                                        denial_info,
                                        i + 1,
                                    )
                            else:
                                print_rich_summary(
                                    pager_console,
                                    denial_info,
                                    i + 1,
                                    detailed=args.detailed,
                                )

                        # Final summary
                        if args.process or args.path:
                            pager_console.print(
                                f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_denials)} unique denials. Displayed {len(filtered_denials)} after filtering."
                            )
                        else:
                            pager_console.print(
                                f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_denials)} unique denials."
                            )

                        # Print unparsed types if any
                        if all_unparsed_types:
                            pager_console.print(
                                "\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:"
                            )
                            pager_console.print(
                                f"  {', '.join(sorted(list(all_unparsed_types)))}"
                            )

                # Generate all output using the pager console
                display_all_content_pager()

                # Get the captured content with colors
                colored_output = string_buffer.getvalue()

                # Set up environment for color support
                env = os.environ.copy()
                env["LESS"] = "-R"  # Enable raw control characters (colors)

                pager_found = False

                # Try less first (most common and supports colors well)
                try:
                    pager_process = subprocess.Popen(
                        ["less", "-R"], stdin=subprocess.PIPE, env=env, text=True
                    )
                    pager_process.communicate(input=colored_output)
                    pager_found = True
                except FileNotFoundError:
                    # Try fallback to more
                    try:
                        pager_process = subprocess.Popen(
                            ["more"], stdin=subprocess.PIPE, text=True
                        )
                        pager_process.communicate(input=colored_output)
                        pager_found = True
                    except FileNotFoundError:
                        pass  # Will handle below

                if not pager_found:
                    # Fallback: just print normally if no pager available
                    console.print(
                        "[yellow]No pager available, showing output directly:[/yellow]"
                    )
                    display_all_content()

            except Exception as e:
                # If pager fails, fall back to normal output
                console.print(
                    f"[yellow]Pager failed ({e}), falling back to normal output:[/yellow]"
                )
                display_all_content()
        else:
            display_all_content()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Handle broken pipe gracefully when output is piped to head, less, etc.
        # Restore default SIGPIPE behavior and exit cleanly
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        sys.exit(0)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        sys.exit(1)
