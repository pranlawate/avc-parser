#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
SELinux AVC Denial Analyzer

A forensic-focused tool for analyzing SELinux audit logs with intelligent
deduplication and clear correlation tracking. This tool specializes in
post-incident SELinux audit log analysis for complex denial patterns.

Author: Pranav Lawate
License: MIT
Version: 1.3.0
"""

import argparse
import os
import re
import sys
import subprocess
import json
import signal
from datetime import datetime, timedelta
from rich.console import Console, Group
from rich.rule import Rule
from rich.panel import Panel
from rich.align import Align

# Configuration constants
MAX_FILE_SIZE_MB = 100
FILE_ANALYSIS_LINES = 10


def print_error(message: str, console: Console = None):
    """
    Print error message to stderr using Rich formatting.

    Args:
        message (str): Error message to print
        console (Console): Optional console instance for additional non-error output
    """
    error_console = Console(stderr=True)
    error_console.print(message)


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
# Modified to handle optional whitespace before colon: ") :" or "):"
AUDIT_RECORD_RE = re.compile(
    r'(node=(\S+)\s+)?(type=(\S+)\s+)?(msg=)?audit\(((\d+)\.(\d+):(\d+))\)\s*:\s*(.*)'
)


class AvcContext:
    """
    Enhanced SELinux context parsing class based on setroubleshoot's proven approach.

    Parses SELinux security contexts (user:role:type:mls) into structured components
    for enhanced analysis and correlation tracking.
    """

    def __init__(self, context_string: str):
        """
        Initialize AvcContext from a SELinux context string.

        Args:
            context_string (str): SELinux context string (e.g., "system_u:system_r:httpd_t:s0")
        """
        self.user = None
        self.role = None
        self.type = None
        self.mls = None

        if isinstance(context_string, str) and context_string:
            fields = context_string.split(':')
            if len(fields) >= 3:
                self.user = fields[0]
                self.role = fields[1]
                self.type = fields[2]
                if len(fields) > 3:
                    # Handle MLS labels that may contain colons (e.g., s0:c0.c1023)
                    self.mls = ':'.join(fields[3:])
                else:
                    # Default MLS level if not present
                    self.mls = 's0'

    def __str__(self) -> str:
        """Return the full context string."""
        if all([self.user, self.role, self.type, self.mls]):
            return f"{self.user}:{self.role}:{self.type}:{self.mls}"
        return ""

    def __repr__(self) -> str:
        """Return a detailed representation."""
        return f"AvcContext(user='{self.user}', role='{self.role}', type='{self.type}', mls='{self.mls}')"

    def __eq__(self, other) -> bool:
        """Compare two AvcContext objects for equality."""
        if not isinstance(other, AvcContext):
            return False
        return (self.user == other.user and
                self.role == other.role and
                self.type == other.type and
                self.mls == other.mls)

    def __ne__(self, other) -> bool:
        """Compare two AvcContext objects for inequality."""
        return not self.__eq__(other)

    def is_valid(self) -> bool:
        """Check if the context has all required fields."""
        return all([self.user, self.role, self.type, self.mls])

    def get_type_description(self) -> str:
        """
        Get a human-readable description of the SELinux type.

        Returns:
            str: Human-readable description or the type itself if no mapping exists
        """
        # Basic type descriptions for common SELinux types
        type_descriptions = {
            'httpd_t': 'Web server process',
            'init_t': 'System initialization process',
            'unconfined_t': 'Unconfined process',
            'sshd_t': 'SSH daemon process',
            'systemd_t': 'Systemd service manager',
            'default_t': 'Default file context',
            'admin_home_t': 'Administrator home directory',
            'user_home_t': 'User home directory',
            'tmp_t': 'Temporary file',
            'var_t': 'Variable data file',
            'etc_t': 'Configuration file',
            'bin_t': 'System binary',
            'lib_t': 'System library',
        }

        return type_descriptions.get(self.type, self.type)


class PermissionSemanticAnalyzer:
    """
    Provides human-readable descriptions and contextual analysis for SELinux permissions.

    Uses static mappings to avoid requiring policy file access while providing
    meaningful insights into denial semantics.
    """

    # Permission descriptions for common SELinux permissions
    PERMISSION_DESCRIPTIONS = {
        # File permissions
        'read': 'Read file content',
        'write': 'Modify file content',
        'append': 'Append to file',
        'execute': 'Run executable file',
        'open': 'Open file handle',
        'create': 'Create new file',
        'unlink': 'Delete file',
        'rename': 'Rename file',
        'setattr': 'Change file attributes',
        'getattr': 'Read file attributes',
        'lock': 'Lock file for exclusive access',
        'ioctl': 'Perform device control operations',
        'map': 'Memory map file',

        # Network permissions
        'name_connect': 'Connect to network service',
        'name_bind': 'Bind to network port',
        'accept': 'Accept network connections',
        'listen': 'Listen for network connections',
        'recv_msg': 'Receive network message',
        'send_msg': 'Send network message',
        'node_bind': 'Bind to network node',

        # Process permissions
        'transition': 'Change security context',
        'signal': 'Send signal to process',
        'signull': 'Check process existence',
        'sigkill': 'Terminate process forcefully',
        'sigstop': 'Suspend process',
        'ptrace': 'Debug or trace process',
        'getsched': 'Get process scheduling info',
        'setsched': 'Set process scheduling',
        'share': 'Share process memory',

        # Directory permissions
        'search': 'Search directory contents',
        'add_name': 'Add entry to directory',
        'remove_name': 'Remove entry from directory',
        'reparent': 'Move directory entry',
        'rmdir': 'Remove directory',

        # D-Bus permissions
        'acquire_svc': 'Acquire D-Bus service name',
        'send_msg': 'Send D-Bus message',

        # System permissions
        'load': 'Load system module',
        'use': 'Use system resource',
        'admin': 'Perform administrative operation',
        'audit_access': 'Access audit logs',
        'audit_control': 'Control audit system',
        'setuid': 'Change user ID',
        'setgid': 'Change group ID',

        # Security permissions
        'enforce': 'Enforce security policy',
        'load_policy': 'Load security policy',
        'compute_av': 'Compute access vector',
        'compute_create': 'Compute creation context',
        'compute_member': 'Compute member context',
        'check_context': 'Validate security context',
    }

    # Object class descriptions
    CLASS_DESCRIPTIONS = {
        'file': 'file',
        'dir': 'directory',
        'lnk_file': 'symbolic link',
        'chr_file': 'character device',
        'blk_file': 'block device',
        'sock_file': 'socket file',
        'fifo_file': 'named pipe',
        'tcp_socket': 'TCP network socket',
        'udp_socket': 'UDP network socket',
        'unix_stream_socket': 'Unix stream socket',
        'unix_dgram_socket': 'Unix datagram socket',
        'process': 'process',
        'dbus': 'D-Bus service',
        'capability': 'system capability',
        'key': 'security key',
        'shm': 'shared memory',
        'sem': 'semaphore',
        'msg': 'message queue',
        'security': 'security subsystem',
        'system': 'system resource',
    }

    @classmethod
    def get_permission_description(cls, permission: str) -> str:
        """Get human-readable description for a permission."""
        return cls.PERMISSION_DESCRIPTIONS.get(permission, permission)

    @classmethod
    def get_class_description(cls, obj_class: str) -> str:
        """Get human-readable description for an object class."""
        return cls.CLASS_DESCRIPTIONS.get(obj_class, obj_class)

    @classmethod
    def get_contextual_analysis(cls, permission: str, obj_class: str,
                              source_context: AvcContext = None,
                              target_context: AvcContext = None) -> str:
        """
        Generate contextual analysis based on permission, class, and contexts.

        Args:
            permission: The denied permission
            obj_class: The target object class
            source_context: Source AvcContext object (optional)
            target_context: Target AvcContext object (optional)

        Returns:
            Human-readable analysis string
        """
        # Get source process description
        source_desc = "Process"
        if source_context and source_context.type:
            source_desc = source_context.get_type_description()

        # Get target description
        target_desc = cls.get_class_description(obj_class)

        # Generate contextual descriptions based on permission + class combinations
        context_patterns = {
            ('read', 'file'): f"{source_desc} attempting to read file content",
            ('write', 'file'): f"{source_desc} attempting to modify file content",
            ('execute', 'file'): f"{source_desc} attempting to run executable",
            ('open', 'file'): f"{source_desc} attempting to open file",
            ('create', 'file'): f"{source_desc} attempting to create new file",
            ('unlink', 'file'): f"{source_desc} attempting to delete file",

            ('search', 'dir'): f"{source_desc} attempting to search directory",
            ('add_name', 'dir'): f"{source_desc} attempting to add entry to directory",
            ('remove_name', 'dir'): f"{source_desc} attempting to remove directory entry",

            ('name_connect', 'tcp_socket'): f"{source_desc} attempting to connect to network service",
            ('name_bind', 'tcp_socket'): f"{source_desc} attempting to bind to network port",
            ('listen', 'tcp_socket'): f"{source_desc} attempting to listen for connections",

            ('send_msg', 'dbus'): f"{source_desc} attempting to send D-Bus message",
            ('acquire_svc', 'dbus'): f"{source_desc} attempting to acquire D-Bus service",

            ('signal', 'process'): f"{source_desc} attempting to send signal to process",
            ('ptrace', 'process'): f"{source_desc} attempting to debug/trace process",
            ('transition', 'process'): f"{source_desc} attempting to change security context",
        }

        # Look for specific pattern match
        pattern_key = (permission, obj_class)
        if pattern_key in context_patterns:
            return context_patterns[pattern_key]

        # Fallback to generic description
        perm_desc = cls.get_permission_description(permission).lower()
        return f"{source_desc} attempting to {perm_desc} on {target_desc}"

    @classmethod
    def get_port_description(cls, port: str) -> str:
        """Get description for common network ports."""
        port_descriptions = {
            '22': 'SSH service',
            '80': 'HTTP web service',
            '443': 'HTTPS web service',
            '3306': 'MySQL database',
            '5432': 'PostgreSQL database',
            '6379': 'Redis cache',
            '8080': 'HTTP alternate service',
            '9999': 'JBoss management',
            '25': 'SMTP mail service',
            '53': 'DNS service',
            '993': 'IMAPS mail service',
            '995': 'POP3S mail service',
        }
        return port_descriptions.get(port, f"port {port}")


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
                if i >= FILE_ANALYSIS_LINES:
                    break
                lines.append(line.strip())

        # Read more content to check for ausearch output markers
        content_sample = '\n'.join(lines)

        # Definitive pre-processed indicators (ausearch output)
        has_time_headers = 'time->' in content_sample
        has_separators = '----' in content_sample
        has_human_timestamps = bool(re.search(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', content_sample))

        # If any ausearch marker is present, it's definitely pre-processed
        if has_time_headers or has_separators or has_human_timestamps:
            return 'processed'
        else:
            # No ausearch markers = raw audit.log format
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
        re.search(r'(type=AVC|type=USER_AVC|type=AVC_PATH|type=1400|type=1107|avc:.*denied|avc:.*granted)', line, re.IGNORECASE)
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
    context_data, context_unparsed = extract_shared_context_from_non_avc_records(log_block)
    shared_context.update(context_data)
    unparsed_types.update(context_unparsed)

    # Process each AVC and USER_AVC line separately
    for line in log_block.strip().split('\n'):
        line = line.strip()
        if re.search(r'type=(AVC|USER_AVC|AVC_PATH|1400|1107)', line):
            # Parse this specific AVC or USER_AVC line with error handling
            try:
                avc_data = process_individual_avc_record(line, shared_context)
                if avc_data and "permission" in avc_data:  # Only add if it's a valid AVC
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
            timestamp_context['datetime_obj'] = dt_object
            timestamp_context['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            timestamp_context['timestamp'] = dt_object.timestamp()

    return timestamp_context


def parse_time_range(time_spec: str) -> datetime:
    """
    Parse time range specifications into datetime objects.

    Args:
        time_spec (str): Time specification (e.g., 'yesterday', 'today', '2025-01-15', 'recent', '2 hours ago')

    Returns:
        datetime: Parsed datetime object

    Raises:
        ValueError: If time specification cannot be parsed

    Examples:
        >>> parse_time_range('yesterday')
        datetime(2025, 1, 14, 0, 0)
        >>> parse_time_range('2025-01-15 14:30')
        datetime(2025, 1, 15, 14, 30)
    """
    now = datetime.now()
    time_spec_lower = time_spec.lower().strip()

    # Handle relative time keywords
    if time_spec_lower == 'now':
        return now
    elif time_spec_lower == 'today':
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_spec_lower == 'yesterday':
        yesterday = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        return yesterday
    elif time_spec_lower == 'recent':
        # Recent means last hour
        return now - timedelta(hours=1)

    # Handle "X ago" patterns
    ago_match = re.match(r'(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago', time_spec_lower)
    if ago_match:
        amount = int(ago_match.group(1))
        unit = ago_match.group(2)

        if unit == 'second':
            return now - timedelta(seconds=amount)
        elif unit == 'minute':
            return now - timedelta(minutes=amount)
        elif unit == 'hour':
            return now - timedelta(hours=amount)
        elif unit == 'day':
            return now - timedelta(days=amount)
        elif unit == 'week':
            return now - timedelta(weeks=amount)
        elif unit == 'month':
            # Approximate month as 30 days
            return now - timedelta(days=amount * 30)
        elif unit == 'year':
            # Approximate year as 365 days
            return now - timedelta(days=amount * 365)

    # Try parsing explicit date/time formats
    time_formats = [
        '%Y-%m-%d %H:%M:%S',  # 2025-01-15 14:30:45
        '%Y-%m-%d %H:%M',     # 2025-01-15 14:30
        '%Y-%m-%d',           # 2025-01-15 (assumes 00:00:00)
        '%m/%d/%Y %H:%M:%S',  # 01/15/2025 14:30:45
        '%m/%d/%Y %H:%M',     # 01/15/2025 14:30
        '%m/%d/%Y',           # 01/15/2025 (assumes 00:00:00)
        '%d/%m/%Y %H:%M:%S',  # 15/01/2025 14:30:45 (European format)
        '%d/%m/%Y %H:%M',     # 15/01/2025 14:30
        '%d/%m/%Y',           # 15/01/2025 (assumes 00:00:00)
    ]

    for fmt in time_formats:
        try:
            return datetime.strptime(time_spec, fmt)
        except ValueError:
            continue

    # If no format matches, raise an error
    raise ValueError(f"Unable to parse time specification: '{time_spec}'. "
                    f"Supported formats include: 'yesterday', 'today', 'recent', "
                    f"'X hours/days/weeks ago', 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', etc.")


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
            "path": r"name=\"([^\"]+)\"",           # Quoted file path
            "path_unquoted": r"name=([^\s]+)",      # Unquoted path (fallback)
            "inode": r"inode=(\d+)",                # File inode number
            "dev": r"dev=([^\s]+)",                 # Device identifier
        },
        "SYSCALL": {
            "syscall": r"syscall=([\w\d]+)",       # System call name/number
            "exe": r"exe=\"([^\"]+)\"",             # Executable path
            "exit": r"exit=([^\s(]+)",              # Exit code (EACCES, 0, etc.) - stop at parentheses
            "success": r"success=(yes|no)",         # Success flag
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
        elif log_type not in ["AVC", "USER_AVC", "AVC_PATH", "1400", "1107"]:
            # Track unparsed types (excluding all supported AVC-related types)
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
        record_type_match = re.search(r'type=(AVC|USER_AVC|AVC_PATH|1400|1107)', line)
        if not record_type_match:
            return {}

        record_type = record_type_match.group(1)

        # Handle USER_AVC and numeric equivalent (1107)
        if record_type in ['USER_AVC', '1107']:
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
            # Handle AVC, AVC_PATH, and numeric equivalent (1400)
            avc_content = line

        # Set the denial type based on the record type
        if record_type in ['USER_AVC', '1107']:
            avc_data['denial_type'] = 'USER_AVC'
        elif record_type == 'AVC_PATH':
            avc_data['denial_type'] = 'AVC_PATH'
        else:
            # AVC, 1400, or any other kernel AVC type
            avc_data['denial_type'] = 'AVC'

        # Parse timestamp from this specific AVC line (overrides shared context)
        timestamp_pattern = re.search(r'msg=audit\(([^)]+)\)', line)
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

            # Store parsed timestamp in multiple useful formats (overrides shared context)
            if dt_object:
                avc_data['datetime_obj'] = dt_object
                avc_data['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                avc_data['timestamp'] = dt_object.timestamp()

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
            "dbus_dest": r"dest=(:\d+\.\d+)",  # D-Bus destination pattern
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
                elif key in ['scontext', 'tcontext']:
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
                else:
                    avc_data[key] = field_match.group(1).strip()

        # Enhanced path resolution logic
        if 'path' not in avc_data or not avc_data['path']:
            # No path in AVC, try to use PATH record data or build from available info
            if shared_context.get('path'):
                avc_data['path'] = shared_context['path']
                avc_data['path_type'] = 'file_path'
            elif avc_data.get('name') and avc_data['name'] not in ['?', '"?"']:
                # We have a meaningful name field, use it as the path (common for directory access)
                # Skip meaningless names like "?" which appear in D-Bus records
                name_value = avc_data['name']
                # Handle quoted vs unquoted names
                if name_value.startswith('"') and name_value.endswith('"'):
                    name_value = name_value[1:-1]

                # For directories, the name is often just the directory name without full path
                # Mark this as a partial path for better display and indicate it's incomplete
                if avc_data.get('tclass') == 'dir':
                    avc_data['path'] = f".../{name_value}"  # Indicate this is a partial path
                    avc_data['path_type'] = 'directory_name'
                else:
                    avc_data['path'] = name_value
                    avc_data['path_type'] = 'name_only'
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
        if avc_data.get('proctitle') in ["(null)", "null", "", None] and avc_data.get('comm'):
            avc_data['proctitle'] = avc_data['comm']

        # Add semantic analysis for enhanced user comprehension
        if avc_data.get('permission') and avc_data.get('tclass'):
            permission = avc_data['permission']
            obj_class = avc_data['tclass']
            source_context = avc_data.get('scontext')
            target_context = avc_data.get('tcontext')

            # Add permission description
            avc_data['permission_description'] = PermissionSemanticAnalyzer.get_permission_description(permission)

            # Add contextual analysis
            avc_data['contextual_analysis'] = PermissionSemanticAnalyzer.get_contextual_analysis(
                permission, obj_class, source_context, target_context
            )

            # Add object class description
            avc_data['class_description'] = PermissionSemanticAnalyzer.get_class_description(obj_class)

            # Add source type description if available
            if source_context and hasattr(source_context, 'get_type_description'):
                avc_data['source_type_description'] = source_context.get_type_description()

            # Add target type description if available
            if target_context and hasattr(target_context, 'get_type_description'):
                avc_data['target_type_description'] = target_context.get_type_description()

            # Add port description for network denials
            if avc_data.get('dest_port'):
                avc_data['port_description'] = PermissionSemanticAnalyzer.get_port_description(avc_data['dest_port'])

        return avc_data

    except Exception:
        # Individual AVC parsing failed - return empty dict
        return {}


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
        'pid': parsed_log.get('pid'),
        'comm': parsed_log.get('comm'),
        'path': parsed_log.get('path'),
        'permission': permission,
        'permissive': parsed_log.get('permissive'),
        'timestamp': parsed_log.get('datetime_str'),
        'dest_port': parsed_log.get('dest_port'),
        'saddr': parsed_log.get('saddr'),
        'tclass': parsed_log.get('tclass'),
        'exit': parsed_log.get('exit'),
        'success': parsed_log.get('success')
    }
    # Only store non-null values to keep correlations clean
    return {k: v for k, v in correlation_event.items() if v not in [None, "(null)", "null", ""]}


def get_enhanced_permissions_display(denial_info: dict, parsed_log: dict) -> str:
    """
    Generate enhanced permission display string with semantic descriptions.

    Args:
        denial_info (dict): Aggregated denial information containing permissions set
        parsed_log (dict): Parsed log data with permission_description if available

    Returns:
        str: Enhanced permissions string with descriptions
    """
    if 'permissions' in denial_info and len(denial_info['permissions']) > 1:
        # Multiple permissions case
        enhanced_perms = []
        for perm in sorted(denial_info['permissions']):
            if parsed_log.get('permission') == perm and parsed_log.get('permission_description'):
                perm_desc = parsed_log['permission_description']
            else:
                perm_desc = PermissionSemanticAnalyzer.get_permission_description(perm)

            if perm_desc != perm:
                enhanced_perms.append(f"{perm} ({perm_desc})")
            else:
                enhanced_perms.append(perm)
        return ", ".join(enhanced_perms)

    elif parsed_log.get('permission_description'):
        # Single permission with description
        permission = parsed_log.get('permission', '')
        return f"{permission} ({parsed_log['permission_description']})"

    else:
        # Fallback to raw permission
        return parsed_log.get('permission', '')


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
        'httpd': 'web_server_apache',
        'nginx': 'web_server_nginx',
        'lighttpd': 'web_server_lighttpd',
        'caddy': 'web_server_caddy',

        # Database servers
        'mysqld': 'database_mysql',
        'postgres': 'database_postgresql',
        'mongod': 'database_mongodb',
        'redis-server': 'database_redis',

        # System services
        'systemd': 'init_systemd',
        'init': 'init_sysv',
        'logrotate': 'system_logrotate',
        'cron': 'system_cron',
        'crond': 'system_cron',
        'ntpdate': 'system_ntp',
        'chronyd': 'system_ntp',
        'aide': 'security_aide',

        # SSH services
        'sshd': 'ssh_daemon',
        'ssh': 'ssh_client',
        'unix_chkpwd': 'ssh_auth',

        # Container/virtualization
        'docker': 'container_docker',
        'podman': 'container_podman',
        'runc': 'container_runtime',

        # Desktop/user services
        'gnome-shell': 'desktop_gnome',
        'plasma': 'desktop_kde',
        'pulseaudio': 'audio_pulse',
        'pipewire': 'audio_pipewire',
    }

    # Check for direct mapping first
    if comm in service_mappings:
        return service_mappings[comm]

    # Check for pattern-based mappings for related processes
    # Apache web server variants
    if comm.startswith('httpd') or comm.endswith('-httpd') or 'httpd' in comm:
        return 'web_server_apache'

    # Nginx variants
    if comm.startswith('nginx') or comm.endswith('-nginx') or 'nginx' in comm:
        return 'web_server_nginx'

    # PostgreSQL variants
    if comm.startswith('postgres') or 'postgres' in comm:
        return 'database_postgresql'

    # MySQL variants
    if comm.startswith('mysql') or 'mysql' in comm:
        return 'database_mysql'

    # SSH variants
    if comm.startswith('sshd') or 'sshd' in comm:
        return 'ssh_daemon'

    # Handle multi-service domains that need process distinction
    if source_context and source_context.type:
        multi_service_domains = {
            'unconfined_t': f"unconfined_{comm}",
            'init_t': f"init_{comm}",
            'user_t': f"user_{comm}",
            'admin_t': f"admin_{comm}",
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
    file_access_perms = {'read', 'write', 'append', 'getattr', 'open'}
    file_create_perms = {'create', 'write', 'add_name', 'setattr'}
    file_execute_perms = {'execute', 'execute_no_trans', 'entrypoint'}
    file_manage_perms = {'unlink', 'remove_name', 'rename', 'rmdir'}

    # Network operations that commonly group together
    net_bind_perms = {'name_bind', 'bind', 'listen'}
    net_connect_perms = {'name_connect', 'connect', 'send_msg', 'recv_msg'}

    # Process/security operations
    process_signal_perms = {'signal', 'signull', 'sigkill', 'sigstop'}
    process_trace_perms = {'ptrace', 'getsched', 'setsched'}
    process_transition_perms = {'transition', 'entrypoint', 'execute'}

    # D-Bus operations
    dbus_communication_perms = {'send_msg', 'acquire_svc', 'own'}

    # Check permission against categories
    if tclass in ['file', 'dir', 'lnk_file', 'chr_file', 'blk_file', 'sock_file', 'fifo_file']:
        if permission in file_access_perms:
            return 'file_access'
        elif permission in file_create_perms:
            return 'file_create'
        elif permission in file_execute_perms:
            return 'file_execute'
        elif permission in file_manage_perms:
            return 'file_manage'
        else:
            return f'file_{permission}'

    elif tclass in ['tcp_socket', 'udp_socket', 'unix_stream_socket', 'unix_dgram_socket']:
        if permission in net_bind_perms:
            return 'net_bind'
        elif permission in net_connect_perms:
            return 'net_connect'
        else:
            return f'net_{permission}'

    elif tclass == 'process':
        if permission in process_signal_perms:
            return 'process_signal'
        elif permission in process_trace_perms:
            return 'process_trace'
        elif permission in process_transition_perms:
            return 'process_transition'
        else:
            return f'process_{permission}'

    elif tclass == 'dbus':
        if permission in dbus_communication_perms:
            return 'dbus_communication'
        else:
            return f'dbus_{permission}'

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
        'file', 'dir', 'lnk_file', 'chr_file', 'blk_file',
        'sock_file', 'fifo_file', 'anon_inode'
    }

    # Network objects
    network_objects = {
        'tcp_socket', 'udp_socket', 'rawip_socket', 'netlink_socket',
        'unix_stream_socket', 'unix_dgram_socket', 'socket'
    }

    # IPC objects
    ipc_objects = {
        'sem', 'msg', 'msgq', 'shm', 'ipc'
    }

    # System objects
    system_objects = {
        'process', 'security', 'system', 'capability', 'capability2'
    }

    if tclass in filesystem_objects:
        return 'filesystem'
    elif tclass in network_objects:
        return 'network'
    elif tclass in ipc_objects:
        return 'ipc'
    elif tclass in system_objects:
        return 'system'
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
    if not path or path in ['?', '"?"', 'unknown']:
        return 'no_path'

    # Handle dev+inode identifiers
    if path.startswith('dev:'):
        return 'dev_inode'

    # Extract meaningful path patterns for fcontext rules
    import re

    # Common system directories that group well
    system_patterns = {
        r'^/var/log(/.*)?$': '/var/log(/.*)?',
        r'^/var/local/log(/.*)?$': '/var/local/log(/.*)?',  # Add specific pattern for /var/local/log
        r'^/var/spool(/.*)?$': '/var/spool(/.*)?',
        r'^/var/run(/.*)?$': '/var/run(/.*)?',
        r'^/var/lib(/.*)?$': '/var/lib(/.*)?',
        r'^/etc(/.*)?$': '/etc(/.*)?',
        r'^/usr/bin(/.*)?$': '/usr/bin(/.*)?',
        r'^/usr/sbin(/.*)?$': '/usr/sbin(/.*)?',
        r'^/usr/lib(/.*)?$': '/usr/lib(/.*)?',
        r'^/home/[^/]+(/.*)?$': '/home/[^/]+(/.*)?',
        r'^/tmp(/.*)?$': '/tmp(/.*)?',
        r'^/var/tmp(/.*)?$': '/var/tmp(/.*)?',
    }

    # Web server specific patterns
    web_patterns = {
        r'^/var/www(/.*)?$': '/var/www(/.*)?',
        r'^/srv/www(/.*)?$': '/srv/www(/.*)?',
        r'^/usr/share/nginx(/.*)?$': '/usr/share/nginx(/.*)?',
        r'^/etc/httpd(/.*)?$': '/etc/httpd(/.*)?',
        r'^/etc/nginx(/.*)?$': '/etc/nginx(/.*)?',
    }

    # Container storage patterns (already handled by format_path_for_display)
    container_patterns = {
        r'.*/containers/storage/overlay/[^/]+/.*': '/containers/storage/overlay/*/...',
    }

    # Check patterns in order of specificity
    all_patterns = {**web_patterns, **container_patterns, **system_patterns}

    for pattern, replacement in all_patterns.items():
        if re.match(pattern, path):
            return replacement

    # For unmatched paths, normalize to directory patterns for grouping
    # Both files and directories should use the same base pattern for location-based grouping
    if tclass in ['file', 'dir']:
        if tclass == 'file':
            # Extract directory pattern for files
            dir_path = '/'.join(path.split('/')[:-1])
            if dir_path:
                return f"{dir_path}/*"
        elif tclass == 'dir':
            # For directories, use the directory itself as the pattern base
            if path.startswith('...'):
                # This is a partial directory name like ".../sterling" or ".../info_server"
                # Extract the actual directory name
                dir_name = path.split('/')[-1]

                # Map common directory names to use the same pattern as their corresponding files
                # This ensures directories and files in the same location get grouped together
                if dir_name in ['sterling', 'info_server', 'log']:
                    # Use the same pattern that files in /var/local/log get from the regex
                    return '/var/local/log(/.*)?'

                # For unknown partial paths, assume they're also in /var/local/log
                return '/var/local/log(/.*)?'
            else:
                # For full directory paths, use the directory as base pattern
                return f"{path}/*"

    # Keep the exact path for other cases
    return path


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
        scontext_val = parsed_log.get('scontext')
        tcontext_val = parsed_log.get('tcontext')
        return (
            str(scontext_val) if scontext_val else None,
            str(tcontext_val) if tcontext_val else None,
            parsed_log.get('tclass'),
            parsed_log.get('permission')
        )

    # Smart signature generation
    scontext = parsed_log.get('scontext')
    tcontext = parsed_log.get('tcontext')
    tclass = parsed_log.get('tclass', '')
    permission = parsed_log.get('permission', '')
    path = parsed_log.get('path', '')
    comm = parsed_log.get('comm', '')

    # Generate signature components
    process_category = get_process_category(comm, scontext)
    permission_category = get_permission_category(permission, tclass)
    object_group = get_object_group(tclass)
    path_pattern = get_path_pattern(path, tclass)

    # Build signature based on object type
    if object_group == 'filesystem':
        # Filesystem objects: group by (process_category, target_type, object_group, path_pattern, permission_category)
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            path_pattern,
            permission_category
        )
    elif object_group == 'network':
        # Network objects: group by (process_category, port/dest, protocol)
        dest_port = parsed_log.get('dest_port', '')
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            dest_port,
            permission_category
        )
    else:
        # Other objects: use simpler grouping
        signature = (
            process_category,
            str(tcontext) if tcontext else None,
            object_group,
            permission_category
        )

    return signature


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


def format_bionic_text(text: str, base_color: str = "green") -> str:
    """
    Apply BIONIC reading format to text for improved readability.

    Args:
        text (str): The text to format
        base_color (str): Base color for the text (default: "green")

    Returns:
        str: Rich markup formatted text with BIONIC reading emphasis

    Note:
        Emphasizes the first half of words (typically 2-3 characters) to improve
        reading speed and comprehension. Uses bold for emphasis, dim for rest.
    """
    if not text:
        return text

    words = text.split()
    formatted_words = []

    for word in words:
        if len(word) <= 2:
            # Short words get normal emphasis
            formatted_words.append(f"[{base_color}]{word}[/{base_color}]")
        elif len(word) <= 4:
            # Medium words: emphasize first 2 characters
            emphasized = word[:2]
            rest = word[2:]
            formatted_words.append(f"[bold {base_color}]{emphasized}[/bold {base_color}][dim {base_color}]{rest}[/dim {base_color}]")
        else:
            # Longer words: emphasize first 3 characters
            emphasized = word[:3]
            rest = word[3:]
            formatted_words.append(f"[bold {base_color}]{emphasized}[/bold {base_color}][dim {base_color}]{rest}[/dim {base_color}]")

    return " ".join(formatted_words)


def format_path_for_display(path: str, max_length: int = 80) -> str:
    """
    Format file paths for better terminal display with smart truncation.

    Args:
        path (str): The file path to format
        max_length (int): Maximum length before truncation (default: 80)

    Returns:
        str: Formatted path with intelligent truncation for container paths
    """
    if not path or len(path) <= max_length:
        return path

    # Special handling for container storage paths
    if 'containers/storage/overlay' in path:
        # Extract meaningful parts: base path + container ID + final path
        parts = path.split('/')

        # Find the overlay directory index
        try:
            overlay_idx = parts.index('overlay')
            if overlay_idx + 1 < len(parts):
                container_id = parts[overlay_idx + 1]
                # Truncate container ID to first 8 characters
                short_id = container_id[:8] + "..." if len(container_id) > 8 else container_id

                # Get the final meaningful path
                if overlay_idx + 3 < len(parts):
                    # Usually: overlay/ID/diff/actual/path
                    final_path = '/'.join(parts[overlay_idx + 3:])
                    base_path = '/'.join(parts[:overlay_idx])
                    return f"{base_path}/overlay/{short_id}/.../{final_path}"
        except ValueError:
            pass

    # Generic path truncation - show beginning and end
    if len(path) > max_length:
        # Show first 30 and last 30 characters with ellipsis
        start_len = min(30, max_length // 2 - 2)
        end_len = min(30, max_length // 2 - 2)
        return f"{path[:start_len]}...{path[-end_len:]}"

    return path


def has_permissive_denials(denial_info: dict) -> bool:
    """
    Check if a specific denial contains permissive mode events.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        bool: True if denial contains permissive mode events
    """
    # Check aggregated permissive values if available
    if 'permissives' in denial_info and denial_info['permissives']:
        return '1' in denial_info['permissives']

    # Also check individual permissive field
    parsed_log = denial_info.get('log', {})
    permissive = parsed_log.get('permissive', '0')
    return permissive == '1'


def has_container_issues(denial_info: dict) -> tuple[bool, list[str], list[str]]:
    """
    Check if a specific denial contains container-related policy issues.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        tuple[bool, list[str], list[str]]: (has_issues, container_patterns, sample_paths)
    """
    container_patterns = [
        '/containers/storage/overlay/',  # Podman/Docker overlay storage
        '/.local/share/containers/',     # User container storage
        '/var/lib/containers/',          # System container storage
        '/var/lib/docker/',              # Docker storage
    ]

    found_patterns = set()
    sample_paths = []

    # Check main path in denial
    parsed_log = denial_info.get('log', {})
    main_path = parsed_log.get('path', '')
    if main_path:
        for pattern in container_patterns:
            if pattern in main_path:
                found_patterns.add(pattern.strip('/'))
                if len(sample_paths) < 3:  # Keep sample paths for display
                    sample_paths.append(main_path)

    # Check correlation events for paths
    if 'correlations' in denial_info:
        for correlation in denial_info['correlations']:
            corr_path = correlation.get('path', '')
            if corr_path:
                for pattern in container_patterns:
                    if pattern in corr_path:
                        found_patterns.add(pattern.strip('/'))
                        if len(sample_paths) < 3:
                            sample_paths.append(corr_path)

    # Check aggregated paths if available
    if 'paths' in denial_info and denial_info['paths']:
        for path in denial_info['paths']:
            for pattern in container_patterns:
                if pattern in path:
                    found_patterns.add(pattern.strip('/'))
                    if len(sample_paths) < 3:
                        sample_paths.append(path)

    found_patterns_list = sorted(list(found_patterns))
    return len(found_patterns_list) > 0, found_patterns_list, sample_paths[:3]


def has_custom_paths(denial_info: dict) -> tuple[bool, list[str]]:
    """
    Check if a specific denial contains custom/non-standard paths that may indicate policy issues.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        tuple[bool, list[str]]: (has_custom_paths, list of detected custom path patterns)
    """
    custom_path_patterns = [
        '/usr/local',      # Non-standard local installations
        '/opt',            # Optional software packages
        '/home/',          # User home directories (when not user_home_t)
        '/srv',            # Service data directories
        '/data',           # Custom data directories
        '/app',            # Application directories
        '/apps',           # Application directories
        '/software',       # Software installation directories
        '/custom',         # Custom directories
        '/local',          # Local directories outside /usr/local
        '/var/local',      # Non-standard local variable data
    ]

    found_patterns = set()

    # Check main path in denial
    parsed_log = denial_info.get('log', {})
    main_path = parsed_log.get('path', '')
    if main_path:
        for pattern in custom_path_patterns:
            if main_path.startswith(pattern):
                found_patterns.add(pattern)

    # Check correlation events for paths
    if 'correlations' in denial_info:
        for correlation in denial_info['correlations']:
            corr_path = correlation.get('path', '')
            if corr_path:
                for pattern in custom_path_patterns:
                    if corr_path.startswith(pattern):
                        found_patterns.add(pattern)

    # Check aggregated paths if available
    if 'paths' in denial_info and denial_info['paths']:
        for path in denial_info['paths']:
            for pattern in custom_path_patterns:
                if path.startswith(pattern):
                    found_patterns.add(pattern)

    found_patterns_list = sorted(list(found_patterns))
    return len(found_patterns_list) > 0, found_patterns_list


def detect_permissive_mode(unique_denials: list) -> tuple[bool, int, int]:
    """
    Detect permissive mode denials in the dataset.

    Args:
        unique_denials (list): List of unique denial dictionaries

    Returns:
        tuple[bool, int, int]: (has_permissive, permissive_count, total_count)
    """
    permissive_count = 0
    total_count = 0

    for denial_info in unique_denials:
        denial_count = denial_info.get('count', 1)
        total_count += denial_count

        if has_permissive_denials(denial_info):
            permissive_count += denial_count

    return permissive_count > 0, permissive_count, total_count


def has_dontaudit_permissions(denial_info: dict) -> tuple[bool, list[str]]:
    """
    Check if a specific denial contains dontaudit indicator permissions.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        tuple[bool, list[str]]: (has_indicators, list of found indicators)
    """
    dontaudit_indicators = ['noatsecure', 'rlimitinh', 'siginh']
    found_indicators = set()

    # Check aggregated permissions set if available
    if 'permissions' in denial_info and denial_info['permissions']:
        for perm in denial_info['permissions']:
            if perm.lower().strip() in dontaudit_indicators:
                found_indicators.add(perm.lower().strip())

    # Also check individual permission field
    parsed_log = denial_info.get('log', {})
    permission = parsed_log.get('permission', '').lower().strip()
    if permission in dontaudit_indicators:
        found_indicators.add(permission)

    found_indicators_list = sorted(list(found_indicators))
    return len(found_indicators_list) > 0, found_indicators_list


def detect_dontaudit_disabled(unique_denials: list) -> tuple[bool, list[str]]:
    """
    Detect if dontaudit rules are disabled based on presence of commonly suppressed permissions.

    Args:
        unique_denials (list): List of unique denial dictionaries

    Returns:
        tuple[bool, list[str]]: (detected, list of found indicators)

    Note:
        These permissions are almost always suppressed by dontaudit rules in normal systems.
        If they appear in audit logs, it strongly indicates enhanced audit mode is active.
    """
    dontaudit_indicators = ['noatsecure', 'rlimitinh', 'siginh']
    found_indicators = set()

    for denial_info in unique_denials:
        # Check aggregated permissions set if available (for denials with multiple permissions)
        if 'permissions' in denial_info and denial_info['permissions']:
            for perm in denial_info['permissions']:
                if perm.lower().strip() in dontaudit_indicators:
                    found_indicators.add(perm.lower().strip())

        # Also check individual permission field for single-permission denials
        parsed_log = denial_info.get('log', {})
        permission = parsed_log.get('permission', '').lower().strip()
        if permission in dontaudit_indicators:
            found_indicators.add(permission)

    found_indicators_list = sorted(list(found_indicators))
    return len(found_indicators_list) > 0, found_indicators_list


def filter_denials(denials: list, process_filter: str = None, path_filter: str = None,
                   since_filter: str = None, until_filter: str = None,
                   source_filter: str = None, target_filter: str = None) -> list:
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
    if not any([process_filter, path_filter, since_filter, until_filter, source_filter, target_filter]):
        return denials

    filtered_denials = []

    for denial_info in denials:
        parsed_log = denial_info.get('log', {})
        include_denial = True

        # Process filtering
        if process_filter:
            comm = parsed_log.get('comm', '').lower()
            if process_filter.lower() not in comm:
                include_denial = False

        # Path filtering
        if path_filter and include_denial:
            path_found = False

            # Check main path
            path = parsed_log.get('path', '')
            if path and _path_matches(path, path_filter):
                path_found = True

            # Check correlation events for paths
            if not path_found and 'correlations' in denial_info:
                for correlation in denial_info['correlations']:
                    corr_path = correlation.get('path', '')
                    if corr_path and _path_matches(corr_path, path_filter):
                        path_found = True
                        break

            if not path_found:
                include_denial = False

        # Time range filtering
        if (since_dt or until_dt) and include_denial:
            denial_time = denial_info.get('last_seen_obj') or denial_info.get('first_seen_obj')
            if denial_time:
                if since_dt and denial_time < since_dt:
                    include_denial = False
                elif until_dt and denial_time > until_dt:
                    include_denial = False

        # Source context filtering
        if source_filter and include_denial:
            scontext = str(parsed_log.get('scontext', ''))
            if not _context_matches(scontext, source_filter):
                include_denial = False

        # Target context filtering
        if target_filter and include_denial:
            tcontext = str(parsed_log.get('tcontext', ''))
            if not _context_matches(tcontext, target_filter):
                include_denial = False

        if include_denial:
            filtered_denials.append(denial_info)

    return filtered_denials


def _path_matches(path: str, pattern: str) -> bool:
    """
    Check if a path matches a pattern with basic wildcard support.

    Args:
        path (str): The file path to check
        pattern (str): The pattern (supports * wildcards)

    Returns:
        bool: True if path matches pattern
    """
    import fnmatch
    return fnmatch.fnmatch(path, pattern)


def _context_matches(context: str, pattern: str) -> bool:
    """
    Check if a SELinux context matches a pattern with wildcard support.

    Args:
        context (str): The SELinux context to check (e.g., 'system_u:system_r:httpd_t:s0')
        pattern (str): The pattern to match against (supports * wildcards)
                      Can match full context or individual components

    Returns:
        bool: True if context matches pattern

    Examples:
        >>> _context_matches('system_u:system_r:httpd_t:s0', 'httpd_t')
        True
        >>> _context_matches('system_u:system_r:httpd_t:s0', '*httpd*')
        True
        >>> _context_matches('unconfined_u:object_r:default_t:s0', '*default*')
        True
    """
    import fnmatch

    if not context or not pattern:
        return False

    context = context.strip()
    pattern = pattern.strip()

    # Case-insensitive matching for better user experience
    context_lower = context.lower()
    pattern_lower = pattern.lower()

    # Direct substring match (for simple cases like 'httpd_t')
    if pattern_lower in context_lower:
        return True

    # Wildcard pattern matching on full context
    if fnmatch.fnmatch(context_lower, pattern_lower):
        return True

    # If pattern doesn't contain colons, try matching against individual context components
    if ':' not in pattern:
        context_parts = context_lower.split(':')
        for part in context_parts:
            if fnmatch.fnmatch(part, pattern_lower):
                return True

    return False


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
    if 'path' in normalized and normalized['path']:
        path = normalized['path'].strip()
        if path:
            # Ensure absolute path representation
            if not path.startswith('/'):
                path = '/' + path
            # Normalize path separators and remove redundant slashes
            import os
            path = os.path.normpath(path)
            # Ensure forward slashes for cross-platform compatibility
            path = path.replace('\\', '/')
            normalized['path'] = path
            normalized['path_absolute'] = path
            normalized['path_normalized'] = True
        else:
            normalized['path'] = None

    # 2. CLEAN PORT EXTRACTION AND FORMATTING
    if 'dest_port' in normalized and normalized['dest_port']:
        port_str = str(normalized['dest_port']).strip()
        try:
            # Extract numeric port value
            port_num = int(port_str)
            normalized['dest_port'] = port_num
            normalized['dest_port_string'] = str(port_num)
            normalized['dest_port_type'] = 'numeric'

            # Add port classification
            if port_num <= 1023:
                normalized['dest_port_class'] = 'system'
            elif port_num <= 49151:
                normalized['dest_port_class'] = 'registered'
            else:
                normalized['dest_port_class'] = 'dynamic'

        except (ValueError, TypeError):
            # Keep original if not numeric, but clean it
            normalized['dest_port'] = port_str
            normalized['dest_port_string'] = port_str
            normalized['dest_port_type'] = 'non_numeric'

    # 3. NORMALIZED SELINUX CONTEXT FIELD STRUCTURES
    for context_field in ['scontext', 'tcontext']:
        if context_field in normalized and normalized[context_field]:
            context_str = str(normalized[context_field]).strip()
            if ':' in context_str:
                # Parse SELinux context components
                parts = context_str.split(':')
                if len(parts) >= 3:
                    context_base = f"{context_field}_components"
                    normalized[context_base] = {
                        'user': parts[0] if len(parts) > 0 else '',
                        'role': parts[1] if len(parts) > 1 else '',
                        'type': parts[2] if len(parts) > 2 else '',
                        'level': parts[3] if len(parts) > 3 else '',
                        'full': context_str
                    }
                    # Add type extraction for easier filtering
                    if len(parts) > 2:
                        type_key = f"{context_field}_type"
                        normalized[type_key] = parts[2]

    # 4. NETWORK ADDRESS STANDARDIZATION
    if 'saddr' in normalized and normalized['saddr']:
        saddr_str = str(normalized['saddr']).strip()
        # Parse network address information
        saddr_components = {}
        for component in saddr_str.split():
            if '=' in component:
                key, value = component.split('=', 1)
                saddr_components[key] = value

        if saddr_components:
            normalized['saddr_components'] = saddr_components
            # Extract commonly used fields
            if 'laddr' in saddr_components:
                normalized['local_address'] = saddr_components['laddr']
            if 'lport' in saddr_components:
                try:
                    normalized['local_port'] = int(saddr_components['lport'])
                except (ValueError, TypeError):
                    normalized['local_port'] = saddr_components['lport']

    # 5. DATA TYPE CONSISTENCY AND VALIDATION
    # Ensure numeric fields are properly typed
    numeric_fields = ['pid', 'ino', 'inode']
    for field in numeric_fields:
        if field in normalized and normalized[field] is not None:
            try:
                normalized[field] = int(str(normalized[field]).strip())
            except (ValueError, TypeError):
                # Keep as string if conversion fails, but clean it
                normalized[field] = str(normalized[field]).strip()

    # Ensure boolean fields are properly typed
    boolean_fields = ['permissive']
    for field in boolean_fields:
        if field in normalized and normalized[field] is not None:
            value = str(normalized[field]).strip().lower()
            if value in ['0', 'false', 'no']:
                normalized[field] = False
                normalized[f"{field}_numeric"] = 0
            elif value in ['1', 'true', 'yes']:
                normalized[field] = True
                normalized[f"{field}_numeric"] = 1
            else:
                normalized[field] = value

    # 6. STRING FIELD CLEANING AND STANDARDIZATION
    string_fields = ['comm', 'exe', 'syscall', 'denial_type', 'permission', 'tclass']
    for field in string_fields:
        if field in normalized and normalized[field] is not None:
            # Clean and standardize string values
            value = str(normalized[field]).strip()
            # Remove null bytes and control characters
            import re
            value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
            # Normalize whitespace
            value = ' '.join(value.split())
            normalized[field] = value if value else None

    # 7. TIMESTAMP STANDARDIZATION
    if 'timestamp' in normalized and normalized['timestamp']:
        try:
            # Ensure timestamp is float for consistency
            ts_value = float(str(normalized['timestamp']).strip())
            normalized['timestamp'] = ts_value
            normalized['timestamp_float'] = ts_value
        except (ValueError, TypeError):
            # Keep original if conversion fails
            pass

    # 8. ADD METADATA FOR TOOL INTEGRATION
    normalized['_normalized'] = True
    normalized['_normalization_version'] = '1.0'

    return normalized


def sort_denials(denials: list, sort_order: str) -> list:
    """
    Sort denials based on the specified sort order.

    Args:
        denials (list): List of denial dictionaries to sort
        sort_order (str): Sort order - 'recent', 'count', or 'chrono'

    Returns:
        list: Sorted list of denials
    """
    if sort_order == "recent":
        # Most recent first, then latest-starting as tiebreaker (reverse chronological for both)
        return sorted(denials,
                     key=lambda x: (x.get('last_seen_obj') or datetime.fromtimestamp(0),
                                  x.get('first_seen_obj') or datetime.fromtimestamp(0)),
                     reverse=True)
    elif sort_order == "count":
        # Highest count first, then by most recent as tiebreaker
        return sorted(denials,
                     key=lambda x: (x.get('count', 0), x.get('last_seen_obj') or datetime.fromtimestamp(0)),
                     reverse=True)
    elif sort_order == "chrono":
        # Chronological order (oldest first) using first_seen
        return sorted(denials,
                     key=lambda x: x.get('first_seen_obj') or datetime.fromtimestamp(0))
    else:
        # Default to recent if unknown sort order
        return sorted(denials,
                     key=lambda x: x.get('last_seen_obj') or datetime.fromtimestamp(0),
                     reverse=True)


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

    # Check if this denial contains dontaudit permissions and add indicator
    has_dontaudit, dontaudit_perms = has_dontaudit_permissions(denial_info)
    dontaudit_indicator = " [bright_yellow]⚠️ Enhanced Audit[/bright_yellow]" if has_dontaudit else ""

    # Check if this denial contains permissive mode events and add indicator
    has_permissive = has_permissive_denials(denial_info)
    permissive_indicator = " [bright_blue]🛡️ Permissive[/bright_blue]" if has_permissive else ""

    header = f"[bold green]Unique Denial #{
        denial_num}[/bold green] ({count} occurrences, last seen {last_seen_ago}){dontaudit_indicator}{permissive_indicator}"
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
        permissions_str = get_enhanced_permissions_display(denial_info, parsed_log)
        action_fields.append(("Permission", permissions_str))
    elif parsed_log.get("permission"):
        permission_display = get_enhanced_permissions_display(denial_info, parsed_log)
        action_fields.append(("Permission", permission_display))

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

    # Add contextual analysis if available
    if parsed_log.get("contextual_analysis"):
        action_fields.append(("Analysis", parsed_log["contextual_analysis"]))

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
                # Enhance comm display with source type description if available
                if parsed_log.get('source_type_description'):
                    source_desc = parsed_log['source_type_description']
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
                last_seen_str = denial_info['last_seen_obj'].strftime(
                    '%Y-%m-%d %H:%M:%S') if denial_info['last_seen_obj'] else parsed_log[key]
                console.print(f"[dim white]{last_seen_str}[/dim white]")
            elif key in ["proctitle", "exe"]:
                console.print(f"[green]{parsed_log[key]}[/green]")
            elif key == "comm":
                # Enhance comm display with source type description if available
                if parsed_log.get('source_type_description'):
                    enhanced_comm = f"{parsed_log[key]} ({parsed_log['source_type_description']})"
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
    console.print(f"  [bold]Action:[/bold]".ljust(22) + "Denied")

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
        console.print(f"  [bold]Denial Type:[/bold]".ljust(22), end="")
        console.print(f"[bright_green bold]{denial_type_display}[/bright_green bold]")

    for label, key in action_fields:
        if key in parsed_log or (
                label == "Permission" and 'permissions' in denial_info) or (
                label == "SELinux Mode"):
            if label == "Permission" and 'permissions' in denial_info:
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
                # Handle both AvcContext objects and raw strings
                if isinstance(values, str) and ',' in values:
                    # Multiple values - display all
                    console.print(f"[bright_cyan bold]{values}[/bright_cyan bold]")
                else:
                    # Single value - could be AvcContext or string
                    display_value = str(values) if values else ""
                    # Enhance with target type description if available
                    if parsed_log.get('target_type_description'):
                        target_desc = parsed_log['target_type_description']
                        enhanced_value = f"{display_value} ({target_desc})"
                        console.print(f"[bright_cyan bold]{enhanced_value}[/bright_cyan bold]")
                    else:
                        console.print(f"[bright_cyan bold]{display_value}[/bright_cyan bold]")
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
                if parsed_log.get('target_type_description'):
                    enhanced_value = f"{display_value} ({parsed_log['target_type_description']})"
                    console.print(f"[bright_cyan bold]{enhanced_value}[/bright_cyan bold]")
                else:
                    console.print(f"[bright_cyan bold]{display_value}[/bright_cyan bold]")
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
            # Enhance port display with description if available
            port_value = parsed_log['dest_port']
            if parsed_log.get('port_description'):
                enhanced_port = f"{port_value} ({parsed_log['port_description']})"
                console.print(f"[green]{enhanced_port}[/green]")
            else:
                console.print(f"[green]{port_value}[/green]")

    console.print("-" * 35)


def group_events_by_resource(correlations: list, expand_groups: bool = False) -> dict:
    """
    Group correlation events by exact resource (file path, port, etc.) for smart event grouping.

    Args:
        correlations (list): List of correlation event dictionaries
        expand_groups (bool): If True, disable grouping and return individual events

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
    if expand_groups:
        # Return all events as individual when grouping is disabled
        return {
            'grouped': [],
            'individual': [{'type': 'individual_event', 'event': event} for event in correlations]
        }

    # Group events by exact resource (file path, port, socket address, etc.)
    resource_groups = {}
    individual_events = []

    for event in correlations:
        # Determine the resource identifier for grouping
        resource_key = None
        resource_type = None

        # Check for file/directory path
        path = event.get('path', '')
        if path:
            resource_key = path
            # Determine if it's a directory or file based on various indicators
            if (path.startswith('...') or  # Partial directory paths like ".../sterling"
                path.endswith('/') or      # Explicit directory paths ending with /
                event.get('tclass') == 'dir'):  # SELinux object class indicates directory
                resource_type = 'directory'
            else:
                resource_type = 'file'
        # Check for network port
        elif event.get('dest_port'):
            resource_key = f"port:{event.get('dest_port')}"
            resource_type = 'port'
        # Check for socket address
        elif event.get('saddr'):
            resource_key = f"socket:{event.get('saddr')}"
            resource_type = 'socket'
        # Check for other object classes without specific resources (like security keys)
        elif event.get('tclass'):
            tclass = event.get('tclass')
            permission = event.get('permission', '')
            # Group by object class + permission for resources without specific identifiers
            resource_key = f"{tclass}:{permission}"
            resource_type = tclass

        # If we found a resource to group by
        if resource_key:
            if resource_key not in resource_groups:
                resource_groups[resource_key] = {
                    'type': 'resource_group',
                    'resource': resource_key,
                    'resource_type': resource_type,
                    'events': [],
                    'permissions': set(),
                    'pids': set(),
                    'comms': set()
                }

            resource_groups[resource_key]['events'].append(event)
            resource_groups[resource_key]['permissions'].add(event.get('permission', ''))
            resource_groups[resource_key]['pids'].add(event.get('pid', ''))
            resource_groups[resource_key]['comms'].add(event.get('comm', ''))
        else:
            # No groupable resource found - treat as individual
            individual_events.append({'type': 'individual_event', 'event': event})

    # Convert resource groups to final format
    grouped_events = []
    for resource_key, group_data in resource_groups.items():
        events = group_data['events']

        # Group if we have multiple PIDs accessing the same exact resource (2+ events)
        if len(events) >= 2:
            grouped_events.append({
                'type': 'resource_group',
                'resource': resource_key,
                'resource_type': group_data['resource_type'],
                'count': len(events),
                'permissions': sorted(list(group_data['permissions'])),
                'pids': sorted(list(group_data['pids'])),
                'comms': sorted(list(group_data['comms'])),
                'all_events': events
            })
        else:
            # Single event for this resource - treat as individual
            for event in events:
                individual_events.append({'type': 'individual_event', 'event': event})

    return {
        'grouped': grouped_events,
        'individual': individual_events
    }


def print_rich_summary(console: Console, denial_info: dict, denial_num: int, detailed: bool = False, expand_groups: bool = False):
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
    from rich.columns import Columns
    from rich.text import Text

    parsed_log = denial_info['log']
    count = denial_info['count']
    last_seen_dt = denial_info['last_seen_obj']
    last_seen_ago = human_time_ago(last_seen_dt)

    # Rich Rule header with responsive design using BIONIC reading format
    header_text = f"Unique Denial #{denial_num} • {count} occurrences • last seen {last_seen_ago}"
    header_bionic = format_bionic_text(header_text, "green")

    # Check if this denial contains dontaudit permissions and add indicator after BIONIC formatting
    has_dontaudit, dontaudit_perms = has_dontaudit_permissions(denial_info)
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
            custom_indicator = f" • [bright_magenta]📁 {custom_patterns[0]}[/bright_magenta]"
        else:
            custom_indicator = f" • [bright_magenta]📁 custom paths[/bright_magenta]"
        header_bionic += custom_indicator

    # Check if this denial contains container issues and add indicator
    has_container, container_patterns, sample_paths = has_container_issues(denial_info)
    if has_container:
        container_indicator = f" • [bright_cyan]🐳 container[/bright_cyan]"
        header_bionic += container_indicator

    console.print(Rule(header_bionic, style="cyan"))

    # Create WHEN/WHAT panel content
    when_what_content = []

    # 1. WHEN - Add timestamp with AVC type on same line
    # Get AVC type first
    avc_type_suffix = ""
    if parsed_log.get('denial_type'):
        denial_type_display = "Kernel AVC" if parsed_log['denial_type'] == "AVC" else "Userspace AVC" if parsed_log['denial_type'] == "USER_AVC" else parsed_log['denial_type']
        avc_type_suffix = f" • [bright_green]{denial_type_display}[/bright_green]"

    if count > 1 and 'first_seen_obj' in denial_info and denial_info['first_seen_obj'] and last_seen_dt:
        # Show time range for multiple occurrences
        first_seen_str = denial_info['first_seen_obj'].strftime('%Y-%m-%d %H:%M:%S')
        last_seen_str = last_seen_dt.strftime('%Y-%m-%d %H:%M:%S')

        # Check if they're on the same day
        if denial_info['first_seen_obj'].date() == last_seen_dt.date():
            # Same day - show date once with time range
            date_str = denial_info['first_seen_obj'].strftime('%Y-%m-%d')
            first_time = denial_info['first_seen_obj'].strftime('%H:%M:%S')
            last_time = last_seen_dt.strftime('%H:%M:%S')
            timestamp_display = f"{date_str} {first_time}–{last_time}"
        else:
            # Different days - show full range
            timestamp_display = f"{first_seen_str} – {last_seen_str}"

        when_what_content.append(f"[bold white]{timestamp_display}[/bold white]{avc_type_suffix}")
    elif parsed_log.get('datetime_str'):
        # Single occurrence
        when_what_content.append(f"[bold white]{parsed_log['datetime_str']}[/bold white]{avc_type_suffix}")

    # 2. WHAT - Action summary with syscall context
    permissions_display = get_enhanced_permissions_display(denial_info, parsed_log)
    obj_class = parsed_log.get('class_description', parsed_log.get('tclass', ''))

    # Apply BIONIC reading to natural language parts only
    denied_bionic = format_bionic_text("Denied", "white")
    on_bionic = format_bionic_text("on", "white")

    action_line = f"{denied_bionic} [bright_cyan bold]{permissions_display}[/bright_cyan bold] {on_bionic} [green bold]{obj_class}[/green bold]"

    # Add syscall context to the action line
    if parsed_log.get('syscall'):
        via_bionic = format_bionic_text("via", "white")
        action_line += f" {via_bionic} [green]{parsed_log['syscall']}[/green]"

    when_what_content.append(action_line)

    # Display WHEN/WHAT panel
    if when_what_content:
        # Center each line individually for proper alignment
        centered_lines = [Align.center(line) for line in when_what_content]
        panel_content = Panel(Group(*centered_lines), border_style="dim", padding=(0, 3))
        # Responsive width: minimum 60% of screen, maximum 120 characters
        panel_width = min(max(int(console.width * 0.6), 60), 120)
        console.print(Align.center(panel_content, width=panel_width))

    # 3. Security Context - Simplified panel showing only context transition
    scontext = str(parsed_log.get('scontext', ''))
    tcontext = str(parsed_log.get('tcontext', ''))
    if scontext and tcontext:
        context_text = f"[bright_cyan]{scontext}[/bright_cyan] → [bright_cyan]{tcontext}[/bright_cyan]"
        centered_context = Align.center(context_text)
        context_panel = Panel(centered_context, border_style="dim", padding=(0, 3))
        # Responsive width: minimum 60% of screen, maximum 120 characters
        panel_width = min(max(int(console.width * 0.6), 60), 120)
        console.print(Align.center(context_panel, width=panel_width))

    console.print()  # Space before events

    # Correlation events display with smart grouping
    if 'correlations' in denial_info and denial_info['correlations']:
        if detailed:
            console.print("[bold]Detailed Events:[/bold]")
        else:
            console.print("[bold]Events:[/bold]")

        # Apply smart event grouping by exact resource
        grouped_events = group_events_by_resource(denial_info['correlations'], expand_groups)

        # Display grouped events first (multiple PIDs accessing same exact resource)
        for group in grouped_events['grouped']:
            resource = group['resource']
            resource_type = group['resource_type']
            count = group['count']
            permissions = group['permissions']
            pids = group['pids']
            comms = group['comms']

            # Format permissions
            perm_display = permissions[0] if len(permissions) == 1 else ", ".join(permissions)

            # Get process name and description
            process_name = comms[0] if comms else 'unknown'
            process_desc = parsed_log.get('source_type_description', '')
            if process_desc:
                process_display = f"[green]{process_name}[/green] [dim]({process_desc})[/dim]"
            else:
                process_display = f"[green]{process_name}[/green]"

            # Format resource display based on type
            if resource_type == 'file':
                # Check if this is a container file
                is_container_file = any(pattern in resource for pattern in [
                    '/containers/storage/overlay/',
                    '/.local/share/containers/',
                    '/var/lib/containers/',
                    '/var/lib/docker/'
                ])

                if is_container_file:
                    # For container files, show meaningful container context
                    if '/containers/storage/overlay/' in resource:
                        # Extract container path: .../overlay/[container-id]/diff/path/to/file
                        parts = resource.split('/containers/storage/overlay/')
                        if len(parts) > 1:
                            overlay_part = parts[1]
                            # Get container ID and internal path
                            overlay_parts = overlay_part.split('/')
                            if len(overlay_parts) >= 3:  # container-id/diff/internal/path
                                container_id = overlay_parts[0][:12]  # First 12 chars of container ID
                                internal_path = '/'.join(overlay_parts[2:])  # Skip 'diff' part
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{internal_path}[/bright_white] [dim](container [bright_cyan]{container_id}[/bright_cyan])[/dim]"
                            else:
                                filename = resource.split('/')[-1]
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            filename = resource.split('/')[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                    elif '/.local/share/containers/' in resource:
                        # Handle user container storage
                        parts = resource.split('/.local/share/containers/')
                        if len(parts) > 1:
                            container_part = parts[1]
                            # Extract meaningful part after containers/
                            if '/overlay/' in container_part:
                                overlay_parts = container_part.split('/overlay/')
                                if len(overlay_parts) > 1:
                                    overlay_subpart = overlay_parts[1].split('/')
                                    if len(overlay_subpart) >= 3:  # container-id/diff/internal/path
                                        container_id = overlay_subpart[0][:12]
                                        internal_path = '/'.join(overlay_subpart[2:])
                                        resource_display = f"[cyan]container file[/cyan] [bright_white]{internal_path}[/bright_white] [dim](container [bright_cyan]{container_id}[/bright_cyan])[/dim]"
                                    else:
                                        filename = resource.split('/')[-1]
                                        resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                                else:
                                    filename = resource.split('/')[-1]
                                    resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                            else:
                                filename = resource.split('/')[-1]
                                resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            filename = resource.split('/')[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                    else:
                        # Fallback for other container patterns
                        if '/' in resource and len(resource) > 60:
                            filename = resource.split('/')[-1]
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{filename}[/bright_white]"
                        else:
                            resource_display = f"[cyan]container file[/cyan] [bright_white]{resource}[/bright_white]"
                else:
                    # Regular file handling
                    if '/' in resource and len(resource) > 60:
                        filename = resource.split('/')[-1]
                        resource_display = f"file {filename}"
                    else:
                        resource_display = f"file {resource}"
            elif resource_type == 'directory':
                resource_display = f"directory {resource}"
            elif resource_type == 'port':
                port_num = resource.replace('port:', '')
                port_desc = PermissionSemanticAnalyzer.get_port_description(port_num)
                if port_desc != f"port {port_num}":
                    resource_display = f"port {port_num} ({port_desc})"
                else:
                    resource_display = f"port {port_num}"
            elif resource_type == 'socket':
                socket_addr = resource.replace('socket:', '')
                resource_display = f"socket {socket_addr}"
            elif resource_type in ['key', 'capability', 'process', 'dbus']:
                # For object classes without specific resource identifiers
                class_desc = PermissionSemanticAnalyzer.get_class_description(resource_type)
                resource_display = f"{class_desc} resource"
            else:
                resource_display = resource

            denied_bionic = format_bionic_text("denied", "white")
            to_bionic = format_bionic_text("to", "white")

            # Use tree structure only for multiple PIDs, simple format for single PID
            pid_count = len(pids)
            pid_label = "PID" if pid_count == 1 else "PIDs"

            if pid_count == 1:
                # Simple format for single PID - no tree structure needed
                single_pid = list(pids)[0]
                # Count events for this specific PID in this group
                pid_events_count = len([event for event in group['all_events'] if event.get('pid') == single_pid])
                pid_count_display = f" ({pid_events_count}x)" if pid_events_count > 1 else ""
                console.print(f"• {pid_label} {single_pid}{pid_count_display} ({process_display})")
                console.print(f"  {denied_bionic} '[bright_cyan]{perm_display}[/bright_cyan]' {to_bionic} {resource_display} [Enforcing] [red]✗ BLOCKED[/red]")
            else:
                # Tree structure for multiple PIDs
                console.print(f"• {pid_count} {pid_label} ({process_display})")

                # Tree structure for PID list (8 PIDs per line)
                pid_chunks = [pids[i:i+8] for i in range(0, len(pids), 8)]
                for i, chunk in enumerate(pid_chunks):
                    is_last_chunk = (i == len(pid_chunks) - 1)
                    tree_symbol = "└─" if is_last_chunk else "├─"
                    console.print(f"  {tree_symbol} {', '.join(chunk)}")

                # Denial action line
                console.print(f"  {denied_bionic} '[bright_cyan]{perm_display}[/bright_cyan]' {to_bionic} {resource_display} [Enforcing] [red]✗ BLOCKED[/red]")

            if detailed:
                # Group events by PID for multi-level tree display
                events_by_pid = {}
                for event in group['all_events']:
                    pid = event.get('pid', 'unknown')
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
                    console.print(f"  {pid_branch} PID {pid} ({event_count} event{'s' if event_count != 1 else ''}):")

                    # Consolidate identical events for this PID
                    consolidated_events = {}
                    for event in pid_events:
                        permission = event.get('permission', '')
                        timestamp = event.get('timestamp', '')
                        syscall = event.get('syscall', parsed_log.get('syscall', 'unknown'))
                        exit_code = event.get('exit', 'unknown')

                        # Create key for identical events (ignore microsecond differences)
                        time_key = timestamp.split('.')[0] if '.' in timestamp else timestamp  # Remove microseconds
                        event_key = (permission, time_key, syscall, exit_code)

                        if event_key not in consolidated_events:
                            consolidated_events[event_key] = {
                                'permission': permission,
                                'timestamp': timestamp,
                                'syscall': syscall,
                                'exit_code': exit_code,
                                'count': 0
                            }
                        consolidated_events[event_key]['count'] += 1

                    # Display consolidated events
                    consolidated_list = list(consolidated_events.values())
                    display_events = consolidated_list[:3]  # Limit to 3 unique event types per PID

                    for i, consolidated_event in enumerate(display_events):
                        permission = consolidated_event['permission']
                        timestamp = consolidated_event['timestamp']
                        syscall = consolidated_event['syscall']
                        exit_code = consolidated_event['exit_code']
                        count = consolidated_event['count']

                        is_last_event = i == len(display_events) - 1 and len(consolidated_list) <= 3
                        event_branch = "└─" if is_last_event and is_last_pid else "├─"
                        pid_prefix = "   " if is_last_pid else "│  "

                        # Format with count if more than 1 identical event
                        if count > 1:
                            count_text = f" ({count}x)"
                        else:
                            count_text = ""

                        console.print(f"  {pid_prefix} {event_branch} [bright_cyan]{permission}[/bright_cyan]{count_text} | Time: {timestamp} | Syscall: [bright_yellow]{syscall}[/bright_yellow] | Exit: {exit_code}")

                    # Show truncation if needed
                    if len(consolidated_list) > 3:
                        pid_prefix = "   " if is_last_pid else "│  "
                        remaining_count = len(consolidated_list) - 3
                        console.print(f"  {pid_prefix} └─ ... and {remaining_count} more event type{'s' if remaining_count != 1 else ''}")

                # Add process context at the bottom
                exe_path = parsed_log.get('exe', '')
                proctitle = parsed_log.get('proctitle', '')
                contextual_analysis = parsed_log.get('contextual_analysis', '')

                if exe_path or proctitle or contextual_analysis:
                    console.print(f"  └─ Process Context:")
                    if exe_path:
                        console.print(f"     ├─ Executable: [dim]{exe_path}[/dim]")
                    if contextual_analysis:
                        console.print(f"     ├─ Analysis: [yellow]{contextual_analysis}[/yellow]")
                    if proctitle and proctitle != parsed_log.get('comm', ''):
                        console.print(f"     └─ Process Title: [dim]{proctitle}[/dim]")

        # Display individual events (single PID per resource)
        for item in grouped_events['individual']:
            correlation = item['event']
            pid = correlation.get('pid', 'unknown')
            comm = correlation.get('comm', 'unknown')
            permission = correlation.get('permission', '')
            path = correlation.get('path', '')
            dest_port = correlation.get('dest_port', '')
            saddr = correlation.get('saddr', '')
            permissive = correlation.get('permissive', '')
            timestamp = correlation.get('timestamp', '')


            # Build event description with BIONIC reading for natural language parts
            if path:
                # Determine object type for better display
                tclass = parsed_log.get('tclass', 'file')
                if tclass == 'dir':
                    object_bionic = format_bionic_text("directory", "white")
                    target_type = "directory"
                elif tclass in ['tcp_socket', 'udp_socket']:
                    object_bionic = format_bionic_text("socket", "white")
                    target_type = "socket"
                elif tclass == 'chr_file':
                    object_bionic = format_bionic_text("character device", "white")
                    target_type = "char_device"
                elif tclass == 'blk_file':
                    object_bionic = format_bionic_text("block device", "white")
                    target_type = "block_device"
                else:
                    object_bionic = format_bionic_text("file", "white")
                    target_type = "file"

                # Smart path truncation for better display
                formatted_path = format_path_for_display(path)
                target_desc = f"{object_bionic} {formatted_path}"
            elif dest_port:
                # Check if this is a D-Bus destination or network port
                tclass = parsed_log.get('tclass', '')
                if tclass == 'dbus' or dest_port.startswith(':'):
                    # D-Bus destination
                    dbus_bionic = format_bionic_text("D-Bus service", "white")
                    target_desc = f"{dbus_bionic} {dest_port}"
                    target_type = "dbus"
                else:
                    # Network port
                    port_desc = PermissionSemanticAnalyzer.get_port_description(dest_port)
                    port_bionic = format_bionic_text("port", "white")
                    if port_desc != f"port {dest_port}":
                        target_desc = f"{port_bionic} {dest_port} ({port_desc})"
                    else:
                        target_desc = f"{port_bionic} {dest_port}"
                    target_type = "tcp_socket"
            elif saddr:
                socket_bionic = format_bionic_text("socket", "white")
                target_desc = f"{socket_bionic} {saddr}"
                target_type = "socket"
            else:
                target_desc = format_bionic_text("resource", "white")
                target_type = "unknown"

            # Determine enforcement status
            if permissive == "1":
                enforcement = "[green]✓ ALLOWED[/green]"
                mode = "[yellow]Permissive[/yellow]"
            else:
                enforcement = "[red]✗ BLOCKED[/red]"
                mode = "[cyan]Enforcing[/cyan]"

            # Display correlation event
            if detailed:
                # Enhanced detailed view with additional information
                exe_path = parsed_log.get('exe', '')
                # Properly escape brackets in Rich markup - use double backslashes
                if exe_path:
                    escaped_exe = exe_path.replace('[', '\\[').replace(']', '\\]')
                    exe_display = f" \\[{escaped_exe}\\]"
                else:
                    exe_display = ""
                denied_bionic = format_bionic_text("denied", "white")
                to_bionic = format_bionic_text("to", "white")
                # Split into two lines: PID+process line and denial action line
                console.print(f"• PID {pid} ([green]{comm}[/green]){exe_display}")
                console.print(f"  {denied_bionic} '[bright_cyan]{permission}[/bright_cyan]' {to_bionic} {target_desc} [{mode}] {enforcement}")

                # Add detailed sub-information with tree-like structure
                syscall = parsed_log.get('syscall', '')
                cwd = parsed_log.get('cwd', '')
                proctitle = parsed_log.get('proctitle', '')

                if syscall:
                    # Get actual exit code from the correlation event
                    exit_code = correlation.get('exit', 'unknown')
                    console.print(f"  ├─ [bright_cyan]{permission}[/bright_cyan] | Time: {timestamp} | Syscall: [bright_yellow]{syscall}[/bright_yellow] | Exit: {exit_code}")

                # Add process context information
                if cwd:
                    console.print(f"  ├─ Working Directory: [dim]{cwd}[/dim]")

                if proctitle and proctitle != comm:
                    # Determine if this should be the last item for proper tree branching
                    has_analysis = (permission and hasattr(PermissionSemanticAnalyzer, 'get_contextual_analysis')
                                   and parsed_log.get('contextual_analysis', ''))
                    branch = "├─" if has_analysis else "└─"
                    console.print(f"  {branch} Process Title: [dim]{proctitle}[/dim]")

                # Add semantic analysis last as it provides interpretive context
                if permission and hasattr(PermissionSemanticAnalyzer, 'get_contextual_analysis'):
                    contextual_analysis = parsed_log.get('contextual_analysis', '')
                    if contextual_analysis:
                        console.print(f"  └─ Analysis: [dim]{contextual_analysis}[/dim]")

                # Fallback closing branch if no other context is available
                if not (cwd or (proctitle and proctitle != comm) or
                       (permission and hasattr(PermissionSemanticAnalyzer, 'get_contextual_analysis')
                        and parsed_log.get('contextual_analysis', ''))):
                    console.print(f"  └─ Process: [dim]{comm}[/dim]")

            else:
                # Standard compact view
                denied_bionic = format_bionic_text("denied", "white")
                to_bionic = format_bionic_text("to", "white")
                # Split into two lines: PID+process line and denial action line
                console.print(f"• PID {pid} ([green]{comm}[/green])")
                console.print(f"  {denied_bionic} '[bright_cyan]{permission}[/bright_cyan]' {to_bionic} {target_desc} [{mode}] {enforcement}")

    console.print()  # Space after events


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
        # Use stderr for error messages so tests can capture them
        error_console = Console(stderr=True)
        error_console.print("❌ [bold red]Error: Conflicting Arguments[/bold red]")
        error_console.print("   Cannot specify multiple file arguments simultaneously.")
        error_console.print("   [dim]Choose one input method:[/dim]")
        error_console.print("   • [cyan]--file[/cyan] for auto-detection (recommended)")
        error_console.print("   • [cyan]--raw-file[/cyan] for raw audit.log files")
        error_console.print("   • [cyan]--avc-file[/cyan] for pre-processed ausearch output")
        sys.exit(1)

    # Validate JSON flag requirements
    if args.json and file_args_count == 0:
        print_error("❌ [bold red]Error: Missing Required Arguments[/bold red]")
        print_error("   --json flag requires a file input to process.")
        print_error("   [dim]Valid combinations:[/dim]")
        print_error("   • [cyan]--json --file audit.log[/cyan] (recommended)")
        print_error("   • [cyan]--json --raw-file audit.log[/cyan]")
        print_error("   • [cyan]--json --avc-file processed.log[/cyan]")
        sys.exit(1)

    # Handle new --file argument with auto-detection
    if args.file:
        return validate_file_with_auto_detection(args.file, console, quiet=args.json or args.pager)

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


def validate_file_with_auto_detection(file_path: str, console: Console, quiet: bool = False) -> str:
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
            print_error(f"❌ [bold red]Error: Empty File[/bold red]")
            print_error(f"   File is empty: [cyan]{file_path}[/cyan]")
            print_error("   [dim]Please provide a file with audit log content.[/dim]")
            sys.exit(1)

        if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            console.print(f"⚠️  [bold yellow]Warning: Large File Detected[/bold yellow]")
            console.print(f"   File size: {file_size / (1024*1024):.1f}MB")
            console.print("   [dim]Processing may take some time...[/dim]")

        # Auto-detect format type
        detected_format = detect_file_format(file_path)

        detection_msg = ""
        if not quiet:
            if detected_format == 'raw':
                detection_msg = f"🔍 [bold green]Auto-detected:[/bold green] Raw audit.log format\n   Will process using ausearch: [cyan]{file_path}[/cyan]"
            else:
                detection_msg = f"🔍 [bold green]Auto-detected:[/bold green] Pre-processed format\n   Will parse the file [cyan]{file_path}[/cyan] directly"

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
    except PermissionError:
        print_error(f"❌ [bold red]Error: Permission Denied[/bold red]")
        print_error(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        print_error("   [dim]Please check file permissions or run with appropriate privileges.[/dim]")
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
    parser.add_argument(
        "--fields",
        action="store_true",
        help="Use field-by-field display format instead of compact Rich format.")
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show enhanced detailed view with expanded correlation events and context information.")
    parser.add_argument(
        "--process",
        type=str,
        help="Filter denials by process name (e.g., --process httpd).")
    parser.add_argument(
        "--path",
        type=str,
        help="Filter denials by file path (supports wildcards, e.g., --path '/var/www/*').")
    parser.add_argument(
        "--sort",
        type=str,
        choices=["recent", "count", "chrono"],
        default="recent",
        help="Sort order: 'recent' (newest first, default), 'count' (highest count first), 'chrono' (oldest first).")
    parser.add_argument(
        "--since",
        type=str,
        help="Only include denials since this time (e.g., 'yesterday', 'today', '2025-01-15', '2 hours ago').")
    parser.add_argument(
        "--until",
        type=str,
        help="Only include denials until this time (e.g., 'today', '2025-01-15 14:30').")
    parser.add_argument(
        "--source",
        type=str,
        help="Filter by source context pattern (e.g., 'httpd_t', '*unconfined*', 'system_r').")
    parser.add_argument(
        "--target",
        type=str,
        help="Filter by target context pattern (e.g., 'default_t', '*var_lib*').")
    parser.add_argument(
        "--legacy-signatures",
        action="store_true",
        help="Use legacy signature logic for regression testing (disables smart deduplication).")
    parser.add_argument(
        "--expand-groups",
        action="store_true",
        help="Show individual events instead of resource-based groupings (disables smart event grouping).")
    parser.add_argument(
        "--pager",
        action="store_true",
        help="Use interactive pager for large outputs (like 'less' command).")
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
        if detected_format == 'raw':
            detection_message = f"🔍 [bold green]Auto-detected:[/bold green] Raw audit.log format\n   Will process using ausearch: [cyan]{file_path}[/cyan]"
        else:
            detection_message = f"🔍 [bold green]Auto-detected:[/bold green] Pre-processed format\n   Will parse the file [cyan]{file_path}[/cyan] directly"

    if input_type == 'raw_file':
        # Determine the correct file path (could be from --file or --raw-file)
        file_path = args.file if args.file else args.raw_file
        if not args.json:
            ausearch_message = f"Raw file input provided. Running ausearch on '{file_path}'..."
        try:
            ausearch_cmd = [
                "ausearch",
                "-m",
                "AVC,USER_AVC,AVC_PATH,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR",
                "-i",
                "-if",
                file_path]
            result = subprocess.run(ausearch_cmd, capture_output=True, text=True, check=True)
            log_string = result.stdout
        except FileNotFoundError:
            print_error("❌ [bold red]Error: ausearch Command Not Found[/bold red]")
            print_error("   The 'ausearch' command is required for processing raw audit files.")
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
    elif input_type == 'avc_file':
        # Determine the correct file path (could be from --file or --avc-file)
        file_path = args.file if args.file else args.avc_file
        # File path already shown in auto-detection message
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

    # Split log into blocks using '----' separator
    log_blocks = [block.strip() for block in log_string.split('----') if block.strip()]
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
        all_avc_denials.extend(avc_denials)

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

    # Process all AVC denials with smart signature generation
    for parsed_log in all_avc_denials:
        if "permission" in parsed_log:
            permission = parsed_log.get('permission')

            # Generate smart signature using new logic (or legacy for regression testing)
            signature = generate_smart_signature(parsed_log, legacy_mode=args.legacy_signatures)

            dt_obj = parsed_log.get('datetime_obj')

            if signature in unique_denials:
                # Add permission to the set if not already present
                if 'permissions' not in unique_denials[signature]:
                    unique_denials[signature]['permissions'] = set()
                unique_denials[signature]['permissions'].add(permission)

                # Store individual event correlation for PID-to-resource mapping
                if 'correlations' not in unique_denials[signature]:
                    unique_denials[signature]['correlations'] = []

                correlation_event = build_correlation_event(parsed_log, permission)
                unique_denials[signature]['correlations'].append(correlation_event)

                # Collect varying fields (not part of signature)
                varying_fields = ['pid', 'comm', 'path', 'dest_port', 'permissive', 'proctitle']
                for field in varying_fields:
                    if field in parsed_log and parsed_log[field] not in ["(null)", "null", ""]:
                        field_key = f'{field}s'  # e.g., 'pids', 'comms', 'paths'
                        if field_key not in unique_denials[signature]:
                            unique_denials[signature][field_key] = set()
                        unique_denials[signature][field_key].add(parsed_log[field])

                unique_denials[signature]['count'] += 1
                # Update first_seen_obj if this timestamp is older
                if dt_obj and (
                        not unique_denials[signature]['first_seen_obj'] or dt_obj < unique_denials[signature]['first_seen_obj']):
                    unique_denials[signature]['first_seen_obj'] = dt_obj
                # Update last_seen_obj if this timestamp is newer
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

                # Initialize correlation storage for first event
                correlation_event = build_correlation_event(parsed_log, permission)
                denial_entry['correlations'] = [correlation_event]

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

            # Add correlation data for PID-to-resource mapping with normalization
            if 'correlations' in denial_info:
                normalized_correlations = []
                for correlation in denial_info['correlations']:
                    normalized_correlation = normalize_json_fields(correlation.copy())
                    normalized_correlations.append(normalized_correlation)
                json_denial['correlations'] = normalized_correlations

            # Apply JSON field normalization for reliable tool integration
            json_denial['log'] = normalize_json_fields(json_denial['log'])

            # Remove datetime_obj from the log data and convert any remaining datetime
            # objects to strings
            json_denial['log'].pop('datetime_obj', None)
            for key, value in json_denial['log'].items():
                if isinstance(value, datetime):
                    json_denial['log'][key] = value.isoformat()
                elif isinstance(value, AvcContext):
                    # Convert AvcContext objects to strings for JSON serialization
                    json_denial['log'][key] = str(value)
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

        # Create structured JSON output with summary
        total_events = sum(denial['count'] for denial in unique_denials.values())
        json_structure = {
            'unique_denials': output_list,
            'summary': {
                'total_events': total_events,
                'unique_denials_count': len(unique_denials),
                'log_blocks_processed': len(valid_blocks)
            }
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

    else:
        # Non JSON default output
        total_events = sum(denial['count'] for denial in unique_denials.values())

        # Apply sorting based on user preference
        sorted_denials = sort_denials(list(unique_denials.values()), args.sort)

        # Apply filtering if specified
        try:
            filtered_denials = filter_denials(sorted_denials, args.process, args.path,
                                             args.since, args.until, args.source, args.target)
        except ValueError as e:
            console.print(f"[red]Error in filtering: {e}[/red]")
            return

        # Check for detection warnings (on full results before filtering for complete context)
        dontaudit_detected, found_indicators = detect_dontaudit_disabled(sorted_denials)
        permissive_detected, permissive_count, total_events = detect_permissive_mode(sorted_denials)

        # Check for custom paths detection
        custom_paths_detected, found_custom_patterns = False, []
        for denial_info in sorted_denials:
            has_custom, custom_patterns = has_custom_paths(denial_info)
            if has_custom:
                custom_paths_detected = True
                found_custom_patterns.extend(custom_patterns)
        found_custom_patterns = sorted(list(set(found_custom_patterns)))

        # Check for container issues detection
        container_issues_detected, found_container_patterns, container_sample_paths = False, [], []
        for denial_info in sorted_denials:
            has_container, container_patterns, sample_paths = has_container_issues(denial_info)
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
                f"Found {total_events} AVC events. Displaying {
                    len(unique_denials)} unique denials...")

            # Display filtering info if applicable
            if args.process or args.path or args.since or args.until or args.source or args.target:
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
                console.print(f"Showing {len(filtered_denials)} of {len(sorted_denials)} unique denials after filtering.")

            if filtered_denials:
                console.print(Rule("[dim]Parsed Log Summary[/dim]"))

                # Display detection warnings at the top
                if dontaudit_detected:
                    indicators_str = ", ".join(found_indicators)
                    # Create a prominent warning panel
                    from rich.panel import Panel
                    from rich.align import Align
                    from rich.console import Group

                    warning_lines = [
                        Align.center("[bold bright_yellow]⚠️  DONTAUDIT RULES DISABLED[/bold bright_yellow]"),
                        Align.center(""),
                        Align.center("[yellow]Enhanced audit mode is active on this system.[/yellow]"),
                        Align.center(f"[dim]Typically suppressed permissions detected: [bright_yellow]{indicators_str}[/bright_yellow][/dim]"),
                        Align.center(""),
                        Align.center("[dim]This means you're seeing permissions that are normally hidden.[/dim]")
                    ]

                    warning_panel = Panel(
                        Group(*warning_lines),
                        title="[bold red]Security Notice[/bold red]",
                        border_style="bright_yellow",
                        padding=(1, 4)
                    )
                    panel_width = min(max(int(console.width * 0.6), 60), 120)
                    console.print(Align.center(warning_panel, width=panel_width))
                    console.print()

                # Display permissive mode warning if found
                if permissive_detected:
                    from rich.panel import Panel
                    from rich.align import Align
                    from rich.console import Group

                    warning_lines = [
                        Align.center("[bold bright_blue]🛡️  PERMISSIVE MODE DETECTED[/bold bright_blue]"),
                        Align.center(""),
                        Align.center(f"[blue]{permissive_count} of {total_events} events were in permissive mode.[/blue]"),
                        Align.center("[dim]These denials were logged but not enforced.[/dim]")
                    ]

                    permissive_panel = Panel(
                        Group(*warning_lines),
                        title="[bold blue]Mode Notice[/bold blue]",
                        border_style="bright_blue",
                        padding=(1, 4)
                    )
                    panel_width = min(max(int(console.width * 0.6), 60), 120)
                    console.print(Align.center(permissive_panel, width=panel_width))
                    console.print()

                # Display custom paths warning if found
                if custom_paths_detected:
                    from rich.panel import Panel
                    from rich.align import Align
                    from rich.console import Group

                    patterns_str = ", ".join(found_custom_patterns[:3])
                    if len(found_custom_patterns) > 3:
                        patterns_str += f" (+{len(found_custom_patterns) - 3} more)"

                    warning_lines = [
                        Align.center("[bold bright_magenta]📁  CUSTOM PATHS DETECTED[/bold bright_magenta]"),
                        Align.center(""),
                        Align.center(f"[magenta]Non-standard paths found: {patterns_str}[/magenta]"),
                        Align.center("[dim]These may require custom fcontext rules.[/dim]")
                    ]

                    custom_panel = Panel(
                        Group(*warning_lines),
                        title="[bold magenta]Path Notice[/bold magenta]",
                        border_style="bright_magenta",
                        padding=(1, 4)
                    )
                    panel_width = min(max(int(console.width * 0.6), 60), 120)
                    console.print(Align.center(custom_panel, width=panel_width))
                    console.print()

                # Display container issues warning if found
                if container_issues_detected:
                    from rich.panel import Panel
                    from rich.align import Align
                    from rich.console import Group

                    patterns_str = ", ".join(found_container_patterns)

                    warning_lines = [
                        Align.center("[bold bright_cyan]🐳  CONTAINER STORAGE DETECTED[/bold bright_cyan]"),
                        Align.center(""),
                        Align.center(f"[cyan]Container patterns: {patterns_str}[/cyan]"),
                        Align.center("[dim]These may require container-specific SELinux policies.[/dim]")
                    ]

                    container_panel = Panel(
                        Group(*warning_lines),
                        title="[bold cyan]Container Notice[/bold cyan]",
                        border_style="bright_cyan",
                        padding=(1, 4)
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
                    else:
                        print_rich_summary(console, denial_info, i + 1, detailed=args.detailed, expand_groups=args.expand_groups)

                # Show filtering info in final summary if applicable
                if args.process or args.path:
                    console.print(
                        f"\n[bold green]Analysis Complete:[/bold green] Processed {
                            len(log_blocks)} log blocks and found {
                            len(unique_denials)} unique denials. Displayed {
                            len(filtered_denials)} after filtering.")
                else:
                    console.print(
                        f"\n[bold green]Analysis Complete:[/bold green] Processed {
                            len(log_blocks)} log blocks and found {
                            len(unique_denials)} unique denials.")

                # --- Added: Print the list of unparsed types found ---
                if all_unparsed_types:
                    console.print(
                        "\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:")
                    console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")

        # Use interactive pager for large outputs if requested and running in a terminal
        if args.pager and sys.stdout.isatty() and not args.json:
            # Capture output with colors preserved for pager
            import io
            from rich.console import Console as RichConsole

            # Create a string buffer to capture colored output
            string_buffer = io.StringIO()
            pager_console = RichConsole(file=string_buffer, width=console.width, force_terminal=True)

            try:
                # Temporarily switch console for content generation
                original_console = console

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
                        f"Found {total_events} AVC events. Displaying {
                            len(unique_denials)} unique denials...")

                    # Display filtering info if applicable
                    if args.process or args.path or args.since or args.until or args.source or args.target:
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
                        pager_console.print(f"Showing {len(filtered_denials)} of {len(sorted_denials)} unique denials after filtering.")

                    if filtered_denials:
                        pager_console.print(Rule("[dim]Parsed Log Summary[/dim]"))

                        # Display detection warnings at the top
                        if dontaudit_detected:
                            indicators_str = ", ".join(found_indicators)
                            # Create a prominent warning panel
                            from rich.panel import Panel
                            from rich.align import Align
                            from rich.console import Group

                            warning_lines = [
                                Align.center("[bold bright_yellow]⚠️  DONTAUDIT RULES DISABLED[/bold bright_yellow]"),
                                Align.center(""),
                                Align.center("[yellow]Enhanced audit mode is active on this system.[/yellow]"),
                                Align.center(f"[dim]Typically suppressed permissions detected: [bright_yellow]{indicators_str}[/bright_yellow][/dim]"),
                                Align.center(""),
                                Align.center("[dim]This means you're seeing permissions that are normally hidden.[/dim]")
                            ]

                            warning_panel = Panel(
                                Group(*warning_lines),
                                title="[bold red]Security Notice[/bold red]",
                                border_style="bright_yellow",
                                padding=(1, 4)
                            )
                            panel_width = min(max(int(pager_console.width * 0.6), 60), 120)
                            pager_console.print(Align.center(warning_panel, width=panel_width))
                            pager_console.print()

                        # Display permissive mode warning if found
                        if permissive_detected:
                            from rich.panel import Panel
                            from rich.align import Align
                            from rich.console import Group

                            warning_lines = [
                                Align.center("[bold bright_blue]🛡️  PERMISSIVE MODE DETECTED[/bold bright_blue]"),
                                Align.center(""),
                                Align.center(f"[blue]{permissive_count} of {total_events} events were in permissive mode.[/blue]"),
                                Align.center("[dim]These denials were logged but not enforced.[/dim]")
                            ]

                            permissive_panel = Panel(
                                Group(*warning_lines),
                                title="[bold blue]Mode Notice[/bold blue]",
                                border_style="bright_blue",
                                padding=(1, 4)
                            )
                            panel_width = min(max(int(pager_console.width * 0.6), 60), 120)
                            pager_console.print(Align.center(permissive_panel, width=panel_width))
                            pager_console.print()

                        # Display custom paths warning if found
                        if custom_paths_detected:
                            from rich.panel import Panel
                            from rich.align import Align
                            from rich.console import Group

                            patterns_str = ", ".join(found_custom_patterns[:3])
                            if len(found_custom_patterns) > 3:
                                patterns_str += f" (+{len(found_custom_patterns) - 3} more)"

                            warning_lines = [
                                Align.center("[bold bright_magenta]📁  CUSTOM PATHS DETECTED[/bold bright_magenta]"),
                                Align.center(""),
                                Align.center(f"[magenta]Non-standard paths found: {patterns_str}[/magenta]"),
                                Align.center("[dim]These may require custom fcontext rules.[/dim]")
                            ]

                            custom_panel = Panel(
                                Group(*warning_lines),
                                title="[bold magenta]Path Notice[/bold magenta]",
                                border_style="bright_magenta",
                                padding=(1, 4)
                            )
                            panel_width = min(max(int(pager_console.width * 0.6), 60), 120)
                            pager_console.print(Align.center(custom_panel, width=panel_width))
                            pager_console.print()

                        # Display container issues warning if found
                        if container_issues_detected:
                            from rich.panel import Panel
                            from rich.align import Align
                            from rich.console import Group

                            patterns_str = ", ".join(found_container_patterns)

                            warning_lines = [
                                Align.center("[bold bright_cyan]🐳  CONTAINER STORAGE DETECTED[/bold bright_cyan]"),
                                Align.center(""),
                                Align.center(f"[cyan]Container patterns: {patterns_str}[/cyan]"),
                                Align.center("[dim]These may require container-specific SELinux policies.[/dim]")
                            ]

                            container_panel = Panel(
                                Group(*warning_lines),
                                title="[bold cyan]Container Notice[/bold cyan]",
                                border_style="bright_cyan",
                                padding=(1, 4)
                            )
                            panel_width = min(max(int(pager_console.width * 0.6), 60), 120)
                            pager_console.print(Align.center(container_panel, width=panel_width))
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
                            else:
                                print_rich_summary(pager_console, denial_info, i + 1, detailed=args.detailed, expand_groups=args.expand_groups)

                        # Final summary
                        if args.process or args.path:
                            pager_console.print(
                                f"\n[bold green]Analysis Complete:[/bold green] Processed {
                                    len(log_blocks)} log blocks and found {
                                    len(unique_denials)} unique denials. Displayed {
                                    len(filtered_denials)} after filtering.")
                        else:
                            pager_console.print(
                                f"\n[bold green]Analysis Complete:[/bold green] Processed {
                                    len(log_blocks)} log blocks and found {
                                    len(unique_denials)} unique denials.")

                        # Print unparsed types if any
                        if all_unparsed_types:
                            pager_console.print(
                                "\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:")
                            pager_console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")

                # Generate all output using the pager console
                display_all_content_pager()

                # Get the captured content with colors
                colored_output = string_buffer.getvalue()

                # Set up environment for color support
                env = os.environ.copy()
                env['LESS'] = '-R'  # Enable raw control characters (colors)

                pager_found = False

                # Try less first (most common and supports colors well)
                try:
                    pager_process = subprocess.Popen(
                        ['less', '-R'],
                        stdin=subprocess.PIPE,
                        env=env,
                        text=True
                    )
                    pager_process.communicate(input=colored_output)
                    pager_found = True
                except FileNotFoundError:
                    # Try fallback to more
                    try:
                        pager_process = subprocess.Popen(
                            ['more'],
                            stdin=subprocess.PIPE,
                            text=True
                        )
                        pager_process.communicate(input=colored_output)
                        pager_found = True
                    except FileNotFoundError:
                        pass  # Will handle below

                if not pager_found:
                    # Fallback: just print normally if no pager available
                    console.print(f"[yellow]No pager available, showing output directly:[/yellow]")
                    display_all_content()

            except Exception as e:
                # If pager fails, fall back to normal output
                console.print(f"[yellow]Pager failed ({e}), falling back to normal output:[/yellow]")
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
