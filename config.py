"""
Configuration module for AVC parser.
Contains parsing patterns, field definitions, and other configuration constants.
"""

from typing import Dict, List, Tuple

# Parsing patterns for different log record types
PARSING_PATTERNS: Dict[str, Dict[str, str]] = {
    "AVC": {
        "permission": r"denied\s+\{ ([^}]+) \}",
        "pid": r"pid=(\S+)",
        "comm": r"comm=\"([^\"]+)\"",
        "path": r"path=\"([^\"]+)\"",
        "scontext": r"scontext=(\S+)",
        "tcontext": r"tcontext=(\S+)",
        "tclass": r"tclass=(\S+)",
        "dest_port": r"dest=(\S+)",
    },
    "CWD": {
        "cwd": r"cwd=\"([^\"]+)\"",
    },
    "PATH": {
        "path": r"name=\"([^\"]+)\"",
    },
    "SYSCALL": {
        "syscall": r"syscall=([\w\d]+)",
        "exe": r"exe=\"([^\"]+)\"",
    },
    "PROCTITLE": {
        "proctitle": r"proctitle=(\S+)",
    },
    "SOCKADDR": {
        "saddr": r"saddr=\{([^\}]+)\}",
    }
}

# Field display configuration for console output
PROCESS_FIELDS: List[Tuple[str, str]] = [
    ("Timestamp", "datetime_str"),
    ("Process Title", "proctitle"),
    ("Executable", "exe"),
    ("Process Name", "comm"),
    ("Process ID (PID)", "pid"),
    ("Working Dir (CWD)", "cwd"),
    ("Source Context", "scontext")
]

ACTION_FIELDS: List[Tuple[str, str]] = [
    ("Syscall", "syscall"),
    ("Permission", "permission")
]

TARGET_FIELDS: List[Tuple[str, str]] = [
    ("Target Path", "path"),
    ("Target Port", "dest_port"),
    ("Socket Address", "saddr"),
    ("Target Class", "tclass"),
    ("Target Context", "tcontext")
]

# Timestamp parsing configuration
TIMESTAMP_FORMATS: List[str] = [
    '%m/%d/%Y %H:%M:%S.%f',  # Human-readable format
]

# Log block separator
LOG_BLOCK_SEPARATOR: str = '----'

# Special field processing rules
SPECIAL_FIELD_PROCESSORS: Dict[str, str] = {
    'proctitle': 'hex_decode',  # Process title needs hex decoding
}

# JSON output configuration
JSON_OUTPUT_CONFIG = {
    'indent': 2,
    'ensure_ascii': False,
}

# String cleaning patterns for JSON output
STRING_CLEAN_PATTERNS: Dict[str, str] = {
    '\x00': '',  # Remove null bytes
    '\r': '',    # Remove carriage returns
    '\n': '\\n', # Escape newlines
}
