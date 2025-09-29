"""
Utils package for SELinux AVC Denial Analyzer.

This package contains utility modules organized by functionality:
- file_utils: File detection and handling utilities
- time_utils: Time parsing and formatting utilities
- pattern_utils: Pattern matching and filtering utilities
- sort_utils: Sorting and ordering utilities
"""

# Import from legacy utils (to be gradually migrated)
from .legacy import (
    format_bionic_text,
    format_path_for_display,
    human_time_ago,
    print_error,
    signal_handler,
)

# Import from new modular utils
from .file_utils import detect_file_format
from .time_utils import parse_time_range
from .pattern_utils import path_matches, context_matches
from .sort_utils import sort_denials
from .selinux_utils import generate_sesearch_command

__all__ = [
    # Legacy utils (from utils.py)
    'format_bionic_text',
    'format_path_for_display',
    'human_time_ago',
    'print_error',
    'signal_handler',
    # New modular utils
    'detect_file_format',
    'parse_time_range',
    'path_matches',
    'context_matches',
    'sort_denials',
    'generate_sesearch_command',
]