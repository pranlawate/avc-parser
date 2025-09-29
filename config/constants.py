"""
Configuration constants for the SELinux AVC Denial Analyzer.

This module contains all configuration constants, regex patterns, and
settings used throughout the application.
"""

import re

# File processing configuration
MAX_FILE_SIZE_MB = 100
FILE_ANALYSIS_LINES = 10

# Enhanced audit record regex pattern from setroubleshoot for robust parsing
# Handles: (node=XXX )?(type=XXX )?(msg=)?audit(timestamp:serial): body
# Modified to handle optional whitespace before colon: ") :" or "):"
AUDIT_RECORD_RE = re.compile(
    r"(node=(\S+)\s+)?(type=(\S+)\s+)?(msg=)?audit\(((\d+)\.(\d+):(\d+))\)\s*:\s*(.*)"
)