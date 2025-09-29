"""
File detection and handling utilities for SELinux AVC Denial Analyzer.

This module contains functions for detecting file formats and handling
file-related operations.
"""

import re

from config import FILE_ANALYSIS_LINES


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
        with open(file_path, "r", encoding="utf-8") as f:
            # Read first few lines for analysis
            lines = []
            for i, line in enumerate(f):
                if i >= FILE_ANALYSIS_LINES:
                    break
                lines.append(line.strip())

        # Read more content to check for ausearch output markers
        content_sample = "\n".join(lines)

        # Definitive pre-processed indicators (ausearch output)
        has_time_headers = "time->" in content_sample
        has_separators = "----" in content_sample
        has_human_timestamps = bool(
            re.search(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", content_sample)
        )

        # If any ausearch marker is present, it's definitely pre-processed
        if has_time_headers or has_separators or has_human_timestamps:
            return "processed"
        else:
            # No ausearch markers = raw audit.log format
            return "raw"

    except (FileNotFoundError, PermissionError, UnicodeDecodeError):
        # Default to processed format if we can't read the file
        # The file validation will catch and handle the actual error
        return "processed"