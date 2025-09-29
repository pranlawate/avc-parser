"""
Time parsing and formatting utilities for SELinux AVC Denial Analyzer.

This module contains functions for parsing time specifications and
handling temporal operations.
"""

import re
from datetime import datetime, timedelta


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
    if time_spec_lower == "now":
        return now
    elif time_spec_lower == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_spec_lower == "yesterday":
        yesterday = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
            days=1
        )
        return yesterday
    elif time_spec_lower == "recent":
        # Recent means last hour
        return now - timedelta(hours=1)

    # Handle "X ago" patterns
    ago_match = re.match(
        r"(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago", time_spec_lower
    )
    if ago_match:
        amount = int(ago_match.group(1))
        unit = ago_match.group(2)

        if unit == "second":
            return now - timedelta(seconds=amount)
        elif unit == "minute":
            return now - timedelta(minutes=amount)
        elif unit == "hour":
            return now - timedelta(hours=amount)
        elif unit == "day":
            return now - timedelta(days=amount)
        elif unit == "week":
            return now - timedelta(weeks=amount)
        elif unit == "month":
            # Approximate month as 30 days
            return now - timedelta(days=amount * 30)
        elif unit == "year":
            # Approximate year as 365 days
            return now - timedelta(days=amount * 365)

    # Try parsing explicit date/time formats
    time_formats = [
        "%Y-%m-%d %H:%M:%S",  # 2025-01-15 14:30:45
        "%Y-%m-%d %H:%M",  # 2025-01-15 14:30
        "%Y-%m-%d",  # 2025-01-15 (assumes 00:00:00)
        "%m/%d/%Y %H:%M:%S",  # 01/15/2025 14:30:45
        "%m/%d/%Y %H:%M",  # 01/15/2025 14:30
        "%m/%d/%Y",  # 01/15/2025 (assumes 00:00:00)
        "%d/%m/%Y %H:%M:%S",  # 15/01/2025 14:30:45 (European format)
        "%d/%m/%Y %H:%M",  # 15/01/2025 14:30
        "%d/%m/%Y",  # 15/01/2025 (assumes 00:00:00)
    ]

    for fmt in time_formats:
        try:
            return datetime.strptime(time_spec, fmt)
        except ValueError:
            continue

    # If no format matches, raise an error
    raise ValueError(f"Unable to parse time specification: {time_spec}")