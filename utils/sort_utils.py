"""
Sorting and ordering utilities for SELinux AVC Denial Analyzer.

This module contains functions for sorting denials and other data structures
based on various criteria.
"""

from datetime import datetime


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
        return sorted(
            denials,
            key=lambda x: (
                x.get("last_seen_obj") or datetime.fromtimestamp(0),
                x.get("first_seen_obj") or datetime.fromtimestamp(0),
            ),
            reverse=True,
        )
    elif sort_order == "count":
        # Highest count first, then by most recent as tiebreaker
        return sorted(
            denials,
            key=lambda x: (
                x.get("count", 0),
                x.get("last_seen_obj") or datetime.fromtimestamp(0),
            ),
            reverse=True,
        )
    elif sort_order == "chrono":
        # Chronological order (oldest first) using first_seen
        return sorted(
            denials, key=lambda x: x.get("first_seen_obj") or datetime.fromtimestamp(0)
        )
    else:
        # Default to recent if unknown sort order
        return sorted(
            denials,
            key=lambda x: x.get("last_seen_obj") or datetime.fromtimestamp(0),
            reverse=True,
        )