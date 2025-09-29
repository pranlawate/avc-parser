"""
Pattern matching and filtering utilities for SELinux AVC Denial Analyzer.

This module contains functions for matching paths, contexts, and other
pattern-based operations.
"""

import fnmatch


def path_matches(path: str, pattern: str) -> bool:
    """
    Check if a path matches a pattern with basic wildcard support.

    Args:
        path (str): The file path to check
        pattern (str): The pattern (supports * wildcards)

    Returns:
        bool: True if path matches pattern
    """
    return fnmatch.fnmatch(path, pattern)


def context_matches(context: str, pattern: str) -> bool:
    """
    Check if a SELinux context matches a pattern with wildcard support.

    Args:
        context (str): The SELinux context to check (e.g., 'system_u:system_r:httpd_t:s0')
        pattern (str): The pattern to match against (supports * wildcards)
                      Can match full context or individual components

    Returns:
        bool: True if context matches pattern

    Examples:
        >>> context_matches('system_u:system_r:httpd_t:s0', 'httpd_t')
        True
        >>> context_matches('system_u:system_r:httpd_t:s0', '*httpd*')
        True
        >>> context_matches('unconfined_u:object_r:default_t:s0', '*default*')
        True
    """
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
    if ":" not in pattern:
        context_parts = context_lower.split(":")
        for part in context_parts:
            if fnmatch.fnmatch(part, pattern_lower):
                return True

    return False