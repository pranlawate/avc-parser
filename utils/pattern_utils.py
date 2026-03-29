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

    Supports comma-separated patterns for OR matching:
    'init_t,kmod_t,mount_t' matches if ANY value matches.

    Args:
        context (str): The SELinux context to check (e.g., 'system_u:system_r:httpd_t:s0')
        pattern (str): The pattern to match against (supports * wildcards and comma-separated OR)

    Returns:
        bool: True if context matches pattern

    Examples:
        >>> context_matches('system_u:system_r:httpd_t:s0', 'httpd_t')
        True
        >>> context_matches('system_u:system_r:httpd_t:s0', '*httpd*')
        True
        >>> context_matches('system_u:system_r:init_t:s0', 'init_t,kmod_t,mount_t')
        True
    """
    if not context or not pattern:
        return False

    if "," in pattern:
        return any(_single_context_matches(context, p.strip()) for p in pattern.split(","))
    return _single_context_matches(context, pattern)


def _single_context_matches(context: str, pattern: str) -> bool:
    """Match a single pattern against a context."""
    if not pattern:
        return False

    context_lower = context.strip().lower()
    pattern_lower = pattern.strip().lower()

    if pattern_lower in context_lower:
        return True

    if fnmatch.fnmatch(context_lower, pattern_lower):
        return True

    if ":" not in pattern:
        for part in context_lower.split(":"):
            if fnmatch.fnmatch(part, pattern_lower):
                return True

    return False