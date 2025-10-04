"""
Anomaly detection module for SELinux AVC Denial Analyzer.

This module contains functions for detecting behavioral anomalies and
configuration deviations in SELinux audit logs, including permissive mode,
disabled dontaudit rules, container patterns, and non-standard paths.
"""


def has_permissive_denials(denial_info: dict) -> bool:
    """
    Check if a specific denial contains permissive mode events.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        bool: True if denial contains permissive mode events
    """
    # Check aggregated permissive values if available
    if "permissives" in denial_info and denial_info["permissives"]:
        return "1" in denial_info["permissives"]

    # Also check individual permissive field
    parsed_log = denial_info.get("log", {})
    permissive = parsed_log.get("permissive", "0")
    return permissive == "1"


def has_container_paths(denial_info: dict) -> tuple[bool, list[str], list[str]]:
    """
    Check if a specific denial contains container-related paths.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        tuple[bool, list[str], list[str]]: (has_container_paths, container_patterns, sample_paths)
    """
    container_patterns = [
        "/containers/storage/overlay/",  # Podman/Docker overlay storage
        "/.local/share/containers/",  # User container storage
        "/var/lib/containers/",  # System container storage
        "/var/lib/docker/",  # Docker storage
    ]

    found_patterns = set()
    sample_paths = []

    # Check main path in denial
    parsed_log = denial_info.get("log", {})
    main_path = parsed_log.get("path", "")
    if main_path:
        for pattern in container_patterns:
            if pattern in main_path:
                found_patterns.add(pattern.strip("/"))
                if len(sample_paths) < 3:  # Keep sample paths for display
                    sample_paths.append(main_path)

    # Check correlation events for paths
    if "correlations" in denial_info:
        for correlation in denial_info["correlations"]:
            corr_path = correlation.get("path", "")
            if corr_path:
                for pattern in container_patterns:
                    if pattern in corr_path:
                        found_patterns.add(pattern.strip("/"))
                        if len(sample_paths) < 3:
                            sample_paths.append(corr_path)

    # Check aggregated paths if available
    if "paths" in denial_info and denial_info["paths"]:
        for path in denial_info["paths"]:
            for pattern in container_patterns:
                if pattern in path:
                    found_patterns.add(pattern.strip("/"))
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
        "/usr/local",  # Non-standard local installations
        "/opt",  # Optional software packages
        "/home/",  # User home directories (when not user_home_t)
        "/srv",  # Service data directories
        "/data",  # Custom data directories
        "/app",  # Application directories
        "/apps",  # Application directories
        "/software",  # Software installation directories
        "/custom",  # Custom directories
        "/local",  # Local directories outside /usr/local
        "/var/local",  # Non-standard local variable data
    ]

    found_patterns = set()

    # Check main path in denial
    parsed_log = denial_info.get("log", {})
    main_path = parsed_log.get("path", "")
    if main_path:
        for pattern in custom_path_patterns:
            if main_path.startswith(pattern):
                found_patterns.add(pattern)

    # Check correlation events for paths
    if "correlations" in denial_info:
        for correlation in denial_info["correlations"]:
            corr_path = correlation.get("path", "")
            if corr_path:
                for pattern in custom_path_patterns:
                    if corr_path.startswith(pattern):
                        found_patterns.add(pattern)

    # Check aggregated paths if available
    if "paths" in denial_info and denial_info["paths"]:
        for path in denial_info["paths"]:
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
        # Count actual permissive events from correlations for accuracy
        correlations = denial_info.get("correlations", [])
        if correlations:
            for corr in correlations:
                total_count += 1
                if corr.get("permissive") == "1":
                    permissive_count += 1
        else:
            # Fallback to denial count if no correlations
            denial_count = denial_info.get("count", 1)
            total_count += denial_count
            if has_permissive_denials(denial_info):
                permissive_count += denial_count

    return permissive_count > 0, permissive_count, total_count


def has_dontaudit_indicators(denial_info: dict) -> tuple[bool, list[str]]:
    """
    Check if a specific denial contains permissions that indicate dontaudit rules are disabled.

    Args:
        denial_info (dict): Individual denial dictionary

    Returns:
        tuple[bool, list[str]]: (has_indicators, list of found indicators)
    """
    dontaudit_indicators = ["noatsecure", "rlimitinh", "siginh"]
    found_indicators = set()

    # Check aggregated permissions set if available
    if "permissions" in denial_info and denial_info["permissions"]:
        for perm in denial_info["permissions"]:
            if perm.lower().strip() in dontaudit_indicators:
                found_indicators.add(perm.lower().strip())

    # Also check individual permission field
    parsed_log = denial_info.get("log", {})
    permission = parsed_log.get("permission", "").lower().strip()
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
    dontaudit_indicators = ["noatsecure", "rlimitinh", "siginh"]
    found_indicators = set()

    for denial_info in unique_denials:
        # Check aggregated permissions set if available (for denials with multiple permissions)
        if "permissions" in denial_info and denial_info["permissions"]:
            for perm in denial_info["permissions"]:
                if perm.lower().strip() in dontaudit_indicators:
                    found_indicators.add(perm.lower().strip())

        # Also check individual permission field for single-permission denials
        parsed_log = denial_info.get("log", {})
        permission = parsed_log.get("permission", "").lower().strip()
        if permission in dontaudit_indicators:
            found_indicators.add(permission)

    found_indicators_list = sorted(list(found_indicators))
    return len(found_indicators_list) > 0, found_indicators_list