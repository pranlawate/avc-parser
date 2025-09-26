"""
Utility functions for SELinux AVC Denial Analyzer.

This module contains formatting helpers, time utilities, and other
utility functions with minimal dependencies.
"""

import sys
from datetime import datetime

from rich.console import Console


def print_error(message: str, console: Console = None):
    """
    Print error message to stderr using Rich formatting.

    Args:
        message (str): Error message to print
        console (Console): Optional console instance for additional non-error output
    """
    error_console = Console(stderr=True)
    error_console.print(message)


def signal_handler(_signum, _frame):
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
            formatted_words.append(
                f"[bold {base_color}]{emphasized}[/bold {base_color}][{base_color}]{rest}[/{base_color}]"
            )
        else:
            # Longer words: emphasize first 3 characters
            emphasized = word[:3]
            rest = word[3:]
            formatted_words.append(
                f"[bold {base_color}]{emphasized}[/bold {base_color}][{base_color}]{rest}[/{base_color}]"
            )

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
    if "containers/storage/overlay" in path:
        # Extract meaningful parts: base path + container ID + final path
        parts = path.split("/")

        # Find the overlay directory index
        try:
            overlay_idx = parts.index("overlay")
            if overlay_idx + 1 < len(parts):
                container_id = parts[overlay_idx + 1]
                # Truncate container ID to first 8 characters
                short_id = (
                    container_id[:8] + "..." if len(container_id) > 8 else container_id
                )

                # Get the final meaningful path
                if overlay_idx + 3 < len(parts):
                    # Usually: overlay/ID/diff/actual/path
                    final_path = "/".join(parts[overlay_idx + 3 :])
                    base_path = "/".join(parts[:overlay_idx])
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


def human_time_ago(
    dt_object: datetime,
) -> str:  # pylint: disable=too-many-return-statements
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
