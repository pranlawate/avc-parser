#!/usr/bin/env python3
"""
SELinux AVC Analyzer CLI for sos-data-extractor
Provides full parse_avc.py functionality through OOP wrapper with argument mapping

Usage in sos-data-extractor:
    from selinux.selinux_analyzer import selinux_analyze
    selinux_analyze(sos_dir, report="brief", json_output=False)

Or as standalone:
    python3 selinux_analyzer.py <sos_dir> [options]
"""

import argparse
import sys
import os
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selinux.avc_analyzer import AVCAnalyzer


def selinux_analyze(
    sos_dir: str,
    report: Optional[str] = None,
    json_output: bool = False,
    fields: bool = False,
    detailed: bool = False,
    process: Optional[str] = None,
    path: Optional[str] = None,
    sort: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    source: Optional[str] = None,
    target: Optional[str] = None,
    expand_groups: bool = False,
    pager: bool = False,
) -> bool:
    """
    Analyze SELinux AVC denials with full feature support

    Args:
        sos_dir: Path to sos report directory
        report: Report format ('brief' or 'sealert')
        json_output: Output as JSON
        fields: Field-by-field technical breakdown
        detailed: Enhanced detailed view
        process: Filter by process name
        path: Filter by file path (supports wildcards)
        sort: Sort order ('recent', 'count', 'chrono')
        since: Only include denials since this time
        until: Only include denials until this time
        source: Filter by source context pattern
        target: Filter by target context pattern
        expand_groups: Show individual events instead of groupings
        pager: Use pager for output

    Returns:
        bool: True if successful, False otherwise
    """
    analyzer = AVCAnalyzer(sos_dir)

    # Build arguments for parse_avc.py
    args = ["--file", analyzer.audit_log]

    # Output format options
    if json_output:
        args.append("--json")
    elif fields:
        args.append("--fields")
    elif detailed:
        args.append("--detailed")
    elif report:
        args.extend(["--report", report])

    # Filtering options
    if process:
        args.extend(["--process", process])
    if path:
        args.extend(["--path", path])
    if source:
        args.extend(["--source", source])
    if target:
        args.extend(["--target", target])

    # Sorting options
    if sort:
        args.extend(["--sort", sort])

    # Time range filtering
    if since:
        args.extend(["--since", since])
    if until:
        args.extend(["--until", until])

    # Display options
    if expand_groups:
        args.append("--expand-groups")
    if pager:
        args.append("--pager")

    # Execute parse_avc.py with all mapped arguments
    import subprocess
    try:
        result = subprocess.run(
            ["python3", analyzer.parser_path] + args,
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False


def main():
    """
    CLI interface for standalone usage
    Mirrors parse_avc.py arguments for sos-data-extractor integration
    """
    parser = argparse.ArgumentParser(
        description="SELinux AVC Analyzer for sos-data-extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis with default output
  %(prog)s /var/tmp/sosreport-host-123

  # Executive summary report
  %(prog)s /var/tmp/sosreport-host-123 --report brief

  # Technical report with policy investigation commands
  %(prog)s /var/tmp/sosreport-host-123 --report sealert

  # JSON output for automation
  %(prog)s /var/tmp/sosreport-host-123 --json

  # Filter by process
  %(prog)s /var/tmp/sosreport-host-123 --process httpd --report brief

  # Filter by path and sort by count
  %(prog)s /var/tmp/sosreport-host-123 --path '/var/www/*' --sort count

  # Time-based filtering
  %(prog)s /var/tmp/sosreport-host-123 --since yesterday --until today

  # Technical deep-dive
  %(prog)s /var/tmp/sosreport-host-123 --fields --detailed

  # Use pager for large output
  %(prog)s /var/tmp/sosreport-host-123 --report sealert --pager
        """
    )

    parser.add_argument(
        "sos_dir",
        help="Path to extracted sos report directory"
    )

    # Output format options
    output_group = parser.add_argument_group("Output Format Options")
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output parsed data in JSON format"
    )
    output_group.add_argument(
        "--fields",
        action="store_true",
        help="Field-by-field technical breakdown for deep-dive analysis"
    )
    output_group.add_argument(
        "--detailed",
        action="store_true",
        help="Show enhanced detailed view with expanded correlation events"
    )
    output_group.add_argument(
        "--report",
        nargs="?",
        const="brief",
        choices=["brief", "sealert"],
        help="Generate professional report (brief=executive summary, sealert=technical details)"
    )

    # Filtering options
    filter_group = parser.add_argument_group("Filtering Options")
    filter_group.add_argument(
        "--process",
        type=str,
        help="Filter denials by process name (e.g., --process httpd)"
    )
    filter_group.add_argument(
        "--path",
        type=str,
        help="Filter denials by file path (supports wildcards, e.g., --path '/var/www/*')"
    )
    filter_group.add_argument(
        "--source",
        type=str,
        help="Filter by source context pattern (e.g., 'httpd_t', '*unconfined*')"
    )
    filter_group.add_argument(
        "--target",
        type=str,
        help="Filter by target context pattern (e.g., 'default_t', '*var_lib*')"
    )

    # Sorting and time options
    sort_group = parser.add_argument_group("Sorting and Time Options")
    sort_group.add_argument(
        "--sort",
        type=str,
        choices=["recent", "count", "chrono"],
        help="Sort order (recent=most recent first, count=highest count, chrono=chronological)"
    )
    sort_group.add_argument(
        "--since",
        type=str,
        help="Only include denials since this time (e.g., 'yesterday', '2 hours ago')"
    )
    sort_group.add_argument(
        "--until",
        type=str,
        help="Only include denials until this time (e.g., 'today', '2025-01-15')"
    )

    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument(
        "--expand-groups",
        action="store_true",
        help="Show individual events instead of resource-based groupings"
    )
    display_group.add_argument(
        "--pager",
        action="store_true",
        help="Use pager (less/more) for output"
    )

    args = parser.parse_args()

    # Call the analysis function with all mapped arguments
    success = selinux_analyze(
        sos_dir=args.sos_dir,
        report=args.report,
        json_output=args.json,
        fields=args.fields,
        detailed=args.detailed,
        process=args.process,
        path=args.path,
        sort=args.sort,
        since=args.since,
        until=args.until,
        source=args.source,
        target=args.target,
        expand_groups=args.expand_groups,
        pager=args.pager,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
