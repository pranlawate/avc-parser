"""
File and argument validation functions for the SELinux AVC Denial Analyzer.

This module contains all validation logic for command-line arguments and
input files, providing comprehensive error handling and user guidance.
"""

import io
import os
import re
import select
import sys

from rich.console import Console

from config import MAX_FILE_SIZE_MB
from utils import print_error, detect_file_format


def validate_arguments(args, console: Console) -> str:
    """
    Comprehensive argument validation with detailed error messages.

    Args:
        args: Parsed command-line arguments
        console: Rich console for formatted error output

    Returns:
        str: Validation result - 'raw_file', 'avc_file', or 'interactive'

    Raises:
        SystemExit: On validation failures with descriptive error messages
    """
    # Check for conflicting arguments
    file_args = [args.file, args.raw_file, args.avc_file]
    file_args_count = sum(1 for arg in file_args if arg is not None)

    if file_args_count > 1:
        # Use stderr for error messages so tests can capture them
        error_console = Console(stderr=True)
        error_console.print("❌ [bold red]Error: Conflicting File Arguments[/bold red]")
        error_console.print("   Cannot specify multiple file arguments simultaneously.")

        # Show which arguments were provided
        provided_args = []
        if args.file:
            provided_args.append(f"--file {args.file}")
        if args.raw_file:
            provided_args.append(f"--raw-file {args.raw_file}")
        if args.avc_file:
            provided_args.append(f"--avc-file {args.avc_file}")

        error_console.print(f"   [dim]You provided: {', '.join(provided_args)}[/dim]")
        error_console.print("   [dim]Choose one input method:[/dim]")
        error_console.print(
            "   • [cyan]--file <path>[/cyan] for auto-detection (recommended)"
        )
        error_console.print(
            "   • [cyan]--raw-file <path>[/cyan] for raw audit.log files"
        )
        error_console.print(
            "   • [cyan]--avc-file <path>[/cyan] for pre-processed ausearch output"
        )
        error_console.print(
            "   [dim]Example:[/dim] [cyan]python3 parse_avc.py --file /var/log/audit/audit.log[/cyan]"
        )
        sys.exit(1)

    # JSON flag works with both file input and stdin input, so no validation needed

    # Handle new --file argument with auto-detection
    if args.file:
        return validate_file_with_auto_detection(
            args.file, console, quiet=args.json or args.pager
        )

    # Validate raw file if provided
    elif args.raw_file:
        return validate_raw_file(args.raw_file, console)

    # Validate AVC file if provided
    elif args.avc_file:
        return validate_avc_file(args.avc_file, console)

    # Stdin mode (could be interactive or piped)
    else:
        # Check if stdin has data available (piped) vs waiting for interactive input
        try:
            # Try to check if stdin has data available without blocking
            if select.select([sys.stdin], [], [], 0.0)[0]:
                # Data is available on stdin (piped input) - JSON is allowed
                return "interactive"
            else:
                # No data on stdin - truly interactive mode
                if args.json:
                    console.print(
                        "❌ [bold red]Error: Interactive mode not supported with --json[/bold red]"
                    )
                    console.print("   JSON output requires file input for processing.")
                    console.print("   [dim]Tip: Use --file for JSON output or pipe data without --json flag[/dim]")
                    sys.exit(1)
                return "interactive"
        except (OSError, io.UnsupportedOperation):
            # stdin is redirected (test environment) or not available
            # In test environments, treat as interactive mode for safety
            if args.json:
                console.print(
                    "❌ [bold red]Error: Interactive mode not supported with --json[/bold red]"
                )
                console.print("   JSON output requires file input for processing.")
                console.print("   [dim]Tip: Use --file for JSON output or pipe data without --json flag[/dim]")
                sys.exit(1)
            return "interactive"


def validate_file_with_auto_detection(
    file_path: str, console: Console, quiet: bool = False
) -> str:
    """
    Validate file and auto-detect format type (raw vs pre-processed).

    Args:
        file_path (str): Path to the audit file
        console (Console): Rich console for formatted output

    Returns:
        str: 'raw_file' for raw audit.log format, 'avc_file' for pre-processed format

    Raises:
        SystemExit: On file validation errors
    """
    # First, perform basic file validation with enhanced error messages
    try:
        if not os.path.exists(file_path):
            console.print("❌ [bold red]Error: File Not Found[/bold red]")
            console.print(f"   File does not exist: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Please verify the file path and try again.[/dim]")
            console.print("   [dim]Common audit file locations:[/dim]")
            console.print("   • [cyan]/var/log/audit/audit.log[/cyan] (raw audit log)")
            console.print("   • [cyan]./avc_denials.log[/cyan] (processed output)")
            sys.exit(1)

        # Check if path is a directory
        if os.path.isdir(file_path):
            console.print("❌ [bold red]Error: Directory Provided[/bold red]")
            console.print(
                f"   Path is a directory, not a file: [cyan]{file_path}[/cyan]"
            )
            console.print("   [dim]Please specify a specific audit file:[/dim]")
            console.print(f"   • [cyan]{file_path}/audit.log[/cyan] (if it exists)")
            console.print(f"   • [cyan]{file_path}/*.log[/cyan] (list available files)")
            sys.exit(1)

        if not os.access(file_path, os.R_OK):
            console.print("❌ [bold red]Error: Permission Denied[/bold red]")
            console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Try one of these solutions:[/dim]")
            console.print(
                "   • [cyan]sudo python3 parse_avc.py --file <path>[/cyan] (run with privileges)"
            )
            console.print(
                "   • [cyan]sudo cp <path> ~/audit.log && python3 parse_avc.py --file ~/audit.log[/cyan] (copy to accessible location)"
            )
            sys.exit(1)

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            console.print("❌ [bold red]Error: Empty File[/bold red]")
            console.print(f"   File is empty: [cyan]{file_path}[/cyan]")
            console.print("   [dim]Possible solutions:[/dim]")
            console.print(
                "   • Check if audit logging is enabled: [cyan]sudo systemctl status auditd[/cyan]"
            )
            console.print(
                "   • Check for recent audit activity: [cyan]sudo tail /var/log/audit/audit.log[/cyan]"
            )
            console.print("   • Generate test AVC events if in test environment")
            sys.exit(1)

        if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            console.print("⚠️  [bold yellow]Warning: Large File Detected[/bold yellow]")
            console.print(f"   File size: {file_size / (1024 * 1024):.1f}MB")
            console.print("   [dim]Processing may take some time...[/dim]")

        # Auto-detect format type
        detected_format = detect_file_format(file_path)

        if not quiet:
            if detected_format == "raw":
                # Detection message handled by caller
                pass
            else:
                # Detection message handled by caller
                pass

        return "raw_file" if detected_format == "raw" else "avc_file"

    except IsADirectoryError:
        console.print("❌ [bold red]Error: Directory Provided[/bold red]")
        console.print(f"   Path is a directory, not a file: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please specify a specific audit file:[/dim]")
        console.print(f"   • [cyan]{file_path}/audit.log[/cyan] (if it exists)")
        console.print(f"   • [cyan]ls {file_path}/*.log[/cyan] (list available files)")
        sys.exit(1)
    except UnicodeDecodeError:
        console.print("❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Audit files should be text files. Try:[/dim]")
        console.print("   • [cyan]file <path>[/cyan] (check file type)")
        console.print("   • [cyan]head -5 <path>[/cyan] (preview file content)")
        sys.exit(1)
    except PermissionError:
        console.print("❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Try one of these solutions:[/dim]")
        console.print(
            "   • [cyan]sudo python3 parse_avc.py --file <path>[/cyan] (run with privileges)"
        )
        console.print(
            "   • [cyan]sudo cp <path> ~/audit.log && python3 parse_avc.py --file ~/audit.log[/cyan] (copy to accessible location)"
        )
        sys.exit(1)


def validate_raw_file(file_path: str, console: Console) -> str:
    """
    Validates raw audit.log file with comprehensive checks.

    Args:
        file_path: Path to the raw audit file
        console: Rich console for error output

    Returns:
        str: 'raw_file' if validation passes

    Raises:
        SystemExit: On validation failures
    """
    # Check if path exists
    if not os.path.exists(file_path):
        console.print("❌ [bold red]Error: File Not Found[/bold red]")
        console.print(f"   Raw file does not exist: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please check the file path and try again.[/dim]")
        sys.exit(1)

    # Check if it's actually a file
    if os.path.isdir(file_path):
        console.print("❌ [bold red]Error: Directory Provided[/bold red]")
        console.print(f"   Expected a file but got directory: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please specify the audit.log file path, not the directory.[/dim]"
        )
        sys.exit(1)

    # Check file permissions
    if not os.access(file_path, os.R_OK):
        console.print("❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]"
        )
        sys.exit(1)

    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        console.print("❌ [bold red]Error: Empty File[/bold red]")
        console.print(f"   Raw audit file is empty: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Possible solutions:[/dim]")
        console.print(
            "   • Check if audit logging is enabled: [cyan]sudo systemctl status auditd[/cyan]"
        )
        console.print(
            "   • Check for recent audit activity: [cyan]sudo tail /var/log/audit/audit.log[/cyan]"
        )
        console.print("   • Generate test AVC events if in test environment")
        sys.exit(1)

    # Check for binary file (basic heuristic)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.read(1024)  # Try to read first 1KB as text
    except UnicodeDecodeError:
        console.print("❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Raw audit files should be text files. Please check the file format.[/dim]"
        )
        sys.exit(1)
    except PermissionError:
        print_error("❌ [bold red]Error: Permission Denied[/bold red]")
        print_error(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        print_error(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]"
        )
        sys.exit(1)

    return "raw_file"


def validate_avc_file(file_path: str, console: Console) -> str:
    """
    Validates pre-processed AVC file with comprehensive checks.

    Args:
        file_path: Path to the AVC file
        console: Rich console for error output

    Returns:
        str: 'avc_file' if validation passes

    Raises:
        SystemExit: On validation failures
    """
    # Check if path exists
    if not os.path.exists(file_path):
        console.print("❌ [bold red]Error: File Not Found[/bold red]")
        console.print(f"   AVC file does not exist: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Please check the file path and try again.[/dim]")
        sys.exit(1)

    # Check if it's actually a file
    if os.path.isdir(file_path):
        console.print("❌ [bold red]Error: Directory Provided[/bold red]")
        console.print(f"   Expected a file but got directory: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please specify the AVC log file path, not the directory.[/dim]"
        )
        sys.exit(1)

    # Check file permissions
    if not os.access(file_path, os.R_OK):
        console.print("❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]"
        )
        sys.exit(1)

    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        console.print("❌ [bold red]Error: Empty File[/bold red]")
        console.print(f"   Pre-processed AVC file is empty: [cyan]{file_path}[/cyan]")
        console.print("   [dim]Possible solutions:[/dim]")
        console.print(
            "   • Check if ausearch produced output: [cyan]ausearch -m AVC | head -5[/cyan]"
        )
        console.print(
            "   • Verify AVC events exist: [cyan]sudo grep 'avc:' /var/log/audit/audit.log | head -1[/cyan]"
        )
        console.print("   • Generate test AVC events if in test environment")
        sys.exit(1)

    # Try to read and validate file content
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read(1024)  # Read first 1KB for validation

        # Basic content validation - should contain audit-like content
        if not re.search(r"(type=AVC|msg=audit|avc:)", content, re.IGNORECASE):
            console.print("⚠️  [bold yellow]Warning: File Content Check[/bold yellow]")
            console.print(
                f"   File does not appear to contain AVC records: [cyan]{file_path}[/cyan]"
            )
            console.print(
                "   [dim]Proceeding anyway - file may contain valid data in different format.[/dim]"
            )

    except UnicodeDecodeError:
        console.print("❌ [bold red]Error: Binary File Detected[/bold red]")
        console.print(f"   File appears to be binary: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]AVC files should be text files from ausearch output.[/dim]"
        )
        sys.exit(1)
    except PermissionError:
        console.print("❌ [bold red]Error: Permission Denied[/bold red]")
        console.print(f"   Cannot read file: [cyan]{file_path}[/cyan]")
        console.print(
            "   [dim]Please check file permissions or run with appropriate privileges.[/dim]"
        )
        sys.exit(1)

    return "avc_file"