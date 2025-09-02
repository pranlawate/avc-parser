import argparse
import re
import sys
from rich.console import Console
from rich.rule import Rule


def parse_audit_log(log_block: str) -> dict:
    """
    Parses a multi-line audit log block containing various record types.
    """
    parsed_data = {}
    patterns = {
        "AVC": {"permission": r"denied\s+\{ ([^}]+) \}", "pid": r"pid=(\S+)", "comm": r"comm=\"([^\"]+)\"", "scontext": r"scontext=(\S+)", "tcontext": r"tcontext=(\S+)", "tclass": r"tclass=(\S+)", "dest_port": r"dest=(\S+)",},
        "CWD": {"cwd": r"cwd=\"([^\"]+)\"",},
        "PATH": {"path": r"name=\"([^\"]+)\"",},
        "SYSCALL": {"syscall": r"syscall=([\w\d]+)", "exe": r"exe=\"([^\"]+)\"",},
        "PROCTITLE": {"proctitle": r"proctitle=(\S+)",},
        "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}",}
    }
    
    # Split the log block into individual lines
    for line in log_block.strip().split('\n'):
        line = line.strip()
        match = re.search(r"type=(\w+)", line)
        if not match:
            continue
        log_type = match.group(1)
        # Apply the patterns for the detected log type
        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                # Avoid overwriting already found data (e.g., path from AVC)
                if key not in parsed_data:
                    field_match = re.search(pattern, line)
                    if field_match:
                        value = field_match.group(1)
                        if key == 'proctitle':
                            try:
                                parsed_data[key] = bytes.fromhex(value).decode()
                            except ValueError:
                                parsed_data[key] = value.strip('"')
                        else:
                            parsed_data[key] = value.strip()
    return parsed_data

def print_summary(console: Console, parsed_log: dict):
    """Prints a formatted summary, skipping any fields that were not found."""
    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return
    console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))

    # Define the fields and their labels for cleaner printing
    process_fields = [
        ("Process Title", "proctitle"), ("Executable", "exe"),
        ("Process Name", "comm"), ("Process ID (PID)", "pid"),
        ("Working Dir (CWD)", "cwd"), ("Source Context", "scontext")
    ]
    action_fields = [
        ("Syscall", "syscall"), ("Permission", "permission")
    ]
    target_fields = [
        ("Target Path", "path"), ("Target Port", "dest_port"),
        ("Socket Address", "saddr"), ("Target Class", "tclass"),
        ("Target Context", "tcontext")
    ]

    # --- Process Information ---
    for label, key in process_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)
    # --- Action Details ---
    console.print(f"  [bold]Action:[/bold]".ljust(22) + "Denied")
    for label, key in action_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)
    # --- Target Information ---
    for label, key in target_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)

def main():
    """
    Main function to handle command-line arguments and print the parsed output.
    """
    parser = argparse.ArgumentParser(
        description="A tool to parse an SELinux AVC denial log from a file or user prompt."
    )
    parser.add_argument(
        "-f", "--file", 
        type=str, 
        help="Path to a file containing the raw AVC log string."
    )
    
    args = parser.parse_args()

    # Create a Rich Console instance
    console = Console()


    log_string = ""
    if args.file:
        try:
            with open(args.file, 'r') as f:
                log_string = f.read()
        except FileNotFoundError:
            console.print("Error: File not found at '{args.file}'", style="bold red")
#           print(f"Error: File not found at '{args.file}'")
            sys.exit(1)
    else:
        console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] (or Ctrl+Z on Windows) when done:")
#        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        log_string = sys.stdin.read()

        if not log_string:
            console.print("Error: No log provided. Exiting.", style="bold red")
            sys.exit(1)

    parsed_log = parse_audit_log(log_string)
    print_summary(console, parsed_log)


if __name__ == "__main__":
    main()
