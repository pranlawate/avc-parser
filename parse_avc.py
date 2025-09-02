import argparse
import re
import sys
import subprocess
from rich.console import Console
from rich.rule import Rule


def parse_avc_log(log_block: str) -> dict:
    """
    Parses a multi-line AVC log block containing various record types.
    """
    parsed_data = {}
    unparsed_types = set()     # To store unparsed types
    patterns = {
            "AVC": {"permission": r"denied\s+\{ ([^}]+) \}", "pid": r"pid=(\S+)", "comm": r"comm=\"([^\"]+)\"", "path": r"path=\"([^\"]+)\"","scontext": r"scontext=(\S+)", "tcontext": r"tcontext=(\S+)", "tclass": r"tclass=(\S+)", "dest_port": r"dest=(\S+)",},
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
        else:
            # --- Track unparsed types ---
            unparsed_types.add(log_type)

#    print(f" [DEBUG] Final parsed data for this block: {parsed_data}") #DEBUG
    return parsed_data,unparsed_types

def print_summary(console: Console, parsed_log: dict):
    """Prints a formatted summary, skipping any fields that were not found."""
    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return

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
        "-rf", "--raw-file", 
        type=str, 
        help="Path to a raw audit.log file containing the AVC log string."
    )

    parser.add_argument(
        "-af", "--avc-file",
        type=str,
        help="Path to a pre-procesed file containing ausearch output."
    )
    
    args = parser.parse_args()

    # Create a Rich Console instance
    console = Console()

    log_string = ""

    if args.raw_file:
        console.print(f"Raw file input provided. Running ausearch on '{args.raw_file}'...")
        try:
            ausearch_cmd = ["ausearch", "-m", "AVC", "-if", args.raw_file]
            result = subprocess.run(ausearch_cmd, capture_output=True, text=True, check=True)
            log_string = result.stdout
        except FileNotFoundError:
            console.print("Error: The 'ausearch' command was not found. Is audit installed?", style="bold red")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            console.print(f"Error running ausearch: {e.stderr}", style="bold red")
            sys.exit(1)
    elif args.avc_file:
        console.print(f"Pre-processed AVC file provided: '{args.avc_file}'")
        try:
            with open(args.avc_file, 'r') as f:
                log_string = f.read()
        except FileNotFoundError:
            console.print("Error: File not found at '{args.file}'", style="bold red")
#           print(f"Error: File not found at '{args.file}'")
            sys.exit(1)
    else:
        console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] (or Ctrl+Z on Windows) when done:")
#        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        log_string = sys.stdin.read()

#   --- NEW LOGIC: Split, De-duplicate, and Process ---
    log_blocks = [block.strip() for block in log_string.split('----') if block.strip()]

    if not log_blocks:
        console.print("Error: No valid log blocks found.", style="bold red")
        sys.exit(1)

    unique_denials = set()
    unique_logs= []
    all_unparsed_types = set()

    for block in log_blocks:
        parsed_log, unparsed = parse_avc_log(block)
        all_unparsed_types.update(unparsed)
        # We only care about blocks that contain an AVC denial
        if "permission" in parsed_log:
            #Create a unique signature for the denial
            signature = (
                    parsed_log.get('scontext'),
                    parsed_log.get('tcontext'),
                    parsed_log.get('tclass'),
                    parsed_log.get('permission')
                    )
            if signature not in unique_denials:
                unique_denials.add(signature)
                unique_logs.append(parsed_log)
            else:
                console.print(Rule("[yellow]Skipping duplicate[/yellow]"))

    console.print(f"\nFound {len(log_blocks)} log blocks(s). Displaying unique denials...")

    # Now, print the summaries for only the unique_logs:
    if unique_logs:
        console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))

    for i, parsed_log in enumerate(unique_logs):
        console.print(Rule(f"[bold green]Unique Denial #{i+1}[/bold green]"))
        print_summary(console, parsed_log)

    console.print(f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_logs)} unique denials.")

    # --- Added: Print the list of unparsed types found ---
    if all_unparsed_types:
        console.print("\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:")
        console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")


if __name__ == "__main__":
    main()
