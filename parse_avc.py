import argparse
import re
import sys
import subprocess
import json
from datetime import datetime
from rich.console import Console
from rich.rule import Rule

def parse_avc_log(log_block: str) -> (dict, set):
    """
    Parses a multi-line AVC log block,returning both the parsed data
    and a set of any unparsed record types that were found.
    """
    parsed_data = {}
    unparsed_types = set()     # To store unparsed types

#    print(f"\n--- DEBUG: New Log Block Received ---\n'{log_block}'\n--------------------------")
    timestamp_pattern = re.search(r'msg=audit\(([^)]+)\)', log_block)
#     print(f"\n--- DEBUG: The timestamp_pattern is'{timestamp_pattern}'\n")
    if timestamp_pattern:
        timestamp_str = timestamp_pattern.group(1).rsplit(':',1)[0]

        try:
            # Try to parse as a human-readable or unix timestamps ---
            dt_object = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S.%f')
        except ValueError:
            try:
                # Fallback to parsing as a unix timestamp
#                print(f"\nDEBUG: Extracted timestamp to parse as unix timestamp: '{timestamp_str}'")
                dt_object = datetime.fromtimestamp(float(timestamp_str))
            except ValueError:
                dt_object = None # Could not parse timestamp
                print(f"\nDEBUG: Extracted timestamp could not be parsed '{timestamp_str}'")

        if dt_object:
            parsed_data['datetime_obj'] = dt_object
            parsed_data['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            parsed_data['timestamp'] = dt_object.timestamp()

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
        if not match: continue
        log_type = match.group(1)
        # Apply the patterns for the detected log type
        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                field_match = re.search(pattern, line)
                if field_match:
                    value = field_match.group(1)
                    if key == 'proctitle':
                        try: parsed_data[key] = bytes.fromhex(value).decode()
                        except ValueError: parsed_data[key] = value.strip('"')
                    else: parsed_data[key] = value.strip()
        else:
            # --- Track unparsed types ---
            unparsed_types.add(log_type)

#    print(f" [DEBUG] Final parsed data for this block: {parsed_data}") #DEBUG
    return parsed_data,unparsed_types

def human_time_ago(dt_object: datetime) -> str:
    """Converts a datetime timestamp object into a human-readable 'time ago' string."""
    if not dt_object: return "an unknown time"
    now = datetime.now()
    delta = now - dt_object

    if delta.days > 365: return f"{delta.days // 365} year(s) ago"
    elif delta.days > 30: return f"{delta.days // 30} month(s) ago"
    elif delta.days > 7: return f"{delta.days // 7} week(s) ago"
    elif delta.days > 0: return f"{delta.days} day(s) ago"
    elif delta.seconds > 3600: return f"{delta.seconds // 3600} hour(s) ago"
    else: return f"{max(0, delta.seconds // 60)} minute(s) ago"

def print_summary(console: Console, denial_info: dict, denial_num: int):
    """Prints a formatted summary. Skips any fields that were not found. Has a counter of occurances that match signature. Shows human time of last occurence"""
    parsed_log = denial_info['log']
    count = denial_info['count']
    last_seen_dt = denial_info['last_seen_obj']
    last_seen_ago = human_time_ago(last_seen_dt)

    header = f"[bold green]Unique Denial #{denial_num}[/bold green] ({count} occurrences, last seen {last_seen_ago})"
    console.print(Rule(header))

    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return

    # Define the fields and their labels for cleaner printing
    process_fields = [
        ("Timestamp", "datetime_str"),
        ("Process Title", "proctitle"), ("Executable", "exe"),
        ("Process Name", "comm"), ("Process ID (PID)", "pid"),
        ("Working Dir (CWD)", "cwd"), ("Source Context", "scontext")
    ]
    action_fields = [("Syscall", "syscall"), ("Permission", "permission")]
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
    parser = argparse.ArgumentParser(description="A tool to parse an SELinux AVC denial log from a file or user prompt.")
    parser.add_argument("-rf", "--raw-file", type=str, help="Path to a raw audit.log file containing the AVC log string.")
    parser.add_argument("-af", "--avc-file", type=str, help="Path to a pre-processed file containing ausearch output.")
    parser.add_argument("--json", action="store_true", help="Output the parsed data in JSON format.")
    args = parser.parse_args()

    # Create a Rich Console instance
    console = Console()
    log_string = ""

    if args.raw_file:
        console.print(f"Raw file input provided. Running ausearch on '{args.raw_file}'...")
        try:
            ausearch_cmd = ["ausearch", "-m", "AVC", "-i", "-if", args.raw_file]
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
            console.print(f"Error: File not found at '{args.avc_file}'", style="bold red")
#           print(f"Error: File not found at '{args.file}'")
            sys.exit(1)
    else:
        console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] when done:")
#        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        log_string = sys.stdin.read()

#   --- Split, De-duplicate, and Process Logic ---
# Old logic commented as it didn't look inside the block to remove time-> added by ausearch
    log_blocks = [block.strip() for block in log_string.split('----') if block.strip()]

# New logic trying to find and remove 'time->' if present in the log
#    log_blocks_raw = log_string.split('----')

#    log_blocks = []
#    for block in log_blocks_raw:
#        clean_lines = [line for line in block.strip().split('\n') if not line.strip().startswith('time->')]
#        if clean_lines:
#            log_blocks.append("\n".join(clean_lines))
    if not log_blocks:
        if not args.json:
            console.print("Error: No valid log blocks found.", style="bold red")
        sys.exit(1)

    unique_denials = {}
    all_unparsed_types = set()

    for block in log_blocks:
        parsed_log, unparsed = parse_avc_log(block)
        all_unparsed_types.update(unparsed)
        # We only care about blocks that contain an AVC denial
        if "permission" in parsed_log:
            #Create a unique signature for the denial
            signature = (
                parsed_log.get('scontext'), parsed_log.get('tcontext'),
                parsed_log.get('tclass'), parsed_log.get('permission')
            )
            dt_obj = parsed_log.get('datetime_obj')
            if signature in unique_denials:
                unique_denials[signature]['count'] += 1
                unique_denials[signature]['last_seen_obj'] = dt_obj
            else:
                unique_denials[signature] = {'log': parsed_log, 'count': 1, 'first_seen_obj': dt_obj, 'last_seen_obj': dt_obj}
    if args.json:
        # Convert the dictionary of unique denials to a list for JSON output
        output_list = []
        for denial_info in unique_denials.values():
            json_log = denial_info['log'].copy()
            json_log.pop('datetime_obj', None)
            output_list.append(json_log)
        print(json.dumps(output_list, indent=2))

    else:
        # Non JSON default output
        console.print(f"\nFound {len(log_blocks)} AVC events. Displaying {len(unique_denials)} unique denials...")
        sorted_denials = sorted(unique_denials.values(), key=lambda x: x['first_seen_obj'] or datetime.fromtimestamp(0))
        if sorted_denials:
            console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))
        for i, denial_info in enumerate(sorted_denials):
            if i > 0: console.print(Rule(style="dim"))
            print_summary(console, denial_info, i + 1)
        console.print(f"\n[bold green]Analysis Complete:[/bold green] Processed {len(log_blocks)} log blocks and found {len(unique_denials)} unique denials.")

        # --- Added: Print the list of unparsed types found ---
        if all_unparsed_types:
            console.print("\n[yellow]Note:[/yellow] The following record types were found in the log but are not currently parsed:")
            console.print(f"  {', '.join(sorted(list(all_unparsed_types)))}")


if __name__ == "__main__":
    main()
