import argparse
import re
import sys
import subprocess
import json
from datetime import datetime
from rich.console import Console
from rich.rule import Rule

def parse_avc_log(log_block: str) -> (list, set):
    """
    Parses a multi-line AVC log block, returning a list of parsed AVC denials
    and a set of any unparsed record types that were found.
    """
    avc_denials = []  # Changed from single dict to list
    unparsed_types = set()
    
    # Extract shared context (timestamp, process info, etc.)
    shared_context = {}

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
            shared_context['datetime_obj'] = dt_object
            shared_context['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            shared_context['timestamp'] = dt_object.timestamp()

    # Extract other shared context (CWD, PATH, SYSCALL, PROCTITLE, SOCKADDR)
    patterns = {
        "CWD": {"cwd": r"cwd=\"([^\"]+)\"",},
        "PATH": {"path": r"name=\"([^\"]+)\"",},
        "SYSCALL": {"syscall": r"syscall=([\w\d]+)", "exe": r"exe=\"([^\"]+)\"",},
        "PROCTITLE": {"proctitle": r"proctitle=(\S+)",},
        "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}",}
    }
    
    # Process non-AVC lines for shared context
    for line in log_block.strip().split('\n'):
        line = line.strip()
        match = re.search(r"type=(\w+)", line)
        if not match: continue
        log_type = match.group(1)
        
        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                field_match = re.search(pattern, line)
                if field_match:
                    value = field_match.group(1)
                    if key == 'proctitle':
                        try: 
                            shared_context[key] = bytes.fromhex(value).decode()
                        except ValueError: 
                            shared_context[key] = value.strip('"')
                    else: 
                        shared_context[key] = value.strip()
        elif log_type != "AVC":  # Track unparsed types (excluding AVC)
            unparsed_types.add(log_type)

    # Now process each AVC line separately
    for line in log_block.strip().split('\n'):
        line = line.strip()
        if 'type=AVC' in line:
            # Parse this specific AVC line
            avc_data = shared_context.copy()  # Start with shared context
            
            # Extract AVC-specific fields
            avc_patterns = {
                "permission": r"denied\s+\{ ([^}]+) \}",
                "pid": r"pid=(\S+)", 
                "comm": r"comm=\"([^\"]+)\"", 
                "path": r"path=\"([^\"]+)\"",
                "scontext": r"scontext=(\S+)", 
                "tcontext": r"tcontext=(\S+)", 
                "tclass": r"tclass=(\S+)", 
                "dest_port": r"dest=(\S+)",
            }
            
            for key, pattern in avc_patterns.items():
                field_match = re.search(pattern, line)
                if field_match:
                    avc_data[key] = field_match.group(1).strip()
            
            if "permission" in avc_data:  # Only add if it's a valid AVC
                avc_denials.append(avc_data)
                print(f" [DEBUG] Parsed AVC: {avc_data}")  # DEBUG

    print(f" [DEBUG] Found {len(avc_denials)} AVC denials in this block")  # DEBUG
    return avc_denials, unparsed_types

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
    action_fields = [("Syscall", "syscall")]
    
    # Handle permissions - either single permission or comma-separated list
    if 'permissions' in denial_info and denial_info['permissions']:
        permissions_str = ", ".join(sorted(denial_info['permissions']))
        action_fields.append(("Permission", permissions_str))
    elif parsed_log.get("permission"):
        action_fields.append(("Permission", parsed_log["permission"]))
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
        if key in parsed_log or (label == "Permission" and 'permissions' in denial_info):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{key}")

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
        if not args.json:
            console.print(f"Raw file input provided. Running ausearch on '{args.raw_file}'...")
        try:
            ausearch_cmd = ["ausearch", "-m", "AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR", "-i", "-if", args.raw_file]
            result = subprocess.run(ausearch_cmd, capture_output=True, text=True, check=True)
            log_string = result.stdout
        except FileNotFoundError:
            console.print("Error: The 'ausearch' command was not found. Is audit installed?", style="bold red")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            console.print(f"Error running ausearch: {e.stderr}", style="bold red")
            sys.exit(1)
    elif args.avc_file:
        if not args.json:
            console.print(f"Pre-processed AVC file provided: '{args.avc_file}'")
        try:
            with open(args.avc_file, 'r') as f:
                log_string = f.read()
        except FileNotFoundError:
            console.print(f"Error: File not found at '{args.avc_file}'", style="bold red")
#           print(f"Error: File not found at '{args.file}'")
            sys.exit(1)
    else:
        if not args.json:
            console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] when done:")
#        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        try:
            log_string = sys.stdin.read()
        except KeyboardInterrupt:
            console.print(f"[red] Key Board Interrupted [/red]")
            sys.exit(0)

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

    for block_idx, block in enumerate(log_blocks):
        avc_denials, unparsed = parse_avc_log(block)  # Now returns list
        all_unparsed_types.update(unparsed)
        
        # Process each AVC denial separately
        for parsed_log in avc_denials:
            if "permission" in parsed_log:
                #Create a unique signature for the denial (include block index)
                signature = (
                    parsed_log.get('scontext'), parsed_log.get('tcontext'),
                    parsed_log.get('tclass'), block_idx
                )
                permission = parsed_log.get('permission')
                dt_obj = parsed_log.get('datetime_obj')
                
                if signature in unique_denials:
                    # Add permission to the set if not already present
                    if 'permissions' not in unique_denials[signature]:
                        unique_denials[signature]['permissions'] = set()
                    unique_denials[signature]['permissions'].add(permission)
                    unique_denials[signature]['count'] += 1
                    unique_denials[signature]['last_seen_obj'] = dt_obj
                else:
                    unique_denials[signature] = {
                        'log': parsed_log, 
                        'count': 1, 
                        'first_seen_obj': dt_obj, 
                        'last_seen_obj': dt_obj,
                        'permissions': {permission}
                    }
    if args.json:
        # Convert the dictionary of unique denials to a list for JSON output
        output_list = []
        for denial_info in unique_denials.values():
            # Create a JSON-safe copy of the denial info
            json_denial = {
                'log': denial_info['log'].copy(),
                'count': denial_info['count'],
                'first_seen': denial_info['first_seen_obj'].isoformat() if denial_info['first_seen_obj'] else None,
                'last_seen': denial_info['last_seen_obj'].isoformat() if denial_info['last_seen_obj'] else None
            }
            
            # Add permissions set if it exists
            if 'permissions' in denial_info:
                json_denial['permissions'] = sorted(list(denial_info['permissions']))
            
            # Remove datetime_obj from the log data and convert any remaining datetime objects to strings
            json_denial['log'].pop('datetime_obj', None)
            for key, value in json_denial['log'].items():
                if isinstance(value, datetime):
                    json_denial['log'][key] = value.isoformat()
                elif key == 'timestamp' and isinstance(value, (int, float)):
                    # Convert timestamp to string to ensure it's quoted in JSON
                    json_denial['log'][key] = str(value)
                elif isinstance(value, str):
                    # Clean up any problematic characters in string values
                    json_denial['log'][key] = value.replace('\x00', '').replace('\r', '').replace('\n', '\\n')
            
            output_list.append(json_denial)
        
        try:
            json_output = json.dumps(output_list, indent=2, ensure_ascii=False)
            print(json_output)
        except (TypeError, ValueError) as e:
            console.print(f"Error generating JSON: {e}", style="bold red")
            # Fallback: print raw data for debugging
            console.print("Raw data that caused the error:", style="bold yellow")
            for i, item in enumerate(output_list):
                console.print(f"Item {i}: {item}")
            sys.exit(1)

    else:
        # Non JSON default output
        total_events = sum(denial['count'] for denial in unique_denials.values())
        console.print(f"\nFound {total_events} AVC events. Displaying {len(unique_denials)} unique denials...")
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
