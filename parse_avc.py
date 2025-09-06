import argparse
import re
import sys
import subprocess
import json
import logging
from datetime import datetime
from typing import Dict, Set, Tuple, Optional, List, Any
from rich.console import Console
from rich.rule import Rule
from config import (
    PARSING_PATTERNS, PROCESS_FIELDS, ACTION_FIELDS, TARGET_FIELDS,
    TIMESTAMP_FORMATS, LOG_BLOCK_SEPARATOR, SPECIAL_FIELD_PROCESSORS,
    JSON_OUTPUT_CONFIG, STRING_CLEAN_PATTERNS
)
from models import ParsedLog, DenialInfo, ProcessingStats

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def parse_avc_log(log_block: str) -> Tuple[ParsedLog, Set[str]]:
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
            # Try to parse as a human-readable timestamp
            dt_object = datetime.strptime(timestamp_str, TIMESTAMP_FORMATS[0])
        except ValueError:
            try:
                # Fallback to parsing as a unix timestamp
#                print(f"\nDEBUG: Extracted timestamp to parse as unix timestamp: '{timestamp_str}'")
                dt_object = datetime.fromtimestamp(float(timestamp_str))
            except ValueError:
                dt_object = None # Could not parse timestamp
                logger.debug(f"Extracted timestamp could not be parsed: '{timestamp_str}'")

        if dt_object:
            parsed_data['datetime_obj'] = dt_object
            parsed_data['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            parsed_data['timestamp'] = dt_object.timestamp()

    patterns = PARSING_PATTERNS
    
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
                    if key in SPECIAL_FIELD_PROCESSORS and SPECIAL_FIELD_PROCESSORS[key] == 'hex_decode':
                        try: 
                            parsed_data[key] = bytes.fromhex(value).decode()
                        except ValueError: 
                            parsed_data[key] = value.strip('"')
                    else: 
                        parsed_data[key] = value.strip()
        else:
            # --- Track unparsed types ---
            unparsed_types.add(log_type)

    logger.debug(f"Final parsed data for this block: {parsed_data}")
    
    # Create ParsedLog object from parsed data
    parsed_log = ParsedLog.from_dict(parsed_data)
    
    # Validate the parsed log data
    validation_errors = parsed_log.validate()
    if validation_errors:
        logger.warning(f"Validation errors in parsed log: {validation_errors}")
    
    return parsed_log, unparsed_types

def human_time_ago(dt_object: Optional[datetime]) -> str:
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

def print_summary(console: Console, denial_info: DenialInfo, denial_num: int) -> None:
    """Prints a formatted summary. Skips any fields that were not found. Has a counter of occurances that match signature. Shows human time of last occurence"""
    parsed_log = denial_info.log
    count = denial_info.count
    last_seen_dt = denial_info.last_seen_obj
    last_seen_ago = human_time_ago(last_seen_dt)

    header = f"[bold green]Unique Denial #{denial_num}[/bold green] ({count} occurrences, last seen {last_seen_ago})"
    console.print(Rule(header))

    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return

    # Define the fields and their labels for cleaner printing
    process_fields = PROCESS_FIELDS
    action_fields = ACTION_FIELDS
    target_fields = TARGET_FIELDS

    # --- Process Information ---
    for label, key in process_fields:
        value = getattr(parsed_log, key, None)
        if value:
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{value}")

    console.print("-" * 35)
    # --- Action Details ---
    console.print("  [bold]Action:[/bold]".ljust(22) + "Denied")
    for label, key in action_fields:
        value = getattr(parsed_log, key, None)
        if value:
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{value}")

    console.print("-" * 35)
    # --- Target Information ---
    for label, key in target_fields:
        value = getattr(parsed_log, key, None)
        if value:
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{value}")

    console.print("-" * 35)

def detect_file_type(file_path: str) -> str:
    """
    Detect whether a file is a raw audit log or pre-processed AVC log.
    Returns 'raw' or 'avc' based on file content analysis.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read first 20 lines to analyze
            lines = [f.readline().strip() for _ in range(20)]
            lines = [line for line in lines if line]  # Remove empty lines
        
        if not lines:
            return 'unknown'
        
        # Check for raw audit log characteristics
        raw_indicators = 0
        avc_indicators = 0
        
        for line in lines:
            # Raw audit log indicators
            if any(event_type in line for event_type in ['CRED_DISP', 'SERVICE_STOP', 'SERVICE_START', 
                                                        'USER_LOGIN', 'USER_LOGOUT', 'SYSTEM_BOOT', 
                                                        'CONFIG_CHANGE', 'KERNEL', 'DAEMON_START']):
                raw_indicators += 1
            
            # Pre-processed AVC log indicators
            if '----' in line:
                avc_indicators += 1
            if line.startswith('type=PROCTITLE') or line.startswith('type=SYSCALL') or line.startswith('type=AVC'):
                avc_indicators += 1
        
        # Decision logic
        if raw_indicators > avc_indicators:
            return 'raw'
        elif avc_indicators > 0:
            return 'avc'
        else:
            # Fallback: check if file contains AVC events
            for line in lines:
                if 'type=AVC' in line:
                    return 'avc'
            return 'raw'  # Default to raw if uncertain
            
    except Exception as e:
        logger.warning(f"Could not detect file type for {file_path}: {e}")
        return 'unknown'

def main() -> None:
    """
    Main function to handle command-line arguments and print the parsed output.
    """
    parser = argparse.ArgumentParser(description="A tool to parse an SELinux AVC denial log from a file or user prompt.")
    parser.add_argument("-f", "--file", type=str, help="Path to an audit log file (auto-detect type).")
    parser.add_argument("--json", action="store_true", help="Output the parsed data in JSON format.")
    parser.add_argument("--validate", action="store_true", help="Enable validation reporting for parsed data.")
    args = parser.parse_args()

    # Create a Rich Console instance
    console: Console = Console()
    log_string: str = ""

    if args.file:
        # Auto-detect file type
        detected_type = detect_file_type(args.file)
        if not args.json:
            console.print(f"Auto-detected file type: {detected_type}")
        
        if detected_type == 'raw':
            # Process as raw audit log
            if not args.json:
                console.print(f"Raw file input provided. Running ausearch on '{args.file}'...")
            logger.info(f"Processing raw file: {args.file}")
            try:
                ausearch_cmd = ["ausearch", "-m", "AVC", "-i", "-if", args.file]
                logger.debug(f"Running command: {' '.join(ausearch_cmd)}")
                result = subprocess.run(ausearch_cmd, capture_output=True, text=True, check=True)
                log_string = result.stdout
                logger.info(f"Successfully processed raw file, got {len(log_string)} characters")
            except FileNotFoundError:
                error_msg = "The 'ausearch' command was not found. Is audit installed?"
                logger.error(error_msg)
                console.print(f"Error: {error_msg}", style="bold red")
                sys.exit(1)
            except subprocess.CalledProcessError as e:
                error_msg = f"Error running ausearch: {e.stderr}"
                logger.error(error_msg)
                console.print(f"Error: {error_msg}", style="bold red")
                sys.exit(1)
        elif detected_type == 'avc':
            # Process as pre-processed AVC file
            if not args.json:
                console.print(f"Pre-processed AVC file provided: '{args.file}'")
            logger.info(f"Processing AVC file: {args.file}")
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    log_string = f.read()
                logger.info(f"Successfully read AVC file, got {len(log_string)} characters")
            except FileNotFoundError:
                error_msg = f"File not found at '{args.file}'"
                logger.error(error_msg)
                console.print(f"Error: {error_msg}", style="bold red")
                sys.exit(1)
        else:
            console.print(f"Could not determine file type for '{args.file}'. Please check the file format.", style="bold red")
            sys.exit(1)
    else:
        if not args.json:
            console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] when done:")
        logger.info("Reading input from stdin")
        try:
            log_string = sys.stdin.read()
            logger.info(f"Successfully read from stdin, got {len(log_string)} characters")
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
            console.print("[red] Key Board Interrupted [/red]")
            sys.exit(0)

#   --- Split, De-duplicate, and Process Logic ---
# Old logic commented as it didn't look inside the block to remove time-> added by ausearch
    log_blocks: List[str] = [block.strip() for block in log_string.split(LOG_BLOCK_SEPARATOR) if block.strip()]

# New logic trying to find and remove 'time->' if present in the log
#    log_blocks_raw = log_string.split('----')

#    log_blocks = []
#    for block in log_blocks_raw:
#        clean_lines = [line for line in block.strip().split('\n') if not line.strip().startswith('time->')]
#        if clean_lines:
#            log_blocks.append("\n".join(clean_lines))
    if not log_blocks:
        error_msg = "No valid log blocks found"
        logger.error(error_msg)
        if not args.json:
            console.print(f"Error: {error_msg}.", style="bold red")
        sys.exit(1)

    logger.info(f"Found {len(log_blocks)} log blocks to process")
    unique_denials: Dict[Tuple[Optional[str], Optional[str], Optional[str], Optional[str]], DenialInfo] = {}
    all_unparsed_types: Set[str] = set()

    for block in log_blocks:
        parsed_log: ParsedLog
        unparsed: Set[str]
        parsed_log, unparsed = parse_avc_log(block)
        all_unparsed_types.update(unparsed)
        # We only care about blocks that contain an AVC denial
        if parsed_log.permission:
            logger.debug(f"Found AVC denial: {parsed_log.permission} for {parsed_log.comm or 'unknown'}")
            #Create a unique signature for the denial
            signature: Tuple[Optional[str], Optional[str], Optional[str], Optional[str]] = (
                parsed_log.scontext, parsed_log.tcontext,
                parsed_log.tclass, parsed_log.permission
            )
            dt_obj: Optional[datetime] = parsed_log.datetime_obj
            if signature in unique_denials:
                unique_denials[signature].count += 1
                unique_denials[signature].last_seen_obj = dt_obj
            else:
                unique_denials[signature] = DenialInfo(
                    log=parsed_log, 
                    count=1, 
                    first_seen_obj=dt_obj, 
                    last_seen_obj=dt_obj
                )
    
    logger.info(f"Processing complete: {len(unique_denials)} unique denials found from {len(log_blocks)} log blocks")
    if all_unparsed_types:
        logger.warning(f"Unparsed record types found: {sorted(list(all_unparsed_types))}")
    
    # Validation reporting
    if args.validate:
        validation_issues = []
        for denial_info in unique_denials.values():
            errors = denial_info.log.validate()
            if errors:
                validation_issues.extend([f"Denial {denial_info.log.comm or 'unknown'}: {error}" for error in errors])
        
        if validation_issues:
            if not args.json:
                console.print("\n[yellow]Validation Issues Found:[/yellow]")
                for issue in validation_issues:
                    console.print(f"  • {issue}")
            else:
                logger.warning(f"Validation issues found: {validation_issues}")
        else:
            if not args.json:
                console.print("\n[green]✓ All parsed data passed validation[/green]")
            else:
                logger.info("All parsed data passed validation")
    
    if args.json:
        # Convert the dictionary of unique denials to a list for JSON output
        output_list: List[Dict[str, Any]] = []
        for denial_info in unique_denials.values():
            # Use the DenialInfo.to_dict() method for clean JSON output
            json_denial = denial_info.to_dict()
            
            # Clean up any problematic characters in string values
            if 'log' in json_denial:
                for key, value in json_denial['log'].items():
                    if isinstance(value, str):
                        cleaned_value = value
                        for pattern, replacement in STRING_CLEAN_PATTERNS.items():
                            cleaned_value = cleaned_value.replace(pattern, replacement)
                        json_denial['log'][key] = cleaned_value
            
            output_list.append(json_denial)
        
        try:
            json_output = json.dumps(output_list, **JSON_OUTPUT_CONFIG)
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
        console.print(f"\nFound {len(log_blocks)} AVC events. Displaying {len(unique_denials)} unique denials...")
        sorted_denials: List[DenialInfo] = sorted(unique_denials.values(), key=lambda x: x.first_seen_obj or datetime.fromtimestamp(0))
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
