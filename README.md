# SELinux AVC Log Parser

A simple, standalone Python script to parse raw or pre-processed SELinux audit logs into a clean, human-readable format.

## Features

- **Multi-line AVC Parsing**: Parses complex AVC audit log blocks containing `AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, and `SOCKADDR` records
- **Raw Audit Log Support**: Can directly process raw `audit.log` files by internally using `ausearch`
- **Intelligent Deduplication**: Groups identical denials and tracks occurrence counts with first/last seen timestamps
- **Comprehensive Data Extraction**: Extracts process information, security contexts, permissions, paths, and network details
- **Unparsed Type Tracking**: Identifies and reports unparsed record types for development guidance
- **Multiple Input Methods**: Supports raw log files, pre-processed files, or interactive input
- **Rich Output**: Clean, formatted, color-coded summaries using the Rich library
- **JSON Export**: Structured JSON output for integration with ML/AI applications

## Prerequisites

- Python 3.6+
- Python Rich library
- `audit` package (for `ausearch`): Usually pre-installed on most systems

## Installation

1. **Clone the Repository**:
   ```bash
   # Using HTTPS
   git clone https://github.com/pranlawate/avc_parser.git
   
   # Using SSH
   git clone git@github.com:pranlawate/avc-parser.git
   ```

2. **Install Dependencies**:
   ```bash
   pip install rich
   sudo dnf install audit  # If needed (Fedora/RHEL)
   sudo apt install auditd  # If needed (Ubuntu/Debian)
   ```

## Usage

### Option A: Raw Audit File Processing
Process system audit logs directly using internal `ausearch`:
```bash
python parse_avc.py --raw-file /var/log/audit/audit.log
```

### Option B: Pre-processed AVC File
Process AVC logs already filtered with `ausearch`:
```bash
# First, create the AVC file:
ausearch -m AVC -ts recent > avc_denials.log

# Then, parse it:
python parse_avc.py --avc-file avc_denials.log
```

### Option C: Interactive Mode
Paste logs directly into the terminal:
```bash
python parse_avc.py
# Paste your log and press Ctrl+D (Linux/macOS) or Ctrl+Z+Enter (Windows)
```

### Option D: JSON Output
Add `--json` flag for machine-readable output:
```bash
python parse_avc.py --raw-file /var/log/audit/audit.log --json
```

## Example Output

### Standard AVC Denial
```bash
$ python parse_avc.py --avc-file example.log

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 year(s) ago) ───────────
  Timestamp:2024-09-02 23:30:00
  Process Name:httpd
  Process ID (PID):1234
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Permission:read
-----------------------------------
  Target Path:/var/www/html/file1.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### JSON Output
```bash
$ python parse_avc.py --json --avc-file example.log
[
  {
    "log": {
      "datetime_str": "2024-09-02 23:30:00",
      "timestamp": "1725300000.101",
      "pid": "1234",
      "comm": "httpd",
      "scontext": "system_u:system_r:httpd_t:s0",
      "tcontext": "unconfined_u:object_r:default_t:s0",
      "permission": "read",
      "tclass": "file",
      "path": "/var/www/html/file1.html"
    },
    "count": 1,
    "first_seen": "2024-09-02T23:30:00.101000",
    "last_seen": "2024-09-02T23:30:00.101000"
  }
]
```

## Advanced Examples

### Network AVC Denial
```bash
$ python parse_avc.py --avc-file network_denial.log

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 month(s) ago) ───────────
  Timestamp:2025-07-29 09:52:29
  Process Title:/usr/sbin/httpd -DFOREGROUND
  Process ID (PID):4182412
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:connect
  Permission:name_connect
-----------------------------------
  Target Port:9999
  Socket Address:saddr_fam=inet laddr=10.233.237.96 lport=9999
  Target Class:tcp_socket
  Target Context:system_u:object_r:jboss_management_port_t:s0
-----------------------------------
```

### Multiple Denials with Deduplication
```bash
$ python parse_avc.py --raw-file /var/log/audit/audit.log

Found 74 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 (37 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-14 02:30:53
  Process Title:/usr/bin/python3.11
  Process ID (PID):1020588
  Source Context:system_u:system_r:pulpcore_t:s0
-----------------------------------
  Action:Denied
  Syscall:keyctl
  Permission:read
-----------------------------------
  Target Class:key
  Target Context:system_u:system_r:unconfined_service_t:s0
-----------------------------------
────────────────────────────────────────────────────────────────────────────────
───────── Unique Denial #2 (37 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-14 02:30:53
  Process Title:/usr/bin/python3.11
  Process ID (PID):1020588
  Source Context:system_u:system_r:pulpcore_t:s0
-----------------------------------
  Action:Denied
  Syscall:keyctl
  Permission:view
-----------------------------------
  Target Class:key
  Target Context:system_u:system_r:unconfined_service_t:s0
-----------------------------------

Analysis Complete: Processed 74 log blocks and found 2 unique denials.
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-rf, --raw-file` | Path to a raw audit.log file |
| `-af, --avc-file` | Path to a pre-processed AVC file |
| `--json` | Output in JSON format |
| `-h, --help` | Show help message |

## Parsed Data Fields

### Process Information
- **Timestamp**: When the denial occurred
- **Process Name**: Command name (comm)
- **Process ID**: Process identifier
- **Process Title**: Full command line (if available)
- **Executable**: Path to executable
- **Working Directory**: Current working directory

### Security Contexts
- **Source Context**: Security context of the process
- **Target Context**: Security context of the target object

### Action Details
- **Syscall**: System call that triggered the denial
- **Permission**: Specific permission that was denied

### Target Information
- **Target Path**: File or directory path
- **Target Port**: Network port (for socket denials)
- **Socket Address**: Network address information
- **Target Class**: Object class (file, socket, etc.)

## Future Scope

The following enhancements are planned for future releases:

### Code Quality Improvements
- **Type Hints**: Comprehensive type annotations throughout the codebase
- **Configuration Management**: Centralized configuration module for parsing patterns
- **Structured Logging**: Replace print statements with proper logging framework
- **Data Classes**: Use dataclasses for structured data representation
- **Data Validation**: Built-in validation for parsed fields with `--validate` flag

### Interface Enhancements
- **Auto-Detection**: Intelligent file type detection with single `--file` option
- **Simplified Interface**: Unified command-line interface for all file types

### Advanced Features
- **Unit Testing**: Comprehensive pytest test suite
- **Packaging**: pip-installable package with setuptools
- **Live Monitoring**: Real-time log monitoring with `--follow` flag
- **Context Translation**: Human-readable SELinux context descriptions
- **Event Correlation**: Detection of denial bursts and patterns
- **Process Tracking**: Cross-denial process analysis
- **Additional Output Formats**: CSV and HTML report generation
- **Configuration Management**: Custom parsing patterns and rules
- **Performance Optimization**: Parallel processing and streaming support
- **Interactive Mode**: TUI interface for complex analysis workflows

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is open source. Please check the repository for license details.

## Support

For questions, issues, or feature requests, please open an issue on the GitHub repository.