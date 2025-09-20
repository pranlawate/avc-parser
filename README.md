# SELinux AVC Denial Analyzer

A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication and clear correlation tracking.

## Project Scope & Purpose

### What This Tool Does
This tool specializes in **post-incident SELinux audit log analysis** for scenarios requiring:
- Clear correlation of complex denial patterns
- Intelligent deduplication with occurrence tracking
- Static log file analysis without system access
- Professional output suitable for reporting and documentation

### How This Differs from sealert
**Complementary tool** designed for different use cases:

| **sealert** | **AVC Denial Analyzer** |
|-------------|-------------------------|
| Real-time monitoring & policy suggestions | Post-incident log analysis & correlation |
| Live audit socket processing | Static file analysis |
| Policy recommendations | Clear denial summaries |
| Daemon-based setup | Single standalone script |
| Verbose data dumps | Professional formatted output |

**Use this tool when**: You need clear analysis of audit logs from systems you can't access directly, or when sealert's real-time output becomes overwhelming.

## Current Features

- **Multi-line AVC Parsing**: Parses complex AVC audit log blocks containing `AVC`, `USER_AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, and `SOCKADDR` records
- **USER_AVC Support**: Handles userspace AVC denials (e.g., D-Bus, systemd) with proper message extraction
- **Raw Audit Log Support**: Can directly process raw `audit.log` files by internally using `ausearch` with comprehensive message types
- **Intelligent Deduplication**: Groups identical denials and tracks occurrence counts with first/last seen timestamps
- **Smart Field Aggregation**: Collects varying fields (PIDs, paths, permissions) across duplicate denials and displays them comma-separated
- **Enhanced Path Resolution**: Uses PATH record `name` field for complete paths, falls back to `dev+inode` identifiers when paths are missing *(WIP)*
- **Comprehensive Data Extraction**: Extracts process information, security contexts, permissions, paths, and network details
- **Denial Type Detection**: Distinguishes between Kernel AVC and Userspace AVC denials
- **Dynamic Labeling**: Correctly labels D-Bus destinations vs network ports based on target class
- **SELinux Mode Display**: Shows Enforcing/Permissive mode for each denial
- **Unparsed Type Tracking**: Identifies and reports unparsed record types for development guidance
- **Auto-Detection**: Single `--file` flag that automatically detects raw vs pre-processed files (NEW!)
- **Multiple Input Methods**: Supports raw log files, pre-processed files, or interactive input
- **Rich Output**: Clean, formatted, color-coded summaries using the Rich library
- **JSON Export**: Structured JSON output for integration with ML/AI applications
- **Robust Error Handling**: Comprehensive input validation, graceful error recovery, and detailed error messages
- **Enhanced Parsing**: Uses setroubleshoot's robust audit record regex for better edge case handling

## Upcoming Features (Planned)

### Phase 2-3: Core Enhancements
- **Correlation Tracking**: Solve PID-to-resource mapping problem with individual event details
- **Rich Display Format**: Professional responsive output with correlation events
- **Syscall Success Tracking**: Replace generic permissive warnings with actual syscall results
- **Dontaudit Detection**: Identify when dontaudit rules are disabled for enhanced audit mode

### Phase 4-5: Quality & Documentation
- **Comprehensive Testing**: Unit tests, integration tests, and regression testing
- **Enhanced Documentation**: Migration guides, usage examples, and installation instructions

### Phase 6-8: Advanced Features
- **Performance Optimization**: Memory management and progress indicators for large files
- **Extended Parsing**: Support for FANOTIFY, SELINUX_ERR, and USER_SELINUX_ERR message types
- **Advanced UX**: Color customization, filtering capabilities, and interactive features

📋 **Detailed Implementation Plan**: See [ROADMAP.md](ROADMAP.md) for comprehensive 8-phase roadmap with technical specifications and design decisions.

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
   pip3 install rich
   sudo dnf install audit  # If needed (Fedora/RHEL)
   sudo apt install auditd  # If needed (Ubuntu/Debian)
   ```

## Usage

### Option A: Raw Audit File Processing
Process system audit logs directly using internal `ausearch`:
```bash
python3 parse_avc.py --raw-file /var/log/audit/audit.log
```

### Option B: Pre-processed AVC File
Process AVC logs already filtered with `ausearch`:
```bash
# First, create the AVC file:
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR -ts recent > avc_denials.log

# Then, parse it:
python3 parse_avc.py --avc-file avc_denials.log
```

### Option C: Interactive Mode
Paste logs directly into the terminal:
```bash
python3 parse_avc.py
# Paste your log and press Ctrl+D (Linux/macOS) or Ctrl+Z+Enter (Windows)
```

### Option D: JSON Output
Add `--json` flag for machine-readable output:
```bash
python3 parse_avc.py --raw-file /var/log/audit/audit.log --json
```

## Example Output

### Standard AVC Denial
```bash
$ python3 parse_avc.py --avc-file file_context_AVC.log 
Pre-processed AVC file provided: 'file_context_AVC.log'

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 year(s) ago) ───────────
  Timestamp:2024-09-05 02:18:01
  Process Title:httpd
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):1234
  Working Dir (CWD):/
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Kernel AVC
  Syscall:openat
  Permission:read
  SELinux Mode:Enforcing
-----------------------------------
  Target Path:/var/www/html/index.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### JSON Output
```bash
$ python3 parse_avc.py --json --avc-file file_context_AVC.log 
[
  {
    "log": {
      "datetime_str": "2024-09-05 02:18:01",
      "timestamp": "1725482881.101",
      "syscall": "openat",
      "exe": "/usr/sbin/httpd",
      "cwd": "/",
      "path": "/var/www/html/index.html",
      "denial_type": "AVC",
      "permission": "read",
      "pid": "1234",
      "comm": "httpd",
      "scontext": "system_u:system_r:httpd_t:s0",
      "tcontext": "unconfined_u:object_r:default_t:s0",
      "tclass": "file",
      "permissive": "0",
      "proctitle": "httpd"
    },
    "count": 1,
    "first_seen": "2024-09-05T02:18:01.101000",
    "last_seen": "2024-09-05T02:18:01.101000",
    "permissions": [
      "read"
    ]
  }
]
```

## Advanced Examples

### Network AVC Denial
```bash
$ python3 parse_avc.py --avc-file network_AVC.log 
Pre-processed AVC file provided: 'network_AVC.log'

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-29 09:52:29
  Process Title:/usr/sbin/httpd -DFOREGROUND
  Process Name:httpd
  Process ID (PID):4182412
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Kernel AVC
  Syscall:connect
  Permission:name_connect
-----------------------------------
  Socket Address:saddr_fam=inet laddr=10.233.237.96 lport=9999
  Target Class:tcp_socket
  Target Context:system_u:object_r:jboss_management_port_t:s0
  Target Port:9999
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### Multiple Denials with Field Aggregation
```bash
$ python3 parse_avc.py --avc-file test_multiple_pids.log
Pre-processed AVC file provided: 'testAVC/test_multiple_pids.log'

Found 2 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
─────────── Unique Denial #1 (2 occurrences, last seen 5 day(s) ago) ───────────
  Timestamp:2025-09-04 18:19:00
  Process Title:/usr/sbin/httpd -DFOREGROUND
  Executable:/usr/sbin/httpd
  Process Name:httpd, httpd-worker
  Process ID (PID):1234, 5678
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Kernel AVC
  Syscall:openat
  Permission:read, write
  SELinux Mode:Enforcing, Permissive
-----------------------------------
  Target Path:/var/www/html/file1.html, /var/www/html/file2.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### Multiple Denials with De-duplication
```bash
$ python3 parse_avc.py -rf testAVC/audit.log 
Raw file input provided. Running ausearch on 'audit.log'...

Found 76 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 (74 occurrences, last seen an unknown time) ─────────
  Process Title:/usr/bin/python3.11 /usr/bin/pulpcore-worker
  Process Name:pulpcore-worker
  Process ID (PID):1020588, 1020782, 1020887, 1020976, 1021077, 1021270, 
1021901, 1039740, 1039928, 1040118, 1040570, 1040889, 1041354, 1343630, 1343656,
1343803, 1346039, 1346299, 1346310, 1346564, 1347373, 1348333, 1348467, 1348855,
1349773, 1349927, 1350460, 1350668, 1350850, 1351213, 1376151, 1376165, 1376316,
1376718, 1377033
  Source Context:system_u:system_r:pulpcore_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Kernel AVC
  Syscall:keyctl
  Permission:read, view
  SELinux Mode:Permissive
-----------------------------------
  Target Class:key
  Target Context:system_u:system_r:unconfined_service_t:s0
-----------------------------------
────────────────────────────────────────────────────────────────────────────────
───────── Unique Denial #2 (2 occurrences, last seen an unknown time) ──────────
  Process ID (PID):1094
  Source Context:system_u:system_r:systemd_localed_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Userspace AVC
  Permission:send_msg
  SELinux Mode:Enforcing
-----------------------------------
  Target Class:dbus
  Target Context:system_u:system_r:insights_client_t:s0
  D-Bus Destination::1.41126, :1.53788
-----------------------------------

Analysis Complete: Processed 76 log blocks and found 2 unique denials.
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
- **Denial Type**: Kernel AVC or Userspace AVC
- **Syscall**: System call that triggered the denial
- **Permission**: Specific permission that was denied
- **SELinux Mode**: Enforcing or Permissive mode

### Target Information
- **Target Path**: File or directory path
- **Target Port**: Network port (for socket denials)
- **D-Bus Destination**: D-Bus connection identifier (for D-Bus denials)
- **Socket Address**: Network address information
- **Target Class**: Object class (file, socket, dbus, etc.)

## Development Roadmap

This project follows a structured 8-phase development plan focusing on incremental improvements and user experience enhancements.

### Implementation Strategy
- **Phases 1-3**: Core functionality enhancements (auto-detection, correlation tracking, professional display)
- **Phases 4-5**: Quality assurance and documentation improvements
- **Phases 6-8**: Performance optimization and advanced features

### Key Focus Areas
- **Forensic Accuracy**: Enhanced correlation tracking and syscall success monitoring
- **User Experience**: Professional responsive output and simplified command-line interface
- **Robustness**: Comprehensive testing, input validation, and error handling
- **Extensibility**: Support for additional message types and export formats

🗺️ **Complete Development Plan**: See [ROADMAP.md](ROADMAP.md) for detailed implementation phases, technical specifications, design decisions, and strategic positioning analysis.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is open source. Please check the repository for license details.

## Support

For questions, issues, or feature requests, please open an issue on the GitHub repository.
