# SELinux AVC Denial Analyzer

**Version 1.1.0** | A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication and clear correlation tracking.

## ⚡ Quick Start

```bash
# Install dependencies
pip3 install rich

# Analyze audit logs (auto-detects format)
python3 parse_avc.py --file /var/log/audit/audit.log

# Get field-by-field details
python3 parse_avc.py --file /var/log/audit/audit.log --fields

# Export to JSON
python3 parse_avc.py --file /var/log/audit/audit.log --json
```

## 🎯 Purpose

**Post-incident SELinux audit log forensic analysis** for security analysts, system administrators, and compliance auditors.

### 🔄 How This Differs from sealert/setroubleshoot

| **setroubleshoot/sealert** | **AVC Denial Analyzer** |
|---------------------------|-------------------------|
| Real-time monitoring & policy suggestions | Post-incident log analysis & correlation |
| Live audit socket processing | Static file analysis |
| Policy recommendations | Clear denial summaries |
| Daemon-based setup | Single standalone script |

**Use this tool when**: You need forensic analysis of audit logs from systems you can't access directly, or when setroubleshoot's real-time output becomes overwhelming during incident response.

## ✅ Key Features

### 🎨 **Professional Display**
- **Rich Terminal Format**: Default responsive panels with BIONIC reading, professional styling, and correlation events
- **Enhanced Detailed View**: Use `--detailed` for expanded correlation analysis with syscall details and context information
- **Field-by-Field View**: Detailed breakdown using `--fields` flag for traditional analysis
- **JSON Export**: Structured output with semantic fields for automation and integration

### 🔍 **Advanced Analysis**
- **Semantic Intelligence**: Human-readable permissions (`read` → `Read file content`) and contextual analysis
- **Smart Deduplication**: Groups identical denials with occurrence counts, timestamps, and field aggregation
- **Correlation Tracking**: Individual PID-to-resource mappings solve deduplication information loss
- **Enhanced Path Resolution**: PATH record correlation with dev+inode fallback for complex scenarios

### 📥 **Flexible Input**
- **Auto-Detection**: Single `--file` flag automatically detects raw audit.log vs pre-processed format
- **Multiple Sources**: Raw audit.log, ausearch output, or interactive paste input
- **Robust Parsing**: Multi-line audit blocks (`AVC`, `USER_AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, `SOCKADDR`)
- **Comprehensive Validation**: File type, permissions, and content validation with helpful error messages

### 📖 **BIONIC Reading Format**
- **Enhanced Readability**: Strategic text formatting emphasizes key letter groups for improved scanning speed
- **Smart Application**: Applied to natural language text while preserving technical data clarity
- **Professional Appearance**: Maintains color harmony and visual consistency throughout the display

## 🔮 Upcoming Features

### 🎯 **Phase 3B: Advanced Display Features** (Next)
- **Smart Filtering**: Process, path, time range, and context filtering capabilities
- **Sorting Options**: Recent, count, chronological sorting
- **Enhanced Detail View**: Expanded information for deeper investigation

### 🧪 **Phase 4: Testing & Quality**
- **Comprehensive Testing**: Unit tests, integration tests, regression testing
- **Performance Optimization**: Memory management for large files

### 📚 **Phase 5: Enhanced Documentation**
- **Architecture Overview**: Function relationship trees and data flow diagrams
- **Developer Guide**: Contribution setup and architectural understanding
- **Migration Guides**: Enhanced README and usage examples

📊 **Complete Plan**: See [ROADMAP.md](ROADMAP.md) for detailed implementation roadmap and [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for scope decisions.

## Prerequisites

- Python 3.6+
- Python Rich library
- `audit` package (for `ausearch`): Usually pre-installed on most systems

## Installation

1. **Clone the Repository**:
   ```bash
   # Using HTTPS
   git clone https://github.com/pranlawate/avc-parser.git

   # Using SSH
   git clone git@github.com:pranlawate/avc-parser.git
   ```

2. **Install Dependencies**:
   ```bash
   pip3 install rich
   sudo dnf install audit  # If needed (Fedora/RHEL)
   sudo apt install auditd  # If needed (Ubuntu/Debian)
   ```

## 🚀 Usage

### **Recommended: Auto-Detection** ✨
Single flag automatically detects file format (raw audit.log vs pre-processed):
```bash
python3 parse_avc.py --file /var/log/audit/audit.log
python3 parse_avc.py --file avc_denials.log
```

### **Alternative Methods:**

**Raw Audit File Processing:**
```bash
python3 parse_avc.py --raw-file /var/log/audit/audit.log
```

**Pre-processed AVC File:**
```bash
# Create AVC file:
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR -ts recent > avc_denials.log
# Parse it:
python3 parse_avc.py --avc-file avc_denials.log
```

**Interactive Mode:**
```bash
python3 parse_avc.py
# Paste logs and press Ctrl+D (Linux/macOS) or Ctrl+Z+Enter (Windows)
```

### **Output Formats:**

**Rich Display (Default)**: Professional terminal format with responsive panels and BIONIC reading
```bash
python3 parse_avc.py --file /var/log/audit/audit.log
```

**Enhanced Detailed View**: Use `--detailed` for expanded correlation analysis
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --detailed
```

**Field-by-Field Display**: Use `--fields` for traditional detailed field breakdown
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --fields
```

**JSON Output**: Add `--json` for machine-readable output
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --json
```

## Example Output

### **Rich Display Format (Default)** ✨
Professional panels with BIONIC reading for enhanced readability:
```bash
$ python3 parse_avc.py --file file_context_AVC.log
🔍 Auto-detected: Pre-processed format

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 1 occurrences • last seen 1 year(s) ago ──────────
╭──────────────────────────────────────────────────────────────────────────────╮
│                             2024-09-05 02:18:01                              │
│                                  Kernel AVC                                  │
│              Denied read (Read file content) on file via openat              │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────╮
│               httpd (Web server process) 1234 • working from /               │
│      system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0       │
╰──────────────────────────────────────────────────────────────────────────────╯

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/index.html [Enforcing] ✗ BLOCKED

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### **Enhanced Detailed View** (using `--detailed`)
Expanded correlation analysis with syscall details and context information:
```bash
$ python3 parse_avc.py --file test_multiple_pids.log --detailed
Found 2 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 2 occurrences • last seen 2 week(s) ago ──────────
╭──────────────────────────────────────────────────────────────────────────────╮
│                         2025-09-04 18:19:00–18:19:00                         │
│                                  Kernel AVC                                  │
│  Denied read (Read file content), write (Modify file content) on file via    │
│  openat                                                                      │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────╮
│                    httpd (Web server process) 1234, 5678                     │
│      system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0       │
╰──────────────────────────────────────────────────────────────────────────────╯

Detailed Events:
• PID 1234 (httpd) [/usr/sbin/httpd] denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED
  ├─ Syscall: openat | Exit: EACCES | Time: 2025-09-04 18:19:00
  ├─ Analysis: Web server process attempting to read file content
  └─ Process Title: /usr/sbin/httpd -DFOREGROUND
• PID 5678 (httpd-worker) [/usr/sbin/httpd] denied 'write' to file /var/www/html/file2.html [Permissive] ✓ ALLOWED
  ├─ Syscall: openat | Exit: EACCES | Time: 2025-09-04 18:19:00
  ├─ Analysis: Web server process attempting to read file content
  └─ Process Title: /usr/sbin/httpd -DFOREGROUND

Security Context Details:
  Source: system_u:system_r:httpd_t:s0 (Web server process)
  Target: unconfined_u:object_r:default_t:s0 (Default file context)
  Object Class: file

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### **Field-by-Field Display Format** (using `--fields`)
```bash
$ python3 parse_avc.py --file file_context_AVC.log --fields
🔍 Auto-detected: Pre-processed format

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 year(s) ago) ───────────
  Timestamp:2024-09-05 02:18:01
  Process Title:httpd
  Executable:/usr/sbin/httpd
  Process Name:httpd (Web server process)
  Process ID (PID):1234
  Working Dir (CWD):/
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Denial Type:Kernel AVC
  Syscall:openat
  Permission:read (Read file content)
  SELinux Mode:Enforcing
  Analysis:Web server process attempting to read file content
-----------------------------------
  Target Path:/var/www/html/index.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0 (Default file context)
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
    ],
    "correlations": [
      {
        "pid": "1234",
        "comm": "httpd",
        "path": "/var/www/html/index.html",
        "permission": "read",
        "permissive": "0",
        "timestamp": "2024-09-05 02:18:01"
      }
    ]
  }
]
```

## Advanced Examples

### Network AVC Denial (Rich Format)
```bash
$ python3 parse_avc.py --avc-file network_AVC.log
Pre-processed AVC file provided: 'network_AVC.log'

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 1 occurrences • last seen 1 month(s) ago ──────────
2025-07-29 09:52:29 • Kernel AVC
Denied name_connect (Connect to network service) on tcp_socket via connect

httpd 4182412 • working from unknown
system_u:system_r:httpd_t:s0 attempting access to
system_u:object_r:jboss_management_port_t:s0

Events:
• PID 4182412 (httpd) denied 'name_connect' to tcp_socket port 9999 (JBoss Management) [Enforcing] ✗ BLOCKED

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### Network AVC Denial (Field-by-Field Format)
```bash
$ python3 parse_avc.py --avc-file network_AVC.log --fields
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

### Multiple Denials with Field Aggregation (Rich Format)
```bash
$ python3 parse_avc.py --avc-file test_multiple_pids.log
Pre-processed AVC file provided: 'testAVC/test_multiple_pids.log'

Found 2 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
─────────── Unique Denial #1 • 2 occurrences • last seen 5 day(s) ago ───────────
2025-09-04 18:19:00 • Kernel AVC
Denied read, write (Read file content, Write file content) on file via openat

httpd, httpd-worker 1234, 5678 • working from unknown
system_u:system_r:httpd_t:s0 attempting access to
unconfined_u:object_r:default_t:s0

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED
• PID 5678 (httpd-worker) denied 'write' to file /var/www/html/file2.html [Permissive] ⚠ LOGGED

Analysis Complete: Processed 2 log blocks and found 1 unique denials.
```

### Multiple Denials with Field Aggregation (Field-by-Field Format)
```bash
$ python3 parse_avc.py --avc-file test_multiple_pids.log --fields
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

### Multiple Denials with De-duplication (Field-by-Field Format)
```bash
$ python3 parse_avc.py -rf testAVC/audit.log --fields
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
| `-f, --file` | Path to any audit file (auto-detects format) |
| `-rf, --raw-file` | Path to a raw audit.log file |
| `-af, --avc-file` | Path to a pre-processed AVC file |
| `--fields` | Use field-by-field display format (legacy) |
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

## 📈 Development Status

**Current Version**: 1.1.0 | **Current Phase**: 3B (Advanced Display Features)

| Component | Status | Description |
|-----------|--------|-------------|
| **Core Foundation** | ✅ **COMPLETE** | Auto-detection, validation, robust parsing |
| **Semantic Analysis** | ✅ **COMPLETE** | Human-readable permissions, contextual intelligence |
| **Correlation Tracking** | ✅ **COMPLETE** | PID-to-resource mapping, individual event details |
| **Rich Display Format** | ✅ **COMPLETE** | Professional terminal output, responsive design |
| **Code Quality** | ✅ **COMPLETE** | Refactored architecture, maintainable functions |
| **Smart Filtering** | 🔄 **IN PROGRESS** | Process, path, time range filtering |
| **Testing & Quality** | ⏳ **PLANNED** | Comprehensive test suite, performance optimization |

### 🎯 **Design Principles**
- **Forensic Focus**: Post-incident analysis (not real-time monitoring)
- **Professional Output**: Rich terminal formatting with correlation tracking
- **Minimal Dependencies**: Python + Rich only (no policy files required)
- **Cross-Platform**: Linux, macOS, Windows compatibility

📊 **Complete Roadmap**: [ROADMAP.md](ROADMAP.md) | **Feature Decisions**: [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md)

## 💡 Tips & Troubleshooting

### Performance
- **Large Files**: For audit.log files >100MB, consider using `ausearch` to pre-filter by time range
- **Memory Usage**: Use `--json` output for processing large datasets programmatically

### Common Issues
- **Permission Denied**: Ensure read access to audit files (may require `sudo`)
- **Missing ausearch**: Install audit package (`dnf install audit` or `apt install auditd`)
- **Empty Output**: Check SELinux is enabled (`sestatus`) and audit logging is active

### Best Practices
- **Incident Analysis**: Start with Rich format for overview, use `--fields` for detailed investigation
- **Automation**: Use `--json` output for integration with SIEM tools or custom scripts
- **Time Ranges**: Use `ausearch -ts` to filter logs by time before analysis

## 🤝 Contributing

Contributions are welcome! Please see our development roadmap and feature decisions for current priorities:
- 🐛 **Bug Reports**: Open an issue with reproduction steps
- 💡 **Feature Requests**: Check [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for scope alignment
- 🔧 **Pull Requests**: Follow existing code style and include tests

## 📄 License

**MIT License** - This project is open source and free to use. See the repository for full license details.

## 🆘 Support

- **Questions**: Open a GitHub issue for usage questions
- **Bug Reports**: Include log samples and error messages
- **Feature Requests**: Check our roadmap before submitting

---

**SELinux AVC Denial Analyzer v1.1.0** | Made for forensic analysts and system administrators
