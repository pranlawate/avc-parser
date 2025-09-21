# SELinux AVC Denial Analyzer

A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication and clear correlation tracking.

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

## ✅ Current Features

### 🔍 **Core Analysis**
- **Multi-line AVC Parsing**: Complex audit log blocks with `AVC`, `USER_AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, `SOCKADDR` records
- **Intelligent Deduplication**: Groups identical denials with occurrence counts and timestamps
- **Smart Field Aggregation**: Collects varying fields (PIDs, paths, permissions) across duplicates
- **Enhanced Path Resolution**: PATH record correlation with dev+inode fallback

### 🎨 **Semantic Analysis** ✨ NEW
- **Human-Readable Permissions**: `read` → `read (Read file content)`
- **Contextual Analysis**: `Analysis: Web server process attempting to read file content`
- **Type Descriptions**: Enhanced context display with `httpd (Web server process)`
- **Port Intelligence**: `5432 (PostgreSQL database)` for common services

### 📥 **Input Processing**
- **Auto-Detection**: Single `--file` flag detects raw vs pre-processed format automatically
- **Multiple Input Methods**: Raw audit.log, pre-processed files, or interactive input
- **Robust Parsing**: setroubleshoot's proven regex patterns for edge case handling
- **Comprehensive Validation**: File type, permission, and content validation with helpful errors

### 📊 **Output Formats**
- **Rich Terminal Output**: Color-coded, formatted summaries with professional appearance
- **JSON Export**: Structured output including semantic fields for integration
- **Cross-Platform**: Works on Linux, macOS, and Windows where Python runs

## ✅ Recent Additions

### 🔗 **Phase 2A: Simple Correlation Storage** ✨ NEW
- **PID-to-Resource Mapping**: Individual event correlations solve deduplication mapping loss
- **JSON Integration**: Correlation data available in `--json` output for API consumers
- **Forensic Analysis**: Track exactly which PID accessed which resource with which permission

## 🔮 Upcoming Features

### 🎨 **Phase 3: Rich Display Format** (Next)
- **Responsive Headers**: Professional Rich-based formatting that adapts to terminal width
- **Correlation Events**: Display individual PID-to-resource mappings when available
- **Legacy Compatibility**: `--legacy-format` flag preserves current behavior
- **Smart Filtering**: Process, path, time range, and context filtering capabilities

### 🧪 **Phase 4: Testing & Quality**
- **Comprehensive Testing**: Unit tests, integration tests, regression testing
- **Performance Optimization**: Memory management for large files
- **Enhanced Documentation**: Migration guides and usage examples

📊 **Complete Plan**: See [ROADMAP.md](ROADMAP.md) for detailed implementation roadmap and [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for scope decisions.

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

### **JSON Output:**
Add `--json` for machine-readable output:
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --json
```

## Example Output

### **Standard AVC Denial with Semantic Analysis** ✨
```bash
$ python3 parse_avc.py --file file_context_AVC.log
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
| `-f, --file` | Path to any audit file (auto-detects format) |
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

## 📈 Development Status

**Current Phase**: 3A (Rich Display Format)

| Phase | Status | Key Features |
|-------|--------|--------------|
| **1A/1B** | ✅ **COMPLETED** | Foundation, auto-detection, validation |
| **2B** | ✅ **COMPLETED** | Semantic analysis, permission descriptions |
| **2A** | ✅ **COMPLETED** | Simple correlation storage, PID-to-resource mapping |
| **3A** | 🔄 **NEXT** | Rich display format, correlation events display |
| **3B** | ⏳ **PLANNED** | Smart filtering, sorting options |
| **4** | ⏳ **PLANNED** | Testing, documentation |

### 🎯 **Design Focus**
- **Forensic Analysis**: Post-incident audit log analysis (not real-time monitoring)
- **Correlation Clarity**: Solve PID-to-resource mapping without architectural complexity
- **Professional Output**: Terminal-friendly with clean JSON export
- **Minimal Dependencies**: Python + Rich only (no policy files required)

📊 **Details**: [ROADMAP.md](ROADMAP.md) | **Decisions**: [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md)

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is open source. Please check the repository for license details.

## Support

For questions, issues, or feature requests, please open an issue on the GitHub repository.
