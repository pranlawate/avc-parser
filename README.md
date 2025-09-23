# SELinux AVC Denial Analyzer

**Version 1.2.0** | A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication and clear correlation tracking.

## ⚡ Quick Start

```bash
# Install dependencies
pip3 install rich

# Analyze audit logs (auto-detects format)
python3 parse_avc.py --file /var/log/audit/audit.log

# Filter by process and sort by count (most frequent first)
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --sort count

# Filter by path with wildcards
python3 parse_avc.py --file /var/log/audit/audit.log --path "/var/www/*"

# Get enhanced detailed analysis
python3 parse_avc.py --file /var/log/audit/audit.log --detailed

# Get field-by-field details
python3 parse_avc.py --file /var/log/audit/audit.log --fields

# Export to JSON
python3 parse_avc.py --file /var/log/audit/audit.log --json

# Use legacy signature logic (for regression testing)
python3 parse_avc.py --file /var/log/audit/audit.log --legacy-signatures
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
- **Smart Deduplication**: SELinux remediation-aware grouping that properly distinguishes services while grouping related permissions for optimal `semanage` command correlation
- **Correlation Tracking**: Individual PID-to-resource mappings solve deduplication information loss
- **Enhanced Path Resolution**: PATH record correlation with dev+inode fallback for complex scenarios
- **dontaudit Detection**: Automatic detection of disabled dontaudit rules using permission indicators
- **Smart Filtering**: Process name and path filtering with wildcard support (`--process`, `--path`)
- **Flexible Sorting**: Multiple sort orders - recent, count-based, or chronological (`--sort`)

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

### 🎯 **Phase 3B-2: Polish Features** (Current)
- **Smart Deduplication Logic**: Enhanced signature generation for better service distinction and permission grouping
- **Smart Event Grouping**: Intelligent grouping by common directory paths to reduce output volume for large audit logs
- **Advanced Filtering**: Time range filtering (`--since`, `--until`) and context filtering (`--source`, `--target`)
- **Smart Resource Display**: Context-aware formatting based on object class (file vs network)
- **JSON Field Normalization**: Standardized path formats, clean port extraction, and normalized context fields for reliable tool integration

### 🧪 **Phase 4B: Integration & Performance** (After Polish Features)
- **Real-world Testing**: Various audit log formats, different Linux distributions
- **Cross-platform Compatibility**: Testing across RHEL, Ubuntu, SUSE, Arch distributions
- **Memory Optimization**: Large file handling improvements (>500MB audit logs)

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

## 📋 Examples & Usage Patterns

This section demonstrates the tool's capabilities with real examples, organized from basic to advanced usage patterns.

### 🎯 **Basic Usage Examples**

#### Simple File Analysis
```bash
$ python3 parse_avc.py --file testAVC/file_context_AVC.log
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/file_context_AVC.log directly

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

#### Network Denial Analysis
```bash
$ python3 parse_avc.py --file testAVC/network_AVC.log
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/network_AVC.log directly

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 • 1 occurrences • last seen 1 month(s) ago ──────────
╭──────────────────────────────────────────────────────────────────────────────╮
│                             2025-07-29 09:52:29                              │
│                                  Kernel AVC                                  │
│ Denied name_connect (Connect to network service) on TCP network socket via   │
│ connect                                                                      │
╰──────────────────────────────────────────────────────────────────────────────╮
╭──────────────────────────────────────────────────────────────────────────────╮
│                      httpd (Web server process) 4182412                      │
│ system_u:system_r:httpd_t:s0 → system_u:object_r:jboss_management_port_t:s0  │
╰──────────────────────────────────────────────────────────────────────────────╯

Events:
• PID 4182412 (httpd) denied 'name_connect' to port 9999 (JBoss management) [Enforcing] ✗ BLOCKED

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

### 🔍 **Advanced Filtering & Sorting**

#### Process-Specific Analysis
```bash
$ python3 parse_avc.py --file testAVC/dontaudit_AVC.log --process unix_chkpwd
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/dontaudit_AVC.log directly

Found 169 AVC events. Displaying 6 unique denials...
Applied filters: process='unix_chkpwd'
Showing 1 of 6 unique denials after filtering.
────────────────────────────── Parsed Log Summary ──────────────────────────────
╭────────────────────────────── Security Notice ───────────────────────────────╮
│                                                                              │
│                         ⚠️  DONTAUDIT RULES DISABLED                          │
│                Enhanced audit mode is active on this system.                 │
│   Typically suppressed permissions detected: noatsecure, rlimitinh, siginh   │
│        This means you're seeing permissions that are normally hidden.        │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

───────── Unique Denial #1 • 6 occurrences • last seen 3 month(s) ago ──────────
╭──────────────────────────────────────────────────────────────────────────────╮
│                         2025-06-18 09:12:51–09:12:51                         │
│                                  Kernel AVC                                  │
│          Denied noatsecure, rlimitinh, siginh on process via execve          │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────╮
│              unix_chkpwd (SSH daemon process) 3636299, 3636300               │
│                  system_u:system_r:sshd_t:s0-s0:c0.c1023 →                   │
│                  system_u:system_r:chkpwd_t:s0-s0:c0.c1023                   │
╰──────────────────────────────────────────────────────────────────────────────╯

Events:
• PID 3636299 (unix_chkpwd) denied 'siginh' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED
• PID 3636299 (unix_chkpwd) denied 'rlimitinh' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED
• PID 3636299 (sshd) denied 'noatsecure' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED
• PID 3636300 (unix_chkpwd) denied 'siginh' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED
• PID 3636300 (unix_chkpwd) denied 'rlimitinh' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED
• PID 3636300 (sshd) denied 'noatsecure' to file /lib64/ld-linux-x86-64.so.2 [Enforcing] ✗ BLOCKED

Analysis Complete: Processed 167 log blocks and found 6 unique denials. Displayed 1 after filtering.
```

#### Path-Based Filtering with Wildcards
```bash
$ python3 parse_avc.py --file testAVC/test_sorting.log --path "/var/www/*"
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/test_sorting.log directly

Found 4 AVC events. Displaying 2 unique denials...
Applied filters: path='/var/www/*'
Showing 2 of 2 unique denials after filtering.
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 3 occurrences • last seen 1 year(s) ago ──────────
[Results showing only /var/www/ path matches...]
```

#### Count-Based Sorting (Most Frequent First)
```bash
$ python3 parse_avc.py --file testAVC/test_sorting.log --sort count
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/test_sorting.log directly

Found 4 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 3 occurrences • last seen 1 year(s) ago ──────────
[Most frequent denial first...]

────────── Unique Denial #2 • 1 occurrences • last seen 1 year(s) ago ──────────
[Less frequent denial second...]
```

#### Combined Filtering and Sorting
```bash
$ python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --path "/var/www/*" --sort count
Applied filters: process='httpd', path='/var/www/*'
Showing 3 of 8 unique denials after filtering.
[Results sorted by frequency, filtered by process and path...]
```

### 📊 **Display Format Options**

#### Enhanced Detailed View (`--detailed`)
```bash
$ python3 parse_avc.py --file testAVC/test_multiple_pids.log --detailed
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/test_multiple_pids.log directly

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

#### Field-by-Field Display (`--fields`)
```bash
$ python3 parse_avc.py --file testAVC/file_context_AVC.log --fields
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

### 🔧 **JSON Output for Automation**

Clean, standardized JSON output with normalized field formats perfect for integration with external tools, SIEM systems, and AI-powered analysis tools.

#### Structured Data Export
```bash
$ python3 parse_avc.py --file testAVC/file_context_AVC.log --json
{
  "unique_denials": [
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
      "permissions": ["read"],
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
  ],
  "summary": {
    "total_events": 1,
    "unique_denials_count": 1,
    "log_blocks_processed": 1
  }
}
```

### 🚨 **Special Detection Features**

#### Enhanced Audit Mode Detection
```bash
$ python3 parse_avc.py --file testAVC/dontaudit_AVC.log
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/dontaudit_AVC.log directly

Found 169 AVC events. Displaying 6 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
╭────────────────────────────── Security Notice ───────────────────────────────╮
│                                                                              │
│                         ⚠️  DONTAUDIT RULES DISABLED                          │
│                Enhanced audit mode is active on this system.                 │
│   Typically suppressed permissions detected: noatsecure, rlimitinh, siginh   │
│        This means you're seeing permissions that are normally hidden.        │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

[Denial analysis continues...]
```

### 📈 **Complex Analysis Patterns**

#### Large-Scale Deduplication
```bash
$ python3 parse_avc.py --raw-file /var/log/audit/audit.log --sort count --fields
Raw file input provided. Running ausearch on '/var/log/audit/audit.log'...

Found 152 AVC events. Displaying 8 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 (89 occurrences, last seen 2 hour(s) ago) ──────────
  Process Name:httpd
  Process ID (PID):12034, 12035, 12036, 12037, 12038, 12039, 12040, 12041, 12042
  [... extensive PID list showing high-volume repeated denials ...]
-----------------------------------
  Permission:read, write, execute
  SELinux Mode:Enforcing
-----------------------------------
  Target Path:/var/www/html/config.php, /var/www/html/data/cache, /var/www/html/uploads
  Target Class:file
-----------------------------------
[Shows intelligent aggregation of related denials...]
```

### 🎯 **Best Practice Examples**

#### Incident Response Workflow
```bash
# 1. Quick overview with recent-first sorting (default)
python3 parse_avc.py --file /var/log/audit/audit.log

# 2. Focus on problematic service
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --sort count

# 3. Investigate specific paths
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --path "/var/www/*" --detailed

# 4. Export findings for documentation
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --json > httpd_denials.json
```

#### Timeline Analysis
```bash
# Chronological analysis for attack progression
python3 parse_avc.py --file /var/log/audit/audit.log --sort chrono --detailed

# Recent activity focus
python3 parse_avc.py --file /var/log/audit/audit.log --sort recent
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-f, --file` | Path to any audit file (auto-detects format) |
| `-rf, --raw-file` | Path to a raw audit.log file |
| `-af, --avc-file` | Path to a pre-processed AVC file |
| `--fields` | Use field-by-field display format (legacy) |
| `--detailed` | Show enhanced detailed view with expanded context |
| `--json` | Output in JSON format |
| `--process` | Filter denials by process name (e.g., `--process httpd`) |
| `--path` | Filter denials by file path with wildcards (e.g., `--path '/var/www/*'`) |
| `--sort` | Sort order: `recent` (default), `count`, or `chrono` |
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

**Current Version**: 1.2.0 | **Current Phase**: 3B-2 (Smart Deduplication Logic)

| Component | Status | Description |
|-----------|--------|-------------|
| **Core Foundation** | ✅ **COMPLETE** | Auto-detection, validation, robust parsing |
| **Semantic Analysis** | ✅ **COMPLETE** | Human-readable permissions, contextual intelligence |
| **Correlation Tracking** | ✅ **COMPLETE** | PID-to-resource mapping, individual event details |
| **Rich Display Format** | ✅ **COMPLETE** | Professional terminal output, responsive design |
| **Code Quality** | ✅ **COMPLETE** | Refactored architecture, maintainable functions |
| **Basic Filtering & Sorting** | ✅ **COMPLETE** | Process, path filtering; recent, count, chrono sorting |
| **dontaudit Detection** | ✅ **COMPLETE** | Automatic detection of enhanced audit mode |
| **Smart Deduplication Logic** | ⏳ **IN PROGRESS** | SELinux remediation-aware signature generation |
| **Advanced Filtering** | ⏳ **PLANNED** | Time range and context filtering |
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
- **Process Targeting**: Use `--process <name>` to focus on specific services during investigation
- **Path Analysis**: Use `--path` with wildcards (`/var/www/*`) to analyze file access patterns
- **Priority Analysis**: Use `--sort count` to identify most frequent denials first
- **Timeline Investigation**: Use `--sort chrono` for chronological attack progression analysis
- **Enhanced Audit Detection**: Look for dontaudit warnings indicating enhanced audit mode

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

**SELinux AVC Denial Analyzer v1.2.0** | Made for forensic analysts and system administrators
