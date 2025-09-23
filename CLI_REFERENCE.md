# SELinux AVC Denial Analyzer - CLI Reference

**Version 1.3.0** | Complete command-line reference, data fields, and troubleshooting guide

This document provides comprehensive reference information for using the SELinux AVC Denial Analyzer from the command line.

## 📋 **Command Line Options**

### Input Options
| Option | Description |
|--------|-------------|
| `-f, --file` | Path to any audit file (auto-detects format) |
| `-rf, --raw-file` | Path to a raw audit.log file |
| `-af, --avc-file` | Path to a pre-processed AVC file |

### Output Format Options
| Option | Description |
|--------|-------------|
| `--fields` | Use field-by-field display format instead of compact Rich format |
| `--detailed` | Show enhanced detailed view with expanded correlation events and context |
| `--json` | Output in JSON format |

### Filtering & Sorting Options
| Option | Description |
|--------|-------------|
| `--process` | Filter denials by process name (e.g., `--process httpd`) |
| `--path` | Filter denials by file path with wildcards (e.g., `--path '/var/www/*'`) |
| `--sort` | Sort order: `recent` (default), `count`, or `chrono` |

### Advanced Options
| Option | Description |
|--------|-------------|
| `--legacy-signatures` | Use legacy signature logic for regression testing (disables smart deduplication) |
| `--expand-groups` | Show individual events instead of resource-based groupings (disables smart event grouping) |
| `-h, --help` | Show help message |

## 🔧 **Command Usage Examples**

### Basic Usage
```bash
# Auto-detect file format
python3 parse_avc.py --file /var/log/audit/audit.log

# Specify file type explicitly
python3 parse_avc.py --raw-file /var/log/audit/audit.log
python3 parse_avc.py --avc-file avc_denials.log
```

### Output Formats
```bash
# Default Rich format (recommended)
python3 parse_avc.py --file audit.log

# Enhanced detailed view
python3 parse_avc.py --file audit.log --detailed

# Field-by-field format
python3 parse_avc.py --file audit.log --fields

# JSON output for automation
python3 parse_avc.py --file audit.log --json
```

### Filtering Options
```bash
# Filter by process name
python3 parse_avc.py --file audit.log --process httpd

# Filter by file path with wildcards
python3 parse_avc.py --file audit.log --path "/var/www/*"

# Combine filters
python3 parse_avc.py --file audit.log --process httpd --path "/var/www/*"
```

### Sorting Options
```bash
# Sort by most recent (default)
python3 parse_avc.py --file audit.log --sort recent

# Sort by event count (most frequent first)
python3 parse_avc.py --file audit.log --sort count

# Sort chronologically (oldest first)
python3 parse_avc.py --file audit.log --sort chrono
```

### Advanced Options
```bash
# Show individual events instead of groups
python3 parse_avc.py --file audit.log --expand-groups

# Use legacy signature logic for testing
python3 parse_avc.py --file audit.log --legacy-signatures

# Complex analysis workflow
python3 parse_avc.py --file audit.log --process httpd --sort count --detailed --json > analysis.json
```

## 📊 **Parsed Data Fields**

### Process Information
- **Timestamp**: When the denial occurred (ISO format or relative time)
- **Process Name (comm)**: Command name from the audit record
- **Process ID (PID)**: Process identifier with event count (e.g., `PID 1234 (3x)`)
- **Process Title (proctitle)**: Full command line if available
- **Executable (exe)**: Path to the executable file
- **Working Directory (cwd)**: Current working directory when denial occurred

### Security Contexts
- **Source Context (scontext)**: SELinux security context of the process
  - Format: `user:role:type:mls_level`
  - Example: `system_u:system_r:httpd_t:s0`
- **Target Context (tcontext)**: SELinux security context of the target object
  - Example: `unconfined_u:object_r:default_t:s0`

### Action Details
- **Denial Type**:
  - `Kernel AVC` - Standard kernel access vector cache denial
  - `Userspace AVC` - Userspace application denial
- **Syscall**: System call that triggered the denial (e.g., `openat`, `connect`)
- **Permission**: Specific permission that was denied with human-readable description
  - Example: `read (Read file content)`
- **SELinux Mode**:
  - `Enforcing` - Denial was blocked (✗ BLOCKED)
  - `Permissive` - Denial was logged but allowed (✓ ALLOWED)

### Target Information
- **Target Path**: File or directory path that was accessed
- **Target Port**: Network port number (for socket denials)
  - Includes port description when available (e.g., `9999 (JBoss management)`)
- **D-Bus Destination**: D-Bus connection identifier (for D-Bus denials)
- **Socket Address (saddr)**: Network address information
- **Target Class (tclass)**: Object class type
  - `file`, `dir`, `socket`, `tcp_socket`, `udp_socket`, `dbus`, `process`, etc.

### Correlation Data
- **Event Count**: Number of similar events grouped together
- **PIDs Involved**: List of process IDs that generated these denials
- **Time Range**: First seen to last seen timestamps
- **Permissions List**: All permissions denied in this group

## 🔍 **Data Field Examples**

### Rich Format Display
```
• PID 1234 (3x) (httpd (Web server process))
  denied 'read' to file /var/www/html/config.php [Enforcing] ✗ BLOCKED
```

### Fields Format Display
```
Timestamp: 2024-09-05 02:18:01
Process Name: httpd (Web server process)
Process ID (PID): 1234
Executable: /usr/sbin/httpd
Working Dir (CWD): /
Source Context: system_u:system_r:httpd_t:s0
-----------------------------------
Action: Denied
Denial Type: Kernel AVC
Syscall: openat
Permission: read (Read file content)
SELinux Mode: Enforcing
-----------------------------------
Target Path: /var/www/html/config.php
Target Class: file
Target Context: unconfined_u:object_r:default_t:s0 (Default file context)
```

### JSON Format Structure
```json
{
  "unique_denials": [
    {
      "log": {
        "datetime_str": "2024-09-05 02:18:01",
        "timestamp": "1725482881.101",
        "syscall": "openat",
        "exe": "/usr/sbin/httpd",
        "cwd": "/",
        "path": "/var/www/html/config.php",
        "denial_type": "AVC",
        "permission": "read",
        "pid": "1234",
        "comm": "httpd",
        "scontext": "system_u:system_r:httpd_t:s0",
        "tcontext": "unconfined_u:object_r:default_t:s0",
        "tclass": "file",
        "permissive": "0"
      },
      "count": 3,
      "permissions": ["read"],
      "correlations": [
        {
          "pid": "1234",
          "comm": "httpd",
          "path": "/var/www/html/config.php",
          "permission": "read",
          "permissive": "0",
          "timestamp": "2024-09-05 02:18:01"
        }
      ]
    }
  ]
}
```

## 💡 **Tips & Troubleshooting**

### Performance Optimization
- **Large Files**: For audit.log files >100MB, consider using `ausearch` to pre-filter by time range:
  ```bash
  ausearch -m AVC -ts today | python3 parse_avc.py
  ```
- **Memory Usage**: Use `--json` output for processing large datasets programmatically
- **Large Outputs**: Use pipe redirection for easier navigation:
  ```bash
  python3 parse_avc.py --file audit.log | less
  ```

### Common Issues & Solutions

#### Permission Denied
**Problem**: Cannot read audit files
**Solution**:
```bash
# Ensure read access (may require sudo)
sudo python3 parse_avc.py --file /var/log/audit/audit.log

# Or copy file to accessible location
sudo cp /var/log/audit/audit.log ~/audit.log
python3 parse_avc.py --file ~/audit.log
```

#### Missing ausearch Command
**Problem**: `ausearch` command not found
**Solution**:
```bash
# Install audit package
sudo dnf install audit      # Fedora/RHEL/CentOS
sudo apt install auditd     # Ubuntu/Debian
sudo zypper install audit   # openSUSE
```

#### Empty Output
**Problem**: No denials found in audit logs
**Diagnosis**:
```bash
# Check if SELinux is enabled
sestatus

# Check if audit logging is active
sudo systemctl status auditd

# Check recent audit log activity
sudo tail /var/log/audit/audit.log
```

#### Pipe Errors
**Problem**: BrokenPipeError when using `| head` or `| less`
**Status**: This will be fixed in Phase 4B (User Experience Enhancements)
**Workaround**:
```bash
# Use file redirection instead
python3 parse_avc.py --file audit.log > output.txt
head output.txt
```

### Best Practices

#### Incident Analysis Workflow
1. **Quick Overview**: Start with default Rich format
   ```bash
   python3 parse_avc.py --file audit.log
   ```

2. **Identify Patterns**: Use count sorting to find frequent denials
   ```bash
   python3 parse_avc.py --file audit.log --sort count
   ```

3. **Focus Investigation**: Filter by problematic service
   ```bash
   python3 parse_avc.py --file audit.log --process httpd --sort count
   ```

4. **Detailed Analysis**: Use detailed view for context
   ```bash
   python3 parse_avc.py --file audit.log --process httpd --detailed
   ```

5. **Documentation**: Export findings to JSON
   ```bash
   python3 parse_avc.py --file audit.log --process httpd --json > findings.json
   ```

#### Automation & Integration
- **SIEM Integration**: Use `--json` output for structured data
- **Monitoring Scripts**: Combine with `ausearch` for recent activity
- **Reporting**: Use `--fields` format for detailed reports

#### Time-Based Analysis
```bash
# Create filtered audit log for specific time period
ausearch -m AVC -ts today > today_avc.log
python3 parse_avc.py --file today_avc.log

# Analyze recent activity (last hour)
ausearch -m AVC -ts recent > recent_avc.log
python3 parse_avc.py --file recent_avc.log --sort recent
```

#### Path Pattern Analysis
```bash
# Web server file access patterns
python3 parse_avc.py --file audit.log --path "/var/www/*"

# System configuration access
python3 parse_avc.py --file audit.log --path "/etc/*"

# User home directory access
python3 parse_avc.py --file audit.log --path "/home/*"

# Container or temporary file access
python3 parse_avc.py --file audit.log --path "/tmp/*" --path "/var/lib/containers/*"
```

#### Priority Analysis Strategies
- **Security-First**: Use `--sort count` to identify most frequent denials
- **Timeline-First**: Use `--sort chrono` for attack progression analysis
- **Recent-First**: Use `--sort recent` (default) for current activity focus
- **Service-Specific**: Combine process filtering with count sorting

### Enhanced Audit Detection
Look for these indicators in the output:
- **dontaudit warnings**: System showing normally suppressed permissions
- **Permissive mode notices**: Events allowed despite policy violations
- **High event counts**: PIDs with `(10x)` or higher indicating repeated access attempts
- **Unusual paths**: Access to system directories or sensitive files
- **Network denials**: Unexpected service-to-service communication attempts

## 🔗 **Related Documentation**

- **[README.md](README.md)** - Installation and getting started
- **[EXAMPLES.md](EXAMPLES.md)** - Comprehensive usage examples
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap and planned features
- **[FEATURE_DECISIONS.md](FEATURE_DECISIONS.md)** - Feature scope and architectural decisions

---

**SELinux AVC Denial Analyzer v1.3.0** | Made for forensic analysts and system administrators