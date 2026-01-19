# SELinux AVC Denial Analyzer - CLI Reference

**Version 1.8.1** | Complete command-line reference, data fields, and troubleshooting guide with Extended Audit Record Support, Context-Aware Analysis, Smart Path Normalization, Exit Code Translation, Two-Tier Professional Report System, and SELinux Policy Investigation Integration

This document provides comprehensive reference information for using the SELinux AVC Denial Analyzer from the command line.

> **📝 Command Format**: Examples use `avc-parser` assuming you've installed the wrapper via `make install-wrapper`. If you haven't, replace `avc-parser` with `avc-parser` in all commands.

> **🎯 Production Ready v1.8.1**: Setroubleshoot-based optimizations with smart path normalization (security-aware), exit code translation, sophisticated PATH record matching, and Python 3.9+ compatibility. Built on Phase 11 foundation with extended audit record support (FANOTIFY, SELINUX_ERR, MAC_POLICY_LOAD), context-aware permission descriptions, enhanced detailed view, modern development tooling (ruff, pytest, coverage), and comprehensive testing (169 tests).

> **🔧 Advanced Filtering**: The tool includes powerful time range and SELinux context filtering capabilities for sophisticated forensic analysis. See the [Advanced Filtering Examples](#advanced-filtering-examples) section for detailed usage patterns.

## 📋 **Command Line Options**

### Input Options
| Option | Description |
|--------|-------------|
| `-f, --file` | Path to any audit file (auto-detects format) |
| `-rf, --raw-file` | Path to a raw audit.log file |
| `-af, --avc-file` | Path to a pre-processed AVC file |

### Display Mode Options (Mutually Exclusive)
| Mode | Description | Compatible Modifiers |
|------|-------------|----------------------|
| **Default Rich** | Professional terminal display with panels and colors | `--detailed`, `--pager` |
| `--report [brief\|sealert]` | Professional text formats: `brief` (executive summaries), `sealert` (technical analysis) | `--pager` |
| `--fields` | Field-by-field technical breakdown for deep-dive analysis | `--pager` |
| `--json` | Machine-readable structured output | Works with all filtering options |

**Precedence Order**: `--json` > `--fields` > `--report [format]` > Default Rich

### Display Modifiers (Work with Compatible Modes)
| Modifier | Description | Compatible With |
|----------|-------------|-----------------|
| `--detailed` | Enhanced view with expanded correlation events and context | Default Rich mode only |
| `--pager` | Interactive pager for large outputs (like 'less' command) | All display modes |

### Filtering & Sorting Options
| Option | Description |
|--------|-------------|
| `--process` | Filter denials by process name (e.g., `--process httpd`) |
| `--path` | Filter denials by file path with wildcards (e.g., `--path '/var/www/*'`) |
| `--since` | Only include denials since this time (e.g., `--since yesterday`, `--since '2025-01-15'`) |
| `--until` | Only include denials until this time (e.g., `--until today`, `--until '2025-01-15 14:30'`) |
| `--source` | Filter by source context pattern (e.g., `--source httpd_t`, `--source '*unconfined*'`) |
| `--target` | Filter by target context pattern (e.g., `--target default_t`, `--target '*var_lib*'`) |
| `--sort` | Sort order: `recent` (default), `count`, or `chrono` |

### Advanced Options
| Option | Description |
|--------|-------------|
| `--legacy-signatures` | Use legacy signature logic for regression testing (disables smart deduplication) |
| `-v, --verbose` | Enable verbose output for debugging and troubleshooting |
| `--stats` | Display summary statistics only (quick overview without full output) |
| `--pager` | Use interactive pager for large outputs (like 'less' command) - only works in terminal environments |
| `-h, --help` | Show help message |

## 🔧 **Command Usage Examples**

### Basic Usage
```bash
# Auto-detect file format
avc-parser --file /var/log/audit/audit.log

# Specify file type explicitly
avc-parser --raw-file /var/log/audit/audit.log
avc-parser --avc-file avc_denials.log
```

### Display Mode Examples
```bash
# Default Rich format (professional terminal display)
avc-parser --file audit.log

# Enhanced detailed view (Rich + more correlation details)
avc-parser --file audit.log --detailed

# Professional report formats
avc-parser --file audit.log --report        # Brief format (executive summaries)
avc-parser --file audit.log --report brief  # Brief format (explicit)
avc-parser --file audit.log --report sealert # Technical analysis format

# Field-by-field format (technical deep-dive)
avc-parser --file audit.log --fields

# JSON output (automation/integration)
avc-parser --file audit.log --json
```

### Display Modifier Examples
```bash
# Rich mode with detailed view
avc-parser --file audit.log --detailed

# Interactive pager (works with all modes)
avc-parser --file audit.log --pager
avc-parser --file audit.log --report --pager         # Brief + pager
avc-parser --file audit.log --report sealert --pager # Sealert + pager
avc-parser --file audit.log --fields --pager
```

### Argument Combination Rules
```bash
# Valid Rich mode combinations
avc-parser --file audit.log --detailed --pager

# Standalone modes (no meaningful modifiers except --pager)
avc-parser --file audit.log --report brief --pager
avc-parser --file audit.log --report sealert --pager
avc-parser --file audit.log --fields --pager

# JSON with filtering (works with any filter combination)
avc-parser --file audit.log --json --process httpd --since yesterday

# Precedence examples (higher precedence wins, modifiers ignored)
avc-parser --file audit.log --report sealert --fields  # Uses --fields
avc-parser --file audit.log --json --detailed          # Uses --json
```

### Filtering Options
```bash
# Filter by process name
avc-parser --file audit.log --process httpd

# Filter by file path with wildcards
avc-parser --file audit.log --path "/var/www/*"

# Filter by time range
avc-parser --file audit.log --since yesterday
avc-parser --file audit.log --since "2025-01-15" --until "2025-01-16"
avc-parser --file audit.log --since "2 hours ago"

# Filter by SELinux context
avc-parser --file audit.log --source httpd_t
avc-parser --file audit.log --target "*default*"
avc-parser --file audit.log --source "*unconfined*" --target "var_lib_t"

# Combine multiple filters
avc-parser --file audit.log --process httpd --path "/var/www/*" --since yesterday --source httpd_t
```

### Sorting Options
```bash
# Sort by most recent (default)
avc-parser --file audit.log --sort recent

# Sort by event count (most frequent first)
avc-parser --file audit.log --sort count

# Sort chronologically (oldest first)
avc-parser --file audit.log --sort chrono
```

### Advanced Options
```bash
# Get quick summary statistics
avc-parser --file audit.log --stats

# Enable verbose debugging output
avc-parser --file audit.log --verbose

# Combine verbose with filtering for troubleshooting
avc-parser --file audit.log --verbose --process httpd

# Use interactive pager for large outputs
avc-parser --file audit.log --pager

# Combine pager with detailed view for comprehensive analysis
avc-parser --file audit.log --pager --detailed

# Use pager with filtering for focused review
avc-parser --file audit.log --pager --process httpd --since yesterday

# Use legacy signature logic for testing
avc-parser --file audit.log --legacy-signatures

# Complex analysis workflow
avc-parser --file audit.log --process httpd --sort count --detailed --json > analysis.json
```

## 🎯 **Advanced Filtering Examples**

### Time Range Filtering
```bash
# Recent activity analysis
avc-parser --file audit.log --since yesterday --sort count

# Specific incident timeframe
avc-parser --file audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00"

# Relative time specifications
avc-parser --file audit.log --since "2 hours ago" --detailed
```

### SELinux Context Filtering
```bash
# Source context analysis
avc-parser --file audit.log --source httpd_t --since yesterday

# Target context with wildcards
avc-parser --file audit.log --target "*default*" --sort count

# Combined context filtering
avc-parser --file audit.log --source "*unconfined*" --target "var_lib_t"
```

### Multi-Criteria Forensic Analysis
```bash
# Comprehensive incident investigation
avc-parser --file audit.log --process httpd --path "/var/www/*" --since yesterday --source httpd_t --sort count

# Security anomaly detection
avc-parser --file audit.log --source "*unconfined*" --since "1 week ago" --detailed

# Time-bounded context analysis
avc-parser --file audit.log --since "2025-01-15 08:00" --until "2025-01-15 18:00" --target "*shadow*" --sort chrono
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
  - `Kernel AVC` - Standard kernel access vector cache denial (AVC)
  - `Userspace AVC` - Userspace application denial (USER_AVC)
  - `File Access Notification` - FANOTIFY denial
  - `Kernel Security Error` - SELinux error (SELINUX_ERR, USER_SELINUX_ERR)
  - `Policy Reload` - MAC_POLICY_LOAD event (informational)
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

### Time Specifications (--since, --until)
- **Relative Keywords**:
  - `now` - Current time
  - `today` - Beginning of today (00:00:00)
  - `yesterday` - Beginning of yesterday (00:00:00)
  - `recent` - Last hour
- **"X ago" Patterns**:
  - `2 hours ago`, `3 days ago`, `1 week ago`, `2 months ago`, `1 year ago`
  - Supports: seconds, minutes, hours, days, weeks, months, years
- **Explicit Date/Time Formats**:
  - `2025-01-15` (assumes 00:00:00)
  - `2025-01-15 14:30` or `2025-01-15 14:30:45`
  - `01/15/2025` or `01/15/2025 14:30` (US format)
  - `15/01/2025` or `15/01/2025 14:30` (European format)

### Context Pattern Matching (--source, --target)
- **Direct Match**: `httpd_t` matches any context containing `httpd_t`
- **Wildcard Patterns**: `*unconfined*` matches contexts containing "unconfined"
- **Component Matching**: Pattern without colons matches individual context components
- **Case Insensitive**: All matching is case-insensitive for better usability
- **Examples**:
  - `--source httpd_t` matches `system_u:system_r:httpd_t:s0`
  - `--target "*default*"` matches `unconfined_u:object_r:default_t:s0`
  - `--source "system_r"` matches the role component

### Process Name Resolution
The tool uses an intelligent fallback hierarchy to determine process names:
1. **Primary**: `comm` field (direct command name from audit record)
2. **Secondary**: `exe` field (extracts filename from executable path like `/usr/bin/httpd` → `httpd`)
3. **Tertiary**: `proctitle` field (extracts command from process title, cleans suffixes like `nginx:` → `nginx`)

This ensures meaningful process names appear in analysis instead of "unknown" values.

### Timezone Limitations
- **Current Limitation**: The tool uses system timezone for timestamp interpretation
- **ausearch Integration**: Timezone environment variables (TZ=) are not currently passed to ausearch subprocess
- **Workaround**: Run the tool in the desired timezone environment: `TZ="Asia/Kolkata" avc-parser --file audit.log`
- **Planned Enhancement**: Native timezone support in Phase 4B-3

## 🛠️ **Debugging and Troubleshooting**

### Quick Summary with --stats
Get an instant overview of a log file without viewing full details:
```bash
avc-parser --file audit.log --stats
```

Output includes:
- Total events and unique denials
- Time range of activity
- Top processes causing denials
- Top permissions denied
- Security notices (dontaudit, permissive mode)
- Next steps suggestions

**Use Case**: Quickly assess log severity before deep-dive analysis.

### Verbose Debugging with --verbose
Enable debug output to troubleshoot unexpected results:
```bash
avc-parser --file audit.log --verbose
```

Verbose output shows:
- Number of log blocks detected and parsed
- Parsing success rate (e.g., "Successfully parsed 877 AVC denials from 620 valid blocks")
- Grouping statistics ("Created 202 unique denial groups from 877 total events")
- Filtering details ("Filtering: 201 denials filtered out, 1 remaining")

**Use Case**: Diagnose why filters aren't matching, understand parsing behavior, or report issues.

### Empty Filter Results
When filters produce no matches, you'll see helpful guidance:
```
⚠️  No denials matched your filter criteria

You filtered for:
  • process='nonexistent'

But found 0 matches out of 202 total denials.

💡 Suggestions:
  • Remove filters to see all denials: avc-parser --file audit.log
  • Check available process names: avc-parser --file audit.log | grep 'PID'
  • Try wildcard patterns: --process '*nonex*'
```

**Use Case**: Quickly correct filter typos or understand what's in the log.

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

> **🔬 Enhanced JSON Normalization**: Comprehensive field normalization, two-tier report system, and SELinux policy investigation commands for reliable tool integration, SIEM compatibility, and automated analysis workflows.

#### Core Structure
```json
{
  "unique_denials": [
    {
      "log": {
        // Original parsed fields
        "datetime_str": "2024-09-05 02:18:01",
        "timestamp": 1725482881.101,
        "syscall": "openat",
        "exe": "/usr/sbin/httpd",
        "cwd": "/",
        "path": "/var/www/html/config.php",
        "denial_type": "AVC",
        "permission": "read",
        "pid": 1234,
        "comm": "httpd",
        "scontext": "system_u:system_r:httpd_t:s0",
        "tcontext": "unconfined_u:object_r:default_t:s0",
        "tclass": "file",
        "permissive": false,

        // Enhanced normalized fields
        "path_absolute": "/var/www/html/config.php",
        "path_normalized": true,
        "scontext_components": {
          "user": "system_u",
          "role": "system_r",
          "type": "httpd_t",
          "level": "s0",
          "full": "system_u:system_r:httpd_t:s0"
        },
        "scontext_type": "httpd_t",
        "tcontext_components": {
          "user": "unconfined_u",
          "role": "object_r",
          "type": "default_t",
          "level": "s0",
          "full": "unconfined_u:object_r:default_t:s0"
        },
        "tcontext_type": "default_t",
        "permissive_numeric": 0,
        "timestamp_float": 1725482881.101,
        "_normalized": true,
        "_normalization_version": "1.0"
      },
      "count": 3,
      "permissions": ["read"],
      "correlations": [
        {
          // Correlations also include normalized fields
          "pid": 1234,
          "comm": "httpd",
          "path": "/var/www/html/config.php",
          "permission": "read",
          "permissive": false,
          "timestamp": "2024-09-05 02:18:01",
          "path_absolute": "/var/www/html/config.php",
          "path_normalized": true,
          "permissive_numeric": 0,
          "_normalized": true
        }
      ],
      "first_seen": "2024-09-05T02:18:01",
      "last_seen": "2024-09-05T02:18:01"
    }
  ],
  "summary": {
    "total_events": 3,
    "unique_denials_count": 1,
    "log_blocks_processed": 1
  }
}
```

#### Network Denial Example (with Port Normalization)
```json
{
  "log": {
    "dest_port": 8080,
    "dest_port_string": "8080",
    "dest_port_type": "numeric",
    "dest_port_class": "registered",
    "saddr_components": {
      "laddr": "192.168.1.100",
      "lport": "8080"
    },
    "local_address": "192.168.1.100",
    "local_port": 8080
  }
}
```

#### Normalization Features
- **Path Standardization**: Absolute paths with consistent separators (`path_absolute`, `path_normalized`)
- **Port Classification**: Numeric conversion with system/registered/dynamic classification
- **SELinux Context Parsing**: Component extraction (`user`, `role`, `type`, `level`) for easy filtering
- **Data Type Consistency**: Proper boolean/numeric types instead of strings
- **Metadata Tracking**: Normalization version and status for tool compatibility

## 💡 **Tips & Troubleshooting**

### Performance Optimization
- **Large Files**: For audit.log files >100MB, consider using `ausearch` to pre-filter by time range:
  ```bash
  ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR,MAC_POLICY_LOAD -ts today | avc-parser
  ```
- **Memory Usage**: Use `--json` output for processing large datasets programmatically
- **Large Outputs**: Use pipe redirection for easier navigation:
  ```bash
  avc-parser --file audit.log | less
  ```

### Common Issues & Solutions

#### Permission Denied
**Problem**: Cannot read audit files
**Solution**:
```bash
# Ensure read access (may require sudo)
sudo avc-parser --file /var/log/audit/audit.log

# Or copy file to accessible location
sudo cp /var/log/audit/audit.log ~/audit.log
avc-parser --file ~/audit.log
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

#### Pipe Compatibility
**Status**: ✅ **FIXED** - Pipe operations now work correctly
**Usage**:
```bash
# All standard pipe operations work seamlessly
avc-parser --file audit.log | head -10
avc-parser --file audit.log | less
avc-parser --file audit.log | grep "httpd"
avc-parser --file audit.log | wc -l
```

### Best Practices

#### Incident Analysis Workflow
1. **Quick Overview**: Start with default Rich format
   ```bash
   avc-parser --file audit.log
   ```

2. **Identify Patterns**: Use count sorting to find frequent denials
   ```bash
   avc-parser --file audit.log --sort count
   ```

3. **Focus Investigation**: Filter by problematic service with time bounds
   ```bash
   avc-parser --file audit.log --process httpd --since yesterday --sort count
   ```

4. **Context Analysis**: Filter by SELinux contexts for targeted investigation
   ```bash
   avc-parser --file audit.log --source httpd_t --target "*default*" --detailed
   ```

5. **Time-Bounded Analysis**: Investigate specific incident timeframes
   ```bash
   avc-parser --file audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00" --sort chrono
   ```

6. **Documentation**: Export findings with complete filter context
   ```bash
   avc-parser --file audit.log --process httpd --since yesterday --json > incident_analysis.json
   ```

#### Automation & Integration
- **SIEM Integration**: Use `--json` output for structured data
- **Monitoring Scripts**: Combine with `ausearch` for recent activity
- **Reporting**: Use `--fields` format for detailed reports

#### Time-Based Analysis
```bash
# Create filtered audit log for specific time period
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR,MAC_POLICY_LOAD -ts today > today_avc.log
avc-parser --file today_avc.log

# Analyze recent activity (last hour)
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR,MAC_POLICY_LOAD -ts recent > recent_avc.log
avc-parser --file recent_avc.log --sort recent
```

#### Path Pattern Analysis
```bash
# Web server file access patterns
avc-parser --file audit.log --path "/var/www/*"

# System configuration access
avc-parser --file audit.log --path "/etc/*"

# User home directory access
avc-parser --file audit.log --path "/home/*"

# Container or temporary file access
avc-parser --file audit.log --path "/tmp/*" --path "/var/lib/containers/*"
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

**SELinux AVC Denial Analyzer v1.8.1** | Made for forensic analysts and system administrators