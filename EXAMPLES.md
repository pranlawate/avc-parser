# SELinux AVC Denial Analyzer - Examples & Usage Patterns

**Version 1.3.0** | Comprehensive examples and usage patterns for the SELinux AVC Denial Analyzer

This document demonstrates the tool's capabilities with real examples, organized from basic to advanced usage patterns.

> **💡 Key Feature**: Notice how PID event counts are shown in the default compact view - `PID 1234 (3x)` indicates this PID generated 3 events, while `PID 5678` (no count) means only 1 event. This provides immediate correlation insight without expanding details.

## 🎯 **Basic Usage Examples**

### Simple File Analysis
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

### Multiple Events Analysis (PID Count Feature Demo)
```bash
$ python3 parse_avc.py --file testAVC/test_sorting.log
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/test_sorting.log directly

Found 4 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 • 3 occurrences • last seen 1 year(s) ago ──────────
           ╭────────────────────────────────────────────────────────╮
           │       2024-09-05 02:18:01–02:18:04 • Kernel AVC        │
           │   Denied read (Read file content) on file via openat   │
           ╰────────────────────────────────────────────────────────╯
          ╭──────────────────────────────────────────────────────────╮
          │            system_u:system_r:httpd_t:s0 →                │
          │            unconfined_u:object_r:default_t:s0            │
          ╰──────────────────────────────────────────────────────────╯

Events:
• PID 1234 (3x) (httpd (Web server process))
  denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED

────────── Unique Denial #2 • 1 occurrences • last seen 1 year(s) ago ──────────
Events:
• PID 5678 (nginx)
  denied 'read' to file /var/www/html/file2.html [Enforcing] ✗ BLOCKED

Analysis Complete: Processed 4 log blocks and found 2 unique denials.
```

### Network Denial Analysis
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

## 🔍 **Advanced Filtering & Sorting**

### Process-Specific Analysis
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

### Path-Based Filtering with Wildcards
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

### Count-Based Sorting (Most Frequent First)
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

### Combined Filtering and Sorting
```bash
$ python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --path "/var/www/*" --sort count
Applied filters: process='httpd', path='/var/www/*'
Showing 3 of 8 unique denials after filtering.
[Results sorted by frequency, filtered by process and path...]
```

## 📊 **Display Format Options**

### Enhanced Detailed View (`--detailed`)
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

### Field-by-Field Display (`--fields`)
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

## 🔧 **JSON Output for Automation**

Clean, standardized JSON output with normalized field formats perfect for integration with external tools, SIEM systems, and AI-powered analysis tools.

### Structured Data Export
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

## 🚨 **Special Detection Features**

### Enhanced Audit Mode Detection
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

## 📈 **Complex Analysis Patterns**

### Large-Scale Deduplication
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

## 🎯 **Best Practice Examples**

### Incident Response Workflow
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

### Timeline Analysis
```bash
# Chronological analysis for attack progression
python3 parse_avc.py --file /var/log/audit/audit.log --sort chrono --detailed

# Recent activity focus
python3 parse_avc.py --file /var/log/audit/audit.log --sort recent

# Detailed individual event analysis (disable grouping)
python3 parse_avc.py --file /var/log/audit/audit.log --expand-groups --detailed
```

## 💡 **Advanced Usage Tips**

### Performance Optimization
- **Large Files**: For audit.log files >100MB, consider using `ausearch` to pre-filter by time range
- **Memory Usage**: Use `--json` output for processing large datasets programmatically
- **Large Outputs**: Use pipe redirection for easier navigation: `python3 parse_avc.py --file audit.log | less`

### Pipe Operations (✅ Fixed in v1.3.0)
```bash
# View first few lines of output
python3 parse_avc.py --file audit.log | head -10

# Page through large outputs
python3 parse_avc.py --file audit.log | less

# Filter output for specific content
python3 parse_avc.py --file audit.log | grep "httpd"

# Count total lines of output
python3 parse_avc.py --file audit.log | wc -l

# Extract just PID information
python3 parse_avc.py --file audit.log | grep "PID"
```

### Best Practices
- **Incident Analysis**: Start with Rich format for overview, use `--fields` for detailed investigation
- **Automation**: Use `--json` output for integration with SIEM tools or custom scripts
- **Time Ranges**: Use `ausearch -ts` to filter logs by time before analysis
- **Process Targeting**: Use `--process <name>` to focus on specific services during investigation
- **Path Analysis**: Use `--path` with wildcards (`/var/www/*`) to analyze file access patterns
- **Priority Analysis**: Use `--sort count` to identify most frequent denials first
- **Timeline Investigation**: Use `--sort chrono` for chronological attack progression analysis
- **Enhanced Audit Detection**: Look for dontaudit warnings indicating enhanced audit mode

---

📊 **Related Documentation**:
- [README.md](README.md) - Installation and getting started
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Complete command reference
- [ROADMAP.md](ROADMAP.md) - Development roadmap and features
- [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) - Feature scope and decisions

**SELinux AVC Denial Analyzer v1.3.0** | Made for forensic analysts and system administrators