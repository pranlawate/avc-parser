# SELinux AVC Denial Analyzer - Examples & Usage Patterns

**Version 1.8.0** | Comprehensive examples and usage patterns for the SELinux AVC Denial Analyzer with Extended Audit Record Support (FANOTIFY, SELINUX_ERR, MAC_POLICY_LOAD), Context-Aware Analysis, Smart Path Normalization, Exit Code Translation, Two-Tier Professional Report System, and SELinux Policy Investigation Integration

This document demonstrates the tool's capabilities with real examples, organized from basic to advanced usage patterns.

> **🎯 New Advanced Filtering**: The tool now includes comprehensive time range and SELinux context filtering for forensic analysis. Jump to [Advanced Filtering Examples](#advanced-time-range-filtering) to see the powerful new capabilities in action.

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

### Advanced Time Range Filtering
```bash
# Filter by relative time
$ python3 parse_avc.py --file /var/log/audit/audit.log --since yesterday
Applied filters: since='yesterday'
Showing 15 of 45 unique denials after filtering.

# Filter by specific date range
$ python3 parse_avc.py --file /var/log/audit/audit.log --since "2025-01-15" --until "2025-01-16"
Applied filters: since='2025-01-15', until='2025-01-16'
Showing 8 of 45 unique denials after filtering.

# Filter by recent activity
$ python3 parse_avc.py --file /var/log/audit/audit.log --since "2 hours ago"
Applied filters: since='2 hours ago'
Showing 3 of 45 unique denials after filtering.
```

### SELinux Context Filtering
```bash
# Filter by source context type
$ python3 parse_avc.py --file /var/log/audit/audit.log --source httpd_t
Applied filters: source='httpd_t'
Showing 12 of 45 unique denials after filtering.

# Filter by target context with wildcards
$ python3 parse_avc.py --file /var/log/audit/audit.log --target "*default*"
Applied filters: target='*default*'
Showing 8 of 45 unique denials after filtering.

# Filter by both source and target contexts
$ python3 parse_avc.py --file /var/log/audit/audit.log --source "*unconfined*" --target "var_lib_t"
Applied filters: source='*unconfined*', target='var_lib_t'
Showing 3 of 45 unique denials after filtering.
```

### Combined Advanced Filtering
```bash
# Comprehensive incident analysis
$ python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --path "/var/www/*" --since yesterday --source httpd_t --sort count
Applied filters: process='httpd', path='/var/www/*', since='yesterday', source='httpd_t'
Showing 5 of 45 unique denials after filtering.

# Security investigation with time boundaries
$ python3 parse_avc.py --file /var/log/audit/audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00" --target "*sensitive*" --sort chrono
Applied filters: since='2025-01-15 09:00', until='2025-01-15 17:00', target='*sensitive*'
Showing 2 of 45 unique denials after filtering.
```

## 🔧 **Process Name Resolution Examples**

### Improved Contextual Analysis
The tool now uses actual process names instead of SELinux type descriptions in contextual analysis:

```bash
# Example with missing comm field - falls back to exe
$ echo 'type=AVC msg=audit(01/15/2025 14:30:00.123:456): avc: denied { read } for pid=1234 exe="/usr/bin/nginx" path="/etc/passwd" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=0' | python3 parse_avc.py --detailed

• PID 1234 (nginx) [/usr/bin/nginx]
  denied 'read' to file /etc/passwd [Enforcing] ✗ BLOCKED
  └─ Analysis: nginx attempting to read file content    # ✅ Uses actual process name

# Example with proctitle fallback
$ echo 'type=AVC msg=audit(01/15/2025 14:30:00.123:456): avc: denied { read } for pid=1234 proctitle="mongod --config /etc/mongod.conf" path="/var/log/audit.log" scontext=system_u:system_r:mongod_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0' | python3 parse_avc.py --detailed

• PID 1234 (mongod)
  denied 'read' to file /var/log/audit.log [Enforcing] ✗ BLOCKED
  └─ Analysis: mongod attempting to read file content   # ✅ Uses actual process name from proctitle
```

**Process Name Resolution Hierarchy:**
1. **comm** field (if available) → `httpd`
2. **exe** field → `/usr/bin/nginx` → `nginx`
3. **proctitle** field → `mongod --config /etc/mongod.conf` → `mongod`

This provides more precise and user-friendly analysis output compared to generic SELinux type descriptions.

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

# 2. Focus on recent activity (last 24 hours)
python3 parse_avc.py --file /var/log/audit/audit.log --since yesterday --sort count

# 3. Focus on problematic service with time constraints
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --since "2 hours ago" --sort count

# 4. Investigate specific paths and contexts
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --path "/var/www/*" --source httpd_t --detailed

# 5. Export findings for documentation
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --since yesterday --json > incident_analysis.json
```

### Advanced Security Investigation
```bash
# 1. Identify unusual source contexts
python3 parse_avc.py --file /var/log/audit/audit.log --source "*unconfined*" --since "1 week ago" --sort count

# 2. Monitor sensitive target contexts
python3 parse_avc.py --file /var/log/audit/audit.log --target "*shadow*" --since yesterday
python3 parse_avc.py --file /var/log/audit/audit.log --target "*passwd*" --since yesterday

# 3. Time-bounded security analysis
python3 parse_avc.py --file /var/log/audit/audit.log --since "2025-01-15 08:00" --until "2025-01-15 18:00" --sort chrono

# 4. Cross-reference process and context anomalies
python3 parse_avc.py --file /var/log/audit/audit.log --process "*" --source "*unconfined*" --since "3 days ago" --detailed
```

### Timeline Analysis
```bash
# Chronological analysis for attack progression
python3 parse_avc.py --file /var/log/audit/audit.log --sort chrono --detailed

# Recent activity focus
python3 parse_avc.py --file /var/log/audit/audit.log --sort recent

# Detailed individual event analysis (disable grouping)
python3 parse_avc.py --file /var/log/audit/audit.log --detailed
```

## 🛠️ **Debugging and Troubleshooting**

### Quick Summary with --stats
Get an instant overview without viewing full details:
```bash
$ python3 parse_avc.py --file testAVC/tpm-enforcing.log --stats

📊 SELinux AVC Log Summary
═══════════════════════════════════════════════════════════════════════════════
File:              testAVC/tpm-enforcing.log (698.4 KB)
Total Events:      877
Unique Denials:    202
Blocks Processed:  620
Time Range:        2025-11-01 22:08:25 to 2025-11-01 22:34:16 (25 minutes)

Top Processes:
  1. sudo                 (504 events)
  2. unix_chkpwd          (59 events)
  3. cryptsetup           (52 events)

Top Source Contexts:
  1. staff_sudo_t         (528 events)
  2. sysadm_t             (96 events)
  3. firewalld_t          (69 events)

Security Notices:
  ⚠️  DONTAUDIT RULES DISABLED (enhanced audit mode)

💡 Next Steps:
  • View all denials:     python3 parse_avc.py --file testAVC/tpm-enforcing.log
  • Focus on sudo:        python3 parse_avc.py --file testAVC/tpm-enforcing.log --process sudo
  • Export to JSON:       python3 parse_avc.py --file testAVC/tpm-enforcing.log --json
```

**Use Case**: Triage logs quickly to decide if deep analysis is needed.

### Verbose Debugging with --verbose
Troubleshoot unexpected results with debug output:
```bash
$ python3 parse_avc.py --file testAVC/file_context_AVC.log --verbose

→ Debug: Split input into 1 log blocks
→ Debug: Parsing 1 log blocks
→ Debug: Successfully parsed 1 AVC denials from 1 valid blocks
→ Debug: Created 1 unique denial groups from 1 total events
🔍 Auto-detected: Pre-processed format
   Will parse the file testAVC/file_context_AVC.log directly

Found 1 AVC events. Displaying 1 unique denials...
[... normal output continues ...]
```

**Use Case**: Diagnose why filters aren't matching or report issues with detailed context.

### Combining Verbose with Filtering
```bash
$ python3 parse_avc.py --file testAVC/tpm-enforcing.log --verbose --process systemd-crypten

→ Debug: Split input into 620 log blocks
→ Debug: Parsing 620 log blocks
→ Debug: Successfully parsed 877 AVC denials from 620 valid blocks
→ Debug: Created 202 unique denial groups from 877 total events
→ Debug: Filtering: 201 denials filtered out, 1 remaining
[... shows only systemd-crypten denials ...]
```

**Use Case**: Verify filtering is working as expected.

### Empty Filter Results (Enhanced Guidance)
When filters don't match anything, you get helpful suggestions:
```bash
$ python3 parse_avc.py --file testAVC/tpm-enforcing.log --process nonexistent

Found 877 AVC events. Displaying 202 unique denials...
Applied filters: process='nonexistent'
Showing 0 of 202 unique denials after filtering.

⚠️  No denials matched your filter criteria

You filtered for:
  • process='nonexistent'

But found 0 matches out of 202 total denials.

💡 Suggestions:
  • Remove filters to see all denials: python3 parse_avc.py --file testAVC/tpm-enforcing.log
  • Check available process names:
    python3 parse_avc.py --file testAVC/tpm-enforcing.log | grep 'PID'
  • Try wildcard patterns:
    --process '*nonex*'
```

**Use Case**: Quickly correct typos and discover what's actually in the log.

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

**SELinux AVC Denial Analyzer v1.8.0** | Made for forensic analysts and system administrators