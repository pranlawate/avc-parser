# Smart Deduplication Algorithm

## Overview

The AVC Parser uses an intelligent **signature-based deduplication algorithm** that groups SELinux denials by their **remediation pattern** rather than exact matching. This transforms overwhelming audit logs (often 10,000+ similar denials) into a manageable set of actionable groups (typically 10-30).

## The Problem

A single SELinux misconfiguration can generate thousands of nearly-identical AVC denials:

```
# Apache accessing files in /var/www/html/
type=AVC msg=audit(1234567890.001:101): avc: denied { read } scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file name="/var/www/html/index.html"
type=AVC msg=audit(1234567890.002:102): avc: denied { open } scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file name="/var/www/html/index.html"
type=AVC msg=audit(1234567890.003:103): avc: denied { getattr } scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file name="/var/www/html/index.html"
type=AVC msg=audit(1234567890.004:104): avc: denied { read } scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file name="/var/www/html/style.css"
... (996 more similar denials)
```

**Traditional approaches fail:**
- **No deduplication**: 1,000 separate denials (overwhelming)
- **Exact deduplication**: Still hundreds of "unique" denials (different files/permissions)
- **Manual analysis**: Time-consuming and error-prone

**The key insight**: All these denials need the **same fix**:
```bash
# Single policy fix for all 1,000 denials:
semanage fcontext -a -t httpd_sys_content_t '/var/www/html(/.*)?'
restorecon -Rv /var/www/html
```

## Solution: Smart Signature Generation

Instead of grouping by exact fields, we categorize denials by their **remediation pattern**.

### Signature Components

A smart signature consists of:

```python
signature = (
    process_category,       # How the process is categorized
    target_context,         # Target SELinux context (unchanged)
    object_group,           # Object type category
    path_pattern,           # Normalized path pattern (filesystem objects only)
    permission_category     # Permission operation category
)
```

### 1. Process Categorization (`get_process_category()`)

**Purpose**: Group related process variants that should be treated identically.

**Examples**:
- `httpd`, `httpd-worker`, `httpd-prefork` → `web_server_apache`
- `mysqld`, `mysql-server` → `database_mysql`
- `postgres`, `postmaster` → `database_postgresql`

**Special handling**:
- **Multi-service domains**: `unconfined_t` can run many different processes
  - `unconfined_t + firefox` → `unconfined_firefox`
  - `unconfined_t + python` → `unconfined_python`

**Implementation**:
```python
service_mappings = {
    "httpd": "web_server_apache",
    "nginx": "web_server_nginx",
    "mysqld": "database_mysql",
    # ... 20+ mappings
}

# Pattern matching for variants
if comm.startswith("httpd") or "httpd" in comm:
    return "web_server_apache"
```

### 2. Permission Categorization (`get_permission_category()`)

**Purpose**: Group permissions that require the same policy fix.

**Categories**:
- **Read operations**: `read`, `open`, `getattr`, `search`, `map`
  - Fix: Allow read access
- **Write operations**: `write`, `append`, `create`, `add_name`, `remove_name`
  - Fix: Allow write access
- **Execute operations**: `execute`, `execmod`
  - Fix: Allow execute permission
- **Management operations**: `setattr`, `chown`, `chmod`, `rename`
  - Fix: Allow file management

**Example**:
```python
# These all need "allow httpd_t httpd_sys_content_t:file read;"
permission in {"read", "open", "getattr"} → "read_operations"
```

### 3. Object Grouping (`get_object_group()`)

**Purpose**: Group SELinux object classes that often share policy rules.

**Categories**:
- **Filesystem**: `file`, `dir`, `lnk_file`, `chr_file`, `blk_file`, `fifo_file`, `sock_file`
- **Network**: `tcp_socket`, `udp_socket`, `unix_stream_socket`, `unix_dgram_socket`
- **System**: `process`, `capability`, `system`
- **IPC**: `shm`, `sem`, `msg`, `msgq`
- **Other**: Ungrouped classes returned as-is

**Why?**:
- Policy rules often apply to multiple related classes
- `file` and `dir` frequently need the same type enforcement rule

### 4. Path Pattern Extraction (`get_path_pattern()`)

**Purpose**: Normalize file paths to group related resources.

**Transformations**:
```python
# Directory-based grouping for filesystem objects
"/var/log/httpd/access_log"      → "/var/log/httpd/"
"/var/log/httpd/error_log"       → "/var/log/httpd/"

# Normalize user-specific paths
"/home/alice/.bashrc"            → "/home/*/"
"/home/bob/.bashrc"              → "/home/*/"

# Normalize temporary files
"/tmp/file_12345"                → "/tmp/"
"/tmp/file_67890"                → "/tmp/"

# Normalize process-specific suffixes
"/run/httpd.pid.1234"            → "/run/httpd.pid"
```

## Deduplication Process

### Step 1: Parse AVC Denial

```python
parsed_log = {
    "scontext": AvcContext("system_u:system_r:httpd_t:s0"),
    "tcontext": AvcContext("system_u:object_r:httpd_sys_content_t:s0"),
    "tclass": "file",
    "permission": "read",
    "path": "/var/www/html/index.html",
    "comm": "httpd",
    "pid": "1234",
    # ... more fields
}
```

### Step 2: Generate Smart Signature

```python
signature = generate_smart_signature(parsed_log)

# Results in:
signature = (
    "web_server_apache",              # process_category
    "system_u:object_r:httpd_sys_content_t:s0",  # target_context
    "filesystem",                     # object_group
    "/var/www/html/",                # path_pattern
    "read_operations"                 # permission_category
)
```

### Step 3: Group by Signature

```python
unique_denials = {}  # Dictionary: signature → denial group

if signature in unique_denials:
    # Already seen - increment count and collect variations
    unique_denials[signature]["count"] += 1
    unique_denials[signature]["permissions"].add(permission)
    unique_denials[signature]["paths"].add(path)
    unique_denials[signature]["pids"].add(pid)
    unique_denials[signature]["correlations"].append(correlation_event)

    # Update time range
    if timestamp < unique_denials[signature]["first_seen_obj"]:
        unique_denials[signature]["first_seen_obj"] = timestamp
    if timestamp > unique_denials[signature]["last_seen_obj"]:
        unique_denials[signature]["last_seen_obj"] = timestamp
else:
    # First occurrence - create new group
    unique_denials[signature] = {
        "count": 1,
        "permissions": {permission},
        "paths": {path},
        "pids": {pid},
        "comms": {comm},
        "correlations": [correlation_event],
        "first_seen_obj": timestamp,
        "last_seen_obj": timestamp,
        "log": parsed_log,  # Representative example
    }
```

### Step 4: Preserve Individual Events

While grouping, all individual denial events are preserved in the `correlations` list:

```python
correlation_event = {
    "pid": "1234",
    "comm": "httpd",
    "permission": "read",
    "path": "/var/www/html/index.html",
    "timestamp": "2026-01-08 10:30:00",
    "event_id": "1234567890.001:101"
}
```

This allows:
- **Summary view**: "Apache denied 1,000 times accessing /var/www/html/*"
- **Detailed view**: Drill down to see every individual denial
- **Timeline analysis**: When did denials start/stop?
- **PID tracking**: Which process instances were affected?

## Output Example

### Before Deduplication (Raw Audit Log)
```
1000 individual AVC denials
- httpd[1234] denied read /var/www/html/index.html
- httpd[1234] denied open /var/www/html/index.html
- httpd[1234] denied getattr /var/www/html/index.html
- httpd[1235] denied read /var/www/html/style.css
- httpd[1235] denied open /var/www/html/style.css
... (995 more)
```

### After Smart Deduplication
```
Unique Denial Group #1 (1000 occurrences, last seen 30 minutes ago)

Process:     web_server_apache (httpd)
Source:      system_u:system_r:httpd_t:s0
Target:      system_u:object_r:httpd_sys_content_t:s0
Object:      filesystem
Permissions: read, open, getattr
Paths:       /var/www/html/* (15 unique paths)
PIDs:        1234, 1235, 1236, 1237, 1238

Remediation:
  semanage fcontext -a -t httpd_sys_content_t '/var/www/html(/.*)?'
  restorecon -Rv /var/www/html

sesearch -A -s httpd_t -t httpd_sys_content_t -c file -p read,open,getattr
```

## Validation: Grouping Optimality

The `validate_grouping_optimality()` function checks if grouping is optimal:

```python
def validate_grouping_optimality(unique_denials: dict) -> dict:
    """
    Measure grouping efficiency by checking sesearch command uniqueness.

    Optimal grouping: Each group should produce a unique sesearch command.
    Suboptimal: Multiple groups → same sesearch command (could be merged)
    """
    sesearch_to_groups = {}

    for signature, denial_info in unique_denials.items():
        sesearch_cmd = generate_sesearch_command(denial_info)

        if sesearch_cmd in sesearch_to_groups:
            sesearch_to_groups[sesearch_cmd].append(signature)
        else:
            sesearch_to_groups[sesearch_cmd] = [signature]

    # Calculate efficiency
    total_groups = len(unique_denials)
    unique_commands = len(sesearch_to_groups)
    efficiency_score = unique_commands / total_groups if total_groups > 0 else 1.0

    return {
        "total_groups": total_groups,
        "unique_sesearch_commands": unique_commands,
        "efficiency_score": efficiency_score,  # 1.0 = optimal
        "duplicate_groups": [
            {"sesearch": cmd, "groups": groups}
            for cmd, groups in sesearch_to_groups.items()
            if len(groups) > 1
        ]
    }
```

**Efficiency Score**:
- **1.0**: Perfect - Each group has unique sesearch command
- **< 1.0**: Suboptimal - Some groups could be merged
- **> 1.0**: Impossible (would mean groups share signatures)

## Legacy Mode

For regression testing and comparison, legacy signature mode is available:

```python
signature = generate_smart_signature(parsed_log, legacy_mode=True)

# Legacy signature (overly granular):
signature = (
    context_to_str(scontext),  # Full source context
    context_to_str(tcontext),  # Full target context
    tclass,                    # Exact object class
    permission                 # Exact permission
)
```

**Use cases**:
- Compare smart vs. legacy grouping
- Regression testing
- Debugging grouping issues

**CLI flag**: `--legacy-signatures`

## Trade-offs and Design Decisions

### Grouping Granularity

**Too aggressive** (over-grouping):
- Risk: Lose important distinctions
- Example: Grouping network ports 22, 80, 443 together
- Problem: Different services, different fixes needed

**Too conservative** (under-grouping):
- Risk: Still overwhelming output
- Example: Separate groups for /tmp/file1, /tmp/file2
- Problem: Same fix needed for all

**Solution**: Remediation-aware grouping
- Groups align with actual policy fixes
- Balance between specificity and usability

### Path Normalization

**Challenge**: When to normalize paths?

```python
# Group these together?
/var/log/httpd/access_log.1
/var/log/httpd/access_log.2
/var/log/httpd/error_log

# Yes - same directory, same fix:
/var/log/httpd/

# But preserve distinction for:
/var/log/httpd/
/var/log/mysql/

# Different services, might need different rules
```

**Implementation**:
- Normalize within directory
- Preserve directory structure
- User home directories: `/home/*/`
- Temp files: `/tmp/`

### Multi-Service Domains

**Challenge**: `unconfined_t` runs many different processes

```python
# These should NOT be grouped:
unconfined_t + firefox
unconfined_t + python
unconfined_t + bash

# Solution: Include process name in category
"unconfined_firefox"
"unconfined_python"
"unconfined_bash"
```

## Performance Considerations

**Time Complexity**:
- Signature generation: O(1) per denial
- Dictionary lookup: O(1) average case
- Overall: O(n) where n = number of denials

**Space Complexity**:
- Stores all unique signatures: O(k) where k = unique groups
- Stores correlations: O(n) for all events
- Typical: 50,000 denials → 20 groups → minimal overhead

**Benchmarks** (from profiling):
```
Input:  79,305 AVC denials
Groups: ~20-30 unique denial groups
Time:   0.224 seconds total (including parsing)
Memory: 25MB peak
```

## Future Enhancements

Potential improvements to the algorithm:

1. **Machine Learning**: Learn from user feedback on grouping quality
2. **Configurable Grouping**: User-defined categorization rules
3. **Context-Aware Normalization**: Use SELinux policy to inform grouping
4. **Time-Based Grouping**: Group denials that occurred in same time window
5. **Severity Scoring**: Prioritize groups by security impact

## References

- Source code: `parse_avc.py` (lines 1792-1857: `generate_smart_signature()`)
- Helper functions: Lines 1375-1724
- Validation: Lines 1726-1790 (`validate_grouping_optimality()`)
- Tests: `tests/test_core_parsing.py`

## Author

Pranav Lawate <pran.lawate@gmail.com>

## License

MIT License - See LICENSE file for details
