# SOS Data Extractor - CLI Integration Guide

## Quick Start - Option 1: CLI Script (Recommended)

The **simplest integration** uses `selinux_analyzer.py` which provides full parse_avc.py functionality through a clean CLI interface.

### Integration in 3 Steps:

#### Step 1: Copy Files to sos-data-extractor
```bash
cd sos-data-extractor
mkdir -p selinux/avc_parser
cp -r ../avc-parser/* selinux/avc_parser/
```

#### Step 2: Add to main.py
```python
# At top of main.py
import subprocess

# In main() function, add:
def analyze_selinux_avc():
    print("\n" + "="*70)
    print("  SELinux AVC Denial Analysis")
    print("="*70 + "\n")

    subprocess.run([
        "python3",
        "selinux/avc_parser/selinux/selinux_analyzer.py",
        args.sos_dir,
        "--report", "brief"
    ])

# Call it with other analyses:
analyze_selinux_avc()
```

#### Step 3: Test
```bash
python3 main.py /path/to/sosreport
```

That's it! Your users now have full SELinux AVC analysis.

---

## All Available Arguments

The CLI script supports **all parse_avc.py arguments**:

### Output Formats
```bash
# Executive summary (default)
selinux_analyzer.py /sos/dir --report brief

# Technical deep-dive with remediation steps
selinux_analyzer.py /sos/dir --report sealert

# Field-by-field breakdown
selinux_analyzer.py /sos/dir --fields

# JSON for automation
selinux_analyzer.py /sos/dir --json

# Enhanced detailed view
selinux_analyzer.py /sos/dir --detailed
```

### Filtering
```bash
# Filter by process
selinux_analyzer.py /sos/dir --process httpd --report brief

# Filter by path (supports wildcards)
selinux_analyzer.py /sos/dir --path '/var/www/*'

# Filter by source context
selinux_analyzer.py /sos/dir --source 'httpd_t'

# Filter by target context
selinux_analyzer.py /sos/dir --target '*var_lib*'
```

### Sorting and Time Ranges
```bash
# Sort by occurrence count
selinux_analyzer.py /sos/dir --sort count

# Sort by most recent
selinux_analyzer.py /sos/dir --sort recent

# Time range filtering
selinux_analyzer.py /sos/dir --since yesterday --until today
selinux_analyzer.py /sos/dir --since '2 hours ago'
```

### Display Options
```bash
# Show individual events (disable grouping)
selinux_analyzer.py /sos/dir --expand-groups

# Use pager for large output
selinux_analyzer.py /sos/dir --report sealert --pager
```

---

## Advanced Integration Options

### Option A: Interactive Menu in sos-data-extractor

```python
def selinux_menu():
    """Interactive SELinux analysis menu"""
    print("\n=== SELinux AVC Analysis Options ===")
    print("1. Executive Summary (Brief Report)")
    print("2. Technical Analysis (Sealert Report)")
    print("3. Field-by-Field Breakdown")
    print("4. JSON Export")
    print("5. Custom Filters")
    print("6. Back")

    choice = input("\nSelect option: ")

    base_cmd = ["python3", "selinux/avc_parser/selinux/selinux_analyzer.py", sos_dir]

    if choice == "1":
        subprocess.run(base_cmd + ["--report", "brief", "--pager"])
    elif choice == "2":
        subprocess.run(base_cmd + ["--report", "sealert", "--pager"])
    elif choice == "3":
        subprocess.run(base_cmd + ["--fields", "--pager"])
    elif choice == "4":
        subprocess.run(base_cmd + ["--json"])
    elif choice == "5":
        process = input("Filter by process (or Enter to skip): ")
        path = input("Filter by path (or Enter to skip): ")

        cmd = base_cmd + ["--report", "brief"]
        if process:
            cmd.extend(["--process", process])
        if path:
            cmd.extend(["--path", path])
        subprocess.run(cmd + ["--pager"])
```

### Option B: Programmatic Access

```python
from selinux.avc_parser.selinux.selinux_analyzer import selinux_analyze

# Generate report and check result
success = selinux_analyze(
    sos_dir="/path/to/sos",
    report="brief",
    process="httpd",
    sort="count"
)

if not success:
    print("No SELinux denials found or analysis failed")
```

### Option C: JSON Data Processing

```python
import subprocess
import json

# Get JSON data
result = subprocess.run(
    ["python3", "selinux/avc_parser/selinux/selinux_analyzer.py",
     sos_dir, "--json"],
    capture_output=True,
    text=True
)

if result.returncode == 0:
    data = json.loads(result.stdout)

    # Process the data
    for denial in data['unique_denials']:
        log = denial['log']
        print(f"Process: {log['comm']}")
        print(f"Target: {log.get('path', 'N/A')}")
        print(f"Count: {denial['count']}")
        print()
```

---

## Feature Comparison

| Feature | CLI Script | OOP Wrapper |
|---------|-----------|-------------|
| All parse_avc.py arguments | ✅ Yes | ⚠️ Subset |
| Filtering (process, path, etc) | ✅ Yes | ❌ No |
| Sorting options | ✅ Yes | ❌ No |
| Time range filtering | ✅ Yes | ❌ No |
| All report formats | ✅ Yes | ✅ Yes |
| JSON export | ✅ Yes | ✅ Yes |
| Pager support | ✅ Yes | ❌ No |
| Setup complexity | ✅ Low | Medium |
| Customization | Medium | ✅ High |

**Recommendation**: Use **CLI Script** for 90% of use cases. Use OOP Wrapper only if you need deep customization.

---

## Complete Example for sos-data-extractor

```python
# In main.py

def analyze_selinux(sos_dir):
    """
    SELinux AVC analysis with multiple output options
    Integrates seamlessly with sos-data-extractor
    """
    import subprocess
    from rich import print
    from rich.panel import Panel

    # Check if audit log exists
    audit_log = os.path.join(sos_dir, "var", "log", "audit", "audit.log")
    if not os.path.exists(audit_log):
        print("[yellow]No audit log found - SELinux may not be enabled[/yellow]")
        return

    # Display header
    print("\n" + "="*70)
    print(Panel.fit(
        "[bold cyan]SELinux AVC Denial Analysis[/bold cyan]",
        border_style="cyan"
    ))
    print("="*70 + "\n")

    # Run analysis with brief report format
    result = subprocess.run([
        "python3",
        "selinux/avc_parser/selinux/selinux_analyzer.py",
        sos_dir,
        "--report", "brief",
        "--sort", "count"  # Show most frequent denials first
    ])

    if result.returncode != 0:
        print("[yellow]SELinux analysis completed with warnings[/yellow]")
    else:
        print("\n[green]✅ SELinux analysis completed successfully[/green]")

# In main() function
def main():
    # ... existing code ...

    # Add SELinux analysis
    analyze_selinux(args.sos_dir)

    # ... rest of analyses ...
```

---

## Benefits of This Approach

✅ **Zero Code Duplication** - Uses parse_avc.py directly
✅ **Automatic Updates** - Improvements to parse_avc.py automatically available
✅ **Full Feature Set** - All arguments and options supported
✅ **Consistent Output** - Same formatting as standalone parse_avc.py
✅ **Low Maintenance** - No wrapper code to maintain
✅ **Easy Testing** - Test standalone before integration

---

## Troubleshooting

### Issue: "Module not found"
```python
# Make sure path is correct:
import sys
sys.path.insert(0, 'selinux/avc_parser')
```

### Issue: "No audit log found"
```python
# Check the sos directory structure:
audit_log = os.path.join(sos_dir, "var", "log", "audit", "audit.log")
if os.path.exists(audit_log):
    print(f"✅ Found audit log: {audit_log}")
else:
    print("❌ Audit log not found - SELinux may not be enabled")
```

### Issue: "Permission denied"
```bash
# Make script executable:
chmod +x selinux/avc_parser/selinux/selinux_analyzer.py
```

---

## Next Steps

1. **Test the integration** with real sos reports
2. **Customize the output** based on your users' needs
3. **Add error handling** for edge cases
4. **Consider adding** to your interactive menu system

For more details, see:
- [Complete CLI Reference](CLI_REFERENCE.md)
- [OOP Wrapper Documentation](SOS_INTEGRATION.md) (advanced use cases)
- [Examples Directory](../examples/) for more integration patterns
