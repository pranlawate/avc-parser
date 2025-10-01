# How the OOP Wrapper Works - Detailed Explanation

## Overview

The `AVCAnalyzer` class is a **thin wrapper** that translates between two architectural styles:
- **OOP calls** (from sos-data-extractor) → **Functional code** (your existing AVC parser)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ sos-data-extractor (OOP Architecture)                       │
│                                                               │
│  from selinux.avc_analyzer import AVCAnalyzer                │
│  analyzer = AVCAnalyzer(sos_dir)  ← Creates object          │
│  analyzer.analyze_avc_denials()    ← Calls method           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ AVCAnalyzer Wrapper Class (Adapter)                         │
│                                                               │
│  __init__(sos_dir):                                          │
│    • Stores sos_dir as instance variable                     │
│    • Constructs audit log path                               │
│    • Initializes Rich console                                │
│                                                               │
│  analyze_avc_denials():                                      │
│    • Calls your functional code ──────────────┐              │
│    • Stores results in self.denials           │              │
│    • Generates summary                        │              │
│    • Displays Rich table                      │              │
└───────────────────────────────────────────────┼──────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────┐
│ Your Existing Functional Code (NO CHANGES NEEDED)           │
│                                                               │
│  parse_avc.py:                                               │
│    parse_audit_log(file) → returns list of denials          │
│    process_denials(raw) → returns processed denials         │
│                                                               │
│  validators/file_validator.py                                │
│  formatters/report_formatter.py                              │
│  detectors/anomaly_detector.py                               │
│  utils/* modules                                             │
└─────────────────────────────────────────────────────────────┘
```

## Execution Flow - Step by Step

### Example: sos-data-extractor calls the wrapper

```python
# In sos-data-extractor/main.py
analyzer = AVCAnalyzer("/var/tmp/sosreport-123")
analyzer.analyze_avc_denials()
```

### What Happens Internally:

#### **Step 1: Object Creation**
```python
# When: analyzer = AVCAnalyzer("/var/tmp/sosreport-123")

def __init__(self, sos_dir: str):
    self.sos_dir = "/var/tmp/sosreport-123"
    self.audit_log = "/var/tmp/sosreport-123/var/log/audit/audit.log"
    self.console = Console()  # Rich console for output
    self.denials = []         # Will store results
    self.summary = {}         # Will store statistics
```

**Result**: Object created with instance variables ready

---

#### **Step 2: Method Call**
```python
# When: analyzer.analyze_avc_denials()

def analyze_avc_denials(self):
    # 2.1: Check if audit log exists
    if not os.path.exists(self.audit_log):
        rprint("[yellow]No audit log found[/yellow]")
        return False

    # 2.2: Import your functional code
    from parse_avc import parse_audit_log, process_denials

    # 2.3: Call your existing function (NO OOP here!)
    raw_denials = parse_audit_log(self.audit_log)
    # parse_audit_log is YOUR existing function that:
    # - Reads the file
    # - Parses AVC lines
    # - Returns: [{"comm": "httpd", "tcontext": "..."}...]

    # 2.4: Call another existing function
    self.denials = process_denials(raw_denials)
    # process_denials is YOUR existing function that:
    # - Groups denials
    # - Counts occurrences
    # - Returns: processed denial list

    # 2.5: Store results in object (OOP style)
    self._generate_summary()  # Calculate stats
    self._display_summary_table()  # Show Rich table

    return True
```

**Result**: Your functional code runs, results stored in object

---

#### **Step 3: Access Results (Optional)**
```python
# Later in sos-data-extractor, they can access results:

# Get data as JSON
data = analyzer.get_denials_json()
# Returns: {"unique_denials": [...], "summary": {...}}

# Get only critical issues
critical = analyzer.get_critical_denials()
# Calls YOUR detect_anomalies() function
# Returns: filtered list

# Generate reports
report = analyzer.generate_brief_report()
# Calls YOUR format_brief_report() function
# Returns: formatted string
```

**Result**: OOP-style access to functional results

## Key Insight: No Code Duplication

```python
# The wrapper DOES NOT reimplement your logic
# It just CALLS your existing functions!

# Your functional code (unchanged):
def parse_audit_log(file_path):
    # All your existing parsing logic
    return denials

# Wrapper just calls it:
class AVCAnalyzer:
    def analyze_avc_denials(self):
        raw_denials = parse_audit_log(self.audit_log)  # ← Just a function call!
```

## Comparison: Direct vs Wrapper Usage

### Direct Functional Usage (Current):
```python
# Command line
python3 parse_avc.py --file audit.log

# Or direct import
from parse_avc import parse_audit_log
denials = parse_audit_log("audit.log")
```

### OOP Wrapper Usage (sos-data-extractor):
```python
# Class-based interface
analyzer = AVCAnalyzer(sos_dir)
analyzer.analyze_avc_denials()
data = analyzer.get_denials_json()
```

**Both use the SAME underlying code** - just different interfaces!

## Why This Works So Well

### ✅ **No Refactoring**
- Your `parse_avc.py` stays 100% unchanged
- All your modules stay functional
- No risk of breaking existing functionality

### ✅ **Thin Translation Layer**
```python
# The wrapper is just 150 lines of "glue code"
# It translates between calling styles:

# OOP style input:
analyzer.analyze_avc_denials()

# ↓ Wrapper translates to ↓

# Functional style execution:
parse_audit_log(file)
process_denials(raw)
format_brief_report(denials)
```

### ✅ **Automatic Updates**
- Update `parse_avc.py` → wrapper automatically uses new code
- Fix bugs in functional code → wrapper benefits immediately
- No synchronization needed

## Real-World Example

Let's trace a complete execution:

```python
# sos-data-extractor executes:
analyzer = AVCAnalyzer("/var/tmp/sosreport-rhel9-123")
success = analyzer.analyze_avc_denials()

# Internal execution trace:
# 1. __init__ sets self.audit_log = "/var/tmp/sosreport-rhel9-123/var/log/audit/audit.log"
# 2. analyze_avc_denials() checks file exists ✓
# 3. Imports from parse_avc import parse_audit_log
# 4. Calls: raw_denials = parse_audit_log(self.audit_log)
#    └─> YOUR CODE runs: reads file, parses AVC denials
#    └─> Returns: [
#          {"comm": "httpd", "denied": "read", "path": "/var/www/html/index.html"},
#          {"comm": "nginx", "denied": "write", "path": "/tmp/cache"}
#        ]
# 5. Calls: self.denials = process_denials(raw_denials)
#    └─> YOUR CODE runs: groups by similarity, counts
#    └─> Returns: processed list
# 6. Calls: self._generate_summary()
#    └─> Wrapper code: calculates {"total_denials": 2, "processes": 2}
# 7. Calls: self._display_summary_table()
#    └─> Wrapper code: displays Rich table:
#        ┌────────────────────┬───────┐
#        │ Metric             │ Count │
#        ├────────────────────┼───────┤
#        │ Total Denials      │ 2     │
#        │ Affected Processes │ 2     │
#        └────────────────────┴───────┘
# 8. Returns: True

# Now sos-data-extractor can also do:
json_data = analyzer.get_denials_json()
# Returns: {"unique_denials": [...], "summary": {...}}
```

## The "Magic" - It's Just Function Calls!

There's no magic here - the wrapper is simply:
1. **State Management** (OOP): Stores sos_dir, denials, summary in `self`
2. **Function Calls** (Functional): Calls your existing functions
3. **Result Storage** (OOP): Puts results in object attributes
4. **Interface Translation** (Adapter): Provides methods that sos-data-extractor expects

## Benefits Summary

| Aspect | Functional (Current) | OOP Wrapper | Combined |
|--------|---------------------|-------------|----------|
| CLI Usage | ✅ parse_avc.py | ❌ | ✅ Both work |
| Python Import | ✅ Direct import | ❌ | ✅ Both work |
| sos-data-extractor | ❌ Style mismatch | ✅ Perfect fit | ✅ Works! |
| Maintenance | ✅ Easy | ✅ Automatic | ✅ Zero duplication |
| Code Changes | ✅ None needed | ✅ None needed | ✅ No refactoring |

## Conclusion

The wrapper is a **translation layer** that:
- Accepts OOP-style calls from sos-data-extractor
- Executes your functional code underneath
- Returns results in OOP-style format
- Requires **zero changes** to your existing code

It's like a bilingual interpreter - it speaks "OOP" to sos-data-extractor and "Functional" to your code, allowing both to communicate perfectly!
