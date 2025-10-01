# SOS Data Extractor Integration Guide

## Overview

This document explains how to integrate the AVC Parser with the sos-data-extractor tool using the OOP adapter pattern.

## Architecture Pattern

**Adapter Pattern (Wrapper Class)**
- ✅ **Lightweight wrapper** around existing functional code
- ✅ **No refactoring required** - leverages current implementation
- ✅ **OOP-compatible** - matches sos-data-extractor's class-based architecture
- ✅ **Maintainable** - changes to core code automatically available through wrapper

## Integration Steps

### 1. Copy AVC Parser to sos-data-extractor

```bash
# In sos-data-extractor directory
mkdir -p selinux
cp -r ../avc-parser/{parse_avc.py,validators,formatters,detectors,utils,config,selinux} selinux/avc_parser/
```

### 2. Add to sos-data-extractor/main.py

```python
# Add import at top
from selinux.avc_parser.selinux.avc_analyzer import AVCAnalyzer

# In main() function where other modules are instantiated
def main():
    parser = argparse.ArgumentParser(description="SOS Command Extractor")
    parser.add_argument("sos_dir", help="Path to the extracted sos directory")
    args = parser.parse_args()

    # ... existing banner/animation code ...

    # Add AVC analysis
    avc_analyzer = AVCAnalyzer(args.sos_dir)
    avc_analyzer.analyze_avc_denials()
```

### 3. Usage Patterns

#### Basic Analysis
```python
from selinux.avc_parser.selinux.avc_analyzer import AVCAnalyzer

analyzer = AVCAnalyzer("/path/to/sos/report")
analyzer.analyze_avc_denials()  # Displays rich table summary
```

#### Programmatic Access
```python
# Get JSON data
data = analyzer.get_denials_json()
print(f"Found {data['summary']['total_denials']} denials")

# Get critical issues only
critical = analyzer.get_critical_denials()
for denial in critical:
    print(f"Critical: {denial['comm']} → {denial['tcontext_type']}")
```

#### Generate Reports
```python
# Executive summary
brief = analyzer.generate_brief_report()
print(brief)

# Technical report with remediation
technical = analyzer.generate_technical_report()
print(technical)
```

## Example: Complete Integration

```python
# In sos-data-extractor/selinux/selinux_analysis.py
from selinux.avc_parser.selinux.avc_analyzer import AVCAnalyzer

class SELinuxAnalysis:
    """Complete SELinux analysis including AVC denials, policies, contexts"""

    def __init__(self, sos_dir):
        self.sos_dir = sos_dir
        self.avc_analyzer = AVCAnalyzer(sos_dir)

    def run_analysis(self):
        """Run complete SELinux analysis"""
        print("\n=== SELinux AVC Denial Analysis ===")
        self.avc_analyzer.analyze_avc_denials()

        # Additional SELinux checks
        self._check_selinux_status()
        self._check_selinux_contexts()

    def _check_selinux_status(self):
        # Your existing SELinux status checks
        pass

    def _check_selinux_contexts(self):
        # Your existing context checks
        pass
```

## Benefits of This Approach

### High ROI ✅
- **Effort**: LOW (1-2 hours integration work)
- **Value**: HIGH (full AVC analysis capability)
- **Maintenance**: LOW (no duplication, uses existing code)

### No Refactoring Required
- ✅ AVC Parser stays functional - no changes needed
- ✅ Wrapper class provides OOP interface
- ✅ Both tools remain independent

### Best Practices
- ✅ **Separation of Concerns**: Core logic separate from OOP wrapper
- ✅ **Single Responsibility**: Wrapper only handles interface adaptation
- ✅ **DRY Principle**: No code duplication
- ✅ **Maintainability**: Updates to core automatically propagate

## Alternative: Direct Functional Calls

If you prefer not to use the wrapper class:

```python
# Direct import of functional code
from selinux.avc_parser.parse_avc import parse_audit_log, process_denials

# Use functions directly
audit_log = "/path/to/sos/var/log/audit/audit.log"
denials = parse_audit_log(audit_log)
processed = process_denials(denials)
```

## Testing Integration

```bash
# Test the wrapper standalone
cd selinux/avc_parser
python3 selinux/avc_analyzer.py /path/to/sos/report

# Test within sos-data-extractor
python3 main.py /path/to/sos/report
```

## Conclusion

**Recommended Approach**: Use the `AVCAnalyzer` wrapper class

This provides:
- ✅ Clean OOP interface matching sos-data-extractor patterns
- ✅ Full access to AVC Parser functionality
- ✅ No refactoring of existing code
- ✅ Easy maintenance and updates
- ✅ Consistent with sos-data-extractor architecture

**ROI**: HIGH - Minimal effort, maximum value, clean architecture
