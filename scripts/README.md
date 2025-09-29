# 🛠️ Development and Utility Scripts

This directory contains development tools and utilities for working with the AVC Parser project.

## 🚀 Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `run_tests.py` | Test runner with clean output | `python3 run_tests.py` |
| `validate_logs.py` | Log file validation and diagnostics | `python3 validate_logs.py <log_file>` |
| `generate_test_data.py` | Generate synthetic test data | `python3 generate_test_data.py [options]` |
| `profile_performance.py` | Performance profiling and analysis | `python3 profile_performance.py <log_file>` |

## 📋 Script Details

### **run_tests.py**
Simple test runner that provides clean, formatted output for the test suite.
```bash
python3 scripts/run_tests.py
```

### **validate_logs.py**
Comprehensive log file validation tool that checks:
- File accessibility and format
- AVC content quality
- Parser compatibility
- Performance characteristics

```bash
python3 scripts/validate_logs.py testAVC/multi_AVC.log
```

### **generate_test_data.py**
Generate synthetic audit log data for testing:
```bash
# Generate basic test files
python3 scripts/generate_test_data.py --small

# Generate performance test files
python3 scripts/generate_test_data.py --large

# Generate edge case test files
python3 scripts/generate_test_data.py --edge-cases

# Generate all types
python3 scripts/generate_test_data.py --all
```

### **profile_performance.py**
Profile parser performance and identify bottlenecks:
```bash
python3 scripts/profile_performance.py testAVC/large_scale_test.log
```

Provides:
- Memory usage patterns
- CPU performance hotspots
- I/O throughput analysis
- Scaling characteristics

## 🎯 Common Workflows

### **Testing New Features**
```bash
# Run full test suite
python3 scripts/run_tests.py

# Generate test data for edge cases
python3 scripts/generate_test_data.py --edge-cases

# Validate test files
python3 scripts/validate_logs.py generated_test_data/edge_cases.log
```

### **Performance Optimization**
```bash
# Profile current performance
python3 scripts/profile_performance.py testRAW/audit.log

# Generate large test files
python3 scripts/generate_test_data.py --large

# Profile with different file sizes
python3 scripts/profile_performance.py generated_test_data/performance_10mb.log
```

### **Debugging Issues**
```bash
# Validate problematic log file
python3 scripts/validate_logs.py /path/to/problem.log

# Generate similar test data
python3 scripts/generate_test_data.py --edge-cases

# Test parser compatibility
python3 scripts/validate_logs.py generated_test_data/edge_cases.log
```

## 🔧 Requirements

Most scripts require only standard Python libraries. Performance profiling requires:
```bash
pip install psutil
```

## 📁 Output Files

Scripts may generate output files:
- `generated_test_data/` - Synthetic test files
- `performance_profile_*.json` - Performance reports
- `consolidated_report_*.json` - Analysis reports

## 🎯 Tips

- Run scripts from the project root directory
- Use `--help` flag for detailed options
- Scripts are designed to be safe and non-destructive
- Output files include timestamps for easy tracking