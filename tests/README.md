# AVC Parser Test Suite

Basic testing framework for the SELinux AVC Denial Analyzer.

## Running Tests

```bash
# Run all tests
python3 run_tests.py

# Run specific test file
python3 -m unittest tests.test_core_functions

# Run with verbose output
python3 -m unittest tests.test_core_functions -v
```

## Test Coverage

### Core Functions (`test_core_functions.py`)
- **Audit Record Parsing**: Tests `parse_audit_record_text()` with various formats
- **File Format Detection**: Tests `detect_file_format()` auto-detection logic
- **Log Validation**: Tests `validate_log_entry()` sanitization and validation
- **Regression Protection**: Ensures existing test files continue to work

## Test Data

- Uses temporary files for format detection tests
- References existing `testAVC/*.log` files for regression tests
- Tests both Unix timestamps and edge cases

## Adding New Tests

1. Create new test file in `tests/` directory
2. Follow naming convention: `test_*.py`
3. Import functions from parent directory
4. Use `unittest.TestCase` classes
5. Run `python3 run_tests.py` to verify

## Test Philosophy

- **Minimal but effective**: Focus on core functions and regression protection
- **Fast execution**: All tests run in under 1 second
- **Clear failure messages**: Easy to debug when tests fail
- **Support development**: Tests help ensure new features don't break existing functionality