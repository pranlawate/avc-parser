#!/usr/bin/env python3
"""
Core function tests for AVC Parser

Tests the fundamental parsing and detection functions to ensure
they work correctly and prevent regressions.
"""

import unittest
import sys
import os

# Add parent directory to path to import parse_avc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parse_avc import (
    parse_audit_record_text,
    detect_file_format,
    validate_log_entry
)


class TestAuditRecordParsing(unittest.TestCase):
    """Test the enhanced audit record parsing function."""

    def test_parse_basic_avc_record(self):
        """Test parsing a standard AVC record with Unix timestamp."""
        line = "type=AVC msg=audit(1234567890.123:456): avc: denied { read }"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertTrue(success)
        self.assertEqual(record_type, "AVC")
        self.assertEqual(event_id, "1234567890.123:456")
        self.assertEqual(body, "avc: denied { read }")
        self.assertIsNone(host)

    def test_parse_with_node_prefix(self):
        """Test parsing audit record with node= prefix."""
        line = "node=server1 type=AVC msg=audit(1234567890.123:456): avc: denied { write }"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertTrue(success)
        self.assertEqual(host, "server1")
        self.assertEqual(record_type, "AVC")
        self.assertEqual(event_id, "1234567890.123:456")

    def test_parse_with_whitespace_variation(self):
        """Test parsing record with space before colon."""
        line = "type=PROCTITLE msg=audit(1234567890.237:87712186) : proctitle=test"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertTrue(success)
        self.assertEqual(record_type, "PROCTITLE")
        self.assertEqual(body, "proctitle=test")

    def test_parse_invalid_record(self):
        """Test parsing an invalid audit record."""
        line = "This is not an audit record"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertFalse(success)
        self.assertIsNone(host)
        self.assertIsNone(record_type)


class TestFileFormatDetection(unittest.TestCase):
    """Test the file format auto-detection logic."""

    def setUp(self):
        """Create temporary test files for format detection."""
        # Create a temporary pre-processed format file
        self.processed_content = """type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied { read }
type=SYSCALL msg=audit(09/04/2025 18:19:00.303:503): arch=x86_64 syscall=openat"""

        # Create a temporary raw format file
        self.raw_content = """audit(1234567890.123:456): avc: denied { read }
audit(1234567890.124:457): syscall=openat success=no"""

        # Write test files
        with open('/tmp/test_processed.log', 'w') as f:
            f.write(self.processed_content)

        with open('/tmp/test_raw.log', 'w') as f:
            f.write(self.raw_content)

    def tearDown(self):
        """Clean up temporary test files."""
        for file_path in ['/tmp/test_processed.log', '/tmp/test_raw.log']:
            if os.path.exists(file_path):
                os.remove(file_path)

    def test_detect_processed_format(self):
        """Test detection of pre-processed format."""
        result = detect_file_format('/tmp/test_processed.log')
        self.assertEqual(result, 'processed')

    def test_detect_raw_format(self):
        """Test detection of raw audit.log format."""
        result = detect_file_format('/tmp/test_raw.log')
        self.assertEqual(result, 'raw')

    def test_detect_nonexistent_file(self):
        """Test detection with non-existent file (should default gracefully)."""
        result = detect_file_format('/tmp/nonexistent.log')
        self.assertEqual(result, 'processed')  # Default fallback


class TestLogValidation(unittest.TestCase):
    """Test the log entry validation function."""

    def test_validate_good_audit_records(self):
        """Test validation of properly formatted audit records."""
        log_block = """type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied { read }
type=SYSCALL msg=audit(09/04/2025 18:19:00.303:503): arch=x86_64"""

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertTrue(is_valid)
        self.assertEqual(len(warnings), 0)
        self.assertIn("type=AVC", sanitized)

    def test_validate_with_malformed_lines(self):
        """Test validation with some malformed lines."""
        log_block = """type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied { read }
# This is a comment
Random text that is not audit record
type=SYSCALL msg=audit(09/04/2025 18:19:00.303:503): arch=x86_64"""

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertTrue(is_valid)  # Should still be valid overall
        self.assertEqual(len(warnings), 1)
        self.assertIn("malformed", warnings[0])

    def test_validate_empty_block(self):
        """Test validation of empty log block."""
        log_block = ""

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertFalse(is_valid)
        self.assertIn("Empty", warnings[0])


class TestRegressionProtection(unittest.TestCase):
    """Regression tests to ensure existing functionality keeps working."""

    def test_multi_avc_log_processing(self):
        """Test that multi_AVC.log still processes correctly."""
        # This is a basic smoke test - just ensure the file can be processed
        # without errors. More detailed output validation could be added later.
        test_file = "testAVC/multi_AVC.log"

        if os.path.exists(test_file):
            format_detected = detect_file_format(test_file)
            self.assertEqual(format_detected, 'processed')

            # Test that the file can be read and validated
            with open(test_file, 'r') as f:
                content = f.read()

            # Split into blocks like the main program does
            blocks = [block.strip() for block in content.split('----') if block.strip()]
            self.assertGreater(len(blocks), 0)

    def test_network_avc_log_processing(self):
        """Test that network_AVC.log still processes correctly."""
        test_file = "testAVC/network_AVC.log"

        if os.path.exists(test_file):
            format_detected = detect_file_format(test_file)
            self.assertEqual(format_detected, 'processed')


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)