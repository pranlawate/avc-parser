#!/usr/bin/env python3
"""
Malformed Audit Log Tests for AVC Parser

Tests handling of corrupted, incomplete, and malformed audit logs
to ensure robustness in real-world forensic scenarios.
"""

import unittest
import sys
import os
import tempfile
from io import StringIO
from unittest.mock import patch

# Add parent directory to path to import parse_avc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parse_avc import _parse_avc_log_internal, detect_file_format
from rich.console import Console


class TestMalformedAuditRecords(unittest.TestCase):
    """Test handling of malformed individual audit records."""

    def test_incomplete_avc_record(self):
        """Test handling of incomplete AVC records."""
        malformed_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234
----"""
        # Should not crash, may or may not produce denials
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should complete without exception
            self.assertIsInstance(denials, list)
            self.assertIsInstance(unparsed, set)
        except Exception as e:
            self.fail(f"Incomplete AVC record caused crash: {e}")

    def test_missing_avc_keyword(self):
        """Test handling of records missing 'avc:' keyword."""
        malformed_log = """----
type=AVC msg=audit(1735221600.123:456): denied { read } for pid=1234 comm="httpd"
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Missing avc keyword caused crash: {e}")

    def test_malformed_timestamp(self):
        """Test handling of malformed timestamps."""
        malformed_log = """----
type=AVC msg=audit(INVALID_TIMESTAMP): avc: denied { read } for pid=1234 comm="httpd" path="/test" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should handle gracefully, may produce denial with None timestamp
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Malformed timestamp caused crash: {e}")

    def test_invalid_selinux_context(self):
        """Test handling of invalid SELinux contexts."""
        malformed_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="httpd" path="/test" scontext=INVALID_CONTEXT tcontext=ALSO_INVALID tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Invalid SELinux context caused crash: {e}")

    def test_missing_required_fields(self):
        """Test handling of records missing required fields."""
        malformed_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read }
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Missing required fields caused crash: {e}")


class TestCorruptedLogStructure(unittest.TestCase):
    """Test handling of corrupted log structure."""

    def test_missing_separators(self):
        """Test handling of logs without proper separators."""
        malformed_log = """type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="httpd" path="/test" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
type=AVC msg=audit(1735221600.124:457): avc: denied { write } for pid=1235 comm="nginx" path="/test2" scontext=system_u:system_r:nginx_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file"""
        try:
            denials, unparsed = _parse_avc_log_internal(malformed_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Missing separators caused crash: {e}")

    def test_mixed_format_records(self):
        """Test handling of mixed format records in same log."""
        mixed_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="httpd"
----
RANDOM_TEXT_LINE_SHOULD_BE_IGNORED
type=USER_AVC msg=audit(1735221600.124:457): user_avc: denied { write } for pid=1235
ANOTHER_INVALID_LINE
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(mixed_log)
            # Should handle gracefully, might produce some denials
            self.assertIsInstance(denials, list)
            self.assertIsInstance(unparsed, set)
        except Exception as e:
            self.fail(f"Mixed format records caused crash: {e}")

    def test_extremely_long_lines(self):
        """Test handling of extremely long audit lines."""
        # Create a very long path/command
        long_path = "/very/long/path/" + "directory/" * 100 + "file.log"
        long_log = f"""----
type=AVC msg=audit(1735221600.123:456): avc: denied {{ read }} for pid=1234 comm="httpd" path="{long_path}" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(long_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Extremely long lines caused crash: {e}")


class TestSpecialCharacterHandling(unittest.TestCase):
    """Test handling of special characters and encoding issues."""

    def test_unicode_characters(self):
        """Test handling of unicode characters in audit logs."""
        unicode_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="tëst" path="/tëst/fïle.log" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(unicode_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Unicode characters caused crash: {e}")

    def test_escaped_quotes_in_fields(self):
        """Test handling of escaped quotes in field values."""
        escaped_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="test\\"quote" path="/test/\\"quoted\\"/file" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(escaped_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Escaped quotes caused crash: {e}")

    def test_null_bytes_in_log(self):
        """Test handling of null bytes in audit logs."""
        null_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="test\x00null" path="/test\x00file" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(null_log)
            # Should handle gracefully
            self.assertIsInstance(denials, list)
        except Exception as e:
            self.fail(f"Null bytes caused crash: {e}")


class TestFileFormatDetectionRobustness(unittest.TestCase):
    """Test file format detection with malformed files."""

    def test_detect_format_empty_file(self):
        """Test format detection with empty file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = detect_file_format(tmp_path)
            # Should return something, not crash
            self.assertIn(result, ["raw", "processed", "unknown"])
        except Exception as e:
            self.fail(f"Empty file format detection caused crash: {e}")
        finally:
            os.unlink(tmp_path)

    def test_detect_format_binary_file(self):
        """Test format detection with binary file."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp:
            tmp.write(b"\xff\xfe\xfd\xfc" * 100)  # Binary data
            tmp_path = tmp.name

        try:
            result = detect_file_format(tmp_path)
            # Should handle gracefully, likely return "unknown"
            self.assertIsInstance(result, str)
        except Exception as e:
            # Some exceptions are expected for binary files
            self.assertIn("decode", str(e).lower())
        finally:
            os.unlink(tmp_path)

    def test_detect_format_very_large_file(self):
        """Test format detection with very large file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            # Write a lot of data
            for i in range(1000):
                tmp.write(f"line_{i}: some audit log data here\n")
            tmp_path = tmp.name

        try:
            result = detect_file_format(tmp_path)
            # Should complete without reading entire file
            self.assertIn(result, ["raw", "processed"])
        except Exception as e:
            self.fail(f"Large file format detection caused crash: {e}")
        finally:
            os.unlink(tmp_path)


class TestErrorRecoveryAndContinuation(unittest.TestCase):
    """Test that parser can recover from errors and continue processing."""

    def test_mixed_valid_invalid_records(self):
        """Test processing logs with mix of valid and invalid records."""
        mixed_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="httpd" path="/valid1" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----
COMPLETELY_INVALID_RECORD_HERE
----
type=AVC msg=audit(INVALID_TIMESTAMP): broken record
----
type=AVC msg=audit(1735221600.125:458): avc: denied { write } for pid=1235 comm="nginx" path="/valid2" scontext=system_u:system_r:nginx_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(mixed_log)
            # Should produce at least some valid denials
            self.assertIsInstance(denials, list)
            # Should track unparsed types
            self.assertIsInstance(unparsed, set)
        except Exception as e:
            self.fail(f"Mixed valid/invalid records caused crash: {e}")

    def test_recovery_after_parsing_error(self):
        """Test that parsing continues after encountering errors."""
        error_prone_log = """----
type=AVC msg=audit(1735221600.123:456): avc: denied { read } for pid=1234 comm="valid1"
----
type=MALFORMED_RECORD_TYPE msg=this_will_cause_issues
----
type=AVC msg=audit(1735221600.124:457): avc: denied { write } for pid=1235 comm="valid2" path="/test" scontext=system_u:system_r:nginx_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----"""
        try:
            denials, unparsed = _parse_avc_log_internal(error_prone_log)
            # Should continue processing despite errors
            self.assertIsInstance(denials, list)
            # Should have collected unparsed types
            self.assertGreater(len(unparsed), 0)
        except Exception as e:
            self.fail(f"Error recovery failed: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)