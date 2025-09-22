#!/usr/bin/env python3
"""
Edge case and input validation test suite for AVC parser.

This test suite verifies handling of edge cases, malformed input,
boundary conditions, and various input validation scenarios.
"""

import unittest
import sys
import os
import tempfile
from datetime import datetime

# Add parent directory to path so we can import parse_avc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_avc import (
    parse_avc_log,
    parse_audit_record_text,
    process_individual_avc_record,
    AvcContext,
    validate_log_entry,
    detect_file_format,
    validate_arguments,
    sort_denials,
    filter_denials
)


class TestMalformedInput(unittest.TestCase):
    """Test handling of malformed and corrupted input."""

    def test_completely_invalid_input(self):
        """Test handling of completely non-audit input."""
        invalid_inputs = [
            "",
            "   ",
            "\n\n\n",
            "This is a random text file",
            "HTTP/1.1 200 OK\nContent-Type: text/html",
            "#!/bin/bash\necho 'hello world'",
            "SELECT * FROM table WHERE id = 1;",
        ]

        for invalid_input in invalid_inputs:
            with self.subTest(input=invalid_input[:20]):
                denials, unparsed = parse_avc_log(invalid_input)
                self.assertIsInstance(denials, list)
                self.assertIsInstance(unparsed, set)
                # Should not crash, may return empty results

    def test_partially_corrupted_audit_records(self):
        """Test handling of partially corrupted audit records."""
        corrupted_records = [
            # Missing msg= part
            "type=AVC audit(123:456): avc: denied { read }",
            # Missing type= part
            "msg=audit(123:456): avc: denied { read }",
            # Malformed timestamp
            "type=AVC msg=audit(INVALID_TIMESTAMP): avc: denied { read }",
            # Missing colon after audit()
            "type=AVC msg=audit(123:456) avc: denied { read }",
            # Truncated record
            "type=AVC msg=audit(123:456): avc: den",
            # Invalid characters in fields
            "type=AVC msg=audit(123:456): avc: denied { read } for pid=\x00\x01",
        ]

        for corrupted in corrupted_records:
            with self.subTest(record=corrupted[:40]):
                # Should not crash on corrupted input
                try:
                    denials, unparsed = parse_avc_log(corrupted)
                    self.assertIsInstance(denials, list)
                    self.assertIsInstance(unparsed, set)
                except Exception as e:
                    self.fail(f"parse_avc_log crashed on corrupted input: {e}")

    def test_mixed_valid_invalid_records(self):
        """Test handling of logs with mix of valid and invalid records."""
        mixed_log = """
This is not an audit record
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
Random text line that should be ignored
type=INVALID msg=corrupted: this should not parse
type=AVC msg=audit(06/18/2025 09:13:51.190:4997971): avc: denied { write } for pid=5678 comm="nginx" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_log_t:s0 tclass=file permissive=1
        """.strip()

        denials, unparsed = parse_avc_log(mixed_log)

        # Should extract valid records and ignore invalid ones
        self.assertGreaterEqual(len(denials), 1)  # At least one valid record
        for denial in denials:
            self.assertIn('permission', denial)  # Valid records should have required fields

    def test_extreme_field_values(self):
        """Test handling of extreme field values."""
        extreme_cases = [
            # Very long path
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="' + 'A' * 4000 + '" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Very long comm name
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="' + 'B' * 1000 + '" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Large PID number
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=999999999999 comm="test" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Many permissions
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read write execute append create unlink rename setattr getattr lock ioctl } for pid=1234 comm="test" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
        ]

        for extreme_case in extreme_cases:
            with self.subTest(case=extreme_case[:60] + "..."):
                try:
                    denials, unparsed = parse_avc_log(extreme_case)
                    self.assertIsInstance(denials, list)
                    if denials:
                        # If parsing succeeded, verify basic structure
                        denial = denials[0]
                        self.assertIsInstance(denial, dict)
                        self.assertIn('permission', denial)
                except Exception as e:
                    self.fail(f"Extreme case parsing failed: {e}")


class TestBoundaryConditions(unittest.TestCase):
    """Test boundary conditions and edge cases."""

    def test_minimum_valid_record(self):
        """Test parsing of minimal valid AVC record."""
        minimal_record = 'type=AVC msg=audit(123:456): avc: denied { read } for pid=1'
        denials, unparsed = parse_avc_log(minimal_record)

        # Should parse successfully despite missing many optional fields
        if denials:  # If it parses
            denial = denials[0]
            self.assertEqual(denial['permission'], 'read')
            self.assertEqual(denial['pid'], '1')

    def test_maximum_complexity_record(self):
        """Test parsing of maximally complex AVC record."""
        complex_record = '''
node=server1 type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read write append execute create unlink rename setattr getattr lock ioctl map } for pid=1234567890 comm="very-long-process-name-that-goes-on-and-on" path="/very/long/path/with/many/components/that/tests/the/limits/of/path/parsing/file.txt" name="file.txt" dev="dm-0" ino=67554729 scontext=system_u:system_r:very_long_domain_name_t:s0-s0:c0.c1023 tcontext=unconfined_u:object_r:very_long_object_type_t:s0-s0:c0.c1023 tclass=file permissive=0
        '''.strip()

        denials, unparsed = parse_avc_log(complex_record)

        if denials:
            denial = denials[0]
            # Verify complex fields are parsed
            self.assertIn('read', denial['permission'])
            self.assertIn('write', denial['permission'])
            self.assertEqual(denial['pid'], '1234567890')
            self.assertIn('very-long-process-name', denial['comm'])

    def test_unicode_and_special_characters(self):
        """Test handling of Unicode and special characters."""
        unicode_cases = [
            # Unicode in comm field
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="测试进程" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Unicode in path
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="test" path="/home/用户/文档/файл.txt" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Special characters in path
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="test" path="/path/with spaces/and-special!@#$%^&*()_+chars.txt" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
        ]

        for unicode_case in unicode_cases:
            with self.subTest(case=unicode_case[:60] + "..."):
                try:
                    denials, unparsed = parse_avc_log(unicode_case)
                    self.assertIsInstance(denials, list)
                    # Should handle Unicode gracefully
                except UnicodeError:
                    self.fail("Unicode characters caused parsing to fail")

    def test_empty_and_null_fields(self):
        """Test handling of empty and null field values."""
        empty_field_cases = [
            # Empty comm field
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Null path field
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="test" path="(null)" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
            # Missing optional fields
            'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0',
        ]

        for empty_case in empty_field_cases:
            with self.subTest(case=empty_case[:60] + "..."):
                denials, unparsed = parse_avc_log(empty_case)
                self.assertIsInstance(denials, list)
                # Should handle empty/null fields gracefully

    def test_timestamp_edge_cases(self):
        """Test handling of various timestamp formats and edge cases."""
        timestamp_cases = [
            # Year 2038 problem (Unix timestamp)
            'type=AVC msg=audit(01/19/2038 03:14:07.999:999999): avc: denied { read } for pid=1234',
            # Very precise microseconds
            'type=AVC msg=audit(06/18/2025 09:12:51.999999:4997970): avc: denied { read } for pid=1234',
            # Zero timestamp
            'type=AVC msg=audit(01/01/1970 00:00:00.000:1): avc: denied { read } for pid=1234',
            # Alternative date format
            'type=AVC msg=audit(18/06/25 09:12:51.190:4997970): avc: denied { read } for pid=1234',
        ]

        for timestamp_case in timestamp_cases:
            with self.subTest(case=timestamp_case[:60] + "..."):
                denials, unparsed = parse_avc_log(timestamp_case)
                # Should not crash on various timestamp formats
                self.assertIsInstance(denials, list)


class TestValidationEdgeCases(unittest.TestCase):
    """Test validation logic edge cases."""

    def test_log_validation_edge_cases(self):
        """Test log validation with various edge cases."""
        # Test with only whitespace
        is_valid, sanitized, warnings = validate_log_entry("   \n  \t  \n   ")
        self.assertFalse(is_valid)
        self.assertIn("Empty or whitespace-only", warnings[0])

        # Test with control characters
        log_with_control = "type=AVC\x00msg=audit(123:456)\x01: avc: denied"
        is_valid, sanitized, warnings = validate_log_entry(log_with_control)
        self.assertTrue(is_valid)
        self.assertNotIn('\x00', sanitized)
        self.assertNotIn('\x01', sanitized)
        self.assertTrue(any("control characters" in w for w in warnings))

        # Test with very long line
        very_long_line = "type=AVC msg=audit(123:456): " + "A" * 10000
        is_valid, sanitized, warnings = validate_log_entry(very_long_line)
        # Should handle very long lines gracefully
        self.assertIsInstance(is_valid, bool)
        self.assertIsInstance(sanitized, str)
        self.assertIsInstance(warnings, list)

    def test_context_parsing_edge_cases(self):
        """Test AvcContext parsing with edge cases."""
        edge_cases = [
            None,  # None input
            "",    # Empty string
            "single_field",  # Single field
            "user:role",     # Missing type and MLS
            "user:role:type",  # Missing MLS (should get default s0)
            "user:role:type:very:complex:mls:label:with:many:colons",  # Complex MLS
            "system_u:system_r:type_with_very_long_name_that_goes_on_and_on_t:s0",  # Long type name
        ]

        for edge_case in edge_cases:
            with self.subTest(context=str(edge_case)[:40]):
                context = AvcContext(edge_case)
                # Should not crash on any input
                self.assertIsInstance(context.is_valid(), bool)
                self.assertIsInstance(str(context), str)

    def test_file_format_detection_edge_cases(self):
        """Test file format detection with edge cases."""
        # Test with very small file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("a")  # Single character
            tiny_file = f.name

        try:
            format_type = detect_file_format(tiny_file)
            self.assertIn(format_type, ['raw', 'processed'])
        finally:
            os.unlink(tiny_file)

        # Test with empty file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            pass  # Empty file
            empty_file = f.name

        try:
            format_type = detect_file_format(empty_file)
            self.assertIn(format_type, ['raw', 'processed'])
        finally:
            os.unlink(empty_file)

        # Test with non-existent file
        format_type = detect_file_format("/non/existent/file.log")
        self.assertIn(format_type, ['raw', 'processed'])  # Should return default


class TestPerformanceEdgeCases(unittest.TestCase):
    """Test performance-related edge cases."""

    def test_large_number_of_denials(self):
        """Test handling of logs with many denials."""
        # Generate a log with many similar denials
        log_lines = []
        for i in range(100):  # 100 denials
            log_lines.append(f'type=AVC msg=audit(06/18/2025 09:12:{i:02d}.190:499797{i}): avc: denied {{ read }} for pid={1234+i} comm="proc{i}" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0')

        large_log = '\n'.join(log_lines)

        try:
            denials, unparsed = parse_avc_log(large_log)
            self.assertEqual(len(denials), 100)
            # Verify parsing maintains uniqueness correctly
            pids = [d['pid'] for d in denials]
            self.assertEqual(len(set(pids)), 100)  # All PIDs should be unique
        except Exception as e:
            self.fail(f"Large log parsing failed: {e}")

    def test_deeply_nested_correlation_data(self):
        """Test handling of complex correlation scenarios."""
        # Create a log block that would generate complex correlations
        complex_log = """
type=SYSCALL msg=audit(06/18/2025 09:12:51.190:4997970): arch=x86_64 syscall=openat success=no exit=-13
type=CWD msg=audit(06/18/2025 09:12:51.190:4997970): cwd="/very/long/working/directory/path/that/tests/correlation/depth"
type=PATH msg=audit(06/18/2025 09:12:51.190:4997970): item=0 name="/very/long/path/to/target/file/that/should/be/correlated/properly.txt" inode=67554729 dev=dm-0
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="test_process" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        denials, unparsed = parse_avc_log(complex_log)

        if denials:
            denial = denials[0]
            # Should have correlation from PATH record
            self.assertIn('path', denial)
            self.assertIn('cwd', denial)
            # Verify correlation data integrity
            if 'path' in denial:
                self.assertIn('/very/long/path/to/target', denial['path'])


class TestSortingAndFilteringEdgeCases(unittest.TestCase):
    """Test sorting and filtering edge cases."""

    def test_sorting_with_none_timestamps(self):
        """Test sorting when some denials have None timestamps."""
        denials_with_nones = [
            {
                'first_seen_obj': None,
                'last_seen_obj': None,
                'count': 1,
                'log': {'comm': 'process_a'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 11),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),
                'count': 2,
                'log': {'comm': 'process_b'}
            },
            {
                'first_seen_obj': None,
                'last_seen_obj': datetime(2025, 6, 18, 9, 15, 0),
                'count': 3,
                'log': {'comm': 'process_c'}
            }
        ]

        # Should not crash on None timestamps
        for sort_order in ['recent', 'count', 'chrono']:
            with self.subTest(sort_order=sort_order):
                try:
                    sorted_denials = sort_denials(denials_with_nones, sort_order)
                    self.assertEqual(len(sorted_denials), 3)
                except Exception as e:
                    self.fail(f"Sorting with None timestamps failed for {sort_order}: {e}")

    def test_filtering_with_missing_fields(self):
        """Test filtering when some denials have missing fields."""
        denials_with_missing = [
            {
                'log': {
                    'comm': 'httpd',
                    # Missing path
                },
                'correlations': []
            },
            {
                'log': {
                    # Missing comm
                    'path': '/var/www/html/index.html'
                },
                'correlations': []
            },
            {
                'log': {
                    'comm': 'nginx',
                    'path': '/var/log/nginx.log'
                },
                # Missing correlations
            }
        ]

        # Should not crash on missing fields
        try:
            filtered = filter_denials(denials_with_missing, process_filter='httpd')
            self.assertIsInstance(filtered, list)

            filtered = filter_denials(denials_with_missing, path_filter='/var/www/*')
            self.assertIsInstance(filtered, list)

            filtered = filter_denials(denials_with_missing, process_filter='httpd', path_filter='/var/www/*')
            self.assertIsInstance(filtered, list)
        except Exception as e:
            self.fail(f"Filtering with missing fields failed: {e}")

    def test_empty_denial_list_operations(self):
        """Test operations on empty denial lists."""
        empty_list = []

        # Sorting empty list
        for sort_order in ['recent', 'count', 'chrono']:
            sorted_empty = sort_denials(empty_list, sort_order)
            self.assertEqual(sorted_empty, [])

        # Filtering empty list
        filtered_empty = filter_denials(empty_list, process_filter='httpd')
        self.assertEqual(filtered_empty, [])

        filtered_empty = filter_denials(empty_list, path_filter='/var/*')
        self.assertEqual(filtered_empty, [])


if __name__ == '__main__':
    unittest.main()