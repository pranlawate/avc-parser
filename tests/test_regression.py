#!/usr/bin/env python3
"""
Regression test suite for AVC parser.

This test suite verifies that existing functionality remains intact
during development by testing against known good outputs and behaviors.
"""

import unittest
import sys
import os
import json
from datetime import datetime

# Add parent directory to path so we can import parse_avc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_avc import parse_avc_log, sort_denials, filter_denials


class TestExistingFunctionality(unittest.TestCase):
    """Test that existing functionality still works as expected."""

    def setUp(self):
        """Set up test data with known AVC log samples."""
        self.simple_avc_log = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/index.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        self.multi_avc_log = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/file1.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=AVC msg=audit(06/18/2025 09:13:51.190:4997971): avc: denied { write } for pid=5678 comm="nginx" path="/var/log/nginx.log" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:httpd_log_t:s0 tclass=file permissive=1
type=AVC msg=audit(06/18/2025 09:14:51.190:4997972): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/file2.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        self.network_avc_log = """
type=AVC msg=audit(06/18/2025 09:15:51.190:4997973): avc: denied { name_connect } for pid=4182412 comm="httpd" dest=9999 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:jboss_management_port_t:s0 tclass=tcp_socket permissive=0
        """.strip()

    def test_basic_parsing_consistency(self):
        """Test that basic parsing returns expected structure."""
        denials, unparsed = parse_avc_log(self.simple_avc_log)

        # Verify basic structure
        self.assertEqual(len(denials), 1)
        self.assertIsInstance(denials, list)
        self.assertIsInstance(unparsed, set)

        denial = denials[0]
        self.assertIsInstance(denial, dict)

        # Verify expected fields are present
        required_fields = ['permission', 'pid', 'comm', 'path', 'scontext', 'tcontext', 'tclass', 'permissive']
        for field in required_fields:
            self.assertIn(field, denial, f"Field '{field}' missing from parsed denial")

        # Verify field values
        self.assertEqual(denial['permission'], 'read')
        self.assertEqual(denial['pid'], '1234')
        self.assertEqual(denial['comm'], 'httpd')
        self.assertEqual(denial['path'], '/var/www/html/index.html')
        self.assertEqual(denial['tclass'], 'file')
        self.assertEqual(denial['permissive'], '0')

    def test_multiple_denials_parsing(self):
        """Test parsing of multiple denials maintains independence."""
        denials, unparsed = parse_avc_log(self.multi_avc_log)

        self.assertEqual(len(denials), 3)

        # Verify each denial has correct data
        self.assertEqual(denials[0]['permission'], 'read')
        self.assertEqual(denials[0]['pid'], '1234')
        self.assertEqual(denials[0]['comm'], 'httpd')

        self.assertEqual(denials[1]['permission'], 'write')
        self.assertEqual(denials[1]['pid'], '5678')
        self.assertEqual(denials[1]['comm'], 'nginx')

        self.assertEqual(denials[2]['permission'], 'read')
        self.assertEqual(denials[2]['pid'], '1234')
        self.assertEqual(denials[2]['comm'], 'httpd')

        # Verify timestamps are different
        timestamps = [d['datetime_obj'] for d in denials if 'datetime_obj' in d]
        self.assertEqual(len(timestamps), 3)
        self.assertNotEqual(timestamps[0], timestamps[1])
        self.assertNotEqual(timestamps[1], timestamps[2])

    def test_network_denial_parsing(self):
        """Test that network denials are parsed correctly."""
        denials, unparsed = parse_avc_log(self.network_avc_log)

        self.assertEqual(len(denials), 1)
        denial = denials[0]

        self.assertEqual(denial['permission'], 'name_connect')
        self.assertEqual(denial['tclass'], 'tcp_socket')
        self.assertEqual(denial['dest_port'], '9999')
        self.assertNotIn('path', denial)  # Network denials don't have paths

    def test_semantic_analysis_consistency(self):
        """Test that semantic analysis fields are added consistently."""
        denials, _ = parse_avc_log(self.simple_avc_log)
        denial = denials[0]

        # Verify semantic analysis fields are present
        semantic_fields = [
            'permission_description',
            'contextual_analysis',
            'class_description',
            'source_type_description',
            'target_type_description'
        ]

        for field in semantic_fields:
            self.assertIn(field, denial, f"Semantic field '{field}' missing")

        # Verify semantic content
        self.assertEqual(denial['permission_description'], 'Read file content')
        self.assertEqual(denial['class_description'], 'file')
        self.assertIn('Web server', denial['contextual_analysis'])

    def test_timestamp_parsing_consistency(self):
        """Test that timestamp parsing works correctly."""
        denials, _ = parse_avc_log(self.simple_avc_log)
        denial = denials[0]

        # Verify timestamp fields
        self.assertIn('datetime_obj', denial)
        self.assertIn('datetime_str', denial)
        self.assertIn('timestamp', denial)

        # Verify timestamp types and values
        self.assertIsInstance(denial['datetime_obj'], datetime)
        self.assertIsInstance(denial['datetime_str'], str)
        self.assertIsInstance(denial['timestamp'], float)

        # Verify timestamp accuracy
        dt = denial['datetime_obj']
        self.assertEqual(dt.year, 2025)
        self.assertEqual(dt.month, 6)
        self.assertEqual(dt.day, 18)
        self.assertEqual(dt.hour, 9)
        self.assertEqual(dt.minute, 12)
        self.assertEqual(dt.second, 51)
        self.assertEqual(dt.microsecond, 190000)


class TestSortingRegression(unittest.TestCase):
    """Test that sorting functionality works as expected."""

    def setUp(self):
        """Set up test denial data with known timestamps."""
        self.test_denials = [
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 11),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),
                'count': 54,
                'log': {'comm': 'process_a'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 51),
                'last_seen_obj': datetime(2025, 6, 18, 9, 12, 51),
                'count': 6,
                'log': {'comm': 'process_b'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 31),
                'last_seen_obj': datetime(2025, 6, 18, 9, 12, 31),
                'count': 1,
                'log': {'comm': 'process_c'}
            }
        ]

    def test_recent_sort_order(self):
        """Test recent sort order (default)."""
        sorted_denials = sort_denials(self.test_denials, "recent")

        # Should be sorted by last_seen_obj descending
        expected_order = ['process_a', 'process_b', 'process_c']
        actual_order = [d['log']['comm'] for d in sorted_denials]

        self.assertEqual(actual_order, expected_order)

    def test_count_sort_order(self):
        """Test count-based sort order."""
        sorted_denials = sort_denials(self.test_denials, "count")

        # Should be sorted by count descending
        expected_order = ['process_a', 'process_b', 'process_c']
        actual_order = [d['log']['comm'] for d in sorted_denials]

        self.assertEqual(actual_order, expected_order)

    def test_chronological_sort_order(self):
        """Test chronological sort order."""
        sorted_denials = sort_denials(self.test_denials, "chrono")

        # Should be sorted by first_seen_obj ascending
        expected_order = ['process_a', 'process_c', 'process_b']
        actual_order = [d['log']['comm'] for d in sorted_denials]

        self.assertEqual(actual_order, expected_order)

    def test_invalid_sort_defaults_to_recent(self):
        """Test that invalid sort order defaults to recent."""
        sorted_denials = sort_denials(self.test_denials, "invalid")
        recent_sorted = sort_denials(self.test_denials, "recent")

        self.assertEqual(
            [d['log']['comm'] for d in sorted_denials],
            [d['log']['comm'] for d in recent_sorted]
        )


class TestFilteringRegression(unittest.TestCase):
    """Test that filtering functionality works correctly."""

    def setUp(self):
        """Set up test denial data for filtering."""
        self.test_denials = [
            {
                'log': {
                    'comm': 'httpd',
                    'path': '/var/www/html/index.html'
                },
                'correlations': [
                    {'path': '/var/www/html/config.php'}
                ]
            },
            {
                'log': {
                    'comm': 'nginx',
                    'path': '/var/log/nginx.log'
                },
                'correlations': []
            },
            {
                'log': {
                    'comm': 'httpd',
                    'path': '/etc/httpd/conf/httpd.conf'
                },
                'correlations': []
            }
        ]

    def test_process_filtering(self):
        """Test filtering by process name."""
        filtered = filter_denials(self.test_denials, process_filter='httpd')

        self.assertEqual(len(filtered), 2)
        for denial in filtered:
            self.assertEqual(denial['log']['comm'], 'httpd')

    def test_path_filtering(self):
        """Test filtering by path pattern."""
        filtered = filter_denials(self.test_denials, path_filter='/var/www/*')

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['log']['comm'], 'httpd')
        self.assertIn('/var/www/html/', filtered[0]['log']['path'])

    def test_correlation_path_filtering(self):
        """Test filtering includes correlation paths."""
        filtered = filter_denials(self.test_denials, path_filter='/var/www/html/*')

        # Should include denial with correlation path match
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['log']['comm'], 'httpd')

    def test_combined_filtering(self):
        """Test filtering with both process and path filters."""
        filtered = filter_denials(
            self.test_denials,
            process_filter='httpd',
            path_filter='/var/www/*'
        )

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['log']['comm'], 'httpd')
        self.assertIn('/var/www/', filtered[0]['log']['path'])

    def test_no_filtering(self):
        """Test that no filters returns all denials."""
        filtered = filter_denials(self.test_denials)

        self.assertEqual(len(filtered), 3)
        self.assertEqual(filtered, self.test_denials)


class TestErrorHandlingRegression(unittest.TestCase):
    """Test that error handling remains robust."""

    def test_empty_log_handling(self):
        """Test handling of empty log input."""
        denials, unparsed = parse_avc_log("")

        self.assertEqual(len(denials), 0)
        self.assertIsInstance(denials, list)
        self.assertIsInstance(unparsed, set)

    def test_malformed_log_handling(self):
        """Test handling of malformed log input."""
        malformed_log = "This is not an audit log at all"
        denials, unparsed = parse_avc_log(malformed_log)

        # Should not crash, should return empty results
        self.assertIsInstance(denials, list)
        self.assertIsInstance(unparsed, set)

    def test_partial_avc_record_handling(self):
        """Test handling of incomplete AVC records."""
        partial_log = "type=AVC msg=audit(123:456): avc: denied"  # Missing fields
        denials, unparsed = parse_avc_log(partial_log)

        # Should not crash, may or may not parse depending on required fields
        self.assertIsInstance(denials, list)
        self.assertIsInstance(unparsed, set)

    def test_corrupted_timestamp_handling(self):
        """Test handling of corrupted timestamps."""
        corrupted_log = 'type=AVC msg=audit(INVALID:456): avc: denied { read } for pid=1234'
        denials, unparsed = parse_avc_log(corrupted_log)

        # Should not crash, timestamp should be None or missing
        self.assertIsInstance(denials, list)
        if denials:
            # If parsing succeeded, timestamp fields should handle the corruption gracefully
            denial = denials[0]
            # Either datetime_obj is None or the field is missing
            self.assertTrue(
                'datetime_obj' not in denial or denial['datetime_obj'] is None
            )


class TestDataIntegrityRegression(unittest.TestCase):
    """Test that data integrity is maintained during processing."""

    def test_context_object_integrity(self):
        """Test that AvcContext objects are properly handled."""
        log_with_contexts = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        denials, _ = parse_avc_log(log_with_contexts)
        denial = denials[0]

        # Verify context fields exist and are properly typed
        self.assertIn('scontext', denial)
        self.assertIn('tcontext', denial)

        # Check if they're AvcContext objects or strings
        from parse_avc import AvcContext
        scontext = denial['scontext']
        tcontext = denial['tcontext']

        # Should be either AvcContext objects or strings
        self.assertTrue(
            isinstance(scontext, (AvcContext, str)),
            f"scontext is {type(scontext)}, expected AvcContext or str"
        )
        self.assertTrue(
            isinstance(tcontext, (AvcContext, str)),
            f"tcontext is {type(tcontext)}, expected AvcContext or str"
        )

        # If they're AvcContext objects, they should be valid
        if isinstance(scontext, AvcContext):
            self.assertTrue(scontext.is_valid())
        if isinstance(tcontext, AvcContext):
            self.assertTrue(tcontext.is_valid())

    def test_permission_set_integrity(self):
        """Test that permission handling maintains data integrity."""
        log_with_multiple_perms = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read write } for pid=1234 comm="httpd" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        denials, _ = parse_avc_log(log_with_multiple_perms)
        denial = denials[0]

        # Permission field should contain the full permission string
        self.assertIn('permission', denial)
        self.assertIn('read', denial['permission'])
        self.assertIn('write', denial['permission'])

    def test_numeric_field_types(self):
        """Test that numeric fields maintain correct types."""
        log_with_numbers = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" ino=67554729 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
        """.strip()

        denials, _ = parse_avc_log(log_with_numbers)
        denial = denials[0]

        # Verify field types
        self.assertIsInstance(denial['pid'], str)  # PIDs are stored as strings
        self.assertIsInstance(denial['permissive'], str)  # Permissive is stored as string
        if 'ino' in denial:
            self.assertIsInstance(denial['ino'], str)  # Inode numbers stored as strings


if __name__ == '__main__':
    unittest.main()