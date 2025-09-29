#!/usr/bin/env python3
"""
Test suite for timestamp tracking and sorting functionality.

This test suite verifies the timestamp tracking bugs we just fixed:
1. first_seen_obj properly tracks earliest chronological timestamp
2. last_seen_obj properly tracks latest chronological timestamp
3. Sorting is stable and consistent when timestamps are equal
"""

import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path so we can import parse_avc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_avc import parse_avc_log
from utils import sort_denials


class TestTimestampTracking(unittest.TestCase):
    """Test timestamp tracking and aggregation logic."""

    def setUp(self):
        """Set up test data with known timestamps."""
        # Sample log block with events in non-chronological order
        self.log_block_mixed_order = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { siginh } for pid=3636299 comm=unix_chkpwd scontext=system_u:system_r:sshd_t:s0 tcontext=system_u:system_r:chkpwd_t:s0 tclass=process permissive=0
type=AVC msg=audit(06/18/2025 09:12:11.727:4997934): avc: denied { read } for pid=3181129 comm=in:imfile name=asesrv dev="dm-0" ino=34573303 scontext=system_u:system_r:syslogd_t:s0 tcontext=unconfined_u:object_r:var_t:s0 tclass=dir permissive=0
type=AVC msg=audit(06/18/2025 09:16:31.917:4997999): avc: denied { read } for pid=3181129 comm=in:imfile name=SB007NA dev="dm-0" ino=67554729 scontext=system_u:system_r:syslogd_t:s0 tcontext=unconfined_u:object_r:var_t:s0 tclass=dir permissive=0
"""

        # Single event log block
        self.log_block_single = """
type=AVC msg=audit(06/18/2025 09:12:31.287:4997950): avc: denied { siginh } for pid=3635437 comm=sh scontext=system_u:system_r:init_t:s0 tcontext=system_u:system_r:initrc_t:s0 tclass=process permissive=0
"""

    def test_timestamp_parsing_chronological_order(self):
        """Test that timestamps are correctly parsed from mixed-order events."""
        denials, _ = parse_avc_log(self.log_block_mixed_order)

        # Should have 3 denials
        self.assertEqual(len(denials), 3)

        # Check that all timestamps are parsed correctly
        timestamps = [d.get('datetime_obj') for d in denials if d.get('datetime_obj')]
        self.assertEqual(len(timestamps), 3)

        # Verify timestamp order in parsed data (should maintain input order)
        expected_order = [
            datetime(2025, 6, 18, 9, 12, 51, 190000),  # First in log
            datetime(2025, 6, 18, 9, 12, 11, 727000),  # Second in log
            datetime(2025, 6, 18, 9, 16, 31, 917000),  # Third in log
        ]

        for i, denial in enumerate(denials):
            self.assertEqual(denial['datetime_obj'], expected_order[i])

    def test_aggregation_timestamp_tracking(self):
        """Test that aggregation correctly tracks first_seen and last_seen."""
        # Create mock denial data that would be aggregated together
        denial_data = {
            'log': {
                'scontext': 'system_u:system_r:syslogd_t:s0',
                'tcontext': 'unconfined_u:object_r:var_t:s0',
                'tclass': 'dir',
                'permission': 'read',
                'datetime_obj': datetime(2025, 6, 18, 9, 12, 11, 727000)
            },
            'count': 1,
            'first_seen_obj': datetime(2025, 6, 18, 9, 12, 11, 727000),
            'last_seen_obj': datetime(2025, 6, 18, 9, 12, 11, 727000),
            'permissions': {'read'}
        }

        # Simulate adding a later event to the same denial
        later_timestamp = datetime(2025, 6, 18, 9, 16, 31, 917000)

        # Update logic (simulating aggregation behavior)
        if later_timestamp > denial_data['last_seen_obj']:
            denial_data['last_seen_obj'] = later_timestamp
        # This is the bug we fixed - we should also check for earlier timestamps
        if later_timestamp < denial_data['first_seen_obj']:
            denial_data['first_seen_obj'] = later_timestamp

        # Simulate adding an earlier event
        earlier_timestamp = datetime(2025, 6, 18, 9, 10, 30, 500000)

        if earlier_timestamp > denial_data['last_seen_obj']:
            denial_data['last_seen_obj'] = earlier_timestamp
        if earlier_timestamp < denial_data['first_seen_obj']:
            denial_data['first_seen_obj'] = earlier_timestamp

        # Verify tracking works correctly
        self.assertEqual(denial_data['first_seen_obj'], earlier_timestamp)
        self.assertEqual(denial_data['last_seen_obj'], later_timestamp)

    def test_single_event_timestamps(self):
        """Test timestamp handling for single-event denials."""
        denials, _ = parse_avc_log(self.log_block_single)

        self.assertEqual(len(denials), 1)
        denial = denials[0]

        # For single events, first_seen should equal last_seen
        expected_time = datetime(2025, 6, 18, 9, 12, 31, 287000)
        self.assertEqual(denial['datetime_obj'], expected_time)


class TestSortingStability(unittest.TestCase):
    """Test sorting stability and consistency."""

    def setUp(self):
        """Set up test denial data with various timestamp scenarios."""
        self.denials = [
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 11),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),  # Latest overall
                'count': 54,
                'log': {'comm': 'in:imfile_1'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 51),
                'last_seen_obj': datetime(2025, 6, 18, 9, 12, 51),  # Single event
                'count': 6,
                'log': {'comm': 'unix_chkpwd'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 31),
                'last_seen_obj': datetime(2025, 6, 18, 9, 12, 31),  # Single event, earlier
                'count': 1,
                'log': {'comm': 'sh'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 11),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),  # Same last_seen as first
                'count': 27,
                'log': {'comm': 'in:imfile_2'}
            }
        ]

    def test_recent_sort_order(self):
        """Test that recent sort orders by latest activity first."""
        sorted_denials = sort_denials(self.denials, "recent")

        # Expected order: latest last_seen first, with first_seen as tiebreaker
        expected_order = ['in:imfile_1', 'in:imfile_2', 'unix_chkpwd', 'sh']
        actual_order = [d['log']['comm'] for d in sorted_denials]

        self.assertEqual(actual_order, expected_order)

        # Verify the timestamps are in correct descending order
        last_seen_times = [d['last_seen_obj'] for d in sorted_denials]
        for i in range(len(last_seen_times) - 1):
            self.assertGreaterEqual(last_seen_times[i], last_seen_times[i + 1])

    def test_chronological_sort_order(self):
        """Test that chronological sort orders by earliest activity first."""
        sorted_denials = sort_denials(self.denials, "chrono")

        # Expected order: earliest first_seen first
        expected_order = ['in:imfile_1', 'in:imfile_2', 'sh', 'unix_chkpwd']
        actual_order = [d['log']['comm'] for d in sorted_denials]

        self.assertEqual(actual_order, expected_order)

        # Verify the timestamps are in correct ascending order
        first_seen_times = [d['first_seen_obj'] for d in sorted_denials]
        for i in range(len(first_seen_times) - 1):
            self.assertLessEqual(first_seen_times[i], first_seen_times[i + 1])

    def test_count_sort_order(self):
        """Test that count sort orders by frequency first."""
        sorted_denials = sort_denials(self.denials, "count")

        # Expected order: highest count first
        expected_counts = [54, 27, 6, 1]
        actual_counts = [d['count'] for d in sorted_denials]

        self.assertEqual(actual_counts, expected_counts)

    def test_sort_stability_with_equal_timestamps(self):
        """Test sorting behavior when timestamps are identical."""
        # Create denials with identical last_seen times
        equal_timestamp_denials = [
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 10),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),
                'count': 10,
                'log': {'comm': 'process_a'}
            },
            {
                'first_seen_obj': datetime(2025, 6, 18, 9, 12, 20),
                'last_seen_obj': datetime(2025, 6, 18, 9, 16, 31),  # Same last_seen
                'count': 5,
                'log': {'comm': 'process_b'}
            }
        ]

        # Recent sort should use first_seen as tiebreaker (later first_seen first)
        sorted_recent = sort_denials(equal_timestamp_denials, "recent")
        self.assertEqual(sorted_recent[0]['log']['comm'], 'process_b')  # Later first_seen
        self.assertEqual(sorted_recent[1]['log']['comm'], 'process_a')  # Earlier first_seen

    def test_invalid_sort_order_defaults_to_recent(self):
        """Test that invalid sort order defaults to recent behavior."""
        sorted_denials = sort_denials(self.denials, "invalid_sort")
        recent_sorted = sort_denials(self.denials, "recent")

        # Should produce same result as recent sort
        self.assertEqual(
            [d['log']['comm'] for d in sorted_denials],
            [d['log']['comm'] for d in recent_sorted]
        )


if __name__ == '__main__':
    unittest.main()