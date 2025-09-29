#!/usr/bin/env python3
"""
Validation function tests for AVC Parser

Tests the argument validation, file validation, and edge case handling
to ensure robust error checking and user guidance.
"""

import unittest
import sys
import os
import tempfile
from unittest.mock import patch, MagicMock

# Add parent directory to path to import parse_avc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parse_avc import human_time_ago
from validators import (
    validate_arguments,
    validate_raw_file,
    validate_avc_file,
    validate_file_with_auto_detection,
)
from config import MAX_FILE_SIZE_MB
from datetime import datetime, timedelta
from rich.console import Console


class TestArgumentValidation(unittest.TestCase):
    """Test the argument validation logic."""

    def setUp(self):
        """Set up test console."""
        self.console = Console(file=open(os.devnull, "w"))  # Suppress output

    def test_conflicting_file_arguments(self):
        """Test that conflicting file arguments are caught."""

        class MockArgs:
            file = "test.log"
            raw_file = "raw.log"
            avc_file = None
            json = False

        with self.assertRaises(SystemExit):
            validate_arguments(MockArgs(), self.console)

    def test_json_in_test_environment(self):
        """Test that JSON flag behaves correctly in test environment (treated as interactive)."""

        class MockArgs:
            file = None
            raw_file = None
            avc_file = None
            json = True

        # In test environment, stdin is redirected and treated as interactive mode
        # So JSON should still fail (for safety in test environments)
        with self.assertRaises(SystemExit):
            validate_arguments(MockArgs(), self.console)

    def test_valid_file_argument(self):
        """Test valid --file argument."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("type=AVC msg=audit(1234567890.123:456): avc: denied { read }")
            tmp_path = tmp.name

        try:

            class MockArgs:
                file = tmp_path
                raw_file = None
                avc_file = None
                json = False
                pager = False

            result = validate_arguments(MockArgs(), self.console)
            self.assertIn(result, ["raw_file", "avc_file"])
        finally:
            os.unlink(tmp_path)

    def test_interactive_mode(self):
        """Test interactive mode validation."""

        class MockArgs:
            file = None
            raw_file = None
            avc_file = None
            json = False
            pager = False

        result = validate_arguments(MockArgs(), self.console)
        self.assertEqual(result, "interactive")


class TestFileValidation(unittest.TestCase):
    """Test file validation functions."""

    def setUp(self):
        """Set up test console and temporary files."""
        self.console = Console(file=open(os.devnull, "w"))

    def test_validate_nonexistent_file(self):
        """Test validation of non-existent file."""
        with self.assertRaises(SystemExit):
            validate_raw_file("/nonexistent/file.log", self.console)

    def test_validate_empty_file(self):
        """Test validation of empty file."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with self.assertRaises(SystemExit):
                validate_raw_file(tmp_path, self.console)
        finally:
            os.unlink(tmp_path)

    def test_validate_large_file_warning(self):
        """Test warning for large files."""
        # Create a file larger than the limit (we'll mock the size check)
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("type=AVC msg=audit(1234567890.123:456): avc: denied { read }")
            tmp_path = tmp.name

        try:
            # Mock os.path.getsize to return a large size
            with patch("validators.file_validator.os.path.getsize") as mock_getsize:
                mock_getsize.return_value = (MAX_FILE_SIZE_MB + 1) * 1024 * 1024
                # This should print a warning but not exit
                result = validate_raw_file(tmp_path, self.console)
                self.assertEqual(result, "raw_file")
        finally:
            os.unlink(tmp_path)

    def test_validate_avc_file_with_content(self):
        """Test AVC file validation with proper content."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("type=AVC msg=audit(1234567890.123:456): avc: denied { read }")
            tmp_path = tmp.name

        try:
            result = validate_avc_file(tmp_path, self.console)
            self.assertEqual(result, "avc_file")
        finally:
            os.unlink(tmp_path)

    def test_auto_detection_validation(self):
        """Test auto-detection file validation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("type=AVC msg=audit(1234567890.123:456): avc: denied { read }")
            tmp_path = tmp.name

        try:
            result = validate_file_with_auto_detection(tmp_path, self.console)
            self.assertIn(result, ["raw_file", "avc_file"])
        finally:
            os.unlink(tmp_path)


class TestTimeFormatting(unittest.TestCase):
    """Test time formatting functions."""

    def test_human_time_ago_days(self):
        """Test time formatting for days ago."""
        past_time = datetime.now() - timedelta(days=5)
        result = human_time_ago(past_time)
        self.assertIn("day", result)

    def test_human_time_ago_hours(self):
        """Test time formatting for hours ago."""
        past_time = datetime.now() - timedelta(hours=3)
        result = human_time_ago(past_time)
        self.assertIn("hour", result)

    def test_human_time_ago_minutes(self):
        """Test time formatting for minutes ago."""
        past_time = datetime.now() - timedelta(minutes=30)
        result = human_time_ago(past_time)
        self.assertIn("minute", result)

    def test_human_time_ago_none(self):
        """Test time formatting with None input."""
        result = human_time_ago(None)
        self.assertEqual(result, "an unknown time")

    def test_human_time_ago_years(self):
        """Test time formatting for years ago."""
        past_time = datetime.now() - timedelta(days=400)
        result = human_time_ago(past_time)
        self.assertIn("year", result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Set up test console."""
        self.console = Console(file=open(os.devnull, "w"))

    def test_binary_file_detection(self):
        """Test detection of binary files."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp:
            # Write invalid UTF-8 bytes that will trigger UnicodeDecodeError
            tmp.write(b"\xff\xfe\xfd\xfc" * 500)  # Invalid UTF-8 sequence repeated
            tmp_path = tmp.name

        try:
            with self.assertRaises(SystemExit):
                validate_raw_file(tmp_path, self.console)
        finally:
            os.unlink(tmp_path)

    def test_permission_denied_simulation(self):
        """Test permission denied error handling."""
        # Create a file and then mock permission error
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("test content")
            tmp_path = tmp.name

        try:
            # Mock open to raise PermissionError
            with patch(
                "validators.file_validator.open", side_effect=PermissionError("Permission denied")
            ):
                with self.assertRaises(SystemExit):
                    validate_raw_file(tmp_path, self.console)
        finally:
            os.unlink(tmp_path)

    def test_unicode_decode_error(self):
        """Test Unicode decode error handling."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp:
            # Write invalid UTF-8 bytes
            tmp.write(b"\xff\xfe\xfd")
            tmp_path = tmp.name

        try:
            with self.assertRaises(SystemExit):
                validate_avc_file(tmp_path, self.console)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
