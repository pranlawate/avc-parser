#!/usr/bin/env python3
"""
Integration tests for AVC Parser

Tests end-to-end functionality including command-line processing,
JSON output, and integration with test files.
"""

import unittest
import sys
import os
import json
import subprocess
import tempfile

# Add parent directory to path to import parse_avc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestJSONOutput(unittest.TestCase):
    """Test JSON output functionality."""

    def test_json_output_format(self):
        """Test that JSON output is valid and contains expected fields."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Run parser with JSON output
        result = subprocess.run([
            sys.executable, "parse_avc.py", "--file", test_file, "--json"
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")

        # Parse JSON output
        try:
            json_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}")

        # Check expected structure
        self.assertIsInstance(json_data, dict)
        self.assertIn("unique_denials", json_data)
        self.assertIn("summary", json_data)

    def test_json_with_nonexistent_file(self):
        """Test JSON output with non-existent file."""
        result = subprocess.run([
            sys.executable, "parse_avc.py", "--file", "/nonexistent.log", "--json"
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertNotEqual(result.returncode, 0)


class TestCommandLineInterface(unittest.TestCase):
    """Test command-line interface functionality."""

    def test_help_output(self):
        """Test that help output is generated without errors."""
        result = subprocess.run([
            sys.executable, "parse_avc.py", "--help"
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertEqual(result.returncode, 0)
        self.assertIn("--file", result.stdout)
        self.assertIn("auto-detects", result.stdout)

    def test_conflicting_arguments(self):
        """Test that conflicting arguments are rejected."""
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "test.log",
            "--raw-file", "raw.log"
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Conflicting Arguments", result.stderr)

    def test_auto_detection_feedback(self):
        """Test that auto-detection provides feedback."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run([
            sys.executable, "parse_avc.py", "--file", test_file
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertEqual(result.returncode, 0)
        self.assertIn("Auto-detected", result.stdout)


class TestFileProcessing(unittest.TestCase):
    """Test file processing workflows."""

    def test_processing_all_test_files(self):
        """Test that all test files can be processed without errors."""
        test_dir = "testAVC"

        if not os.path.exists(test_dir):
            self.skipTest(f"Test directory {test_dir} not found")

        for filename in os.listdir(test_dir):
            if filename.endswith('.log'):
                with self.subTest(filename=filename):
                    test_file = os.path.join(test_dir, filename)

                    result = subprocess.run([
                        sys.executable, "parse_avc.py", "--file", test_file
                    ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

                    self.assertEqual(result.returncode, 0,
                                   f"Failed to process {filename}: {result.stderr}")

    def test_empty_log_handling(self):
        """Test handling of empty log files."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run([
                sys.executable, "parse_avc.py", "--file", tmp_path
            ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Empty File", result.stderr)
        finally:
            os.unlink(tmp_path)

    def test_malformed_log_handling(self):
        """Test handling of malformed log files."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as tmp:
            tmp.write("This is not a valid audit log\nRandom text here\n")
            tmp_path = tmp.name

        try:
            result = subprocess.run([
                sys.executable, "parse_avc.py", "--file", tmp_path
            ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

            # Should handle gracefully (may succeed with warnings or fail cleanly)
            # The key is that it shouldn't crash
            self.assertNotIn("Traceback", result.stderr)
        finally:
            os.unlink(tmp_path)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with existing flags."""

    def test_raw_file_flag_still_works(self):
        """Test that --raw-file flag still functions."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # This will likely fail since we don't have ausearch in test environment
        # But it should fail gracefully with a clear error message
        result = subprocess.run([
            sys.executable, "parse_avc.py", "--raw-file", test_file
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        # Should either succeed or fail with clear ausearch error
        if result.returncode != 0:
            self.assertIn("ausearch", result.stderr.lower())

    def test_avc_file_flag_still_works(self):
        """Test that --avc-file flag still functions."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run([
            sys.executable, "parse_avc.py", "--avc-file", test_file
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)