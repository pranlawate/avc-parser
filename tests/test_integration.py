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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestJSONOutput(unittest.TestCase):
    """Test JSON output functionality."""

    def test_json_output_format(self):
        """Test that JSON output is valid and contains expected fields."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Run parser with JSON output
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--json"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

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
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", "/nonexistent.log", "--json"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertNotEqual(result.returncode, 0)

    def test_json_with_stdin_input(self):
        """Test JSON output with piped stdin input."""
        # Sample AVC data
        avc_data = 'type=AVC msg=audit(01/15/2025 14:30:00.123:456): avc: denied { read } for pid=1234 comm="test" exe="/usr/bin/test" path="/etc/passwd" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=0'

        # Run parser with JSON output via stdin
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--json"],
            input=avc_data,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

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

        # Verify the data was processed correctly
        self.assertEqual(json_data["summary"]["total_events"], 1)
        self.assertEqual(len(json_data["unique_denials"]), 1)

        # Check that sesearch command is generated
        self.assertIn("sesearch_command", json_data["unique_denials"][0])

    def test_json_with_multiple_avc_stdin(self):
        """Test JSON output with multiple AVC records via stdin."""
        # Multiple AVC records
        avc_data = '''type=AVC msg=audit(01/15/2025 14:30:00.123:456): avc: denied { read } for pid=1234 comm="test1" path="/etc/passwd" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=0
type=AVC msg=audit(01/15/2025 14:30:01.124:457): avc: denied { write } for pid=1235 comm="test2" path="/tmp/test" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0'''

        # Run parser with JSON output via stdin
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--json"],
            input=avc_data,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")

        # Parse JSON output
        try:
            json_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}")

        # Check that both events were processed
        self.assertEqual(json_data["summary"]["total_events"], 2)

    def test_json_with_stdin_and_detailed_flag(self):
        """Test JSON output with stdin input and additional flags."""
        avc_data = 'type=AVC msg=audit(01/15/2025 14:30:00.123:456): avc: denied { read } for pid=1234 comm="test" exe="/usr/bin/test" path="/etc/passwd" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=0'

        # Run parser with JSON and detailed flags via stdin
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--json", "--detailed"],
            input=avc_data,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")

        # Parse JSON output
        try:
            json_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}")

        # JSON output should be the same regardless of detailed flag
        self.assertIn("unique_denials", json_data)
        self.assertEqual(json_data["summary"]["total_events"], 1)


class TestCommandLineInterface(unittest.TestCase):
    """Test command-line interface functionality."""

    def test_help_output(self):
        """Test that help output is generated without errors."""
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--file", result.stdout)
        self.assertIn("auto-detects", result.stdout)

    def test_conflicting_arguments(self):
        """Test that conflicting arguments are rejected."""
        result = subprocess.run(
            [
                sys.executable,
                "parse_avc.py",
                "--file",
                "test.log",
                "--raw-file",
                "raw.log",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Conflicting File Arguments", result.stderr)

    def test_auto_detection_feedback(self):
        """Test that auto-detection provides feedback."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

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
            if filename.endswith(".log"):
                with self.subTest(filename=filename):
                    test_file = os.path.join(test_dir, filename)

                    result = subprocess.run(
                        [sys.executable, "parse_avc.py", "--file", test_file],
                        capture_output=True,
                        text=True,
                        cwd=os.path.dirname(os.path.dirname(__file__)),
                    )

                    self.assertEqual(
                        result.returncode,
                        0,
                        f"Failed to process {filename}: {result.stderr}",
                    )

    def test_empty_log_handling(self):
        """Test handling of empty log files."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_path],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Empty File", result.stdout)
        finally:
            os.unlink(tmp_path)

    def test_malformed_log_handling(self):
        """Test handling of malformed log files."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("This is not a valid audit log\nRandom text here\n")
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_path],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )

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
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--raw-file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        # Should either succeed or fail with clear ausearch error
        if result.returncode != 0:
            self.assertIn("ausearch", result.stderr.lower())

    def test_avc_file_flag_still_works(self):
        """Test that --avc-file flag still functions."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--avc-file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0)


class TestAdvancedWorkflows(unittest.TestCase):
    """Test advanced CLI workflows and combinations."""

    def test_filtering_workflows(self):
        """Test various filtering options work correctly."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test process filtering
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--process", "httpd"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)

        # Test path filtering
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--path", "/var/*"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)

    def test_sorting_options(self):
        """Test different sorting options."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test each sort option
        for sort_option in ["recent", "count", "chrono"]:
            with self.subTest(sort_option=sort_option):
                result = subprocess.run(
                    [sys.executable, "parse_avc.py", "--file", test_file, "--sort", sort_option],
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(os.path.dirname(__file__)),
                )
                self.assertEqual(result.returncode, 0)

    def test_output_format_combinations(self):
        """Test different output format combinations."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test detailed view
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--detailed"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Detailed Events", result.stdout)

        # Test fields view (legacy format)
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--fields"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)

        # Test JSON with detailed
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--json", "--detailed"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        # Should still be valid JSON
        json.loads(result.stdout)

    def test_count_limiting(self):
        """Test count limiting functionality (via output analysis)."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Note: --count option doesn't exist, but we can test output length control
        # by analyzing output structure instead
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        # Verify we get some output (basic functionality test)
        self.assertGreater(len(result.stdout), 0)

    def test_context_filtering(self):
        """Test SELinux context filtering."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test source context filtering
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--source", "*httpd*"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)

        # Test target context filtering
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--target", "*default*"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result.returncode, 0)


class TestErrorHandlingWorkflows(unittest.TestCase):
    """Test comprehensive error handling in CLI workflows."""

    def test_invalid_arguments(self):
        """Test handling of various invalid arguments."""
        # Invalid sort option
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", "test.log", "--sort", "invalid"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertNotEqual(result.returncode, 0)

        # Invalid (nonexistent) argument
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", "test.log", "--nonexistent-arg"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertNotEqual(result.returncode, 0)

    def test_directory_instead_of_file(self):
        """Test error handling when directory is passed instead of file."""
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", "tests"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertNotEqual(result.returncode, 0)
        # Error message appears in stdout for this case
        self.assertIn("Directory Provided", result.stdout)

    def test_permission_denied_file(self):
        """Test handling of files with no read permission."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("test content")
            tmp_path = tmp.name

        try:
            # Remove read permissions
            os.chmod(tmp_path, 0o000)

            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_path],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            # Restore permissions for cleanup
            os.chmod(tmp_path, 0o644)
            os.unlink(tmp_path)


class TestRegressionPrevention(unittest.TestCase):
    """Test cases to prevent regression of previously fixed issues."""

    def test_no_avc_records_handling(self):
        """Test proper handling when no AVC records are found."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as tmp:
            tmp.write("type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=2\n")
            tmp.write("type=PATH msg=audit(1234567890.123:456): item=0 name=\"/etc/passwd\"\n")
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_path],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )
            # Should exit cleanly with informative message
            self.assertIn("No AVC records found", result.stdout)
        finally:
            os.unlink(tmp_path)

    def test_pipe_compatibility(self):
        """Test that output works correctly with pipes (head, less, etc.)."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test with head to simulate broken pipe
        result = subprocess.run(
            f"python3 parse_avc.py --file {test_file} | head -n 5",
            shell=True,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        # Should not crash with broken pipe error
        self.assertNotIn("BrokenPipeError", result.stderr)

    def test_bionic_formatting_consistency(self):
        """Test that BIONIC formatting produces consistent output."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Run twice and compare output for consistency
        result1 = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        result2 = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result1.returncode, 0)
        self.assertEqual(result2.returncode, 0)
        self.assertEqual(result1.stdout, result2.stdout)


class TestReportFormat(unittest.TestCase):
    """Test --report flag functionality with two-tier brief/sealert formats."""

    def test_basic_report_brief_format(self):
        """Test basic --report (brief) output format structure."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Check for brief format markers (executive style)
        self.assertIn("=" * 80, output, "Brief report should contain executive separator lines")
        self.assertIn("SELINUX SECURITY INCIDENT #", output, "Brief report should contain incident headers")
        self.assertIn("WHAT:", output, "Brief report should contain WHAT section")
        self.assertIn("WHEN:", output, "Brief report should contain WHEN section")
        self.assertIn("WHO:", output, "Brief report should contain WHO section")
        self.assertIn("WHERE:", output, "Brief report should contain WHERE section")
        self.assertIn("IMPACT:", output, "Brief report should contain IMPACT section")
        self.assertIn("STATUS:", output, "Brief report should contain STATUS section")
        # Note: REMEDIATION section was removed from brief format per user request
        # self.assertIn("REMEDIATION:", output, "Brief report should contain remediation commands")
        # self.assertIn("sesearch -A", output, "Brief report should contain sesearch commands")

        # Verify no Rich panel formatting
        self.assertNotIn("╭", output, "Brief report should not contain Rich panel borders")
        self.assertNotIn("│", output, "Brief report should not contain Rich panel borders")
        self.assertNotIn("╰", output, "Brief report should not contain Rich panel borders")

    def test_report_brief_with_multiple_events(self):
        """Test --report brief format with multiple events shows business impact summary."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Check for brief format business content (no Event Distribution in brief format)
        self.assertIn("SELINUX SECURITY INCIDENT", output, "Brief report should show incident headers")
        self.assertIn("WHAT:", output, "Brief report should show business impact summary")
        self.assertIn("PIDs:", output, "Brief report should show PID information in WHO section")

    def test_report_sealert_with_multiple_events_shows_event_distribution(self):
        """Test --report sealert format with multiple events shows Event Distribution."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "sealert"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Sealert format should show Event Distribution
        self.assertIn("Event Distribution:", output, "Sealert report should show Event Distribution")
        self.assertIn("PID", output, "Sealert report should show PID information")
        self.assertIn("SELinux Unique Denial Group", output, "Sealert report should use correct terminology")

    def test_report_brief_precedence_over_detailed(self):
        """Test that --report takes precedence when combined with --detailed."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "--detailed"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Should use brief report format (with = separators) not Rich detailed format
        self.assertIn("=" * 80, output, "Should use brief report format separators")
        self.assertNotIn("────", output, "Should not use Rich format separators")

    def test_fields_precedence_over_report(self):
        """Test that --fields takes precedence over --report."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "--fields"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Should use fields format, not report format
        self.assertIn("Timestamp:", output, "Should use fields format")
        self.assertIn("Process Name:", output, "Should use fields format")
        self.assertNotIn("═" * 79, output, "Should not use report format separators")

    def test_json_precedence_over_report(self):
        """Test that --json takes precedence over --report."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "--json"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
        output = result.stdout

        # Should be valid JSON, not report format
        try:
            json_data = json.loads(output)
            self.assertIsInstance(json_data, dict)
            self.assertIn("unique_denials", json_data)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON when --json flag is used")

        # Should not contain report format elements
        self.assertNotIn("═" * 79, output, "JSON output should not contain report separators")

    def test_report_security_notices_format(self):
        """Test that security notices appear in clean text format in --report mode."""
        # Create a test file with conditions that trigger security notices
        test_content = """----
time->Fri Sep  8 10:15:23 2023
type=AVC msg=audit(1694170523.456:123): avc:  denied  { noatsecure } for  pid=1234 comm="httpd" path="/var/www/html/test.php" dev="sda1" ino=98765 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=1"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as tmp_file:
            tmp_file.write(test_content)
            tmp_file_path = tmp_file.name

        try:
            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_file_path, "--report"],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )

            self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
            output = result.stdout

            # If security notices appear, they should be in text format
            if "SECURITY NOTICE" in output or "MODE NOTICE" in output:
                # Should use text format separators, not Rich panels
                self.assertNotIn("╭", output, "Security notices should not use Rich panels in report mode")
                self.assertNotIn("│", output, "Security notices should not use Rich panels in report mode")

        finally:
            os.unlink(tmp_file_path)

    def test_terminology_consistency_across_formats(self):
        """Test that terminology is consistent across all formats."""
        test_file = "testAVC/multi_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test Rich default format
        result_rich = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        # Test fields format
        result_fields = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--fields"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        # Test sealert format
        result_sealert = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "sealert"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result_rich.returncode, 0, "Rich format should succeed")
        self.assertEqual(result_fields.returncode, 0, "Fields format should succeed")
        self.assertEqual(result_sealert.returncode, 0, "Sealert format should succeed")

        # All technical formats should use "Unique Denial Group" terminology
        self.assertIn("Unique Denial Group #1", result_rich.stdout, "Rich format should use Unique Denial Group")
        self.assertIn("Unique Denial Group #1", result_fields.stdout, "Fields format should use Unique Denial Group")
        self.assertIn("SELinux Unique Denial Group #1", result_sealert.stdout, "Sealert format should use SELinux Unique Denial Group")

        # Brief format should use business terminology
        result_brief = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "brief"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertEqual(result_brief.returncode, 0, "Brief format should succeed")
        self.assertIn("SELINUX SECURITY INCIDENT #1", result_brief.stdout, "Brief format should use business terminology")

    def test_report_format_argument_validation(self):
        """Test that invalid report format arguments are rejected."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test invalid report format
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "invalid"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertNotEqual(result.returncode, 0, "Should reject invalid report format")
        self.assertIn("invalid choice", result.stderr.lower(), "Should show invalid choice error")

    def test_report_both_formats_work(self):
        """Test that both brief and sealert formats process the same data correctly."""
        test_file = "testAVC/network_AVC.log"

        if not os.path.exists(test_file):
            self.skipTest(f"Test file {test_file} not found")

        # Test brief format
        result_brief = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "brief"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        # Test sealert format
        result_sealert = subprocess.run(
            [sys.executable, "parse_avc.py", "--file", test_file, "--report", "sealert"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result_brief.returncode, 0, "Brief format should succeed")
        self.assertEqual(result_sealert.returncode, 0, "Sealert format should succeed")

        # Note: REMEDIATION/sesearch was removed from brief format per user request
        # Only sealert format should contain sesearch command
        # self.assertIn("sesearch -A -s httpd_t", result_brief.stdout, "Brief should contain sesearch command")
        self.assertIn("sesearch -A -s httpd_t", result_sealert.stdout, "Sealert should contain sesearch command")

        # Should have different format styles
        self.assertIn("SELINUX SECURITY INCIDENT", result_brief.stdout, "Brief should have executive style")
        self.assertIn("SELinux Unique Denial Group", result_sealert.stdout, "Sealert should have technical style")

    def test_report_help_shows_format_options(self):
        """Test that help output shows the new report format options."""
        result = subprocess.run(
            [sys.executable, "parse_avc.py", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("brief,sealert", result.stdout, "Help should show brief and sealert options")
        self.assertIn("executive summaries", result.stdout, "Help should describe brief format")
        self.assertIn("technical analysis", result.stdout, "Help should describe sealert format")

    def test_mixed_permissive_mode_detection(self):
        """Test that mixed permissive/enforcing mode is correctly detected and counted."""
        # Create test data with one enforcing and one permissive event
        test_content = """----
type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied  { read } for  pid=1234 comm="httpd" path="/var/www/html/file1.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied  { write } for  pid=5678 comm="httpd-worker" path="/var/www/html/file2.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=1
----"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as tmp_file:
            tmp_file.write(test_content)
            tmp_file_path = tmp_file.name

        try:
            # Test default output
            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_file_path],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )

            self.assertEqual(result.returncode, 0, f"Parser failed: {result.stderr}")
            output = result.stdout

            # Should detect permissive mode but count correctly
            self.assertIn("PERMISSIVE MODE DETECTED", output, "Should detect permissive mode")
            self.assertIn("1 of 2 events", output, "Should correctly count 1 of 2 events as permissive")

            # Should show both enforcement statuses in events
            self.assertIn("Enforcing", output, "Should show enforcing status")
            self.assertIn("Permissive", output, "Should show permissive status")

            # Test sealert format
            result_sealert = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", tmp_file_path, "--report", "sealert"],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )

            self.assertEqual(result_sealert.returncode, 0, f"Parser failed: {result_sealert.stderr}")
            sealert_output = result_sealert.stdout

            # Should detect mixed mode in sealert
            self.assertIn("Mixed (Enforcing + Permissive)", sealert_output,
                         "Sealert should detect mixed mode")
            self.assertIn("PARTIALLY ALLOWED", sealert_output,
                         "Sealert should indicate partial allowance")

        finally:
            os.unlink(tmp_file_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
