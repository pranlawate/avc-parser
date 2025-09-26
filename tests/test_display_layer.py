#!/usr/bin/env python3
"""
Display Layer Tests for AVC Parser

Tests the Rich formatting, BIONIC text, panels, and terminal output
to ensure display consistency and prevent regressions.
"""

import unittest
import sys
import os
import tempfile
from io import StringIO
from unittest.mock import patch, MagicMock

# Add parent directory to path to import parse_avc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils import format_bionic_text, format_path_for_display
from rich.console import Console


class TestBIONICFormatting(unittest.TestCase):
    """Test BIONIC text formatting functionality."""

    def test_bionic_short_words(self):
        """Test BIONIC formatting for short words (≤2 chars)."""
        result = format_bionic_text("to", "green")
        self.assertIn("[green]to[/green]", result)
        # Short words should not have bold/dim formatting
        self.assertNotIn("bold", result)
        self.assertNotIn("dim", result)

    def test_bionic_medium_words(self):
        """Test BIONIC formatting for medium words (3-4 chars)."""
        result = format_bionic_text("file", "white")
        # Should emphasize first 2 characters
        self.assertIn("[bold white]fi[/bold white]", result)
        self.assertIn("[white]le[/white]", result)

    def test_bionic_long_words(self):
        """Test BIONIC formatting for long words (5+ chars)."""
        result = format_bionic_text("denied", "white")
        # Should emphasize first 3 characters
        self.assertIn("[bold white]den[/bold white]", result)
        self.assertIn("[white]ied[/white]", result)

    def test_bionic_empty_input(self):
        """Test BIONIC formatting with empty input."""
        result = format_bionic_text("", "green")
        self.assertEqual(result, "")

    def test_bionic_multi_word(self):
        """Test BIONIC formatting with multiple words."""
        result = format_bionic_text("denied read", "cyan")
        # Check for BIONIC formatted text (not plain words)
        self.assertIn("[bold cyan]den[/bold cyan][cyan]ied[/cyan]", result)
        self.assertIn("[bold cyan]re[/bold cyan][cyan]ad[/cyan]", result)
        # Should have proper spacing
        self.assertIn(" ", result)


class TestPathFormatting(unittest.TestCase):
    """Test path display formatting."""

    def test_short_path_no_truncation(self):
        """Test that short paths are not truncated."""
        short_path = "/var/log/test.log"
        result = format_path_for_display(short_path, max_length=80)
        self.assertEqual(result, short_path)

    def test_long_path_truncation(self):
        """Test that long paths are truncated appropriately."""
        long_path = "/very/long/path/to/some/deeply/nested/directory/structure/file.log"
        result = format_path_for_display(long_path, max_length=30)
        # Should be truncated and contain ellipsis
        self.assertLess(len(result), len(long_path))
        self.assertIn("...", result)

    def test_path_truncation_preserves_filename(self):
        """Test that path truncation preserves the filename when possible."""
        path = "/very/long/path/to/important_file.log"
        result = format_path_for_display(path, max_length=25)
        # Should contain the filename or part of it
        self.assertTrue("file.log" in result or "important" in result)


class TestRichConsoleOutput(unittest.TestCase):
    """Test Rich console output functionality."""

    def setUp(self):
        """Set up test console."""
        # Create a console that captures output
        self.output = StringIO()
        self.console = Console(file=self.output, force_terminal=True, width=80)

    def test_console_output_capture(self):
        """Test that console output can be captured for testing."""
        self.console.print("Test message")
        output = self.output.getvalue()
        self.assertIn("Test message", output)

    def test_color_markup_validity(self):
        """Test that Rich color markup is valid and doesn't break."""
        # Test BIONIC formatting doesn't break Rich
        test_texts = ["denied", "file", "to", "read", "write"]
        for text in test_texts:
            formatted = format_bionic_text(text, "green")
            try:
                self.console.print(formatted)
                output = self.output.getvalue()
                # Should contain some part of the word (accounting for BIONIC splitting)
                if len(text) <= 2:
                    self.assertIn(text, output)  # Short words stay intact
                else:
                    # For longer words, check for fragments
                    self.assertTrue(len(output) > 0)  # Should produce some output
            except Exception as e:
                self.fail(f"BIONIC formatting broke Rich for '{text}': {e}")


class TestDisplayRegression(unittest.TestCase):
    """Test display functionality doesn't regress."""

    def test_bionic_format_stability(self):
        """Test that BIONIC formatting output is stable."""
        # Test cases that should produce consistent output
        test_cases = [
            ("to", "green", "[green]to[/green]"),
            ("file", "white", "[bold white]fi[/bold white][white]le[/white]"),
            ("denied", "cyan", "[bold cyan]den[/bold cyan][cyan]ied[/cyan]"),
        ]

        for input_text, color, expected in test_cases:
            with self.subTest(input_text=input_text):
                result = format_bionic_text(input_text, color)
                self.assertEqual(result, expected)

    def test_path_display_stability(self):
        """Test that path display formatting is stable."""
        # Test cases that should produce consistent output
        short_path = "/var/log/test.log"
        result = format_path_for_display(short_path, max_length=80)
        self.assertEqual(result, short_path)  # Should be unchanged

        # Test truncation
        long_path = "/very/long/path/that/exceeds/limit.log"
        result = format_path_for_display(long_path, max_length=20)
        self.assertLess(len(result), len(long_path))
        self.assertIn("...", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)