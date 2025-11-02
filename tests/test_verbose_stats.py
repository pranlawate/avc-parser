"""
Tests for --verbose and --stats flags
"""

import subprocess
import sys


def test_verbose_flag():
    """Test that --verbose flag produces debug output"""
    result = subprocess.run(
        [
            sys.executable,
            "parse_avc.py",
            "--file",
            "testAVC/file_context_AVC.log",
            "--verbose",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "→ Debug:" in result.stdout or "→ Debug:" in result.stderr
    assert "Split input into" in result.stdout or "Split input into" in result.stderr


def test_stats_flag():
    """Test that --stats flag produces summary output"""
    result = subprocess.run(
        [sys.executable, "parse_avc.py", "--file", "testAVC/tpm-enforcing.log", "--stats"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "SELinux AVC Log Summary" in result.stdout
    assert "Total Events:" in result.stdout
    assert "Unique Denials:" in result.stdout
    assert "Top Processes:" in result.stdout
    assert "Next Steps:" in result.stdout


def test_empty_filter_enhancement():
    """Test that empty filter results show helpful message"""
    result = subprocess.run(
        [
            sys.executable,
            "parse_avc.py",
            "--file",
            "testAVC/file_context_AVC.log",
            "--process",
            "nonexistent",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "No denials matched your filter criteria" in result.stdout
    assert "You filtered for:" in result.stdout
    assert "Suggestions:" in result.stdout


def test_verbose_with_filtering():
    """Test verbose output with filtering"""
    result = subprocess.run(
        [
            sys.executable,
            "parse_avc.py",
            "--file",
            "testAVC/tpm-enforcing.log",
            "--verbose",
            "--process",
            "systemd-crypten",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "→ Debug:" in result.stdout or "→ Debug:" in result.stderr
    assert "Filtering:" in result.stdout or "Filtering:" in result.stderr


def test_stats_with_file_info():
    """Test --stats includes file information"""
    result = subprocess.run(
        [sys.executable, "parse_avc.py", "--file", "testAVC/tpm-enforcing.log", "--stats"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "File:" in result.stdout
    assert "tpm-enforcing.log" in result.stdout
    assert "KB" in result.stdout  # File size in KB
