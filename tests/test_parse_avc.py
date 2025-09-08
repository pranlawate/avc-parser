"""Tests for SELinux AVC log parsing functionality."""

from datetime import datetime
from pathlib import Path
from typing import List

import pytest

from models import ParsedLog
from parse_avc import detect_file_type, human_time_ago, parse_avc_log

# Sample AVC logs for testing
SAMPLE_AVC_LOG = """
    type=AVC msg=audit(1631234567.123:456): avc:  denied  { read } for  
    pid=1234 comm="httpd" path="/var/www/html/index.html" dev="sda1" ino=123456 
    scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 
    tclass=file permissive=0
""".replace("\n    ", "")

SAMPLE_NETWORK_AVC = """
    type=AVC msg=audit(1631234567.123:457): avc:  denied  { name_connect } for  
    pid=5678 comm="httpd" dest=8080 scontext=system_u:system_r:httpd_t:s0 
    tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket
""".replace("\n    ", "")

SAMPLE_MULTIPLE_PERMS = """
    type=AVC msg=audit(1631234567.123:458): avc:  denied  { read write execute } for  
    pid=1234 comm="httpd" path="/var/www/html/script.sh" dev="sda1" ino=123456 
    scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 
    tclass=file permissive=1
""".replace("\n    ", "")


@pytest.fixture
def temp_log_file(tmp_path: Path) -> Path:
    """Create a temporary log file for testing."""
    log_file = tmp_path / "test.log"
    log_file.write_text(SAMPLE_AVC_LOG)
    return log_file


class TestAVCParsing:
    """Test suite for AVC log parsing functionality."""

    def test_parse_basic_avc(self) -> None:
        """Test parsing of a basic AVC denial log.
        
        Validates:
        - Basic field extraction (permission, comm, pid, tclass)
        - No unparsed content remains
        - Result is of correct type
        """
        parsed_log, unparsed = parse_avc_log(SAMPLE_AVC_LOG)
        assert isinstance(parsed_log, ParsedLog)
        assert parsed_log.permission == "read"
        assert parsed_log.comm == "httpd"
        assert parsed_log.pid == "1234"
        assert parsed_log.tclass == "file"
        assert parsed_log.permissive == "0"  # Check permissive mode
        assert len(unparsed) == 0

    def test_parse_network_avc(self) -> None:
        """Test parsing of a network-related AVC denial.
        
        Validates:
        - Network-specific fields (dest_port)
        - TCP socket class handling
        """
        parsed_log, unparsed = parse_avc_log(SAMPLE_NETWORK_AVC)
        assert parsed_log.permission == "name_connect"
        assert parsed_log.dest_port == "8080"
        assert parsed_log.tclass == "tcp_socket"
        assert len(unparsed) == 0

    def test_multiple_permissions(self) -> None:
        """Test parsing of an AVC log with multiple permissions.
        
        Validates:
        - Multiple permissions are correctly extracted
        - Permissive mode is correctly parsed
        """
        parsed_log, unparsed = parse_avc_log(SAMPLE_MULTIPLE_PERMS)
        assert parsed_log.permission == "read write execute"
        assert parsed_log.permissive == "1"
        assert len(unparsed) == 0

    @pytest.mark.parametrize("input_log,expected_unparsed", [
        ("", True),  # Empty string
        ("Invalid log content", True),  # Invalid content
        ("type=INVALID", True),  # Wrong type
        ("type=AVC", True),  # Incomplete AVC log
    ])
    def test_invalid_logs(self, input_log: str, expected_unparsed: bool) -> None:
        """Test handling of various invalid log formats.
        
        Args:
            input_log: The invalid log content to test
            expected_unparsed: Whether unparsed content is expected
        """
        parsed_log, unparsed = parse_avc_log(input_log)
        assert not parsed_log.permission, "Invalid log should not have permissions"
        assert bool(unparsed) == expected_unparsed

    @pytest.mark.parametrize("log_format", [
        """type=AVC msg=audit(1631234567.123:456): avc: denied { read }""",
        """type=AVC msg=audit(09/08/2025 10:30:45.123:456): avc: denied { read }""",
    ])
    def test_timestamp_formats(self, log_format: str) -> None:
        """Test parsing of different timestamp formats.
        
        Args:
            log_format: The log string with different timestamp format
        """
        parsed_log, _ = parse_avc_log(log_format)
        assert parsed_log.datetime_obj is not None


class TestParsedLogFeatures:
    """Test suite for enhanced ParsedLog features."""

    def test_context_type_extraction(self) -> None:
        """Test extracting type from SELinux context."""
        log = ParsedLog(
            scontext="user_u:role_r:type_t:s0",
            tcontext="system_u:object_r:httpd_t:s0"
        )
        assert log.get_context_type("scontext") == "type_t"
        assert log.get_context_type("tcontext") == "httpd_t"
        assert log.get_context_type("nonexistent") is None

    def test_denial_type_detection(self) -> None:
        """Test detection of denial types."""
        # File denial
        file_log = ParsedLog(path="/path/to/file", tclass="file")
        assert file_log.is_file_denial()
        assert not file_log.is_network_denial()

        # Network denial
        net_log = ParsedLog(dest_port="80", tclass="tcp_socket")
        assert net_log.is_network_denial()
        assert not net_log.is_file_denial()

    def test_audit2allow_formatting(self) -> None:
        """Test formatting denials for audit2allow."""
        log = ParsedLog(
            permission="read",
            pid="1234",
            comm="httpd",
            path="/var/www/html",
            scontext="system_u:system_r:httpd_t:s0",
            tcontext="system_u:object_r:var_t:s0",
            tclass="file"
        )
        formatted = log.get_audit2allow_input()
        assert "type=AVC" in formatted
        assert "avc:  denied" in formatted
        assert "{ read }" in formatted
        assert 'path="/var/www/html"' in formatted
        assert "scontext=system_u:system_r:httpd_t:s0" in formatted

    @pytest.mark.parametrize("context,expected", [
        ("user_u:role_r:type_t:s0", True),
        ("system_u:object_r:httpd_t:s0-s0:c0.c1023", True),
        ("invalid_context", False),
        ("missing:parts", False),
        ("bad:chars:type!:s0", False),
    ])
    def test_selinux_context_validation(self, context: str, expected: bool) -> None:
        """Test SELinux context format validation.
        
        Args:
            context: SELinux context to validate
            expected: Whether the context should be considered valid
        """
        log = ParsedLog()
        assert log._is_valid_selinux_context(context) == expected

    def test_permissive_validation(self) -> None:
        """Test validation of permissive flag values."""
        # Valid values
        log_enforcing = ParsedLog(permissive="0")
        log_permissive = ParsedLog(permissive="1")
        assert not log_enforcing.validate()  # No errors
        assert not log_permissive.validate()  # No errors

        # Invalid values
        log_invalid = ParsedLog(permissive="2")
        assert any("Invalid permissive flag" in err for err in log_invalid.validate())

    def test_port_validation(self) -> None:
        """Test validation of port numbers."""
        # Valid port
        log_valid = ParsedLog(dest_port="8080")
        assert not log_valid.validate()  # No errors

        # Invalid ports
        log_high = ParsedLog(dest_port="65536")
        log_zero = ParsedLog(dest_port="0")
        log_text = ParsedLog(dest_port="invalid")
        
        assert any("out of range" in err for err in log_high.validate())
        assert any("out of range" in err for err in log_zero.validate())
        assert any("Invalid port number" in err for err in log_text.validate())

    def test_dict_serialization(self) -> None:
        """Test dictionary serialization options."""
        log = ParsedLog(
            permission="read",
            pid="1234",
            additional_fields={"extra": "value", "none_field": None}
        )
        
        # Without None values
        dict_without_none = log.to_dict(include_none=False)
        assert "pid" in dict_without_none
        assert "comm" not in dict_without_none
        assert "extra" in dict_without_none
        assert "none_field" not in dict_without_none
        
        # With None values
        dict_with_none = log.to_dict(include_none=True)
        assert "pid" in dict_with_none
        assert "comm" in dict_with_none
        assert "extra" in dict_with_none
        assert "none_field" in dict_with_none

class TestUtilities:
    """Test suite for utility functions."""

    def test_human_time_ago(self) -> None:
        """Test human-readable time ago formatting.
        
        Validates:
        - Current time formatting
        - Past time formatting
        - Different time units
        """
        now = datetime.now()
        assert human_time_ago(now) == "0 minute(s) ago"
        assert "year" in human_time_ago(datetime(2020, 1, 1))

    def test_detect_file_type(self, temp_log_file: Path) -> None:
        """Test file type detection.
        
        Args:
            temp_log_file: Temporary file fixture with sample content
            
        Validates:
        - AVC log file detection
        - File extension handling
        """
        assert detect_file_type(str(temp_log_file)) == "avc"
