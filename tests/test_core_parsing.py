#!/usr/bin/env python3
"""
Test suite for core AVC parsing functionality.

This test suite verifies the core parsing logic including:
1. AVC record extraction and field parsing
2. Correlation tracking and data integrity
3. Semantic analysis and enhanced features
4. Error handling and edge cases
"""

import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path so we can import parse_avc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_avc import (
    parse_avc_log,
    parse_audit_record_text,
    process_individual_avc_record,
    AvcContext,
    PermissionSemanticAnalyzer,
    validate_log_entry,
    detect_file_format
)


class TestAuditRecordParsing(unittest.TestCase):
    """Test audit record parsing functionality."""

    def test_audit_record_regex_basic(self):
        """Test basic audit record pattern matching."""
        line = "type=AVC msg=audit(1234567890.123:456): avc: denied { read } for pid=1234"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertTrue(success)
        self.assertIsNone(host)  # No node= prefix
        self.assertEqual(record_type, "AVC")
        self.assertEqual(event_id, "1234567890.123:456")
        self.assertIn("avc: denied", body)

    def test_audit_record_regex_with_node(self):
        """Test audit record with node= prefix."""
        line = "node=server1 type=USER_AVC msg=audit(1234567890.123:456): avc: denied { write }"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertTrue(success)
        self.assertEqual(host, "server1")
        self.assertEqual(record_type, "USER_AVC")
        self.assertEqual(event_id, "1234567890.123:456")
        self.assertIn("avc: denied", body)

    def test_audit_record_regex_malformed(self):
        """Test handling of malformed audit records."""
        line = "This is not an audit record"
        success, host, record_type, event_id, body = parse_audit_record_text(line)

        self.assertFalse(success)
        self.assertIsNone(host)
        self.assertIsNone(record_type)
        self.assertIsNone(event_id)
        self.assertIsNone(body)


class TestAvcContextParsing(unittest.TestCase):
    """Test SELinux context parsing."""

    def test_valid_context_parsing(self):
        """Test parsing of valid SELinux context."""
        context = AvcContext("system_u:system_r:httpd_t:s0")

        self.assertTrue(context.is_valid())
        self.assertEqual(context.user, "system_u")
        self.assertEqual(context.role, "system_r")
        self.assertEqual(context.type, "httpd_t")
        self.assertEqual(context.mls, "s0")
        self.assertEqual(str(context), "system_u:system_r:httpd_t:s0")

    def test_context_with_complex_mls(self):
        """Test parsing context with complex MLS labels."""
        context = AvcContext("system_u:system_r:sshd_t:s0-s0:c0.c1023")

        self.assertTrue(context.is_valid())
        self.assertEqual(context.user, "system_u")
        self.assertEqual(context.role, "system_r")
        self.assertEqual(context.type, "sshd_t")
        self.assertEqual(context.mls, "s0-s0:c0.c1023")

    def test_invalid_context(self):
        """Test handling of invalid context strings."""
        context = AvcContext("invalid:context")
        self.assertFalse(context.is_valid())

        context = AvcContext("")
        self.assertFalse(context.is_valid())

        context = AvcContext(None)
        self.assertFalse(context.is_valid())

    def test_context_type_description(self):
        """Test type description functionality."""
        context = AvcContext("system_u:system_r:httpd_t:s0")
        self.assertEqual(context.get_type_description(), "Web server process")

        context = AvcContext("system_u:system_r:unknown_type_t:s0")
        self.assertEqual(context.get_type_description(), "unknown_type_t")


class TestIndividualAvcProcessing(unittest.TestCase):
    """Test individual AVC record processing."""

    def test_basic_avc_processing(self):
        """Test processing of basic AVC record."""
        line = 'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/index.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0'
        shared_context = {}

        result = process_individual_avc_record(line, shared_context)

        self.assertIsInstance(result, dict)
        self.assertEqual(result['permission'], 'read')
        self.assertEqual(result['pid'], '1234')
        self.assertEqual(result['comm'], 'httpd')
        self.assertEqual(result['path'], '/var/www/html/index.html')
        self.assertEqual(result['tclass'], 'file')
        self.assertEqual(result['permissive'], '0')
        self.assertEqual(result['denial_type'], 'AVC')

        # Check timestamp parsing
        self.assertIn('datetime_obj', result)
        self.assertIsInstance(result['datetime_obj'], datetime)
        self.assertEqual(result['datetime_obj'].year, 2025)
        self.assertEqual(result['datetime_obj'].month, 6)
        self.assertEqual(result['datetime_obj'].day, 18)

    def test_user_avc_processing(self):
        """Test processing of USER_AVC record."""
        line = "type=USER_AVC msg=audit(06/18/2025 09:12:51.190:456): pid=1234 uid=0 auid=0 ses=123 msg='avc: denied { read } for pid=5678 comm=\"app\" path=\"/tmp/file\" scontext=user_u:user_r:user_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=1'"
        shared_context = {}

        result = process_individual_avc_record(line, shared_context)

        self.assertIsInstance(result, dict)
        self.assertEqual(result['denial_type'], 'USER_AVC')
        self.assertEqual(result['permission'], 'read')
        self.assertEqual(result['pid'], '1234')  # Outer PID takes precedence
        self.assertEqual(result['permissive'], '1')

    def test_avc_processing_with_shared_context(self):
        """Test AVC processing with shared context from other records."""
        line = 'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0'
        shared_context = {
            'path': '/var/www/html/index.html',
            'exe': '/usr/sbin/httpd',
            'cwd': '/var/www'
        }

        result = process_individual_avc_record(line, shared_context)

        self.assertIsInstance(result, dict)
        self.assertEqual(result['permission'], 'read')
        self.assertEqual(result['path'], '/var/www/html/index.html')  # From shared context
        self.assertEqual(result['exe'], '/usr/sbin/httpd')  # From shared context
        self.assertEqual(result['cwd'], '/var/www')  # From shared context

    def test_semantic_analysis_integration(self):
        """Test that semantic analysis is properly integrated."""
        line = 'type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/index.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0'
        shared_context = {}

        result = process_individual_avc_record(line, shared_context)

        # Check semantic analysis fields
        self.assertIn('permission_description', result)
        self.assertIn('contextual_analysis', result)
        self.assertIn('class_description', result)
        self.assertIn('source_type_description', result)
        self.assertIn('target_type_description', result)

        self.assertEqual(result['permission_description'], 'Read file content')
        self.assertEqual(result['class_description'], 'file')
        self.assertIn('Web server', result['contextual_analysis'])


class TestSemanticAnalysis(unittest.TestCase):
    """Test semantic analysis functionality."""

    def test_permission_descriptions(self):
        """Test permission description mappings."""
        self.assertEqual(
            PermissionSemanticAnalyzer.get_permission_description('read'),
            'Read file content'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_permission_description('write'),
            'Modify file content'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_permission_description('unknown_perm'),
            'unknown_perm'
        )

    def test_class_descriptions(self):
        """Test object class description mappings."""
        self.assertEqual(
            PermissionSemanticAnalyzer.get_class_description('file'),
            'file'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_class_description('tcp_socket'),
            'TCP network socket'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_class_description('unknown_class'),
            'unknown_class'
        )

    def test_contextual_analysis(self):
        """Test contextual analysis generation."""
        source_context = AvcContext("system_u:system_r:httpd_t:s0")
        target_context = AvcContext("unconfined_u:object_r:default_t:s0")

        analysis = PermissionSemanticAnalyzer.get_contextual_analysis(
            'read', 'file', source_context, target_context
        )

        self.assertIn('Web server', analysis)
        self.assertIn('read', analysis)
        self.assertIn('file', analysis)

    def test_port_descriptions(self):
        """Test network port description mappings."""
        self.assertEqual(
            PermissionSemanticAnalyzer.get_port_description('80'),
            'HTTP web service'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_port_description('22'),
            'SSH service'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_port_description('9999'),
            'JBoss management'
        )
        self.assertEqual(
            PermissionSemanticAnalyzer.get_port_description('12345'),
            'port 12345'
        )


class TestLogValidation(unittest.TestCase):
    """Test log validation and sanitization."""

    def test_valid_log_entry(self):
        """Test validation of valid log entry."""
        log_block = """
type=AVC msg=audit(1234567890.123:456): avc: denied { read } for pid=1234 comm="httpd"
type=SYSCALL msg=audit(1234567890.123:456): arch=x86_64 syscall=openat
        """.strip()

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertTrue(is_valid)
        self.assertIn('type=AVC', sanitized)
        self.assertIn('type=SYSCALL', sanitized)
        self.assertIsInstance(warnings, list)

    def test_empty_log_entry(self):
        """Test handling of empty log entry."""
        is_valid, sanitized, warnings = validate_log_entry("")

        self.assertFalse(is_valid)
        self.assertEqual(sanitized, "")
        self.assertIn("Empty or whitespace-only log block", warnings[0])

    def test_log_entry_with_control_characters(self):
        """Test sanitization of log entry with control characters."""
        log_block = "type=AVC msg=audit(123:456): avc\x00\x01: denied"

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertTrue(is_valid)
        self.assertNotIn('\x00', sanitized)
        self.assertNotIn('\x01', sanitized)
        self.assertIn("Removed control characters", warnings[0])

    def test_malformed_log_entry(self):
        """Test handling of malformed log entries."""
        log_block = """
This is not an audit log
Another invalid line
type=AVC msg=audit(123:456): avc: denied { read }
        """.strip()

        is_valid, sanitized, warnings = validate_log_entry(log_block)

        self.assertTrue(is_valid)  # Should still be valid due to one valid line
        self.assertIn('type=AVC', sanitized)
        self.assertTrue(any('malformed' in w for w in warnings))


class TestFileFormatDetection(unittest.TestCase):
    """Test file format detection functionality."""

    def test_detect_processed_format(self):
        """Test detection of pre-processed format."""
        # Create a temporary file with processed format content
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("time->06/18/2025 09:12:51\n")
            f.write("type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied\n")
            f.write("----\n")
            temp_file = f.name

        try:
            format_type = detect_file_format(temp_file)
            self.assertEqual(format_type, 'processed')
        finally:
            os.unlink(temp_file)

    def test_detect_raw_format(self):
        """Test detection of raw format."""
        # Create a temporary file with raw format content
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("audit(1234567890.123:456): avc: denied { read }\n")
            f.write("audit(1234567890.124:457): syscall=openat\n")
            temp_file = f.name

        try:
            format_type = detect_file_format(temp_file)
            self.assertEqual(format_type, 'raw')
        finally:
            os.unlink(temp_file)


class TestCorrelationTracking(unittest.TestCase):
    """Test correlation tracking functionality."""

    def test_multi_event_correlation(self):
        """Test correlation tracking with multiple events."""
        log_block = """
type=AVC msg=audit(06/18/2025 09:12:51.190:4997970): avc: denied { read } for pid=1234 comm="httpd" path="/file1" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=AVC msg=audit(06/18/2025 09:12:52.190:4997971): avc: denied { write } for pid=5678 comm="httpd" path="/file2" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=1
        """.strip()

        denials, unparsed = parse_avc_log(log_block)

        self.assertEqual(len(denials), 2)

        # Verify individual denial data
        self.assertEqual(denials[0]['permission'], 'read')
        self.assertEqual(denials[0]['pid'], '1234')
        self.assertEqual(denials[0]['path'], '/file1')
        self.assertEqual(denials[0]['permissive'], '0')

        self.assertEqual(denials[1]['permission'], 'write')
        self.assertEqual(denials[1]['pid'], '5678')
        self.assertEqual(denials[1]['path'], '/file2')
        self.assertEqual(denials[1]['permissive'], '1')

        # Verify timestamp differences
        self.assertNotEqual(denials[0]['datetime_obj'], denials[1]['datetime_obj'])
        self.assertLess(denials[0]['datetime_obj'], denials[1]['datetime_obj'])


if __name__ == '__main__':
    unittest.main()