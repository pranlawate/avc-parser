#!/usr/bin/env python3
"""
Log Validation Utility

This script validates audit log files for common issues, format problems,
and provides recommendations for optimal parsing performance.
"""

import os
import sys
import re
import gzip
import subprocess
from pathlib import Path
from datetime import datetime

def check_file_accessibility(file_path):
    """Check if file exists and is readable."""
    checks = {
        "exists": os.path.exists(file_path),
        "readable": os.access(file_path, os.R_OK) if os.path.exists(file_path) else False,
        "size_mb": 0,
        "is_binary": False
    }

    if checks["exists"]:
        try:
            file_stat = os.stat(file_path)
            checks["size_mb"] = file_stat.st_size / 1024 / 1024

            # Check if binary
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                checks["is_binary"] = b'\0' in chunk

        except Exception as e:
            checks["error"] = str(e)

    return checks

def detect_log_format(file_path):
    """Detect the format of the log file."""
    format_info = {
        "detected_format": "unknown",
        "line_count": 0,
        "avc_count": 0,
        "timestamp_format": "unknown",
        "has_node_prefix": False,
        "compression": None
    }

    try:
        # Handle compressed files
        opener = gzip.open if file_path.endswith('.gz') else open
        mode = 'rt' if file_path.endswith('.gz') else 'r'

        if file_path.endswith('.gz'):
            format_info["compression"] = "gzip"

        with opener(file_path, mode, errors='ignore') as f:
            sample_lines = []
            for i, line in enumerate(f):
                if i >= 1000:  # Sample first 1000 lines
                    break
                sample_lines.append(line.strip())
                format_info["line_count"] += 1

                # Count AVC records
                if 'avc:' in line.lower():
                    format_info["avc_count"] += 1

                # Check for node prefix
                if line.startswith('node='):
                    format_info["has_node_prefix"] = True

        # Analyze timestamp formats
        timestamp_patterns = {
            "unix": re.compile(r'type=\w+\s+msg=audit\(\d+\.\d+:\d+\)'),
            "iso": re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
            "human": re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
        }

        for line in sample_lines[:100]:  # Check first 100 lines
            for fmt_name, pattern in timestamp_patterns.items():
                if pattern.search(line):
                    format_info["timestamp_format"] = fmt_name
                    break

        # Determine overall format
        if format_info["avc_count"] > 0:
            if 'type=' in ' '.join(sample_lines[:10]):
                format_info["detected_format"] = "raw_audit"
            else:
                format_info["detected_format"] = "processed_avc"
        else:
            format_info["detected_format"] = "no_avc_data"

    except Exception as e:
        format_info["error"] = str(e)

    return format_info

def validate_avc_content(file_path):
    """Validate AVC-specific content quality."""
    validation_results = {
        "total_lines": 0,
        "valid_avc_lines": 0,
        "malformed_lines": 0,
        "missing_fields": [],
        "common_issues": [],
        "sample_errors": []
    }

    required_fields = ['scontext', 'tcontext', 'tclass']
    opener = gzip.open if file_path.endswith('.gz') else open
    mode = 'rt' if file_path.endswith('.gz') else 'r'

    try:
        with opener(file_path, mode, errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                validation_results["total_lines"] += 1

                if 'avc:' in line.lower():
                    # Check for required fields
                    missing_in_line = []
                    for field in required_fields:
                        if f'{field}=' not in line:
                            missing_in_line.append(field)

                    if missing_in_line:
                        validation_results["malformed_lines"] += 1
                        for field in missing_in_line:
                            if field not in validation_results["missing_fields"]:
                                validation_results["missing_fields"].append(field)

                        if len(validation_results["sample_errors"]) < 5:
                            validation_results["sample_errors"].append({
                                "line": line_num,
                                "missing": missing_in_line,
                                "content": line.strip()[:100] + "..." if len(line) > 100 else line.strip()
                            })
                    else:
                        validation_results["valid_avc_lines"] += 1

                # Check for common issues
                if len(line) > 10000:
                    if "extremely_long_lines" not in validation_results["common_issues"]:
                        validation_results["common_issues"].append("extremely_long_lines")

                if '\x00' in line:
                    if "null_bytes" not in validation_results["common_issues"]:
                        validation_results["common_issues"].append("null_bytes")

                # Limit processing for very large files
                if line_num > 10000:
                    break

    except Exception as e:
        validation_results["error"] = str(e)

    return validation_results

def test_parser_compatibility(file_path):
    """Test if the file works with the AVC parser."""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    test_results = {
        "parser_works": False,
        "execution_time": 0,
        "output_size": 0,
        "error_message": None,
        "denials_found": 0
    }

    try:
        start_time = datetime.now()

        result = subprocess.run([
            sys.executable,
            os.path.join(parent_dir, "parse_avc.py"),
            "--file", file_path,
            "--json"
        ], capture_output=True, text=True, timeout=30)

        end_time = datetime.now()
        test_results["execution_time"] = (end_time - start_time).total_seconds()

        if result.returncode == 0:
            test_results["parser_works"] = True
            test_results["output_size"] = len(result.stdout)

            # Try to parse JSON output to count denials
            try:
                import json
                data = json.loads(result.stdout)
                test_results["denials_found"] = len(data.get('unique_denials', []))
            except:
                pass
        else:
            test_results["error_message"] = result.stderr.strip()

    except subprocess.TimeoutExpired:
        test_results["error_message"] = "Parser timeout (>30s)"
    except Exception as e:
        test_results["error_message"] = str(e)

    return test_results

def generate_recommendations(file_checks, format_info, validation_results, parser_test):
    """Generate actionable recommendations."""
    recommendations = []
    issues = []

    # File accessibility issues
    if not file_checks["exists"]:
        issues.append("File does not exist")
        return {"issues": issues, "recommendations": ["Check file path"]}

    if not file_checks["readable"]:
        issues.append("File is not readable")
        recommendations.append("Check file permissions")

    if file_checks["is_binary"]:
        issues.append("File appears to be binary")
        recommendations.append("Ensure file is text-based audit log")

    # Size recommendations
    if file_checks["size_mb"] > 100:
        recommendations.append(f"Large file ({file_checks['size_mb']:.1f} MB) - consider splitting or using streaming")

    # Format issues
    if format_info["detected_format"] == "no_avc_data":
        issues.append("No AVC data detected")
        recommendations.append("Verify this is an SELinux audit log with AVC denials")

    if format_info["avc_count"] == 0:
        issues.append("No AVC records found")
        recommendations.append("Check if SELinux is enabled and generating denials")

    # Content validation issues
    if validation_results["malformed_lines"] > 0:
        ratio = validation_results["malformed_lines"] / max(validation_results["valid_avc_lines"], 1)
        if ratio > 0.1:  # More than 10% malformed
            issues.append(f"High malformed line ratio: {ratio:.1%}")
            recommendations.append("Consider log preprocessing or format correction")

    if validation_results["missing_fields"]:
        issues.append(f"Missing required fields: {', '.join(validation_results['missing_fields'])}")
        recommendations.append("Ensure complete audit log collection")

    # Parser compatibility
    if not parser_test["parser_works"]:
        issues.append("Parser failed to process file")
        if parser_test["error_message"]:
            recommendations.append(f"Fix parser error: {parser_test['error_message']}")

    if parser_test["denials_found"] == 0 and parser_test["parser_works"]:
        issues.append("Parser found no denials")
        recommendations.append("Verify log contains actual AVC denial events")

    # Performance recommendations
    if parser_test["execution_time"] > 10:
        recommendations.append("Slow parsing detected - consider file optimization")

    if not issues:
        recommendations.append("✅ File appears to be in good condition for parsing")

    return {"issues": issues, "recommendations": recommendations}

def validate_file(file_path):
    """Perform comprehensive validation of a log file."""
    print(f"🔍 Validating: {file_path}")
    print("=" * 60)

    # Run all validation checks
    file_checks = check_file_accessibility(file_path)
    format_info = detect_log_format(file_path) if file_checks["readable"] else {}
    validation_results = validate_avc_content(file_path) if file_checks["readable"] else {}
    parser_test = test_parser_compatibility(file_path) if file_checks["readable"] else {}

    # Display results
    print("📁 FILE INFORMATION")
    print(f"  Size: {file_checks.get('size_mb', 0):.2f} MB")
    print(f"  Readable: {'✅' if file_checks.get('readable') else '❌'}")
    print(f"  Binary: {'⚠️ Yes' if file_checks.get('is_binary') else '✅ No'}")

    if format_info:
        print(f"\n📋 FORMAT ANALYSIS")
        print(f"  Detected format: {format_info.get('detected_format', 'unknown')}")
        print(f"  Total lines: {format_info.get('line_count', 0):,}")
        print(f"  AVC records: {format_info.get('avc_count', 0):,}")
        print(f"  Timestamp format: {format_info.get('timestamp_format', 'unknown')}")
        if format_info.get('compression'):
            print(f"  Compression: {format_info['compression']}")

    if validation_results:
        print(f"\n🔬 CONTENT VALIDATION")
        total_avc = validation_results.get('valid_avc_lines', 0) + validation_results.get('malformed_lines', 0)
        if total_avc > 0:
            quality_ratio = validation_results.get('valid_avc_lines', 0) / total_avc
            print(f"  Quality ratio: {quality_ratio:.1%}")
        print(f"  Valid AVC lines: {validation_results.get('valid_avc_lines', 0):,}")
        print(f"  Malformed lines: {validation_results.get('malformed_lines', 0):,}")

        if validation_results.get('missing_fields'):
            print(f"  Missing fields: {', '.join(validation_results['missing_fields'])}")

    if parser_test:
        print(f"\n⚡ PARSER COMPATIBILITY")
        print(f"  Parser works: {'✅' if parser_test.get('parser_works') else '❌'}")
        if parser_test.get('parser_works'):
            print(f"  Execution time: {parser_test.get('execution_time', 0):.2f}s")
            print(f"  Denials found: {parser_test.get('denials_found', 0):,}")
        elif parser_test.get('error_message'):
            print(f"  Error: {parser_test['error_message']}")

    # Generate and display recommendations
    recommendations = generate_recommendations(file_checks, format_info, validation_results, parser_test)

    if recommendations["issues"]:
        print(f"\n⚠️  ISSUES DETECTED")
        for i, issue in enumerate(recommendations["issues"], 1):
            print(f"  {i}. {issue}")

    print(f"\n💡 RECOMMENDATIONS")
    for i, rec in enumerate(recommendations["recommendations"], 1):
        print(f"  {i}. {rec}")

    return {
        "file_checks": file_checks,
        "format_info": format_info,
        "validation_results": validation_results,
        "parser_test": parser_test,
        "recommendations": recommendations
    }

def main():
    """Main validation function."""
    if len(sys.argv) < 2:
        print("📋 Log File Validation Utility")
        print("=" * 40)
        print("Usage: python3 validate_logs.py <log_file_path>")
        print("\nThis utility validates audit log files for:")
        print("  • File accessibility and format")
        print("  • AVC content quality")
        print("  • Parser compatibility")
        print("  • Performance characteristics")
        print("\nExample:")
        print("  python3 validate_logs.py ../testAVC/multi_AVC.log")
        return

    file_path = sys.argv[1]

    # Convert to absolute path
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    validation_result = validate_file(file_path)

    # Exit with error code if serious issues found
    if validation_result["recommendations"]["issues"]:
        critical_issues = ["File does not exist", "File is not readable", "Parser failed to process file"]
        if any(issue in validation_result["recommendations"]["issues"] for issue in critical_issues):
            sys.exit(1)

    print(f"\n✅ Validation completed successfully")

if __name__ == "__main__":
    main()