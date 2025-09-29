#!/usr/bin/env python3
"""
Batch Processing Example

This script demonstrates how to process multiple audit log files
in batch mode for comprehensive security analysis across systems.
"""

import subprocess
import sys
import os
import json
import glob
from datetime import datetime
from pathlib import Path

def process_directory(directory_path, output_format="summary"):
    """Process all log files in a directory."""
    print(f"📁 Processing directory: {directory_path}")
    print("-" * 50)

    # Find all log files
    log_patterns = ["*.log", "*.audit", "audit.*"]
    log_files = []

    for pattern in log_patterns:
        log_files.extend(glob.glob(os.path.join(directory_path, pattern)))
        log_files.extend(glob.glob(os.path.join(directory_path, "**", pattern), recursive=True))

    # Remove duplicates and sort
    log_files = sorted(list(set(log_files)))

    if not log_files:
        print(f"⚠️  No log files found in {directory_path}")
        return

    print(f"🔍 Found {len(log_files)} log files")

    # Change to parent directory to run parse_avc.py
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    original_dir = os.getcwd()
    os.chdir(parent_dir)

    total_denials = 0
    total_events = 0
    processed_files = 0
    failed_files = []

    try:
        for log_file in log_files:
            try:
                print(f"\n📋 Processing: {os.path.basename(log_file)}")

                # Determine file type and use appropriate flag
                file_flag = "--file"  # Default auto-detection

                result = subprocess.run([
                    sys.executable, "parse_avc.py",
                    file_flag, log_file,
                    "--json"
                ], capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        file_denials = len(data.get('unique_denials', []))
                        file_events = sum(denial.get('count', 1) for denial in data.get('unique_denials', []))

                        total_denials += file_denials
                        total_events += file_events
                        processed_files += 1

                        print(f"  ✅ {file_denials} unique denials, {file_events} total events")

                        # Save individual file results if requested
                        if output_format == "detailed":
                            output_file = f"batch_results_{os.path.basename(log_file)}.json"
                            with open(output_file, 'w') as f:
                                json.dump(data, f, indent=2)
                            print(f"  💾 Detailed results saved to {output_file}")

                    except json.JSONDecodeError:
                        print(f"  ⚠️  Invalid JSON output from {log_file}")
                        failed_files.append(log_file)

                else:
                    print(f"  ❌ Failed to process: {result.stderr.strip()}")
                    failed_files.append(log_file)

            except subprocess.TimeoutExpired:
                print(f"  ⏰ Timeout processing {log_file}")
                failed_files.append(log_file)
            except Exception as e:
                print(f"  💥 Error processing {log_file}: {e}")
                failed_files.append(log_file)

    finally:
        os.chdir(original_dir)

    # Summary report
    print(f"\n📊 Batch Processing Summary")
    print("=" * 40)
    print(f"📁 Directory: {directory_path}")
    print(f"📋 Files found: {len(log_files)}")
    print(f"✅ Files processed: {processed_files}")
    print(f"❌ Files failed: {len(failed_files)}")
    print(f"🔍 Total unique denials: {total_denials}")
    print(f"📈 Total denial events: {total_events}")

    if failed_files:
        print(f"\n⚠️  Failed files:")
        for failed_file in failed_files[:5]:  # Show first 5
            print(f"  • {os.path.basename(failed_file)}")
        if len(failed_files) > 5:
            print(f"  ... and {len(failed_files) - 5} more")

    return {
        "total_files": len(log_files),
        "processed_files": processed_files,
        "failed_files": len(failed_files),
        "total_denials": total_denials,
        "total_events": total_events
    }

def compare_systems():
    """Compare denial patterns across different systems."""
    print("🔍 Multi-System Comparison Example")
    print("-" * 40)

    # Simulate processing logs from different systems
    test_dirs = ["testAVC", "testRAW"]
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    system_stats = {}

    for test_dir in test_dirs:
        full_path = os.path.join(parent_dir, test_dir)
        if os.path.exists(full_path):
            print(f"\n🖥️  System: {test_dir}")
            stats = process_directory(full_path, "summary")
            system_stats[test_dir] = stats

    # Comparison summary
    if len(system_stats) > 1:
        print(f"\n🔄 System Comparison")
        print("=" * 30)
        for system, stats in system_stats.items():
            denial_rate = stats['total_events'] / max(stats['processed_files'], 1)
            print(f"{system:12} | {stats['total_events']:6} events | {denial_rate:.1f} avg/file")

def generate_consolidated_report():
    """Generate a consolidated security report from multiple sources."""
    print("\n📄 Consolidated Security Report Example")
    print("-" * 50)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    # Get all available test files
    test_files = glob.glob("testAVC/*.log") + glob.glob("testRAW/*.log")

    consolidated_data = {
        "report_timestamp": datetime.now().isoformat(),
        "sources": [],
        "summary": {
            "total_sources": 0,
            "total_denials": 0,
            "total_events": 0,
            "critical_issues": [],
            "top_processes": {},
            "top_targets": {}
        }
    }

    for test_file in test_files[:5]:  # Limit to 5 files for demo
        try:
            result = subprocess.run([
                sys.executable, "parse_avc.py",
                "--file", test_file,
                "--json"
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                data = json.loads(result.stdout)
                source_info = {
                    "file": os.path.basename(test_file),
                    "denials": len(data.get('unique_denials', [])),
                    "events": sum(denial.get('count', 1) for denial in data.get('unique_denials', []))
                }

                consolidated_data["sources"].append(source_info)
                consolidated_data["summary"]["total_denials"] += source_info["denials"]
                consolidated_data["summary"]["total_events"] += source_info["events"]

                # Track high-frequency denials as potential critical issues
                for denial in data.get('unique_denials', []):
                    if denial.get('count', 1) > 50:  # Threshold for critical
                        log_data = denial.get('log', {})
                        critical_issue = f"{log_data.get('comm', 'unknown')} → {log_data.get('tclass', 'unknown')}"
                        consolidated_data["summary"]["critical_issues"].append(critical_issue)

        except Exception as e:
            print(f"⚠️  Skipping {test_file}: {e}")

    consolidated_data["summary"]["total_sources"] = len(consolidated_data["sources"])

    print("✅ Consolidated report generated:")
    print(f"  📁 Sources processed: {consolidated_data['summary']['total_sources']}")
    print(f"  🔍 Total denials: {consolidated_data['summary']['total_denials']}")
    print(f"  📈 Total events: {consolidated_data['summary']['total_events']}")
    print(f"  ⚠️  Critical issues: {len(consolidated_data['summary']['critical_issues'])}")

    # Save report
    report_filename = f"consolidated_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump(consolidated_data, f, indent=2)
    print(f"  💾 Report saved to {report_filename}")

def main():
    """Run batch processing examples."""
    print("📦 AVC Parser - Batch Processing Examples")
    print("=" * 50)

    # Example 1: Process a directory
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_dir = os.path.join(parent_dir, "testAVC")

    if os.path.exists(test_dir):
        process_directory(test_dir, "summary")

    # Example 2: Compare systems
    compare_systems()

    # Example 3: Consolidated reporting
    generate_consolidated_report()

    print("\n🎯 Batch Processing Tips:")
    print("  • Use timeout values for large files")
    print("  • Implement parallel processing for speed")
    print("  • Monitor memory usage with many files")
    print("  • Set up automated scheduling with cron")
    print("  • Archive processed results for historical analysis")

if __name__ == "__main__":
    main()