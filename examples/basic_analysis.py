#!/usr/bin/env python3
"""
Basic AVC Denial Analysis Example

This script demonstrates the fundamental usage of AVC Parser for analyzing
SELinux audit logs and understanding denial patterns.
"""

import subprocess
import sys
import os

def run_basic_analysis():
    """Run basic analysis examples with different options."""

    # Change to parent directory to run parse_avc.py
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    print("🔍 AVC Parser - Basic Analysis Examples")
    print("=" * 50)

    # Example 1: Simple analysis
    print("\n📋 Example 1: Basic Denial Analysis")
    print("-" * 40)
    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/2AVC.log"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print("✅ Analysis completed successfully")
            print("Sample output (first 10 lines):")
            lines = result.stdout.split('\n')[:10]
            for line in lines:
                if line.strip():
                    print(f"  {line}")
        else:
            print(f"❌ Error: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("⏰ Analysis timed out")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

    # Example 2: JSON output
    print("\n📊 Example 2: JSON Output (for integration)")
    print("-" * 40)
    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/network_AVC.log",
            "--json"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print("✅ JSON output generated successfully")
            # Show just the structure, not full content
            import json
            try:
                data = json.loads(result.stdout)
                print(f"  📈 Unique denials: {len(data.get('unique_denials', []))}")
                print(f"  📈 Valid log blocks: {len(data.get('valid_blocks', []))}")
                if data.get('unique_denials'):
                    first_denial = data['unique_denials'][0]
                    print(f"  📋 Sample denial: {first_denial.get('log', {}).get('comm', 'N/A')} → {first_denial.get('log', {}).get('tclass', 'N/A')}")
            except json.JSONDecodeError:
                print("  📄 Raw JSON output generated (structure varies)")
        else:
            print(f"❌ Error: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("⏰ JSON generation timed out")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

    # Example 3: Security report
    print("\n🔒 Example 3: Security Report")
    print("-" * 40)
    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/multi_AVC.log",
            "--report", "brief"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print("✅ Security report generated successfully")
            print("Sample security insights:")
            lines = result.stdout.split('\n')
            security_lines = [line for line in lines if any(keyword in line.lower()
                            for keyword in ['security', 'notice', 'permissive', 'warning'])][:5]
            for line in security_lines:
                if line.strip():
                    print(f"  🛡️  {line.strip()}")
        else:
            print(f"❌ Error: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("⏰ Report generation timed out")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

    print("\n🎯 Next Steps:")
    print("  • Try 'json_integration.py' for SIEM integration")
    print("  • Run 'security_report.py' for detailed reporting")
    print("  • Check 'batch_processing.py' for multiple files")
    print("  • Explore filtering options with --process or --path")

if __name__ == "__main__":
    run_basic_analysis()