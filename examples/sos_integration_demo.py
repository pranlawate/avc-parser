#!/usr/bin/env python3
"""
Demonstration of OOP wrapper integration for sos-data-extractor

This example shows how to use the AVCAnalyzer class in an OOP architecture
similar to sos-data-extractor's class-based design.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selinux.avc_analyzer import AVCAnalyzer


def main():
    """Demonstrate AVCAnalyzer usage patterns"""

    if len(sys.argv) < 2:
        print("Usage: python3 sos_integration_demo.py <sos_directory>")
        print("\nExample:")
        print("  python3 sos_integration_demo.py /var/tmp/sosreport-host-2024-01-01-xyz")
        sys.exit(1)

    sos_dir = sys.argv[1]

    print("=" * 70)
    print("  SELinux AVC Analysis - OOP Wrapper Demonstration")
    print("=" * 70)
    print()

    # Pattern 1: Basic analysis with Rich table output
    print("📊 Pattern 1: Basic Analysis")
    print("-" * 70)
    analyzer = AVCAnalyzer(sos_dir)
    success = analyzer.analyze_avc_denials()

    if not success:
        print("Analysis failed or no denials found")
        return

    print()

    # Pattern 2: Programmatic access to denial data
    print("📊 Pattern 2: Programmatic Data Access")
    print("-" * 70)
    json_data = analyzer.get_denials_json()
    print(f"Total unique denials: {json_data['summary']['total_denials']}")
    print(f"Affected processes: {json_data['summary']['processes']}")
    print(f"Unique target types: {json_data['summary']['unique_types']}")
    print()

    # Pattern 3: Critical denials filtering
    print("📊 Pattern 3: Critical Denials (count > 10)")
    print("-" * 70)
    critical = analyzer.get_critical_denials()
    if critical:
        print(f"Found {len(critical)} critical denial patterns:")
        for denial in critical[:3]:  # Show first 3
            log = denial.get('log', {})
            print(f"  • {log.get('comm', 'unknown')} → {log.get('tcontext_type', 'unknown')} ({denial.get('count', 0)} occurrences)")
    else:
        print("No critical denials found (all counts < 10)")
    print()

    # Pattern 4: Executive summary report
    print("📊 Pattern 4: Executive Summary Report")
    print("-" * 70)
    brief_report = analyzer.generate_brief_report()
    print(brief_report[:500] + "..." if len(brief_report) > 500 else brief_report)
    print()

    # Pattern 5: Technical report generation
    print("📊 Pattern 5: Technical Report (first 10 lines)")
    print("-" * 70)
    technical = analyzer.generate_technical_report()
    lines = technical.split('\n')[:10]
    print('\n'.join(lines))
    print()

    print("=" * 70)
    print("✅ Demonstration completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
