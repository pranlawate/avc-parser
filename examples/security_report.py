#!/usr/bin/env python3
"""
Security Report Generation Example

This script demonstrates how to generate custom security reports
with risk assessment, trend analysis, and actionable recommendations.
"""

import subprocess
import sys
import os
import json
from datetime import datetime
from collections import defaultdict

def generate_executive_summary(log_file):
    """Generate an executive summary report."""
    print("🔒 Executive Security Summary")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        # Generate both JSON and report format
        json_result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", log_file,
            "--json"
        ], capture_output=True, text=True, timeout=30)

        report_result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", log_file,
            "--report", "brief"
        ], capture_output=True, text=True, timeout=30)

        if json_result.returncode == 0:
            data = json.loads(json_result.stdout)

            # Executive metrics
            total_denials = len(data.get('unique_denials', []))
            total_events = sum(denial.get('count', 1) for denial in data.get('unique_denials', []))

            # Risk assessment
            high_risk = sum(1 for denial in data.get('unique_denials', []) if denial.get('count', 1) > 100)
            medium_risk = sum(1 for denial in data.get('unique_denials', []) if 10 < denial.get('count', 1) <= 100)
            low_risk = total_denials - high_risk - medium_risk

            print("📊 SECURITY METRICS")
            print(f"  • Total Security Events: {total_events:,}")
            print(f"  • Unique Denial Types: {total_denials}")
            print(f"  • Risk Distribution:")
            print(f"    - High Risk (>100 events): {high_risk}")
            print(f"    - Medium Risk (11-100): {medium_risk}")
            print(f"    - Low Risk (≤10): {low_risk}")

            # Top concerns
            print(f"\n⚠️  TOP SECURITY CONCERNS")
            sorted_denials = sorted(data.get('unique_denials', []), key=lambda x: x.get('count', 1), reverse=True)
            for i, denial in enumerate(sorted_denials[:3]):
                log_data = denial.get('log', {})
                print(f"  {i+1}. {log_data.get('comm', 'Unknown')} → {log_data.get('tclass', 'Unknown')}")
                print(f"     Frequency: {denial.get('count', 1)} events")
                print(f"     Permissions: {', '.join(denial.get('permissions', []))}")

            # Extract security notices from report
            if report_result.returncode == 0:
                report_lines = report_result.stdout.split('\n')
                security_notices = [line for line in report_lines if 'NOTICE' in line or 'WARNING' in line]
                if security_notices:
                    print(f"\n🛡️  SECURITY NOTICES")
                    for notice in security_notices[:3]:
                        if notice.strip():
                            print(f"  • {notice.strip()}")

            print(f"\n📅 Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        else:
            print(f"❌ Failed to generate summary: {json_result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def analyze_threat_patterns(log_file):
    """Analyze patterns that might indicate security threats."""
    print("\n🎯 Threat Pattern Analysis")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", log_file,
            "--json"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            data = json.loads(result.stdout)

            # Threat indicators
            threat_patterns = {
                "privilege_escalation": [],
                "unauthorized_access": [],
                "data_exfiltration": [],
                "system_tampering": []
            }

            for denial in data.get('unique_denials', []):
                log_data = denial.get('log', {})
                permissions = denial.get('permissions', [])
                tclass = log_data.get('tclass', '')
                path = log_data.get('path', '')
                comm = log_data.get('comm', '')

                # Pattern detection logic
                if any(perm in permissions for perm in ['sys_admin', 'setuid', 'setgid']):
                    threat_patterns["privilege_escalation"].append({
                        "process": comm,
                        "target": tclass,
                        "severity": "high" if denial.get('count', 1) > 50 else "medium"
                    })

                if tclass in ['file', 'dir'] and any(path.startswith(p) for p in ['/etc', '/usr/bin', '/sbin']):
                    threat_patterns["system_tampering"].append({
                        "process": comm,
                        "target": path,
                        "severity": "high" if denial.get('count', 1) > 20 else "medium"
                    })

                if 'read' in permissions and any(path.startswith(p) for p in ['/home', '/var/www', '/opt']):
                    threat_patterns["unauthorized_access"].append({
                        "process": comm,
                        "target": path,
                        "severity": "medium" if denial.get('count', 1) > 10 else "low"
                    })

                if 'write' in permissions and tclass == 'file' and any(ext in path for ext in ['.conf', '.key', '.pem']):
                    threat_patterns["data_exfiltration"].append({
                        "process": comm,
                        "target": path,
                        "severity": "high"
                    })

            # Report findings
            total_threats = sum(len(patterns) for patterns in threat_patterns.values())
            print(f"🔍 Threat patterns detected: {total_threats}")

            for category, patterns in threat_patterns.items():
                if patterns:
                    print(f"\n⚠️  {category.upper().replace('_', ' ')}: {len(patterns)} indicators")
                    for pattern in patterns[:2]:  # Show top 2
                        severity_icon = "🔴" if pattern["severity"] == "high" else "🟡" if pattern["severity"] == "medium" else "🟢"
                        print(f"    {severity_icon} {pattern['process']} → {pattern['target']}")

            if total_threats == 0:
                print("✅ No obvious threat patterns detected")

        else:
            print(f"❌ Failed to analyze patterns: {result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def generate_compliance_report(log_file):
    """Generate a compliance-focused report."""
    print("\n📋 Compliance Report")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", log_file,
            "--report", "sealert"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            report_lines = result.stdout.split('\n')

            # Parse compliance elements
            compliance_data = {
                "policy_violations": 0,
                "permissive_events": 0,
                "configuration_issues": 0,
                "recommendations": []
            }

            for line in report_lines:
                if 'permissive' in line.lower():
                    compliance_data["permissive_events"] += 1
                if 'dontaudit' in line.lower():
                    compliance_data["configuration_issues"] += 1
                if 'boolean' in line.lower() or 'setsebool' in line.lower():
                    compliance_data["recommendations"].append(line.strip())

            compliance_data["policy_violations"] = len([line for line in report_lines if 'denied' in line.lower()])

            print("📊 COMPLIANCE METRICS")
            print(f"  • Policy Violations: {compliance_data['policy_violations']}")
            print(f"  • Permissive Mode Events: {compliance_data['permissive_events']}")
            print(f"  • Configuration Issues: {compliance_data['configuration_issues']}")

            if compliance_data["recommendations"]:
                print(f"\n🔧 REMEDIATION ACTIONS")
                for rec in compliance_data["recommendations"][:3]:
                    if rec:
                        print(f"  • {rec}")

            # Compliance score (simplified)
            total_issues = sum([compliance_data["policy_violations"],
                               compliance_data["permissive_events"],
                               compliance_data["configuration_issues"]])

            if total_issues == 0:
                score = 100
            elif total_issues < 10:
                score = 85
            elif total_issues < 50:
                score = 70
            else:
                score = 50

            print(f"\n📈 COMPLIANCE SCORE: {score}/100")
            if score >= 85:
                print("✅ Good compliance posture")
            elif score >= 70:
                print("⚠️  Some compliance issues detected")
            else:
                print("🔴 Significant compliance concerns")

        else:
            print(f"❌ Failed to generate compliance report: {result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def main():
    """Generate comprehensive security reports."""
    print("📄 AVC Parser - Security Report Generation")
    print("=" * 50)

    # Use a sample log file
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_log = os.path.join(parent_dir, "testAVC", "multi_AVC.log")

    if not os.path.exists(sample_log):
        print(f"⚠️  Sample log not found: {sample_log}")
        print("Please run this script from the examples/ directory")
        return

    print(f"🔍 Analyzing: {os.path.basename(sample_log)}")

    # Generate different types of reports
    generate_executive_summary(sample_log)
    analyze_threat_patterns(sample_log)
    generate_compliance_report(sample_log)

    print("\n🎯 Report Generation Tips:")
    print("  • Customize threat patterns for your environment")
    print("  • Set up automated report scheduling")
    print("  • Export reports to PDF/HTML for distribution")
    print("  • Integrate with ticketing systems for alerts")
    print("  • Archive reports for historical trend analysis")

if __name__ == "__main__":
    main()