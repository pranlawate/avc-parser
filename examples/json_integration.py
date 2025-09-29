#!/usr/bin/env python3
"""
JSON Integration Example for SIEM and Monitoring Systems

This script demonstrates how to integrate AVC Parser with SIEM systems,
monitoring tools, and data pipelines using structured JSON output.
"""

import subprocess
import sys
import os
import json
from datetime import datetime

def elasticsearch_integration():
    """Example integration with Elasticsearch/ELK stack."""
    print("🔍 Elasticsearch Integration Example")
    print("-" * 40)

    # Change to parent directory
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        # Generate JSON output
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/multi_AVC.log",
            "--json"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            data = json.loads(result.stdout)

            # Transform for Elasticsearch indexing
            es_documents = []
            for denial in data.get('unique_denials', []):
                log_data = denial.get('log', {})

                # Create Elasticsearch document
                es_doc = {
                    "@timestamp": datetime.now().isoformat(),
                    "selinux": {
                        "denial": {
                            "source_context": log_data.get('scontext', ''),
                            "target_context": log_data.get('tcontext', ''),
                            "process": log_data.get('comm', ''),
                            "object_class": log_data.get('tclass', ''),
                            "permissions": denial.get('permissions', []),
                            "path": log_data.get('path', ''),
                            "denied_count": denial.get('count', 1)
                        }
                    },
                    "host": {
                        "hostname": log_data.get('hostname', 'unknown')
                    },
                    "event": {
                        "category": "security",
                        "type": "denied",
                        "outcome": "failure"
                    }
                }
                es_documents.append(es_doc)

            print(f"✅ Generated {len(es_documents)} Elasticsearch documents")
            print("📋 Sample document structure:")
            if es_documents:
                sample = es_documents[0]
                print(f"  • Process: {sample['selinux']['denial']['process']}")
                print(f"  • Object: {sample['selinux']['denial']['object_class']}")
                print(f"  • Permissions: {sample['selinux']['denial']['permissions']}")

            # Simulate bulk indexing (in real usage, send to Elasticsearch)
            print("\n📤 Bulk indexing simulation:")
            for i, doc in enumerate(es_documents[:3]):  # Show first 3
                print(f"  {i+1}. POST /selinux-denials/_doc/ {json.dumps(doc, indent=None)[:100]}...")

        else:
            print(f"❌ Error generating JSON: {result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def splunk_integration():
    """Example integration with Splunk."""
    print("\n🔍 Splunk Integration Example")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/network_AVC.log",
            "--json"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            data = json.loads(result.stdout)

            # Transform for Splunk indexing
            splunk_events = []
            for denial in data.get('unique_denials', []):
                log_data = denial.get('log', {})

                # Create Splunk event
                splunk_event = {
                    "time": datetime.now().isoformat(),
                    "source": "selinux:avc",
                    "sourcetype": "linux:audit:avc",
                    "host": log_data.get('hostname', 'unknown'),
                    "event": {
                        "selinux_denial": True,
                        "comm": log_data.get('comm', ''),
                        "scontext": log_data.get('scontext', ''),
                        "tcontext": log_data.get('tcontext', ''),
                        "tclass": log_data.get('tclass', ''),
                        "permissions": " ".join(denial.get('permissions', [])),
                        "path": log_data.get('path', ''),
                        "count": denial.get('count', 1),
                        "severity": "medium" if denial.get('count', 1) > 10 else "low"
                    }
                }
                splunk_events.append(splunk_event)

            print(f"✅ Generated {len(splunk_events)} Splunk events")
            print("📋 Sample Splunk event:")
            if splunk_events:
                sample = splunk_events[0]['event']
                print(f"  • sourcetype: linux:audit:avc")
                print(f"  • comm: {sample['comm']}")
                print(f"  • permissions: {sample['permissions']}")
                print(f"  • severity: {sample['severity']}")

        else:
            print(f"❌ Error: {result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def metrics_extraction():
    """Extract metrics for monitoring dashboards."""
    print("\n📊 Metrics Extraction Example")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(parent_dir)

    try:
        result = subprocess.run([
            sys.executable, "parse_avc.py",
            "--file", "testAVC/large_scale_test.log",
            "--json"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            data = json.loads(result.stdout)

            # Extract key metrics
            metrics = {
                "total_denials": len(data.get('unique_denials', [])),
                "total_events": sum(denial.get('count', 1) for denial in data.get('unique_denials', [])),
                "top_processes": {},
                "top_object_classes": {},
                "permission_frequency": {}
            }

            # Aggregate metrics
            for denial in data.get('unique_denials', []):
                log_data = denial.get('log', {})
                count = denial.get('count', 1)

                # Process frequency
                comm = log_data.get('comm', 'unknown')
                metrics["top_processes"][comm] = metrics["top_processes"].get(comm, 0) + count

                # Object class frequency
                tclass = log_data.get('tclass', 'unknown')
                metrics["top_object_classes"][tclass] = metrics["top_object_classes"].get(tclass, 0) + count

                # Permission frequency
                for perm in denial.get('permissions', []):
                    metrics["permission_frequency"][perm] = metrics["permission_frequency"].get(perm, 0) + count

            # Sort and limit top entries
            metrics["top_processes"] = dict(sorted(metrics["top_processes"].items(), key=lambda x: x[1], reverse=True)[:5])
            metrics["top_object_classes"] = dict(sorted(metrics["top_object_classes"].items(), key=lambda x: x[1], reverse=True)[:5])
            metrics["permission_frequency"] = dict(sorted(metrics["permission_frequency"].items(), key=lambda x: x[1], reverse=True)[:5])

            print("✅ Metrics extracted successfully:")
            print(f"  📈 Total unique denials: {metrics['total_denials']}")
            print(f"  📈 Total denial events: {metrics['total_events']}")
            print(f"  🔝 Top process: {list(metrics['top_processes'].keys())[0] if metrics['top_processes'] else 'N/A'}")
            print(f"  🔝 Top object class: {list(metrics['top_object_classes'].keys())[0] if metrics['top_object_classes'] else 'N/A'}")

            # Generate Prometheus-style metrics
            print("\n📊 Prometheus metrics format:")
            print(f"# HELP selinux_denials_total Total number of SELinux denials")
            print(f"# TYPE selinux_denials_total counter")
            print(f"selinux_denials_total {metrics['total_events']}")

            for process, count in list(metrics["top_processes"].items())[:3]:
                print(f"selinux_denials_by_process{{process=\"{process}\"}} {count}")

        else:
            print(f"❌ Error: {result.stderr}")

    except Exception as e:
        print(f"💥 Error: {e}")

def main():
    """Run all integration examples."""
    print("🔗 AVC Parser - SIEM Integration Examples")
    print("=" * 50)

    elasticsearch_integration()
    splunk_integration()
    metrics_extraction()

    print("\n🎯 Integration Tips:")
    print("  • Use --json for structured output")
    print("  • Implement error handling in production")
    print("  • Consider batch processing for large files")
    print("  • Set up automated parsing with cron/systemd")
    print("  • Monitor parser performance and memory usage")

if __name__ == "__main__":
    main()