#!/usr/bin/env python3
"""
Performance Testing and Benchmarking Example

This script demonstrates how to benchmark AVC Parser performance
across different file sizes, formats, and system configurations.
"""

import subprocess
import sys
import os
import time
import json
import psutil
from datetime import datetime
from pathlib import Path

def measure_execution_time(func):
    """Decorator to measure function execution time."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        return result, execution_time
    return wrapper

@measure_execution_time
def run_parser(file_path, *args):
    """Run the parser with timing measurement."""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    cmd = [sys.executable, os.path.join(parent_dir, "parse_avc.py"), "--file", file_path] + list(args)

    # Measure memory before
    process = psutil.Process()
    memory_before = process.memory_info().rss / 1024 / 1024  # MB

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Measure memory after
    memory_after = process.memory_info().rss / 1024 / 1024  # MB
    memory_used = memory_after - memory_before

    return {
        "returncode": result.returncode,
        "stdout_size": len(result.stdout),
        "stderr_size": len(result.stderr),
        "memory_used_mb": memory_used
    }

def benchmark_file_sizes():
    """Benchmark performance across different file sizes."""
    print("📊 File Size Performance Benchmark")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_files = []

    # Find available test files
    for test_dir in ["testAVC", "testRAW"]:
        test_path = os.path.join(parent_dir, test_dir)
        if os.path.exists(test_path):
            for file_path in Path(test_path).glob("*.log"):
                file_size = file_path.stat().st_size
                test_files.append({
                    "path": str(file_path),
                    "size_bytes": file_size,
                    "size_mb": file_size / 1024 / 1024,
                    "name": file_path.name
                })

    # Sort by file size
    test_files.sort(key=lambda x: x["size_bytes"])

    benchmark_results = []

    for file_info in test_files[:5]:  # Test up to 5 files
        print(f"\n🔍 Testing: {file_info['name']} ({file_info['size_mb']:.2f} MB)")

        try:
            result, execution_time = run_parser(file_info["path"])

            if result["returncode"] == 0:
                # Calculate throughput
                throughput_mb_per_sec = file_info["size_mb"] / execution_time if execution_time > 0 else 0

                benchmark_data = {
                    "file": file_info["name"],
                    "size_mb": file_info["size_mb"],
                    "execution_time": execution_time,
                    "memory_used_mb": result["memory_used_mb"],
                    "throughput_mb_per_sec": throughput_mb_per_sec,
                    "output_size_kb": result["stdout_size"] / 1024
                }

                benchmark_results.append(benchmark_data)

                print(f"  ✅ Time: {execution_time:.2f}s")
                print(f"  📈 Throughput: {throughput_mb_per_sec:.2f} MB/s")
                print(f"  💾 Memory: {result['memory_used_mb']:.1f} MB")
                print(f"  📄 Output: {result['stdout_size']} chars")
            else:
                print(f"  ❌ Failed to process file")

        except subprocess.TimeoutExpired:
            print(f"  ⏰ Timeout (>120s)")
        except Exception as e:
            print(f"  💥 Error: {e}")

    # Summary
    if benchmark_results:
        print(f"\n📊 Performance Summary")
        print("=" * 30)
        avg_throughput = sum(r["throughput_mb_per_sec"] for r in benchmark_results) / len(benchmark_results)
        max_memory = max(r["memory_used_mb"] for r in benchmark_results)
        total_time = sum(r["execution_time"] for r in benchmark_results)

        print(f"Average throughput: {avg_throughput:.2f} MB/s")
        print(f"Peak memory usage: {max_memory:.1f} MB")
        print(f"Total processing time: {total_time:.2f}s")

    return benchmark_results

def benchmark_output_formats():
    """Benchmark different output format performance."""
    print("\n🎨 Output Format Performance Benchmark")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_file = os.path.join(parent_dir, "testAVC", "multi_AVC.log")

    if not os.path.exists(test_file):
        print("⚠️  Test file not available")
        return []

    formats = [
        ("default", []),
        ("json", ["--json"]),
        ("detailed", ["--detailed"]),
        ("report_brief", ["--report", "brief"]),
        ("report_sealert", ["--report", "sealert"])
    ]

    format_results = []

    for format_name, args in formats:
        print(f"\n🔍 Testing format: {format_name}")

        try:
            result, execution_time = run_parser(test_file, *args)

            if result["returncode"] == 0:
                format_data = {
                    "format": format_name,
                    "execution_time": execution_time,
                    "memory_used_mb": result["memory_used_mb"],
                    "output_size_kb": result["stdout_size"] / 1024
                }

                format_results.append(format_data)

                print(f"  ✅ Time: {execution_time:.3f}s")
                print(f"  💾 Memory: {result['memory_used_mb']:.1f} MB")
                print(f"  📄 Output: {result['stdout_size']} chars")
            else:
                print(f"  ❌ Failed")

        except Exception as e:
            print(f"  💥 Error: {e}")

    # Format comparison
    if format_results:
        print(f"\n📊 Format Comparison")
        print("=" * 25)
        baseline = next((r for r in format_results if r["format"] == "default"), None)

        for result in format_results:
            relative_time = ""
            if baseline and baseline["execution_time"] > 0:
                ratio = result["execution_time"] / baseline["execution_time"]
                relative_time = f" ({ratio:.1f}x)"

            print(f"{result['format']:15} | {result['execution_time']:.3f}s{relative_time}")

    return format_results

def stress_test():
    """Perform stress testing with multiple concurrent processes."""
    print("\n💪 Stress Test (Multiple Processes)")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_file = os.path.join(parent_dir, "testAVC", "large_scale_test.log")

    if not os.path.exists(test_file):
        test_file = os.path.join(parent_dir, "testAVC", "multi_AVC.log")

    if not os.path.exists(test_file):
        print("⚠️  No suitable test file available")
        return

    print(f"🔍 Stress testing with: {os.path.basename(test_file)}")

    # Test with increasing number of concurrent processes
    for num_processes in [1, 2, 4]:
        print(f"\n⚡ Testing with {num_processes} concurrent process(es)")

        start_time = time.time()
        processes = []

        try:
            # Launch multiple processes
            for i in range(num_processes):
                cmd = [sys.executable, os.path.join(parent_dir, "parse_avc.py"),
                       "--file", test_file, "--json"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
                processes.append(proc)

            # Wait for all to complete
            results = []
            for proc in processes:
                stdout, stderr = proc.communicate(timeout=60)
                results.append({
                    "returncode": proc.returncode,
                    "stdout_size": len(stdout),
                    "stderr_size": len(stderr)
                })

            end_time = time.time()
            total_time = end_time - start_time

            successful = sum(1 for r in results if r["returncode"] == 0)
            print(f"  ✅ Successful: {successful}/{num_processes}")
            print(f"  ⏱️  Total time: {total_time:.2f}s")
            print(f"  📈 Avg time per process: {total_time/num_processes:.2f}s")

        except subprocess.TimeoutExpired:
            print(f"  ⏰ Stress test timed out")
            for proc in processes:
                proc.terminate()
        except Exception as e:
            print(f"  💥 Error: {e}")

def generate_performance_report(benchmark_results, format_results):
    """Generate a comprehensive performance report."""
    print("\n📄 Performance Report")
    print("=" * 30)

    report = {
        "timestamp": datetime.now().isoformat(),
        "system_info": {
            "cpu_count": psutil.cpu_count(),
            "memory_gb": psutil.virtual_memory().total / 1024 / 1024 / 1024,
            "python_version": sys.version
        },
        "file_benchmark": benchmark_results,
        "format_benchmark": format_results
    }

    # Calculate key metrics
    if benchmark_results:
        avg_throughput = sum(r["throughput_mb_per_sec"] for r in benchmark_results) / len(benchmark_results)
        print(f"💨 Average throughput: {avg_throughput:.2f} MB/s")

    if format_results:
        fastest_format = min(format_results, key=lambda x: x["execution_time"])
        slowest_format = max(format_results, key=lambda x: x["execution_time"])
        print(f"🏎️  Fastest format: {fastest_format['format']} ({fastest_format['execution_time']:.3f}s)")
        print(f"🐌 Slowest format: {slowest_format['format']} ({slowest_format['execution_time']:.3f}s)")

    # Save detailed report
    report_file = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"💾 Detailed report saved: {report_file}")

def main():
    """Run comprehensive performance benchmarks."""
    print("⚡ AVC Parser - Performance Benchmarking")
    print("=" * 50)

    print(f"🖥️  System: {psutil.cpu_count()} CPUs, {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f} GB RAM")
    print(f"🐍 Python: {sys.version.split()[0]}")

    # Run benchmarks
    benchmark_results = benchmark_file_sizes()
    format_results = benchmark_output_formats()
    stress_test()
    generate_performance_report(benchmark_results, format_results)

    print("\n🎯 Performance Tips:")
    print("  • Use --json for fastest processing")
    print("  • Monitor memory usage with large files")
    print("  • Consider parallel processing for batch jobs")
    print("  • Profile specific use cases for optimization")

if __name__ == "__main__":
    main()