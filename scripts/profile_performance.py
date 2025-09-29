#!/usr/bin/env python3
"""
Performance Profiling Utility

This script profiles the AVC Parser performance, identifies bottlenecks,
and provides optimization recommendations.
"""

import subprocess
import sys
import os
import time
import psutil
import json
import cProfile
import pstats
import io
from datetime import datetime
from pathlib import Path

def profile_memory_usage(file_path, duration=60):
    """Profile memory usage during parsing."""
    print(f"💾 Memory profiling: {os.path.basename(file_path)}")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Start the parser process
    cmd = [sys.executable, os.path.join(parent_dir, "parse_avc.py"), "--file", file_path, "--json"]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ps_process = psutil.Process(process.pid)

    # Monitor memory usage
    memory_samples = []
    start_time = time.time()

    try:
        while process.poll() is None and (time.time() - start_time) < duration:
            try:
                memory_info = ps_process.memory_info()
                cpu_percent = ps_process.cpu_percent()

                memory_samples.append({
                    "timestamp": time.time() - start_time,
                    "rss_mb": memory_info.rss / 1024 / 1024,
                    "vms_mb": memory_info.vms / 1024 / 1024,
                    "cpu_percent": cpu_percent
                })

                time.sleep(0.1)  # Sample every 100ms
            except psutil.NoSuchProcess:
                break

        stdout, stderr = process.communicate(timeout=5)

    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()

    # Analyze memory usage
    if memory_samples:
        max_memory = max(sample["rss_mb"] for sample in memory_samples)
        avg_memory = sum(sample["rss_mb"] for sample in memory_samples) / len(memory_samples)
        max_cpu = max(sample["cpu_percent"] for sample in memory_samples)

        print(f"  📊 Peak memory: {max_memory:.1f} MB")
        print(f"  📊 Average memory: {avg_memory:.1f} MB")
        print(f"  📊 Peak CPU: {max_cpu:.1f}%")
        print(f"  📊 Samples collected: {len(memory_samples)}")

        # Memory growth analysis
        if len(memory_samples) > 10:
            early_avg = sum(sample["rss_mb"] for sample in memory_samples[:5]) / 5
            late_avg = sum(sample["rss_mb"] for sample in memory_samples[-5:]) / 5
            growth = late_avg - early_avg

            if growth > 10:  # More than 10MB growth
                print(f"  ⚠️  Memory growth detected: +{growth:.1f} MB")
            else:
                print(f"  ✅ Memory usage stable: {growth:+.1f} MB")

        return {
            "max_memory_mb": max_memory,
            "avg_memory_mb": avg_memory,
            "max_cpu_percent": max_cpu,
            "samples": len(memory_samples),
            "success": process.returncode == 0
        }
    else:
        print("  ❌ No memory samples collected")
        return None

def profile_cpu_performance(file_path):
    """Profile CPU performance and identify hotspots."""
    print(f"⚡ CPU profiling: {os.path.basename(file_path)}")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Create a wrapper script for profiling
    wrapper_script = f"""
import sys
sys.path.insert(0, '{parent_dir}')

# Import and run the parser
import parse_avc
import argparse

# Simulate command line arguments
sys.argv = ['parse_avc.py', '--file', '{file_path}', '--json']

# Run the main function
parse_avc.main()
"""

    # Run with cProfile
    pr = cProfile.Profile()
    start_time = time.time()

    try:
        pr.enable()
        exec(wrapper_script)
        pr.disable()

        execution_time = time.time() - start_time

        # Analyze profile results
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(20)  # Top 20 functions

        profile_output = s.getvalue()

        print(f"  ⏱️  Total execution time: {execution_time:.2f}s")
        print(f"  🔍 Top CPU hotspots:")

        # Extract top functions from profile
        lines = profile_output.split('\n')
        for line in lines[5:10]:  # Skip header, show top 5
            if line.strip() and not line.startswith('ncalls'):
                parts = line.split()
                if len(parts) >= 6:
                    cumtime = parts[3]
                    function = ' '.join(parts[5:])
                    print(f"    • {function}: {cumtime}s")

        return {
            "execution_time": execution_time,
            "profile_data": profile_output,
            "success": True
        }

    except Exception as e:
        print(f"  ❌ Profiling failed: {e}")
        return {"success": False, "error": str(e)}

def profile_io_performance(file_path):
    """Profile I/O performance."""
    print(f"💿 I/O profiling: {os.path.basename(file_path)}")
    print("-" * 40)

    if not os.path.exists(file_path):
        print("  ❌ File not found")
        return None

    file_size = os.path.getsize(file_path) / 1024 / 1024  # MB

    # Test file reading performance
    start_time = time.time()
    line_count = 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1

        read_time = time.time() - start_time
        read_throughput = file_size / read_time if read_time > 0 else 0

        print(f"  📁 File size: {file_size:.2f} MB")
        print(f"  📄 Lines: {line_count:,}")
        print(f"  ⏱️  Read time: {read_time:.2f}s")
        print(f"  📈 Read throughput: {read_throughput:.1f} MB/s")

        # Test with different buffer sizes
        buffer_sizes = [8192, 65536, 262144]  # 8KB, 64KB, 256KB
        buffer_results = {}

        for buffer_size in buffer_sizes:
            start_time = time.time()
            bytes_read = 0

            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(buffer_size)
                    if not chunk:
                        break
                    bytes_read += len(chunk)

            buffer_time = time.time() - start_time
            buffer_throughput = (bytes_read / 1024 / 1024) / buffer_time if buffer_time > 0 else 0
            buffer_results[buffer_size] = buffer_throughput

        print(f"  🔧 Buffer optimization:")
        for size, throughput in buffer_results.items():
            print(f"    {size//1024}KB buffer: {throughput:.1f} MB/s")

        best_buffer = max(buffer_results.items(), key=lambda x: x[1])
        print(f"  ✅ Best buffer size: {best_buffer[0]//1024}KB ({best_buffer[1]:.1f} MB/s)")

        return {
            "file_size_mb": file_size,
            "line_count": line_count,
            "read_time": read_time,
            "read_throughput": read_throughput,
            "buffer_results": buffer_results,
            "best_buffer_kb": best_buffer[0] // 1024
        }

    except Exception as e:
        print(f"  ❌ I/O profiling failed: {e}")
        return {"success": False, "error": str(e)}

def profile_scaling_performance():
    """Profile performance across different file sizes."""
    print("📈 Scaling performance analysis")
    print("-" * 40)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Find test files of different sizes
    test_files = []
    for test_dir in ["testAVC", "testRAW"]:
        test_path = os.path.join(parent_dir, test_dir)
        if os.path.exists(test_path):
            for file_path in Path(test_path).glob("*.log"):
                file_size = file_path.stat().st_size / 1024 / 1024  # MB
                test_files.append({
                    "path": str(file_path),
                    "size_mb": file_size,
                    "name": file_path.name
                })

    # Sort by size
    test_files.sort(key=lambda x: x["size_mb"])

    scaling_results = []

    for file_info in test_files[:5]:  # Test up to 5 files
        print(f"\n  📋 Testing: {file_info['name']} ({file_info['size_mb']:.2f} MB)")

        start_time = time.time()

        try:
            result = subprocess.run([
                sys.executable, os.path.join(parent_dir, "parse_avc.py"),
                "--file", file_info["path"],
                "--json"
            ], capture_output=True, text=True, timeout=120)

            execution_time = time.time() - start_time

            if result.returncode == 0:
                # Count denials in output
                try:
                    data = json.loads(result.stdout)
                    denials_found = len(data.get('unique_denials', []))
                    events_found = sum(denial.get('count', 1) for denial in data.get('unique_denials', []))
                except:
                    denials_found = 0
                    events_found = 0

                throughput = file_info["size_mb"] / execution_time if execution_time > 0 else 0

                scaling_results.append({
                    "file": file_info["name"],
                    "size_mb": file_info["size_mb"],
                    "execution_time": execution_time,
                    "throughput": throughput,
                    "denials": denials_found,
                    "events": events_found
                })

                print(f"    ✅ {execution_time:.2f}s, {throughput:.1f} MB/s, {denials_found} denials")

            else:
                print(f"    ❌ Failed to process")

        except subprocess.TimeoutExpired:
            print(f"    ⏰ Timeout")

    # Analyze scaling characteristics
    if len(scaling_results) > 1:
        print(f"\n  📊 Scaling analysis:")

        # Calculate scaling factor
        small_file = min(scaling_results, key=lambda x: x["size_mb"])
        large_file = max(scaling_results, key=lambda x: x["size_mb"])

        size_ratio = large_file["size_mb"] / small_file["size_mb"]
        time_ratio = large_file["execution_time"] / small_file["execution_time"]

        scaling_factor = time_ratio / size_ratio

        print(f"    Size ratio: {size_ratio:.1f}x")
        print(f"    Time ratio: {time_ratio:.1f}x")
        print(f"    Scaling factor: {scaling_factor:.2f}")

        if scaling_factor < 1.2:
            print(f"    ✅ Good linear scaling")
        elif scaling_factor < 2.0:
            print(f"    ⚠️  Moderate scaling overhead")
        else:
            print(f"    ❌ Poor scaling - investigate bottlenecks")

    return scaling_results

def generate_performance_report(results):
    """Generate a comprehensive performance report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"performance_profile_{timestamp}.json"

    report = {
        "timestamp": datetime.now().isoformat(),
        "system_info": {
            "cpu_count": psutil.cpu_count(),
            "memory_gb": psutil.virtual_memory().total / 1024 / 1024 / 1024,
            "python_version": sys.version,
            "platform": sys.platform
        },
        "results": results
    }

    # Save detailed report
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n💾 Performance report saved: {report_file}")

    # Performance summary
    print(f"\n📋 Performance Summary")
    print("=" * 30)

    if "memory" in results:
        memory_result = results["memory"]
        print(f"💾 Peak memory usage: {memory_result.get('max_memory_mb', 'N/A')} MB")

    if "cpu" in results:
        cpu_result = results["cpu"]
        print(f"⚡ Execution time: {cpu_result.get('execution_time', 'N/A')}s")

    if "io" in results:
        io_result = results["io"]
        print(f"💿 I/O throughput: {io_result.get('read_throughput', 'N/A')} MB/s")

    return report_file

def main():
    """Run comprehensive performance profiling."""
    print("⚡ AVC Parser - Performance Profiling")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python3 profile_performance.py <log_file>")
        print("\nThis utility profiles:")
        print("  • Memory usage patterns")
        print("  • CPU performance hotspots")
        print("  • I/O throughput characteristics")
        print("  • Scaling performance")
        print("\nExample:")
        print("  python3 profile_performance.py ../testAVC/multi_AVC.log")
        return

    file_path = sys.argv[1]

    # Convert to absolute path
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    print(f"🔍 Profiling: {file_path}")
    print(f"📁 Size: {os.path.getsize(file_path) / 1024 / 1024:.2f} MB")

    # Run all profiling tests
    results = {}

    print(f"\n1️⃣  Memory Profiling")
    memory_result = profile_memory_usage(file_path)
    if memory_result:
        results["memory"] = memory_result

    print(f"\n2️⃣  CPU Profiling")
    cpu_result = profile_cpu_performance(file_path)
    if cpu_result["success"]:
        results["cpu"] = cpu_result

    print(f"\n3️⃣  I/O Profiling")
    io_result = profile_io_performance(file_path)
    if io_result:
        results["io"] = io_result

    print(f"\n4️⃣  Scaling Analysis")
    scaling_result = profile_scaling_performance()
    if scaling_result:
        results["scaling"] = scaling_result

    # Generate report
    report_file = generate_performance_report(results)

    print(f"\n🎯 Optimization Recommendations:")
    print("  • Monitor memory growth for large files")
    print("  • Use appropriate buffer sizes for I/O")
    print("  • Consider streaming for very large files")
    print("  • Profile specific use cases for optimization")

if __name__ == "__main__":
    main()