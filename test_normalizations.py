#!/usr/bin/env python3
"""
Test system-independent path normalizations.

Tests the smart normalization functions to ensure edge cases are handled correctly.
"""

import sys
sys.path.insert(0, '.')

from parse_avc import normalize_path_smart, resolve_relative_path_with_cwd

def test_proc_normalization():
    """Test /proc/<pid> normalization with cross-process detection."""
    print("=" * 70)
    print("TEST 1: /proc/<pid> Normalization")
    print("=" * 70)

    # Test 1a: Process accessing its own /proc (safe to normalize)
    path, meta = normalize_path_smart("/proc/1234/fd", avc_pid=1234, tclass="file")
    print(f"\n1a. Process 1234 accessing /proc/1234/fd:")
    print(f"   Normalized: {path}")
    print(f"   Cross-process: {meta.get('cross_process_access')}")
    print(f"   Type: {meta.get('normalization_type')}")
    assert path == "/proc/<pid>/fd", f"Expected /proc/<pid>/fd, got {path}"
    assert not meta.get('cross_process_access'), "Should not be cross-process"
    print("   ✓ PASS: Correctly normalized to /proc/<pid>/fd")

    # Test 1b: Process accessing different process's /proc (SECURITY ISSUE)
    path, meta = normalize_path_smart("/proc/5678/fd", avc_pid=1234, tclass="file")
    print(f"\n1b. Process 1234 accessing /proc/5678/fd:")
    print(f"   Normalized: {path}")
    print(f"   Cross-process: {meta.get('cross_process_access')}")
    print(f"   Type: {meta.get('normalization_type')}")
    assert path == "/proc/5678/fd", f"Expected original path, got {path}"
    assert meta.get('cross_process_access'), "Should be flagged as cross-process"
    print("   ✓ PASS: Preserved original path and flagged security issue")

    # Test 1c: No PID available (conservative normalization)
    path, meta = normalize_path_smart("/proc/9999/status", avc_pid=None, tclass="file")
    print(f"\n1c. Unknown process accessing /proc/9999/status (no PID):")
    print(f"   Normalized: {path}")
    print(f"   Type: {meta.get('normalization_type')}")
    assert path == "/proc/<pid>/status", f"Expected /proc/<pid>/status, got {path}"
    print("   ✓ PASS: Normalized conservatively")

def test_pipe_socket_normalization():
    """Test pipe/socket inode stripping."""
    print("\n" + "=" * 70)
    print("TEST 2: Pipe/Socket Instance Stripping")
    print("=" * 70)

    # Test 2a: pipe with inode
    path, meta = normalize_path_smart("pipe:[12345]", tclass="fifo_file")
    print(f"\n2a. pipe:[12345] with tclass=fifo_file:")
    print(f"   Normalized: {path}")
    print(f"   Type: {meta.get('normalization_type')}")
    assert path == "fifo_file", f"Expected fifo_file, got {path}"
    print("   ✓ PASS: Normalized to tclass name")

    # Test 2b: socket with inode
    path, meta = normalize_path_smart("socket:[67890]", tclass="unix_stream_socket")
    print(f"\n2b. socket:[67890] with tclass=unix_stream_socket:")
    print(f"   Normalized: {path}")
    assert path == "unix_stream_socket", f"Expected unix_stream_socket, got {path}"
    print("   ✓ PASS: Normalized to tclass name")

    # Test 2c: anon_inode
    path, meta = normalize_path_smart("anon_inode:[eventfd]", tclass="anon_inode")
    print(f"\n2c. anon_inode:[eventfd]:")
    print(f"   Normalized: {path}")
    assert path == "anon_inode", f"Expected anon_inode, got {path}"
    print("   ✓ PASS: Normalized to tclass name")

def test_abstract_socket():
    """Test abstract UNIX socket path handling."""
    print("\n" + "=" * 70)
    print("TEST 3: Abstract Socket Handling")
    print("=" * 70)

    # Test 3a: Abstract socket with \0 prefix
    path, meta = normalize_path_smart("\0/tmp/.X11-unix/X0", tclass="unix_stream_socket")
    print(f"\n3a. Abstract socket \\0/tmp/.X11-unix/X0:")
    print(f"   Normalized: {path}")
    print(f"   Type: {meta.get('normalization_type')}")
    assert path == "@/tmp/.X11-unix/X0", f"Expected @/tmp/.X11-unix/X0, got {path}"
    print("   ✓ PASS: Converted \\0 to @")

def test_cwd_resolution():
    """Test CWD-based relative path resolution."""
    print("\n" + "=" * 70)
    print("TEST 4: CWD-Based Relative Path Resolution")
    print("=" * 70)

    # Test 4a: Relative path with CWD
    path = resolve_relative_path_with_cwd("foo.txt", "/home/user")
    print(f"\n4a. foo.txt with CWD=/home/user:")
    print(f"   Resolved: {path}")
    assert path == "/home/user/foo.txt", f"Expected /home/user/foo.txt, got {path}"
    print("   ✓ PASS: Resolved to absolute path")

    # Test 4b: Already absolute path
    path = resolve_relative_path_with_cwd("/etc/passwd", "/home/user")
    print(f"\n4b. /etc/passwd with CWD=/home/user:")
    print(f"   Resolved: {path}")
    assert path == "/etc/passwd", f"Expected /etc/passwd, got {path}"
    print("   ✓ PASS: Left absolute path unchanged")

    # Test 4c: Relative path with ../
    path = resolve_relative_path_with_cwd("../etc/foo.conf", "/home/user")
    print(f"\n4c. ../etc/foo.conf with CWD=/home/user:")
    print(f"   Resolved: {path}")
    assert path == "/home/etc/foo.conf", f"Expected /home/etc/foo.conf, got {path}"
    print("   ✓ PASS: Normalized ../ correctly")

    # Test 4d: No CWD available
    path = resolve_relative_path_with_cwd("foo.txt", None)
    print(f"\n4d. foo.txt with no CWD:")
    print(f"   Resolved: {path}")
    assert path == "foo.txt", f"Expected foo.txt, got {path}"
    print("   ✓ PASS: Left relative path as-is")

def test_edge_cases():
    """Test edge cases and boundary conditions."""
    print("\n" + "=" * 70)
    print("TEST 5: Edge Cases")
    print("=" * 70)

    # Test 5a: None/empty path
    path, meta = normalize_path_smart(None)
    print(f"\n5a. None path:")
    print(f"   Result: {path}")
    assert path is None, f"Expected None, got {path}"
    print("   ✓ PASS: Handled None correctly")

    # Test 5b: Regular file path (no normalization needed)
    path, meta = normalize_path_smart("/etc/passwd", avc_pid=1234, tclass="file")
    print(f"\n5b. /etc/passwd (regular path):")
    print(f"   Normalized: {path}")
    print(f"   Was normalized: {meta.get('normalized')}")
    assert path == "/etc/passwd", f"Expected /etc/passwd, got {path}"
    assert not meta.get('normalized'), "Should not be normalized"
    print("   ✓ PASS: Left regular path unchanged")

    # Test 5c: /proc but not /proc/PID format
    path, meta = normalize_path_smart("/proc/self/fd", avc_pid=1234)
    print(f"\n5c. /proc/self/fd:")
    print(f"   Normalized: {path}")
    assert path == "/proc/self/fd", f"Expected /proc/self/fd, got {path}"
    print("   ✓ PASS: Left /proc/self unchanged")

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("TESTING SYSTEM-INDEPENDENT PATH NORMALIZATIONS")
    print("=" * 70)

    try:
        test_proc_normalization()
        test_pipe_socket_normalization()
        test_abstract_socket()
        test_cwd_resolution()
        test_edge_cases()

        print("\n" + "=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)
        print("\nPath normalizations are working correctly!")
        print("Security-critical edge cases are properly handled.")

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
