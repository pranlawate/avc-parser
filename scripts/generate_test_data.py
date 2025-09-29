#!/usr/bin/env python3
"""
Test Data Generation Utility

This script generates synthetic audit log data for testing parser functionality,
performance benchmarking, and edge case validation.
"""

import random
import time
import os
import sys
from datetime import datetime, timedelta

class AuditLogGenerator:
    """Generates realistic audit log entries for testing."""

    def __init__(self):
        # Common SELinux contexts
        self.source_contexts = [
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
            "system_u:system_r:httpd_t:s0",
            "system_u:system_r:sshd_t:s0-s0:c0.c1023",
            "system_u:system_r:kernel_t:s0",
            "unconfined_u:unconfined_r:chrome_sandbox_t:s0",
            "system_u:system_r:NetworkManager_t:s0",
            "system_u:system_r:postfix_master_t:s0",
            "unconfined_u:unconfined_r:container_t:s0:c123,c456"
        ]

        self.target_contexts = [
            "system_u:object_r:etc_t:s0",
            "system_u:object_r:var_log_t:s0",
            "unconfined_u:object_r:user_home_t:s0",
            "system_u:object_r:httpd_config_t:s0",
            "system_u:object_r:passwd_file_t:s0",
            "system_u:object_r:admin_home_t:s0",
            "system_u:object_r:container_file_t:s0:c123,c456",
            "system_u:object_r:tmp_t:s0"
        ]

        # Common processes
        self.processes = [
            "httpd", "sshd", "systemd", "chrome", "firefox", "postfix",
            "nginx", "docker", "containerd", "mysqld", "postgres",
            "NetworkManager", "gdm", "pulseaudio", "bash", "python3"
        ]

        # Object classes and permissions
        self.object_classes = {
            "file": ["read", "write", "open", "getattr", "execute"],
            "dir": ["read", "write", "add_name", "remove_name", "search"],
            "tcp_socket": ["bind", "listen", "accept", "connect"],
            "unix_stream_socket": ["connect", "read", "write"],
            "process": ["signal", "ptrace", "getsched", "setsched"],
            "capability": ["dac_override", "sys_admin", "net_admin"],
            "filesystem": ["mount", "unmount", "getattr"]
        }

        # Common paths
        self.paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/resolv.conf",
            "/var/log/audit/audit.log", "/var/log/messages", "/var/www/html/index.html",
            "/home/user/.bashrc", "/home/user/Documents/file.txt", "/tmp/tmpfile",
            "/usr/bin/python3", "/usr/sbin/httpd", "/usr/lib64/libc.so.6",
            "/dev/null", "/dev/urandom", "/proc/meminfo", "/sys/class/net/eth0",
            "/containers/storage/overlay/abc123/merged/etc/passwd",
            "/var/lib/docker/containers/def456/config.json",
            "/opt/app/config.ini", "/srv/data/database.db"
        ]

        # Hostnames for multi-system logs
        self.hostnames = ["web01", "db02", "app03", "proxy04", "worker05"]

    def generate_timestamp(self, base_time=None, format_type="unix"):
        """Generate timestamp in various formats."""
        if base_time is None:
            base_time = datetime.now()

        # Add some random variance
        variance = timedelta(seconds=random.randint(-3600, 3600))
        timestamp = base_time + variance

        if format_type == "unix":
            unix_time = timestamp.timestamp()
            serial = random.randint(1000, 9999)
            return f"audit({unix_time:.3f}:{serial})"
        elif format_type == "iso":
            return timestamp.isoformat()
        elif format_type == "human":
            return timestamp.strftime("%b %d %H:%M:%S")

        return str(timestamp)

    def generate_avc_denial(self, event_id=None, hostname=None, timestamp_format="unix"):
        """Generate a realistic AVC denial record."""
        if event_id is None:
            event_id = self.generate_timestamp(format_type=timestamp_format)

        if hostname is None:
            hostname = random.choice(self.hostnames)

        # Pick random contexts and process
        scontext = random.choice(self.source_contexts)
        tcontext = random.choice(self.target_contexts)
        comm = random.choice(self.processes)
        tclass = random.choice(list(self.object_classes.keys()))
        permissions = random.sample(self.object_classes[tclass],
                                   random.randint(1, min(3, len(self.object_classes[tclass]))))

        # Optional fields
        path = random.choice(self.paths) if random.random() > 0.3 else None
        pid = random.randint(1000, 65535)
        uid = random.randint(0, 1000)

        # Build the AVC record
        parts = [
            f"type=AVC",
            f"msg={event_id}",
            f"avc: denied",
            f"{{ {' '.join(permissions)} }}",
            f"for pid={pid}",
            f"comm=\"{comm}\"",
        ]

        if path:
            parts.append(f"path=\"{path}\"")

        parts.extend([
            f"dev=\"dm-0\"",
            f"ino={random.randint(100000, 999999)}",
            f"scontext={scontext}",
            f"tcontext={tcontext}",
            f"tclass={tclass}",
            f"permissive={random.choice([0, 0, 0, 1])}"  # Mostly enforcing
        ])

        # Add hostname prefix sometimes
        if random.random() > 0.7:
            return f"node={hostname} {' '.join(parts)}"
        else:
            return ' '.join(parts)

    def generate_syscall_record(self, event_id, uid=None, pid=None):
        """Generate a corresponding SYSCALL record."""
        if uid is None:
            uid = random.randint(0, 1000)
        if pid is None:
            pid = random.randint(1000, 65535)

        syscalls = ["openat", "read", "write", "connect", "bind", "execve", "clone"]
        syscall = random.choice(syscalls)

        return (f"type=SYSCALL msg={event_id} arch=c000003e syscall={random.randint(0, 400)} "
                f"success=no exit=-13 a0=ffffff9c a1=7f8b8c0 a2=0 a3=0 items=1 ppid={pid-1} "
                f"pid={pid} auid={uid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} "
                f"egid={uid} sgid={uid} fsgid={uid} tty=pts0 ses=1 comm=\"{random.choice(self.processes)}\" "
                f"exe=\"/usr/bin/{random.choice(self.processes)}\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)")

    def generate_path_record(self, event_id, path=None):
        """Generate a PATH record."""
        if path is None:
            path = random.choice(self.paths)

        return (f"type=PATH msg={event_id} item=0 name=\"{path}\" inode={random.randint(100000, 999999)} "
                f"dev=fd:00 mode=0100644 ouid={random.randint(0, 1000)} ogid={random.randint(0, 1000)} "
                f"rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0")

    def generate_log_block(self, num_denials=1, include_syscall=True, include_path=True, timestamp_format="unix"):
        """Generate a complete log block with related records."""
        base_time = datetime.now() - timedelta(hours=random.randint(0, 24))
        records = []

        for _ in range(num_denials):
            event_id = self.generate_timestamp(base_time, timestamp_format)

            # AVC denial
            avc_record = self.generate_avc_denial(event_id, timestamp_format=timestamp_format)
            records.append(avc_record)

            # Related records
            if include_syscall and random.random() > 0.3:
                records.append(self.generate_syscall_record(event_id))

            if include_path and random.random() > 0.5:
                records.append(self.generate_path_record(event_id))

        return '\n'.join(records)

def generate_test_file(filename, num_denials=100, file_type="mixed", complexity="medium"):
    """Generate a test file with specified characteristics."""
    print(f"🔨 Generating test file: {filename}")
    print(f"  • Denials: {num_denials}")
    print(f"  • Type: {file_type}")
    print(f"  • Complexity: {complexity}")

    generator = AuditLogGenerator()

    with open(filename, 'w') as f:
        for i in range(num_denials):
            if file_type == "avc_only":
                # Just AVC records
                record = generator.generate_avc_denial()
                f.write(record + '\n')

            elif file_type == "raw_audit":
                # Full audit log with multiple record types
                if complexity == "simple":
                    block = generator.generate_log_block(num_denials=1, include_syscall=False, include_path=False)
                elif complexity == "complex":
                    block = generator.generate_log_block(num_denials=random.randint(1, 3), include_syscall=True, include_path=True)
                else:  # medium
                    block = generator.generate_log_block(num_denials=1, include_syscall=True, include_path=random.random() > 0.5)

                f.write(block + '\n\n')

            elif file_type == "mixed":
                # Mix of formats
                if random.random() > 0.7:
                    block = generator.generate_log_block(num_denials=random.randint(1, 2))
                    f.write(block + '\n\n')
                else:
                    record = generator.generate_avc_denial()
                    f.write(record + '\n')

            # Add some noise occasionally
            if complexity == "complex" and random.random() > 0.9:
                noise_records = [
                    "type=USER_AUTH msg=audit(1234567890.123:4567): pid=1234 uid=0 auid=0 ses=1 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=192.168.1.100 addr=192.168.1.100 terminal=ssh res=success'",
                    "type=CRED_ACQ msg=audit(1234567890.124:4568): pid=1234 uid=0 auid=0 ses=1 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=192.168.1.100 addr=192.168.1.100 terminal=ssh res=success'",
                    "type=LOGIN msg=audit(1234567890.125:4569): pid=1234 uid=0 old_auid=4294967295 auid=0 ses=1 msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=192.168.1.100 addr=192.168.1.100 terminal=ssh res=success'"
                ]
                f.write(random.choice(noise_records) + '\n')

    print(f"✅ Generated {filename} ({os.path.getsize(filename)} bytes)")

def generate_edge_case_file(filename):
    """Generate a file with edge cases and problematic content."""
    print(f"🔨 Generating edge case file: {filename}")

    generator = AuditLogGenerator()

    with open(filename, 'w') as f:
        # Normal records first
        for _ in range(10):
            f.write(generator.generate_avc_denial() + '\n')

        # Edge cases
        edge_cases = [
            # Very long line
            "type=AVC msg=audit(1234567890.123:1234): avc: denied { read } for pid=1234 comm=\"very_long_process_name_that_exceeds_normal_limits_and_might_cause_parsing_issues\" path=\"" + "/very/long/path" * 50 + "/file.txt\" dev=\"dm-0\" ino=123456 scontext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0",

            # Missing fields
            "type=AVC msg=audit(1234567890.124:1235): avc: denied { write } for pid=1235 comm=\"incomplete\"",

            # Malformed timestamp
            "type=AVC msg=malformed_timestamp: avc: denied { read } for pid=1236 comm=\"test\" scontext=test tcontext=test tclass=file permissive=0",

            # Unicode characters
            "type=AVC msg=audit(1234567890.125:1237): avc: denied { read } for pid=1237 comm=\"tëst\" path=\"/tmp/fïlé.txt\" scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0",

            # Empty lines and whitespace
            "",
            "   ",
            "\t\t",

            # Very short line
            "avc:",

            # Line with control characters
            "type=AVC msg=audit(1234567890.126:1238): avc: denied { read } for pid=1238 comm=\"ctrl\x00char\" path=\"/tmp/test.txt\" scontext=test tcontext=test tclass=file permissive=0"
        ]

        for case in edge_cases:
            f.write(case + '\n')

        # More normal records
        for _ in range(10):
            f.write(generator.generate_avc_denial() + '\n')

    print(f"✅ Generated edge case file: {filename}")

def generate_performance_test_file(filename, target_size_mb=10):
    """Generate a large file for performance testing."""
    print(f"🔨 Generating performance test file: {filename} (target: {target_size_mb} MB)")

    generator = AuditLogGenerator()
    target_size = target_size_mb * 1024 * 1024  # Convert to bytes
    current_size = 0

    with open(filename, 'w') as f:
        denial_count = 0
        while current_size < target_size:
            block = generator.generate_log_block(
                num_denials=random.randint(1, 3),
                include_syscall=True,
                include_path=True
            )
            f.write(block + '\n\n')

            current_size = f.tell()
            denial_count += 1

            # Progress indicator
            if denial_count % 1000 == 0:
                progress = (current_size / target_size) * 100
                print(f"  Progress: {progress:.1f}% ({current_size / 1024 / 1024:.1f} MB)")

    actual_size = os.path.getsize(filename) / 1024 / 1024
    print(f"✅ Generated {filename} ({actual_size:.1f} MB, {denial_count} denial blocks)")

def main():
    """Generate various test data files."""
    print("🧪 Test Data Generation Utility")
    print("=" * 40)

    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python3 generate_test_data.py [options]")
        print("\nOptions:")
        print("  --help          Show this help message")
        print("  --small         Generate small test files")
        print("  --large         Generate large performance test files")
        print("  --edge-cases    Generate edge case test files")
        print("  --all           Generate all types of test files")
        print("\nDefault: Generate basic test files")
        return

    # Create test data directory
    test_dir = "generated_test_data"
    os.makedirs(test_dir, exist_ok=True)
    os.chdir(test_dir)

    generate_all = "--all" in sys.argv
    generate_large = "--large" in sys.argv or generate_all
    generate_edge = "--edge-cases" in sys.argv or generate_all
    generate_small = "--small" in sys.argv or generate_all or len(sys.argv) == 1

    if generate_small:
        print("\n📋 Generating basic test files...")
        generate_test_file("simple_avc.log", num_denials=50, file_type="avc_only", complexity="simple")
        generate_test_file("medium_audit.log", num_denials=100, file_type="raw_audit", complexity="medium")
        generate_test_file("complex_mixed.log", num_denials=200, file_type="mixed", complexity="complex")

    if generate_edge:
        print("\n⚠️  Generating edge case files...")
        generate_edge_case_file("edge_cases.log")

    if generate_large:
        print("\n🚀 Generating performance test files...")
        generate_performance_test_file("performance_1mb.log", target_size_mb=1)
        generate_performance_test_file("performance_10mb.log", target_size_mb=10)

    print(f"\n✅ Test data generation completed!")
    print(f"📁 Files generated in: {os.path.abspath('.')}")
    print("\n🎯 Usage tips:")
    print("  • Use simple_avc.log for basic parser testing")
    print("  • Use edge_cases.log to test error handling")
    print("  • Use performance_*.log files for benchmarking")
    print("  • Test with different --report formats")

if __name__ == "__main__":
    main()