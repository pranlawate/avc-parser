# avc-parser

SELinux AVC denial parser and analyzer with MLS/MCS security level analysis, intelligent deduplication, key findings detection, and multiple output formats.

Parses AVC denial messages from `/var/log/audit/audit.log` with full support for extended audit records (SYSCALL, PATH, CWD, PROCTITLE, EXECVE, SOCKADDR). Transforms thousands of raw denials into actionable groups with automatic detection of labeling issues, boot-blocking denials, and relabeling failures.

## Installation

### Recommended: COPR (Fedora 42/43)

```bash
sudo dnf copr enable pranlawate/selinux-tools
sudo dnf install avc-parser
```

### From source

```bash
git clone https://github.com/pranlawate/avc-parser.git
cd avc-parser
pip install -e .
```

## Usage

```bash
# Parse audit log (auto-detects format)
avc-parser -f /var/log/audit/audit.log

# Output formats
avc-parser -f /var/log/audit/audit.log --format brief     # Executive summary
avc-parser -f /var/log/audit/audit.log --format sealert   # Technical analysis
avc-parser -f /var/log/audit/audit.log --format stats     # Quick overview
avc-parser -f /var/log/audit/audit.log --json              # JSON for automation

# Filtering
avc-parser -f /var/log/audit/audit.log --process httpd
avc-parser -f /var/log/audit/audit.log --source init_t,kmod_t,mount_t
avc-parser -f /var/log/audit/audit.log --mls               # MLS-related only
avc-parser -f /var/log/audit/audit.log --since yesterday
```

## Key Features

- **Smart Deduplication**: Groups denials by remediation pattern. 10,000 raw denials become 20 actionable groups.
- **MLS/MCS Analysis**: Parses security levels, detects sensitivity mismatches, explains Bell-LaPadula rules (No Read Up, No Write Down), distinguishes clearance from effective level.
- **Key Findings Engine**: Automatically detects labeling breakdowns (unlabeled_t), relabeling tool failures, boot-blocking denials, systemic patterns, and denial recurrence across reboots.
- **Remediation Classification**: Each denial group classified as relabel-fixable, broken labeling source, or policy issue.
- **Multiple Formats**: Rich terminal UI, field-by-field facts, executive brief, technical sealert, statistics, and normalized JSON.
- **Flexible Filtering**: By process, path, source/target context, time range, MLS mismatches. Comma-separated values for OR matching.
- **Policy Investigation**: Auto-generated `sesearch` commands for each denial group.

## How This Differs from sealert/setroubleshoot

| setroubleshoot/sealert | avc-parser |
|---|---|
| Real-time monitoring | Post-incident forensic analysis |
| Live audit socket | Static file analysis (including sosreport logs) |
| Policy suggestions | Denial grouping, correlation, and key findings |
| Daemon-based | Single standalone tool |

Use avc-parser when you need forensic analysis of audit logs from systems you can't access directly, or when setroubleshoot output becomes overwhelming during incident response.

## Part of the SELinux Tool Suite

avc-parser works alongside [sepgen](https://github.com/pranlawate/sepgen)
(policy generator) and [semacro](https://github.com/pranlawate/semacro)
(macro explorer) for a complete SELinux policy development workflow:

```bash
sepgen analyze ./src/ --name myapp    # Generate policy from source
sepgen trace /usr/bin/myapp           # Observe runtime behavior
sepgen refine --name myapp            # Fix denials (uses avc-parser)
semacro which myapp_t target_t read   # Find the right macro
```

Install the complete suite:
```bash
sudo dnf copr enable pranlawate/selinux-tools
sudo dnf install sepgen semacro avc-parser
```

## Documentation

- [Examples & Usage Patterns](docs/EXAMPLES.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Deduplication Algorithm](docs/DEDUPLICATION_ALGORITHM.md)
- [Changelog](docs/CHANGELOG.md)
- [Feature Decisions & Backlog](docs/FEATURE_DECISIONS.md)

## Contributing

- Bug Reports: Open an issue with reproduction steps and audit log samples
- Feature Requests: Check [Feature Decisions](docs/FEATURE_DECISIONS.md) for scope alignment
- Pull Requests: Follow existing code style and include tests
- Development: Use `make help` for available development commands

## License

MIT License — see [LICENSE](LICENSE)

## Author

Pranav Lawate
