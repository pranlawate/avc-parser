# Architecture

Clean modular design with pipeline architecture: parse, deduplicate, analyze, filter, format.

```
avc-parser/
├── parse_avc.py              # Core: CLI, parsing, aggregation, display orchestration
├── config/                   # Configuration constants and regex patterns
│   └── constants.py
├── validators/              # Input validation and file handling
│   └── file_validator.py
├── avc_selinux/             # SELinux domain model
│   ├── context.py           # AvcContext: parses user:role:type:mls contexts
│   └── mls.py               # MLS/MCS: level parsing, dominance, Bell-LaPadula analysis
├── analyzers/               # Key findings analysis engine
│   ├── findings.py          # Finding data model and severity levels
│   ├── labeling.py          # Unlabeled files and MLS labeling inconsistency
│   ├── relabeling.py        # Relabeling tool failure detection
│   ├── boot_impact.py       # Boot-blocking denial detection
│   ├── patterns.py          # Systemic pattern detection
│   └── recurrence.py        # Denial recurrence across policy reloads
├── detectors/               # Per-denial anomaly flags
│   └── anomaly_detector.py  # Permissive mode, dontaudit, container, custom paths
├── formatters/              # Output formatting
│   ├── json_formatter.py    # JSON for SIEM/automation
│   ├── report_formatter.py  # Brief (executive) and sealert (technical) reports
│   └── stats_formatter.py   # Summary statistics
├── utils/                   # Shared utilities
│   ├── file_utils.py        # File format detection
│   ├── selinux_utils.py     # sesearch command generation
│   ├── pattern_utils.py     # Path and context matching
│   ├── sort_utils.py        # Denial sorting
│   ├── time_utils.py        # Time range parsing
│   └── legacy.py            # BIONIC text, display helpers
├── tests/                   # 249 tests
├── completions/             # Bash/zsh tab completion
├── examples/                # Integration examples (SIEM, batch, security reports)
└── scripts/                 # Dev utilities (test runner, profiler, log validator)
```

## Pipeline

```
Input → Validate → Parse → Correlate → Deduplicate → Sort → Analyze → Filter → Format
```

1. **Input**: Auto-detect raw audit.log vs ausearch output
2. **Parse**: Extract AVC/SYSCALL/PATH/CWD/PROCTITLE/EXECVE/SOCKADDR records, merge shared context
3. **Deduplicate**: Smart signatures group by remediation pattern (process category, target context, object group, path pattern, permission category)
4. **Analyze**: Key findings engine detects labeling issues, relabeling failures, boot-blocking denials, systemic patterns, recurrence
5. **Filter**: --process, --source, --target, --path, --since/--until, --mls (comma-separated OR supported)
6. **Format**: --format rich|facts|stats|json|brief|sealert

## Key Design Decisions

- **Analyzers vs Detectors**: Detectors check individual denials (permissive? container path?). Analyzers scan all denials for cross-group patterns (systemic labeling issue? boot-blocking?).
- **Smart signatures**: Group denials by remediation pattern, not exact fields. 10,000 raw denials become 20 actionable groups.
- **MLS handling**: Parse into structured MlsLevel/MlsRange (mirrors libsepol). None for missing MLS (data fidelity over convenience).
- **Filters before formatters**: All filters run before any output format, so --mls works with --format json.
