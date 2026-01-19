# SELinux AVC Denial Analyzer

**Version 1.8.1** | A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication, two-tier professional report system, SELinux policy investigation integration, extended audit record support (FANOTIFY, SELINUX_ERR, MAC_POLICY_LOAD), context-aware analysis, smart path normalization with security awareness, exit code translation, advanced filtering capabilities, and normalized JSON output.

## ⚡ Quick Start

```bash
# Clone and setup
git clone https://github.com/pranlawate/avc-parser.git
cd avc-parser
pip3 install rich
make install-wrapper  # Optional: Install wrapper for easy access

# === BASIC USAGE ===
# Analyze audit logs (auto-detects format)
avc-parser --file /var/log/audit/audit.log
# Or without wrapper: python3 parse_avc.py --file /var/log/audit/audit.log

# === DISPLAY MODES ===
# Enhanced detailed analysis with per-PID breakdowns
avc-parser --file /var/log/audit/audit.log --detailed

# Field-by-field technical deep-dive
avc-parser --file /var/log/audit/audit.log --fields

# Report formats for different audiences
avc-parser --file /var/log/audit/audit.log --report        # Brief (executive summaries)
avc-parser --file /var/log/audit/audit.log --report sealert # Technical analysis

# JSON export for automation/SIEM
avc-parser --file /var/log/audit/audit.log --json

# === FILTERING OPTIONS ===
# Filter by process name
avc-parser --file /var/log/audit/audit.log --process httpd

# Filter by path with wildcards
avc-parser --file /var/log/audit/audit.log --path "/var/www/*"

# Filter by time range
avc-parser --file /var/log/audit/audit.log --since yesterday --until today
avc-parser --file /var/log/audit/audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00"

# Filter by SELinux context
avc-parser --file /var/log/audit/audit.log --source httpd_t --target "*default*"

# === SORTING OPTIONS ===
# Sort by frequency (most common first)
avc-parser --file /var/log/audit/audit.log --sort count

# Sort chronologically
avc-parser --file /var/log/audit/audit.log --sort chrono

# === ADVANCED OPTIONS ===
# Interactive pager for large outputs
avc-parser --file /var/log/audit/audit.log --pager

# === OUTPUT FEATURES ===
# Example: Auto-generated policy investigation commands
# ╭──────────────── Policy Investigation Command ────────────────╮
# │    sesearch -A -s httpd_t -t default_t -c file -p read,write  │
# ╰────────────────────────────────────────────────────────────────╯
#
# Example: PID event counts in denial summaries
# • PID 1234 (3x) (httpd) - 3 events from this PID
# • PID 5678 (nginx) - 1 event (no count shown)
```

## 🎯 Purpose

**Post-incident SELinux audit log forensic analysis** for security analysts, system administrators, and compliance auditors.

### 🔄 How This Differs from sealert/setroubleshoot

| **setroubleshoot/sealert** | **AVC Denial Analyzer** |
|---------------------------|-------------------------|
| Real-time monitoring & policy suggestions | Post-incident log analysis & correlation |
| Live audit socket processing | Static file analysis |
| Policy recommendations | Clear denial summaries |
| Daemon-based setup | Single standalone script |

**Use this tool when**: You need forensic analysis of audit logs from systems you can't access directly, or when setroubleshoot's real-time output becomes overwhelming during incident response.

## ✅ Key Features

### 🎨 **Professional Display Modes**
- **Rich Terminal Format** (default): Responsive panels with BIONIC reading and professional styling
  - Compatible with: `--detailed` (enhanced correlation), `--pager` (interactive navigation)
- **Report Formats** (`--report [format]`): Professional text formats for different audiences
  - `--report` or `--report brief`: Executive summaries for incident reports and management briefings
  - `--report sealert`: Technical analysis format with comprehensive forensic details
  - Compatible with: `--pager` only (standalone formats optimized for specific use cases)
- **Technical Analysis** (`--fields`): Field-by-field breakdown for deep-dive technical analysis
  - Compatible with: `--pager` only (standalone format for detailed investigation)
- **Machine Integration** (`--json`): Normalized structured output for automation and SIEM integration
  - Compatible with: All filtering options (works independently of display preferences)

**Display Precedence**: `--json` > `--fields` > `--report [format]` > Rich (default)

### 🔍 **Advanced Analysis**
- **Semantic Intelligence**: Human-readable permissions (`read` → `Read file content`) and contextual analysis
- **Smart Deduplication**: SELinux remediation-aware grouping that properly distinguishes services while grouping related permissions for optimal `semanage` command correlation
- **Policy Investigation Commands**: Auto-generated `sesearch` commands for each denial group with copy-paste workflow integration
- **Grouping Validation**: Efficiency analysis detecting when denial groups share identical policy queries for optimization insights
- **Correlation Tracking**: Individual PID-to-resource mappings solve deduplication information loss
- **PID Event Counting**: Shows event frequency per PID in compact view (e.g., `PID 1234 (3x)`) for better correlation understanding
- **Enhanced Path Resolution**: Sophisticated PATH record matching (based on setroubleshoot) with dev+inode fallback for complex scenarios
- **Smart Path Normalization**: Security-aware normalization removes ephemeral data while preserving critical information
  - `/proc/<pid>` normalization with cross-process access detection (flags security issues instead of hiding them)
  - Pipe/socket instance stripping (`pipe:[12345]` → `pipe`) for better deduplication
  - Abstract socket display convention (`\0path` → `@path`) for readability
  - CWD-based relative path resolution for accurate absolute paths
  - System-independent (no filesystem access, works on any platform)
- **dontaudit Detection**: Automatic detection of disabled dontaudit rules using permission indicators
- **Advanced Filtering**: Comprehensive filtering by process, path, time range, and SELinux contexts (`--process`, `--path`, `--since`, `--until`, `--source`, `--target`)
- **Time Range Analysis**: Flexible time specifications from relative keywords (`yesterday`) to specific timestamps (`2025-01-15 14:30`)
- **Context Pattern Matching**: Intelligent SELinux context filtering with wildcard support and component-level matching
- **Flexible Sorting**: Multiple sort orders - recent, count-based, or chronological (`--sort`)

### 📥 **Flexible Input**
- **Auto-Detection**: Single `--file` flag automatically detects raw audit.log vs pre-processed format
- **Multiple Sources**: Raw audit.log, ausearch output, or interactive paste input
- **Robust Parsing**: Multi-line audit blocks (`AVC`, `USER_AVC`, `FANOTIFY`, `SELINUX_ERR`, `USER_SELINUX_ERR`, `MAC_POLICY_LOAD`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, `SOCKADDR`)
- **Comprehensive Validation**: File type, permissions, and content validation with helpful error messages

### 📖 **BIONIC Reading Format**
- **Enhanced Readability**: Strategic text formatting emphasizes key letter groups for improved scanning speed
- **Smart Application**: Applied to natural language text while preserving technical data clarity
- **Professional Appearance**: Maintains color harmony and visual consistency throughout the display

📊 **Development Plans**: See [ROADMAP.md](ROADMAP.md) for future plans and [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for implementation details.

🎯 **Current Status (v1.8.1)**: Production-ready with setroubleshoot-based optimizations (smart path normalization, exit code translation), clean modular architecture, modern development tooling, extended audit record support, enhanced forensic analysis capabilities, and convenient wrapper installation system. Python 3.9+ compatible. Next phase: CI/CD automation and performance benchmarking.

## 🏗️ Architecture

**Clean Modular Design** with completed architectural refactoring (Phase 9A ✅):

```
avc-parser/
├── parse_avc.py              # Core application
├── config/                   # Configuration management
│   ├── constants.py         # Audit patterns, size limits, analysis settings
│   └── __init__.py
├── validators/              # Input validation and file handling
│   ├── file_validator.py    # File validation, argument checking, auto-detection
│   └── __init__.py
├── formatters/              # Output formatting and data serialization
│   ├── json_formatter.py    # JSON output, field normalization, SIEM integration
│   ├── report_formatter.py  # Report display formatting (brief/sealert)
│   └── __init__.py
├── detectors/               # Anomaly detection and analysis
│   ├── anomaly_detector.py  # Permissive mode, dontaudit, container, custom paths
│   └── __init__.py
├── utils/                   # Utility functions and helpers
│   ├── file_utils.py        # File format detection
│   ├── time_utils.py        # Time parsing and formatting
│   ├── pattern_utils.py     # Pattern matching utilities
│   ├── sort_utils.py        # Sorting utilities
│   ├── selinux_utils.py     # SELinux command generation
│   ├── legacy.py            # Legacy display and helper functions
│   └── __init__.py
├── selinux/                 # SELinux analysis and context parsing
│   ├── context.py          # AvcContext class and semantic analysis
│   └── __init__.py
├── docs/                    # Documentation
│   ├── README.md           # Project documentation
│   ├── ROADMAP.md          # Development roadmap
│   ├── CHANGELOG.md        # Version history
│   ├── FEATURE_DECISIONS.md # Implementation decisions
│   ├── EXAMPLES.md         # Command-line usage examples
│   └── CLI_REFERENCE.md    # Complete command reference
├── examples/                # Executable integration examples
│   ├── basic_analysis.py   # Quick start demonstration
│   ├── json_integration.py # SIEM integration patterns
│   ├── batch_processing.py # Multi-file processing workflows
│   ├── security_report.py  # Custom security reporting
│   ├── performance_test.py # Performance benchmarking
│   └── README.md           # Examples guide
├── scripts/                 # Development and utility scripts
│   ├── run_tests.py        # Test runner script
│   ├── validate_logs.py    # Log file validation utility
│   ├── generate_test_data.py # Synthetic test data generator
│   ├── profile_performance.py # Performance profiling tool
│   └── README.md           # Scripts documentation
├── tests/                   # Comprehensive test suite (169 tests)
│   ├── test_*.py           # Feature-specific test modules
│   └── testAVC/, testRAW/  # Sample audit logs and test fixtures
└── pyproject.toml          # Modern Python project configuration
    ├── Project metadata and dependencies
    ├── Development tooling (ruff, pytest, coverage)
    └── Quality assurance settings
```

**Architecture Benefits**:
- **Clean Modular Design**: Logical separation into 6 modules (config, validators, formatters, utils, detectors, selinux)
- **Comprehensive Test Suite**: 169 tests covering core parsing, validation, and integration workflows (100% pass rate)
- **Enhanced Maintainability**: Clear separation of concerns with focused modules
- **Modern Development Tooling**: Ruff linting/formatting, pytest framework, coverage reporting
- **Developer Experience**: Comprehensive examples, utilities, and development tools
- **Integration Ready**: SIEM patterns, batch processing, and performance tools included
- **Quality Assurance**: Automated testing, log validation, profiling utilities

## 🚀 Quick Start

### **Validate Your Logs**
```bash
# Check if your log file will work well
python3 scripts/validate_logs.py /var/log/audit/audit.log
```

### **Basic Usage**
```bash
# Analyze denials with rich output
avc-parser --file /var/log/audit/audit.log

# Generate JSON for SIEM integration
avc-parser --file /var/log/audit/audit.log --json

# Create security report
avc-parser --file /var/log/audit/audit.log --report brief
```

**Note:** Replace `avc-parser` with `python3 parse_avc.py` if you didn't install the wrapper.

📖 **For comprehensive usage examples, see [EXAMPLES.md](EXAMPLES.md)**

## Prerequisites

- Python 3.8+
- Python Rich library (`rich>=10.0.0`)
- `audit` package (for `ausearch`): Usually pre-installed on most systems
- `make` (optional, for wrapper installation)

## Installation

1. **Clone the Repository**:
   ```bash
   # Using HTTPS
   git clone https://github.com/pranlawate/avc-parser.git

   # Using SSH
   git clone git@github.com:pranlawate/avc-parser.git
   ```

2. **Install Dependencies**:
   ```bash
   cd avc-parser
   pip3 install rich
   sudo dnf install audit  # If needed (Fedora/RHEL)
   sudo apt install auditd  # If needed (Ubuntu/Debian)
   ```

3. **Optional: Install Wrapper for Easy Access** (Recommended):
   ```bash
   # Interactive installation - choose between /usr/local/bin or ~/bin
   make install-wrapper

   # Now you can run from anywhere as:
   avc-parser --file /var/log/audit/audit.log
   ```

   **Without make:**
   ```bash
   # Manual installation to ~/bin (no sudo required)
   # Note: Run these commands from within the avc-parser directory
   mkdir -p ~/bin
   cat > ~/bin/avc-parser << EOF
   #!/bin/bash
   exec python3 $(pwd)/parse_avc.py "\$@"
   EOF
   chmod +x ~/bin/avc-parser

   # Ensure ~/bin is in your PATH (add to ~/.bashrc if needed)
   export PATH="$HOME/bin:$PATH"
   ```

## 🚀 Usage

**Note:** If you installed the wrapper, replace `python3 parse_avc.py` with `avc-parser` in all commands below.

### **Recommended: Auto-Detection** ✨
Single flag automatically detects file format (raw audit.log vs pre-processed):
```bash
# With wrapper
avc-parser --file /var/log/audit/audit.log

# Without wrapper
python3 parse_avc.py --file /var/log/audit/audit.log
```

### **Alternative Methods:**

**Raw Audit File Processing:**
```bash
avc-parser --raw-file /var/log/audit/audit.log
```

**Pre-processed AVC File:**
```bash
# Create AVC file:
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR,MAC_POLICY_LOAD -ts recent > avc_denials.log
# Parse it:
avc-parser --avc-file avc_denials.log
```

**Interactive Mode:**
```bash
avc-parser
# Paste logs and press Ctrl+D (Linux/macOS) or Ctrl+Z+Enter (Windows)
```

### **Display Modes:**

**Rich Terminal Format** (default): Professional panels with correlation events
```bash
avc-parser --file /var/log/audit/audit.log
avc-parser --file /var/log/audit/audit.log --detailed  # Enhanced with per-PID breakdowns
```

**Report Formats**: Professional text formats for different audiences
```bash
avc-parser --file /var/log/audit/audit.log --report        # Brief format (executive summaries)
avc-parser --file /var/log/audit/audit.log --report brief  # Brief format (explicit)
avc-parser --file /var/log/audit/audit.log --report sealert # Technical analysis format
```

**Technical Analysis**: Field-by-field breakdown for deep investigation
```bash
avc-parser --file /var/log/audit/audit.log --fields
```

**Machine Integration**: Structured output for automation and SIEM
```bash
avc-parser --file /var/log/audit/audit.log --json
# Output includes: "sesearch_command": "sesearch -A -s httpd_t -t default_t -c file -p read,write"
```

### **Filtering Options:**

**Process Filtering**: Focus on specific services
```bash
avc-parser --file /var/log/audit/audit.log --process httpd
```

**Path Filtering**: Target specific file paths with wildcards
```bash
avc-parser --file /var/log/audit/audit.log --path "/var/www/*"
```

**Time Range Filtering**: Analyze specific time windows
```bash
avc-parser --file /var/log/audit/audit.log --since yesterday --until today
avc-parser --file /var/log/audit/audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00"
```

**SELinux Context Filtering**: Filter by source/target contexts
```bash
avc-parser --file /var/log/audit/audit.log --source httpd_t
avc-parser --file /var/log/audit/audit.log --target "*default*"
```

### **Sorting Options:**

```bash
avc-parser --file /var/log/audit/audit.log --sort recent  # Most recent first (default)
avc-parser --file /var/log/audit/audit.log --sort count   # Most frequent first
avc-parser --file /var/log/audit/audit.log --sort chrono  # Chronological order
```

### **Advanced Options:**

**Interactive Pager**: Navigate large outputs easily
```bash
avc-parser --file /var/log/audit/audit.log --pager
```


📚 **For more information:**
- [EXAMPLES.md](EXAMPLES.md) - Real-world usage patterns and workflows
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Complete command reference and troubleshooting


## 📊 Project Status

**Production-ready SELinux AVC denial forensic analysis tool**

**Core Features**: ✅ Complete  
- Smart deduplication with SELinux policy investigation integration
- Rich terminal display with professional formatting  
- Comprehensive filtering (time, process, path, context)
- JSON export with structured output

**Quality Assurance**: ✅ Complete
- 169 comprehensive tests with regression prevention
- Modern development tooling (ruff, pytest, coverage)
- Modular architecture for maintainability
- Cross-platform compatibility

**📚 Documentation**: [EXAMPLES.md](EXAMPLES.md) | [CLI_REFERENCE.md](CLI_REFERENCE.md) | [ROADMAP.md](ROADMAP.md)

## 🤝 Contributing

Contributions are welcome! Please see our development roadmap and feature decisions for current priorities:
- 🐛 **Bug Reports**: Open an issue with reproduction steps
- 💡 **Feature Requests**: Check [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for scope alignment
- 🔧 **Pull Requests**: Follow existing code style and include tests
- 🛠️ **Development**: Use `make help` for available development commands

## 📄 License

**MIT License** - This project is open source and free to use. See the repository for full license details.

## 🆘 Support

- **Questions**: Open a GitHub issue for usage questions
- **Bug Reports**: Include log samples and error messages
- **Feature Requests**: Check our roadmap before submitting

---

**SELinux AVC Denial Analyzer v1.8.1** | Made for forensic analysts and system administrators
