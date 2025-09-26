# SELinux AVC Denial Analyzer

**Version 1.3.0** | A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication, advanced filtering capabilities, normalized JSON output, and clear correlation tracking.

## ⚡ Quick Start

```bash
# Install dependencies
pip3 install rich

# Analyze audit logs (auto-detects format)
python3 parse_avc.py --file /var/log/audit/audit.log

# Filter by process and sort by count (most frequent first)
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --sort count

# Filter by path with wildcards
python3 parse_avc.py --file /var/log/audit/audit.log --path "/var/www/*"

# Filter by time range (advanced filtering)
python3 parse_avc.py --file /var/log/audit/audit.log --since yesterday --until today
python3 parse_avc.py --file /var/log/audit/audit.log --since "2025-01-15 09:00" --until "2025-01-15 17:00"
# Supports: relative times (yesterday, today, recent), "X ago" (2 hours ago), specific dates/times

# Filter by SELinux context
python3 parse_avc.py --file /var/log/audit/audit.log --source httpd_t --target "*default*"

# Get enhanced detailed analysis
python3 parse_avc.py --file /var/log/audit/audit.log --detailed

# Get field-by-field details
python3 parse_avc.py --file /var/log/audit/audit.log --fields

# Export to JSON
python3 parse_avc.py --file /var/log/audit/audit.log --json

# Use legacy signature logic (for regression testing)
python3 parse_avc.py --file /var/log/audit/audit.log --legacy-signatures

# Show individual events instead of resource-based groupings
python3 parse_avc.py --file /var/log/audit/audit.log --expand-groups

# Use interactive pager for large outputs
python3 parse_avc.py --file /var/log/audit/audit.log --pager

# Example output showing PID event counts in default view:
# • PID 1234 (3x) (httpd (Web server process)) - PID 1234 has 3 events
# • PID 5678 (nginx) - PID 5678 has 1 event (no count shown)
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

### 🎨 **Professional Display**
- **Rich Terminal Format**: Default responsive panels with BIONIC reading, professional styling, and correlation events
- **Interactive Pager Mode**: Built-in `less`-like interface with `--pager` for comfortable navigation of large outputs
- **Enhanced Detailed View**: Use `--detailed` for expanded correlation analysis with syscall details and context information
- **Field-by-Field View**: Detailed breakdown using `--fields` flag for traditional analysis
- **Normalized JSON Export**: Structured output with standardized field formats, semantic enrichment, and consistent data types for reliable tool integration and SIEM compatibility

### 🔍 **Advanced Analysis**
- **Semantic Intelligence**: Human-readable permissions (`read` → `Read file content`) and contextual analysis
- **Smart Deduplication**: SELinux remediation-aware grouping that properly distinguishes services while grouping related permissions for optimal `semanage` command correlation
- **Correlation Tracking**: Individual PID-to-resource mappings solve deduplication information loss
- **PID Event Counting**: Shows event frequency per PID in compact view (e.g., `PID 1234 (3x)`) for better correlation understanding
- **Enhanced Path Resolution**: PATH record correlation with dev+inode fallback for complex scenarios
- **dontaudit Detection**: Automatic detection of disabled dontaudit rules using permission indicators
- **Advanced Filtering**: Comprehensive filtering by process, path, time range, and SELinux contexts (`--process`, `--path`, `--since`, `--until`, `--source`, `--target`)
- **Time Range Analysis**: Flexible time specifications from relative keywords (`yesterday`) to specific timestamps (`2025-01-15 14:30`)
- **Context Pattern Matching**: Intelligent SELinux context filtering with wildcard support and component-level matching
- **Flexible Sorting**: Multiple sort orders - recent, count-based, or chronological (`--sort`)

### 📥 **Flexible Input**
- **Auto-Detection**: Single `--file` flag automatically detects raw audit.log vs pre-processed format
- **Multiple Sources**: Raw audit.log, ausearch output, or interactive paste input
- **Robust Parsing**: Multi-line audit blocks (`AVC`, `USER_AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, `SOCKADDR`)
- **Comprehensive Validation**: File type, permissions, and content validation with helpful error messages

### 📖 **BIONIC Reading Format**
- **Enhanced Readability**: Strategic text formatting emphasizes key letter groups for improved scanning speed
- **Smart Application**: Applied to natural language text while preserving technical data clarity
- **Professional Appearance**: Maintains color harmony and visual consistency throughout the display

## 🔮 Upcoming Features


### 🎨 **Phase 4C: Enhanced User Experience** (In Progress)
- **Smart Resource Display**: Context-aware formatting based on object class (file vs network vs etc.)
- **Terminal Integration**: Enhanced output formatting for various terminal environments

### 🧪 **Phase 4D: Integration & Performance** (Quality Assurance)
- **Real-world Scenarios**: Various audit log formats, different Linux distributions
- **Cross-platform Compatibility**: Testing across RHEL, Ubuntu, SUSE, Arch distributions
- **Memory Optimization**: Large file handling improvements (>500MB audit logs)

### 📚 **Phase 5: Enhanced Documentation**
- **Architecture Overview**: Function relationship trees and data flow diagrams
- **Developer Guide**: Contribution setup and architectural understanding
- **Migration Guides**: Enhanced README and usage examples

📊 **Complete Plan**: See [ROADMAP.md](ROADMAP.md) for detailed implementation roadmap and [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for scope decisions.

## Prerequisites

- Python 3.6+
- Python Rich library
- `audit` package (for `ausearch`): Usually pre-installed on most systems

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
   pip3 install rich
   sudo dnf install audit  # If needed (Fedora/RHEL)
   sudo apt install auditd  # If needed (Ubuntu/Debian)
   ```

## 🚀 Usage

### **Recommended: Auto-Detection** ✨
Single flag automatically detects file format (raw audit.log vs pre-processed):
```bash
python3 parse_avc.py --file /var/log/audit/audit.log
python3 parse_avc.py --file avc_denials.log
```

### **Alternative Methods:**

**Raw Audit File Processing:**
```bash
python3 parse_avc.py --raw-file /var/log/audit/audit.log
```

**Pre-processed AVC File:**
```bash
# Create AVC file:
ausearch -m AVC,USER_AVC,FANOTIFY,SELINUX_ERR,USER_SELINUX_ERR -ts recent > avc_denials.log
# Parse it:
python3 parse_avc.py --avc-file avc_denials.log
```

**Interactive Mode:**
```bash
python3 parse_avc.py
# Paste logs and press Ctrl+D (Linux/macOS) or Ctrl+Z+Enter (Windows)
```

### **Output Formats:**

**Rich Display (Default)**: Professional terminal format with responsive panels and BIONIC reading
```bash
python3 parse_avc.py --file /var/log/audit/audit.log
```

**Enhanced Detailed View**: Use `--detailed` for expanded correlation analysis
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --detailed
```

**Field-by-Field Display**: Use `--fields` for traditional detailed field breakdown
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --fields
```

**JSON Output**: Add `--json` for machine-readable output
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --json
```

📚 **Need more help?**
- **Comprehensive Examples**: [EXAMPLES.md](EXAMPLES.md) - Real-world usage patterns and workflows
- **Command Reference**: [CLI_REFERENCE.md](CLI_REFERENCE.md) - Complete options, data fields, and troubleshooting

## 📋 **Basic Examples**

### Quick Start Examples
```bash
# Basic file analysis
python3 parse_avc.py --file /var/log/audit/audit.log

# Filter by service and show most frequent denials
python3 parse_avc.py --file /var/log/audit/audit.log --process httpd --sort count

# Export findings for documentation
python3 parse_avc.py --file /var/log/audit/audit.log --json > analysis.json
```

📚 **For comprehensive examples**: See [EXAMPLES.md](EXAMPLES.md) for detailed usage patterns, filtering examples, and complex analysis workflows.

🔧 **For complete command reference**: See [CLI_REFERENCE.md](CLI_REFERENCE.md) for all command-line options, data fields, and troubleshooting guide.

## 📈 Development Status

**Current Version**: 1.3.0 | **Current Phase**: 4C (Pre-Modularization Safety Infrastructure COMPLETE)

| Component | Status | Description |
|-----------|--------|-------------|
| **Core Foundation** | ✅ **COMPLETE** | Auto-detection, validation, robust parsing |
| **Semantic Analysis** | ✅ **COMPLETE** | Human-readable permissions, contextual intelligence |
| **Correlation Tracking** | ✅ **COMPLETE** | PID-to-resource mapping, individual event details |
| **Rich Display Format** | ✅ **COMPLETE** | Professional terminal output, responsive design |
| **Code Quality** | ✅ **COMPLETE** | Refactored architecture, maintainable functions |
| **Basic Filtering & Sorting** | ✅ **COMPLETE** | Process, path filtering; recent, count, chrono sorting |
| **dontaudit Detection** | ✅ **COMPLETE** | Automatic detection of enhanced audit mode |
| **Smart Deduplication Logic** | ✅ **COMPLETE** | SELinux remediation-aware signature generation |
| **Smart Event Grouping** | ✅ **COMPLETE** | Intelligent directory path grouping for large outputs |
| **Testing Foundation** | ✅ **COMPLETE** | 107 comprehensive tests, quality analysis, bug fixes |
| **PID Event Counting** | ✅ **COMPLETE** | Event frequency display per PID in compact view (e.g., PID 1234 (3x)) |
| **Pipe Compatibility** | ✅ **COMPLETE** | Handle broken pipe errors for head/less redirection |
| **Advanced Filtering** | ✅ **COMPLETE** | Time range and context filtering with pattern matching support |
| **JSON Field Normalization** | ✅ **COMPLETE** | Standardized path formats, clean port extraction, normalized context fields |
| **Interactive Pager Mode** | ✅ **COMPLETE** | Built-in less-like interface with --pager, color preservation, smart fallbacks |
| **Dev-Suite Optimization** | ✅ **COMPLETE** | Fast, reliable development tools (Phase 4C) - optimized for 4870-line modularization |
| **Performance Optimization** | ⏳ **PLANNED** | Memory management, cross-platform testing |

### 🎯 **Design Principles**
- **Forensic Focus**: Post-incident analysis (not real-time monitoring)
- **Professional Output**: Rich terminal formatting with correlation tracking
- **Minimal Dependencies**: Python + Rich only (no policy files required)
- **Cross-Platform**: Linux, macOS, Windows compatibility

📊 **Documentation**: [EXAMPLES.md](EXAMPLES.md) | [CLI_REFERENCE.md](CLI_REFERENCE.md) | [ROADMAP.md](ROADMAP.md) | [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md)

## 🛠️ Development

### Quick Development Setup
```bash
# Install development dependencies
make install-tools

# Format code (with ruff)
make format

# Generate function flow diagrams
make flow-diagram      # Complete architecture (49 nodes, 104 edges)
make flow-focused      # Focused view from main() function

# Fast quality check (< 5 seconds)
make quick-check

# Run comprehensive analysis
make lint

# Security analysis
make security

# See all available commands
make help
```

### Code Quality Tools (Ultra-Fast Optimized)
**🏆 Tier 1 - Daily Use (< 1 second)**
- **✅ ruff**: All-in-one formatting + linting + import sorting (197x faster than old 3-tool combo)
- **✅ pydeps**: Import dependency analysis - fast, reliable
- **✅ vulture**: Dead code detection - found 46 real issues
- **✅ code2flow**: Function dependency visualization

**🥈 Tier 2 - Deep Analysis**
- **✅ bandit**: Security code analysis
- **✅ safety**: Dependency security scanning
- **✅ refurb**: Python modernization suggestions

**❌ Excluded Tools** (Performance issues or replaced)
- pytest (timeout), flake8 (broken pipe), radon (pipe issues), pylint (too slow)
- black, isort, pyflakes (replaced by single ruff tool)

### Development Workflow
1. Use `make format` to format code with ruff (no automatic hooks)
2. Use `make quick-check` for ultra-fast quality validation
3. Use `make flow-diagram` to visualize function relationships after major changes
4. All quality tools are managed through the Makefile for consistency

### Architecture Overview

**Modular Design (Phase 4C Complete)**:
```
avc-parser/
├── parse_avc.py       # Main application (4400 lines)
│                      # CLI interface, parsing logic, display formatting
├── context.py         # SELinux context parsing & semantic analysis
│                      # AvcContext class, PermissionSemanticAnalyzer
├── utils.py          # Utility functions
│                      # Time formatting, path display, error handling
└── tests/            # Comprehensive test suite (107 tests)
```

**Ultra-Fast Development Workflow**:
- `make quick-check` - Sub-second quality validation (ruff)
- `make test` - Complete test suite (107 tests)
- `make deps-graph` - Import dependency analysis
- `make all` - Complete development workflow

**Key Benefits**:
- **197x faster development** (ruff vs old 3-tool combination)
- **Maintainable architecture** (reduced from 4870 to 4400 lines main file)
- **Clean module boundaries** with minimal coupling
- **Zero dead code** and modern Python optimizations

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

**SELinux AVC Denial Analyzer v1.3.0** | Made for forensic analysts and system administrators
