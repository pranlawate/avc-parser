# SELinux AVC Denial Analyzer

**Version 1.4.0** | A forensic-focused tool for analyzing SELinux audit logs with intelligent deduplication, SELinux policy investigation integration, advanced filtering capabilities, and normalized JSON output.

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

# Get field-by-field details (technical deep-dive)
python3 parse_avc.py --file /var/log/audit/audit.log --fields

# Get report-friendly format (documentation and copy-paste workflows)
python3 parse_avc.py --file /var/log/audit/audit.log --report

# Export to JSON
python3 parse_avc.py --file /var/log/audit/audit.log --json

# Use legacy signature logic (for regression testing)
python3 parse_avc.py --file /var/log/audit/audit.log --legacy-signatures

# Show individual events instead of resource-based groupings
python3 parse_avc.py --file /var/log/audit/audit.log --expand-groups

# Use interactive pager for large outputs
python3 parse_avc.py --file /var/log/audit/audit.log --pager

# Example output includes automatically generated policy investigation commands:
# ╭──────────────── Policy Investigation Command ────────────────╮
# │    sesearch -A -s httpd_t -t default_t -c file -p read,write  │
# ╰────────────────────────────────────────────────────────────────╯
#
# Plus PID event counts in denial summaries:
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
- **Report-Friendly Format**: Use `--report` for professional documentation, copy-paste workflows, and incident reports with preserved grouping information
- **Field-by-Field View**: Detailed technical breakdown using `--fields` flag for deep-dive analysis
- **Normalized JSON Export**: Structured output with standardized field formats, semantic enrichment, and consistent data types for reliable tool integration and SIEM compatibility

### 🔍 **Advanced Analysis**
- **Semantic Intelligence**: Human-readable permissions (`read` → `Read file content`) and contextual analysis
- **Smart Deduplication**: SELinux remediation-aware grouping that properly distinguishes services while grouping related permissions for optimal `semanage` command correlation
- **Policy Investigation Commands**: Auto-generated `sesearch` commands for each denial group with copy-paste workflow integration
- **Grouping Validation**: Efficiency analysis detecting when denial groups share identical policy queries for optimization insights
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

📊 **Development Plans**: See [ROADMAP.md](ROADMAP.md) for future plans and [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md) for implementation details.

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

**Report-Friendly Format**: Use `--report` for professional documentation and copy-paste workflows
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --report
```

**Field-by-Field Display**: Use `--fields` for detailed technical breakdown and deep-dive analysis
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --fields
```

**JSON Output**: Add `--json` for machine-readable output with `sesearch_command` field
```bash
python3 parse_avc.py --file /var/log/audit/audit.log --json
# Output includes: "sesearch_command": "sesearch -A -s httpd_t -t default_t -c file -p read,write"
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


## 📊 Project Status

**Production-ready SELinux AVC denial forensic analysis tool**

**Core Features**: ✅ Complete  
- Smart deduplication with SELinux policy investigation integration
- Rich terminal display with professional formatting  
- Comprehensive filtering (time, process, path, context)
- JSON export with structured output

**Quality Assurance**: ✅ Complete  
- 146 comprehensive tests with regression prevention
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

**SELinux AVC Denial Analyzer v1.4.0** | Made for forensic analysts and system administrators
