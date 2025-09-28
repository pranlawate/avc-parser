# Changelog

All notable changes to the SELinux AVC Denial Analyzer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-09-28

### Added
- **Two-Tier Professional Report System**: New `--report [format]` flag with brief and sealert formats
  - `--report brief` or `--report`: Executive summaries with business impact language
  - `--report sealert`: Technical analysis format with comprehensive forensic details
- **SELinux Policy Investigation Integration**: Auto-generated `sesearch` commands for seamless workflow
  - Policy investigation commands displayed in yellow-bordered panels
  - Copy-paste workflow from denial analysis to policy investigation
  - JSON export includes `sesearch_command` field for automation
- **Grouping Efficiency Validation**: Analysis of denial grouping optimality using sesearch command correlation
- **Enhanced Testing**: Test suite expanded from 149 to 156 tests
  - Comprehensive test coverage for two-tier report system
  - Terminology consistency validation across all formats

### Changed
- **Terminology Consistency**: Standardized "Unique Denial Group" across all technical formats (Rich, fields, sealert)
- **Business Terminology**: "SELINUX SECURITY INCIDENT" terminology for executive brief format
- **Argument Architecture**: Properly categorized Display Modes vs Display Modifiers with clear precedence
- **Documentation Overhaul**: Updated all documentation for consistency and new features

### Fixed
- **JSON stdin input**: Resolved stdin processing bug for JSON input handling
- **Notice panels**: Fixed security notice panels for clean copy-paste compatibility in report formats

## [1.4.0] - 2025-09-26

### Added
- **Interactive Pager Mode**: Built-in `--pager` flag with color preservation for large outputs
- **Advanced Filtering Capabilities**:
  - Time range filtering with `--since` and `--until` flags
  - SELinux context filtering with `--source` and `--target` flags
  - Support for relative time specifications (yesterday, "2 hours ago", specific dates)
  - Wildcard pattern matching for context filtering
- **PID Event Counting**: Display event frequency per PID (e.g., `PID 1234 (3x)`) for better correlation
- **Process Name Resolution Enhancement**: Intelligent fallback hierarchy for process name detection
  - Primary: `comm` field, Secondary: `exe` field, Tertiary: `proctitle` field
- **Enhanced Process Integration**: Dynamic process name usage in semantic analysis

### Changed
- **Modular Architecture**: Refactored 4870-line monolith into clean 3-module structure
  - `parse_avc.py` (main application), `context.py` (SELinux context), `utils.py` (utilities)
- **Ultra-Fast Development Workflow**: Migrated to ruff (197x performance improvement over multi-tool workflow)
- **Comprehensive Test Coverage**: Expanded test suite from 107 to 146 tests (+39 new tests)
  - Display layer testing, malformed log robustness, enhanced integration testing
  - Regression prevention framework with automated test runner

### Fixed
- **BIONIC Readability**: Fixed bold-normal vs bold-dim contrast for dark terminal backgrounds
- **Error Handling**: Replaced misleading "no AVC records" errors with proper informational messages
- **Multiple File Guidance**: Enhanced help text clarity for single-file processing expectations
- **Pipe Compatibility**: Fixed broken pipe errors when output is redirected to `head`, `less`, etc.

## [1.3.0] - 2025-09-25

### Added
- **Smart Deduplication Logic**: SELinux remediation-aware grouping that properly distinguishes services
  - Service distinction for same SELinux contexts (httpd vs nginx)
  - Permission grouping for related permissions sharing common remediation
  - Optimal `semanage` command correlation - each group solved by single command
- **Smart Event Grouping**: Intelligent grouping by directory paths to reduce output volume
  - Hierarchical breakdown for subdirectories
  - `--expand-groups` flag for full detail when needed
- **dontaudit Detection**: Automatic detection using permission indicators (noatsecure, rlimitinh, siginh)
- **Enhanced Path Resolution**: PATH record correlation with dev+inode fallback

### Changed
- **Grouping Validation**: Efficiency analysis detecting when denial groups share identical policy queries
- **Legacy Support**: Added `--legacy-signatures` flag for regression testing and edge cases

### Fixed
- **Critical Display Bugs**: Container notice regression and multiple file handling enhancement
- **Performance Optimization**: Sub-second analysis of large audit logs maintained post-refactoring

## [1.2.0] - 2025-09-23

### Added
- **JSON Field Normalization**: Comprehensive field normalization for reliable tool integration
  - Standardized path formats (absolute paths, consistent separators)
  - Clean port number extraction and formatting
  - Normalized SELinux context field structures
  - Reliable field presence and data types for automation
- **Enhanced JSON Output**: Structured output with metadata tracking
  - Normalization version and status for tool compatibility
  - Component extraction for SELinux contexts (user, role, type, level)
  - Network denial support with port classification

### Changed
- **Professional Display**: Rich terminal format with responsive panels and BIONIC reading
- **Correlation Tracking**: Individual PID-to-resource mappings solve deduplication information loss

## [1.1.0] - 2025-09-22

### Added
- **Basic Filtering Options**: Process and path filtering capabilities
  - `--process` flag for filtering denials by process name
  - `--path` flag for filtering denials by file path with wildcard support
- **Sorting Options**: Multiple sort orders for different analysis workflows
  - `--sort recent` (default), `--sort count`, `--sort chrono`
- **Semantic Intelligence**: Human-readable permissions and contextual analysis
  - Permission descriptions (e.g., `read` → `Read file content`)
  - Contextual analysis based on actual process names

### Changed
- **Rich Rule Header Format**: Professional terminal display with rules and responsive formatting
- **Function Refactoring**: Improved code organization and maintainability
  - Extracted helper functions for better single-responsibility design
  - DRY principle implementation with reusable helper functions

## [1.0.0] - 2025-09-21

### Added
- **Core Foundation**: Initial release with complete AVC denial analysis capabilities
- **Auto-Detection**: Single `--file` flag automatically detects raw audit.log vs pre-processed format
- **Multiple Input Sources**: Raw audit.log, ausearch output, interactive paste input
- **Robust Parsing**: Multi-line audit blocks (AVC, USER_AVC, SYSCALL, CWD, PATH, PROCTITLE, SOCKADDR)
- **Display Formats**:
  - Rich terminal format (default) with professional panels
  - Field-by-field format (`--fields`) for technical deep-dive
  - JSON output (`--json`) for automation and integration
- **Comprehensive Validation**: File type, permissions, and content validation
- **Enhanced Regex Patterns**: Adopted setroubleshoot's robust audit record regex
- **Conservative Error Handling**: Graceful degradation with corrupted audit data

### Changed
- **Backward Compatibility**: Maintained `--raw-file` and `--avc-file` for existing users
- **Log Block Processing**: Process audit logs as blocks separated by '----' separators

### Technical Details
- **Dependencies**: Python 3.6+ with Rich library for terminal formatting
- **Cross-Platform**: Linux, macOS, Windows compatibility where Python runs
- **Documentation-Driven**: Comprehensive docstrings and inline comments
- **Testing Foundation**: Initial test suite with real-world data validation

---

## Version History Summary

- **v1.5.0**: Two-tier report system with policy investigation integration
- **v1.4.0**: Advanced filtering, pager mode, and modular architecture
- **v1.3.0**: Smart deduplication and intelligent event grouping
- **v1.2.0**: JSON normalization and professional display enhancements
- **v1.1.0**: Basic filtering, sorting, and semantic intelligence
- **v1.0.0**: Core foundation with auto-detection and multiple display formats

## Migration Guide

### From 1.4.x to 1.5.0
- No breaking changes - all existing functionality preserved
- New `--report [format]` flag available for professional documentation workflows
- Enhanced JSON output includes `sesearch_command` field

### From 1.3.x to 1.4.0
- No breaking changes - backward compatibility maintained
- New filtering flags available: `--since`, `--until`, `--source`, `--target`
- `--pager` flag available for interactive navigation

### From 1.2.x to 1.3.0
- No breaking changes - smart grouping is default behavior
- `--legacy-signatures` flag available for regression testing
- `--expand-groups` flag available to disable smart grouping

### From 1.1.x to 1.2.0
- No breaking changes - JSON output enhanced with normalized fields
- All existing JSON consumers continue to work

### From 1.0.x to 1.1.0
- No breaking changes - new filtering options are additive
- All existing command-line usage patterns continue to work

---

*For complete feature documentation, see [README.md](README.md) and [CLI_REFERENCE.md](CLI_REFERENCE.md)*