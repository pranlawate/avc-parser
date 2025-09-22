# Feature Decision Log

This document maintains a comprehensive record of all feature decisions, including accepted, rejected, and deferred features for the AVC Parser project.

## Decision Categories

- **✅ ACCEPTED**: Features implemented or planned within scope
- **❌ REJECTED**: Features explicitly excluded from project scope
- **⏸️ DEFERRED**: Features delayed to future research phase
- **🔄 REVISED**: Features that were modified from original proposal

---

## Display Format Decisions

### ✅ ACCEPTED: Rich Rule Header Format
**Proposal**: Professional terminal display with Rich library using rules and responsive formatting
**Alternatives Considered**:
- Manual ASCII art headers
- Simple text-based formatting
- Fixed-width tables
**Reason**: Superior terminal responsiveness, automatic width handling, better copy-paste compatibility
**Date**: 2025-09-21 (From roadmap design decisions)
**Status**: PLANNED

### ❌ REJECTED: Fixed-Width ASCII Table Format
**Proposal**: Traditional fixed-width table display for denial information
**Reason**: Doesn't scale across different terminal sizes, poor responsiveness
**Alternative**: Rich Rule header format with dynamic width handling
**Date**: 2025-09-21

### ❌ REJECTED: Manual Terminal Width Calculations
**Proposal**: Manual detection and handling of terminal width for formatting
**Reason**: Rich library provides automatic width management, reducing complexity
**Date**: 2025-09-21

---

## Filtering and Search Decisions

### ✅ ACCEPTED: Basic Process and Path Filtering
**Proposal**: Add `--process` and `--path` flags for basic filtering capabilities
**Reason**: High-value features for daily forensic workflows, simple implementation
**Date**: 2025-09-22 (Phase 3B-1)
**Status**: PLANNED

### ✅ ACCEPTED: Sorting Options
**Proposal**: Add `--sort recent|count|chrono` for different analysis workflows
**Reason**: Different use cases require different sorting (recent for daily use, count for admins, chrono for audit analysis)
**Date**: 2025-09-22 (Phase 3B-1)
**Status**: PLANNED

### ✅ ACCEPTED: Advanced Time and Context Filtering
**Proposal**: Time range filtering (`--since`, `--until`) and context filtering (`--source`, `--target`)
**Reason**: Advanced filtering capabilities for complex forensic analysis
**Date**: 2025-09-22 (Phase 3B-2)
**Status**: PLANNED AFTER TESTING FOUNDATION

### ❌ REJECTED: Complex Query Language
**Proposal**: SQL-like or regex-based query language for advanced filtering
**Reason**: Adds significant complexity, command-line flags sufficient for target use cases
**Date**: 2025-09-22

### ❌ REJECTED: Real-time Filtering During Audit Stream Processing
**Proposal**: Real-time filtering capabilities for live audit streams
**Reason**: Outside forensic analysis scope, tool focuses on static log analysis
**Date**: 2025-09-22

---

## Input/Output Format Decisions

### ✅ ACCEPTED: Single --file Flag with Auto-Detection
**Proposal**: Replace --raw-file and --avc-file with single --file flag that auto-detects format
**Reason**: Eliminates user confusion about file types, simpler UX
**Date**: 2025-09-21 (Phase 1B)
**Status**: COMPLETED

### ❌ REJECTED: Separate Format-Specific Flags as Primary Interface
**Proposal**: Keep --raw-file and --avc-file as the primary interface
**Reason**: Creates user confusion about which flag to use
**Alternative**: Auto-detection with backward compatibility
**Date**: 2025-09-21

### ✅ ACCEPTED: Backward Compatibility for Legacy Flags
**Proposal**: Maintain --raw-file and --avc-file for existing users
**Reason**: Smooth migration path, doesn't break existing scripts
**Date**: 2025-09-21
**Status**: COMPLETED

### ❌ REJECTED: Binary File Output Formats
**Proposal**: Support for binary output formats for performance
**Reason**: Outside scope - we focus on human-readable terminal and JSON output
**Date**: 2025-09-21

### ❌ REJECTED: XML Output Format
**Proposal**: XML output option alongside JSON
**Reason**: JSON is sufficient for structured output, XML adds complexity
**Date**: 2025-09-21

---

## Parsing Strategy Decisions

### ✅ ACCEPTED: Enhanced Regex Pattern from setroubleshoot
**Proposal**: Adopt setroubleshoot's robust audit record regex for better edge case handling
**Reason**: Proven pattern that handles node= prefixes, optional msg=, and various formats
**Date**: 2025-09-21 (Phase 1B)
**Status**: COMPLETED

### ❌ REJECTED: Custom Audit Record Parser from Scratch
**Proposal**: Write completely new audit record parsing logic
**Reason**: setroubleshoot's patterns are proven and handle edge cases we haven't discovered
**Date**: 2025-09-21

### ✅ ACCEPTED: Log Block Processing (Current Approach)
**Proposal**: Process audit logs as blocks separated by '----' separators
**Reason**: Works well with ausearch output format, maintains proven logic
**Date**: 2025-09-21
**Status**: CURRENT APPROACH

### ❌ REJECTED: Line-by-Line Streaming Parser
**Proposal**: Process audit records one line at a time as they arrive
**Reason**: Outside scope - we focus on static file analysis, not streaming
**Date**: 2025-09-21

---

## Correlation Strategy Decisions

### 🔄 REVISED: Correlation Tracking Approach
**Original Proposal**: Full event assembly with AuditEvent/AuditRecord classes
**Revision**: Lightweight correlation data structure for PID-to-resource mapping
**Reason**: Solves core problem without architectural complexity
**Date**: 2025-09-21
**Status**: REVISED TO SIMPLE APPROACH

### ❌ REJECTED: In-Memory Event Assembly Architecture
**Proposal**: Complex event assembly system with temporal grouping by event ID
**Reason**: High complexity for uncertain benefit, outside forensic analysis scope
**Alternative**: Simple correlation storage alongside existing aggregated data
**Date**: 2025-09-21

---

## Architecture Decisions

### ✅ ACCEPTED: Simple Correlation Storage (Revised from Complex Event Assembly)
**Original Proposal**: Full event assembly architecture based on setroubleshoot's AuditEvent class
**Revision**: Lightweight correlation data structure for PID-to-resource mapping
**Reason**: Solves core correlation problem without architectural complexity
**Date**: 2025-09-21
**Impact**: Maintains current proven parsing logic while adding needed correlation

### ❌ REJECTED: Complex Event Assembly Architecture
**Proposal**: Full adoption of setroubleshoot's event assembly with AuditEvent/AuditRecord classes
**Reason**:
- High architectural complexity for uncertain benefit
- Outside forensic analysis scope
- Would require major refactoring of proven parsing logic
**Date**: 2025-09-21
**Alternative**: Simple correlation storage approach

### ✅ ACCEPTED: Policy-Independent Semantic Analysis
**Proposal**: Human-readable permission descriptions using static mappings
**Reason**: Provides value without requiring policy file dependencies
**Date**: 2025-09-21
**Status**: COMPLETED

---

## Real-Time vs Post-Incident Analysis

### ❌ REJECTED: Real-Time Audit Stream Monitoring
**Proposal**: Socket-based streaming audit analysis similar to setroubleshoot daemon
**Reason**: Outside project scope - we focus on post-incident forensic analysis
**Alternative**: Users should use setroubleshoot for real-time monitoring
**Date**: 2025-09-21

### ❌ REJECTED: Live Audit Integration
**Proposal**: Direct integration with auditd for live denial capture
**Reason**: Real-time monitoring is outside forensic analysis scope
**Date**: 2025-09-21

---

## System Behavior Analysis

### ❌ REJECTED: SYSCALL Success/Failure Tracking
**Proposal**: Parse SYSCALL records to determine if denials actually blocked operations
**Reason**:
- Requires complex event assembly architecture
- System behavior analysis outside forensic scope
- Adds complexity without clear forensic value
**Date**: 2025-09-21

### ❌ REJECTED: Exit Code Analysis
**Proposal**: Extract and analyze exit codes from SYSCALL records
**Reason**: System behavior tracking outside scope, requires event assembly
**Date**: 2025-09-21

### 🔄 REVISED: dontaudit Detection Logic
**Original Proposal**: Complex system behavior analysis for dontaudit rule detection
**Revision**: Simple permission-based detection using specific indicators
**Reason**: Simple detection using `noatsecure`, `rlimitinh`, `siginh` permissions provides high forensic value with minimal complexity
**Implementation**: Check for presence of commonly suppressed permissions that indicate enhanced audit mode
**Date**: 2025-09-22 (Revised from original 2025-09-21 rejection)
**Status**: ACCEPTED FOR PHASE 3B-1

### ❌ REJECTED: Performance Impact Analysis
**Proposal**: Analyze performance implications of denials on system behavior
**Reason**: System performance monitoring outside forensic analysis scope
**Date**: 2025-09-21

---

## Policy and Recommendations

### ❌ REJECTED: Policy File Analysis
**Proposal**: Parse SELinux policy files to provide context about denials
**Reason**:
- Requires policy file dependencies
- Policy analysis outside forensic scope
- Reduces tool portability
**Date**: 2025-09-21

### ❌ REJECTED: Automated Policy Recommendations
**Proposal**: Generate suggested policy changes based on denial patterns
**Reason**: Policy generation outside forensic analysis scope
**Date**: 2025-09-21

### ❌ REJECTED: audit2allow Integration
**Proposal**: Integrate audit2allow functionality for policy suggestions
**Reason**: Policy generation tools already exist, outside our scope
**Date**: 2025-09-21

---

## User Interface Decisions

### ❌ REJECTED: Web Interface
**Proposal**: Web-based dashboard for audit log analysis
**Reason**: Outside scope - we focus on CLI/terminal analysis
**Date**: 2025-09-21

### ❌ REJECTED: Graphical Dashboard
**Proposal**: GUI application with charts and visualizations
**Reason**: Outside scope - forensic analysis is terminal-focused
**Date**: 2025-09-21

### ❌ REJECTED: Interactive TUI Interface
**Proposal**: Terminal UI with interactive filtering and navigation
**Reason**: Complex UI outside scope, terminal output is sufficient
**Date**: 2025-09-21

### ✅ ACCEPTED: Rich Terminal Output with Color Formatting
**Proposal**: Professional terminal display with color schemes
**Reason**: Enhances readability while staying within terminal scope
**Date**: 2025-09-21
**Status**: IMPLEMENTED

---

## Data Processing and Storage

### ❌ REJECTED: Database Storage
**Proposal**: Store parsed denials in SQLite/PostgreSQL for querying
**Reason**: Outside scope - we process files and output results, no persistence needed
**Date**: 2025-09-21

### ❌ REJECTED: Multi-Host Correlation
**Proposal**: Correlate audit logs across multiple systems
**Reason**: Complex distributed analysis outside forensic scope
**Date**: 2025-09-21

### ❌ REJECTED: Log Streaming and Aggregation
**Proposal**: Aggregate audit logs from multiple sources
**Reason**: Log aggregation systems already exist, outside our scope
**Date**: 2025-09-21

### ✅ ACCEPTED: JSON Export with Semantic Fields
**Proposal**: Structured JSON output including semantic analysis
**Reason**: Enables integration while maintaining simplicity
**Date**: 2025-09-21
**Status**: IMPLEMENTED

---

## Advanced Analysis Features

### ⏸️ DEFERRED: Timeline Analysis and Visualization
**Proposal**: Temporal pattern visualization for attack progression
**Reason**: Potentially valuable but complex, deferred to future research
**Date**: 2025-09-21

### ⏸️ DEFERRED: Pattern Detection and Machine Learning
**Proposal**: ML-based attack pattern recognition
**Reason**: Advanced feature outside current scope, future research candidate
**Date**: 2025-09-21

### ⏸️ DEFERRED: Container/Namespace Awareness
**Proposal**: Enhanced context for modern containerized deployments
**Reason**: Useful feature but adds complexity, deferred to future
**Date**: 2025-09-21

---

## Scope Boundary Clarifications

### Clear IN SCOPE:
- Static audit log file analysis (ausearch output, raw audit.log)
- Correlation tracking for PID-to-resource mapping clarity
- Human-readable semantic analysis without policy file dependencies
- Professional display formatting for terminal and JSON output
- File format auto-detection and validation
- Deduplication with intelligent aggregation

### Clear OUT OF SCOPE:
- Real-time audit stream monitoring
- Policy file analysis or policy recommendations
- Complex event streaming or distributed log correlation
- Web interfaces or graphical dashboards
- Automated remediation or policy generation
- Performance monitoring or system behavior analysis

---

## Code Quality and Development Decisions

### ✅ ACCEPTED: Rich Library for Terminal Formatting
**Proposal**: Use Rich library for professional terminal output with color and formatting
**Alternatives Considered**: Manual ANSI escape codes, other terminal libraries
**Reason**: Mature library with automatic width handling, color schemes, and fallbacks
**Date**: 2025-09-21
**Status**: IMPLEMENTED

### ❌ REJECTED: Manual ANSI Escape Code Implementation
**Proposal**: Implement terminal colors and formatting using raw ANSI escape codes
**Reason**: Rich library provides better compatibility and automatic fallbacks
**Date**: 2025-09-21

### ✅ ACCEPTED: Conservative Error Handling with Graceful Degradation
**Proposal**: Wrap parsing functions with try-catch to prevent single corrupted records from breaking analysis
**Reason**: Forensic analysis should be robust against corrupted audit data
**Date**: 2025-09-21
**Status**: IMPLEMENTED

### ❌ REJECTED: Strict Parsing with Failure on Malformed Records
**Proposal**: Fail fast when encountering any malformed audit records
**Reason**: Real-world audit logs often contain partial or corrupted data
**Date**: 2025-09-21

### ✅ ACCEPTED: Comprehensive Input Validation with User-Friendly Messages
**Proposal**: Detailed validation for file types, permissions, and content with helpful error messages
**Reason**: Improves user experience and prevents common usage errors
**Date**: 2025-09-21 (Phase 1A)
**Status**: COMPLETED

### ❌ REJECTED: Minimal Error Messages
**Proposal**: Basic error handling with simple error messages
**Reason**: Forensic analysis tools should provide clear guidance for usage issues
**Date**: 2025-09-21

---

## Testing and Quality Decisions

### ✅ ACCEPTED: Comprehensive Test Suite with Real-World Data
**Proposal**: Unit tests, integration tests, and tests using real audit log examples
**Reason**: Parsing logic is complex and needs validation against real-world data
**Date**: 2025-09-21
**Status**: PLANNED (Phase 4)

### ❌ REJECTED: Minimal Testing Approach
**Proposal**: Basic smoke tests only
**Reason**: Forensic tools need high reliability and comprehensive testing
**Date**: 2025-09-21

### ✅ ACCEPTED: Documentation-Driven Development
**Proposal**: Comprehensive docstrings and inline comments for maintainability
**Reason**: Complex parsing logic needs clear documentation for maintenance
**Date**: 2025-09-21 (Phase 1A)
**Status**: IMPLEMENTED

---

## Dependency and Portability Decisions

### ✅ ACCEPTED: Python Standard Library + Rich Only
**Proposal**: Minimize external dependencies to Python standard library and Rich for formatting
**Reason**: Maximizes portability and reduces deployment complexity
**Date**: 2025-09-21
**Status**: CURRENT APPROACH

### ❌ REJECTED: Heavy Framework Dependencies
**Proposal**: Use larger frameworks like Django, Flask, or click for CLI handling
**Reason**: Adds unnecessary complexity for our focused CLI tool
**Date**: 2025-09-21

### ❌ REJECTED: Policy File Library Dependencies
**Proposal**: Include libraries for SELinux policy parsing (libselinux-python, etc.)
**Reason**: Outside scope, reduces portability, semantic analysis works without policy files
**Date**: 2025-09-21

### ✅ ACCEPTED: Cross-Platform Compatibility
**Proposal**: Ensure tool works on Linux, macOS, and Windows (where Python runs)
**Reason**: Forensic analysts may need to analyze logs on different platforms
**Date**: 2025-09-21
**Status**: DESIGN PRINCIPLE

---

## Recent Implementation Decisions (2025-09-21)

### ✅ ACCEPTED: Rich Rule Header Format Implementation
**Proposal**: Implement professional Rich Rule headers with responsive terminal formatting
**Implementation**: Rich Rules with dynamic width, correlation events display, professional color scheme
**Reason**: Superior terminal responsiveness and professional appearance for forensic analysis
**Date**: 2025-09-21
**Status**: IMPLEMENTED (Phase 3A)

### ✅ ACCEPTED: Function Refactoring for Code Quality
**Proposal**: Break down oversized functions into focused, single-responsibility components
**Implementation**: Extracted helper functions from 260+ line _parse_avc_log_internal()
**Functions Created**:
- `parse_timestamp_from_audit_block()` - Timestamp parsing logic
- `extract_shared_context_from_non_avc_records()` - Context extraction
- `process_individual_avc_record()` - Individual AVC processing with semantic analysis
**Reason**: Improved maintainability, testability, and code clarity without functional changes
**Date**: 2025-09-21
**Status**: IMPLEMENTED

### ✅ ACCEPTED: DRY Principle Implementation
**Proposal**: Extract repeated logic into reusable helper functions
**Implementation**: Created unified helper functions for permission enhancement and correlation building
**Functions Created**:
- `get_enhanced_permissions_display()` - Unified permission formatting
- `build_correlation_event()` - Standardized correlation data structure
**Reason**: Eliminated code duplication and improved consistency
**Date**: 2025-09-21
**Status**: IMPLEMENTED

### ✅ ACCEPTED: Legacy Format Flag Rename
**Proposal**: Rename `--legacy-format` flag to `--fields` for better clarity
**Reason**: More intuitive naming that describes the field-by-field display format
**Date**: 2025-09-21
**Status**: IMPLEMENTED

### ✅ ACCEPTED: Lightweight Architecture Documentation
**Proposal**: Add ASCII-based architecture documentation to Phase 5 instead of full UML
**Components**: Function relationship trees, data flow diagrams, developer guide
**Reason**: Provides architectural clarity while maintaining minimal dependencies and scope compliance
**Date**: 2025-09-21
**Status**: PLANNED (Phase 5)

### ✅ ACCEPTED: JSON Field Normalization for Tool Integration
**Proposal**: Standardize JSON output field formats (paths, ports, contexts) to enable reliable integration with external tools like selinux-ai-tool
**Scope Check**: ✅ Within "Professional terminal & JSON output" and "Human-readable semantic analysis" boundaries
**Complexity Assessment**: ✅ LOW - Enhancement to existing parsing logic
**Dependency Analysis**: ✅ No new dependencies required
**Value Assessment**: ✅ HIGH - Improves data quality for both human analysis and tool consumption
**Implementation**:
- Standardized path formats (absolute paths, consistent separators)
- Clean port number extraction and formatting
- Normalized SELinux context field structures
- Reliable field presence and data types for automation
**Reason**: High ROI enhancement that makes our JSON universally consumable while staying within forensic analysis scope
**Date**: 2025-09-22 (Phase 3B-2)
**Status**: PLANNED

---

## Decision Process

All feature decisions should follow this process:
1. **Scope Check**: Does this align with our forensic analysis focus?
2. **Complexity Assessment**: Does this add significant architectural complexity?
3. **Dependency Analysis**: Does this require external dependencies or policy files?
4. **Value Assessment**: Does this provide clear value for post-incident analysis?
5. **Documentation**: Record decision with rationale in this document

---

*This document serves as the definitive record of feature decisions to prevent scope creep and maintain project focus.*