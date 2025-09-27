# AVC Parser Enhancement Roadmap

Focused implementation plan for enhancing the AVC parser with correlation tracking and professional display capabilities.

## 🎯 Application Scope

**Purpose**: Post-incident SELinux audit log forensic analysis
**Users**: Security analysts, system administrators, compliance auditors
**Function**: Parse, correlate, and present SELinux denial patterns for human analysis

### 🔍 **Scope Boundaries**

**✅ IN SCOPE:**
- Static audit log file analysis | Human-readable semantic analysis
- Correlation tracking for PID-to-resource mapping | Professional terminal & JSON output
- File format auto-detection | Deduplication with intelligent aggregation

**❌ OUT OF SCOPE:**
- Real-time monitoring | Policy file analysis | Web interfaces
- Event streaming | Automated remediation | System behavior tracking

### 🎨 **Design Principles**
1. **Forensic Focus**: Post-incident analysis clarity over real-time features
2. **Minimal Dependencies**: Python + Rich only (no policy files)
3. **Correlation Clarity**: Simple mapping solutions over complex architectures
4. **Professional Output**: Terminal-friendly with clean JSON export

## 💡 Core Problems Solved

| Problem | Solution |
|---------|----------|
| **Correlation Loss** | PID-to-resource mapping through simple correlation storage |
| **Argument Confusion** | Single `--file` flag with auto-detection |
| **Display Limitations** | Rich-based responsive formatting |
| **User Experience** | Semantic analysis + auto-detection |

## Design Decisions Made

### 1. Rich Rule Header Format (Selected)
**Chosen Format:**
```
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
Denied read (Read file content), write (Modify file content) on file

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED
• PID 5678 (httpd-worker) denied 'write' to file /var/www/html/file2.html [Permissive] ✓ ALLOWED
```

**Why Selected:**
- Superior terminal responsiveness (Rich automatically handles width)
- Professional appearance across all terminal sizes
- Better copy-paste compatibility
- Integrates with existing color theme
- Automatic ASCII fallback built-in

### 2. Correlation Tracking Approach
**Solution:** Store individual event correlations alongside aggregated data
```python
correlations = [
    {"pid": "1234", "comm": "httpd", "path": "/file1", "permission": "read", "permissive": "0"},
    {"pid": "5678", "comm": "httpd-worker", "path": "/file2", "permission": "write", "permissive": "1"}
]
```

**Benefits:**
- Solves PID-to-resource mapping problem
- Maintains backward compatibility
- Enables detailed event breakdown
- Supports ratio analysis (1:9, 2:8, etc.)

### 3. Sorting Strategy
- **Default:** Recent first (by last_seen) - most practical for daily use
- **`--sort count`:** High frequency first - for system administrators
- **`--sort chrono`:** Oldest first - maintains current behavior for audit analysis

### 4. Legacy Compatibility
- **`--legacy-format`** flag preserves current output format
- Existing `print_summary()` function kept intact
- Smooth migration path for existing users/scripts

### 5. Semantic Analysis (Policy-Independent)
- Human-readable permission descriptions using static mappings
- Context intelligence based on object class + permission combinations
- No policy file access required - works with audit logs alone

## 📋 Implementation Plan

### ✅ **PHASE 1: Foundation** (COMPLETED)
**1A: Code Quality & Validation** | **1B: Auto-Detection & Parsing**
- Documentation & error handling | Enhanced regex patterns from setroubleshoot
- Input validation & signal handling | Single `--file` flag with auto-detection
- Argument validation improvements | Backward compatibility maintained

### 🔄 **PHASE 2: Correlation & Semantic Analysis**

#### ✅ **2A: Simple Correlation Storage** (COMPLETED)
- [x] **Correlation Data Structure**: Lightweight storage for individual event details
- [x] **Enhanced Record Support**: Robust parsing for all AVC message type variants
- [x] **Correlation Integration**: Individual correlations alongside aggregated data
- [x] **JSON Integration**: Correlation data available in structured output

#### ✅ **2B: Semantic Enhancement** (COMPLETED)
- [x] **Permission Semantic Analysis**: Human-readable descriptions + contextual intelligence
- [x] **Enhanced Display**: Type descriptions, port intelligence, professional formatting
- [x] **JSON Support**: Semantic fields included in structured output

**Scope Note**: SYSCALL success/failure tracking moved OUT OF SCOPE (requires complex event assembly)

### ✅ **PHASE 3: Rich Display Format** (COMPLETED)

#### ✅ **3A: Core Display** (COMPLETED)
- [x] **Rich Rule Header Format**: Professional terminal display with responsive design and BIONIC reading
- [x] **Professional Panel Layout**: Clean two-panel design (WHEN/WHAT + WHO/WHERE) with proper centering
- [x] **Correlation Events Display**: Individual PID-to-resource mapping in Rich format
- [x] **Enhanced Detailed View**: `--detailed` flag with expanded correlation analysis and syscall details
- [x] **BIONIC Reading Format**: Strategic text formatting for improved scanning of natural language
- [x] **Legacy Compatibility**: `--fields` flag preserves field-by-field display format
- [x] **Dynamic Styling**: Context-aware formatting with professional color scheme
- [x] **Information Hierarchy**: Optimized layout for incident analysis workflow
- [x] **Smart Multi-PID Display**: Shows all PIDs from correlation data with intelligent time ranges

#### ✅ **3B-1: High-Impact User Features** (COMPLETED)
- [x] **dontaudit Detection**: Simple permission-based detection using `noatsecure`, `rlimitinh`, `siginh` indicators
- [x] **Basic Filtering**: Process (`--process httpd`) and path filtering (`--path /var/www/*`)
- [x] **Sorting Options**: `--sort recent|count|chrono` for different analysis workflows

#### ✅ **3B-2: Polish Features** (COMPLETED)
- [x] **Smart Deduplication Logic**: SELinux remediation-aware signature generation to properly distinguish services while grouping related permissions for optimal `semanage` command correlation
- [x] **Smart Event Grouping**: Intelligent grouping of events by common directory paths to reduce output volume for large audit logs (builds on improved signatures)

**Scope Note**: Syscall success indicators moved OUT OF SCOPE (requires complex event assembly)

### ✅ **PHASE 4A: Testing Foundation** (COMPLETED)
- [x] **Unit Tests**: Core parsing logic, correlation accuracy, semantic analysis validation (107 comprehensive tests)
- [x] **Regression Testing**: Ensure existing functionality remains intact during feature additions
- [x] **Input Validation**: Edge cases, malformed logs, large files, boundary conditions
- [x] **Quality Analysis**: Comprehensive code review, bug detection, and critical fix implementation
- [x] **PID Event Counting**: Display event frequency per PID in compact view (e.g., `PID 1234 (3x)`) for improved correlation clarity
- [x] **Pipe Compatibility Fix**: Handle broken pipe errors when output is redirected to `head`, `less`, etc. (Critical daily workflow fix)

### ✅ **PHASE 4B-1: Advanced Filtering** (COMPLETED)
- [x] **Advanced Filtering**: Time range filtering (`--since yesterday`, `--until today`) and context filtering (`--source httpd_t`, `--target '*default*'`) with comprehensive pattern matching support
- [x] **Time Range Specifications**: Flexible time parsing supporting relative keywords, "X ago" patterns, and multiple date formats
- [x] **Context Pattern Matching**: Intelligent SELinux context filtering with wildcard support and case-insensitive matching
- [x] **Combined Filtering**: Seamless integration with existing process and path filters
- [x] **Comprehensive Testing**: Validated across multiple log formats with 25+ test scenarios

### ✅ **PHASE 4: JSON Field Normalization** (COMPLETED)
- [x] **JSON Field Normalization**: Standardized path formats, clean port extraction, normalized context fields for reliable tool integration

### ✅ **PHASE 5: Quality Tools Foundation** (COMPLETED)
- [x] **Ruff Migration**: Ultra-fast single-tool solution replacing black+isort+pyflakes (197x performance improvement)
- [x] **Code2flow Visualization**: Function call graph generation (49 nodes, 104 edges)
- [x] **Development Workflow**: Comprehensive Makefile with optimized targets
- [x] **Documentation Integration**: Complete development setup documentation in README
- [x] **Modularization**: Successful 4870-line → 3-module architecture transformation
**Impact**: Professional development infrastructure with blazing-fast workflow
**Achievement**: Revolutionary modularization with zero performance trade-offs

### ✅ **PHASE 6: Critical Bug Fixes & UX Improvements** (COMPLETED)
- [x] **BIONIC Readability**: Fixed contrast issues on dark backgrounds (bold-normal vs bold-dim)
- [x] **Error Handling**: Proper "no AVC records" messaging instead of misleading errors
- [x] **Multiple File Guidance**: Enhanced help text clarity for single-file processing expectation
- [x] **Performance Validation**: Post-modularization benchmarking (626ms for 20MB files)
**Impact**: Enhanced user experience and professional error handling
**Achievement**: Critical UX improvements ensuring production readiness

### ✅ **PHASE 7: Comprehensive Test Coverage** (COMPLETED)
- [x] **Test Suite Expansion**: 107 → 146 tests (+39 new tests for comprehensive coverage)
- [x] **Display Layer Testing**: 12 tests for Rich formatting, BIONIC text, path display validation
- [x] **Malformed Log Robustness**: 16 tests for edge cases, corrupted data, error recovery
- [x] **Integration Testing**: 21 tests for complete CLI workflows and end-to-end validation
- [x] **Regression Prevention**: Automated test runner with performance monitoring (`make test-regression`)
**Impact**: Bulletproof regression prevention with 100% test success rate (4.4s execution)
**Achievement**: Revolutionary test infrastructure ensuring safe development and deployment


### ✅ **PHASE 8: Interactive Pager Mode** (COMPLETED)
**Status**: Professional paging interface implemented for large audit log analysis

#### ✅ **Interactive Pager Mode** (COMPLETED)
- [x] **Built-in Pager Interface**: `--pager` flag with less/more integration for large outputs
- [x] **Color Preservation**: Maintains Rich formatting and colors in pager mode
- [x] **Cross-Platform Compatibility**: Fallback behavior when pager unavailable

#### **8A: Rich Module UX Enhancements** (PENDING EVALUATION)
- [ ] **Progress Bars**: Visual progress indicators for large file processing operations
- [ ] **Status Spinners**: Loading indicators during ausearch operations
- [ ] **Enhanced JSON Display**: Rich.JSON module for beautiful JSON output formatting
- [ ] **Professional Summary Tables**: Rich.Table for structured data presentation
- [ ] **Tree-based Correlation Display**: Rich.Tree for hierarchical relationship visualization
- [ ] **Multi-column Warning Panels**: Better space utilization for detection warnings

#### **8B: Smart Resource Display** (PENDING EVALUATION)
- [ ] **Context-aware Formatting**: Dynamic formatting based on object class (file vs network vs etc.)
- [ ] **Terminal Integration**: Enhanced output formatting for various terminal environments
- [ ] **Adaptive Layout**: Responsive design for different terminal widths

#### **8C: Advanced Integration Features** (PENDING EVALUATION)
- [ ] **Timezone Handling Enhancement**: Support for timezone-aware audit log parsing
- [ ] **Sesearch Command Generation**: Evaluate and implement SELinux policy query command generation feature

### 🧪 **PHASE 9: Integration & Performance** (QUALITY ASSURANCE)
- [ ] **Real-world Scenarios**: Various audit log formats, different Linux distributions
- [ ] **Cross-platform Compatibility**: Testing across RHEL, Ubuntu, SUSE, Arch distributions
- [ ] **Memory Optimization**: Large file handling improvements (>500MB audit logs)

### 📚 **PHASE 10: Documentation** (PLANNED)
**Enhanced Documentation** | **Architecture & Development**
- Enhanced README with migration guides | Updated help text and usage examples
- Installation instructions & version management | Feature documentation updates
- **Code Architecture Overview**: Function relationship trees & data flow diagrams | **Developer Guide**: Contribution setup and architectural understanding
- **Parsing Pipeline Visualization**: ASCII-based flow diagrams | **Component Interaction Maps**: Key classes and their relationships

### 🔄 **REFACTORING: Code Quality & Optimization** (COMPLETED)
**Code Structure** | **Performance & Extensions**
- [x] **Function Extraction**: Broke down oversized functions into focused components | Memory management for large files
- [x] **DRY Optimization**: Extracted repeated logic into reusable helper functions | Time range filtering capabilities
- [x] **Progress indicators & graceful degradation**: Enhanced error handling and user feedback
- [x] **Statistics mode & enhanced reporting**: Smart deduplication and correlation tracking

### 🚀 **FUTURE RESEARCH: Advanced Features** (OUT OF SCOPE)
- Advanced filtering and search capabilities | Enhanced correlation analysis
- Performance optimization for very large files | Extended semantic analysis
- **Temporal Analysis**: Multi-file processing for logs collected across different times with relative analysis capabilities

## Technical Analysis Context

### Issues Identified and Fixed
1. **Argument Logic Problems**:
   - Fixed conflicting arguments (`--raw-file` + `--avc-file`)
   - Added validation for directories, binary files, non-existent files
   - Improved error messages for edge cases

2. **Correlation Loss Problem**:
   - Current deduplication loses PID-to-resource mapping
   - Users can't determine which PID accessed which path
   - Ratio confusion (1:9, 2:8, etc.) when multiple processes/paths involved

3. **Display Format Limitations**:
   - Current verbose format doesn't scale across terminal sizes
   - Poor copy-paste compatibility
   - Limited visual hierarchy

### setroubleshoot Analysis Insights
**Adopted Improvements:**
- **Enhanced Regex Pattern**: More robust audit record parsing with node= and type= prefix support
- **Event Assembly Logic**: Temporal grouping system for proper record correlation (simplified from complex caching)
- **AvcContext Class**: Proven SELinux context parsing and field extraction
- **Extended Record Types**: Support for additional message types (AVC_PATH, 1400, 1107)
- **Permission Semantic Analysis**: Static permission mappings and contextual intelligence (no policy file required)

**Strategic Positioning:**
- **Complementary Tool**: Post-incident analysis vs real-time monitoring
- **File-focused**: Static log analysis vs socket-based streaming
- **Correlation Clarity**: PID-to-resource mapping vs policy recommendations
- **Professional Output**: Clean summaries vs verbose data dumps

### Rich Library Features to Leverage
- **Automatic Width Management**: No manual terminal width calculations
- **Custom Styles and Colors**: Integrate with green/cyan/white theme
- **Alignment Options**: Center, left, right alignment for different contexts
- **Character Customization**: Different line styles for different denial types
- **Terminal Capability Detection**: Unicode support with ASCII fallback

### Display Format Examples

#### Compact View (Default):
```
Found 8 AVC events. Displaying 3 unique denials...
Applied filters: process='httpd'
Showing 2 of 3 unique denials after filtering.
────────────────────────────── Parsed Log Summary ──────────────────────────────
ℹ️  DONTAUDIT DISABLED: Enhanced audit mode detected
   Found typically suppressed permissions: noatsecure

─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
╭──────────────────────────────────────────────────────────────────────────────╮
│                         2025-09-04 18:19:00–18:19:00                         │
│                                  Kernel AVC                                  │
│  Denied read (Read file content), write (Modify file content) on file via    │
│  openat                                                                      │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────╮
│               httpd (Web server process) 1234, 5678                          │
│      system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0       │
╰──────────────────────────────────────────────────────────────────────────────╯

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED
• PID 5678 (httpd-worker) denied 'write' to file /var/www/html/file2.html [Permissive] ✓ ALLOWED
```

#### Detailed View (`-d/--detailed`):
```
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
ℹ️  DONTAUDIT DISABLED: Enhanced audit mode detected
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
  └─ Source: Web server process (httpd_t) | Target: Default file context (default_t)
Denied read (Read file content), write (Modify file content) on file
Timeframe: 2025-09-04 18:19:00 → 2025-09-04 18:19:00

Detailed Events:
• PID 1234 (httpd) [/usr/sbin/httpd] denied 'read' to file /var/www/html/file1.html [Enforcing] ✗ BLOCKED
  ├─ Syscall: openat | Result: failed | Exit: EACCES | Time: 18:19:00.303
  ├─ Analysis: Web server attempting to read website content
  └─ Proctitle: /usr/sbin/httpd -DFOREGROUND

• PID 5678 (httpd-worker) [/usr/sbin/httpd] denied 'write' to file /var/www/html/file2.html [Permissive] ✓ ALLOWED
  ├─ Syscall: openat | Result: succeeded | Exit: 0 | Time: 18:19:00.303
  ├─ Analysis: Web server attempting to modify website content
  └─ Proctitle: /usr/sbin/httpd -DFOREGROUND
```

## Current Implementation Focus (ROI-Optimized Priority Order)

**MAJOR MILESTONE**: Phase 4C/4D Modularization - ✅ **COMPLETED WITH EXCELLENCE** (2025-09-26)

## ✅ **COMPLETED PHASES SUMMARY**

✅ **Phase 1**: Foundation - **COMPLETED**
  - Code quality, validation, auto-detection, enhanced parsing

✅ **Phase 2**: Correlation & Semantic Analysis - **COMPLETED**
  - Simple correlation storage, permission semantic analysis

✅ **Phase 3**: Rich Display Format - **COMPLETED**
  - Professional terminal display, BIONIC reading, filtering, sorting

✅ **Phase 4**: JSON Field Normalization - **COMPLETED**
  - Standardized formats for tool integration

✅ **Phase 5**: Quality Tools Foundation - **COMPLETED** (2025-09-26)
  - **Revolutionary Achievement**: 4870-line monolith → clean 3-module architecture
  - **Ultra-fast ruff toolchain**: 197x performance improvement over black+isort+pyflakes
  - **Comprehensive Testing**: All 107 tests passing after modularization
  - **Production Ready**: Clean imports, module boundaries, maintainable structure

✅ **Phase 6**: Critical Bug Fixes & UX Improvements - **COMPLETED** (2025-09-26)
  - **BIONIC Readability Enhancement**: Fixed contrast issues on dark backgrounds
  - **Error Handling**: Proper "no AVC records" messaging instead of misleading errors
  - **Multiple File Guidance**: Enhanced help text clarity for single-file processing
  - **Performance Validation**: Post-modularization benchmarking (626ms for 20MB files)

✅ **Phase 7**: Comprehensive Test Coverage - **COMPLETED** (2025-09-26)
  - **Test Suite Expansion**: 107 → 146 tests (+39 new tests for comprehensive coverage)
  - **Display Layer Testing**: 12 tests for Rich formatting, BIONIC text, path display
  - **Malformed Log Robustness**: 16 tests for edge cases, corrupted data, error recovery
  - **Integration Testing**: 21 tests for complete CLI workflows and end-to-end validation
  - **Regression Prevention**: Automated test runner with performance monitoring (`make test-regression`)

✅ **Phase 8**: Interactive Pager Mode - **COMPLETED** (2025-09-26)
  - **Built-in Pager Interface**: `--pager` flag with less-like interface for large outputs
  - **Color Preservation**: Maintains Rich formatting and colors in pager mode
  - **Cross-Platform Compatibility**: Fallback behavior when pager unavailable

**PENDING EVALUATION (Next Phase Decisions Required):**
❌ **Phase 8A**: Rich Module UX Enhancements - **REJECTED** (2025-09-26)
  - **Progress bars**: Minimal ROI for sub-second file processing
  - **Status spinners**: Sub-second visibility provides no user value
  - **Enhanced JSON display**: Current JSON output is sufficient
  - **Professional summary tables**: Current Rich panels are adequate
  - **Evaluation Result**: Low ROI cosmetic features rejected in favor of core functionality
🔄 **Phase 8B**: Smart Resource Display - **PENDING EVALUATION**
  - Context-aware formatting based on object class
  - Terminal integration and adaptive layout
🔄 **Phase 8C**: Advanced Integration Features - **PENDING EVALUATION**
  - Timezone handling enhancement for international usage
  - Sesearch command generation (requires workflow evaluation)

**ADDITIONAL EVALUATION REQUIRED:**
🔄 **Quality Tools Enhancement (Phase 12)**: safety, vulture, radon, mypy, prospector - **PENDING EVALUATION**
🔄 **Report-Friendly Output Format**: Compact/report mode for copying and documentation - **PENDING EVALUATION**

**SUBSEQUENT PHASES:**
**Phase 9**: Integration & performance testing
**Phase 10**: Enhanced documentation & architecture overview ✅ SUBSTANTIALLY COMPLETED
**Phase 11**: Distribution & Packaging (RPM, Pip, release automation)

## Key Benefits Expected (Scope-Compliant)

1. **Simplified UX**: Single `--file` flag eliminates user confusion about file types ✅ COMPLETED
2. **Correlation Clarity**: Lightweight storage solves PID-to-resource mapping without architectural complexity ✅ COMPLETED
3. **Professional Output**: Rich Rule responsive format works across all terminal sizes ✅ COMPLETED
4. **Enhanced Analysis**: Optional detailed view for deeper investigation ✅ COMPLETED
5. **Legacy Support**: Existing users can continue using familiar format ✅ COMPLETED
6. **Semantic Intelligence**: Human-readable permission descriptions and contextual analysis without requiring policy files ✅ COMPLETED
7. **Forensic Focus**: Optimized for post-incident analysis clarity rather than real-time monitoring
8. **Minimal Dependencies**: No policy file requirements for maximum portability
9. **Professional Display**: Terminal-friendly with clean JSON export capabilities ✅ COMPLETED
10. **Code Quality**: Optimized architecture with focused, maintainable functions ✅ COMPLETED
11. **BIONIC Reading**: Enhanced text scanning with strategic emphasis on natural language ✅ COMPLETED
12. **Proven Patterns**: Adopts setroubleshoot's parsing techniques without full architectural complexity

## Scope Compliance Summary

**✅ WITHIN SCOPE & COMPLETED:**
- Phase 1: Foundation (Core validation, auto-detection, enhanced parsing)
- Phase 2: Correlation & Semantic Analysis (lightweight correlation, permission analysis)
- Phase 3: Rich Display Format (BIONIC reading, professional panels, filtering, sorting)
- Phase 4: JSON Field Normalization (standardized formats for tool integration)
- Phase 5: Quality Tools Foundation (ruff migration, modularization, development workflow)
- Phase 6: Critical Bug Fixes & UX Improvements (BIONIC readability, error handling)
- Phase 7: Comprehensive Test Coverage (146 tests, regression prevention framework)
- Phase 8: Interactive Pager Mode (built-in paging interface with color preservation)

**❌ WITHIN SCOPE & REJECTED:**
- Phase 8A: Rich Module UX Enhancements (minimal ROI cosmetic features)

**🔄 WITHIN SCOPE & PENDING EVALUATION:**
- Phase 8B: Smart Resource Display (context-aware formatting, adaptive layout)
- Phase 8C: Advanced Integration Features (timezone handling, sesearch command generation)
- Quality Tools Enhancement: Additional development tools (safety, vulture, radon, mypy, prospector)
- Report-Friendly Output: Alternative display format for documentation and reporting

**✅ WITHIN SCOPE & PLANNED:**
- Phase 9: Integration & Performance Testing
- Phase 10: Enhanced Documentation & Architecture Overview
- Phase 11: Distribution & Packaging (RPM, Pip, release automation)

**❌ OUT OF SCOPE (Moved to Future Research):**
- Complex event assembly and streaming correlation
- Real-time monitoring capabilities
- System behavior analysis and performance tracking
- Policy file analysis and automated recommendations
- Web interfaces and graphical dashboards

## 📦 **PHASE 11: Distribution & Packaging (Professional Deployment)**

### **Strategic Distribution Approach**
**Primary**: RPM packaging for native SELinux environment integration
**Secondary**: Pip module for development workflows and cross-platform support
**Tertiary**: Additional distribution formats for broader ecosystem coverage

### **Phase 11A: RPM Package Implementation**
- [ ] **RPM Spec File**: Create `selinux-avc-analyzer.spec` with proper metadata
- [ ] **Build System**: Configure build automation and file permissions
- [ ] **Repository Integration**: Submit to Fedora Package Review and EPEL

### **Phase 11B: Pip Module Implementation**
- [ ] **Modern Python Packaging**: Create `pyproject.toml` with console script entry points
- [ ] **Package Structure**: Refactor to `src/selinux_avc_analyzer/` package structure
- [ ] **PyPI Publishing**: Configure automated releases with GitHub Actions
- [ ] **Cross-Platform Compatibility**: Handle audit package gracefully on non-Linux systems

### **Phase 11C: Additional Distribution Formats**
- [ ] **Debian Package**: Create `.deb` for Ubuntu with proper dependencies
- [ ] **Arch User Repository**: Create `PKGBUILD` for AUR submission
- [ ] **Container Distribution**: Optimized `Dockerfile` for containerized usage

### **Phase 11D: Documentation & Release Automation**
- [ ] **Installation Documentation**: Comprehensive guides for all platforms
- [ ] **Release Automation**: Multi-format releases with automated testing
- [ ] **Distribution Validation**: Cross-platform testing matrix

### **Implementation Timeline & Success Metrics**

**Week 1-2**: RPM packaging foundation (Phase 11A)
**Week 3**: Pip module structure (Phase 11B)
**Week 4**: Release automation setup (Phase 11D)
**Week 5**: Repository submissions and additional formats (Phase 11C)
**Week 6**: Comprehensive testing and validation

**Success Criteria**:
- RPM available in Fedora repositories within 2 months
- Pip package published to PyPI with automated releases
- Complete installation documentation for all supported platforms
- Validated functionality on 5+ Linux distributions
- Zero-touch release process with proper version management

## Future Research Ideas (Not Committed Features)

These ideas are preserved for potential future exploration but are not part of the committed roadmap:

- **Timeline Analysis**: Temporal pattern visualization for attack progression
- **Cross-System Correlation**: Multi-host audit log analysis capabilities
- **Advanced Pattern Detection**: Machine learning for attack pattern recognition
- **Interactive Query Interface**: GUI/TUI for complex filtering
- **Performance Impact Analysis**: System behavior correlation
- **Container/Namespace Awareness**: Modern deployment context understanding

---

*This roadmap serves as the definitive guide for AVC parser enhancements focused on delivering maximum value through core audit analysis capabilities.*