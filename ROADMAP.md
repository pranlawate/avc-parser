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

#### 🔄 **3B: Practical Features** (PLANNED)
- Smart filtering (process, path, time, context) | Sorting options (recent, count, chronological)
- Detailed view with enhanced information | Smart resource display based on object class

**Scope Note**: Syscall success indicators moved OUT OF SCOPE (requires complex event assembly)

### 🧪 **PHASE 4: Testing & Quality** (PLANNED)
**Core Testing** | **Integration & Performance**
- Unit tests for parsing logic & correlation | Real-world audit log scenario testing
- Input validation & error handling tests | Cross-platform compatibility verification
- Regression testing for critical functionality | Memory optimization for large files

### 📚 **PHASE 5: Documentation** (PLANNED)
**Enhanced Documentation** | **Architecture & Development**
- Enhanced README with migration guides | Updated help text and usage examples
- Installation instructions & version management | Feature documentation updates
- **Code Architecture Overview**: Function relationship trees & data flow diagrams | **Developer Guide**: Contribution setup and architectural understanding
- **Parsing Pipeline Visualization**: ASCII-based flow diagrams | **Component Interaction Maps**: Key classes and their relationships

### 🔄 **PHASE 6: Code Quality & Optimization** (IN PROGRESS)
**Code Structure** | **Performance & Extensions**
- [x] **Function Extraction**: Broke down oversized functions into focused components | Memory management for large files
- [x] **DRY Optimization**: Extracted repeated logic into reusable helper functions | Time range filtering capabilities
- Progress indicators & graceful degradation | Statistics mode & enhanced reporting

### 🚀 **PHASE 7: Advanced Features** (FUTURE)
- Advanced filtering and search capabilities | Enhanced correlation analysis
- Performance optimization for very large files | Extended semantic analysis

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
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
ℹ️  DONTAUDIT DISABLED: Enhanced audit mode detected
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
Denied read (Read file content), write (Modify file content) on file

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

## Current Implementation Focus

**Phase 3B**: Practical display features (filtering, sorting)
**Phase 4**: Testing & Quality Assurance
**Phase 5**: Enhanced documentation & architecture overview
**Phase 7**: Advanced features and extensions

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
- Phase 1A: Core Foundation & Input Validation
- Phase 1B: Auto-Detection & Enhanced Parsing
- Phase 2A: Simple Correlation Storage (lightweight approach)
- Phase 2B: Permission Semantic Analysis
- Phase 3A: Rich Rule Display Format with BIONIC Reading & Professional Panels (terminal-focused)
- Phase 6: Code Quality & Optimization (function extraction, DRY improvements)

**🔄 WITHIN SCOPE & NEXT:**
- Phase 3B: Practical Display Features (filtering, sorting)
- Phase 4: Testing & Quality Assurance

**✅ WITHIN SCOPE & PLANNED:**
- Phase 4: Testing & Quality Assurance
- Phase 5: Enhanced Documentation & Architecture Overview

**❌ OUT OF SCOPE (Moved to Future Research):**
- Complex event assembly and streaming correlation
- Real-time monitoring capabilities
- System behavior analysis and performance tracking
- Policy file analysis and automated recommendations
- Web interfaces and graphical dashboards

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