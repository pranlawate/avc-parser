# AVC Parser Enhancement Roadmap

This document contains the comprehensive implementation plan for enhancing the AVC parser with auto-detection, correlation tracking, Rich Rule display format, and numerous other improvements.

## Overview

This roadmap was developed through extensive analysis of current limitations and user experience issues. The plan addresses:
- **Correlation Loss Problem**: Current deduplication loses PID-to-resource mapping (e.g., can't tell which PID maps to which target path)
- **Argument Logic Issues**: Edge cases with conflicting arguments, binary files, directory inputs
- **Display Format Limitations**: Current verbose format doesn't scale well across terminal sizes
- **User Experience**: Need for auto-detection, sorting options, and focus capabilities

## Design Decisions Made

### 1. Rich Rule Header Format (Selected)
**Chosen Format:**
```
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
Denied read, write on file

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/file1.html [Enforcing]
• PID 5678 (httpd-worker) denied 'write' to file /var/www/html/file2.html [Permissive]
```

**Why Selected:**
- Superior terminal responsiveness (Rich automatically handles width)
- Professional appearance across all terminal sizes
- Better copy-paste compatibility
- Integrates with existing color theme
- Automatic ASCII fallback built-in

**Alternative Considered:** Manual line separators, tabular format, header styles with ASCII characters
**Key Decision:** Keep "Unique Denial" terminology for semantic clarity

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

### 5. Color Theme Integration
- Continue professional green/cyan/white palette
- Rich Rule styling based on denial characteristics
- Context-aware formatting for different target classes

## Implementation Plan

### PHASE 1: Core Foundation & Quick Fixes

#### 1A. Immediate Code Quality
- [ ] **Code documentation**: Add docstrings and inline comments for maintainability
- [ ] **Argument validation enhancements**: Better error messages for invalid combinations
- [ ] **Signal handling**: Proper cleanup on Ctrl+C during long operations

#### 1B. Auto-Detection Feature
- [ ] Add new `--file` or `-f` argument that replaces `--raw-file` and `--avc-file`
- [ ] Implement file content analysis logic to detect format type
- [ ] Add detection for `type=AVC msg=audit(...)` patterns → pre-processed
- [ ] Default to raw audit.log treatment when patterns not found
- [ ] Extend existing file validation logic to new flag
- [ ] Maintain backward compatibility with existing `--raw-file` and `--avc-file` flags

### PHASE 2: Correlation Tracking Implementation
- [ ] Design correlation data structure to store individual event details
- [ ] Implement correlation storage alongside existing aggregated data
- [ ] Track all varying fields: pid, comm, exe, proctitle, path, dest_port, saddr, permission, permissive
- [ ] Maintain existing aggregated sets for backward compatibility
- [ ] Update deduplication logic to preserve correlation information
- [ ] Enhance JSON output to include correlations array

### PHASE 3: Rich Rule Display Format Implementation

#### 3A. Core Display Format
- [ ] Implement new Rich Rule Header format as default
- [ ] Add `--legacy-format` flag to preserve current output format
- [ ] Create compact view with correlation events display
- [ ] Preserve "Unique Denial" terminology for semantic clarity

#### 3B. Advanced Display Features
- [ ] Implement detailed view (`-d/--detailed`) with tree structure sub-details
- [ ] Add smart resource display based on tclass (file paths, network ports, D-Bus destinations)
- [ ] Integrate Rich Rule features: dynamic styling, context-aware formatting, responsive text handling, color integration
- [ ] Implement sorting options: default (recent first), `--sort count` (frequency first), `--sort chrono` (oldest first)
- [ ] **Add focus/filtering capabilities** *(Note: Revisit and finalize approach during implementation based on code state at that time)*
  - Consider: `--focus <id>`, `--process <name>`, `--path <pattern>`, `--frequent <threshold>`, `--recent <timeframe>`
  - Evaluate: Denial ID selection vs. pattern-based filtering vs. hybrid approach
  - Assess: Implementation complexity based on correlation tracking and display format changes

### PHASE 4: Testing & Validation
- [ ] **Unit tests**: Add comprehensive test suite for new features
- [ ] Test auto-detection with various file types and edge cases
- [ ] Verify correlation tracking accuracy for PID-path-permission mapping
- [ ] Test display formats across different terminal sizes (60, 80, 120+ columns)
- [ ] Validate `--legacy-format` maintains exact current behavior
- [ ] **Integration tests**: Test with real-world audit log scenarios
- [ ] **Cross-platform testing**: Verify behavior on different operating systems
- [ ] Ensure all existing functionality remains intact

### PHASE 5: Documentation & User Experience
- [ ] **README updates**: Document new features, correlation tracking, display formats
- [ ] **Help text improvements**: Update argument descriptions and examples for new flags
- [ ] **Usage examples**: Add examples showing auto-detection, detailed mode, legacy format
- [ ] **Migration guide**: Help users transition from old argument style to new format
- [ ] **Version management**: Update version strings and changelog

### PHASE 6: Performance & Robustness
- [ ] **Memory management**: Optimize for very large audit log files
- [ ] **Performance benchmarks**: Measure impact of correlation tracking
- [ ] **Progress indicators**: Show progress for large file processing
- [ ] **Graceful degradation**: Handle terminal capability limitations
- [ ] **Performance documentation**: Document behavior with large log files

### PHASE 7: Extended Features (Future Enhancements)

#### 7A. Architecture Improvements
- [ ] **Structured Logging**: Replace print statements with configurable logging framework
  - Add verbosity control (`-v`, `-q`, `--debug`)
  - Separate user output from debug/error logging
  - Clean JSON output (logs to stderr, JSON to stdout)
- [ ] **Type Safety**: Add full type hints throughout the codebase
- [ ] **Configuration File**: Support for user preferences and default settings

#### 7B. Feature Extensions
- [ ] **Extended Message Type Parsing**: Add support for `FANOTIFY`, `SELINUX_ERR`, and `USER_SELINUX_ERR` message types
- [ ] **Time Range Filtering**: Filter denials by date/time ranges
- [ ] **Context-Aware Grouping**: Group related denials by process or target
- [ ] **Export Formats**: CSV output options for integration with other tools
- [ ] **Filtering capabilities**: Filter by source context, target context, process name
- [ ] **Statistics mode**: Show denial frequency statistics and trends

#### 7C. Advanced UX Features
- [ ] **Color customization**: Allow users to customize color themes
- [ ] **Output formatting options**: Add compact vs. verbose modes
- [ ] **Shell completion**: Add bash/zsh completion support for new arguments

### PHASE 8: Development & Distribution
- [ ] **Input Validation**: Enhanced validation for malformed log entries
- [ ] **Development setup**: Instructions for contributors
- [ ] **Linting configuration**: Set up code style enforcement
- [ ] **Release process**: Document release procedure
- [ ] **Installation instructions**: Update for new dependencies/features

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

### Rich Library Features to Leverage
- **Automatic Width Management**: No manual terminal width calculations
- **Custom Styles and Colors**: Integrate with green/cyan/white theme
- **Alignment Options**: Center, left, right alignment for different contexts
- **Character Customization**: Different line styles for different denial types
- **Terminal Capability Detection**: Unicode support with ASCII fallback

### Format Comparison Analysis
- **Line Separator vs Header Style**: Line separator wins on terminal responsiveness, accessibility, color theming, tool integration
- **Unicode vs ASCII**: Unicode preferred with automatic ASCII fallback
- **Tabular vs Card Format**: Card format better for variable-length content

### Display Format Examples

#### Compact View (Default):
```
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
Denied read, write on file

Events:
• PID 1234 (httpd) denied 'read' to file /var/www/html/file1.html [Enforcing]
• PID 5678 (httpd-worker) denied 'write' to file /var/www/html/file2.html [Permissive]
```

#### Detailed View (`-d/--detailed`):
```
─────────── Unique Denial #1 • 2 occurrences • last seen 2 weeks ago ───────────
system_u:system_r:httpd_t:s0 → unconfined_u:object_r:default_t:s0
Denied read, write on file
Timeframe: 2025-09-04 18:19:00 → 2025-09-04 18:19:00

Detailed Events:
• PID 1234 (httpd) [/usr/sbin/httpd] denied 'read' to file /var/www/html/file1.html [Enforcing]
  ├─ Syscall: openat | Time: 18:19:00.303
  └─ Proctitle: /usr/sbin/httpd -DFOREGROUND

• PID 5678 (httpd-worker) [/usr/sbin/httpd] denied 'write' to file /var/www/html/file2.html [Permissive]
  ├─ Syscall: openat | Time: 18:19:00.303
  └─ Proctitle: /usr/sbin/httpd -DFOREGROUND
```

## Current Implementation Focus

**Phases 1-5**: Auto-detection + Correlation + Rich Display + Testing + Documentation

**Future Enhancements**: Phases 6-8 (Performance + Extended Features + Development Infrastructure)

## Key Benefits Expected

1. **Simplified UX**: Single `--file` flag eliminates user confusion about file types
2. **Correlation Clarity**: Solves PID-to-resource mapping problem completely
3. **Professional Output**: Rich Rule responsive format works across all terminal sizes
4. **Enhanced Analysis**: Optional detailed view for deeper investigation
5. **Legacy Support**: Existing users can continue using familiar format
6. **Future-Proof**: Rich integration provides foundation for advanced features

---

*This roadmap serves as the definitive guide for AVC parser enhancements and should be referenced throughout implementation to maintain consistency with design decisions and user experience goals.*