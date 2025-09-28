# AVC Parser Development Roadmap

## 🎯 Project Vision

SELinux AVC denial forensic analysis tool for security analysts, system administrators, and compliance auditors. Focus on post-incident log analysis with intelligent deduplication and clear correlation tracking.

## ✅ **COMPLETED PHASES**

### **Phase 1-4: Foundation (COMPLETED)**
Core parsing, validation, correlation, semantic analysis, and JSON normalization

### **Phase 5: Architecture & Quality Tools (COMPLETED - 2025-09-26)**
- Modularization: 4870-line monolith → 3-module architecture
- Ultra-fast development workflow with ruff migration (197x performance gain)
- Comprehensive testing framework with all tests passing

### **Phase 6: Critical Bug Fixes & UX (COMPLETED - 2025-09-26)**
- BIONIC readability improvements for dark backgrounds
- Enhanced error handling and user guidance
- Performance validation post-modularization

### **Phase 7: Comprehensive Test Coverage (COMPLETED - 2025-09-26)**
- Test suite expansion: 107 → 146 tests (+39 new tests)
- Regression prevention framework with automated validation
- Display layer, malformed log, and integration testing

### **Phase 8: Enhanced User Experience (COMPLETED - 2025-09-28)**
- Interactive pager mode (`--pager` flag) with color preservation
- Smart resource display with context-aware formatting
- **SELinux Policy Investigation Integration**: Auto-generated `sesearch` commands with copy-paste workflow

## 🔮 **NEXT PHASES**

### **🔄 PENDING EVALUATION**
**Quality Tools Enhancement**: Additional development tools (safety, vulture, radon, mypy, prospector)
- **Rationale**: Evaluate ROI vs complexity for advanced static analysis
- **Consideration**: Current ruff setup provides excellent coverage

**Report-Friendly Output**: Compact mode for documentation workflows
- **Rationale**: Alternative to Rich display for copy-paste and reporting
- **Consideration**: JSON output may already serve this need

### **📋 PLANNED PHASES**

**Phase 9: Integration & Performance Testing**
- Real-world scenario validation across distributions
- Performance benchmarking and optimization
- Cross-platform compatibility verification

**Phase 10: Enhanced Documentation** (✅ Substantially Complete)
- Comprehensive user guides and examples
- Developer documentation and architecture overview
- CLI reference and troubleshooting guides

**Phase 11: Distribution & Packaging**
- **11A**: RPM packaging for Fedora/RHEL/CentOS
- **11B**: PyPI module with modern Python packaging
- **11C**: Additional formats (Debian, AUR, containers)
- **11D**: Release automation and cross-platform testing

## 🚫 **OUT OF SCOPE**

**Explicitly excluded from project scope:**
- Real-time monitoring capabilities
- Web interfaces and graphical dashboards
- Policy file analysis and automated recommendations
- Complex event streaming and live correlation
- System behavior analysis beyond audit logs

## 📊 **Success Metrics**

**Current Status**: Production-ready forensic analysis tool
- **Architecture**: Clean modular design (3 modules)
- **Testing**: 146 comprehensive tests with regression prevention
- **Performance**: Sub-second analysis of large audit logs
- **User Experience**: Professional Rich display with policy investigation workflow

**Distribution Goals**:
- RPM packages in Fedora/EPEL repositories
- PyPI module for cross-platform development
- Comprehensive documentation and examples

## 🛠 **Development Workflow**

**Quality Assurance**: Ultra-fast ruff-based validation
**Testing**: Automated regression prevention framework
**Architecture**: Modular design with clear separation of concerns
**Documentation**: User-focused guides with technical implementation details

---

*For detailed implementation specifications, see [FEATURE_DECISIONS.md](FEATURE_DECISIONS.md)*
*For user-facing features and examples, see [README.md](README.md)*