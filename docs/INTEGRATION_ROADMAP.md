# Integration Roadmap: avc-parser → sos-report-parser

**Status**: Planning Complete, Ready for Implementation
**Branch**: test-oop-wrapper
**Target Integration**: sos-report-parser (Red Hat deployment)

---

## Executive Summary

This roadmap outlines the technical strategy for integrating selinux-avc-parser into sos-report-parser.

**Core Strategy**: Modular integration with clear attribution, maintaining standalone project independence.

---

## 1. Integration Goals

### Technical Requirements

- **sos-report-parser**: Approved for integration
- **Integration needs**: OOP interface + tabular output format
- **Approach**: Copy files with clear attribution

### Integration Benefits

✅ **Clear Attribution**
- Author name in runtime output (JSON metadata, help text)
- Git history preservation
- Documentation crediting original author

✅ **Independent Development**
- Standalone repo remains independent
- Continue development on separate timeline
- PyPI publishing as separate project

✅ **Modular Architecture**
- Isolated in separate directory for easy maintenance
- Clean interfaces (OOP wrapper + CLI function)
- No tight coupling with host project

### Project Benefits

✅ **OOP Interface** - avc_analyzer.py wrapper for OOP architecture
✅ **Table Format** - `--report table` option for tabular display
✅ **No Dependencies** - Copy files approach, no PyPI dependencies
✅ **Improved Analysis** - Smart deduplication and correlation
✅ **Easy Integration** - selinux_analyze() function ready to use

---

## 2. Technical Implementation Plan

### Phase 1: Add Table Format Option

**Location**: parse_avc.py (test-oop-wrapper branch)
**Status**: Not started
**Estimated Effort**: 1-2 hours

**Implementation**:
```python
# Add to argument parser
parser.add_argument(
    '--report',
    choices=['brief', 'technical', 'sealert', 'table'],  # Add 'table'
    help='Generate formatted report'
)

# Add display function
def display_denial_tables(console, denials):
    """Display denials in simple table format for OOP integration"""
    for i, denial in enumerate(denials, 1):
        table = Table(title=f"AVC Denial #{i}")
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")

        table.add_row("Process", denial['comm'])
        table.add_row("Action", denial['permission'])
        table.add_row("Target", denial.get('path', 'N/A'))
        table.add_row("Source Context", denial['scontext'])
        table.add_row("Target Context", denial['tcontext'])
        table.add_row("Count", str(denial['count']))

        if denial.get('timestamps'):
            first = denial['timestamps'][0]
            last = denial['timestamps'][-1]
            table.add_row("First Seen", first)
            table.add_row("Last Seen", last)

        console.print(table)
        console.print()  # Spacing between tables

# Add to main() report handling
if args.report == 'table':
    display_denial_tables(console, unique_denials)
    return
```

**Testing**:
```bash
python3 parse_avc.py --file test_data/audit.log --report table
```

**Why**: Satisfies primary dev's "tabular format" requirement without degrading rich analysis features.

---

### Phase 2: Runtime Attribution

**Location**: parse_avc.py
**Status**: Not started
**Estimated Effort**: 30 minutes

**Implementation**:

```python
# Add metadata to JSON output (in main() when args.json is True)
output_data = {
    "metadata": {
        "tool": "selinux-avc-parser",
        "version": "1.6.0",
        "author": "Pranav Lawate",
        "repository": "https://github.com/plawate/avc-parser",
        "license": "MIT"
    },
    "summary": {
        "total_denials": len(all_denials),
        "unique_denials": len(unique_denials),
        # ... rest of summary
    },
    "unique_denials": denial_list
}

# Update help description
parser = argparse.ArgumentParser(
    description='SELinux AVC Parser by Pranav Lawate - Intelligent AVC denial analysis with smart deduplication',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent('''
        Examples:
          %(prog)s --file /var/log/audit/audit.log --report brief
          %(prog)s --file audit.log --json

        Project: https://github.com/plawate/avc-parser
        Author: Pranav Lawate
    ''')
)

# Add version argument
parser.add_argument(
    '--version',
    action='version',
    version='%(prog)s 1.6.0 by Pranav Lawate'
)
```

**Testing**:
```bash
python3 parse_avc.py --help  # Check author in description
python3 parse_avc.py --version  # Check version string
python3 parse_avc.py --file test_data/audit.log --json | jq .metadata  # Check JSON metadata
```

**Why**: Every time someone uses the tool or sees output, your name is there. More effective than LICENSE files nobody reads.

---

### Phase 3: Integration Package Structure

**Location**: To be provided to sos-report-parser team
**Status**: Not started
**Estimated Effort**: 1 hour

**Directory Structure**:
```
sos-report-parser/
└── selinux_analysis/              # New directory in their repo
    ├── __init__.py                # Package initialization with attribution
    ├── README.md                  # Integration documentation
    ├── parse_avc.py               # Your full tool (copy from avc-parser)
    ├── avc_analyzer.py            # OOP wrapper (already created)
    └── selinux_analyzer.py        # CLI integration function (already created)
```

**File: selinux_analysis/__init__.py**:
```python
"""
SELinux AVC Analysis Module

This module integrates selinux-avc-parser by Pranav Lawate.
Original project: https://github.com/plawate/avc-parser

Provides intelligent AVC denial analysis with:
- Smart deduplication and correlation
- Multiple output formats (JSON, tables, reports)
- Advanced filtering and sorting
- Automatic sesearch command generation
"""

__version__ = "1.6.0"
__author__ = "Pranav Lawate"
__source__ = "https://github.com/plawate/avc-parser"

from .avc_analyzer import AVCAnalyzer
from .selinux_analyzer import selinux_analyze

__all__ = ['AVCAnalyzer', 'selinux_analyze']
```

**File: selinux_analysis/README.md**:
```markdown
# SELinux Analysis Module

This module integrates [selinux-avc-parser](https://github.com/plawate/avc-parser) by **Pranav Lawate** into sos-report-parser.

## Overview

Provides intelligent SELinux AVC denial analysis with advanced features:
- Smart deduplication based on context patterns
- Correlation of related denials
- Multiple output formats (JSON, tables, reports)
- Advanced filtering by process, path, context
- Automatic sesearch command generation

## Usage

### Programmatic (OOP Interface)

```python
from selinux_analysis import AVCAnalyzer

analyzer = AVCAnalyzer(sos_dir)
analyzer.analyze_avc_denials()  # Display Rich table
json_data = analyzer.get_denials_json()
```

### CLI Integration

```python
from selinux_analysis import selinux_analyze

# Simple table output
selinux_analyze(sos_dir, report='table')

# Advanced filtering
selinux_analyze(sos_dir, report='brief', process='httpd', path='/var/www/*')
```

## Credits

- **Author**: Pranav Lawate
- **Original Project**: https://github.com/plawate/avc-parser
- **License**: MIT

For standalone usage with additional features, see the original repository.
```

**Integration into their shells/selinux.py**:
```python
from selinux_analysis import selinux_analyze

def selinux_shell(sos_dir: str, userQuery: str) -> bool:
    """SELinux analysis shell with AVC denial support"""

    # Parse user query for commands
    if "avc" in userQuery.lower() or "denial" in userQuery.lower():
        # Use advanced AVC analysis (your tool)
        # Default to table format for consistency with their tool
        selinux_analyze(sos_dir, report='table')
        return True

    elif "getenforce" in userQuery.lower():
        # Their existing enforcement check
        return check_selinux_status(sos_dir)

    else:
        # Default: show both status and AVC analysis
        check_selinux_status(sos_dir)
        selinux_analyze(sos_dir, report='table')
        return True
```

**Why**:
- Isolated in separate directory (easy to disable if issues)
- Clear attribution in __init__.py and README
- Default to 'table' format for their users
- Advanced features available for power users

---

### Phase 4: Integration Handoff

**Integration Package Contents**:
- selinux_analysis/ directory with all necessary files
- README.md with usage instructions
- Example integration code
- Test cases demonstrating functionality

**Integration Documentation**:
- API reference for selinux_analyze() function
- OOP interface documentation (AVCAnalyzer class)
- Performance considerations
- Error handling guidelines

---

### Phase 5: Maintain Standalone Independence

**Standalone Repository** (https://github.com/plawate/avc-parser):

**Continue Development**:
- Add features independently (not driven by integration requirements)
- Experiment with advanced analysis techniques
- Keep full feature set unconstrained by integration use case

**Update README.md** (add section):
```markdown
## Production Usage

This tool is integrated into Red Hat's [sos-report-parser](https://github.com/their-org/sos-report-parser) for automated SOS report analysis.

For standalone usage with full feature access, install directly:
```bash
pip install selinux-avc-parser
```

**PyPI Publishing** (when YOU decide):
- Publish to PyPI on your timeline
- Use for resume/portfolio
- Increases visibility and credibility

**Documentation**:
- Maintain comprehensive docs in standalone repo
- Reference integration but emphasize standalone capabilities
- Use for demonstrating technical writing skills

**Git Workflow**:
```bash
# Your development flow remains unchanged
git checkout main
git pull
git checkout -b feature/new-analysis
# ... make changes ...
git commit -m "Add new feature"
git push origin feature/new-analysis

# When ready to update their integration (optional, your choice):
# Just notify them new version is available
# They can update selinux_analysis/ directory from your repo
```

**Why**:
- Maintains independent control over project direction
- Standalone version remains separate portfolio piece
- Future optionality for other integrations

---

## 3. Implementation Checklist

### Pre-Implementation
- [x] Strategic analysis complete
- [x] Integration goals defined
- [x] Roadmap documented
- [ ] Integration approval confirmed

### Phase 1: Table Format
- [ ] Add 'table' option to --report argument
- [ ] Implement display_denial_tables() function
- [ ] Test table output with sample data
- [ ] Commit to test-oop-wrapper branch

### Phase 2: Attribution
- [ ] Add metadata to JSON output
- [ ] Update help text with author info
- [ ] Add --version argument
- [ ] Test JSON metadata output
- [ ] Commit to test-oop-wrapper branch

### Phase 3: Integration Package
- [ ] Create selinux_analysis/__init__.py
- [ ] Create selinux_analysis/README.md
- [ ] Copy parse_avc.py to integration package
- [ ] Copy avc_analyzer.py to integration package
- [ ] Copy selinux_analyzer.py to integration package
- [ ] Create example integration code for their shells/selinux.py
- [ ] Document in separate integration guide

### Phase 4: Integration Handoff
- [ ] Provide integration package documentation
- [ ] Coordinate integration timeline
- [ ] Provide integration package files
- [ ] Support integration testing

### Phase 5: Standalone Maintenance
- [ ] Update standalone README with integration reference
- [ ] Continue development on standalone features
- [ ] Plan PyPI publishing timeline
- [ ] Update portfolio/resume with achievement

---

## 4. Success Metrics

### Attribution Verification

- [ ] Author name appears in `python3 parse_avc.py --help`
- [ ] Author name appears in `python3 parse_avc.py --version`
- [ ] Author name appears in JSON metadata
- [ ] README.md in selinux_analysis/ includes proper credits
- [ ] __init__.py has authorship information

### Independence Verification

- [ ] Standalone repo remains separate
- [ ] Independent commit access to avc-parser repo
- [ ] Integration is a copy, not a submodule
- [ ] Can develop standalone features independently

### Integration Success

- [ ] OOP interface works (AVCAnalyzer class)
- [ ] Table format available (--report table)
- [ ] Easy integration (selinux_analyze() function)
- [ ] No PyPI dependencies required
- [ ] Better analysis than basic grep approach
- [ ] Doesn't break existing functionality
- [ ] Performance acceptable for SOS report sizes

### Project Isolation

- [ ] Integration isolated in selinux_analysis/ directory
- [ ] Standalone version proves code works if issues arise
- [ ] Git history preserved in both repos
- [ ] Can disable integration easily if needed

---

## 5. Risk Management

### Risk: Attribution Lost

**Mitigation**:
- Runtime attribution (author name in output)
- Code comments with authorship
- README in integration directory
- Git history in both repos preserves timeline

**Contingency**:
- Git timestamps in avc-parser repo establish original authorship
- Runtime output includes author name
- Standalone repo proves independent work

### Risk: Integration Subsumes Standalone Project

**Mitigation**:
- Maintain separate standalone repo
- Continue independent development
- Integration is a COPY, not a merge
- Standalone README emphasizes full feature set
- Plan PyPI publishing independently

**Contingency**:
- Point to different use cases (standalone vs integrated)
- Emphasize maintenance benefits of separation
- Standalone version offers features not needed in integration

### Risk: Integration Causes Bugs

**Mitigation**:
- Isolated in selinux_analysis/ directory
- Extensive testing before integration
- Standalone version proves code works
- Can disable easily (remove import)
- Error handling in wrapper code

**Contingency**:
- Fix quickly in standalone repo
- Provide updated version
- If unfixable, can disable selinux_analysis/
- Isolate whether bug is in integration or core tool

### Risk: Technical Implementation Disputes

**Mitigation**:
- Provide both OOP and functional interfaces
- Default to table format for consistency
- Document all features clearly
- Keep integration simple and modular

**Contingency**:
- Offer to adjust wrapper (not core tool)
- Provide examples demonstrating functionality
- Standalone version demonstrates tool quality

---

## 6. Timeline

**Week 1** (Current):
- Complete Phase 1: Add table format
- Complete Phase 2: Runtime attribution
- Test both phases thoroughly
- Commit to test-oop-wrapper branch

**Week 2**:
- Complete Phase 3: Create integration package
- Coordinate integration timeline
- Prepare integration documentation

**Week 3**:
- Provide integration package
- Support integration testing
- Address integration questions
- Update standalone README

**Week 4+**:
- Monitor integration deployment
- Continue standalone development
- Plan PyPI publishing timeline

---

## 7. Decision Log

**Why Copy Files vs PyPI Dependency?**
- Simpler integration approach
- No dependency approval process needed
- Easier for integration team to maintain
- Update timeline remains flexible

**Why Maintain Standalone Repo?**
- Independent project development
- Full control over feature direction
- Separate portfolio piece
- Future optionality for other integrations

**Why Runtime Attribution?**
- More visible than LICENSE files
- Every tool usage shows authorship
- Survives copy/paste operations
- Effective attribution mechanism

**Why Table Format Addition?**
- Minimal implementation effort (few hours)
- Satisfies integration requirements
- Doesn't degrade existing features
- Shows API flexibility

---

## 8. Reference Links

**Project Repositories**:
- avc-parser: https://github.com/plawate/avc-parser
- Integration branch: test-oop-wrapper
- sos-report-parser: [URL TBD]

**Related Documentation**:
- [SOS_INTEGRATION.md](./SOS_INTEGRATION.md) - Original integration approach
- [SOS_CLI_INTEGRATION.md](./SOS_CLI_INTEGRATION.md) - CLI wrapper documentation
- [WRAPPER_EXPLANATION.md](./WRAPPER_EXPLANATION.md) - Technical details of OOP wrapper

**Key Files**:
- selinux/avc_analyzer.py - OOP wrapper class
- selinux/selinux_analyzer.py - CLI integration function
- examples/sos_integration_demo.py - Usage examples

---

## 9. Technical Context

**avc-parser**:
- Architecture: Functional design
- Features: Smart deduplication, correlation, rich analysis
- Version: 1.6.0 stable
- Arguments: 14 CLI arguments fully supported

**sos-report-parser**:
- Architecture: OOP design
- Current SELinux support: Basic grep-based analysis
- Status: Approved for integration

**Integration Approach**:
- Pattern: Adapter pattern with subprocess calls
- Interface: Both OOP (AVCAnalyzer) and functional (selinux_analyze)
- Isolation: Separate selinux_analysis/ directory
- Dependencies: None (copy files approach)

---

## 10. Project Information

**Project Owner**: Pranav Lawate
**Primary Repository**: https://github.com/plawate/avc-parser
**Integration Target**: sos-report-parser (Red Hat)
**License**: MIT

**This roadmap is a living document. Update as strategy evolves.**

---

*Last Updated: 2025-10-04*
*Status: Ready for Implementation*
