"""
SELinux analysis and context parsing package for AVC Denial Analyzer.

Renamed from 'selinux' to 'avc_selinux' to avoid conflict with system
python3-libselinux package.

This package provides SELinux-specific functionality including context parsing,
type analysis, and semantic understanding of SELinux security policies.
"""

from .context import AvcContext
from .mls import MlsLevel, MlsRange, parse_mls_string, analyze_mls_relationship

__all__ = ["AvcContext", "MlsLevel", "MlsRange", "parse_mls_string", "analyze_mls_relationship"]