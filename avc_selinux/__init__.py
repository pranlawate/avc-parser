"""
SELinux analysis and context parsing package for AVC Denial Analyzer.

Renamed from 'selinux' to 'avc_selinux' to avoid conflict with system
python3-libselinux package.

This package provides SELinux-specific functionality including context parsing,
type analysis, and semantic understanding of SELinux security policies.
"""

from .context import AvcContext

__all__ = ["AvcContext"]