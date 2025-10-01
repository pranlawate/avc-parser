"""
OOP wrapper for AVC Parser - Integration adapter for sos-data-extractor
Provides object-oriented interface while leveraging existing functional implementation
"""

import os
import json
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint

# Import our existing functional modules
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validators.file_validator import validate_file_path
from utils.file_utils import read_audit_log, detect_format
from detectors.anomaly_detector import detect_anomalies
from formatters.report_formatter import format_brief_report, format_sealert_report


class AVCAnalyzer:
    """
    Object-oriented interface for SELinux AVC denial analysis.
    Compatible with sos-data-extractor's class-based architecture.

    Usage in sos-data-extractor:
        from selinux.avc_analyzer import AVCAnalyzer

        analyzer = AVCAnalyzer(sos_dir)
        analyzer.analyze_avc_denials()
    """

    def __init__(self, sos_dir: str):
        """
        Initialize AVC Analyzer with sos report directory

        Args:
            sos_dir: Path to extracted sos report directory
        """
        self.sos_dir = sos_dir
        self.audit_log = os.path.join(sos_dir, "var", "log", "audit", "audit.log")
        self.console = Console()
        self.denials = []
        self.summary = {}

    def analyze_avc_denials(self) -> bool:
        """
        Main analysis method - finds and analyzes AVC denials

        Returns:
            bool: True if analysis successful, False otherwise
        """
        if not os.path.exists(self.audit_log):
            rprint("[yellow]No audit log found - SELinux may not be enabled[/yellow]")
            return False

        try:
            # Use our existing functional code
            from parse_avc import parse_audit_log, process_denials

            # Parse audit log
            raw_denials = parse_audit_log(self.audit_log)

            if not raw_denials:
                rprint("[green]No SELinux AVC denials found - system is compliant[/green]")
                return True

            # Process and store results
            self.denials = process_denials(raw_denials)
            self._generate_summary()

            # Display results
            self._display_summary_table()

            return True

        except Exception as e:
            self.console.print(f"[red]Error analyzing AVC denials: {e}[/red]")
            return False

    def get_denials_json(self) -> Dict:
        """
        Export denials as JSON for programmatic access

        Returns:
            dict: JSON-formatted denial data
        """
        return {
            "unique_denials": self.denials,
            "summary": self.summary
        }

    def get_critical_denials(self) -> List[Dict]:
        """
        Get high-priority denials requiring immediate attention

        Returns:
            list: Critical denial events
        """
        # Use our existing anomaly detector
        anomalies = detect_anomalies(self.denials)
        return [d for d in self.denials if d.get('is_anomaly', False)]

    def generate_brief_report(self) -> str:
        """
        Generate executive summary report

        Returns:
            str: Brief report text
        """
        if not self.denials:
            return "No SELinux denials detected"

        return format_brief_report(self.denials, self.summary)

    def generate_technical_report(self) -> str:
        """
        Generate detailed technical report with remediation steps

        Returns:
            str: Technical sealert-style report
        """
        if not self.denials:
            return "No SELinux denials detected"

        return format_sealert_report(self.denials, self.summary)

    def _generate_summary(self):
        """Generate summary statistics from denials"""
        self.summary = {
            "total_denials": len(self.denials),
            "unique_types": len(set(d.get('tcontext_type', '') for d in self.denials)),
            "processes": len(set(d.get('comm', '') for d in self.denials)),
            "critical_count": len(self.get_critical_denials())
        }

    def _display_summary_table(self):
        """Display rich table with denial summary"""
        table = Table(title="SELinux AVC Denial Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")

        table.add_row("Total Denials", str(self.summary.get('total_denials', 0)))
        table.add_row("Unique Target Types", str(self.summary.get('unique_types', 0)))
        table.add_row("Affected Processes", str(self.summary.get('processes', 0)))
        table.add_row("Critical Issues", str(self.summary.get('critical_count', 0)))

        self.console.print(table)

        if self.summary.get('critical_count', 0) > 0:
            rprint("[red]⚠️  Critical SELinux denials detected - review recommended[/red]")


# Example standalone usage for testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python avc_analyzer.py <sos_directory>")
        sys.exit(1)

    analyzer = AVCAnalyzer(sys.argv[1])
    analyzer.analyze_avc_denials()
