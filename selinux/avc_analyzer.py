"""
OOP wrapper for AVC Parser - Integration adapter for sos-data-extractor
Provides object-oriented interface while leveraging existing functional implementation
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint


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
        self.parser_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "parse_avc.py"
        )

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
            # Run parse_avc.py with JSON output to get structured data
            result = subprocess.run(
                ["python3", self.parser_path, "--file", self.audit_log, "--json"],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                if "No AVC events found" in result.stdout or "No AVC events found" in result.stderr:
                    rprint("[green]No SELinux AVC denials found - system is compliant[/green]")
                    return True
                else:
                    self.console.print(f"[red]Error running AVC parser: {result.stderr}[/red]")
                    return False

            # Parse JSON output
            data = json.loads(result.stdout)
            self.denials = data.get("unique_denials", [])

            if not self.denials:
                rprint("[green]No SELinux AVC denials found - system is compliant[/green]")
                return True

            self._generate_summary()
            self._display_summary_table()

            return True

        except json.JSONDecodeError as e:
            self.console.print(f"[red]Error parsing AVC data: {e}[/red]")
            return False
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
            list: Critical denial events (denials with high occurrence counts)
        """
        # Consider denials with count > 10 as critical
        return [d for d in self.denials if d.get('count', 0) > 10]

    def generate_brief_report(self) -> str:
        """
        Generate executive summary report using parse_avc.py --report brief

        Returns:
            str: Brief report text
        """
        if not self.denials:
            return "No SELinux denials detected"

        try:
            result = subprocess.run(
                ["python3", self.parser_path, "--file", self.audit_log, "--report", "brief"],
                capture_output=True,
                text=True,
                check=False
            )
            return result.stdout if result.returncode == 0 else "Error generating brief report"
        except Exception:
            return "Error generating brief report"

    def generate_technical_report(self) -> str:
        """
        Generate detailed technical report with remediation steps using parse_avc.py --report sealert

        Returns:
            str: Technical sealert-style report
        """
        if not self.denials:
            return "No SELinux denials detected"

        try:
            result = subprocess.run(
                ["python3", self.parser_path, "--file", self.audit_log, "--report", "sealert"],
                capture_output=True,
                text=True,
                check=False
            )
            return result.stdout if result.returncode == 0 else "Error generating technical report"
        except Exception:
            return "Error generating technical report"

    def _generate_summary(self):
        """Generate summary statistics from denials"""
        # Extract process names from log data
        processes = set()
        target_types = set()
        for denial in self.denials:
            log = denial.get('log', {})
            if 'comm' in log:
                processes.add(log['comm'])
            if 'tcontext_type' in log:
                target_types.add(log['tcontext_type'])

        self.summary = {
            "total_denials": len(self.denials),
            "unique_types": len(target_types),
            "processes": len(processes),
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
