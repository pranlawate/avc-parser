"""
Findings analysis engine for AVC Denial Analyzer.

Detects systemic patterns across denial groups and surfaces key findings
for all output formats.
"""

from .findings import Finding, Findings, FindingSeverity, FindingCategory

__all__ = ["Finding", "Findings", "FindingSeverity", "FindingCategory", "run_all_analyzers"]


def run_all_analyzers(sorted_denials, policy_load_events=None):
    """Run all analyzers and collect findings."""
    from .labeling import analyze_labeling
    from .relabeling import analyze_relabeling
    from .boot_impact import analyze_boot_impact
    from .patterns import analyze_systemic_patterns
    from .recurrence import analyze_recurrence

    findings = Findings()
    findings.total_groups = len(sorted_denials)

    for analyzer in [
        analyze_labeling,
        analyze_relabeling,
        analyze_boot_impact,
        analyze_systemic_patterns,
    ]:
        for finding in analyzer(sorted_denials):
            findings.add(finding)

    if policy_load_events:
        for finding in analyze_recurrence(sorted_denials, policy_load_events):
            findings.add(finding)

    return findings
