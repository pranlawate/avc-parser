"""Findings data model for key findings analysis."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class FindingSeverity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

    def __lt__(self, other):
        order = {FindingSeverity.CRITICAL: 0, FindingSeverity.WARNING: 1, FindingSeverity.INFO: 2}
        return order[self] < order[other]


class FindingCategory(Enum):
    LABELING = "labeling"
    RELABELING = "relabeling"
    BOOT_IMPACT = "boot_impact"
    SYSTEMIC = "systemic"
    RECURRENCE = "recurrence"


@dataclass
class Finding:
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    affected_groups: list[int] = field(default_factory=list)
    investigation_hints: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


class Findings:
    """Collection of findings with per-denial tag indexing."""

    def __init__(self):
        self.items: list[Finding] = []
        self.tags: dict[int, list[Finding]] = {}

    def add(self, finding: Finding):
        self.items.append(finding)
        self.items.sort(key=lambda f: f.severity)
        for idx in finding.affected_groups:
            if idx not in self.tags:
                self.tags[idx] = []
            self.tags[idx].append(finding)

    def remediation_counts(self, total_groups: int) -> dict:
        labeling_groups = set()
        relabeling_groups = set()
        for f in self.items:
            if f.category == FindingCategory.LABELING:
                labeling_groups.update(f.affected_groups)
            elif f.category == FindingCategory.RELABELING:
                relabeling_groups.update(f.affected_groups)
        relabel_fixable = labeling_groups - relabeling_groups
        return {
            "relabel_fixable": len(relabel_fixable),
            "broken_source": len(relabeling_groups),
            "policy_issue": total_groups - len(relabel_fixable) - len(relabeling_groups),
        }
