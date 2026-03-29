"""Labeling issue detection: unlabeled_t files and MLS level inconsistency."""

from __future__ import annotations
from .findings import Finding, FindingSeverity, FindingCategory

CORE_SYSTEM_TYPES = frozenset({
    "etc_t", "lib_t", "bin_t", "ld_so_cache_t",
    "modules_dep_t", "modules_conf_t", "usr_t",
})


def analyze_labeling(denials: list) -> list[Finding]:
    findings = []
    _check_unlabeled(denials, findings)
    _check_mls_inconsistency(denials, findings)
    return findings


def _check_unlabeled(denials, findings):
    unlabeled_groups = []
    unlabeled_events = 0
    for i, d in enumerate(denials):
        tcontext = str(d.get("log", {}).get("tcontext", ""))
        parts = tcontext.split(":")
        ttype = parts[2] if len(parts) >= 3 else ""
        if ttype == "unlabeled_t":
            unlabeled_groups.append(i)
            unlabeled_events += d.get("count", 1)

    if len(unlabeled_groups) >= 3 or unlabeled_events >= 10:
        is_permissive = any(
            denials[i].get("log", {}).get("permissive") == "1"
            for i in unlabeled_groups
        )
        findings.append(Finding(
            severity=FindingSeverity.WARNING if is_permissive else FindingSeverity.CRITICAL,
            category=FindingCategory.LABELING,
            title="Widespread unlabeled_t files",
            description=(
                f"{len(unlabeled_groups)} denial groups ({unlabeled_events} events) "
                f"target unlabeled_t. Files have lost their SELinux labels, "
                f"indicating a labeling breakdown that relabeling should fix."
            ),
            affected_groups=unlabeled_groups,
            investigation_hints=[
                "Run: fixfiles -v check",
                "Run: rpm -V selinux-policy-*",
                "Run: restorecon -Rv / (to relabel all files)",
            ],
            evidence={"unlabeled_groups": len(unlabeled_groups), "unlabeled_events": unlabeled_events},
        ))


def _check_mls_inconsistency(denials, findings):
    wrong_level_types = set()
    affected_groups = []
    total_events = 0

    for i, d in enumerate(denials):
        log = d.get("log", {})
        tcontext = str(log.get("tcontext", ""))
        scontext = str(log.get("scontext", ""))
        t_parts = tcontext.split(":")
        s_parts = scontext.split(":")

        ttype = t_parts[2] if len(t_parts) >= 3 else ""
        t_mls = ":".join(t_parts[3:]) if len(t_parts) > 3 else ""
        s_mls_raw = s_parts[3] if len(s_parts) > 3 else ""
        s_mls_low = s_mls_raw.split("-")[0] if "-" in s_mls_raw else s_mls_raw

        if ttype in CORE_SYSTEM_TYPES and t_mls and "s15" in t_mls and s_mls_low in ("s0", ""):
            wrong_level_types.add(ttype)
            affected_groups.append(i)
            total_events += d.get("count", 1)

    if len(wrong_level_types) >= 5:
        findings.append(Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.LABELING,
            title="MLS labeling inconsistency: system files at wrong level",
            description=(
                f"{len(wrong_level_types)} core system types ({', '.join(sorted(wrong_level_types))}) "
                f"are labeled at s15 (SystemHigh) while processes run at s0. "
                f"This indicates a file_contexts compilation issue or failed relabeling."
            ),
            affected_groups=affected_groups,
            investigation_hints=[
                "Run: fixfiles -v check (look for 'context is invalid' errors)",
                "Run: rpm -V selinux-policy-mls",
                "Run: fixfiles -F relabel (check output for invalid context warnings)",
            ],
            evidence={"wrong_types": sorted(wrong_level_types), "total_events": total_events},
        ))
