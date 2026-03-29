"""Systemic pattern detection: many processes sharing one root cause."""

from __future__ import annotations
from .findings import Finding, FindingSeverity, FindingCategory


def analyze_systemic_patterns(denials: list) -> list[Finding]:
    target_to_sources = {}

    for i, d in enumerate(denials):
        log = d.get("log", {})
        tcontext = str(log.get("tcontext", ""))
        scontext = str(log.get("scontext", ""))
        t_parts = tcontext.split(":")
        s_parts = scontext.split(":")
        t_type = t_parts[2] if len(t_parts) >= 3 else ""
        t_mls = ":".join(t_parts[3:]) if len(t_parts) > 3 else ""
        s_type = s_parts[2] if len(s_parts) >= 3 else ""

        key = (t_type, t_mls)
        if key not in target_to_sources:
            target_to_sources[key] = {"sources": set(), "groups": [], "events": 0}
        target_to_sources[key]["sources"].add(s_type)
        target_to_sources[key]["groups"].append(i)
        target_to_sources[key]["events"] += d.get("count", 1)

    findings = []
    for (t_type, t_mls), info in target_to_sources.items():
        if len(info["sources"]) >= 10:
            mls_note = f" at MLS level {t_mls}" if t_mls else ""
            findings.append(Finding(
                severity=FindingSeverity.WARNING,
                category=FindingCategory.SYSTEMIC,
                title=f"Systemic issue: {len(info['sources'])} processes denied on {t_type}",
                description=(
                    f"{len(info['sources'])} different process types are all denied access to "
                    f"{t_type}{mls_note} ({info['events']} total events). "
                    f"This indicates a labeling or policy infrastructure problem "
                    f"rather than individual process policy gaps."
                ),
                affected_groups=info["groups"],
                evidence={
                    "target_type": t_type,
                    "target_mls": t_mls,
                    "source_count": len(info["sources"]),
                    "total_events": info["events"],
                },
            ))
    return findings
