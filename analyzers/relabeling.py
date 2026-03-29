"""Relabeling tool failure detection."""

from __future__ import annotations
from .findings import Finding, FindingSeverity, FindingCategory

RELABELING_TYPES = frozenset({"semanage_t", "setfiles_t", "restorecon_t", "load_policy_t"})
RELABEL_PERMISSIONS = frozenset({"relabelfrom", "relabelto"})


def analyze_relabeling(denials: list) -> list[Finding]:
    affected = []
    total_events = 0
    tools = set()

    for i, d in enumerate(denials):
        log = d.get("log", {})
        scontext = str(log.get("scontext", ""))
        s_parts = scontext.split(":")
        s_type = s_parts[2] if len(s_parts) >= 3 else ""

        permission = log.get("permission", "")
        permissions = d.get("permissions", set())
        all_perms = permissions | {permission} if permission else permissions

        if s_type in RELABELING_TYPES and all_perms & RELABEL_PERMISSIONS:
            affected.append(i)
            total_events += d.get("count", 1)
            tools.add(log.get("comm", s_type))

    if affected:
        return [Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.RELABELING,
            title="Relabeling tools are being denied",
            description=(
                f"{len(affected)} denial groups ({total_events} events) show relabeling tools "
                f"({', '.join(sorted(tools))}) denied relabelfrom/relabelto permissions. "
                f"The system cannot fix its own labels. Relabeling will not resolve "
                f"these denials because the relabeling tools themselves are blocked."
            ),
            affected_groups=affected,
            investigation_hints=[
                "Run: rpm -V selinux-policy-mls (check for corrupted policy files)",
                "Run: fixfiles -v check (look for 'context is invalid' errors)",
                "Verify semanage_store_t files are accessible: ls -Z /var/lib/selinux/",
            ],
            evidence={"tools": sorted(tools), "total_events": total_events},
        )]
    return []
