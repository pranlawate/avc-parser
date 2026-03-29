"""Boot-blocking denial detection."""

from __future__ import annotations
from .findings import Finding, FindingSeverity, FindingCategory

BOOT_CRITICAL_TYPES = frozenset({
    "init_t", "kmod_t", "mount_t", "systemd_modules_load_t",
    "udev_t", "fsadm_t", "lvm_t", "plymouthd_t", "systemd_t",
    "systemd_sysctl_t", "systemd_tmpfiles_t",
})

ESSENTIAL_TARGET_TYPES = frozenset({
    "fixed_disk_device_t", "removable_device_t", "modules_dep_t",
    "modules_conf_t", "lib_t", "bin_t", "etc_t", "root_t",
    "ld_so_cache_t", "boot_t", "unlabeled_t",
})


def analyze_boot_impact(denials: list) -> list[Finding]:
    affected = []
    total_events = 0
    blocked_services = set()

    for i, d in enumerate(denials):
        log = d.get("log", {})
        scontext = str(log.get("scontext", ""))
        tcontext = str(log.get("tcontext", ""))
        s_parts = scontext.split(":")
        t_parts = tcontext.split(":")
        s_type = s_parts[2] if len(s_parts) >= 3 else ""
        t_type = t_parts[2] if len(t_parts) >= 3 else ""

        if s_type in BOOT_CRITICAL_TYPES and t_type in ESSENTIAL_TARGET_TYPES:
            affected.append(i)
            total_events += d.get("count", 1)
            blocked_services.add(log.get("comm", s_type))

    if affected:
        return [Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.BOOT_IMPACT,
            title="Boot-blocking denials detected",
            description=(
                f"{len(affected)} denial groups ({total_events} events) block "
                f"boot-critical services ({', '.join(sorted(blocked_services)[:5])}) "
                f"from accessing essential system resources. "
                f"Switching to enforcing mode with these denials will prevent boot."
            ),
            affected_groups=affected,
            investigation_hints=[
                "Do NOT switch to enforcing mode until these denials are resolved",
                f"View boot-blocking denials: avc-parser -f <file> --source {','.join(sorted(blocked_services)[:5])}",
                "Focus on resolving labeling issues first (if present), then policy gaps",
            ],
            evidence={"blocked_services": sorted(blocked_services), "total_events": total_events},
        )]
    return []
