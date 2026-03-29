"""Denial recurrence detection across policy reloads."""

from __future__ import annotations

from collections import Counter

from .findings import Finding, FindingCategory, FindingSeverity


def analyze_recurrence(denials: list, policy_load_events: list) -> list[Finding]:
    if not policy_load_events:
        return []

    epoch_boundaries = sorted(
        [e["datetime_obj"] for e in policy_load_events if e.get("datetime_obj")],
    )
    if not epoch_boundaries:
        return []

    before_counts = Counter()
    after_counts = Counter()

    for d in denials:
        log = d.get("log", {})
        tcontext = str(log.get("tcontext", ""))
        t_parts = tcontext.split(":")
        t_type = t_parts[2] if len(t_parts) >= 3 else ""
        count = d.get("count", 1)

        first_seen = d.get("first_seen_obj")
        last_seen = d.get("last_seen_obj")

        if first_seen and first_seen < epoch_boundaries[0]:
            before_counts[t_type] += count

        if last_seen and last_seen >= epoch_boundaries[-1]:
            after_counts[t_type] += count

    findings = []
    for t_type in before_counts:
        if t_type in after_counts and before_counts[t_type] > 0:
            before = before_counts[t_type]
            after = after_counts[t_type]

            if after < before * 0.3:
                continue

            if after >= before * 0.7:
                trend = "stable"
            else:
                trend = "decreasing"

            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RECURRENCE,
                    title=f"Recurring denials for {t_type} across policy reloads",
                    description=(
                        f"{t_type} denials appeared before and after policy reload(s). "
                        f"Before: {before} events, after: {after} events (trend: {trend}). "
                        f"Relabeling did not fully resolve these denials."
                    ),
                    investigation_hints=[
                        f"Run: fixfiles -v check | grep {t_type}",
                        "Check if file_contexts.bin contains invalid contexts for this type",
                        "Verify labels after relabel: find / -context '*unlabeled_t*' 2>/dev/null | head",
                    ],
                    evidence={"target_type": t_type, "before": before, "after": after, "trend": trend},
                )
            )
    return findings
