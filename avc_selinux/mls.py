"""
MLS/MCS security level parsing and comparison.

Parses SELinux MLS (Multi-Level Security) and MCS (Multi-Category Security)
labels into structured components for analysis and comparison.

Data structures mirror libsepol's mls_types.h:
  - MlsLevel  -> mls_level_t  (sensitivity + category set)
  - MlsRange  -> mls_range_t  (level[2]: low and high)

Parsing follows the algorithm in libsepol's mls.c (mls_context_to_sid)
and mcstrans's mls_level.c (mls_level_from_string).
"""

from __future__ import annotations

import re


class MlsLevel:
    """
    Single MLS security level: sensitivity + category set.

    Mirrors libsepol's mls_level_t (uint32_t sens + ebitmap_t cat).
    Categories are stored as a Python frozenset of ints for immutability.
    """

    __slots__ = ("sensitivity", "sensitivity_num", "categories", "_raw")

    def __init__(self, sensitivity: str, sensitivity_num: int, categories: frozenset[int]):
        self.sensitivity = sensitivity
        self.sensitivity_num = sensitivity_num
        self.categories = categories
        self._raw = None

    def dominates(self, other: MlsLevel) -> bool:
        """
        Check if this level dominates another.

        Mirrors libsepol mls_level_dom(l1, l2):
        l1 dominates l2 when l1.sens >= l2.sens AND l1.cats is superset of l2.cats.
        """
        return (
            self.sensitivity_num >= other.sensitivity_num
            and self.categories >= other.categories
        )

    def is_equal(self, other: MlsLevel) -> bool:
        """Mirrors libsepol mls_level_eq."""
        return (
            self.sensitivity_num == other.sensitivity_num
            and self.categories == other.categories
        )

    def is_incomparable(self, other: MlsLevel) -> bool:
        """Two levels are incomparable when neither dominates the other."""
        return not self.dominates(other) and not other.dominates(self)

    def __eq__(self, other) -> bool:
        if not isinstance(other, MlsLevel):
            return False
        return self.is_equal(other)

    def __repr__(self) -> str:
        cat_str = _format_categories(self.categories) if self.categories else ""
        return f"MlsLevel(sensitivity='{self.sensitivity}', categories='{cat_str}')"

    def __str__(self) -> str:
        cat_str = _format_categories(self.categories)
        if cat_str:
            return f"{self.sensitivity}:{cat_str}"
        return self.sensitivity

    def get_description(self) -> str:
        """Human-readable description of this level."""
        parts = [f"sensitivity {self.sensitivity}"]
        if self.categories:
            cat_count = len(self.categories)
            cat_str = _format_categories(self.categories)
            if cat_count == 1024:
                parts.append("all categories (c0.c1023)")
            elif cat_count > 10:
                parts.append(f"{cat_count} categories ({cat_str})")
            else:
                parts.append(f"categories {cat_str}")
        return ", ".join(parts)


class MlsRange:
    """
    MLS security range: low level to high level.

    Mirrors libsepol's mls_range_t (mls_level_t level[2]).
    level[0] = low, level[1] = high.
    If a context has only a single level (no hyphen), low == high.
    """

    __slots__ = ("low", "high", "_raw")

    def __init__(self, low: MlsLevel, high: MlsLevel):
        self.low = low
        self.high = high
        self._raw = None

    def is_valid(self) -> bool:
        """High must dominate low. Mirrors libsepol mls_context_isvalid."""
        return self.high.dominates(self.low)

    def contains(self, other: MlsRange) -> bool:
        """
        Check if this range contains another range.

        Mirrors libsepol mls_range_contains:
        self.low dominated by other.low AND other.high dominated by self.high.
        """
        return other.low.dominates(self.low) and self.high.dominates(other.high)

    def is_single_level(self) -> bool:
        """True if low and high are the same level."""
        return self.low.is_equal(self.high)

    def __eq__(self, other) -> bool:
        if not isinstance(other, MlsRange):
            return False
        return self.low == other.low and self.high == other.high

    def __repr__(self) -> str:
        return f"MlsRange(low={self.low!r}, high={self.high!r})"

    def __str__(self) -> str:
        if self.is_single_level():
            return str(self.low)
        return f"{self.low}-{self.high}"

    def get_description(self) -> str:
        """Human-readable description of this range."""
        if self.is_single_level():
            return self.low.get_description()
        return f"range from {self.low.get_description()} to {self.high.get_description()}"


def parse_mls_string(mls_string: str) -> MlsRange | None:
    """
    Parse an MLS/MCS string into an MlsRange.

    Handles all standard formats:
      - "s0"                     single sensitivity, no categories
      - "s0:c0.c1023"           sensitivity with category range
      - "s0:c3,c5,c10.c20"     sensitivity with disjoint categories
      - "s0-s0:c0.c1023"       range: low sensitivity to high with categories
      - "s0:c0-s0:c0.c1023"    range: both sides with categories

    Parsing follows libsepol mls.c (mls_context_to_sid) and
    mcstrans mls_level.c (mls_level_from_string).

    Args:
        mls_string: Raw MLS string from audit context

    Returns:
        MlsRange if parsing succeeds, None if input is empty or unparseable
    """
    if not mls_string or not mls_string.strip():
        return None

    mls_string = mls_string.strip()

    try:
        low_str, high_str = _split_range(mls_string)
        low = _parse_level(low_str)
        if low is None:
            return None

        if high_str:
            high = _parse_level(high_str)
            if high is None:
                return None
        else:
            high = MlsLevel(low.sensitivity, low.sensitivity_num, low.categories)

        result = MlsRange(low, high)
        result._raw = mls_string
        return result
    except (ValueError, IndexError):
        return None


def analyze_mls_relationship(
    source_range: MlsRange | None,
    target_range: MlsRange | None,
) -> str | None:
    """
    Analyze the MLS relationship between source and target contexts.

    Compares the effective levels (low side of range = process's current
    operating level) and explains the clearance vs effective level distinction
    when the source has a multi-level range.

    Returns a human-readable analysis string with educational context,
    or None if MLS is not a relevant factor.
    """
    if not source_range or not target_range:
        return None

    s_level = source_range.low
    t_level = target_range.low

    if s_level.is_equal(t_level):
        return None

    # Build a note about clearance vs effective level when source has a range
    range_note = ""
    if not source_range.is_single_level():
        range_note = (
            f" Note: the process has clearance up to {source_range.high}, "
            f"but its current operating level is {source_range.low} (the low side "
            f"of the range). The kernel checks access against the current level, "
            f"not the maximum clearance. To access {t_level.sensitivity} content, "
            f"the process would need to raise its effective level "
            f"(e.g., via newrole or runcon)."
        )

    if s_level.sensitivity_num != t_level.sensitivity_num:
        if s_level.sensitivity_num < t_level.sensitivity_num:
            return (
                f"Source process at {s_level.sensitivity} (lower) tried to access "
                f"target at {t_level.sensitivity} (higher). "
                f"MLS 'No Read Up' rule (Simple Security Property): a process "
                f"cannot read data classified above its current level."
                f"{range_note} "
                f"Fix: raise the process's effective level or lower the target's classification. "
                f"Use --mls to view all MLS-related denials."
            )
        return (
            f"Source process at {s_level.sensitivity} (higher) accessing "
            f"target at {t_level.sensitivity} (lower). "
            f"Reading down is normally allowed, but MLS 'No Write Down' rule "
            f"(Star Property) blocks writing to lower-classified objects to prevent "
            f"leaking sensitive data downward. If this is a write denial, "
            f"the source must be reclassified or the target raised."
            f"{range_note} "
            f"Use --mls to view all MLS-related denials."
        )

    if s_level.categories != t_level.categories:
        s_only = s_level.categories - t_level.categories
        t_only = t_level.categories - s_level.categories
        s_cat_str = _format_categories(frozenset(sorted(s_only)[:5])) if s_only else ""
        t_cat_str = _format_categories(frozenset(sorted(t_only)[:5])) if t_only else ""

        if t_only and not s_only:
            return (
                f"Target has categories ({t_cat_str}{'...' if len(t_only) > 5 else ''}) "
                f"not in source's current level. "
                f"MCS compartmentalization: access requires the process's category set "
                f"to include all of the target's categories."
                f"{range_note} "
                f"Fix: add the missing categories to the source's security range. "
                f"Use --mls to view all MLS-related denials."
            )
        if s_only and not t_only:
            return (
                f"Source has categories ({s_cat_str}{'...' if len(s_only) > 5 else ''}) "
                f"beyond what the target has. Source clearance is a superset of target, "
                f"which normally allows read access. If this is a write denial, "
                f"MLS may block writing to narrower compartments. "
                f"Use --mls to view all MLS-related denials."
            )
        return (
            f"Source and target have disjoint category sets "
            f"(source has {s_cat_str}{'...' if len(s_only) > 5 else ''} "
            f"not in target; target has {t_cat_str}{'...' if len(t_only) > 5 else ''} "
            f"not in source). MCS compartmentalization prevents access between "
            f"unrelated compartments. Fix: align the category assignments. "
            f"Use --mls to view all MLS-related denials."
        )

    return None


MLS_PRIMER = """MLS/MCS Security Levels Explained:
  Sensitivity: Hierarchical classification (s0=lowest, s15=highest).
    Processes have a clearance range (e.g., s0-s15). Objects have a single level.
  Categories: Compartments for lateral separation (c0-c1023).
    Access requires the process's categories to include all of the object's categories.
  Clearance vs Effective Level:
    A process with range s0-s15 has clearance UP TO s15, but operates at s0 (low side).
    The kernel checks access against the current level, not the maximum clearance.
    To access higher-level data, the process must raise its effective level.
  Key rules:
    No Read Up:    A process at s0 cannot read data at s15 (Simple Security Property)
    No Write Down: A process at s15 cannot write to s0 objects (Star Property)
    Compartments:  A process with {c0,c1} cannot access an object with {c2} (MCS)
  Tip: Use --mls to filter and view only MLS-related denials."""


def get_mls_primer() -> str:
    """Return a brief MLS/MCS educational primer for display in reports."""
    return MLS_PRIMER


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------

_SENSITIVITY_RE = re.compile(r"^s(\d+)$")
_CATEGORY_TOKEN_RE = re.compile(r"^c(\d+)(?:\.c(\d+))?$")


def _split_range(mls_string: str) -> tuple[str, str | None]:
    """
    Split an MLS string into low and high level strings.

    The tricky part: hyphens appear in ranges (s0-s0:c0.c1023) but
    sensitivity names contain digits, not hyphens. Categories use dots
    and commas. So the range separator is a hyphen that is followed by
    an 's' (start of a sensitivity name).

    Following libsepol mls.c: scan for '-' that starts a new sensitivity.
    """
    match = re.search(r"-(?=s\d)", mls_string)
    if match:
        low_str = mls_string[:match.start()]
        high_str = mls_string[match.start() + 1:]
        return low_str, high_str
    return mls_string, None


def _parse_level(level_str: str) -> MlsLevel | None:
    """Parse a single level string like 's0' or 's0:c0.c1023'."""
    if not level_str:
        return None

    parts = level_str.split(":", 1)
    sens_str = parts[0]
    cat_str = parts[1] if len(parts) > 1 else None

    sens_match = _SENSITIVITY_RE.match(sens_str)
    if not sens_match:
        return None

    sens_num = int(sens_match.group(1))
    categories = _parse_categories(cat_str) if cat_str else frozenset()

    level = MlsLevel(sens_str, sens_num, categories)
    level._raw = level_str
    return level


def _parse_categories(cat_str: str) -> frozenset[int]:
    """
    Parse a category string like 'c0.c1023' or 'c3,c5,c10.c20'.

    Follows libsepol mls.c parse logic and mcstrans parse_category():
      - Comma separates individual tokens
      - Dot within a token means inclusive range (c_low through c_high)
    """
    if not cat_str:
        return frozenset()

    result = set()
    for token in cat_str.split(","):
        token = token.strip()
        if not token:
            continue
        match = _CATEGORY_TOKEN_RE.match(token)
        if not match:
            continue
        low = int(match.group(1))
        high_str = match.group(2)
        if high_str is not None:
            high = int(high_str)
            result.update(range(low, high + 1))
        else:
            result.add(low)

    return frozenset(result)


def _format_categories(categories: frozenset[int]) -> str:
    """
    Format a category set back into compact string notation.

    Collapses consecutive integers into cN.cM ranges.
    Example: {0, 1, 2, 3, 5, 7, 8, 9} -> "c0.c3,c5,c7.c9"
    """
    if not categories:
        return ""

    sorted_cats = sorted(categories)
    ranges = []
    start = sorted_cats[0]
    end = start

    for cat in sorted_cats[1:]:
        if cat == end + 1:
            end = cat
        else:
            ranges.append((start, end))
            start = cat
            end = cat
    ranges.append((start, end))

    parts = []
    for s, e in ranges:
        if s == e:
            parts.append(f"c{s}")
        else:
            parts.append(f"c{s}.c{e}")
    return ",".join(parts)
