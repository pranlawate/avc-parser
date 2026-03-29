"""Tests for MLS/MCS security level parsing, comparison, and analysis."""

import unittest

from avc_selinux.mls import (
    MlsLevel,
    MlsRange,
    analyze_mls_relationship,
    parse_mls_string,
    _format_categories,
    _parse_categories,
    _split_range,
)
from avc_selinux.context import AvcContext


class TestMlsLevelParsing(unittest.TestCase):
    """Test parsing of individual MLS levels."""

    def test_simple_sensitivity(self):
        result = parse_mls_string("s0")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.sensitivity, "s0")
        self.assertEqual(result.low.sensitivity_num, 0)
        self.assertEqual(result.low.categories, frozenset())
        self.assertTrue(result.is_single_level())

    def test_sensitivity_with_single_category(self):
        result = parse_mls_string("s0:c0")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.categories, frozenset({0}))

    def test_sensitivity_with_category_range(self):
        result = parse_mls_string("s0:c0.c1023")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.sensitivity, "s0")
        self.assertEqual(len(result.low.categories), 1024)
        self.assertIn(0, result.low.categories)
        self.assertIn(1023, result.low.categories)

    def test_sensitivity_with_disjoint_categories(self):
        result = parse_mls_string("s0:c3,c5,c10.c20")
        self.assertIsNotNone(result)
        self.assertIn(3, result.low.categories)
        self.assertIn(5, result.low.categories)
        self.assertIn(10, result.low.categories)
        self.assertIn(20, result.low.categories)
        self.assertNotIn(4, result.low.categories)
        self.assertNotIn(6, result.low.categories)
        expected_count = 1 + 1 + 11  # c3, c5, c10-c20
        self.assertEqual(len(result.low.categories), expected_count)

    def test_higher_sensitivity(self):
        result = parse_mls_string("s15")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.sensitivity_num, 15)

    def test_none_input(self):
        self.assertIsNone(parse_mls_string(None))

    def test_empty_string(self):
        self.assertIsNone(parse_mls_string(""))

    def test_whitespace_only(self):
        self.assertIsNone(parse_mls_string("   "))

    def test_invalid_format(self):
        self.assertIsNone(parse_mls_string("invalid"))

    def test_malformed_sensitivity(self):
        self.assertIsNone(parse_mls_string("x0"))


class TestMlsRangeParsing(unittest.TestCase):
    """Test parsing of MLS ranges (low-high)."""

    def test_range_low_high(self):
        result = parse_mls_string("s0-s0:c0.c1023")
        self.assertIsNotNone(result)
        self.assertFalse(result.is_single_level())
        self.assertEqual(result.low.sensitivity, "s0")
        self.assertEqual(result.low.categories, frozenset())
        self.assertEqual(result.high.sensitivity, "s0")
        self.assertEqual(len(result.high.categories), 1024)

    def test_range_both_with_categories(self):
        result = parse_mls_string("s0:c0-s0:c0.c1023")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.categories, frozenset({0}))
        self.assertEqual(len(result.high.categories), 1024)

    def test_range_different_sensitivities(self):
        result = parse_mls_string("s0-s15")
        self.assertIsNotNone(result)
        self.assertEqual(result.low.sensitivity_num, 0)
        self.assertEqual(result.high.sensitivity_num, 15)

    def test_single_level_copies_to_high(self):
        result = parse_mls_string("s0:c5")
        self.assertIsNotNone(result)
        self.assertTrue(result.is_single_level())
        self.assertEqual(result.low.categories, result.high.categories)

    def test_real_audit_mls(self):
        """Test with actual MLS string from testAVC/tpm-permissive.log."""
        result = parse_mls_string("s0-s0:c0.c1023")
        self.assertIsNotNone(result)
        self.assertTrue(result.is_valid())
        self.assertEqual(str(result), "s0-s0:c0.c1023")


class TestMlsDominance(unittest.TestCase):
    """Test MLS level dominance comparison (mirrors libsepol mls_level_dom)."""

    def test_same_level_dominates(self):
        r = parse_mls_string("s0")
        self.assertTrue(r.low.dominates(r.high))

    def test_higher_sensitivity_dominates(self):
        low = parse_mls_string("s0").low
        high = parse_mls_string("s1").low
        self.assertTrue(high.dominates(low))
        self.assertFalse(low.dominates(high))

    def test_superset_categories_dominates(self):
        narrow = parse_mls_string("s0:c0").low
        wide = parse_mls_string("s0:c0.c1023").low
        self.assertTrue(wide.dominates(narrow))
        self.assertFalse(narrow.dominates(wide))

    def test_disjoint_categories_incomparable(self):
        a = parse_mls_string("s0:c0").low
        b = parse_mls_string("s0:c1").low
        self.assertFalse(a.dominates(b))
        self.assertFalse(b.dominates(a))
        self.assertTrue(a.is_incomparable(b))

    def test_range_validity(self):
        valid = parse_mls_string("s0-s0:c0.c1023")
        self.assertTrue(valid.is_valid())

    def test_range_contains(self):
        outer = parse_mls_string("s0-s0:c0.c1023")
        inner = parse_mls_string("s0-s0:c0.c10")
        self.assertTrue(outer.contains(inner))


class TestMlsStringRoundtrip(unittest.TestCase):
    """Test that parsing and formatting produces consistent results."""

    def test_simple_roundtrip(self):
        self.assertEqual(str(parse_mls_string("s0")), "s0")

    def test_categories_roundtrip(self):
        self.assertEqual(str(parse_mls_string("s0:c0.c1023")), "s0:c0.c1023")

    def test_range_roundtrip(self):
        self.assertEqual(str(parse_mls_string("s0-s0:c0.c1023")), "s0-s0:c0.c1023")

    def test_disjoint_roundtrip(self):
        self.assertEqual(str(parse_mls_string("s0:c3,c5")), "s0:c3,c5")


class TestCategoryFormatting(unittest.TestCase):
    """Test category set formatting back to compact notation."""

    def test_empty(self):
        self.assertEqual(_format_categories(frozenset()), "")

    def test_single(self):
        self.assertEqual(_format_categories(frozenset({5})), "c5")

    def test_range(self):
        self.assertEqual(_format_categories(frozenset(range(0, 4))), "c0.c3")

    def test_disjoint(self):
        result = _format_categories(frozenset({3, 5}))
        self.assertEqual(result, "c3,c5")

    def test_mixed(self):
        cats = frozenset({0, 1, 2, 3, 5, 7, 8, 9})
        result = _format_categories(cats)
        self.assertEqual(result, "c0.c3,c5,c7.c9")


class TestSplitRange(unittest.TestCase):
    """Test range string splitting."""

    def test_no_range(self):
        self.assertEqual(_split_range("s0"), ("s0", None))

    def test_no_range_with_categories(self):
        self.assertEqual(_split_range("s0:c0.c1023"), ("s0:c0.c1023", None))

    def test_range_simple(self):
        self.assertEqual(_split_range("s0-s0:c0.c1023"), ("s0", "s0:c0.c1023"))

    def test_range_both_cats(self):
        self.assertEqual(_split_range("s0:c0-s0:c0.c1023"), ("s0:c0", "s0:c0.c1023"))


class TestMlsAnalysis(unittest.TestCase):
    """Test MLS relationship analysis between source and target."""

    def test_same_level_returns_none(self):
        s = parse_mls_string("s0")
        t = parse_mls_string("s0")
        self.assertIsNone(analyze_mls_relationship(s, t))

    def test_source_higher_sensitivity(self):
        s = parse_mls_string("s1")
        t = parse_mls_string("s0")
        result = analyze_mls_relationship(s, t)
        self.assertIn("higher", result)
        self.assertIn("No Write Down", result)
        self.assertIn("--mls", result)

    def test_source_lower_sensitivity(self):
        s = parse_mls_string("s0")
        t = parse_mls_string("s1")
        result = analyze_mls_relationship(s, t)
        self.assertIn("lower", result)
        self.assertIn("No Read Up", result)
        self.assertIn("--mls", result)

    def test_disjoint_categories(self):
        s = parse_mls_string("s0:c0")
        t = parse_mls_string("s0:c1")
        result = analyze_mls_relationship(s, t)
        self.assertIn("disjoint", result)
        self.assertIn("compartmentalization", result)
        self.assertIn("--mls", result)

    def test_target_has_extra_categories(self):
        s = parse_mls_string("s0:c0")
        t = parse_mls_string("s0:c0,c1")
        result = analyze_mls_relationship(s, t)
        self.assertIn("not in source", result)

    def test_source_superset_categories(self):
        s = parse_mls_string("s0:c0,c1")
        t = parse_mls_string("s0:c0")
        result = analyze_mls_relationship(s, t)
        self.assertIn("superset", result)

    def test_none_inputs(self):
        self.assertIsNone(analyze_mls_relationship(None, None))
        s = parse_mls_string("s0")
        self.assertIsNone(analyze_mls_relationship(s, None))
        self.assertIsNone(analyze_mls_relationship(None, s))

    def test_real_mls_log_scenario(self):
        """Real scenario from testAVC/tpm-permissive.log: s0-s0:c0.c1023 vs s0."""
        s = parse_mls_string("s0-s0:c0.c1023")
        t = parse_mls_string("s0")
        result = analyze_mls_relationship(s, t)
        self.assertIsNone(result)

    def test_real_mls_policy_scenario(self):
        """Real scenario from audit_mls.log: s0-s15:c0.c1023 vs s15:c0.c1023."""
        s = parse_mls_string("s0-s15:c0.c1023")
        t = parse_mls_string("s15:c0.c1023")
        result = analyze_mls_relationship(s, t)
        self.assertIn("lower", result)
        self.assertIn("No Read Up", result)
        self.assertIn("clearance up to", result)
        self.assertIn("current operating level is s0", result)
        self.assertIn("runcon", result)


class TestAvcContextMlsIntegration(unittest.TestCase):
    """Test AvcContext integration with MLS parsing."""

    def test_four_field_context_has_mls_range(self):
        ctx = AvcContext("system_u:system_r:httpd_t:s0")
        self.assertEqual(ctx.mls, "s0")
        self.assertIsNotNone(ctx.mls_range)
        self.assertEqual(ctx.mls_range.low.sensitivity, "s0")

    def test_complex_mls_context(self):
        ctx = AvcContext("system_u:system_r:sshd_t:s0-s0:c0.c1023")
        self.assertEqual(ctx.mls, "s0-s0:c0.c1023")
        self.assertIsNotNone(ctx.mls_range)
        self.assertFalse(ctx.mls_range.is_single_level())
        self.assertEqual(len(ctx.mls_range.high.categories), 1024)

    def test_three_field_context_no_mls(self):
        ctx = AvcContext("user_u:user_r:user_t")
        self.assertIsNone(ctx.mls)
        self.assertIsNone(ctx.mls_range)
        self.assertTrue(ctx.is_valid())

    def test_three_field_str_roundtrip(self):
        ctx = AvcContext("user_u:user_r:user_t")
        self.assertEqual(str(ctx), "user_u:user_r:user_t")

    def test_four_field_str_roundtrip(self):
        ctx = AvcContext("system_u:system_r:httpd_t:s0")
        self.assertEqual(str(ctx), "system_u:system_r:httpd_t:s0")

    def test_complex_mls_str_roundtrip(self):
        ctx = AvcContext("system_u:system_r:sshd_t:s0-s0:c0.c1023")
        self.assertEqual(str(ctx), "system_u:system_r:sshd_t:s0-s0:c0.c1023")

    def test_three_field_not_equal_to_four_field_s0(self):
        three = AvcContext("user_u:user_r:user_t")
        four = AvcContext("user_u:user_r:user_t:s0")
        self.assertNotEqual(three, four)

    def test_get_mls_description(self):
        ctx = AvcContext("system_u:system_r:httpd_t:s0:c0.c1023")
        desc = ctx.get_mls_description()
        self.assertIsNotNone(desc)
        self.assertIn("sensitivity", desc)

    def test_get_mls_description_none_when_no_mls(self):
        ctx = AvcContext("user_u:user_r:user_t")
        self.assertIsNone(ctx.get_mls_description())


class TestMlsLevelDescription(unittest.TestCase):
    """Test human-readable MLS descriptions."""

    def test_simple_description(self):
        r = parse_mls_string("s0")
        self.assertIn("s0", r.get_description())

    def test_all_categories_description(self):
        r = parse_mls_string("s0:c0.c1023")
        desc = r.get_description()
        self.assertIn("all categories", desc)

    def test_range_description(self):
        r = parse_mls_string("s0-s0:c0.c1023")
        desc = r.get_description()
        self.assertIn("range", desc)


if __name__ == "__main__":
    unittest.main()
